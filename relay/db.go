package main

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type Database struct {
	db         *sql.DB
	isPostgres bool
}

type Identity struct {
	Username  string `json:"username"`
	PubKey    string `json:"pubkey"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	Revoked   bool   `json:"revoked"`
}

type MessageEnvelope struct {
	ID           int64  `json:"id"`
	Recipient    string `json:"recipient"`
	Sender       string `json:"sender"`
	Ciphertext   string `json:"ciphertext"`
	Nonce        string `json:"nonce"`
	EphemeralKey string `json:"ephemeral_key"`
	Timestamp    int64  `json:"timestamp"`
}

func InitDB(connStr string) (*Database, error) {
	isPg := strings.HasPrefix(connStr, "postgres://") || strings.HasPrefix(connStr, "postgresql://")
	driverName := "sqlite"
	if isPg {
		driverName = "postgres"
	}

	db, err := sql.Open(driverName, connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database (%s): %w", driverName, err)
	}

	if !isPg {
		// SQLite WAL mode
		if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
			return nil, fmt.Errorf("failed to configure sqlite PRAGMA: %w", err)
		}
	} else {
		// Postgres connection pool limits suitable for Neon/Supabase free tiers
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(10 * time.Minute)
	}

	var schema string
	if isPg {
		schema = `
		CREATE TABLE IF NOT EXISTS identities (
			username VARCHAR(32) PRIMARY KEY,
			pubkey VARCHAR(64) NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL,
			revoked INT NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS inbox (
			id BIGSERIAL PRIMARY KEY,
			recipient VARCHAR(32) NOT NULL,
			sender VARCHAR(32) NOT NULL,
			ciphertext TEXT NOT NULL,
			nonce VARCHAR(64) NOT NULL,
			ephemeral_key VARCHAR(64) NOT NULL,
			created_at BIGINT NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_inbox_recipient ON inbox(recipient, created_at);
		`
	} else {
		schema = `
		CREATE TABLE IF NOT EXISTS identities (
			username TEXT PRIMARY KEY,
			pubkey TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS inbox (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			recipient TEXT NOT NULL,
			sender TEXT NOT NULL,
			ciphertext TEXT NOT NULL,
			nonce TEXT NOT NULL,
			ephemeral_key TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_inbox_recipient ON inbox(recipient, created_at);
		`
	}

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return &Database{db: db, isPostgres: isPg}, nil
}

// rebind converts '?' placeholders to '$1, $2, ...' for Postgres
func (d *Database) rebind(query string) string {
	if !d.isPostgres {
		return query
	}
	var b strings.Builder
	paramIdx := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			b.WriteString("$")
			b.WriteString(strconv.Itoa(paramIdx))
			paramIdx++
		} else {
			b.WriteByte(query[i])
		}
	}
	return b.String()
}

func (d *Database) ClaimIdentity(username, pubkey string, timestamp int64) error {
	query := d.rebind(`INSERT INTO identities (username, pubkey, created_at, updated_at, revoked)
	                   VALUES (?, ?, ?, ?, 0)`)
	_, err := d.db.Exec(query, username, pubkey, timestamp, timestamp)
	return err
}

func (d *Database) ResolveIdentity(username string) (*Identity, error) {
	query := d.rebind(`SELECT username, pubkey, created_at, updated_at, revoked FROM identities WHERE username = ?`)
	row := d.db.QueryRow(query, username)

	var id Identity
	var revokedInt int
	if err := row.Scan(&id.Username, &id.PubKey, &id.CreatedAt, &id.UpdatedAt, &revokedInt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	id.Revoked = (revokedInt != 0)
	return &id, nil
}

func (d *Database) RotateKey(username, newPubkey string, timestamp int64) error {
	query := d.rebind(`UPDATE identities SET pubkey = ?, updated_at = ? WHERE username = ? AND revoked = 0`)
	res, err := d.db.Exec(query, newPubkey, timestamp, username)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("identity not found or already revoked")
	}
	return nil
}

func (d *Database) RevokeIdentity(username string, timestamp int64) error {
	query := d.rebind(`UPDATE identities SET revoked = 1, updated_at = ? WHERE username = ?`)
	_, err := d.db.Exec(query, timestamp, username)
	return err
}

func (d *Database) EnqueueMessage(msg *MessageEnvelope) (int64, error) {
	if d.isPostgres {
		query := `INSERT INTO inbox (recipient, sender, ciphertext, nonce, ephemeral_key, created_at)
		          VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`
		var id int64
		err := d.db.QueryRow(query, msg.Recipient, msg.Sender, msg.Ciphertext, msg.Nonce, msg.EphemeralKey, msg.Timestamp).Scan(&id)
		return id, err
	}

	query := `INSERT INTO inbox (recipient, sender, ciphertext, nonce, ephemeral_key, created_at)
	          VALUES (?, ?, ?, ?, ?, ?)`
	res, err := d.db.Exec(query, msg.Recipient, msg.Sender, msg.Ciphertext, msg.Nonce, msg.EphemeralKey, msg.Timestamp)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *Database) FetchInbox(recipient string, limit int) ([]MessageEnvelope, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := d.rebind(`SELECT id, recipient, sender, ciphertext, nonce, ephemeral_key, created_at
	                   FROM inbox WHERE recipient = ? ORDER BY id ASC LIMIT ?`)
	rows, err := d.db.Query(query, recipient, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []MessageEnvelope
	var ids []int64
	for rows.Next() {
		var m MessageEnvelope
		if err := rows.Scan(&m.ID, &m.Recipient, &m.Sender, &m.Ciphertext, &m.Nonce, &m.EphemeralKey, &m.Timestamp); err != nil {
			return nil, err
		}
		messages = append(messages, m)
		ids = append(ids, m.ID)
	}

	// Delete fetched messages (store-and-forward)
	if len(ids) > 0 {
		delQuery := fmt.Sprintf("DELETE FROM inbox WHERE id IN (%s)", formatIDs(ids))
		_, _ = d.db.Exec(delQuery)
	}

	return messages, nil
}

func (d *Database) PurgeExpired(maxAgeSeconds int64) (int64, error) {
	cutoff := time.Now().Unix() - maxAgeSeconds
	query := d.rebind(`DELETE FROM inbox WHERE created_at < ?`)
	res, err := d.db.Exec(query, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func formatIDs(ids []int64) string {
	res := ""
	for i, id := range ids {
		if i > 0 {
			res += ","
		}
		res += fmt.Sprintf("%d", id)
	}
	return res
}
