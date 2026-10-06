package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var usernameRegex = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

type Server struct {
	db          *Database
	claimLimiter *RateLimiter
	sendLimiter  *RateLimiter
	hubMu       sync.RWMutex
	subscribers map[string]map[chan MessageEnvelope]struct{}
}

func NewServer(db *Database) *Server {
	return &Server{
		db:          db,
		claimLimiter: NewRateLimiter(0.2, 5),   // 1 token every 5 sec, burst of 5
		sendLimiter:  NewRateLimiter(5.0, 30),  // 5 tokens/sec, burst of 30
		subscribers: make(map[string]map[chan MessageEnvelope]struct{}),
	}
}

func (s *Server) subscribe(username string) chan MessageEnvelope {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()

	ch := make(chan MessageEnvelope, 16)
	if s.subscribers[username] == nil {
		s.subscribers[username] = make(map[chan MessageEnvelope]struct{})
	}
	s.subscribers[username][ch] = struct{}{}
	return ch
}

func (s *Server) unsubscribe(username string, ch chan MessageEnvelope) {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()

	if subs, ok := s.subscribers[username]; ok {
		delete(subs, ch)
		close(ch)
		if len(subs) == 0 {
			delete(s.subscribers, username)
		}
	}
}

func (s *Server) broadcast(msg MessageEnvelope) {
	s.hubMu.RLock()
	defer s.hubMu.RUnlock()

	if subs, ok := s.subscribers[msg.Recipient]; ok {
		for ch := range subs {
			select {
			case ch <- msg:
			default:
				// Channel full, drop or let it poll
			}
		}
	}
}

// Request & Response structs
type ClaimRequest struct {
	Username  string `json:"username"`
	PubKey    string `json:"pubkey"`
	Sig       string `json:"sig"`
	Timestamp int64  `json:"timestamp"`
}

type RotateRequest struct {
	Username  string `json:"username"`
	OldPubKey string `json:"old_pubkey"`
	NewPubKey string `json:"new_pubkey"`
	Sig       string `json:"sig"`
	Timestamp int64  `json:"timestamp"`
}

type RevokeRequest struct {
	Username  string `json:"username"`
	PubKey    string `json:"pubkey"`
	Sig       string `json:"sig"`
	Timestamp int64  `json:"timestamp"`
}

type SendRequest struct {
	Recipient    string `json:"recipient"`
	Sender       string `json:"sender"`
	Ciphertext   string `json:"ciphertext"`
	Nonce        string `json:"nonce"`
	EphemeralKey string `json:"ephemeral_key"`
	Timestamp    int64  `json:"timestamp"`
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ip := getClientIP(r)
	if !s.claimLimiter.Allow(ip) {
		writeError(w, http.StatusTooManyRequests, "Rate limit exceeded for identity claims")
		return
	}

	var req ClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if !usernameRegex.MatchString(req.Username) {
		writeError(w, http.StatusBadRequest, "Invalid username format (3-32 chars, a-z0-9_)")
		return
	}

	now := time.Now().Unix()
	if math.Abs(float64(now-req.Timestamp)) > 300 {
		writeError(w, http.StatusBadRequest, "Timestamp outside acceptable window (±300s)")
		return
	}

	pubBytes, err := hex.DecodeString(req.PubKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "Invalid Ed25519 public key hex (must be 32 bytes)")
		return
	}

	sigBytes, err := hex.DecodeString(req.Sig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		writeError(w, http.StatusBadRequest, "Invalid Ed25519 signature hex (must be 64 bytes)")
		return
	}

	claimMsg := fmt.Sprintf("claim:%s:%d", req.Username, req.Timestamp)
	if !ed25519.Verify(pubBytes, []byte(claimMsg), sigBytes) {
		writeError(w, http.StatusUnauthorized, "Invalid signature for identity claim")
		return
	}

	// Check if already claimed
	existing, err := s.db.ResolveIdentity(req.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if existing != nil {
		if existing.PubKey == req.PubKey && !existing.Revoked {
			// Already claimed by this same key
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"status":   "claimed",
				"username": req.Username,
				"pubkey":   req.PubKey,
			})
			return
		}
		writeError(w, http.StatusConflict, "Username is already claimed")
		return
	}

	if err := s.db.ClaimIdentity(req.Username, req.PubKey, req.Timestamp); err != nil {
		writeError(w, http.StatusConflict, "Username claim collision")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status":   "created",
		"username": req.Username,
		"pubkey":   req.PubKey,
	})
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/resolve/")
	username := strings.ToLower(strings.TrimSpace(path))
	if !usernameRegex.MatchString(username) {
		writeError(w, http.StatusBadRequest, "Invalid username")
		return
	}

	id, err := s.db.ResolveIdentity(username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if id == nil {
		writeError(w, http.StatusNotFound, "Identity not found")
		return
	}

	writeJSON(w, http.StatusOK, id)
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	id, err := s.db.ResolveIdentity(req.Username)
	if err != nil || id == nil || id.Revoked {
		writeError(w, http.StatusNotFound, "Identity not found or revoked")
		return
	}

	if id.PubKey != req.OldPubKey {
		writeError(w, http.StatusUnauthorized, "Old public key does not match current registered key")
		return
	}

	oldPubBytes, err := hex.DecodeString(req.OldPubKey)
	if err != nil || len(oldPubBytes) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "Invalid old public key")
		return
	}
	sigBytes, err := hex.DecodeString(req.Sig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		writeError(w, http.StatusBadRequest, "Invalid signature")
		return
	}

	rotateMsg := fmt.Sprintf("rotate:%s:%s:%d", req.Username, req.NewPubKey, req.Timestamp)
	if !ed25519.Verify(oldPubBytes, []byte(rotateMsg), sigBytes) {
		writeError(w, http.StatusUnauthorized, "Invalid signature for rotation")
		return
	}

	if err := s.db.RotateKey(req.Username, req.NewPubKey, req.Timestamp); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to rotate key")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "rotated", "username": req.Username, "pubkey": req.NewPubKey})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	id, err := s.db.ResolveIdentity(req.Username)
	if err != nil || id == nil {
		writeError(w, http.StatusNotFound, "Identity not found")
		return
	}

	pubBytes, err := hex.DecodeString(req.PubKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "Invalid public key")
		return
	}
	sigBytes, err := hex.DecodeString(req.Sig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		writeError(w, http.StatusBadRequest, "Invalid signature")
		return
	}

	revokeMsg := fmt.Sprintf("revoke:%s:%d", req.Username, req.Timestamp)
	if !ed25519.Verify(pubBytes, []byte(revokeMsg), sigBytes) {
		writeError(w, http.StatusUnauthorized, "Invalid signature for revocation")
		return
	}

	if err := s.db.RevokeIdentity(req.Username, req.Timestamp); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to revoke identity")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "username": req.Username})
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ip := getClientIP(r)
	if !s.sendLimiter.Allow(ip) {
		writeError(w, http.StatusTooManyRequests, "Rate limit exceeded for message sending")
		return
	}

	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Recipient = strings.ToLower(strings.TrimSpace(req.Recipient))
	req.Sender = strings.ToLower(strings.TrimSpace(req.Sender))

	if req.Recipient == "" || req.Sender == "" || req.Ciphertext == "" || req.Nonce == "" {
		writeError(w, http.StatusBadRequest, "Recipient, sender, ciphertext, and nonce are required")
		return
	}

	// Payload size cap to avoid relay abuse (max 64 KB for text messages)
	if len(req.Ciphertext) > 65536 {
		writeError(w, http.StatusBadRequest, "Ciphertext exceeds maximum allowed size (64 KB)")
		return
	}

	if req.Timestamp == 0 {
		req.Timestamp = time.Now().Unix()
	}

	envelope := MessageEnvelope{
		Recipient:    req.Recipient,
		Sender:       req.Sender,
		Ciphertext:   req.Ciphertext,
		Nonce:        req.Nonce,
		EphemeralKey: req.EphemeralKey,
		Timestamp:    req.Timestamp,
	}

	id, err := s.db.EnqueueMessage(&envelope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to enqueue message")
		return
	}
	envelope.ID = id

	// Real-time broadcast to SSE subscribers
	s.broadcast(envelope)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status": "queued",
		"id":     id,
	})
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	username := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("username")))
	if username == "" {
		writeError(w, http.StatusBadRequest, "username parameter is required")
		return
	}

	messages, err := s.db.FetchInbox(username, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to fetch inbox")
		return
	}

	if messages == nil {
		messages = []MessageEnvelope{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"messages": messages,
		"count":    len(messages),
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("username")))
	if username == "" {
		writeError(w, http.StatusBadRequest, "username parameter is required")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := s.subscribe(username)
	defer s.unsubscribe(username, ch)

	// Send initial connected ping
	fmt.Fprintf(w, "event: connected\ndata: {\"username\":\"%s\"}\n\n", username)
	flusher.Flush()

	// Also flush any pending inbox messages immediately
	pending, err := s.db.FetchInbox(username, 50)
	if err == nil {
		for _, m := range pending {
			data, _ := json.Marshal(m)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
		}
		flusher.Flush()
	}

	notify := r.Context().Done()
	keepAliveTicker := time.NewTicker(15 * time.Second)
	defer keepAliveTicker.Stop()

	for {
		select {
		case <-notify:
			return
		case <-keepAliveTicker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case msg, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(msg)
			if err == nil {
				fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}

func (s *Server) startTTLCleaner(ttlSeconds int64) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		for range ticker.C {
			deleted, err := s.db.PurgeExpired(ttlSeconds)
			if err != nil {
				log.Printf("[TTL Cleaner] Error purging messages: %v", err)
			} else if deleted > 0 {
				log.Printf("[TTL Cleaner] Purged %d expired messages", deleted)
			}
		}
	}()
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = os.Getenv("DB_PATH")
	}
	if connStr == "" {
		connStr = "relay.db"
	}

	db, err := InitDB(connStr)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	server := NewServer(db)
	server.startTTLCleaner(48 * 3600) // 48-hour TTL

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "glyph-relay"})
	})
	mux.HandleFunc("/v1/claim", server.handleClaim)
	mux.HandleFunc("/v1/resolve/", server.handleResolve)
	mux.HandleFunc("/v1/rotate", server.handleRotate)
	mux.HandleFunc("/v1/revoke", server.handleRevoke)
	mux.HandleFunc("/v1/send", server.handleSend)
	mux.HandleFunc("/v1/inbox", server.handleInbox)
	mux.HandleFunc("/v1/events", server.handleEvents)

	log.Printf("Starting Glyph E2EE Relay on port %s...", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Relay server exited: %v", err)
	}
}
