package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setupTestServer(t *testing.T) (*Server, *http.ServeMux) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	server := NewServer(db)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/claim", server.handleClaim)
	mux.HandleFunc("/v1/resolve/", server.handleResolve)
	mux.HandleFunc("/v1/rotate", server.handleRotate)
	mux.HandleFunc("/v1/revoke", server.handleRevoke)
	mux.HandleFunc("/v1/send", server.handleSend)
	mux.HandleFunc("/v1/inbox", server.handleInbox)
	mux.HandleFunc("/v1/events", server.handleEvents)

	return server, mux
}

func generateEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	return pub, priv
}

func TestClaimAndResolve(t *testing.T) {
	_, mux := setupTestServer(t)

	pub, priv := generateEd25519(t)
	username := "alice"
	timestamp := time.Now().Unix()

	claimMsg := fmt.Sprintf("claim:%s:%d", username, timestamp)
	sig := ed25519.Sign(priv, []byte(claimMsg))

	body, _ := json.Marshal(ClaimRequest{
		Username:  username,
		PubKey:    hex.EncodeToString(pub),
		Sig:       hex.EncodeToString(sig),
		Timestamp: timestamp,
	})

	// 1. Claim username
	req := httptest.NewRequest(http.MethodPost, "/v1/claim", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Resolve username
	reqResolve := httptest.NewRequest(http.MethodGet, "/v1/resolve/alice", nil)
	recResolve := httptest.NewRecorder()
	mux.ServeHTTP(recResolve, reqResolve)

	if recResolve.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", recResolve.Code, recResolve.Body.String())
	}

	var resolved Identity
	_ = json.NewDecoder(recResolve.Body).Decode(&resolved)
	if resolved.Username != "alice" || resolved.PubKey != hex.EncodeToString(pub) {
		t.Fatalf("Resolved identity mismatch: %+v", resolved)
	}

	// 3. Collision test: another user tries to claim "alice"
	pubBob, privBob := generateEd25519(t)
	bobSig := ed25519.Sign(privBob, []byte(claimMsg))
	bodyBob, _ := json.Marshal(ClaimRequest{
		Username:  username,
		PubKey:    hex.EncodeToString(pubBob),
		Sig:       hex.EncodeToString(bobSig),
		Timestamp: timestamp,
	})
	reqBob := httptest.NewRequest(http.MethodPost, "/v1/claim", bytes.NewReader(bodyBob))
	recBob := httptest.NewRecorder()
	mux.ServeHTTP(recBob, reqBob)

	if recBob.Code != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict for collision, got %d", recBob.Code)
	}
}

func TestSendAndInbox(t *testing.T) {
	_, mux := setupTestServer(t)

	// Send encrypted message to bob
	sendBody, _ := json.Marshal(SendRequest{
		Recipient:    "bob",
		Sender:       "alice",
		Ciphertext:   "dGVzdF9jaXBoZXJ0ZXh0", // base64
		Nonce:        "0102030405060708090a0b0c",
		EphemeralKey: "aabbccdd11223344",
		Timestamp:    time.Now().Unix(),
	})

	reqSend := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(sendBody))
	recSend := httptest.NewRecorder()
	mux.ServeHTTP(recSend, reqSend)

	if recSend.Code != http.StatusAccepted {
		t.Fatalf("Expected 202 Accepted, got %d: %s", recSend.Code, recSend.Body.String())
	}

	// Bob fetches inbox
	reqInbox := httptest.NewRequest(http.MethodGet, "/v1/inbox?username=bob", nil)
	recInbox := httptest.NewRecorder()
	mux.ServeHTTP(recInbox, reqInbox)

	if recInbox.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", recInbox.Code, recInbox.Body.String())
	}

	var res struct {
		Messages []MessageEnvelope `json:"messages"`
		Count    int               `json:"count"`
	}
	_ = json.NewDecoder(recInbox.Body).Decode(&res)

	if res.Count != 1 || len(res.Messages) != 1 {
		t.Fatalf("Expected 1 message in inbox, got %d", res.Count)
	}

	if res.Messages[0].Sender != "alice" || res.Messages[0].Ciphertext != "dGVzdF9jaXBoZXJ0ZXh0" {
		t.Fatalf("Envelope content mismatch: %+v", res.Messages[0])
	}

	// Second fetch should be empty (store-and-forward purged)
	recInbox2 := httptest.NewRecorder()
	mux.ServeHTTP(recInbox2, reqInbox)
	var res2 struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(recInbox2.Body).Decode(&res2)
	if res2.Count != 0 {
		t.Fatalf("Expected inbox to be empty after fetch, got %d", res2.Count)
	}
}
