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

func claimUser(t *testing.T, mux *http.ServeMux, username string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	timestamp := time.Now().Unix()
	claimMsg := fmt.Sprintf("claim:%s:%d", username, timestamp)
	sig := ed25519.Sign(priv, []byte(claimMsg))

	body, _ := json.Marshal(ClaimRequest{
		Username:  username,
		PubKey:    hex.EncodeToString(pub),
		Sig:       hex.EncodeToString(sig),
		Timestamp: timestamp,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/claim", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("claimUser %s failed with %d: %s", username, rec.Code, rec.Body.String())
	}
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

	pubAlice, privAlice := generateEd25519(t)
	pubBob, privBob := generateEd25519(t)

	claimUser(t, mux, "alice", pubAlice, privAlice)
	claimUser(t, mux, "bob", pubBob, privBob)

	ts := time.Now().Unix()
	ciphertext := "dGVzdF9jaXBoZXJ0ZXh0"
	nonce := "0102030405060708090a0b0c"
	ephKey := "aabbccdd11223344"

	sendMsg := fmt.Sprintf("send:alice:bob:%s:%s:%s:%d", ciphertext, nonce, ephKey, ts)
	senderSig := ed25519.Sign(privAlice, []byte(sendMsg))

	sendBody, _ := json.Marshal(SendRequest{
		Recipient:    "bob",
		Sender:       "alice",
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		EphemeralKey: ephKey,
		Timestamp:    ts,
		Sig:          hex.EncodeToString(senderSig),
	})

	// Alice sends message to Bob
	reqSend := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(sendBody))
	recSend := httptest.NewRecorder()
	mux.ServeHTTP(recSend, reqSend)

	if recSend.Code != http.StatusAccepted {
		t.Fatalf("Expected 202 Accepted, got %d: %s", recSend.Code, recSend.Body.String())
	}

	// Bob fetches inbox with signed authorization headers
	inboxTs := time.Now().Unix()
	inboxMsg := fmt.Sprintf("inbox:bob:%d", inboxTs)
	inboxSig := ed25519.Sign(privBob, []byte(inboxMsg))

	reqInbox := httptest.NewRequest(http.MethodGet, "/v1/inbox?username=bob", nil)
	reqInbox.Header.Set("X-Glyph-Timestamp", fmt.Sprintf("%d", inboxTs))
	reqInbox.Header.Set("X-Glyph-Signature", hex.EncodeToString(inboxSig))

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

	if res.Messages[0].Sender != "alice" || res.Messages[0].Ciphertext != ciphertext {
		t.Fatalf("Envelope content mismatch: %+v", res.Messages[0])
	}

	// Second fetch should be empty (store-and-forward purged)
	inboxTs2 := time.Now().Unix()
	inboxMsg2 := fmt.Sprintf("inbox:bob:%d", inboxTs2)
	inboxSig2 := ed25519.Sign(privBob, []byte(inboxMsg2))

	reqInbox2 := httptest.NewRequest(http.MethodGet, "/v1/inbox?username=bob", nil)
	reqInbox2.Header.Set("X-Glyph-Timestamp", fmt.Sprintf("%d", inboxTs2))
	reqInbox2.Header.Set("X-Glyph-Signature", hex.EncodeToString(inboxSig2))

	recInbox2 := httptest.NewRecorder()
	mux.ServeHTTP(recInbox2, reqInbox2)
	var res2 struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(recInbox2.Body).Decode(&res2)
	if res2.Count != 0 {
		t.Fatalf("Expected inbox to be empty after fetch, got %d", res2.Count)
	}
}

func TestInboxAuthentication(t *testing.T) {
	_, mux := setupTestServer(t)

	pubBob, privBob := generateEd25519(t)
	_, privEve := generateEd25519(t)
	claimUser(t, mux, "bob", pubBob, privBob)

	// 1. Unauthenticated inbox fetch (missing headers) must return 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "/v1/inbox?username=bob", nil)
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for missing signature, got %d", recUnauth.Code)
	}

	// 2. Forged inbox fetch (Eve signs for Bob) must return 401
	ts := time.Now().Unix()
	forgedSig := ed25519.Sign(privEve, []byte(fmt.Sprintf("inbox:bob:%d", ts)))
	reqForged := httptest.NewRequest(http.MethodGet, "/v1/inbox?username=bob", nil)
	reqForged.Header.Set("X-Glyph-Timestamp", fmt.Sprintf("%d", ts))
	reqForged.Header.Set("X-Glyph-Signature", hex.EncodeToString(forgedSig))

	recForged := httptest.NewRecorder()
	mux.ServeHTTP(recForged, reqForged)
	if recForged.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for forged signature, got %d", recForged.Code)
	}
}

func TestSenderAuthentication(t *testing.T) {
	_, mux := setupTestServer(t)

	pubAlice, privAlice := generateEd25519(t)
	pubBob, privBob := generateEd25519(t)
	_, privEve := generateEd25519(t)

	claimUser(t, mux, "alice", pubAlice, privAlice)
	claimUser(t, mux, "bob", pubBob, privBob)

	ts := time.Now().Unix()
	ciphertext := "YXR0YWNr"
	nonce := "0102030405060708090a0b0c"
	ephKey := "aabbccdd11223344"

	// 1. Eve attempts to spoof Alice as sender using Eve's signature
	sendMsg := fmt.Sprintf("send:alice:bob:%s:%s:%s:%d", ciphertext, nonce, ephKey, ts)
	eveSig := ed25519.Sign(privEve, []byte(sendMsg))

	sendBody, _ := json.Marshal(SendRequest{
		Recipient:    "bob",
		Sender:       "alice",
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		EphemeralKey: ephKey,
		Timestamp:    ts,
		Sig:          hex.EncodeToString(eveSig),
	})

	reqSpoof := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(sendBody))
	recSpoof := httptest.NewRecorder()
	mux.ServeHTTP(recSpoof, reqSpoof)

	if recSpoof.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for spoofed sender, got %d", recSpoof.Code)
	}

	// 2. Missing signature must be rejected
	sendBodyNoSig, _ := json.Marshal(SendRequest{
		Recipient:    "bob",
		Sender:       "alice",
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		EphemeralKey: ephKey,
		Timestamp:    ts,
	})
	reqNoSig := httptest.NewRequest(http.MethodPost, "/v1/send", bytes.NewReader(sendBodyNoSig))
	recNoSig := httptest.NewRecorder()
	mux.ServeHTTP(recNoSig, reqNoSig)

	if recNoSig.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for missing sig, got %d", recNoSig.Code)
	}
}

func TestArbitraryRevocationPrevention(t *testing.T) {
	_, mux := setupTestServer(t)

	pubAlice, privAlice := generateEd25519(t)
	pubEve, privEve := generateEd25519(t)

	claimUser(t, mux, "alice", pubAlice, privAlice)

	ts := time.Now().Unix()
	revokeMsg := fmt.Sprintf("revoke:alice:%d", ts)
	eveSig := ed25519.Sign(privEve, []byte(revokeMsg))

	// 1. Eve tries to revoke Alice using Eve's public key
	revokeBodyEve, _ := json.Marshal(RevokeRequest{
		Username:  "alice",
		PubKey:    hex.EncodeToString(pubEve),
		Sig:       hex.EncodeToString(eveSig),
		Timestamp: ts,
	})

	reqEve := httptest.NewRequest(http.MethodPost, "/v1/revoke", bytes.NewReader(revokeBodyEve))
	recEve := httptest.NewRecorder()
	mux.ServeHTTP(recEve, reqEve)

	if recEve.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden when revoking with non-matching key, got %d", recEve.Code)
	}

	// Verify Alice is still active
	reqResolve := httptest.NewRequest(http.MethodGet, "/v1/resolve/alice", nil)
	recResolve := httptest.NewRecorder()
	mux.ServeHTTP(recResolve, reqResolve)
	var resolved Identity
	_ = json.NewDecoder(recResolve.Body).Decode(&resolved)
	if resolved.Revoked {
		t.Fatalf("Alice should not be revoked after attacker attempt")
	}

	// 2. Alice legitimately revokes her own account
	aliceSig := ed25519.Sign(privAlice, []byte(revokeMsg))
	revokeBodyAlice, _ := json.Marshal(RevokeRequest{
		Username:  "alice",
		PubKey:    hex.EncodeToString(pubAlice),
		Sig:       hex.EncodeToString(aliceSig),
		Timestamp: ts,
	})
	reqAlice := httptest.NewRequest(http.MethodPost, "/v1/revoke", bytes.NewReader(revokeBodyAlice))
	recAlice := httptest.NewRecorder()
	mux.ServeHTTP(recAlice, reqAlice)

	if recAlice.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for legitimate revocation, got %d: %s", recAlice.Code, recAlice.Body.String())
	}

	// Verify Alice is marked revoked
	recResolve2 := httptest.NewRecorder()
	mux.ServeHTTP(recResolve2, reqResolve)
	_ = json.NewDecoder(recResolve2.Body).Decode(&resolved)
	if !resolved.Revoked {
		t.Fatalf("Alice should be revoked")
	}
}
