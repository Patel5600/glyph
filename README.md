# Glyph: Minimal Ultra-Fast E2EE Text Messenger

> **Hard Size Budget:** ≤ 2–3 MB target  
> **Achieved Release APK Size:** **0.90 MB (942 KB)** ⚡

Glyph is an ultra-minimalist, high-performance End-to-End Encrypted (E2EE) text messenger with zero telemetry, zero bloat, and no phone/email registration.

---

## 🏛️ Architecture Overview

```
[Android Client (0.90 MB APK)] ───► [Go Relay on Render Free]
                                             │
                                             ▼
                                [Neon / Supabase Free Postgres]
```

- **Persistence without data loss:** Even if the Render free-tier container goes to sleep after inactivity, all identity claims and pending store-and-forward inboxes are safely preserved in external managed PostgreSQL (Neon / Supabase).
- **Cold start tolerance:** Render spins up on the first request (~15-20s), and zero user data or message queues are lost.

---

## 📦 Size Budget Breakdown

| Component | Target | Measured |
| :--- | :---: | :---: |
| **MAMA40 Core (`libmama.so`)** | ≤ 250 KB | **91 KB** (stripped ARM64 assembly) |
| **DEX & Code (R8 Full Shrink)** | ≤ 1.5 MB | **~480 KB** |
| **Resources & Manifest** | ≤ 250 KB | **~120 KB** |
| **Total Release APK** | **≤ 2.0 MB** | **0.90 MB (942,896 bytes)** 🎉 |

---

## 🔐 Cryptographic Specification (MAMA40 Assembly)

- **Identity Keypair:** Ed25519-compatible Curve25519 digital signatures for identity claim, rotation, and revocation.
- **E2EE Handshake:** X25519 ECDH + SHA-256 Key Derivation Function.
- **Symmetric Cipher:** ChaCha20-Poly1305 AEAD (RFC 8439) with 256-bit symmetric keys and 128-bit MAC tags.
- **Forward Secrecy:** Unique ephemeral keypair generated per message.
- **Nonce Uniqueness:** 12-byte CSPRNG nonces enforced per message.
- **Zero-Knowledge Relay:** The relay only sees ciphertext blobs, ephemeral public keys, and nonces.

---

## 🚀 Getting Started

### 1. Run the Go Relay Server

#### Local Development (SQLite):
```bash
cd relay
go run .
# Runs on :8080 with local SQLite database (relay.db)
```

#### Production (Render + Neon/Supabase Postgres):
Set the environment variable in your Render service:
```bash
DATABASE_URL=postgres://user:password@ep-xyz.neon.tech/glyph?sslmode=require
PORT=8080
```
Then deploy using `relay/Dockerfile` or `relay/render.yaml`.

---

### 2. Build the Android Client

Prerequisites: Android SDK (`android-35`), JDK 21.

```bash
cd client
./gradlew assembleRelease
```
The output APK will be at:
`client/app/build/outputs/apk/release/app-release.apk` (**0.90 MB**).

---

### 3. Claiming & Chatting Between Two Users

#### User A (Alice):
1. Launch Glyph on Device A.
2. Enter username: `alice`.
3. Set Relay URL (e.g. `http://<relay-ip>:8080` or Render URL).
4. Tap **Claim Identity**.
5. Save the generated recovery phrase. Tap **Continue**.

#### User B (Bob):
1. Launch Glyph on Device B.
2. Enter username: `bob`.
3. Set Relay URL to the same relay server.
4. Tap **Claim Identity**.
5. Save the recovery phrase. Tap **Continue**.

#### Exchanging Encrypted Messages:
1. On Alice's device, tap **+ New Chat**.
2. Type `bob` and tap **Start Chat**.
3. Alice types: `"Hello Bob, this is encrypted with MAMA40!"` and taps **Send**.
4. Bob receives the message instantly via Server-Sent Events (SSE) or inbox poll.
5. Bob replies: `"Received loud and clear, 100% E2EE!"`.

---

## 🛡️ Security Guarantees

Read [`SECURITY.md`](SECURITY.md) for full cryptographic details, nonce uniqueness rules, and threat models.
