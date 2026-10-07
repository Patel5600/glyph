# Security & Cryptographic Specification

## 1. Cryptographic Primitives (MAMA40 & Ed25519 Engines)
Glyph Messenger utilizes bare-metal assembly cryptographic engines (ARM64 NEON & x86-64 AVX2) with zero dynamic heap allocations during message processing:
- **Identity & Signatures:** RFC 8032 Ed25519 for identity claim, rotation, revocation, relay authorization, and end-to-end sender authenticity.
- **Key Agreement:** X25519 ECDH (RFC 7748) combined with ephemeral Diffie-Hellman keys per message.
- **Symmetric Encryption & MAC:** ChaCha20-Poly1305 AEAD (RFC 8439) with 256-bit keys and 128-bit authentication tags.
- **Key Derivation (KDF):** SHA-256 over \(SS \parallel ek_{pub} \parallel pk_{recipient}\).
- **Post-Quantum Extension:** NIST FIPS 203 ML-KEM-768 primitives built into native binary for post-quantum hybrid ratcheting.

---

## 2. Cryptographic Sender Authenticity & Forward Secrecy
1. **End-to-End Sender Signature:** Plaintext envelopes are cryptographically signed with the sender's private Ed25519 identity key prior to AEAD encryption:
   \[
   \text{Sig} = \text{Ed25519}_{\text{Sign}}(\text{sender\_priv}, \text{"msg"} \parallel \text{sender} \parallel \text{recipient} \parallel \text{timestamp} \parallel \text{body})
   \]
   The recipient verifies this signature against the sender's registered public key upon decryption. Forged sender labels are mathematically rejected with a security exception.
2. **Ephemeral Key Agreement:** Every message creates a fresh 32-byte ephemeral X25519 keypair, guaranteeing that key-nonce reuse is cryptographically impossible. Ephemeral secrets are zeroized in memory immediately following encryption/decryption.

---

## 3. Relay Authorization & Threat Model

Glyph operates as a **Plaintext-Blind Store-and-Forward Relay**. The relay handles routing and delivery but has zero visibility into plaintext content.

### Authenticated Endpoints:
1. **`/v1/send` (Sender Authentication):** Senders must sign the relay transmission envelope with their registered Ed25519 key:
   \[
   \text{"send:"} \parallel \text{sender} \parallel \text{recipient} \parallel \text{ciphertext} \parallel \text{nonce} \parallel \text{ephemeral\_key} \parallel \text{timestamp}
   \]
   The relay validates the signature against the sender's registered public key before enqueuing.
2. **`/v1/inbox` & `/v1/events` (Inbox Authorization):** Clients must present signed authorization headers (`X-Glyph-Signature`, `X-Glyph-Timestamp`):
   \[
   \text{"inbox:"} \parallel \text{username} \parallel \text{timestamp}
   \]
   The relay strictly verifies the signature against the recipient's registered public key with a 300-second drift window, preventing unauthorized queue draining or message theft.
3. **`/v1/revoke` (Revocation Authorization):** Revocation signatures are strictly verified against the *currently registered* identity public key, preventing third-party takeover.

### What the Relay CAN See (Routing Metadata):
- Sender username (e.g. `@alice`)
- Recipient username (e.g. `@bob`)
- Encrypted ciphertext blob (base64)
- 12-byte Nonce (hex)
- 32-byte Ephemeral Public Key (hex)
- Message timestamp
- Client IP address for rate-limiting

### What the Relay CANNOT See:
- **Plaintext Message Body:** The relay never possesses private keys and has zero access to message content.
- **Private Keys:** All signing keys and private DH keys are generated on-device and never leave the device.
- **User Metadata:** No phone numbers, emails, addresses, contacts, or third-party OAuth IDs exist in the system.

---

## 4. Message Storage & TTL
- Messages in relay storage are stored solely for store-and-forward delivery.
- Once a message is fetched by the authenticated recipient (`GET /v1/inbox` or streamed via `/v1/events`), it is immediately deleted from relay storage.
- An automated TTL cleaner purges any undelivered messages older than 48 hours.

---

## 5. Hardware-Backed Key Storage & Recovery
- **Hardware Encryption at Rest:** Identity private keys (`sign_priv`, `dh_priv`) are encrypted at rest using an **Android KeyStore** master key (`AES/GCM/NoPadding`, 256-bit) backed by hardware TEE or StrongBox Keymaster.
- **Dynamic Recovery Derivation:** The 64-byte master recovery seed is derived dynamically on-demand from the hardware-decrypted keys only when authenticated, eliminating plaintext recovery code storage in sandbox files.
- **Transport Security:** Production builds enforce strict TLS via Android Network Security Config (`cleartextTrafficPermitted="false"`).
