# Security & Cryptographic Specification

## 1. Cryptographic Primitives (MAMA40 Engine)
Glyph Messenger utilizes the **MAMA40** bare-metal assembly cryptographic engine (ARM64 NEON & x86-64 AVX2) with zero dynamic heap allocations during message processing:
- **Signatures & Claims:** Ed25519 / MAMA Schnorr over Curve25519 for identity claim, rotation, and revocation.
- **Key Agreement:** X25519 ECDH (RFC 7748) combined with ephemeral Diffie-Hellman keys.
- **Symmetric Encryption & MAC:** ChaCha20-Poly1305 AEAD (RFC 8439) with 256-bit keys and 128-bit authentication tags.
- **Key Derivation (KDF):** SHA-256 over \(SS \parallel ek_{pub} \parallel pk_{recipient}\).
- **Post-Quantum Extension:** NIST FIPS 203 ML-KEM-768 primitives built into native binary for post-quantum hybrid ratcheting.

---

## 2. Nonce Rules & Uniqueness
1. **Nonce Size:** 96 bits (12 bytes) per RFC 8439.
2. **Generation:** Generated on device using `MamaCrypto.randomBytes(12)` immediately prior to each encryption operation.
3. **Uniqueness:** Guaranteed by cryptographically secure random generation combined with fresh ephemeral keypairs per message.
4. **Collision Prevention:** Because a fresh ephemeral keypair is generated per message, key-nonce reuse across messages is cryptographically impossible.

---

## 3. What the Relay Can and Cannot See

### What the Relay CAN See (Zero-Knowledge Metadata):
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
- **User Passwords / Emails / Phone Numbers:** No phone, email, or third-party OAuth IDs exist in the system.

---

## 4. Message Storage & TTL
- Messages in relay storage are stored solely for store-and-forward delivery.
- Once a message is fetched by the recipient (`GET /v1/inbox` or streamed via `/v1/events`), it is immediately deleted from relay storage.
- An automated TTL cleaner purges any undelivered messages older than 48 hours.

---

## 5. Key Recovery & Storage
- Private keys are stored in encrypted application sandbox storage protected by Android Keystore / Biometrics.
- A 64-byte master recovery seed is presented to the user **once** during onboarding in chunked hex format.
- Users must record this recovery code offline. The relay does not hold recovery keys.
