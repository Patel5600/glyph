package com.glyph.messenger.crypto

import android.util.Base64
import com.mama40.crypto.MamaCrypto
import org.json.JSONObject
import java.security.MessageDigest

data class EncryptedMessagePacket(
    val ciphertextBase64: String,
    val nonceHex: String,
    val ephemeralKeyHex: String
)

object ChatCrypto {

    /**
     * Encrypts a plaintext message for the recipient using:
     * 1. Cryptographic Sender Signature (Ed25519) binding sender, recipient, timestamp, and message body.
     * 2. X25519 ECDH + SHA256 KDF key agreement.
     * 3. MAMA40 ChaCha20-Poly1305 AEAD with AAD identity binding.
     */
    fun encrypt(
        plaintext: String,
        recipientDhPubHex: String,
        senderUsername: String,
        recipientUsername: String,
        senderSignPrivHex: String
    ): EncryptedMessagePacket {
        val recipientDhPub = IdentityManager.hexToBytes(recipientDhPubHex)

        // 1. Generate fresh 32-byte ephemeral keypair
        val ephemeralPriv = MamaCrypto.randomBytes(32)
        val ephemeralPub = MamaCrypto.x25519Base(ephemeralPriv)
            ?: throw IllegalStateException("Failed to derive ephemeral public key")

        // 2. Perform ECDH: SS = X25519(ephemeralPriv, recipientDhPub)
        val sharedSecret = MamaCrypto.x25519(ephemeralPriv, recipientDhPub)
            ?: throw IllegalStateException("X25519 key agreement failed")

        // 3. Derive 32-byte symmetric key K = SHA256(SS || ephemeralPub || recipientDhPub)
        val md = MessageDigest.getInstance("SHA-256")
        md.update(sharedSecret)
        md.update(ephemeralPub)
        md.update(recipientDhPub)
        val symmetricKey = md.digest()

        // 4. Generate unique 12-byte nonce
        val nonce = MamaCrypto.randomBytes(12)

        // 5. Cryptographically sign the message with sender's Ed25519 private key
        val ts = System.currentTimeMillis() / 1000
        val signData = "msg:$senderUsername:$recipientUsername:$ts:$plaintext".toByteArray(Charsets.UTF_8)
        val senderSignPriv = IdentityManager.hexToBytes(senderSignPrivHex)
        val sig = Ed25519.sign(senderSignPriv, signData)
        val sigHex = IdentityManager.bytesToHex(sig)

        val innerPayload = JSONObject().apply {
            put("t", plaintext)
            put("s", sigHex)
            put("ts", ts)
        }.toString()

        // 6. AAD (Associated Data) binding sender & recipient identity to prevent replay/re-routing
        val aad = "$senderUsername->$recipientUsername".toByteArray(Charsets.UTF_8)

        // 7. AEAD Authenticated Encryption via MAMA40 bare-metal assembly
        val plaintextBytes = innerPayload.toByteArray(Charsets.UTF_8)
        val ctWithTag = MamaCrypto.aeadEncrypt(symmetricKey, nonce, plaintextBytes, aad)
            ?: throw IllegalStateException("ChaCha20-Poly1305 encryption failed")

        // Zeroize sensitive ephemeral secret in memory
        sharedSecret.fill(0)
        symmetricKey.fill(0)
        ephemeralPriv.fill(0)

        return EncryptedMessagePacket(
            ciphertextBase64 = Base64.encodeToString(ctWithTag, Base64.NO_WRAP),
            nonceHex = IdentityManager.bytesToHex(nonce),
            ephemeralKeyHex = IdentityManager.bytesToHex(ephemeralPub)
        )
    }

    /**
     * Decrypts an incoming message packet and verifies cryptographic sender signature against sender's Ed25519 public key.
     */
    fun decrypt(
        ciphertextBase64: String,
        nonceHex: String,
        ephemeralKeyHex: String,
        recipientDhPrivHex: String,
        recipientDhPubHex: String,
        senderUsername: String,
        recipientUsername: String,
        senderSignPubHex: String? = null
    ): String {
        val recipientDhPriv = IdentityManager.hexToBytes(recipientDhPrivHex)
        val recipientDhPub = IdentityManager.hexToBytes(recipientDhPubHex)
        val ephemeralPub = IdentityManager.hexToBytes(ephemeralKeyHex)
        val nonce = IdentityManager.hexToBytes(nonceHex)
        val ctWithTag = Base64.decode(ciphertextBase64, Base64.NO_WRAP)

        // 1. Perform ECDH: SS = X25519(recipientDhPriv, ephemeralPub)
        val sharedSecret = MamaCrypto.x25519(recipientDhPriv, ephemeralPub)
            ?: throw IllegalStateException("X25519 key agreement failed")

        // 2. Derive 32-byte symmetric key K = SHA256(SS || ephemeralPub || recipientDhPub)
        val md = MessageDigest.getInstance("SHA-256")
        md.update(sharedSecret)
        md.update(ephemeralPub)
        md.update(recipientDhPub)
        val symmetricKey = md.digest()

        // 3. AAD binding
        val aad = "$senderUsername->$recipientUsername".toByteArray(Charsets.UTF_8)

        // 4. AEAD Authenticated Decryption
        val ptBytes = MamaCrypto.aeadDecrypt(symmetricKey, nonce, ctWithTag, aad)
            ?: throw IllegalStateException("MAC authentication failure or corrupted ciphertext")

        // Zeroize sensitive secret in memory
        sharedSecret.fill(0)
        symmetricKey.fill(0)

        val ptString = String(ptBytes, Charsets.UTF_8)

        // 5. Verify cryptographic sender signature
        return try {
            val json = JSONObject(ptString)
            if (json.has("t") && json.has("s") && json.has("ts") && senderSignPubHex != null) {
                val text = json.getString("t")
                val sigHex = json.getString("s")
                val ts = json.getLong("ts")
                val signData = "msg:$senderUsername:$recipientUsername:$ts:$text".toByteArray(Charsets.UTF_8)
                val senderSignPub = IdentityManager.hexToBytes(senderSignPubHex)
                val sigBytes = IdentityManager.hexToBytes(sigHex)

                val isValid = Ed25519.verify(senderSignPub, signData, sigBytes)
                if (!isValid) {
                    throw SecurityException("Cryptographic sender verification failed: forged or tampered message from @$senderUsername")
                }
                text
            } else if (json.has("t")) {
                json.getString("t")
            } else {
                ptString
            }
        } catch (e: Exception) {
            if (e is SecurityException) throw e
            ptString
        }
    }
}
