package com.glyph.messenger.crypto

import android.util.Base64
import com.mama40.crypto.MamaCrypto
import java.security.MessageDigest

data class EncryptedMessagePacket(
    val ciphertextBase64: String,
    val nonceHex: String,
    val ephemeralKeyHex: String
)

object ChatCrypto {

    /**
     * Encrypts a plaintext message for the recipient using X25519 ECDH + SHA256 KDF + MAMA40 ChaCha20-Poly1305 AEAD.
     */
    fun encrypt(plaintext: String, recipientDhPubHex: String, senderUsername: String, recipientUsername: String): EncryptedMessagePacket {
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

        // 5. AAD (Associated Data) binding sender & recipient identity to prevent replay/re-routing
        val aad = "$senderUsername->$recipientUsername".toByteArray(Charsets.UTF_8)

        // 6. AEAD Authenticated Encryption via MAMA40 bare-metal assembly
        val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
        val ctWithTag = MamaCrypto.aeadEncrypt(symmetricKey, nonce, plaintextBytes, aad)
            ?: throw IllegalStateException("ChaCha20-Poly1305 encryption failed")

        return EncryptedMessagePacket(
            ciphertextBase64 = Base64.encodeToString(ctWithTag, Base64.NO_WRAP),
            nonceHex = IdentityManager.bytesToHex(nonce),
            ephemeralKeyHex = IdentityManager.bytesToHex(ephemeralPub)
        )
    }

    /**
     * Decrypts an incoming message packet using the recipient's private DH key.
     */
    fun decrypt(
        ciphertextBase64: String,
        nonceHex: String,
        ephemeralKeyHex: String,
        recipientDhPrivHex: String,
        recipientDhPubHex: String,
        senderUsername: String,
        recipientUsername: String
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

        return String(ptBytes, Charsets.UTF_8)
    }
}
