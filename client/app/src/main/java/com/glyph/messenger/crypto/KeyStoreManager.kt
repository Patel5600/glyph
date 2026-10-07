package com.glyph.messenger.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed key manager utilizing Android KeyStore (TEE / StrongBox).
 * Protects long-term identity keys (Ed25519 & X25519) via AES-256-GCM hardware encryption at rest.
 */
class KeyStoreManager {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val MASTER_KEY_ALIAS = "glyph_master_key_v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val GCM_IV_LENGTH_BYTES = 12
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    init {
        ensureMasterKey()
    }

    private fun ensureMasterKey() {
        if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            generateMasterKey()
        }
    }

    private fun generateMasterKey() {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val specBuilder = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)

        try {
            // Attempt StrongBox hardware security module first
            val strongBoxSpec = KeyGenParameterSpec.Builder(
                MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .setIsStrongBoxBacked(true)
                .build()

            keyGenerator.init(strongBoxSpec)
            keyGenerator.generateKey()
        } catch (e: Exception) {
            // Fall back to standard TEE (Trusted Execution Environment) hardware backing
            keyGenerator.init(specBuilder.build())
            keyGenerator.generateKey()
        }
    }

    private fun getMasterKey(): SecretKey {
        return keyStore.getKey(MASTER_KEY_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("Master key not found in Android KeyStore")
    }

    /**
     * Encrypts sensitive raw bytes using AES-256-GCM.
     * Returns Base64-encoded string: [12-byte IV || Ciphertext + Tag].
     */
    fun encrypt(plaintext: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getMasterKey())
        val iv = cipher.iv
        val ciphertextWithTag = cipher.doFinal(plaintext)

        val combined = ByteArray(iv.size + ciphertextWithTag.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(ciphertextWithTag, 0, combined, iv.size, ciphertextWithTag.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    /**
     * Decrypts Base64-encoded [12-byte IV || Ciphertext + Tag] using AES-256-GCM.
     */
    fun decrypt(ciphertextBase64: String): ByteArray {
        val combined = Base64.decode(ciphertextBase64, Base64.NO_WRAP)
        require(combined.size > GCM_IV_LENGTH_BYTES) { "Invalid encrypted payload size" }

        val iv = ByteArray(GCM_IV_LENGTH_BYTES)
        val ciphertext = ByteArray(combined.size - GCM_IV_LENGTH_BYTES)

        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH_BYTES)
        System.arraycopy(combined, GCM_IV_LENGTH_BYTES, ciphertext, 0, ciphertext.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, getMasterKey(), spec)

        return cipher.doFinal(ciphertext)
    }
}
