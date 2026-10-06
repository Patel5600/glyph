package com.mama40.crypto

/**
 * MAMA40 Cryptographic Engine JNI Binding.
 * Backed by handcrafted bare-metal ARM64 assembly with zero dynamic allocations.
 */
class MamaCrypto private constructor() {
    companion object {
        init {
            try {
                System.loadLibrary("mama")
            } catch (e: UnsatisfiedLinkError) {
                System.loadLibrary("mama_crypto")
            }
        }

        @JvmStatic external fun init(): Int
        @JvmStatic external fun randomBytes(len: Int): ByteArray
        @JvmStatic external fun sign(msg: ByteArray, privKey: ByteArray, pubKey: ByteArray): ByteArray
        @JvmStatic external fun verify(sig: ByteArray, msg: ByteArray, pubKey: ByteArray): Boolean
        @JvmStatic external fun x25519(privKey: ByteArray, pubKey: ByteArray): ByteArray?
        @JvmStatic external fun x25519Base(privKey: ByteArray): ByteArray?
        @JvmStatic external fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray?): ByteArray?
        @JvmStatic external fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray, aad: ByteArray?): ByteArray?
    }
}
