package com.glyph.messenger.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.mama40.crypto.MamaCrypto
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

data class IdentityRecord(
    val username: String,
    val signPubKeyHex: String,
    val signPrivKeyHex: String,
    val dhPubKeyHex: String,
    val dhPrivKeyHex: String,
    val recoveryCode: String
)

class IdentityManager(private val context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences("glyph_identities", Context.MODE_PRIVATE)

    companion object {
        const val MAX_IDENTITIES = 3
        const val PREF_ACTIVE_USER = "active_username"
        const val PREF_IDENTITIES_LIST = "identities_list"

        fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        fun hexToBytes(hex: String): ByteArray {
            val len = hex.length
            val data = ByteArray(len / 2)
            for (i in 0 until len step 2) {
                data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            }
            return data
        }
    }

    init {
        MamaCrypto.init()
    }

    fun getActiveIdentity(): IdentityRecord? {
        val activeUser = prefs.getString(PREF_ACTIVE_USER, null) ?: return null
        return getIdentity(activeUser)
    }

    fun getIdentity(username: String): IdentityRecord? {
        val jsonStr = prefs.getString("id_$username", null) ?: return null
        return try {
            val obj = JSONObject(jsonStr)
            IdentityRecord(
                username = obj.getString("username"),
                signPubKeyHex = obj.getString("sign_pub"),
                signPrivKeyHex = obj.getString("sign_priv"),
                dhPubKeyHex = obj.getString("dh_pub"),
                dhPrivKeyHex = obj.getString("dh_priv"),
                recoveryCode = obj.getString("recovery_code")
            )
        } catch (e: Exception) {
            null
        }
    }

    fun listIdentities(): List<String> {
        val listJson = prefs.getString(PREF_IDENTITIES_LIST, "[]") ?: "[]"
        val array = JSONArray(listJson)
        val list = mutableListOf<String>()
        for (i in 0 until array.length()) {
            list.add(array.getString(i))
        }
        return list
    }

    fun setActiveIdentity(username: String) {
        prefs.edit().putString(PREF_ACTIVE_USER, username).apply()
    }

    /**
     * Creates a new identity bounded to the given username.
     * Uses MAMA40 bare-metal assembly for key generation and digital signing.
     */
    fun createIdentity(username: String): IdentityRecord {
        val existingList = listIdentities().toMutableList()
        require(existingList.size < MAX_IDENTITIES) { "Maximum $MAX_IDENTITIES identities reached" }

        // 1. Generate 32-byte Ed25519 private seed and derive public key
        val signPriv = MamaCrypto.randomBytes(32)
        val signPub = Ed25519.derivePublicKey(signPriv)

        // 2. Generate X25519 DH keypair for E2EE chat (using MAMA40 assembly engine)
        val dhPriv = MamaCrypto.randomBytes(32)
        val dhPub = MamaCrypto.x25519Base(dhPriv) ?: throw IllegalStateException("Failed to derive DH public key")

        // 3. Format a clean 24-word/chunk recovery code from private keys
        val recoverySeed = ByteArray(64)
        System.arraycopy(signPriv, 0, recoverySeed, 0, 32)
        System.arraycopy(dhPriv, 0, recoverySeed, 32, 32)
        val recoveryCode = bytesToHex(recoverySeed).chunked(4).joinToString("-")

        val record = IdentityRecord(
            username = username,
            signPubKeyHex = bytesToHex(signPub),
            signPrivKeyHex = bytesToHex(signPriv),
            dhPubKeyHex = bytesToHex(dhPub),
            dhPrivKeyHex = bytesToHex(dhPriv),
            recoveryCode = recoveryCode
        )

        // Save to preferences
        val obj = JSONObject().apply {
            put("username", record.username)
            put("sign_pub", record.signPubKeyHex)
            put("sign_priv", record.signPrivKeyHex)
            put("dh_pub", record.dhPubKeyHex)
            put("dh_priv", record.dhPrivKeyHex)
            put("recovery_code", record.recoveryCode)
        }

        if (!existingList.contains(username)) {
            existingList.add(username)
        }

        prefs.edit()
            .putString("id_$username", obj.toString())
            .putString(PREF_IDENTITIES_LIST, JSONArray(existingList).toString())
            .putString(PREF_ACTIVE_USER, username)
            .apply()

        return record
    }

    /**
     * Signs the identity claim message: "claim:<username>:<timestamp>" using Ed25519
     */
    fun signClaim(record: IdentityRecord, timestamp: Long): String {
        val msg = "claim:${record.username}:$timestamp".toByteArray(Charsets.UTF_8)
        val privBytes = hexToBytes(record.signPrivKeyHex)
        val sig = Ed25519.sign(privBytes, msg)
        return bytesToHex(sig)
    }
}
