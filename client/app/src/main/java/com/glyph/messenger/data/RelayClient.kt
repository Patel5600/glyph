package com.glyph.messenger.data

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

data class PeerProfile(
    val username: String,
    val pubkeyHex: String,
    val isRevoked: Boolean
)

data class InboundMessage(
    val id: Long,
    val recipient: String,
    val sender: String,
    val ciphertext: String,
    val nonce: String,
    val ephemeralKey: String,
    val timestamp: Long
)

class RelayClient(private val context: Context) {

    companion object {
        private const val TAG = "GlyphRelay"
        private const val DEFAULT_RELAY_URL = "https://glyph-relay.onrender.com"
        private const val PREF_RELAY_URL = "relay_server_url"
    }

    private val prefs = context.getSharedPreferences("glyph_config", Context.MODE_PRIVATE)

    var relayBaseUrl: String
        get() = prefs.getString(PREF_RELAY_URL, DEFAULT_RELAY_URL) ?: DEFAULT_RELAY_URL
        set(value) = prefs.edit().putString(PREF_RELAY_URL, value.trimEnd('/')).apply()

    suspend fun claimUsername(username: String, pubkeyHex: String, sigHex: String, timestamp: Long): Result<Boolean> =
        withContext(Dispatchers.IO) {
            try {
                val url = URL("$relayBaseUrl/v1/claim")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    connectTimeout = 15000
                    readTimeout = 15000
                    doOutput = true
                }

                val payload = JSONObject().apply {
                    put("username", username)
                    put("pubkey", pubkeyHex)
                    put("sig", sigHex)
                    put("timestamp", timestamp)
                }

                OutputStreamWriter(conn.outputStream, "UTF-8").use {
                    it.write(payload.toString())
                    it.flush()
                }

                val code = conn.responseCode
                if (code == 201 || code == 200) {
                    Result.success(true)
                } else if (code == 409) {
                    Result.failure(Exception("Username is already taken by another key"))
                } else {
                    val err = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $code"
                    Result.failure(Exception("Claim failed ($code): $err"))
                }
            } catch (e: Exception) {
                Log.e(TAG, "claimUsername failed", e)
                Result.failure(e)
            }
        }

    suspend fun resolveUsername(username: String): Result<PeerProfile?> =
        withContext(Dispatchers.IO) {
            try {
                val url = URL("$relayBaseUrl/v1/resolve/$username")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = 15000
                    readTimeout = 15000
                }

                val code = conn.responseCode
                if (code == 404) {
                    return@withContext Result.success(null)
                }
                if (code != 200) {
                    return@withContext Result.failure(Exception("Resolve HTTP $code"))
                }

                val resp = conn.inputStream.bufferedReader().use { it.readText() }
                val obj = JSONObject(resp)
                Result.success(
                    PeerProfile(
                        username = obj.getString("username"),
                        pubkeyHex = obj.getString("pubkey"),
                        isRevoked = obj.optBoolean("revoked", false)
                    )
                )
            } catch (e: Exception) {
                Log.e(TAG, "resolveUsername failed", e)
                Result.failure(e)
            }
        }

    suspend fun sendMessage(
        recipient: String,
        sender: String,
        ciphertext: String,
        nonce: String,
        ephemeralKey: String
    ): Result<Long> = withContext(Dispatchers.IO) {
        try {
            val url = URL("$relayBaseUrl/v1/send")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                connectTimeout = 15000
                readTimeout = 15000
                doOutput = true
            }

            val payload = JSONObject().apply {
                put("recipient", recipient)
                put("sender", sender)
                put("ciphertext", ciphertext)
                put("nonce", nonce)
                put("ephemeral_key", ephemeralKey)
                put("timestamp", System.currentTimeMillis() / 1000)
            }

            OutputStreamWriter(conn.outputStream, "UTF-8").use {
                it.write(payload.toString())
                it.flush()
            }

            val code = conn.responseCode
            if (code == 202 || code == 200) {
                val resp = conn.inputStream.bufferedReader().use { it.readText() }
                val obj = JSONObject(resp)
                Result.success(obj.optLong("id", 0L))
            } else {
                val err = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $code"
                Result.failure(Exception("Send failed ($code): $err"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "sendMessage failed", e)
            Result.failure(e)
        }
    }

    suspend fun fetchInbox(username: String): Result<List<InboundMessage>> =
        withContext(Dispatchers.IO) {
            try {
                val url = URL("$relayBaseUrl/v1/inbox?username=$username")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = 15000
                    readTimeout = 15000
                }

                val code = conn.responseCode
                if (code != 200) {
                    return@withContext Result.failure(Exception("Fetch inbox HTTP $code"))
                }

                val resp = conn.inputStream.bufferedReader().use { it.readText() }
                val obj = JSONObject(resp)
                val arr = obj.getJSONArray("messages")
                val list = mutableListOf<InboundMessage>()

                for (i in 0 until arr.length()) {
                    val m = arr.getJSONObject(i)
                    list.add(
                        InboundMessage(
                            id = m.getLong("id"),
                            recipient = m.getString("recipient"),
                            sender = m.getString("sender"),
                            ciphertext = m.getString("ciphertext"),
                            nonce = m.getString("nonce"),
                            ephemeralKey = m.getString("ephemeral_key"),
                            timestamp = m.getLong("created_at")
                        )
                    )
                }

                Result.success(list)
            } catch (e: Exception) {
                Log.e(TAG, "fetchInbox failed", e)
                Result.failure(e)
            }
        }

    /**
     * Connects to Server-Sent Events (SSE) stream for real-time instant messaging.
     * Invokes onMessageReceived for each incoming decrypted packet.
     */
    suspend fun streamEvents(username: String, onMessage: (InboundMessage) -> Unit) =
        withContext(Dispatchers.IO) {
            try {
                val url = URL("$relayBaseUrl/v1/events?username=$username")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    setRequestProperty("Accept", "text/event-stream")
                    connectTimeout = 30000
                    readTimeout = 0 // Infinite stream
                }

                if (conn.responseCode != 200) {
                    Log.w(TAG, "SSE connection failed: ${conn.responseCode}")
                    return@withContext
                }

                val reader = BufferedReader(InputStreamReader(conn.inputStream, "UTF-8"))
                var line: String?

                while (reader.readLine().also { line = it } != null) {
                    val l = line?.trim() ?: continue
                    if (l.startsWith("data:")) {
                        val jsonStr = l.removePrefix("data:").trim()
                        if (jsonStr.startsWith("{") && jsonStr.contains("ciphertext")) {
                            try {
                                val m = JSONObject(jsonStr)
                                val msg = InboundMessage(
                                    id = m.optLong("id", 0L),
                                    recipient = m.getString("recipient"),
                                    sender = m.getString("sender"),
                                    ciphertext = m.getString("ciphertext"),
                                    nonce = m.getString("nonce"),
                                    ephemeralKey = m.getString("ephemeral_key"),
                                    timestamp = m.optLong("timestamp", System.currentTimeMillis() / 1000)
                                )
                                onMessage(msg)
                            } catch (e: Exception) {
                                Log.e(TAG, "SSE parse error", e)
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.d(TAG, "SSE stream disconnected: ${e.message}")
            }
        }
}
