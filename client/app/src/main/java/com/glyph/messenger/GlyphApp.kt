package com.glyph.messenger

import android.app.Application
import android.util.Log
import com.glyph.messenger.crypto.ChatCrypto
import com.glyph.messenger.crypto.IdentityManager
import com.glyph.messenger.data.InboundMessage
import com.glyph.messenger.data.LocalStore
import com.glyph.messenger.data.RelayClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class GlyphApp : Application() {

    lateinit var identityManager: IdentityManager
        private set
    lateinit var relayClient: RelayClient
        private set
    lateinit var localStore: LocalStore
        private set

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val messageListeners = mutableListOf<(InboundMessage) -> Unit>()

    override fun onCreate() {
        super.onCreate()
        identityManager = IdentityManager(this)
        relayClient = RelayClient(this)
        localStore = LocalStore(this)

        startBackgroundMessageSync()
    }

    fun addMessageListener(listener: (InboundMessage) -> Unit) {
        synchronized(messageListeners) {
            messageListeners.add(listener)
        }
    }

    fun removeMessageListener(listener: (InboundMessage) -> Unit) {
        synchronized(messageListeners) {
            messageListeners.remove(listener)
        }
    }

    fun startBackgroundMessageSync() {
        appScope.launch {
            while (true) {
                val active = identityManager.getActiveIdentity()
                if (active != null) {
                    try {
                        // 1. Drain inbox on connect/wake
                        val inboxRes = relayClient.fetchInbox(active.username)
                        if (inboxRes.isSuccess) {
                            val messages = inboxRes.getOrNull() ?: emptyList()
                            for (msg in messages) {
                                processInboundMessage(active, msg)
                            }
                        }

                        // 2. Open live SSE stream
                        relayClient.streamEvents(active.username) { msg ->
                            processInboundMessage(active, msg)
                        }
                    } catch (e: Exception) {
                        Log.d("GlyphApp", "Sync loop error: ${e.message}")
                    }
                }
                delay(5000) // Reconnect delay
            }
        }
    }

    private fun processInboundMessage(activeIdentity: com.glyph.messenger.crypto.IdentityRecord, msg: InboundMessage) {
        appScope.launch {
            try {
                // Decrypt message with MAMA40 assembly
                val plaintext = ChatCrypto.decrypt(
                    ciphertextBase64 = msg.ciphertext,
                    nonceHex = msg.nonce,
                    ephemeralKeyHex = msg.ephemeralKey,
                    recipientDhPrivHex = activeIdentity.dhPrivKeyHex,
                    recipientDhPubHex = activeIdentity.dhPubKeyHex,
                    senderUsername = msg.sender,
                    recipientUsername = activeIdentity.username
                )

                // Save to local SQLite
                localStore.saveMessage(
                    peerUsername = msg.sender,
                    isOutgoing = false,
                    body = plaintext,
                    timestamp = msg.timestamp
                )

                // Dispatch to active UI listeners
                synchronized(messageListeners) {
                    for (l in messageListeners) {
                        l(msg.copy(ciphertext = plaintext))
                    }
                }
            } catch (e: Exception) {
                Log.e("GlyphApp", "Failed to decrypt inbound message from ${msg.sender}", e)
            }
        }
    }
}
