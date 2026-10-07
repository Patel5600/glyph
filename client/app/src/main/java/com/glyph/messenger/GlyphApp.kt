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
                        val ts = System.currentTimeMillis() / 1000
                        val inboxSig = identityManager.signAuth(active, "inbox", ts)

                        // 1. Drain inbox on connect/wake
                        val inboxRes = relayClient.fetchInbox(active.username, ts, inboxSig)
                        if (inboxRes.isSuccess) {
                            val messages = inboxRes.getOrNull() ?: emptyList()
                            for (msg in messages) {
                                processInboundMessage(active, msg)
                            }
                        }

                        // 2. Open live SSE stream
                        val eventsTs = System.currentTimeMillis() / 1000
                        val eventsSig = identityManager.signAuth(active, "events", eventsTs)
                        relayClient.streamEvents(active.username, eventsTs, eventsSig) { msg ->
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
                // Ensure sender contact is resolved so we have their identity public key
                var contact = localStore.getContact(msg.sender)
                if (contact == null) {
                    val res = relayClient.resolveUsername(msg.sender)
                    if (res.isSuccess) {
                        val p = res.getOrNull()
                        if (p != null) {
                            localStore.saveContact(p.username, p.pubkeyHex)
                            contact = com.glyph.messenger.data.ContactRecord(p.username, p.pubkeyHex, System.currentTimeMillis() / 1000)
                        }
                    }
                }

                // Decrypt and cryptographically verify sender signature
                val plaintext = ChatCrypto.decrypt(
                    ciphertextBase64 = msg.ciphertext,
                    nonceHex = msg.nonce,
                    ephemeralKeyHex = msg.ephemeralKey,
                    recipientDhPrivHex = activeIdentity.dhPrivKeyHex,
                    recipientDhPubHex = activeIdentity.dhPubKeyHex,
                    senderUsername = msg.sender,
                    recipientUsername = activeIdentity.username,
                    senderSignPubHex = contact?.dhPubHex
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
                Log.e("GlyphApp", "Failed to decrypt/verify inbound message from ${msg.sender}", e)
            }
        }
    }
}
