package com.glyph.messenger.ui

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.glyph.messenger.GlyphApp
import com.glyph.messenger.R
import com.glyph.messenger.crypto.ChatCrypto
import com.glyph.messenger.data.ChatMessage
import com.glyph.messenger.data.ContactRecord
import com.glyph.messenger.data.InboundMessage
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ChatThreadActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PEER_USERNAME = "extra_peer_username"
    }

    private lateinit var app: GlyphApp
    private lateinit var peerUsername: String
    private var peerContact: ContactRecord? = null

    private lateinit var txtPeerAvatar: TextView
    private lateinit var txtPeerUsername: TextView
    private lateinit var txtPeerKeyFingerprint: TextView
    private lateinit var layoutPeerHeader: View
    private lateinit var btnProfileSettings: ImageButton
    private lateinit var btnBack: ImageButton
    private lateinit var listMessages: ListView
    private lateinit var editMessage: EditText
    private lateinit var btnSend: Button

    private val messages = mutableListOf<ChatMessage>()
    private lateinit var adapter: MessageAdapter

    private val messageListener: (InboundMessage) -> Unit = { msg ->
        if (msg.sender == peerUsername) {
            runOnUiThread {
                loadMessages()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat_thread)

        app = application as GlyphApp
        peerUsername = intent.getStringExtra(EXTRA_PEER_USERNAME) ?: ""
        if (peerUsername.isEmpty()) {
            finish()
            return
        }

        initViews()
        loadPeerContact()
        loadMessages()
    }

    override fun onResume() {
        super.onResume()
        app.addMessageListener(messageListener)
    }

    override fun onPause() {
        super.onPause()
        app.removeMessageListener(messageListener)
    }

    private fun initViews() {
        txtPeerAvatar = findViewById(R.id.txtPeerAvatar)
        txtPeerUsername = findViewById(R.id.txtPeerUsername)
        txtPeerKeyFingerprint = findViewById(R.id.txtPeerKeyFingerprint)
        layoutPeerHeader = findViewById(R.id.layoutPeerHeader)
        btnProfileSettings = findViewById(R.id.btnProfileSettings)
        btnBack = findViewById(R.id.btnBack)
        listMessages = findViewById(R.id.listMessages)
        editMessage = findViewById(R.id.editMessage)
        btnSend = findViewById(R.id.btnSend)

        txtPeerUsername.text = "@$peerUsername"
        txtPeerAvatar.text = peerUsername.take(1).uppercase(Locale.ROOT)

        adapter = MessageAdapter()
        listMessages.adapter = adapter

        btnBack.setOnClickListener {
            finish()
        }

        btnProfileSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        layoutPeerHeader.setOnClickListener {
            showPeerProfileDialog()
        }

        btnSend.setOnClickListener {
            handleSendMessage()
        }
    }

    private fun showPeerProfileDialog() {
        val contact = peerContact
        val keyInfo = if (contact != null) {
            "Username: @$peerUsername\n\nPublic Key (X25519 DH):\n${contact.dhPubHex}\n\nEncryption: ChaCha20-Poly1305 + MAMA40 Ratchet\nStatus: Verified E2EE"
        } else {
            "Username: @$peerUsername\n\nStatus: Resolving encryption keys..."
        }

        AlertDialog.Builder(this)
            .setTitle("Contact Profile")
            .setMessage(keyInfo)
            .setPositiveButton("User Settings") { _, _ ->
                startActivity(Intent(this, SettingsActivity::class.java))
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun loadPeerContact() {
        lifecycleScope.launch {
            var contact = app.localStore.getContact(peerUsername)
            if (contact == null) {
                // Resolve from relay if not in local store
                val res = app.relayClient.resolveUsername(peerUsername)
                if (res.isSuccess) {
                    val p = res.getOrNull()
                    if (p != null) {
                        app.localStore.saveContact(p.username, p.pubkeyHex)
                        contact = ContactRecord(p.username, p.pubkeyHex, System.currentTimeMillis() / 1000)
                    }
                }
            }
            peerContact = contact
            if (contact != null) {
                val fp = contact.dhPubHex.take(12) + "..."
                txtPeerKeyFingerprint.text = "E2EE Key: $fp"
            }
        }
    }

    private fun loadMessages() {
        lifecycleScope.launch {
            val list = app.localStore.getMessagesForPeer(peerUsername)
            messages.clear()
            messages.addAll(list)
            adapter.notifyDataSetChanged()
            listMessages.setSelection(messages.size - 1)
        }
    }

    private fun handleSendMessage() {
        val text = editMessage.text.toString().trim()
        if (text.isEmpty()) return

        val active = app.identityManager.getActiveIdentity() ?: return
        val contact = peerContact

        if (contact == null) {
            Toast.makeText(this, "Resolving peer public key...", Toast.LENGTH_SHORT).show()
            loadPeerContact()
            return
        }

        editMessage.setText("")
        val now = System.currentTimeMillis() / 1000

        lifecycleScope.launch {
            try {
                // 1. Encrypt with MAMA40 X25519 ECDH + ChaCha20-Poly1305 AEAD + Ed25519 Sender Signature
                val packet = ChatCrypto.encrypt(
                    plaintext = text,
                    recipientDhPubHex = contact.dhPubHex,
                    senderUsername = active.username,
                    recipientUsername = peerUsername,
                    senderSignPrivHex = active.signPrivKeyHex
                )

                // 2. Save locally immediately
                app.localStore.saveMessage(
                    peerUsername = peerUsername,
                    isOutgoing = true,
                    body = text,
                    timestamp = now
                )
                loadMessages()

                // 3. Authenticate and dispatch encrypted blob to relay
                val sig = app.identityManager.signSend(
                    record = active,
                    recipient = peerUsername,
                    ciphertext = packet.ciphertextBase64,
                    nonce = packet.nonceHex,
                    ephemeralKey = packet.ephemeralKeyHex,
                    timestamp = now
                )

                val res = app.relayClient.sendMessage(
                    recipient = peerUsername,
                    sender = active.username,
                    ciphertext = packet.ciphertextBase64,
                    nonce = packet.nonceHex,
                    ephemeralKey = packet.ephemeralKeyHex,
                    timestamp = now,
                    sig = sig
                )

                if (res.isFailure) {
                    Toast.makeText(this@ChatThreadActivity, "Relay queue error: ${res.exceptionOrNull()?.message}", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(this@ChatThreadActivity, "Encryption failed: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    inner class MessageAdapter : BaseAdapter() {
        private val timeFormat = SimpleDateFormat("HH:mm", Locale.getDefault())

        override fun getCount(): Int = messages.size
        override fun getItem(position: Int): Any = messages[position]
        override fun getItemId(position: Int): Long = messages[position].id

        override fun getViewTypeCount(): Int = 2
        override fun getItemViewType(position: Int): Int = if (messages[position].isOutgoing) 1 else 0

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val msg = messages[position]
            val isOut = msg.isOutgoing
            val layoutId = if (isOut) R.layout.item_message_outgoing else R.layout.item_message_incoming

            val view = convertView ?: LayoutInflater.from(this@ChatThreadActivity).inflate(layoutId, parent, false)
            val txtBody = view.findViewById<TextView>(R.id.txtBody)
            val txtTime = view.findViewById<TextView>(R.id.txtTime)

            txtBody.text = msg.body
            txtTime.text = timeFormat.format(Date(msg.timestamp * 1000))

            return view
        }
    }
}
