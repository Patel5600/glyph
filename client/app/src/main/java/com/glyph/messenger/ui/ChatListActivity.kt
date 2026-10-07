package com.glyph.messenger.ui

import android.app.AlertDialog
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
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.glyph.messenger.GlyphApp
import com.glyph.messenger.R
import com.glyph.messenger.data.InboundMessage
import com.glyph.messenger.data.RecentChat
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ChatListActivity : AppCompatActivity() {

    private lateinit var app: GlyphApp
    private lateinit var listChats: ListView
    private lateinit var txtEmpty: TextView
    private lateinit var txtActiveUsername: TextView
    private lateinit var btnNewChat: Button
    private lateinit var btnSettings: ImageButton

    private val chats = mutableListOf<RecentChat>()
    private lateinit var adapter: ChatAdapter

    private val messageListener: (InboundMessage) -> Unit = {
        runOnUiThread {
            loadRecentChats()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat_list)

        app = application as GlyphApp
        val active = app.identityManager.getActiveIdentity()
        if (active == null) {
            startActivity(Intent(this, OnboardingActivity::class.java))
            finish()
            return
        }

        initViews(active.username)
    }

    override fun onResume() {
        super.onResume()
        app.addMessageListener(messageListener)
        loadRecentChats()
    }

    override fun onPause() {
        super.onPause()
        app.removeMessageListener(messageListener)
    }

    private fun initViews(activeUsername: String) {
        listChats = findViewById(R.id.listChats)
        txtEmpty = findViewById(R.id.txtEmpty)
        txtActiveUsername = findViewById(R.id.txtActiveUsername)
        btnNewChat = findViewById(R.id.btnNewChat)
        btnSettings = findViewById(R.id.btnSettings)

        txtActiveUsername.text = "@$activeUsername"

        adapter = ChatAdapter()
        listChats.adapter = adapter

        listChats.setOnItemClickListener { _, _, position, _ ->
            val chat = chats[position]
            openChatThread(chat.peerUsername)
        }

        btnNewChat.setOnClickListener {
            showNewChatDialog()
        }

        btnSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    private fun loadRecentChats() {
        lifecycleScope.launch {
            val list = app.localStore.getRecentChats()
            chats.clear()
            chats.addAll(list)
            adapter.notifyDataSetChanged()
            txtEmpty.visibility = if (chats.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    private fun showNewChatDialog() {
        val container = android.widget.FrameLayout(this).apply {
            setPadding(48, 16, 48, 16)
        }
        val input = EditText(this).apply {
            hint = "Enter username (e.g. bob)"
            setSingleLine()
            setBackgroundResource(R.drawable.bg_input)
            setPadding(32, 24, 32, 24)
            setTextColor(getColor(R.color.text_primary))
            setHintTextColor(getColor(R.color.text_secondary))
        }
        container.addView(input)

        AlertDialog.Builder(this)
            .setTitle("New Encrypted Chat")
            .setMessage("Search peer username on the relay server:")
            .setView(container)
            .setPositiveButton("Start Chat") { _, _ ->
                val targetUser = input.text.toString().trim().lowercase()
                if (targetUser.isNotEmpty()) {
                    resolveAndStartChat(targetUser)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun resolveAndStartChat(targetUser: String) {
        val active = app.identityManager.getActiveIdentity() ?: return
        if (targetUser == active.username) {
            Toast.makeText(this, "Cannot chat with yourself", Toast.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch {
            Toast.makeText(this@ChatListActivity, "Resolving @$targetUser...", Toast.LENGTH_SHORT).show()
            val result = app.relayClient.resolveUsername(targetUser)
            if (result.isSuccess) {
                val profile = result.getOrNull()
                if (profile != null && !profile.isRevoked) {
                    // Save contact with public key
                    app.localStore.saveContact(profile.username, profile.pubkeyHex)
                    openChatThread(profile.username)
                } else {
                    Toast.makeText(this@ChatListActivity, "User @$targetUser not found or revoked", Toast.LENGTH_LONG).show()
                }
            } else {
                Toast.makeText(this@ChatListActivity, "Lookup error: ${result.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun openChatThread(peerUsername: String) {
        val intent = Intent(this, ChatThreadActivity::class.java).apply {
            putExtra(ChatThreadActivity.EXTRA_PEER_USERNAME, peerUsername)
        }
        startActivity(intent)
    }

    inner class ChatAdapter : BaseAdapter() {
        private val timeFormat = SimpleDateFormat("HH:mm", Locale.getDefault())

        override fun getCount(): Int = chats.size
        override fun getItem(position: Int): Any = chats[position]
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val view = convertView ?: LayoutInflater.from(this@ChatListActivity)
                .inflate(R.layout.item_chat_thread, parent, false)

            val chat = chats[position]
            val txtAvatar = view.findViewById<TextView>(R.id.txtAvatar)
            val txtPeerName = view.findViewById<TextView>(R.id.txtPeerName)
            val txtLastSnippet = view.findViewById<TextView>(R.id.txtLastSnippet)
            val txtTimestamp = view.findViewById<TextView>(R.id.txtTimestamp)

            txtAvatar.text = chat.peerUsername.take(1).uppercase()
            txtPeerName.text = "@${chat.peerUsername}"
            txtLastSnippet.text = chat.lastMessage
            txtTimestamp.text = timeFormat.format(Date(chat.timestamp * 1000))

            return view
        }
    }
}
