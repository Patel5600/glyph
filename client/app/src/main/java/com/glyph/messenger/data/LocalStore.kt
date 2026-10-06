package com.glyph.messenger.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class ContactRecord(
    val username: String,
    val dhPubHex: String,
    val lastSeen: Long
)

data class ChatMessage(
    val id: Long,
    val peerUsername: String,
    val isOutgoing: Boolean,
    val body: String,
    val timestamp: Long,
    val status: Int // 0 = sending, 1 = sent, 2 = delivered/received
)

data class RecentChat(
    val peerUsername: String,
    val lastMessage: String,
    val timestamp: Long,
    val unreadCount: Int
)

class LocalStore(context: Context) : SQLiteOpenHelper(context, "glyph_messenger.db", null, 1) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS contacts (
                username TEXT PRIMARY KEY,
                dh_pub TEXT NOT NULL,
                last_seen INTEGER NOT NULL
            );
            """.trimIndent()
        )

        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_username TEXT NOT NULL,
                is_outgoing INTEGER NOT NULL,
                body TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                status INTEGER NOT NULL DEFAULT 1
            );
            """.trimIndent()
        )

        db.execSQL("CREATE INDEX IF NOT EXISTS idx_peer_time ON messages(peer_username, timestamp);")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Future migrations
    }

    suspend fun saveContact(username: String, dhPubHex: String): Unit = withContext(Dispatchers.IO) {
        val cv = ContentValues().apply {
            put("username", username)
            put("dh_pub", dhPubHex)
            put("last_seen", System.currentTimeMillis() / 1000)
        }
        writableDatabase.insertWithOnConflict("contacts", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
    }

    suspend fun getContact(username: String): ContactRecord? = withContext(Dispatchers.IO) {
        readableDatabase.query(
            "contacts",
            arrayOf("username", "dh_pub", "last_seen"),
            "username = ?",
            arrayOf(username),
            null, null, null
        ).use { cursor ->
            if (cursor.moveToFirst()) {
                ContactRecord(
                    username = cursor.getString(0),
                    dhPubHex = cursor.getString(1),
                    lastSeen = cursor.getLong(2)
                )
            } else {
                null
            }
        }
    }

    suspend fun saveMessage(
        peerUsername: String,
        isOutgoing: Boolean,
        body: String,
        timestamp: Long = System.currentTimeMillis() / 1000
    ): Long = withContext(Dispatchers.IO) {
        val cv = ContentValues().apply {
            put("peer_username", peerUsername)
            put("is_outgoing", if (isOutgoing) 1 else 0)
            put("body", body)
            put("timestamp", timestamp)
            put("status", 1)
        }
        writableDatabase.insert("messages", null, cv)
    }

    suspend fun getMessagesForPeer(peerUsername: String): List<ChatMessage> = withContext(Dispatchers.IO) {
        val list = mutableListOf<ChatMessage>()
        readableDatabase.query(
            "messages",
            arrayOf("id", "peer_username", "is_outgoing", "body", "timestamp", "status"),
            "peer_username = ?",
            arrayOf(peerUsername),
            null, null,
            "id ASC"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                list.add(
                    ChatMessage(
                        id = cursor.getLong(0),
                        peerUsername = cursor.getString(1),
                        isOutgoing = cursor.getInt(2) == 1,
                        body = cursor.getString(3),
                        timestamp = cursor.getLong(4),
                        status = cursor.getInt(5)
                    )
                )
            }
        }
        list
    }

    suspend fun getRecentChats(): List<RecentChat> = withContext(Dispatchers.IO) {
        val list = mutableListOf<RecentChat>()
        val sql = """
            SELECT peer_username, body, timestamp
            FROM messages
            WHERE id IN (
                SELECT MAX(id) FROM messages GROUP BY peer_username
            )
            ORDER BY timestamp DESC
        """.trimIndent()

        readableDatabase.rawQuery(sql, null).use { cursor ->
            while (cursor.moveToNext()) {
                list.add(
                    RecentChat(
                        peerUsername = cursor.getString(0),
                        lastMessage = cursor.getString(1),
                        timestamp = cursor.getLong(2),
                        unreadCount = 0
                    )
                )
            }
        }
        list
    }
}
