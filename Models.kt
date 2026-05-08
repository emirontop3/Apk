package com.bluechat.model

import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import kotlinx.serialization.Serializable

// ─── Message Types ────────────────────────────────────────────────────────────

enum class MessageType {
    CHAT,           // Normal chat message
    KEY_EXCHANGE,   // Public key advertisement
    DELIVERY_ACK,   // Read receipt
    PEER_ANNOUNCE,  // Peer discovery
    CHANNEL_JOIN,   // Join broadcast channel
    CHANNEL_LEAVE,  // Leave channel
    TYPING,         // Typing indicator
    PING,           // Keep-alive
    BLOCK_ANNOUNCE  // Relay: re-broadcast for mesh
}

enum class MessageStatus {
    SENDING,
    SENT,
    DELIVERED,
    READ,
    FAILED
}

@Serializable
data class WireMessage(
    val id: String,
    val type: String,           // MessageType.name
    val senderId: String,
    val senderPublicKey: String,
    val recipientId: String?,   // null = broadcast
    val channelId: String?,
    val payload: String,        // Encrypted or plain depending on type
    val signature: String,
    val timestamp: Long,
    val ttl: Int = 3,           // Hop count for mesh relay
    val nonce: String           // Anti-replay
)

@Serializable
data class ChatPayload(
    val text: String,
    val replyToId: String? = null,
    val attachmentType: String? = null  // Future: image/file
)

// ─── Local DB Models ─────────────────────────────────────────────────────────

data class Message(
    val id: String,
    val conversationId: String,  // peerId or channelId
    val senderId: String,
    val senderNickname: String,
    val text: String,
    val timestamp: Long,
    val status: MessageStatus,
    val isOutgoing: Boolean,
    val replyToId: String? = null,
    val isEncrypted: Boolean = true
)

@Parcelize
data class Peer(
    val id: String,
    val nickname: String,
    val publicKeyBase64: String,
    val fingerprint: String,
    val avatarSeed: String,
    val rssi: Int = -70,
    val lastSeen: Long = System.currentTimeMillis(),
    val isConnected: Boolean = false,
    val isTrusted: Boolean = false,
    val isBlocked: Boolean = false
) : Parcelable {
    val displayName: String get() = if (nickname.isBlank()) id.take(8) else nickname
    val signalStrength: SignalStrength get() = when {
        rssi >= -60 -> SignalStrength.EXCELLENT
        rssi >= -70 -> SignalStrength.GOOD
        rssi >= -80 -> SignalStrength.FAIR
        else -> SignalStrength.WEAK
    }
}

enum class SignalStrength { EXCELLENT, GOOD, FAIR, WEAK }

data class Channel(
    val id: String,
    val name: String,
    val isPrivate: Boolean = false,
    val passwordHash: String? = null,  // SHA-256 of password for private channels
    val memberCount: Int = 0,
    val unreadCount: Int = 0,
    val lastMessage: String? = null,
    val lastMessageTime: Long? = null,
    val isJoined: Boolean = false
)

data class Conversation(
    val peerId: String,
    val peerNickname: String,
    val peerAvatarSeed: String,
    val peerFingerprint: String,
    val lastMessage: String?,
    val lastMessageTime: Long?,
    val unreadCount: Int,
    val isOnline: Boolean,
    val isPinned: Boolean = false
)

// ─── Key Exchange ─────────────────────────────────────────────────────────────

@Serializable
data class KeyExchangePayload(
    val publicKey: String,
    val nickname: String,
    val userId: String,
    val avatarSeed: String,
    val timestamp: Long
)

// ─── Announce ─────────────────────────────────────────────────────────────────

@Serializable
data class PeerAnnouncePayload(
    val userId: String,
    val nickname: String,
    val publicKey: String,
    val avatarSeed: String,
    val channels: List<String> = emptyList()
)
