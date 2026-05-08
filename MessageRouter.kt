package com.bluechat.bluetooth

import android.util.Log
import com.bluechat.crypto.CryptoManager
import com.bluechat.crypto.Identity
import com.bluechat.model.*
import kotlinx.coroutines.flow.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.concurrent.ConcurrentHashMap

/**
 * MessageRouter orchestrates:
 * - Message serialization/deserialization
 * - End-to-end encryption per peer
 * - Mesh relay (TTL-based forwarding)
 * - Anti-replay protection (seen message IDs)
 * - Key exchange with discovered peers
 * - Channel management
 */
class MessageRouter(
    private val meshManager: BluetoothMeshManager,
    private val identity: Identity
) {
    companion object {
        private const val TAG = "MessageRouter"
        private const val SEEN_MSG_CACHE_SIZE = 500
    }

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    // Cache of seen message IDs for anti-replay
    private val seenMessageIds = LinkedHashSet<String>()

    // Shared secrets per peer (peerUserId -> secret)
    private val sharedSecrets = ConcurrentHashMap<String, ByteArray>()

    // Known peer public keys (peerUserId -> publicKeyBytes)
    private val knownPeerKeys = ConcurrentHashMap<String, ByteArray>()

    // Address -> userId mapping
    private val addressToUserId = ConcurrentHashMap<String, String>()
    private val userIdToAddress = ConcurrentHashMap<String, String>()

    // Known peers
    private val _peers = MutableStateFlow<Map<String, Peer>>(emptyMap())
    val peers: StateFlow<Map<String, Peer>> = _peers

    // Incoming decrypted messages
    private val _messages = MutableSharedFlow<Message>(replay = 0, extraBufferCapacity = 100)
    val messages: SharedFlow<Message> = _messages

    // Typing indicators
    private val _typingPeers = MutableStateFlow<Set<String>>(emptySet())
    val typingPeers: StateFlow<Set<String>> = _typingPeers

    // ─── Init ─────────────────────────────────────────────────────────────────

    suspend fun start() {
        // Listen for incoming raw messages from BLE layer
        meshManager.incomingMessages.collect { (address, data) ->
            processIncoming(address, data)
        }
    }

    // ─── Incoming Processing ──────────────────────────────────────────────────

    private suspend fun processIncoming(fromAddress: String, data: ByteArray) {
        try {
            val raw = String(data, Charsets.UTF_8)
            val wire = json.decodeFromString<WireMessage>(raw)

            // Anti-replay: drop already-seen messages
            if (isSeenMessage(wire.id)) {
                Log.d(TAG, "Dropping duplicate: ${wire.id}")
                return
            }
            markSeen(wire.id)

            // Don't process our own messages relayed back
            if (wire.senderId == identity.userId) return

            val type = MessageType.valueOf(wire.type)

            // Relay if TTL > 0 and it's not for us specifically
            val forUs = wire.recipientId == null || wire.recipientId == identity.userId
            if (!forUs && wire.ttl > 0) {
                relayMessage(wire)
                return
            }

            when (type) {
                MessageType.KEY_EXCHANGE -> handleKeyExchange(fromAddress, wire)
                MessageType.PEER_ANNOUNCE -> handlePeerAnnounce(fromAddress, wire)
                MessageType.CHAT -> handleChat(fromAddress, wire)
                MessageType.DELIVERY_ACK -> handleAck(wire)
                MessageType.TYPING -> handleTyping(wire)
                MessageType.PING -> handlePing(fromAddress)
                MessageType.CHANNEL_JOIN -> { /* handle channel */ }
                else -> {}
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing incoming: ${e.message}")
        }
    }

    // ─── Key Exchange ─────────────────────────────────────────────────────────

    private fun handleKeyExchange(fromAddress: String, wire: WireMessage) {
        try {
            val payload = json.decodeFromString<KeyExchangePayload>(wire.payload)
            val theirPublicKey = CryptoManager.publicKeyFromBase64(payload.publicKey)

            knownPeerKeys[payload.userId] = theirPublicKey
            addressToUserId[fromAddress] = payload.userId
            userIdToAddress[payload.userId] = fromAddress

            // Compute shared secret
            val secret = CryptoManager.computeSharedSecret(
                identity.keyPair.privateKey,
                theirPublicKey
            )
            sharedSecrets[payload.userId] = secret

            // Update peer info
            updatePeer(
                address = fromAddress,
                userId = payload.userId,
                nickname = payload.nickname,
                publicKeyBase64 = payload.publicKey,
                avatarSeed = payload.avatarSeed
            )

            Log.d(TAG, "Key exchange complete with ${payload.nickname}")
        } catch (e: Exception) {
            Log.e(TAG, "Key exchange failed: ${e.message}")
        }
    }

    private fun handlePeerAnnounce(fromAddress: String, wire: WireMessage) {
        try {
            val payload = json.decodeFromString<PeerAnnouncePayload>(wire.payload)
            val theirPublicKey = CryptoManager.publicKeyFromBase64(payload.publicKey)

            if (!knownPeerKeys.containsKey(payload.userId)) {
                knownPeerKeys[payload.userId] = theirPublicKey
                addressToUserId[fromAddress] = payload.userId
                userIdToAddress[payload.userId] = fromAddress

                val secret = CryptoManager.computeSharedSecret(
                    identity.keyPair.privateKey,
                    theirPublicKey
                )
                sharedSecrets[payload.userId] = secret
            }

            updatePeer(
                address = fromAddress,
                userId = payload.userId,
                nickname = payload.nickname,
                publicKeyBase64 = payload.publicKey,
                avatarSeed = payload.avatarSeed
            )
        } catch (e: Exception) {
            Log.e(TAG, "Peer announce failed: ${e.message}")
        }
    }

    // ─── Chat ─────────────────────────────────────────────────────────────────

    private suspend fun handleChat(fromAddress: String, wire: WireMessage) {
        val senderId = wire.senderId
        val secret = sharedSecrets[senderId]

        val text = if (secret != null) {
            try {
                CryptoManager.decryptMessage(wire.payload, secret)
            } catch (e: Exception) {
                Log.e(TAG, "Decryption failed: ${e.message}")
                return
            }
        } else {
            Log.w(TAG, "No shared secret for $senderId, dropping")
            return
        }

        val peer = _peers.value[senderId]
        val msg = Message(
            id = wire.id,
            conversationId = if (wire.channelId != null) wire.channelId else senderId,
            senderId = senderId,
            senderNickname = peer?.nickname ?: senderId.take(8),
            text = text,
            timestamp = wire.timestamp,
            status = MessageStatus.DELIVERED,
            isOutgoing = false,
            isEncrypted = true
        )

        _messages.emit(msg)

        // Send delivery ack
        sendAck(senderId, wire.id)
    }

    // ─── Send ─────────────────────────────────────────────────────────────────

    suspend fun sendChatMessage(recipientId: String?, channelId: String?, text: String): String {
        val msgId = CryptoManager.generateRandomId()
        val timestamp = System.currentTimeMillis()

        val payload = if (recipientId != null) {
            val secret = sharedSecrets[recipientId]
                ?: throw IllegalStateException("No shared secret for $recipientId")
            CryptoManager.encryptMessage(text, secret)
        } else {
            // Channel: use channel-derived key or plain for now
            text
        }

        val wire = WireMessage(
            id = msgId,
            type = MessageType.CHAT.name,
            senderId = identity.userId,
            senderPublicKey = identity.publicKeyBase64,
            recipientId = recipientId,
            channelId = channelId,
            payload = payload,
            signature = CryptoManager.signMessage(payload, identity.keyPair.privateKey),
            timestamp = timestamp,
            ttl = if (recipientId != null) 3 else 1,
            nonce = android.util.Base64.encodeToString(CryptoManager.generateNonce(), android.util.Base64.NO_WRAP)
        )

        val data = json.encodeToString(wire).toByteArray()

        if (recipientId != null) {
            val address = userIdToAddress[recipientId]
            if (address != null) {
                meshManager.sendMessage(address, data)
            } else {
                // Try broadcasting if we don't have direct connection
                meshManager.broadcastMessage(data)
            }
        } else {
            meshManager.broadcastMessage(data)
        }

        markSeen(msgId)
        return msgId
    }

    fun sendKeyExchange() {
        val payload = json.encodeToString(KeyExchangePayload(
            publicKey = identity.publicKeyBase64,
            nickname = identity.nickname,
            userId = identity.userId,
            avatarSeed = identity.avatarSeed,
            timestamp = System.currentTimeMillis()
        ))

        val wire = WireMessage(
            id = CryptoManager.generateRandomId(),
            type = MessageType.KEY_EXCHANGE.name,
            senderId = identity.userId,
            senderPublicKey = identity.publicKeyBase64,
            recipientId = null,
            channelId = null,
            payload = payload,
            signature = CryptoManager.signMessage(payload, identity.keyPair.privateKey),
            timestamp = System.currentTimeMillis(),
            ttl = 1,
            nonce = android.util.Base64.encodeToString(CryptoManager.generateNonce(), android.util.Base64.NO_WRAP)
        )

        val data = json.encodeToString(wire).toByteArray()
        meshManager.broadcastMessage(data)
    }

    fun sendAnnounce() {
        val payload = json.encodeToString(PeerAnnouncePayload(
            userId = identity.userId,
            nickname = identity.nickname,
            publicKey = identity.publicKeyBase64,
            avatarSeed = identity.avatarSeed
        ))

        val wire = WireMessage(
            id = CryptoManager.generateRandomId(),
            type = MessageType.PEER_ANNOUNCE.name,
            senderId = identity.userId,
            senderPublicKey = identity.publicKeyBase64,
            recipientId = null,
            channelId = null,
            payload = payload,
            signature = CryptoManager.signMessage(payload, identity.keyPair.privateKey),
            timestamp = System.currentTimeMillis(),
            ttl = 3, // Mesh relay
            nonce = android.util.Base64.encodeToString(CryptoManager.generateNonce(), android.util.Base64.NO_WRAP)
        )

        val data = json.encodeToString(wire).toByteArray()
        meshManager.broadcastMessage(data)
    }

    fun sendTypingIndicator(recipientId: String) {
        val address = userIdToAddress[recipientId] ?: return
        val wire = WireMessage(
            id = CryptoManager.generateRandomId(),
            type = MessageType.TYPING.name,
            senderId = identity.userId,
            senderPublicKey = identity.publicKeyBase64,
            recipientId = recipientId,
            channelId = null,
            payload = "typing",
            signature = "",
            timestamp = System.currentTimeMillis(),
            ttl = 1,
            nonce = android.util.Base64.encodeToString(CryptoManager.generateNonce(), android.util.Base64.NO_WRAP)
        )
        val data = json.encodeToString(wire).toByteArray()
        meshManager.sendMessage(address, data)
    }

    // ─── Relay ────────────────────────────────────────────────────────────────

    private fun relayMessage(wire: WireMessage) {
        val relayed = wire.copy(ttl = wire.ttl - 1)
        val data = json.encodeToString(relayed).toByteArray()
        meshManager.broadcastMessage(data)
        Log.d(TAG, "Relayed message ${wire.id} (TTL: ${wire.ttl} -> ${relayed.ttl})")
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private fun sendAck(recipientId: String, messageId: String) {
        val address = userIdToAddress[recipientId] ?: return
        val wire = WireMessage(
            id = CryptoManager.generateRandomId(),
            type = MessageType.DELIVERY_ACK.name,
            senderId = identity.userId,
            senderPublicKey = identity.publicKeyBase64,
            recipientId = recipientId,
            channelId = null,
            payload = messageId,
            signature = "",
            timestamp = System.currentTimeMillis(),
            ttl = 1,
            nonce = android.util.Base64.encodeToString(CryptoManager.generateNonce(), android.util.Base64.NO_WRAP)
        )
        val data = json.encodeToString(wire).toByteArray()
        meshManager.sendMessage(address, data)
    }

    private fun handleAck(wire: WireMessage) {
        // Message confirmed delivered - emit event upstream
    }

    private fun handleTyping(wire: WireMessage) {
        val currentTyping = _typingPeers.value.toMutableSet()
        currentTyping.add(wire.senderId)
        _typingPeers.value = currentTyping
    }

    private fun handlePing(fromAddress: String) {
        // Respond with pong (announce)
        val address = fromAddress
        // Could send announce back
    }

    private fun isSeenMessage(id: String): Boolean = synchronized(seenMessageIds) {
        id in seenMessageIds
    }

    private fun markSeen(id: String) = synchronized(seenMessageIds) {
        seenMessageIds.add(id)
        if (seenMessageIds.size > SEEN_MSG_CACHE_SIZE) {
            seenMessageIds.remove(seenMessageIds.first())
        }
    }

    private fun updatePeer(
        address: String,
        userId: String,
        nickname: String,
        publicKeyBase64: String,
        avatarSeed: String
    ) {
        val existing = _peers.value[userId]
        val updated = Peer(
            id = userId,
            nickname = nickname,
            publicKeyBase64 = publicKeyBase64,
            fingerprint = try {
                val keyBytes = android.util.Base64.decode(publicKeyBase64, android.util.Base64.NO_WRAP)
                keyBytes.take(8).joinToString(":") { "%02X".format(it) }
            } catch (e: Exception) { "??:??:??" },
            avatarSeed = avatarSeed,
            isConnected = true,
            isTrusted = existing?.isTrusted ?: false,
            isBlocked = existing?.isBlocked ?: false
        )
        _peers.value = _peers.value + (userId to updated)
    }

    fun getSharedSecret(peerId: String): ByteArray? = sharedSecrets[peerId]
    fun getKnownPeer(peerId: String): Peer? = _peers.value[peerId]
    fun hasPeerKey(peerId: String): Boolean = sharedSecrets.containsKey(peerId)
}
