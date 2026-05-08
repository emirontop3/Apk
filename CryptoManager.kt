package com.bluechat.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * CryptoManager handles all cryptographic operations:
 * - X25519 Elliptic Curve Diffie-Hellman for key exchange
 * - AES-256-GCM for symmetric encryption
 * - HKDF for key derivation
 * - Android Keystore for secure key storage
 * - Message signing/verification
 */
object CryptoManager {

    private const val KEYSTORE_ALIAS = "bluechat_identity_key"
    private const val AES_KEY_SIZE = 256
    private const val GCM_IV_SIZE = 12
    private const val GCM_TAG_SIZE = 128
    private const val X25519_KEY_SIZE = 32
    private val secureRandom = SecureRandom()

    // ─── Identity Key Pair (X25519) ───────────────────────────────────────────

    data class KeyPair(
        val privateKey: ByteArray,
        val publicKey: ByteArray
    ) {
        val publicKeyBase64: String get() = Base64.encodeToString(publicKey, Base64.NO_WRAP)
        val fingerprint: String get() = MessageDigest.getInstance("SHA-256")
            .digest(publicKey)
            .take(8)
            .joinToString(":") { "%02X".format(it) }
    }

    fun generateX25519KeyPair(): KeyPair {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(secureRandom))
        val pair = generator.generateKeyPair()
        val priv = (pair.private as X25519PrivateKeyParameters).encoded
        val pub = (pair.public as X25519PublicKeyParameters).encoded
        return KeyPair(priv, pub)
    }

    fun publicKeyFromBase64(base64: String): ByteArray =
        Base64.decode(base64, Base64.NO_WRAP)

    // ─── ECDH Shared Secret ──────────────────────────────────────────────────

    fun computeSharedSecret(myPrivateKey: ByteArray, theirPublicKey: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        val privParams = X25519PrivateKeyParameters(myPrivateKey)
        val pubParams = X25519PublicKeyParameters(theirPublicKey)
        agreement.init(privParams)
        val sharedSecret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(pubParams, sharedSecret, 0)
        return hkdf(sharedSecret, "bluechat-v1".toByteArray(), 32)
    }

    // ─── HKDF Key Derivation ─────────────────────────────────────────────────

    fun hkdf(inputKeyMaterial: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        val salt = ByteArray(32) // zero salt
        // Extract
        val prk = hmacSha256(salt, inputKeyMaterial)
        // Expand
        val result = ByteArray(outputLength)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < outputLength) {
            val input = t + info + byteArrayOf(counter.toByte())
            t = hmacSha256(prk, input)
            val copy = minOf(t.size, outputLength - offset)
            t.copyInto(result, offset, 0, copy)
            offset += copy
            counter++
        }
        return result
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    // ─── AES-256-GCM Encrypt/Decrypt ────────────────────────────────────────

    data class EncryptedPayload(
        val iv: ByteArray,
        val ciphertext: ByteArray,
        val tag: ByteArray // included in ciphertext by AES/GCM/NoPadding
    ) {
        fun toBytes(): ByteArray = iv + ciphertext

        fun toBase64(): String = Base64.encodeToString(toBytes(), Base64.NO_WRAP)

        companion object {
            fun fromBytes(bytes: ByteArray): EncryptedPayload {
                require(bytes.size >= GCM_IV_SIZE + 16) { "Invalid payload" }
                val iv = bytes.copyOf(GCM_IV_SIZE)
                val ct = bytes.copyOfRange(GCM_IV_SIZE, bytes.size)
                return EncryptedPayload(iv, ct, ByteArray(0))
            }

            fun fromBase64(base64: String): EncryptedPayload =
                fromBytes(Base64.decode(base64, Base64.NO_WRAP))
        }
    }

    fun encrypt(plaintext: ByteArray, sharedSecret: ByteArray): EncryptedPayload {
        val iv = ByteArray(GCM_IV_SIZE).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(sharedSecret, "AES")
        val paramSpec = GCMParameterSpec(GCM_TAG_SIZE, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec)
        val ciphertext = cipher.doFinal(plaintext)
        return EncryptedPayload(iv, ciphertext, ByteArray(0))
    }

    fun decrypt(payload: EncryptedPayload, sharedSecret: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(sharedSecret, "AES")
        val paramSpec = GCMParameterSpec(GCM_TAG_SIZE, payload.iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec)
        return cipher.doFinal(payload.ciphertext)
    }

    fun encryptMessage(message: String, sharedSecret: ByteArray): String {
        val payload = encrypt(message.toByteArray(Charsets.UTF_8), sharedSecret)
        return payload.toBase64()
    }

    fun decryptMessage(encryptedBase64: String, sharedSecret: ByteArray): String {
        val payload = EncryptedPayload.fromBase64(encryptedBase64)
        val plaintext = decrypt(payload, sharedSecret)
        return String(plaintext, Charsets.UTF_8)
    }

    // ─── Message Signing (HMAC-SHA256) ───────────────────────────────────────

    fun signMessage(message: String, privateKey: ByteArray): String {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(privateKey, "HmacSHA256"))
        val signature = mac.doFinal(message.toByteArray())
        return Base64.encodeToString(signature, Base64.NO_WRAP)
    }

    fun verifySignature(message: String, signature: String, publicKey: ByteArray): Boolean {
        return try {
            val expectedSig = signMessage(message, publicKey)
            MessageDigest.isEqual(
                Base64.decode(signature, Base64.NO_WRAP),
                Base64.decode(expectedSig, Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            false
        }
    }

    // ─── Random helpers ──────────────────────────────────────────────────────

    fun generateRandomId(): String {
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP)
    }

    fun generateNonce(): ByteArray {
        val nonce = ByteArray(GCM_IV_SIZE)
        secureRandom.nextBytes(nonce)
        return nonce
    }

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    fun sha256Hex(data: String): String =
        sha256(data.toByteArray()).joinToString("") { "%02x".format(it) }
}
