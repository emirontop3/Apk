package com.bluechat.crypto

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import android.util.Base64
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

val Context.identityDataStore: DataStore<Preferences> by preferencesDataStore(name = "identity")

/**
 * Manages the user's persistent cryptographic identity.
 * Keys are generated once and stored securely.
 */
class IdentityStore(private val context: Context) {

    companion object {
        private val KEY_PRIVATE = stringPreferencesKey("x25519_private")
        private val KEY_PUBLIC = stringPreferencesKey("x25519_public")
        private val KEY_NICKNAME = stringPreferencesKey("nickname")
        private val KEY_USER_ID = stringPreferencesKey("user_id")
        private val KEY_AVATAR_SEED = stringPreferencesKey("avatar_seed")
    }

    suspend fun getOrCreateIdentity(): Identity {
        val prefs = context.identityDataStore.data.first()
        val existingPriv = prefs[KEY_PRIVATE]
        val existingPub = prefs[KEY_PUBLIC]

        return if (existingPriv != null && existingPub != null) {
            Identity(
                userId = prefs[KEY_USER_ID] ?: CryptoManager.generateRandomId(),
                nickname = prefs[KEY_NICKNAME] ?: "Anonymous",
                avatarSeed = prefs[KEY_AVATAR_SEED] ?: "default",
                keyPair = CryptoManager.KeyPair(
                    privateKey = Base64.decode(existingPriv, Base64.NO_WRAP),
                    publicKey = Base64.decode(existingPub, Base64.NO_WRAP)
                )
            )
        } else {
            createNewIdentity()
        }
    }

    private suspend fun createNewIdentity(): Identity {
        val keyPair = CryptoManager.generateX25519KeyPair()
        val userId = CryptoManager.generateRandomId()
        val avatarSeed = CryptoManager.generateRandomId().take(8)

        context.identityDataStore.edit { prefs ->
            prefs[KEY_PRIVATE] = Base64.encodeToString(keyPair.privateKey, Base64.NO_WRAP)
            prefs[KEY_PUBLIC] = Base64.encodeToString(keyPair.publicKey, Base64.NO_WRAP)
            prefs[KEY_USER_ID] = userId
            prefs[KEY_AVATAR_SEED] = avatarSeed
        }

        return Identity(
            userId = userId,
            nickname = "Anonymous",
            avatarSeed = avatarSeed,
            keyPair = keyPair
        )
    }

    suspend fun updateNickname(nickname: String) {
        context.identityDataStore.edit { it[KEY_NICKNAME] = nickname.take(32) }
    }

    fun nicknameFlow(): Flow<String> =
        context.identityDataStore.data.map { it[KEY_NICKNAME] ?: "Anonymous" }

    suspend fun deleteIdentity() {
        context.identityDataStore.edit { it.clear() }
    }
}

data class Identity(
    val userId: String,
    val nickname: String,
    val avatarSeed: String,
    val keyPair: CryptoManager.KeyPair
) {
    val fingerprint: String get() = keyPair.fingerprint
    val publicKeyBase64: String get() = keyPair.publicKeyBase64
}
