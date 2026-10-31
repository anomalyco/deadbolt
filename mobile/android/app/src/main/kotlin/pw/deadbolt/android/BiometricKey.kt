package pw.deadbolt.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.ProviderException
import java.security.SecureRandom
import java.security.UnrecoverableKeyException
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Biometric unlock on Android, the counterpart of docs/touch-id.md.
 *
 * Enrolling makes a random 32-byte wrapping key, which the core uses to seal a
 * second copy of the store's key set. The wrapping key itself is encrypted with
 * an AES-256-GCM Android Keystore key that requires a BIOMETRIC_STRONG
 * authentication for every operation (timeout 0, so each use is a CryptoObject
 * prompt, never a boolean gate) and is invalidated when a biometric is enrolled.
 * The Keystore asks for StrongBox when the phone has it; whether the key is in
 * secure hardware is up to the phone and is not checked here.
 *
 * Like Touch ID, it lasts 14 days from enrollment: then the passphrase is needed
 * again, and turning fingerprint unlock back on makes a new key. The enrollment
 * time is in the token, bound into the GCM associated data, and checked against
 * the wall clock (a clock set before enrollment also ends it); the Keystore
 * key's validity end is set to the same moment as a second check.
 *
 * The token the core stores is:
 *
 *     "DBAK" | version 2 | created_at (u64 BE, Unix s) | alias len (u8) | alias
 *            | iv len (u8) | iv | ct len (u16 BE) | ct
 *
 * with AAD = "deadbolt-android/biometric/v2\0" | created_at | alias. The AAD is
 * added only to the cipher the prompt authorized, right before its one operation.
 */
object BiometricKey {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private val MAGIC = "DBAK".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 2
    private const val AAD_PREFIX = "deadbolt-android/biometric/v2\u0000"
    const val MAX_AGE_SECONDS = 14L * 24 * 60 * 60

    class Envelope(val createdAt: Long, val alias: String, val iv: ByteArray, val ciphertext: ByteArray)

    /** Whether an enrollment made at [createdAt] may still unlock at [now] (both Unix seconds). */
    fun fresh(createdAt: Long, now: Long): Boolean = createdAt in 0..now && now - createdAt <= MAX_AGE_SECONDS

    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun aad(createdAt: Long, alias: String): ByteArray {
        val prefix = AAD_PREFIX.toByteArray(Charsets.UTF_8)
        val aliasBytes = alias.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(prefix.size + 8 + aliasBytes.size).put(prefix).putLong(createdAt).put(aliasBytes).array()
    }

    private fun generate(alias: String, createdAt: Long, strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setKeyValidityEnd(Date((createdAt + MAX_AGE_SECONDS) * 1000))
            .setIsStrongBoxBacked(strongBox)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
            init(spec)
            generateKey()
        }
    }

    class NewKey(val alias: String, val createdAt: Long, val cipher: Cipher)

    /** A fresh Keystore key under a new alias, and a cipher ready to encrypt once a prompt authorizes it. */
    fun newEnrollment(createdAt: Long): NewKey {
        val alias = "deadbolt-biometric-" + ByteArray(12).also(SecureRandom()::nextBytes).toHex()
        val key = try {
            generate(alias, createdAt, strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            delete(alias)
            generate(alias, createdAt, strongBox = false)
        } catch (_: ProviderException) {
            // Some phones report a missing or failing StrongBox this way.
            delete(alias)
            generate(alias, createdAt, strongBox = false)
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key)
        } catch (e: Exception) {
            delete(alias)
            throw e
        }
        return NewKey(alias, createdAt, cipher)
    }

    /** Encrypts [wrappingKey] with the authorized [cipher] for [key] and returns the token. */
    fun seal(key: NewKey, cipher: Cipher, wrappingKey: ByteArray): ByteArray {
        cipher.updateAAD(aad(key.createdAt, key.alias))
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(wrappingKey)
        val aliasBytes = key.alias.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(MAGIC.size + 1 + 8 + 1 + aliasBytes.size + 1 + iv.size + 2 + ciphertext.size)
            .put(MAGIC).put(VERSION).putLong(key.createdAt)
            .put(aliasBytes.size.toByte()).put(aliasBytes)
            .put(iv.size.toByte()).put(iv)
            .putShort(ciphertext.size.toShort()).put(ciphertext)
            .array()
    }

    /** Parses a token from [seal]; null when it is empty or not one of ours. */
    fun parse(token: ByteArray): Envelope? = try {
        val b = ByteBuffer.wrap(token)
        val magic = ByteArray(MAGIC.size).also(b::get)
        if (!magic.contentEquals(MAGIC) || b.get() != VERSION) {
            null
        } else {
            val createdAt = b.long
            val alias = String(ByteArray(b.get().toInt() and 0xff).also(b::get), Charsets.UTF_8)
            val iv = ByteArray(b.get().toInt() and 0xff).also(b::get)
            val ciphertext = ByteArray(b.short.toInt() and 0xffff).also(b::get)
            if (b.hasRemaining() || alias.isEmpty()) null else Envelope(createdAt, alias, iv, ciphertext)
        }
    } catch (_: RuntimeException) {
        null
    }

    /**
     * A cipher ready to decrypt [envelope] once a prompt authorizes it. Initializing
     * needs no authentication, so this also tells whether the key is still valid.
     */
    fun decryptCipher(envelope: Envelope): Cipher {
        val key = try {
            keyStore().getKey(envelope.alias, null) as? SecretKey
        } catch (_: UnrecoverableKeyException) {
            null
        } ?: throw BiometricInvalidated()
        return try {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.iv))
            }
        } catch (_: KeyPermanentlyInvalidatedException) {
            delete(envelope.alias)
            throw BiometricInvalidated()
        }
    }

    /** Decrypts the wrapping key with the authorized [cipher] from [decryptCipher]. */
    fun open(cipher: Cipher, envelope: Envelope): ByteArray {
        cipher.updateAAD(aad(envelope.createdAt, envelope.alias))
        return cipher.doFinal(envelope.ciphertext)
    }

    fun delete(alias: String) {
        runCatching { keyStore().deleteEntry(alias) }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
}
