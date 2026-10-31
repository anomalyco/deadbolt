package pw.deadbolt.android

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.security.SecureRandom
import javax.crypto.Cipher
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Biometric unlock can't run right now; the passphrase still works. Its message is shown quietly. */
open class BiometricFailure(message: String) : Exception(message)

/** The Keystore key behind the token is gone, a biometric change invalidated it, or it is past 14 days. */
open class BiometricInvalidated(
    message: String = "Biometrics changed on this phone. Use your passphrase, then turn fingerprint unlock on again.",
) : BiometricFailure(message)

/** Fingerprint unlock is 14 days old (or the clock moved before it): the passphrase is due. */
class BiometricExpired :
    BiometricInvalidated("Enter your passphrase. Deadbolt asks for it every 14 days, then fingerprint unlock can be turned on again.")

/** Shows the system biometric prompt over [cipher]; null when the person backs out. */
fun interface Prompter {
    suspend fun authorize(cipher: Cipher, title: String, negative: String): Cipher?
}

/** A new wrapping key and its token, not yet stored in the core. */
class Enrollment(val key: ByteArray, val token: ByteArray, internal val alias: String, internal val previous: String?)

/** Platform biometric key handling, kept apart from [Vault]'s state so its races can be tested. */
interface Biometrics {
    fun available(): Boolean

    /** Whether [token] names a Keystore key that is still valid (no prompt). */
    fun usable(token: ByteArray): Boolean

    /** The wrapping key inside [token], after a prompt titled [title] with a [negative] button; null if it was dismissed. */
    suspend fun unseal(token: ByteArray, prompter: Prompter, title: String, negative: String): ByteArray?

    /** A fresh wrapping key sealed under a new Keystore key, after a prompt; null if dismissed. */
    suspend fun enroll(previousToken: ByteArray, prompter: Prompter): Enrollment?

    /** The core stored [enrollment]: drop the key it replaced. */
    fun commit(enrollment: Enrollment)

    /** The core did not store [enrollment]: drop its new key. */
    fun discard(enrollment: Enrollment)
}

/** [Biometrics] over the Android Keystore ([BiometricKey]). Crypto errors become [BiometricFailure]. */
class KeystoreBiometrics(
    private val context: Context,
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
) : Biometrics {
    /**
     * Whether the last token checked was usable. Checking initializes a Keystore
     * cipher (an operation the prompt would also need), so it happens once per
     * token, not on every refresh; failures and new enrollments clear it.
     */
    private var checked: Pair<ByteArray, Boolean>? = null

    private fun <T> crypto(block: () -> T): T = try {
        block()
    } catch (e: BiometricFailure) {
        throw e
    } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
        throw BiometricInvalidated()
    } catch (e: android.security.keystore.KeyExpiredException) {
        throw BiometricExpired()
    } catch (e: GeneralSecurityException) {
        throw BiometricFailure("Fingerprint unlock isn't working right now. Use your passphrase.")
    } catch (e: ProviderException) {
        throw BiometricFailure("Fingerprint unlock isn't working right now. Use your passphrase.")
    } catch (e: IllegalStateException) {
        throw BiometricFailure("Fingerprint unlock isn't working right now. Use your passphrase.")
    }

    override fun available(): Boolean =
        BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    override fun usable(token: ByteArray): Boolean {
        val envelope = BiometricKey.parse(token) ?: return false
        if (!BiometricKey.fresh(envelope.createdAt, now())) return false
        checked?.let { (seen, ok) -> if (seen.contentEquals(token)) return ok }
        val ok = runCatching { crypto { BiometricKey.decryptCipher(envelope) } }.isSuccess
        checked = token.copyOf() to ok
        return ok
    }

    /** The envelope in [token], if it may still be used; otherwise its key is dropped. */
    private fun current(token: ByteArray): BiometricKey.Envelope {
        val envelope = BiometricKey.parse(token)
            ?: throw BiometricFailure("Fingerprint unlock isn't set up. Use your passphrase.")
        if (!BiometricKey.fresh(envelope.createdAt, now())) {
            BiometricKey.delete(envelope.alias)
            checked = null
            throw BiometricExpired()
        }
        return envelope
    }

    override suspend fun unseal(token: ByteArray, prompter: Prompter, title: String, negative: String): ByteArray? {
        try {
            val envelope = current(token)
            val cipher = crypto { BiometricKey.decryptCipher(envelope) }
            val authorized = prompter.authorize(cipher, title, negative) ?: return null
            return crypto { BiometricKey.open(authorized, envelope) }
        } catch (e: BiometricInvalidated) {
            checked = null
            throw e
        }
    }

    override suspend fun enroll(previousToken: ByteArray, prompter: Prompter): Enrollment? {
        val previous = BiometricKey.parse(previousToken)?.alias
        val newKey = crypto { BiometricKey.newEnrollment(now()) }
        val alias = newKey.alias
        var keep = false
        try {
            val authorized = prompter.authorize(newKey.cipher, "Turn on fingerprint unlock", "Cancel") ?: return null
            val key = ByteArray(32).also(SecureRandom()::nextBytes)
            val token = try {
                crypto { BiometricKey.seal(newKey, authorized, key) }
            } catch (e: BiometricFailure) {
                key.fill(0)
                throw e
            }
            keep = true
            return Enrollment(key, token, alias, previous)
        } finally {
            if (!keep) BiometricKey.delete(alias)
        }
    }

    override fun commit(enrollment: Enrollment) {
        checked = null
        enrollment.previous?.takeIf { it != enrollment.alias }?.let(BiometricKey::delete)
    }

    override fun discard(enrollment: Enrollment) {
        checked = null
        BiometricKey.delete(enrollment.alias)
    }
}

/**
 * The system prompt hosted in [activity]. A cancelled coroutine dismisses it, and
 * a late callback for a cancelled request is dropped.
 */
class ActivityPrompter(private val activity: FragmentActivity) : Prompter {
    override suspend fun authorize(cipher: Cipher, title: String, negative: String): Cipher? =
        suspendCancellableCoroutine { cont ->
            val prompt = BiometricPrompt(
                activity,
                activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (!cont.isActive) return
                        val authorized = result.cryptoObject?.cipher
                        if (authorized == null) {
                            cont.resumeWithException(BiometricFailure("Fingerprint unlock isn't working right now. Use your passphrase."))
                        } else {
                            cont.resume(authorized)
                        }
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        if (!cont.isActive) return
                        when (code) {
                            BiometricPrompt.ERROR_USER_CANCELED,
                            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                            BiometricPrompt.ERROR_CANCELED,
                            -> cont.resume(null)
                            else -> cont.resumeWithException(BiometricFailure("$message Use your passphrase."))
                        }
                    }
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText(negative)
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(false)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
            cont.invokeOnCancellation { activity.runOnUiThread { prompt.cancelAuthentication() } }
        }
}
