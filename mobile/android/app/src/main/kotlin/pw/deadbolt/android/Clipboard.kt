package pw.deadbolt.android

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import android.os.SystemClock
import java.security.MessageDigest

/** Where [Vault] copies values. */
interface SecretClipboard {
    fun copy(text: String, sensitive: Boolean)

    /** Clears a due secret if it is still on the clipboard. Call only while focused. */
    fun clearIfDue()

    /** Clears a copied secret now, due or not, if it is still on the clipboard. Call only while focused. */
    fun clearOurs()
}

/**
 * Copies values and clears copied secrets later, but only if the clipboard still
 * holds exactly what Deadbolt put there, so it never wipes something the user
 * copied since. Android only lets the focused app read the clipboard, so a clear
 * that falls due in the background waits until Deadbolt is in front again.
 */
class Clipboard(context: Context) : SecretClipboard {
    companion object {
        const val CLEAR_AFTER_MS = 45_000L
    }

    private val manager = context.getSystemService(ClipboardManager::class.java)

    /** SHA-256 of the copied secret (never the secret itself) and when to clear it. */
    private var pending: Pair<ByteArray, Long>? = null

    override fun copy(text: String, sensitive: Boolean) {
        val clip = ClipData.newPlainText("Deadbolt", text)
        if (sensitive) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        manager.setPrimaryClip(clip)
        pending = if (sensitive) digest(text) to SystemClock.elapsedRealtime() + CLEAR_AFTER_MS else null
    }

    override fun clearIfDue() {
        val (_, due) = pending ?: return
        if (SystemClock.elapsedRealtime() < due) return
        clearOurs()
    }

    override fun clearOurs() {
        val (hash, _) = pending ?: return
        val clip = manager.primaryClip
        if (clip == null || clip.itemCount == 0) {
            // Empty, or not readable right now: keep waiting only if the app lacks focus.
            if (!manager.hasPrimaryClip()) pending = null
            return
        }
        val current = clip.getItemAt(0).text?.toString()
        if (current != null && MessageDigest.isEqual(digest(current), hash)) manager.clearPrimaryClip()
        pending = null
    }

    private fun digest(text: String) = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
}
