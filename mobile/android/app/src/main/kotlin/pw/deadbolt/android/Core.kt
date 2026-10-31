package pw.deadbolt.android

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import pw.deadbolt.mobile.core.AndroidRuntime
import pw.deadbolt.mobile.core.MobileDevice
import pw.deadbolt.mobile.core.MobileException

/** A failure reported by the Rust core, either as an FFI error or an `{ok:false}` reply. */
class CoreError(message: String) : Exception(message)

data class Status(
    val initialized: Boolean,
    val unlocked: Boolean,
    val deviceId: String?,
    val biometricReady: Boolean,
)

data class ItemRow(val id: String, val title: String, val username: String, val kind: String)

data class ItemDetail(
    val id: String,
    val title: String,
    val username: String,
    val url: String,
    val hasPassword: Boolean,
    val hasOtp: Boolean,
)

data class OtpCode(val code: String, val remaining: Int, val period: Int)

enum class JoinState { Waiting, Joined, Error }

/**
 * One read a computer in the vault asks this phone to allow (crates/net/src/approval.rs
 * `PendingRead`). [originName] is the signed name of the asking device; [caller] is
 * what that device verified about the program asking, plus unverified hints.
 */
data class PendingApproval(
    val id: String,
    val originName: String,
    val title: String,
    val field: String,
    val caller: String,
    /** Unix seconds. */
    val expiresAt: Long,
)

/**
 * The asking program as the other device described it: the executable path it
 * verified, and hints about what runs it (process ancestry, a claimed session)
 * that it could not verify. Parses `"<path>" · pid … · cdhash … · <hint>`.
 */
data class CallerLabel(val program: String, val hint: String?) {
    companion object {
        fun parse(caller: String): CallerLabel {
            val parts = caller.split(" · ").map(String::trim)
            val program = parts.first().removeSurrounding("\"")
            val hint = parts.drop(1).lastOrNull { it.contains("hint") || it.contains("not verified") }
                ?.replace(" (ancestry hint)", "")
                ?.replace(" claimed (not verified)", "")
            return CallerLabel(program.ifEmpty { caller }, hint)
        }
    }
}

/** What [Vault] asks of the device's core; [Core] is the only production implementation. */
interface VaultCore {
    suspend fun status(): Status
    suspend fun joinStart(passphrase: String): String
    suspend fun joinStatus(): Pair<JoinState, String?>
    suspend fun joinCancel()
    suspend fun unlock(passphrase: String)
    suspend fun lock()
    suspend fun sync()
    suspend fun items(query: String): List<ItemRow>
    suspend fun item(id: String): ItemDetail
    suspend fun secret(id: String, field: String): String
    suspend fun code(id: String): OtpCode
    suspend fun biometricEnroll(key: ByteArray, token: ByteArray)
    suspend fun biometricToken(): ByteArray
    suspend fun unlockBiometric(key: ByteArray)

    /** The read waiting for this phone's answer, if any. */
    suspend fun approvalPending(): PendingApproval?

    /** Answers [id]. Allowing needs the freshly unwrapped biometric key; denying passes none. */
    suspend fun approvalRespond(id: String, allow: Boolean, biometricKey: ByteArray)
}

/**
 * The device's Rust core (crates/mobile-core). Every call is synchronous in Rust,
 * so it always runs on [Dispatchers.IO], never on the main thread.
 */
class Core private constructor(private val device: MobileDevice) : VaultCore {
    companion object {
        suspend fun open(context: Context, path: String, name: String): Core = withContext(Dispatchers.IO) {
            try {
                // rustls' Android certificate verifier needs the app context before any network call.
                AndroidRuntime.initialize(context.applicationContext)
                Core(MobileDevice(path, name))
            } catch (e: MobileException) {
                throw CoreError(e.message ?: "couldn't open this device's vault")
            }
        }
    }

    private suspend fun call(op: String, vararg args: Pair<String, Any>): JSONObject =
        withContext(Dispatchers.IO) {
            val request = JSONObject().put("op", op)
            for ((key, value) in args) request.put(key, value)
            val reply = try {
                JSONObject(device.call(request.toString()))
            } catch (e: MobileException) {
                throw CoreError(e.message ?: "$op failed")
            }
            if (!reply.optBoolean("ok")) throw CoreError(reply.optString("error", "$op failed"))
            reply
        }

    private suspend fun <T> ffi(what: String, block: () -> T): T = withContext(Dispatchers.IO) {
        try {
            block()
        } catch (e: MobileException) {
            throw CoreError(e.message ?: "$what failed")
        }
    }

    override suspend fun status(): Status = call("status").let {
        Status(
            initialized = it.optBoolean("initialized"),
            unlocked = it.optBoolean("unlocked"),
            deviceId = it.optString("device_id").ifEmpty { null },
            biometricReady = it.optBoolean("biometric_ready"),
        )
    }

    override suspend fun joinStart(passphrase: String): String =
        call("join-start", "passphrase" to passphrase).getString("code")

    override suspend fun joinStatus(): Pair<JoinState, String?> = call("join-status").let {
        val state = when (it.getString("state")) {
            "waiting" -> JoinState.Waiting
            "joined" -> JoinState.Joined
            else -> JoinState.Error
        }
        state to it.optString("error").ifEmpty { null }
    }

    override suspend fun joinCancel() {
        call("join-cancel")
    }

    override suspend fun unlock(passphrase: String) {
        call("unlock", "passphrase" to passphrase)
    }

    override suspend fun lock() {
        call("lock")
    }

    override suspend fun sync() {
        call("sync")
    }

    override suspend fun items(query: String): List<ItemRow> = withContext(Dispatchers.IO) {
        val started = System.nanoTime()
        val raw = try {
            device.call(JSONObject().put("op", "items").put("query", query).toString())
        } catch (e: MobileException) {
            throw CoreError(e.message ?: "items failed")
        }
        val called = System.nanoTime()
        val reply = JSONObject(raw)
        if (!reply.optBoolean("ok")) throw CoreError(reply.optString("error", "items failed"))
        val array = reply.getJSONArray("items")
        val rows = List(array.length()) { i ->
            val o = array.getJSONObject(i)
            ItemRow(o.getString("id"), o.optString("title"), o.optString("username"), o.optString("kind"))
        }
        Perf.split("items", called - started, System.nanoTime() - called)
        rows
    }

    override suspend fun item(id: String): ItemDetail = call("item", "id" to id).let {
        ItemDetail(
            id = it.getString("id"),
            title = it.optString("title"),
            username = it.optString("username"),
            url = it.optString("url"),
            hasPassword = it.optBoolean("has_password"),
            hasOtp = it.optBoolean("has_otp"),
        )
    }

    override suspend fun secret(id: String, field: String): String =
        call("secret", "id" to id, "field" to field).getString("value")

    override suspend fun code(id: String): OtpCode = call("code", "id" to id).let {
        OtpCode(it.getString("code"), it.getInt("remaining"), it.getInt("period"))
    }

    /** Stores [token] and a key slot that [key] opens; [key] is the caller's to wipe. */
    override suspend fun biometricEnroll(key: ByteArray, token: ByteArray) {
        ffi("biometric enroll") { device.biometricEnroll(key, token) }
    }

    /** The enrolled token, or an empty array when there is none. */
    override suspend fun biometricToken(): ByteArray = ffi("biometric token") { device.biometricToken() }

    override suspend fun unlockBiometric(key: ByteArray) {
        ffi("biometric unlock") { device.unlockBiometric(key) }
    }

    override suspend fun approvalPending(): PendingApproval? {
        val json = ffi("approval check") { device.approvalPending() } ?: return null
        val o = JSONObject(json)
        val scope = o.optJSONObject("scope") ?: o
        return PendingApproval(
            id = o.getString("id"),
            originName = scope.getString("origin_name"),
            title = scope.getString("title"),
            field = scope.getString("field"),
            caller = scope.getString("caller"),
            expiresAt = o.getLong("expires_at"),
        )
    }

    override suspend fun approvalRespond(id: String, allow: Boolean, biometricKey: ByteArray) {
        ffi("approval answer") { device.approvalRespond(id, allow, biometricKey) }
    }
}
