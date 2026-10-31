package pw.deadbolt.android

import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The app's state and everything it asks the core to do. One instance lives as
 * long as the process (see [DeadboltApp]); Compose reads its snapshot state.
 *
 * Unlocks are tied to an [epoch]. Locking, going to the background, a new
 * passphrase unlock or cancelling bumps it, so an unlock or biometric reply that
 * lands afterwards is discarded (and the core locked again) instead of
 * unlocking a vault the person already left.
 */
class Vault(
    private val openCore: suspend () -> VaultCore,
    private val clipboard: SecretClipboard,
    private val biometrics: Biometrics,
    private val scope: CoroutineScope = MainScope(),
    private val clock: () -> Long = SystemClock::elapsedRealtime,
) {
    companion object {
        const val IDLE_LOCK_MS = 5 * 60_000L
        const val SYNC_EVERY_MS = 60_000L
        const val JOIN_POLL_MS = 1_000L
        const val APPROVAL_POLL_MS = 1_000L
        private const val IDLE_CHECK_MS = 10_000L
        private const val SEARCH_DEBOUNCE_MS = 150L
    }

    sealed interface Screen {
        data object Loading : Screen
        data class Broken(val message: String) : Screen
        data object Pair : Screen
        data object Locked : Screen
        data object Unlocked : Screen
    }

    private var core: VaultCore? = null

    var screen by mutableStateOf<Screen>(Screen.Loading); private set
    var status by mutableStateOf<Status?>(null); private set
    var busy by mutableStateOf(false); private set
    var error by mutableStateOf<String?>(null)
    var notice by mutableStateOf<String?>(null)

    var pairingCode by mutableStateOf<String?>(null); private set

    /** Bumped when the locked screen should show the fingerprint prompt by itself (see [shouldAutoPrompt]). */
    var autoPromptTick by mutableStateOf(0); private set

    /** Locked, and the core has a biometric token whose Keystore key is still valid. */
    var biometricUsable by mutableStateOf(false); private set

    /** The biometric token's Keystore key is valid, whether locked or not (allowing a read needs it). */
    var biometricKeyValid by mutableStateOf(false); private set

    /** Unlocked, biometrics enrolled on the phone, and no valid fingerprint unlock (never on, changed or expired). */
    val canEnableBiometrics: Boolean
        get() = status?.unlocked == true && biometricAvailable && !biometricKeyValid

    /** A read a computer asks this phone to allow; shown only while unlocked and in front. */
    var approval by mutableStateOf<PendingApproval?>(null); private set
    var approving by mutableStateOf(false); private set
    var biometricAvailable by mutableStateOf(false); private set

    var query by mutableStateOf(""); private set
    var items by mutableStateOf<List<ItemRow>>(emptyList()); private set
    var detail by mutableStateOf<ItemDetail?>(null); private set
    var code by mutableStateOf<OtpCode?>(null); private set
    var syncing by mutableStateOf(false); private set
    var syncedAt by mutableStateOf<Long?>(null); private set
    var syncError by mutableStateOf<String?>(null); private set

    private var foreground = false
    private var focused = false
    private var lastInteraction = clock()
    private var epoch = 0L
    private var refreshSeq = 0L
    private var starting: Job? = null
    private var joinJob: Job? = null
    private var searchJob: Job? = null
    private var codeJob: Job? = null
    private var biometricJob: Job? = null
    private var approvalJob: Job? = null
    private var unlockedJobs: List<Job> = emptyList()

    /** Locked by the person or the idle timer (not by leaving the app): don't auto-prompt. */
    private var quietLock = false
    private var autoPrompted = false

    fun start() {
        if (core != null || starting?.isActive == true || screen is Screen.Broken) return
        starting = scope.launch {
            try {
                core = openCore()
                refresh()
                Perf.mark("first status")
            } catch (e: CoreError) {
                screen = Screen.Broken(e.message ?: "couldn't open this phone's vault")
            }
        }
    }

    private suspend fun refresh() {
        val core = core ?: return
        val seq = ++refreshSeq
        val s = core.status()
        val available = biometrics.available()
        val keyValid = s.initialized && s.biometricReady && available &&
            runCatching { biometrics.usable(core.biometricToken()) }.getOrDefault(false)
        if (seq != refreshSeq) return // a newer refresh already ran
        status = s
        biometricAvailable = available
        biometricKeyValid = keyValid
        biometricUsable = keyValid && !s.unlocked
        val next = when {
            !s.initialized -> Screen.Pair
            s.unlocked -> Screen.Unlocked
            else -> Screen.Locked
        }
        val wasUnlocked = screen == Screen.Unlocked
        screen = next
        if (next == Screen.Unlocked && !wasUnlocked) onUnlocked()
        if (next != Screen.Unlocked && wasUnlocked) onLocked()
        // Status arrives after the activity started; the screen reacts to the tick.
        if (next == Screen.Locked && shouldAutoPrompt()) autoPromptTick += 1
    }

    /** Ends in-flight unlock work: its late replies are discarded. */
    private fun invalidate() {
        epoch += 1
        biometricJob?.cancel()
        biometricJob = null
        approvalJob?.cancel()
        approvalJob = null
        approving = false
        approval = null
    }

    /** Runs [block] without blocking other work, turning core failures into a quiet [error]. */
    private fun browse(block: suspend (VaultCore) -> Unit) {
        val core = core ?: return
        scope.launch {
            try {
                block(core)
            } catch (e: CoreError) {
                error = e.message
            }
        }
    }

    /** Runs [block] with [busy] set; core failures from a still-current [epoch] become [error]. */
    private fun act(block: suspend (VaultCore, Long) -> Unit) {
        val core = core ?: return
        if (busy) return
        val started = epoch
        scope.launch {
            busy = true
            error = null
            try {
                block(core, started)
            } catch (e: CoreError) {
                if (started == epoch) error = e.message
            } finally {
                busy = false
            }
        }
    }

    // Lifecycle, wired from MainActivity.

    fun onForeground() {
        foreground = true
        lastInteraction = clock()
        autoPrompted = false
        scope.launch { runCatching { refresh() } }
    }

    fun onBackground() {
        foreground = false
        focused = false
        invalidate()
        // Nothing runs while Deadbolt is in the background: a pending unlock or
        // pairing (which holds the new passphrase and device key) is cancelled
        // and the core locked, so neither can finish into an unlocked vault.
        quietLock = false
        if (joinJob?.isActive == true || pairingCode != null) {
            joinJob?.cancel()
            joinJob = null
            pairingCode = null
            error = "Pairing stopped when you left Deadbolt. Get a new code to try again."
        }
        scope.launch { lockNow() }
    }

    fun onFocus(hasFocus: Boolean) {
        focused = hasFocus
        if (hasFocus) clipboard.clearIfDue()
    }

    /** A touch or key press. Polling, syncing and the code countdown never count. */
    fun onInteraction() {
        lastInteraction = clock()
    }

    /** The activity hosting a prompt is going away: dismiss the prompt, keep other work. */
    fun cancelPrompt() {
        biometricJob?.cancel()
        biometricJob = null
        approvalJob?.cancel()
        approvalJob = null
        approving = false
    }

    // Pairing.

    fun startPairing(passphrase: String) = act { core, started ->
        val code = core.joinStart(passphrase)
        if (started != epoch) {
            // Left or cancelled while the code was made: stop the join it started.
            runCatching { core.joinCancel() }
            return@act
        }
        pairingCode = code
        joinJob?.cancel()
        joinJob = scope.launch { pollJoin(core) }
    }

    private suspend fun pollJoin(core: VaultCore) {
        while (scope.isActive) {
            delay(JOIN_POLL_MS)
            val (state, message) = try {
                core.joinStatus()
            } catch (e: CoreError) {
                JoinState.Error to e.message
            }
            when (state) {
                JoinState.Waiting -> continue
                JoinState.Joined -> {
                    pairingCode = null
                    try {
                        refresh()
                    } catch (e: CoreError) {
                        error = e.message
                    }
                    return
                }
                JoinState.Error -> {
                    pairingCode = null
                    error = message ?: "Pairing didn't finish. Try again."
                    return
                }
            }
        }
    }

    fun cancelPairing() {
        invalidate()
        joinJob?.cancel()
        joinJob = null
        pairingCode = null
        scope.launch { runCatching { core?.joinCancel() } }
    }

    // Locking.

    fun unlock(passphrase: String) {
        if (busy) return
        invalidate() // a passphrase unlock replaces any biometric prompt
        act { core, started ->
            core.unlock(passphrase)
            if (started != epoch) {
                // Locked or left while the passphrase was checked: don't stay unlocked.
                runCatching { core.lock() }
            }
            refresh()
        }
    }

    fun lock() {
        quietLock = true
        invalidate()
        scope.launch { lockNow() }
    }

    private suspend fun lockNow() {
        if (focused) clipboard.clearOurs()
        onLocked()
        runCatching { core?.lock() }
        runCatching { refresh() }
    }

    private fun onUnlocked() {
        quietLock = false
        lastInteraction = clock()
        unlockedJobs.forEach(Job::cancel)
        unlockedJobs = listOf(
            scope.launch {
                while (isActive) {
                    delay(IDLE_CHECK_MS)
                    if (clock() - lastInteraction >= IDLE_LOCK_MS) {
                        quietLock = true
                        invalidate()
                        lockNow()
                    }
                }
            },
            scope.launch {
                while (isActive) {
                    if (foreground) syncOnce()
                    delay(SYNC_EVERY_MS)
                }
            },
            scope.launch {
                while (isActive) {
                    delay(1_000)
                    if (focused) clipboard.clearIfDue()
                }
            },
            scope.launch {
                while (isActive) {
                    delay(APPROVAL_POLL_MS)
                    if (foreground && !approving) pollApproval()
                }
            },
        )
        search(query)
    }

    private fun onLocked() {
        approvalJob?.cancel()
        approvalJob = null
        approving = false
        approval = null
        unlockedJobs.forEach(Job::cancel)
        unlockedJobs = emptyList()
        searchJob?.cancel()
        closeItem()
        items = emptyList()
        query = ""
    }

    // Biometrics. Each needs a live BIOMETRIC_STRONG prompt over a Keystore CryptoObject.

    /** Whether the locked screen should prompt by itself, once per trip to the foreground. */
    fun shouldAutoPrompt(): Boolean = biometricUsable && !quietLock && !autoPrompted && foreground

    fun unlockWithBiometrics(prompter: Prompter) {
        val core = core ?: return
        if (busy || biometricJob?.isActive == true) return
        autoPrompted = true
        error = null
        val started = epoch
        biometricJob = scope.launch {
            var key: ByteArray? = null
            try {
                key = biometrics.unseal(core.biometricToken(), prompter, "Unlock Deadbolt", "Use passphrase") ?: return@launch
                if (started != epoch) return@launch
                core.unlockBiometric(key)
                if (started != epoch) runCatching { core.lock() }
                refresh()
            } catch (e: BiometricInvalidated) {
                biometricUsable = false
                biometricKeyValid = false
                error = e.message
            } catch (e: BiometricFailure) {
                if (started == epoch) error = e.message
            } catch (e: CoreError) {
                if (started == epoch) error = e.message
            } finally {
                key?.fill(0)
            }
        }
    }

    fun enableBiometrics(prompter: Prompter) {
        val core = core ?: return
        if (busy || biometricJob?.isActive == true) return
        error = null
        val started = epoch
        biometricJob = scope.launch {
            val enrollment = try {
                biometrics.enroll(core.biometricToken(), prompter) ?: return@launch
            } catch (e: BiometricFailure) {
                error = e.message
                return@launch
            } catch (e: CoreError) {
                error = e.message
                return@launch
            }
            try {
                if (started != epoch || status?.unlocked != true) {
                    biometrics.discard(enrollment)
                    return@launch
                }
                // Once the core has the token, its Keystore key must stay.
                withContext(NonCancellable) {
                    try {
                        core.biometricEnroll(enrollment.key, enrollment.token)
                    } catch (e: CoreError) {
                        biometrics.discard(enrollment)
                        throw e
                    }
                    biometrics.commit(enrollment)
                }
                refresh()
                notice = "Fingerprint unlock is on"
            } catch (e: CoreError) {
                error = e.message
            } finally {
                enrollment.key.fill(0)
            }
        }
    }

    // Read approvals. Never answered without the person: Allow needs a fresh
    // biometric unwrap for that exact request, and a request that changed or went
    // away meanwhile is not answered at all.

    /** Polls the core while unlocked and in front. Doesn't count as activity. */
    private suspend fun pollApproval() {
        val core = core ?: return
        val started = epoch
        val pending = try {
            core.approvalPending()
        } catch (_: CoreError) {
            return
        }
        if (started == epoch && status?.unlocked == true && foreground) approval = pending
    }

    fun allowApproval(prompter: Prompter) = answerApproval(allow = true, prompter)

    fun denyApproval() = answerApproval(allow = false, prompter = null)

    private fun answerApproval(allow: Boolean, prompter: Prompter?) {
        val core = core ?: return
        val shown = approval ?: return
        if (approving) return
        val id = shown.id // the request the person saw; nothing else is answered
        val started = epoch
        approving = true
        error = null
        approvalJob = scope.launch {
            var key: ByteArray? = null
            try {
                if (allow) {
                    key = biometrics.unseal(
                        core.biometricToken(),
                        prompter ?: return@launch,
                        "Allow ${shown.originName} to read ${shown.field}?",
                        "Cancel",
                    ) ?: return@launch // dismissed: keep the request up
                }
                if (started != epoch) return@launch
                val current = core.approvalPending()
                if (current?.id != id) {
                    // Answered elsewhere, expired or replaced while the prompt was up.
                    approval = current
                    if (current == null) notice = "That request is no longer waiting."
                    return@launch
                }
                core.approvalRespond(id, allow, key ?: ByteArray(0))
                if (approval?.id == id) approval = null
                notice = if (allow) "Allowed one read of ${shown.field}" else "Request denied"
            } catch (e: BiometricInvalidated) {
                biometricKeyValid = false
                if (started == epoch) error = e.message
            } catch (e: BiometricFailure) {
                if (started == epoch) error = e.message
            } catch (e: CoreError) {
                if (started == epoch) error = e.message
            } finally {
                key?.fill(0)
                if (started == epoch) approving = false
            }
        }
    }

    // Items.

    fun search(text: String) {
        query = text
        val core = core ?: return
        searchJob?.cancel()
        searchJob = scope.launch {
            if (text.isNotEmpty()) delay(SEARCH_DEBOUNCE_MS)
            try {
                val started = System.nanoTime()
                items = core.items(text)
                Perf.search(text, items.size, System.nanoTime() - started)
            } catch (e: CoreError) {
                error = e.message
            }
        }
    }

    fun syncNow() {
        scope.launch { syncOnce() }
    }

    private suspend fun syncOnce() {
        val core = core ?: return
        if (syncing || status?.unlocked != true) return
        syncing = true
        try {
            core.sync()
            syncedAt = System.currentTimeMillis()
            syncError = null
            search(query)
            detail?.let { d -> runCatching { detail = core.item(d.id) } }
        } catch (e: CoreError) {
            syncError = e.message
        } finally {
            syncing = false
        }
    }

    fun openItem(id: String) = browse { core ->
        val item = core.item(id)
        detail = item
        code = null
        codeJob?.cancel()
        if (item.hasOtp) codeJob = scope.launch { runCode(core, id) }
    }

    /** Fetches the current code and counts it down locally, fetching again at each period's end. */
    private suspend fun runCode(core: VaultCore, id: String) {
        while (scope.isActive) {
            val current = try {
                core.code(id)
            } catch (e: CoreError) {
                error = e.message
                return
            }
            code = current
            var remaining = current.remaining
            while (remaining > 0) {
                delay(1_000)
                remaining -= 1
                code = current.copy(remaining = remaining)
            }
        }
    }

    fun closeItem() {
        codeJob?.cancel()
        codeJob = null
        detail = null
        code = null
    }

    fun copyUsername() {
        val d = detail ?: return
        clipboard.copy(d.username, sensitive = false)
        notice = "Username copied"
    }

    fun copyPassword() = browse { core ->
        val d = detail ?: return@browse
        clipboard.copy(core.secret(d.id, "password"), sensitive = true)
        notice = "Password copied. It clears in ${Clipboard.CLEAR_AFTER_MS / 1000} s if unchanged."
    }

    fun copyCode() {
        val c = code ?: return
        clipboard.copy(c.code, sensitive = true)
        notice = "Code copied"
    }
}
