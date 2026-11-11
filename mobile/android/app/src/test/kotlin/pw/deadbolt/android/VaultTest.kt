package pw.deadbolt.android

import javax.crypto.Cipher
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Vault's lifecycle, lock/unlock races and biometric handling, against in-memory seams. */
@OptIn(ExperimentalCoroutinesApi::class)
class VaultTest {
    private class FakeCore : VaultCore {
        var initialized = true
        var unlocked = false
        var biometricReady = true
        var token = byteArrayOf(7, 7)
        var unlockGate: CompletableDeferred<Unit>? = null
        var enrollError: CoreError? = null
        val calls = mutableListOf<String>()
        var biometricKey: ByteArray? = null
        var enrolled: Pair<ByteArray, ByteArray>? = null

        override suspend fun status() = Status(initialized, unlocked, "device", biometricReady)
        override suspend fun joinStart(passphrase: String): String {
            calls += "join-start"
            return "alpha-bravo-charlie-delta-echo"
        }
        override suspend fun joinStatus() = JoinState.Waiting to null
        override suspend fun joinCancel() {
            calls += "join-cancel"
        }
        override suspend fun unlock(passphrase: String) {
            calls += "unlock"
            unlockGate?.await()
            if (passphrase != "right") throw CoreError("The passphrase or biometric key did not unlock this device.")
            unlocked = true
        }
        override suspend fun lock() {
            calls += "lock"
            unlocked = false
        }
        override suspend fun sync() {
            calls += "sync"
        }
        /** When set, each items() call waits here, so a test can type while one runs. */
        var itemsGate: (suspend (String) -> Unit)? = null
        val queries = mutableListOf<String>()
        var rows = listOf(ItemRow("1", "Example", "user@example.com", "login"), ItemRow("2", "Other", "o@example.com", "login"))
        override suspend fun items(query: String): List<ItemRow> {
            queries += query
            itemsGate?.invoke(query)
            return rows.filter { query.isEmpty() || it.title.lowercase().contains(query) }
        }
        override suspend fun item(id: String) = ItemDetail(id, "Example", "user@example.com", "https://example.com", true, true)
        override suspend fun secret(id: String, field: String) = "synthetic-secret"
        override suspend fun code(id: String) = OtpCode("123456", 30, 30)
        override suspend fun biometricEnroll(key: ByteArray, token: ByteArray) {
            calls += "biometric-enroll"
            enrollError?.let { throw it }
            enrolled = key.copyOf() to token
            biometricReady = true
        }
        override suspend fun biometricToken() = token
        override suspend fun unlockBiometric(key: ByteArray) {
            calls += "unlock-biometric"
            biometricKey = key.copyOf()
            unlocked = true
        }

        var pending: PendingApproval? = null
        val responses = mutableListOf<Triple<String, Boolean, ByteArray>>()
        override suspend fun approvalPending() = pending
        override suspend fun approvalRespond(id: String, allow: Boolean, biometricKey: ByteArray) {
            responses += Triple(id, allow, biometricKey.copyOf())
            if (pending?.id == id) pending = null
        }
    }

    private class FakeBiometrics : Biometrics {
        var usable = true
        var unseal = CompletableDeferred<ByteArray?>()
        var unsealError: BiometricFailure? = null
        var enroll = CompletableDeferred<Enrollment?>()
        var promptCancelled = false
        var handedOut: ByteArray? = null
        val committed = mutableListOf<Enrollment>()
        val discarded = mutableListOf<Enrollment>()

        override fun available() = true
        override fun usable(token: ByteArray) = usable
        val titles = mutableListOf<String>()
        override suspend fun unseal(token: ByteArray, prompter: Prompter, title: String, negative: String): ByteArray? {
            titles += title
            unsealError?.let { throw it }
            return try {
                unseal.await().also { handedOut = it }
            } catch (e: CancellationException) {
                promptCancelled = true
                throw e
            }
        }
        override suspend fun enroll(previousToken: ByteArray, prompter: Prompter): Enrollment? = try {
            enroll.await()
        } catch (e: CancellationException) {
            promptCancelled = true
            throw e
        }
        override fun commit(enrollment: Enrollment) {
            committed += enrollment
        }
        override fun discard(enrollment: Enrollment) {
            discarded += enrollment
        }
    }

    private class FakeClipboard : SecretClipboard {
        val copied = mutableListOf<Pair<String, Boolean>>()
        var cleared = 0
        override fun copy(text: String, sensitive: Boolean) {
            copied += text to sensitive
        }
        override fun clearIfDue() {}
        override fun clearOurs() {
            cleared += 1
        }
    }

    private val prompter = Prompter { _: Cipher, _, _ -> error("the fake biometrics never prompt") }

    private class Setup(val vault: Vault, val core: FakeCore, val biometrics: FakeBiometrics, val clipboard: FakeClipboard)

    private fun TestScope.setup(configure: FakeCore.() -> Unit = {}): Setup {
        val core = FakeCore().apply(configure)
        val biometrics = FakeBiometrics()
        val clipboard = FakeClipboard()
        val vault = Vault(
            openCore = { core },
            clipboard = clipboard,
            biometrics = biometrics,
            scope = backgroundScope,
            clock = { testScheduler.currentTime },
        )
        vault.start()
        vault.onForeground()
        runCurrent()
        return Setup(vault, core, biometrics, clipboard)
    }

    @Test
    fun passphraseUnlockShowsTheList() = runTest {
        val s = setup()
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        s.vault.unlock("right")
        runCurrent()
        assertEquals(Vault.Screen.Unlocked, s.vault.screen)
        assertEquals(listOf("Example", "Other"), s.vault.items.map { it.title })
    }

    @Test
    fun wrongPassphraseStaysLockedWithAQuietMessage() = runTest {
        val s = setup()
        s.vault.unlock("wrong")
        runCurrent()
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertNotNull(s.vault.error)
        assertFalse(s.vault.busy)
    }

    @Test
    fun lockDuringAPassphraseUnlockEndsLocked() = runTest {
        val s = setup()
        val gate = CompletableDeferred<Unit>()
        s.core.unlockGate = gate
        s.vault.unlock("right")
        runCurrent()
        s.vault.lock()
        runCurrent()
        gate.complete(Unit)
        runCurrent()
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertFalse(s.core.unlocked)
        assertEquals("lock", s.core.calls.last())
        assertNull(s.vault.error)
    }

    @Test
    fun leavingTheAppDuringAPassphraseUnlockEndsLocked() = runTest {
        val s = setup()
        val gate = CompletableDeferred<Unit>()
        s.core.unlockGate = gate
        s.vault.unlock("right")
        runCurrent()
        s.vault.onBackground()
        runCurrent()
        gate.complete(Unit)
        runCurrent()
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertFalse(s.core.unlocked)
    }

    @Test
    fun leavingTheAppLocksAnUnlockedVault() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.vault.onBackground()
        runCurrent()
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertTrue(s.vault.items.isEmpty())
    }

    @Test
    fun leavingTheAppDuringPairingCancelsItAndLocks() = runTest {
        val s = setup { initialized = false }
        assertEquals(Vault.Screen.Pair, s.vault.screen)
        s.vault.startPairing("new phone pass")
        runCurrent()
        assertEquals("alpha-bravo-charlie-delta-echo", s.vault.pairingCode)
        s.vault.onBackground()
        runCurrent()
        assertNull(s.vault.pairingCode)
        assertTrue("lock" in s.core.calls)
        assertNotNull("a quiet retry hint", s.vault.error)
        advanceTimeBy(Vault.JOIN_POLL_MS * 5)
        assertNull(s.vault.pairingCode)
    }

    @Test
    fun leavingWhileThePairingCodeIsMadeStopsTheJoin() = runTest {
        val s = setup { initialized = false }
        s.vault.startPairing("new phone pass")
        s.vault.onBackground() // before join-start returns
        runCurrent()
        assertNull(s.vault.pairingCode)
        assertTrue("join-cancel" in s.core.calls)
    }

    @Test
    fun leavingDuringAColdStartUnlockEndsLocked() = runTest {
        val core = FakeCore().apply { unlockGate = CompletableDeferred() }
        val vault = Vault({ core }, FakeClipboard(), FakeBiometrics(), backgroundScope, { testScheduler.currentTime })
        vault.start()
        vault.onForeground()
        runCurrent()
        vault.unlock("right")
        runCurrent()
        vault.onBackground()
        core.unlockGate!!.complete(Unit)
        runCurrent()
        assertFalse(core.unlocked)
        assertEquals(Vault.Screen.Locked, vault.screen)
    }

    @Test
    fun cancellingPairingStopsTheJoin() = runTest {
        val s = setup { initialized = false }
        s.vault.startPairing("new phone pass")
        runCurrent()
        s.vault.cancelPairing()
        runCurrent()
        assertNull(s.vault.pairingCode)
        assertTrue("join-cancel" in s.core.calls)
    }

    @Test
    fun biometricUnlockUsesTheKeyOnceThenWipesIt() = runTest {
        val s = setup()
        assertTrue(s.vault.shouldAutoPrompt())
        s.vault.unlockWithBiometrics(prompter)
        runCurrent()
        s.biometrics.unseal.complete(ByteArray(32) { 9 })
        runCurrent()
        assertEquals(Vault.Screen.Unlocked, s.vault.screen)
        assertArrayEquals(ByteArray(32) { 9 }, s.core.biometricKey)
        assertArrayEquals(ByteArray(32), s.biometrics.handedOut)
        assertFalse(s.vault.shouldAutoPrompt())
    }

    @Test
    fun dismissingTheBiometricPromptStaysLockedQuietly() = runTest {
        val s = setup()
        s.vault.unlockWithBiometrics(prompter)
        runCurrent()
        s.biometrics.unseal.complete(null)
        runCurrent()
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertFalse("unlock-biometric" in s.core.calls)
        assertNull(s.vault.error)
        assertFalse("no second automatic prompt", s.vault.shouldAutoPrompt())
    }

    @Test
    fun lockingDuringABiometricPromptCancelsItAndDropsALateReply() = runTest {
        val s = setup()
        s.vault.unlockWithBiometrics(prompter)
        runCurrent()
        s.vault.lock()
        runCurrent()
        assertTrue(s.biometrics.promptCancelled)
        s.biometrics.unseal.complete(ByteArray(32) { 1 })
        runCurrent()
        assertFalse("unlock-biometric" in s.core.calls)
        assertEquals(Vault.Screen.Locked, s.vault.screen)
    }

    @Test
    fun aPassphraseUnlockReplacesAPendingBiometricPrompt() = runTest {
        val s = setup()
        s.vault.unlockWithBiometrics(prompter)
        runCurrent()
        s.vault.unlock("right")
        runCurrent()
        assertTrue(s.biometrics.promptCancelled)
        assertFalse("unlock-biometric" in s.core.calls)
        assertEquals(Vault.Screen.Unlocked, s.vault.screen)
    }

    @Test
    fun aClosedActivityDismissesItsPromptWithoutLocking() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.vault.enableBiometrics(prompter)
        runCurrent()
        s.vault.cancelPrompt()
        runCurrent()
        assertTrue(s.biometrics.promptCancelled)
        assertEquals(Vault.Screen.Unlocked, s.vault.screen)
        assertFalse("biometric-enroll" in s.core.calls)
    }

    @Test
    fun invalidatedBiometricsFallBackToThePassphrase() = runTest {
        val s = setup()
        s.biometrics.unsealError = BiometricInvalidated()
        s.vault.unlockWithBiometrics(prompter)
        runCurrent()
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertFalse(s.vault.biometricUsable)
        assertNotNull(s.vault.error)
    }

    @Test
    fun aKeystoreFailureIsAQuietMessageNotACrash() = runTest {
        val s = setup()
        s.biometrics.unsealError = BiometricFailure("Fingerprint unlock isn't working right now. Use your passphrase.")
        s.vault.unlockWithBiometrics(prompter)
        runCurrent()
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertEquals("Fingerprint unlock isn't working right now. Use your passphrase.", s.vault.error)
        s.vault.unlock("right")
        runCurrent()
        assertEquals(Vault.Screen.Unlocked, s.vault.screen)
    }

    @Test
    fun enrollingStoresTheTokenKeepsTheKeyAndWipesIt() = runTest {
        val s = setup { biometricReady = false }
        s.vault.unlock("right")
        runCurrent()
        s.vault.enableBiometrics(prompter)
        runCurrent()
        val enrollment = Enrollment(ByteArray(32) { 3 }, byteArrayOf(1, 2, 3), "new", "old")
        s.biometrics.enroll.complete(enrollment)
        runCurrent()
        assertArrayEquals(ByteArray(32) { 3 }, s.core.enrolled?.first)
        assertEquals(listOf(enrollment), s.biometrics.committed)
        assertTrue(s.biometrics.discarded.isEmpty())
        assertArrayEquals(ByteArray(32), enrollment.key)
    }

    @Test
    fun aFailedEnrollmentDropsTheNewKeystoreKey() = runTest {
        val s = setup { biometricReady = false }
        s.vault.unlock("right")
        runCurrent()
        s.core.enrollError = CoreError("Unlock Deadbolt first.")
        s.vault.enableBiometrics(prompter)
        runCurrent()
        val enrollment = Enrollment(ByteArray(32) { 3 }, byteArrayOf(1), "new", null)
        s.biometrics.enroll.complete(enrollment)
        runCurrent()
        assertEquals(listOf(enrollment), s.biometrics.discarded)
        assertTrue(s.biometrics.committed.isEmpty())
        assertNotNull(s.vault.error)
    }

    @Test
    fun anEnrollmentFinishingAfterLockIsDiscarded() = runTest {
        val s = setup { biometricReady = false }
        s.vault.unlock("right")
        runCurrent()
        s.vault.enableBiometrics(prompter)
        runCurrent()
        s.vault.lock()
        runCurrent()
        assertTrue(s.biometrics.promptCancelled)
        assertFalse("biometric-enroll" in s.core.calls)
    }

    @Test
    fun idleLocksAndTheCodeCountdownDoesNotKeepItOpen() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.vault.openItem("1")
        runCurrent()
        assertNotNull(s.vault.code)
        advanceTimeBy(Vault.IDLE_LOCK_MS - 20_000)
        assertEquals(Vault.Screen.Unlocked, s.vault.screen)
        advanceTimeBy(40_000)
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertNull(s.vault.code)
        assertFalse("an idle lock is quiet: no automatic prompt", s.vault.shouldAutoPrompt())
    }

    @Test
    fun aTouchPostponesTheIdleLock() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        advanceTimeBy(Vault.IDLE_LOCK_MS - 30_000)
        s.vault.onInteraction()
        advanceTimeBy(60_000)
        assertEquals(Vault.Screen.Unlocked, s.vault.screen)
    }

    @Test
    fun copyingAPasswordMarksItSensitive() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.vault.openItem("1")
        runCurrent()
        s.vault.copyUsername()
        s.vault.copyPassword()
        runCurrent()
        assertEquals(listOf("user@example.com" to false, "synthetic-secret" to true), s.clipboard.copied)
    }

    // Read approvals.

    private val request = PendingApproval(
        id = "r1",
        originName = "Work laptop",
        title = "Example",
        field = "password",
        caller = "\"/usr/local/bin/deadbolt\" · pid 42:7 · cdhash ${"a".repeat(40)} · OpenCode (ancestry hint)",
        expiresAt = 2_000_000_000,
    )

    private fun TestScope.unlockedWithRequest(): Setup {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.core.pending = request
        advanceTimeBy(Vault.APPROVAL_POLL_MS + 1)
        return s
    }

    @Test
    fun aRequestShowsWhileUnlockedAndPollingDoesNotKeepItOpen() = runTest {
        val s = unlockedWithRequest()
        assertEquals(request, s.vault.approval)
        advanceTimeBy(Vault.IDLE_LOCK_MS + 20_000)
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertNull(s.vault.approval)
        assertTrue(s.core.responses.isEmpty())
    }

    @Test
    fun noRequestIsPolledInTheBackground() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.vault.onBackground()
        runCurrent()
        s.core.pending = request
        advanceTimeBy(Vault.APPROVAL_POLL_MS * 5)
        assertNull(s.vault.approval)
    }

    @Test
    fun allowingUnwrapsAFreshKeyForThatRequestAndWipesIt() = runTest {
        val s = unlockedWithRequest()
        s.vault.allowApproval(prompter)
        runCurrent()
        assertEquals(listOf("Allow Work laptop to read password?"), s.biometrics.titles)
        s.biometrics.unseal.complete(ByteArray(32) { 5 })
        runCurrent()
        val (id, allow, key) = s.core.responses.single()
        assertEquals("r1", id)
        assertTrue(allow)
        assertArrayEquals(ByteArray(32) { 5 }, key)
        assertArrayEquals(ByteArray(32), s.biometrics.handedOut)
        assertNull(s.vault.approval)
        assertFalse(s.vault.approving)
    }

    @Test
    fun dismissingTheAllowPromptAnswersNothing() = runTest {
        val s = unlockedWithRequest()
        s.vault.allowApproval(prompter)
        runCurrent()
        s.biometrics.unseal.complete(null)
        runCurrent()
        assertTrue(s.core.responses.isEmpty())
        assertEquals(request, s.vault.approval)
        assertFalse(s.vault.approving)
    }

    @Test
    fun aRequestReplacedDuringThePromptIsNotAnswered() = runTest {
        val s = unlockedWithRequest()
        s.vault.allowApproval(prompter)
        runCurrent()
        val other = request.copy(id = "r2", title = "Other")
        s.core.pending = other
        s.biometrics.unseal.complete(ByteArray(32) { 5 })
        runCurrent()
        assertTrue(s.core.responses.isEmpty())
        assertArrayEquals(ByteArray(32), s.biometrics.handedOut)
        assertEquals(other, s.vault.approval)
    }

    @Test
    fun aRequestThatExpiredDuringThePromptIsNotAnswered() = runTest {
        val s = unlockedWithRequest()
        s.vault.allowApproval(prompter)
        runCurrent()
        s.core.pending = null
        s.biometrics.unseal.complete(ByteArray(32) { 5 })
        runCurrent()
        assertTrue(s.core.responses.isEmpty())
        assertNull(s.vault.approval)
    }

    @Test
    fun lockingDuringTheAllowPromptHidesTheRequestAndDropsTheReply() = runTest {
        val s = unlockedWithRequest()
        s.vault.allowApproval(prompter)
        runCurrent()
        s.vault.lock()
        runCurrent()
        assertTrue(s.biometrics.promptCancelled)
        assertNull(s.vault.approval)
        s.biometrics.unseal.complete(ByteArray(32) { 5 })
        runCurrent()
        assertTrue(s.core.responses.isEmpty())
    }

    @Test
    fun leavingDuringTheAllowPromptAnswersNothing() = runTest {
        val s = unlockedWithRequest()
        s.vault.allowApproval(prompter)
        runCurrent()
        s.vault.onBackground()
        runCurrent()
        assertTrue(s.biometrics.promptCancelled)
        assertTrue(s.core.responses.isEmpty())
        assertNull(s.vault.approval)
    }

    @Test
    fun denyingSendsNoKeyAndOnlyForTheShownRequest() = runTest {
        val s = unlockedWithRequest()
        s.vault.denyApproval()
        runCurrent()
        val (id, allow, key) = s.core.responses.single()
        assertEquals("r1", id)
        assertFalse(allow)
        assertEquals(0, key.size)
        assertTrue(s.biometrics.titles.isEmpty())
    }

    @Test
    fun aBiometricFailureOnAllowIsQuietAndAnswersNothing() = runTest {
        val s = unlockedWithRequest()
        s.biometrics.unsealError = BiometricInvalidated()
        s.vault.allowApproval(prompter)
        runCurrent()
        assertTrue(s.core.responses.isEmpty())
        assertFalse(s.vault.biometricKeyValid)
        assertNotNull(s.vault.error)
        assertEquals(request, s.vault.approval)
    }

    @Test
    fun theCallerSplitsTheCheckedProgramFromUnverifiedHints() {
        assertEquals(CallerLabel("/usr/local/bin/deadbolt", "OpenCode"), CallerLabel.parse(request.caller))
        assertEquals(
            CallerLabel("/usr/local/bin/deadbolt", "AI session"),
            CallerLabel.parse("\"/usr/local/bin/deadbolt\" · pid 1:2 · cdhash x · AI session claimed (not verified)"),
        )
        assertEquals(CallerLabel("something odd", null), CallerLabel.parse("something odd"))
    }

    // Review fixes: re-enrolling after invalidation or expiry, clipboard on lock.

    @Test
    fun anInvalidatedKeyOffersFingerprintUnlockAgainEvenWithTheOldTokenStored() = runTest {
        val s = setup { biometricReady = true }
        s.biometrics.usable = false // Keystore key deleted; the core still holds its token
        s.vault.unlock("right")
        runCurrent()
        assertTrue(s.vault.canEnableBiometrics)
        s.vault.enableBiometrics(prompter)
        runCurrent()
        s.biometrics.usable = true
        s.biometrics.enroll.complete(Enrollment(ByteArray(32) { 4 }, byteArrayOf(9), "new", "old"))
        runCurrent()
        assertTrue("biometric-enroll" in s.core.calls)
        assertFalse(s.vault.canEnableBiometrics)
    }

    @Test
    fun anExpiredFingerprintUnlockNeedsThePassphraseThenCanBeTurnedOnAgain() = runTest {
        val s = setup()
        assertTrue(s.vault.biometricUsable)
        s.biometrics.unsealError = BiometricExpired()
        s.vault.unlockWithBiometrics(prompter)
        runCurrent()
        assertEquals(Vault.Screen.Locked, s.vault.screen)
        assertFalse(s.vault.biometricUsable)
        assertEquals(BiometricExpired().message, s.vault.error)
        s.biometrics.usable = false // what KeystoreBiometrics reports past 14 days
        s.vault.unlock("right")
        runCurrent()
        assertEquals(Vault.Screen.Unlocked, s.vault.screen)
        assertTrue(s.vault.canEnableBiometrics)
    }

    @Test
    fun lockingClearsOurCopiedSecretOnlyWhileFocused() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.vault.onFocus(true)
        s.vault.lock()
        runCurrent()
        assertEquals(1, s.clipboard.cleared)
        s.vault.unlock("right")
        runCurrent()
        s.vault.onBackground() // focus is gone: the clear waits for the next focus
        runCurrent()
        assertEquals(1, s.clipboard.cleared)
    }

    @Test
    fun comingBackAfterABackgroundLockAsksForTheFingerprintOnce() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.vault.onBackground()
        runCurrent()
        val before = s.vault.autoPromptTick
        s.vault.onForeground()
        runCurrent()
        assertTrue(s.vault.autoPromptTick > before)
        assertTrue(s.vault.shouldAutoPrompt())
        s.vault.unlockWithBiometrics(prompter)
        runCurrent()
        s.biometrics.unseal.complete(null) // dismissed
        runCurrent()
        assertFalse(s.vault.shouldAutoPrompt())
    }

    // Search: immediate, one core call at a time, latest query wins.

    @Test
    fun searchRunsWithoutATypingPause() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.vault.search("ex")
        runCurrent() // no virtual time passes
        assertEquals(listOf("Example"), s.vault.items.map { it.title })
    }

    @Test
    fun fastTypingRunsTheLatestQueryAndNeverShowsAStaleOne() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        val gates = mutableMapOf<String, CompletableDeferred<Unit>>()
        s.core.itemsGate = { q -> gates.getOrPut(q) { CompletableDeferred() }.await() }
        s.core.queries.clear()
        s.vault.search("o")
        runCurrent()
        s.vault.search("ot")
        s.vault.search("oth")
        runCurrent()
        assertEquals("one call at a time", listOf("o"), s.core.queries)
        gates.getValue("o").complete(Unit)
        runCurrent()
        assertEquals("the stale \"o\" result is not shown", listOf("Example", "Other"), s.vault.items.map { it.title })
        assertEquals("skips \"ot\", runs the latest", listOf("o", "oth"), s.core.queries)
        gates.getValue("oth").complete(Unit)
        runCurrent()
        assertEquals(listOf("Other"), s.vault.items.map { it.title })
        assertEquals("oth", s.vault.query)
    }

    @Test
    fun clearingTheSearchShowsTheFullListAtOnce() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.vault.search("oth")
        runCurrent()
        s.core.queries.clear()
        s.core.itemsGate = { CompletableDeferred<Unit>().await() } // the core would hang
        s.vault.search("")
        assertEquals(listOf("Example", "Other"), s.vault.items.map { it.title })
        runCurrent()
        assertTrue("no core call for the cached full list", s.core.queries.isEmpty())
    }

    @Test
    fun aSyncRefreshesTheCachedFullList() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        s.core.rows = s.core.rows + ItemRow("3", "New", "n@example.com", "login")
        s.vault.syncNow()
        runCurrent()
        assertEquals(listOf("Example", "Other", "New"), s.vault.items.map { it.title })
    }

    @Test
    fun aSyncDuringASearchRerunsItAfterwardsWithoutASecondCoreCall() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        val gates = mutableListOf<CompletableDeferred<Unit>>()
        s.core.itemsGate = { CompletableDeferred<Unit>().also { gates += it }.await() }
        s.core.queries.clear()
        s.vault.search("o")
        runCurrent()
        s.core.rows = s.core.rows + ItemRow("3", "Oak", "k@example.com", "login")
        s.vault.syncNow()
        runCurrent()
        assertEquals("still one call at a time", listOf("o"), s.core.queries)
        gates[0].complete(Unit)
        runCurrent()
        assertEquals("the query runs again after the sync", listOf("o", "o"), s.core.queries)
        gates[1].complete(Unit)
        runCurrent()
        assertEquals(listOf("Other", "Oak"), s.vault.items.map { it.title })
        s.core.itemsGate = null
        s.vault.search("")
        runCurrent()
        assertEquals("the pre-sync full list was never cached", listOf("Example", "Other", "Oak"), s.vault.items.map { it.title })
    }

    @Test
    fun lockingDuringASearchDropsItsResult() = runTest {
        val s = setup()
        s.vault.unlock("right")
        runCurrent()
        val gate = CompletableDeferred<Unit>()
        s.core.itemsGate = { gate.await() }
        s.vault.search("ex")
        runCurrent()
        s.vault.lock()
        runCurrent()
        gate.complete(Unit)
        runCurrent()
        assertTrue(s.vault.items.isEmpty())
        assertEquals("", s.vault.query)
    }
}
