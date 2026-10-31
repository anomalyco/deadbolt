package pw.deadbolt.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity

/** A FragmentActivity because androidx.biometric's prompt hosts itself in one. */
class MainActivity : FragmentActivity() {
    private val vault get() = (application as DeadboltApp).vault
    private val prompter = ActivityPrompter(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keep vault contents out of screenshots and the recents thumbnail. Debug
        // builds allow capture so the app can be checked on an emulator.
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        vault.start()
        setContent {
            DeadboltTheme {
                DeadboltUi(
                    vault,
                    onBiometricUnlock = { vault.unlockWithBiometrics(prompter) },
                    onEnableBiometrics = { vault.enableBiometrics(prompter) },
                    onAllowApproval = { vault.allowApproval(prompter) },
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        vault.onForeground()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) vault.onBackground()
    }

    override fun onDestroy() {
        super.onDestroy()
        // The prompt belongs to this activity; a recreated one shows its own.
        vault.cancelPrompt()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        vault.onFocus(hasFocus)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        vault.onInteraction()
    }
}
