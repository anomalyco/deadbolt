package pw.deadbolt.android

import android.app.Application
import android.os.Build
import android.provider.Settings
import java.io.File

class DeadboltApp : Application() {
    /** The vault outlives activities, so a rotation or a recreated window keeps it unlocked. */
    val vault by lazy {
        Vault(
            openCore = {
                val dir = File(noBackupFilesDir, "deadbolt").apply { mkdirs() }
                val name = Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME) ?: Build.MODEL
                Core.open(this, dir.path, name)
            },
            clipboard = Clipboard(this),
            biometrics = KeystoreBiometrics(this),
        )
    }
}
