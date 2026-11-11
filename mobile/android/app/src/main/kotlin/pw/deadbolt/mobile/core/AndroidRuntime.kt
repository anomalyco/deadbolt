package pw.deadbolt.mobile.core

import android.content.Context

/**
 * The JNI entry point crates/mobile-core/src/android.rs exports
 * (`Java_pw_deadbolt_mobile_core_AndroidRuntime_initialize`). UniFFI's own
 * calls go through JNA; this one is plain JNI, so the library is loaded here too.
 */
object AndroidRuntime {
    init {
        System.loadLibrary("deadbolt_mobile_core")
    }

    @JvmStatic
    external fun initialize(context: Context)
}
