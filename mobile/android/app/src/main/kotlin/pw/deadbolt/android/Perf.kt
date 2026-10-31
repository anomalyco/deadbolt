package pw.deadbolt.android

import android.os.Process
import android.os.SystemClock
import android.util.Log

/**
 * Timing marks in logcat (tag DeadboltPerf), read by the launch and search
 * measurements: milliseconds since the process started, and search latency.
 */
object Perf {
    private const val TAG = "DeadboltPerf"
    private val marked = mutableSetOf<String>()

    /** Logs [name] the first time it happens in this process. */
    fun mark(name: String) {
        if (!marked.add(name)) return
        Log.i(TAG, "$name +${SystemClock.uptimeMillis() - Process.getStartUptimeMillis()}ms")
    }

    /** A core call's time through the FFI into Rust ([callNanos]) and parsing its JSON into rows in Kotlin ([rowsNanos]). */
    fun split(what: String, callNanos: Long, rowsNanos: Long) {
        Log.i(TAG, "$what call=${callNanos / 1_000}us rows=${rowsNanos / 1_000}us")
    }

    /** Logs [name] and how long it took, every time. */
    fun event(name: String, nanos: Long) {
        Log.i(TAG, "$name ${nanos / 1_000_000}ms")
    }

    /** The list showing new rows; logcat's timestamp is the moment. */
    fun shown(queryLength: Int, rows: Int) {
        Log.i(TAG, "shown len=$queryLength rows=$rows")
    }

    fun search(query: String, results: Int, nanos: Long) {
        Log.i(TAG, "search len=${query.length} results=$results core=${nanos / 1_000}us")
    }
}
