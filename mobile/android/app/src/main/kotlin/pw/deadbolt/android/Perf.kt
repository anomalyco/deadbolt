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

    fun search(query: String, results: Int, nanos: Long) {
        Log.i(TAG, "search len=${query.length} results=$results core=${nanos / 1_000}us")
    }
}
