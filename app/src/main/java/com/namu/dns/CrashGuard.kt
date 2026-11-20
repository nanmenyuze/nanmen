package com.namu.dns

import android.content.Context
import org.json.JSONObject
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * M7 崩溃留痕：只记录最后一次未捕获异常的时间、线程和堆栈，供下次启动的
 * 「版本迁移与崩溃恢复」页展示。仍把异常交给原处理器，不吞崩溃、不改变系统行为。
 */
object CrashGuard {
    private const val PREFS = "namu_maintenance"
    private const val KEY = "last_crash"
    @Volatile private var installed = false

    fun install(context: Context) {
        if (installed) return
        installed = true
        val app = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            runCatching {
                val sw = StringWriter()
                error.printStackTrace(PrintWriter(sw))
                val stack = sw.toString().take(6000)
                JSONObject().apply {
                    put("at", System.currentTimeMillis())
                    put("thread", thread.name)
                    put("type", error.javaClass.name)
                    put("message", error.message ?: "")
                    put("stack", stack)
                }.let { json ->
                    app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                        .edit().putString(KEY, json.toString()).apply()
                }
            }
            if (previous != null) {
                previous.uncaughtException(thread, error)
            } else {
                android.os.Process.killProcess(android.os.Process.myPid())
                kotlin.system.exitProcess(10)
            }
        }
    }

    fun lastCrash(context: Context): JSONObject? = runCatching {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY, null) ?: return null
        JSONObject(raw)
    }.getOrNull()

    fun summary(context: Context): String {
        val c = lastCrash(context) ?: return "未记录到崩溃"
        val at = c.optLong("at")
        val time = if (at > 0) SimpleDateFormat("MM-dd HH:mm", Locale.US).format(Date(at)) else "未知时间"
        val type = c.optString("type").substringAfterLast('.')
        val message = c.optString("message").take(80)
        return "$time · $type${if (message.isBlank()) "" else "：$message"}"
    }
}
