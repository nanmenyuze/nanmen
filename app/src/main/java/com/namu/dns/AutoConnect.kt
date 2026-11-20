package com.namu.dns

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * 按需连接：开机广播和默认网络恢复时，在用户开启「自动连接」且 VPN 已授权的情况下
 * 尝试拉起前台服务。未授权时不从后台弹 Activity，只发通知让用户回到 App 处理。
 */
object AutoConnect {
    private const val CHANNEL_ID = "namu_auto_connect"
    private const val NOTIF_ID = 1002
    private const val MIN_ATTEMPT_GAP_MS = 5_000L
    private const val NETWORK_DEBOUNCE_MS = 2_500L

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var installed = false
    private var pending: Job? = null
    private var lastAttemptAt = 0L

    fun install(context: Context) {
        val app = context.applicationContext
        if (installed) return
        installed = true
        ensureChannel(app)
        val cm = app.getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                schedule(app, NETWORK_DEBOUNCE_MS)
            }
        }
        // 部分精简 ROM 会拒绝注册默认网络回调；失败时仍保留开机广播入口。
        runCatching { cm.registerDefaultNetworkCallback(callback) }
    }

    fun onBoot(context: Context) {
        schedule(context.applicationContext, 1_500L)
    }

    private fun schedule(context: Context, delayMs: Long) {
        if (!runCatching { App.container.settings.current().autoConnect }.getOrDefault(false)) return
        pending?.cancel()
        pending = scope.launch {
            delay(delayMs)
            attempt(context)
        }
    }

    /** 满足条件才启动；任何异常都降级为通知，不让广播接收器崩溃。 */
    fun attempt(context: Context) {
        val app = context.applicationContext
        val cfg = runCatching { App.container.settings.current() }.getOrNull() ?: return
        if (!cfg.autoConnect) return
        if (NamuVpnService.isRunning()) return
        if (runCatching { App.container.runtime.current().starting }.getOrDefault(false)) return
        val now = SystemClock.elapsedRealtime()
        if (now - lastAttemptAt < MIN_ATTEMPT_GAP_MS) return
        lastAttemptAt = now

        if (VpnService.prepare(app) != null) {
            notify(
                app,
                "自动连接需要 VPN 授权",
                "点此打开南门DNS，在系统弹窗中允许 VPN 后即可自动连接。",
            )
            return
        }
        if (cfg.nodes.isEmpty() && cfg.mode != "dns_only") {
            notify(
                app,
                "自动连接暂不可用",
                "当前配置没有可用节点；请先导入节点，或切换为仅 DNS 过滤模式。",
            )
            return
        }
        try {
            ContextCompat.startForegroundService(
                app,
                Intent(app, NamuVpnService::class.java).setAction(NamuVpnService.ACTION_START),
            )
        } catch (t: Throwable) {
            notify(app, "自动连接失败", t.message ?: "系统限制了后台启动，请手动打开 App 连接。")
        }
    }

    private fun ensureChannel(app: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = app.getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "自动连接",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "开机或网络恢复时的 VPN 自动连接状态"
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun notify(app: Context, title: String, text: String) {
        ensureChannel(app)
        val open = PendingIntent.getActivity(
            app,
            3,
            Intent(app, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(app, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()
        try {
            NotificationManagerCompat.from(app).notify(NOTIF_ID, notification)
        } catch (_: SecurityException) {
            // Android 13+ 未授予通知权限：自动连接仍不会崩溃，用户下次打开 App 可看到开关状态。
        }
    }
}
