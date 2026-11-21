package com.namu.dns

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

class NamuVpnService : VpnService() {

    /** 切网纯决策结果，与 Android 框架解耦以便单测。 */
    enum class NetSwitchDecision { NONE, REBUILD_NOW, CONFIRM_LATER }

    companion object {
        const val ACTION_START = "com.namu.dns.START"
        const val ACTION_STOP = "com.namu.dns.STOP"
        const val ACTION_RELOAD = "com.namu.dns.RELOAD"

        @Volatile private var alive = false

        fun isRunning(): Boolean = alive

        fun reload(context: android.content.Context) {
            try {
                context.startService(
                    Intent(context, NamuVpnService::class.java).setAction(ACTION_RELOAD),
                )
            } catch (_: Exception) {
            }
        }

        fun stop(context: android.content.Context) {
            // 用显式 ACTION_STOP 而不是只 stopService：即使 Activity 被重建、
            // App.connected 状态丢失，也一定能走到 stopVpn() 清理 TUN。
            try {
                context.startService(
                    Intent(context, NamuVpnService::class.java).setAction(ACTION_STOP),
                )
            } catch (_: Exception) {
                try {
                    context.stopService(Intent(context, NamuVpnService::class.java))
                } catch (_: Exception) {
                }
            }
        }
        /** 供 QS 磁贴等外壳入口复用：与 MainActivity.startVpnService 行为一致。 */
        fun start(context: android.content.Context) {
            if (App.container.settings.current().autoClearLogs) {
                App.container.logs.clearRuntime()
                App.container.logs.clearDns()
            }
            App.container.runtime.markStarting()
            val intent = Intent(context, NamuVpnService::class.java).setAction(ACTION_START)
            try {
                androidx.core.content.ContextCompat.startForegroundService(context, intent)
            } catch (e: Exception) {
                // Android 12+ 后台启动限制、权限撤销等都会在这里抛出，不能留下“启动中”。
                App.container.runtime.markStartFailed()
                App.container.messages.show("启动失败：${e.message ?: "无法启动 VPN 服务"}")
            }
        }

        private const val CHANNEL_ID = "namu_vpn_status"
        private const val NOTIF_ID = 1001

        /**
         * 切网确认窗口。Wi-Fi 的 VALIDATED 位会抖（门户复验/息屏/ROM 周期重验），
         * 每抖一次就整隧道重建会让所有连接瞬断（随机全断）。
         * 当前网络仍可用时，"更优"网络必须稳定存在这么久才真正切换；
         * 当前网络真正丢失（onLost）则立即重建，不受窗口限制。
         */
        const val NETWORK_SWITCH_CONFIRM_MS = 5000L
        /** 重建失败后的自动重试延迟：切网瞬间 establish 偶发失败，重试一次通常即成。 */
        const val REBUILD_RETRY_DELAY_MS = 3000L

        fun decideNetworkSwitch(
            pickedIsNull: Boolean,
            pickedIsCurrent: Boolean,
            currentUsable: Boolean,
        ): NetSwitchDecision = when {
            pickedIsNull || pickedIsCurrent -> NetSwitchDecision.NONE
            !currentUsable -> NetSwitchDecision.REBUILD_NOW
            else -> NetSwitchDecision.CONFIRM_LATER
        }
    }

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false
    @Volatile private var stopping = false
    @Volatile private var rebuilding = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var currentNetwork: Network? = null
    @Volatile private var pendingNetworkRebuild = false
    @Volatile private var activeMode: String? = null
    /** 最后一次成功下发给内核的 JSON，用于重载失败回滚。 */
    @Volatile private var lastGoodJson: String? = null
    @Volatile private var reloading = false
    /** 重载进行中又来了新请求：结束后要再跑一遍，否则「保存了但内核还用旧设置」。 */
    @Volatile private var pendingReload = false

    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }
    private val rebuildRunnable = Runnable { rebuildTunnel() }
    private val confirmSwitchRunnable = Runnable { confirmNetworkSwitch() }
    /** 重建失败已自动重试过一次：再失败就干净停止，不留半死状态。 */
    @Volatile private var rebuildRetried = false
    // 所有 nativeStart / nativeStop 串行执行，避免关闭线程把刚启动的新内核再停掉。
    private val nativeLock = Any()

    private val settings get() = App.container.settings
    private val runtime get() = App.container.runtime
    private val messages get() = App.container.messages

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_RELOAD -> if (!stopping) reloadConfig()
            else -> if (!stopping) startVpn()
        }
        return START_STICKY
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.vpn_channel),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "DNS 过滤与分流运行状态"
                setShowBadge(false)
            }
            manager.createNotificationChannel(channel)
        }
    }

    // B1 通知每 2 秒刷新实时速率（仅运行中；无通知权限时静默跳过）。
    private val notifTick = object : Runnable {
        override fun run() {
            if (!running || stopping) return
            try {
                NotificationManagerCompat.from(this@NamuVpnService).notify(NOTIF_ID, buildNotification())
            } catch (_: SecurityException) {
            }
            mainHandler.postDelayed(this, 2000)
        }
    }

    private fun startNotifUpdates() {
        mainHandler.removeCallbacks(notifTick)
        mainHandler.postDelayed(notifTick, 2000)
    }

    private fun stopNotifUpdates() {
        mainHandler.removeCallbacks(notifTick)
    }

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, NamuVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val nodesIntent = PendingIntent.getActivity(
            this,
            2,
            Intent(this, MainActivity::class.java).putExtra("open_nodes", true),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val speedText = if (!stopping && running) {
            val s = App.container.stats.state.value.speedSamples.lastOrNull()
            if (s != null) " · ↑${com.namu.dns.ui.formatBytes(s.up)}/s ↓${com.namu.dns.ui.formatBytes(s.down)}/s" else ""
        } else ""
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.vpn_title))
            .setContentText(if (stopping) "正在关闭，释放内核与 TUN…" else "${modeLabel()} · ${App.container.nodeLabel()}$speedText")
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setShowWhen(false)
            .addAction(0, "切换节点", nodesIntent)
            .addAction(0, getString(R.string.vpn_stop), stopIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun startForegroundNow() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notification)
        }
        try {
            NotificationManagerCompat.from(this).notify(NOTIF_ID, notification)
        } catch (_: SecurityException) {
        }
    }

    private fun modeLabel(): String = when (settings.current().mode) {
        "global" -> "全局代理"
        "dns_only" -> "仅 DNS 过滤"
        "filter_only" -> "纯过滤（不代理）"
        else -> "规则分流"
    }

    private fun startVpn() {
        if (running || stopping) return
        if (!NativeCore.available) {
            messages.show("内核加载失败（native 库缺失）")
            runtime.markStartFailed()
            stopSelf()
            return
        }
        runtime.markStarting()
        val startedAt = android.os.SystemClock.elapsedRealtime()
        startForegroundNow()
        // 配置读写、TUN 建立、nativeStart（内部最长 3s 停止等待 + 300ms 就绪等待）
        // 全部放后台线程，避免主线程阻塞造成 jank/ANR。
        Thread {
            try {
                val cfg = settings.current()
                currentNetwork = pickUnderlyingNetwork()
                if (cfg.autoDisablePrivateDns) {
                    if (!PrivateDnsController.disable(this)) {
                        messages.show("关闭私人 DNS 失败：需要 Root 授权")
                    }
                } else if (PrivateDnsController.bypassing(this)) {
                    messages.show("系统私人 DNS 已开启，DNS 会被 DoT 绕过")
                }
                val pfd = establishTun(cfg)
                if (pfd == null) {
                    if (!stopping) {
                        messages.show("VPN 建立失败，请检查是否有其他 VPN 正在运行")
                        runtime.markStartFailed()
                        mainHandler.post { stopForeground(true); stopSelf() }
                    }
                    return@Thread
                }
                if (stopping) {
                    pfd.close()
                    return@Thread
                }
                val json = try {
                    ConfigStore.buildNative(this, cfg)
                } catch (t: Throwable) {
                    pfd.close()
                    throw t
                }
                val ok = synchronized(nativeLock) {
                    if (stopping) false
                    else NativeCore.nativeStart(pfd.fd, json)
                }
                if (!ok) {
                    pfd.close()
                    messages.show("内核启动失败，请查看日志")
                    runtime.markStartFailed()
                    mainHandler.post { stopForeground(true); stopSelf() }
                    return@Thread
                }
                tun = pfd
                activeMode = cfg.mode
                lastGoodJson = json
                running = true
                alive = true
                rebuildRetried = false
                runtime.markConnected(android.os.SystemClock.elapsedRealtime() - startedAt)
                App.container.refreshRuntime()
                startNetworkMonitor()
                startNotifUpdates()
                // 按 App 分流的数据源：VPN 起来后才开始读表下发。
                UidTablePublisher.start()
            } catch (t: Throwable) {
                messages.show("启动失败: ${t.message}")
                runtime.markStartFailed()
                mainHandler.post { stopForeground(true); stopSelf() }
            }
        }.start()
    }

    private fun reloadConfig() {
        if (!running || stopping) return
        if (reloading || rebuilding) {
            pendingReload = true
            return
        }
        val pfd = tun ?: return
        val cfg = settings.current()
        if (activeMode != cfg.mode) {
            // 模式变化会改变 TUN 路由，必须重建接口；其余设置只热重启内核。
            rebuildTunnel()
            return
        }
        reloading = true
        Thread {
            try {
                val json = ConfigStore.buildNative(this, cfg)
                // 内核热重载现在会一并更新运行配置/节点/选中线路，
                // 优先热重载（连接不中断）；失败才回退整核重启。
                val ok = synchronized(nativeLock) {
                    if (stopping || !running) false
                    else try {
                        if (NativeCore.nativeReloadRules(json)) {
                            true
                        } else {
                            NativeCore.nativeStart(pfd.fd, json)
                        }
                    } catch (_: Throwable) {
                        false
                    }
                }
                if (ok) {
                    lastGoodJson = json
                    App.container.stats.resetSession()
                    runtime.markConnected(0L)
                    App.container.refreshRuntime()
                } else {
                    // 新配置没有生效：尽量把上一版成功配置重新下发，避免内核停在半套规则。
                    val rolledBack = rollbackToLastGood(pfd, cfg.mode)
                    if (rolledBack) {
                        messages.show("新设置未生效，已回滚到上一版配置")
                    } else {
                        messages.show("设置应用失败，且上一版配置回滚失败，请手动重连")
                    }
                }
            } catch (t: Throwable) {
                val rolledBack = rollbackToLastGood(pfd, cfg.mode)
                messages.show(
                    if (rolledBack) "配置生成失败，已回滚到上一版配置"
                    else "配置生成失败：${t.message ?: "未知错误"}，请手动重连",
                )
            } finally {
                reloading = false
                if (pendingReload) {
                    pendingReload = false
                    reloadConfig()
                }
            }
        }.start()
    }

    /** 在 nativeLock 内把上一版成功 JSON 重新下发；模式已变化时交给 rebuildTunnel。 */
    private fun rollbackToLastGood(pfd: ParcelFileDescriptor, failedMode: String): Boolean {
        val prev = lastGoodJson ?: return false
        if (activeMode != failedMode) return false
        return synchronized(nativeLock) {
            if (stopping || !running) return@synchronized false
            try {
                if (NativeCore.nativeReloadRules(prev)) true
                else NativeCore.nativeStart(pfd.fd, prev)
            } catch (_: Throwable) {
                false
            }
        }.also { ok ->
            if (ok) {
                App.container.stats.resetSession()
                runtime.markConnected(0L)
                App.container.refreshRuntime()
            }
        }
    }

    private fun establishTun(cfg: AppConfig): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("NamuDNS")
            .setMtu(1500)
            .addAddress("10.10.10.1", 24)
            .addRoute("10.10.10.53", 32)
            .addDnsServer("10.10.10.53")
            .addAddress("fd00:1::1", 64)
            .addRoute("fd00:1::53", 128)
            .addDnsServer("fd00:1::53")
            .setBlocking(false)

        if (cfg.mode != "dns_only") {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        } else if (cfg.dnsOnlyFullRoute) {
            // DNS-only 也要全量接管：只加 VPN 的 DNS 地址时，App 硬编码 8.8.8.8、
            // 系统 DoT 853、App 自己的 DoH 都不进 TUN，等于 DNS 泄漏。
            // 全量接管后非 DNS 连接仍直连（内核在 dns_only 下判 Direct），
            // 但所有 DNS 查询都会被劫持到本地引擎，DoT 才会被 block_dot 看到。
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        }
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }
        currentNetwork?.let { network ->
            try {
                builder.setUnderlyingNetworks(arrayOf(network))
            } catch (_: Exception) {
            }
        }
        return builder.establish()
    }

    private fun pickUnderlyingNetwork(): Network? {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return null
        val candidates = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            val rank = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 0
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
                else -> 2
            }
            // 可用性优先于介质类型：已验证的蜂窝必须压过未验证（连上但没网）的 Wi-Fi，
            // 否则酒店/机场 Wi-Fi 门户页会把可用网络顶掉。
            val validated = if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 0 else 1
            Triple(network, validated, rank)
        }.sortedWith(compareBy<Triple<Network, Int, Int>> { it.second }.thenBy { it.third })
        return candidates.firstOrNull()?.first
    }

    private fun startNetworkMonitor() {
        if (networkCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = evaluateNetworks()
            override fun onLost(network: Network) = evaluateNetworks()
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = evaluateNetworks()
        }
        networkCallback = callback
        try {
            cm.registerNetworkCallback(request, callback)
        } catch (_: Exception) {
            try {
                cm.registerDefaultNetworkCallback(callback)
            } catch (_: Exception) {
                networkCallback = null
            }
        }
    }

    private fun stopNetworkMonitor() {
        val cb = networkCallback ?: return
        networkCallback = null
        mainHandler.removeCallbacks(rebuildRunnable)
        mainHandler.removeCallbacks(confirmSwitchRunnable)
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        } catch (_: Exception) {
        }
    }

    private fun evaluateNetworks() {
        if (!running || stopping) return
        val picked = pickUnderlyingNetwork()
        val current = currentNetwork
        when (decideNetworkSwitch(
            pickedIsNull = picked == null,
            pickedIsCurrent = picked == current,
            currentUsable = isNetworkUsable(current),
        )) {
            NetSwitchDecision.NONE -> {
                // 无变化或抖动已还原：撤销待确认的切换。
                // 全部网络丢失时也走这里；等网络恢复后 currentUsable=false 会立即重建。
                mainHandler.removeCallbacks(confirmSwitchRunnable)
            }
            NetSwitchDecision.REBUILD_NOW -> {
                // 当前网络真正丢失：立即切换，不等确认窗口。
                currentNetwork = picked
                mainHandler.removeCallbacks(confirmSwitchRunnable)
                scheduleRebuild()
            }
            NetSwitchDecision.CONFIRM_LATER -> {
                // 当前仍可用但出现"更优"网络：可能是验证位抖动，稳定一个窗口后再切。
                mainHandler.removeCallbacks(confirmSwitchRunnable)
                mainHandler.postDelayed(confirmSwitchRunnable, NETWORK_SWITCH_CONFIRM_MS)
            }
        }
    }

    /** 确认窗口到期复核：仍然翻转才真正切换，抖动还原则什么都不做。 */
    private fun confirmNetworkSwitch() {
        if (!running || stopping) return
        val picked = pickUnderlyingNetwork()
        if (picked == null || picked == currentNetwork) return
        if (rebuilding) {
            pendingNetworkRebuild = true
            return
        }
        currentNetwork = picked
        scheduleRebuild()
    }

    private fun isNetworkUsable(network: Network?): Boolean {
        if (network == null) return false
        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    private fun scheduleRebuild() {
        if (rebuilding) {
            // 重建期间又切网：记一笔，等本次重建结束后再评估，避免连续重建互相打断。
            pendingNetworkRebuild = true
            return
        }
        mainHandler.removeCallbacks(rebuildRunnable)
        mainHandler.postDelayed(rebuildRunnable, 500)
    }

    /** Wi-Fi/蜂窝切换后重建 TUN，避免旧会话被内核挂死。 */
    private fun rebuildTunnel() {
        if (!running || stopping || rebuilding) return
        rebuilding = true
        Thread {
            var success = false
            try {
                synchronized(nativeLock) {
                    if (!running || stopping) return@synchronized
                    val cfg = settings.current()
                    try {
                        NativeCore.nativeStop()
                    } catch (_: Throwable) {
                    }
                    try {
                        tun?.close()
                    } catch (_: Exception) {
                    }
                    tun = null
                    App.container.stats.resetSession()
                    Thread.sleep(120)
                    if (!running || stopping) return@synchronized
                    val pfd = establishTun(cfg)
                    if (pfd != null) {
                        val rebuiltJson = try {
                            ConfigStore.buildNative(this, cfg)
                        } catch (_: Throwable) {
                            null
                        }
                        val ok = try {
                            if (stopping || !running || rebuiltJson == null) false
                            else NativeCore.nativeStart(pfd.fd, rebuiltJson)
                        } catch (_: Throwable) {
                            false
                        }
                        if (ok && rebuiltJson != null && running && !stopping) {
                            tun = pfd
                            activeMode = cfg.mode
                            lastGoodJson = rebuiltJson
                            success = true
                        } else {
                            try { NativeCore.nativeStop() } catch (_: Throwable) {}
                            pfd.close()
                        }
                    }
                }
            } catch (_: Throwable) {
            } finally {
                rebuilding = false
            }
            if (success) {
                rebuildRetried = false
                runtime.markConnected(0L)
                App.container.refreshRuntime()
                if (pendingReload) {
                    pendingReload = false
                    reloadConfig()
                }
            } else if (running && !stopping) {
                if (!rebuildRetried) {
                    // 自动重试一次：切网瞬间 establish 偶发失败，第二次通常即成。
                    rebuildRetried = true
                    mainHandler.removeCallbacks(rebuildRunnable)
                    mainHandler.postDelayed(rebuildRunnable, REBUILD_RETRY_DELAY_MS)
                } else {
                    // 连续两次失败：干净停止。旧逻辑留 running=true/tun=null 的半死态，
                    // 界面显示失败但服务自认在跑，后续重载/切网全部静默失效。
                    messages.show("网络已切换，但隧道重建连续失败，已自动停止，请重新连接")
                    stopVpn()
                }
            }
            if (pendingNetworkRebuild) {
                pendingNetworkRebuild = false
                if (running && !stopping) {
                    // 重建期间网络又变了：重新走滞回评估，而不是无脑再重建。
                    evaluateNetworks()
                }
            }
        }.start()
    }

    private fun stopVpn() {
        if (stopping) return
        stopping = true
        running = false
        reloading = false
        stopNetworkMonitor()
        stopNotifUpdates()
        UidTablePublisher.stop()
        mainHandler.removeCallbacks(rebuildRunnable)
        runtime.markStopping()
        // 先显示“正在关闭”，等 nativeStop 真正返回后再撤 TUN/服务，
        // 避免界面已显示关闭、内核仍持有 TUN dup fd 的假关闭状态。
        try { startForegroundNow() } catch (_: Throwable) {}
        val oldTun = tun
        Thread {
            synchronized(nativeLock) {
                try {
                    if (NativeCore.available) NativeCore.nativeStop()
                } catch (_: Throwable) {
                }
            }
            PrivateDnsController.restore(this)
            mainHandler.post {
                try { oldTun?.close() } catch (_: Exception) {}
                tun = null
                activeMode = null
                runtime.markStopped()
                App.container.refreshRuntime()
                alive = false
                stopForeground(true)
                stopSelf()
            }
        }.start()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        if (!stopping && running) stopVpn()
        // 服务被系统/用户强制销毁时也尝试恢复全局 Private DNS；
        // su 可能等待授权或超时，不能在 onDestroy 主线程直接执行。
        // 正常 stopVpn 已在其后台线程负责恢复，这里只兜底未走停止流程的情况。
        if (!stopping) {
            Thread { PrivateDnsController.restore(applicationContext) }.start()
        }
        runtime.markStopped()
        alive = false
        super.onDestroy()
    }
}
