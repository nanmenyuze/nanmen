package com.namu.dns

import android.util.Log

/**
 * 把「五元组 → 归属 UID」表按需下发给内核。
 *
 * 为什么是轮询而不是事件驱动：Android 没有给 VpnService 提供「新连接出现」的
 * 回调，socket 表也只能主动去读。但轮询不是无条件启动——
 * - 只有配置真的需要 UID 判断（App 规则、按 App MITM、金融保护）才启动；
 * - 连接页打开时临时加一份 UI 需求，关闭即释放；
 * - VPN 未运行时一律不跑，避免纯 DNS 场景息屏后仍周期 su。
 *
 * 耗电控制：
 * - service/UI 引用计数，最后一个消费者离开就退出线程；
 * - 一次 su 调用读两份表，避免每轮两次 fork/exec；
 * - 连续失败时退避到 10 秒一次，无 root 的设备不会每 2 秒白跑一次 su；
 * - 连续失败 3 次后下发一次空表，明确告诉内核「现在没有数据」，
 *   让 UID 规则停止生效而不是拿着过期表误判。
 */
internal object UidTablePublisher {
    private const val TAG = "NamuUid"
    private const val INTERVAL_MS = 2000L
    private const val BACKOFF_MS = 10000L

    @Volatile private var thread: Thread? = null
    @Volatile private var running = false
    @Volatile private var generation = 0
    @Volatile private var vpnRunning = false
    @Volatile private var serviceNeeded = false
    @Volatile private var uiNeeded = false

    /** 最近一次成功下发的条目数；0 表示空表，-1 表示从未成功。 */
    @Volatile var lastCount: Int = -1
        private set

    /** 最近一次失败原因，供界面提示「为什么按 App 分流没生效」。 */
    @Volatile var lastError: String? = null
        private set

    fun setVpnRunning(value: Boolean) = synchronized(this) {
        vpnRunning = value
        reconcileLocked()
    }

    /** 配置侧是否有真实消费者（App 规则 / 按 App MITM / 金融保护）。 */
    fun setServiceDemand(value: Boolean) = synchronized(this) {
        serviceNeeded = value
        reconcileLocked()
    }

    /** 连接页是否正在展示归属；对话框关闭必须释放。 */
    fun setUiDemand(value: Boolean) = synchronized(this) {
        uiNeeded = value
        reconcileLocked()
    }

    private fun reconcileLocked() {
        if (vpnRunning && (serviceNeeded || uiNeeded)) startLocked() else stopLocked()
    }

    private fun startLocked() {
        if (running && thread?.isAlive == true) return
        running = true
        val token = ++generation
        val t = Thread({
            var failures = 0
            var pushedEmpty = false
            // token 防止 stop/start 竞态：旧线程看到 generation 变了就退出，
            // 不会和重启后的新线程一起跑两份 su。
            while (running && generation == token) {
                var delay = INTERVAL_MS
                try {
                    val entries = UidResolver.readAll()
                    if (entries == null) {
                        failures++
                        lastError = "需要 Root 授权才能读取系统 socket 归属表"
                        // 退避：无 root 设备不该每 2 秒跑一次 su
                        if (failures >= 3) delay = BACKOFF_MS
                        if (failures >= 3 && !pushedEmpty) {
                            push("[]")
                            pushedEmpty = true
                            lastCount = 0
                        }
                    } else {
                        failures = 0
                        pushedEmpty = false
                        lastError = null
                        val json = UidResolver.toJson(entries)
                        if (push(json)) lastCount = entries.size
                    }
                } catch (t: Throwable) {
                    // 这里任何异常都不能让线程死掉：一旦死掉，按 App 分流会静默失效。
                    lastError = t.message
                    Log.w(TAG, "UID 表下发异常", t)
                }
                try {
                    Thread.sleep(delay)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }, "namu-uid-table")
        t.isDaemon = true
        thread = t
        t.start()
    }

    private fun stopLocked() {
        if (!running) return
        running = false
        generation++
        thread?.interrupt()
        thread = null
        lastCount = -1
        lastError = null
    }

    private fun push(json: String): Boolean {
        if (!NativeCore.available) return false
        return runCatching { NativeCore.nativeSetUidMap(json) >= 0 }
            .getOrElse {
                Log.w(TAG, "nativeSetUidMap 失败", it)
                false
            }
    }
}

/**
 * UID 表的配置侧需求：没有这些消费者就不要启动 su 轮询。
 * 金融保护里的整包排除依赖静态 UID，但微信/支付宝这类 mixed 包的关键字排除
 * 仍要动态 client_uid，所以 MITM 开启且金融保护开启时算真实消费者。
 */
internal fun needsUidMap(cfg: AppConfig, global: GlobalRuleStore.State = GlobalRuleStore.state): Boolean {
    val scope = global.scope
    val appRules = global.localRulesEnabled && global.localRules.any {
        it.enabled && AppUidResolver.isAppRule(it)
    }
    val perAppMitm = scope.enabled && scope.appMode != "all" && scope.apps.isNotEmpty()
    val financeUid = scope.enabled && cfg.financeProtect
    return appRules || perAppMitm || financeUid
}
