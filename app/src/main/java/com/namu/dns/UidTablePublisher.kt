package com.namu.dns

import android.util.Log

/**
 * 把「五元组 → 归属 UID」表周期性下发给内核。
 *
 * 为什么是轮询而不是事件驱动：Android 没有给 VpnService 提供「新连接出现」的回调，
 * socket 表也只能主动去读。轮询是唯一可行的数据来源。
 *
 * 耗电控制（用户对这个敏感）：
 * - 只在 VPN 运行期间工作，服务一停立刻退出线程；
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

    /** 最近一次成功下发的条目数；0 表示空表，-1 表示从未成功。 */
    @Volatile var lastCount: Int = -1
        private set

    /** 最近一次失败原因，供界面提示「为什么按 App 分流没生效」。 */
    @Volatile var lastError: String? = null
        private set

    fun start() {
        if (running) return
        running = true
        val t = Thread({
            var failures = 0
            var pushedEmpty = false
            while (running) {
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

    fun stop() {
        if (!running) return
        running = false
        thread?.interrupt()
        thread = null
        lastCount = -1
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
