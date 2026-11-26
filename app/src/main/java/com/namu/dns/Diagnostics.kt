package com.namu.dns

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import com.namu.dns.ui.formatBytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 诊断报告：把比较不同版本需要的上下文打包成一个 txt。
 * 只读统计，不改配置、不清日志。
 */
object Diagnostics {

    suspend fun export(context: Context): String = withContext(Dispatchers.Default) {
        // JNI 统计、Debug.getMemoryInfo、几百条日志拼接都不能压主线程。
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        Actions.exportText(context, "namu_diag_$ts.txt", build(context))
    }

    @Suppress("DEPRECATION")
    fun build(context: Context): String {
        val sb = StringBuilder()
        val now = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        val container = App.container
        val cfg = container.settings.current()
        val runtime = container.runtime.current()
        val snapshot = container.stats.current().stats
        val logs = container.logs.current()

        sb.appendLine("南门DNS 诊断报告")
        sb.appendLine("生成时间：$now")
        sb.appendLine("应用版本：${BuildConfig.VERSION_NAME} (versionCode ${BuildConfig.VERSION_CODE})")
        sb.appendLine("内核版本：${runCatching { NativeCore.nativeVersion() }.getOrDefault("unknown")}")
        sb.appendLine("包名：${context.packageName}")
        sb.appendLine()

        sb.appendLine("===== 设备 =====")
        sb.appendLine("厂商/型号：${Build.MANUFACTURER} ${Build.MODEL}")
        sb.appendLine("系统：Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        sb.appendLine("ABI：${Build.SUPPORTED_ABIS.joinToString(", ")}")
        sb.appendLine("设备名：${runCatching { Build.DEVICE }.getOrDefault("")}")
        sb.appendLine()

        sb.appendLine("===== 内核实际状态 =====")
        ApplyCoordinator.kernelStateSummary(context).forEach { sb.appendLine(it) }
        sb.appendLine()
        sb.appendLine("===== 运行状态 =====")
        sb.appendLine(
            when {
                runtime.stopping -> "正在关闭"
                runtime.connected -> "已连接"
                runtime.starting -> "正在连接"
                else -> "未连接"
            },
        )
        sb.appendLine("当前配置：${cfg.mode} / ${cfg.selected?.ifBlank { "未选择节点" } ?: "未选择节点"}")
        sb.appendLine("最近一次启动耗时：${runtime.lastStartupMs} ms（点击连接到内核就绪）")
        sb.appendLine(
            "规则：配置 ${cfg.rules.size} 条，手动拦截 ${cfg.customAds.size} 条，" +
                "内核已加载 ${snapshot.filterRules} 条（跳过 ${snapshot.filterSkipped} 条）",
        )
        sb.appendLine("模式：${cfg.mode}，final=${cfg.finalPolicy}")
        val routing = if (tunnelSpec(cfg).fullRoute) "接管 DNS 和连接" else "仅接管系统 DNS"
        sb.appendLine("隧道路由配置：$routing，MITM=${cfg.mitm.enabled}")
        sb.appendLine(
            "DNS：上游 ${SystemDns.display(cfg.dnsUpstream, context)}，回落 " +
                "${SystemDns.display(cfg.dnsFallback, context)}，查询日志=" + cfg.dnsQueryLog,
        )
        sb.appendLine(
            "过滤：enable=${cfg.blockEnabled}，mode=${cfg.blockMode}，cnDirect=${cfg.cnDirect}，" +
                "fakeIp=${cfg.fakeIp}",
        )
        sb.appendLine("规则源：${cfg.rulesUrl.ifBlank { "（未配置）" }}")
        sb.appendLine(
            "自动更新=${cfg.autoUpdateRules}，自动接管私人 DNS=${cfg.autoDisablePrivateDns}，上次更新=" +
                if (cfg.rulesUpdatedAt > 0) {
                    SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(cfg.rulesUpdatedAt))
                } else {
                    "从未"
                },
        )
        runCatching {
            val f = ConfigStore.rulesFile(context, cfg.rulesUrl)
            sb.appendLine(
                "规则文件：${f.name}，${if (f.exists()) formatBytes(f.length()) else "不存在"}，" +
                    "${if (f.exists()) countLines(f) else 0} 行",
            )
        }
        runCatching {
            val f = ConfigStore.moduleBlockFile(context)
            sb.appendLine(
                "模块合并规则：${if (f.exists()) formatBytes(f.length()) else "不存在"}，" +
                    "${if (f.exists()) countLines(f) else 0} 行",
            )
        }
        runCatching {
            val resolver = context.contentResolver
            val mode = android.provider.Settings.Global.getString(resolver, "private_dns_mode")
            val host = android.provider.Settings.Global.getString(resolver, "private_dns_specifier")
            // mode=off 时 specifier 可能还留着上次的域名；这是系统残留快照，不再展示。
            sb.appendLine("系统 Private DNS：${mode ?: "未知"}${if (mode != "off") host?.let { " / $it" }.orEmpty() else ""}")
        }
        sb.appendLine()

        val statsRaw = runCatching {
            if (NativeCore.available) NativeCore.nativeStats() else "{}"
        }.getOrDefault("{}")
        val statsJson = runCatching { JSONObject(statsRaw) }.getOrNull()
        if (statsJson != null) {
            val queries = statsJson.optLong("dnsQueries")
            val cached = statsJson.optLong("dnsCached")
            val cacheLookups = statsJson.optLong("dnsCacheLookups")
            val hitRate = if (cacheLookups > 0) cached * 100.0 / cacheLookups else 0.0
            sb.appendLine("===== 核心统计 =====")
            sb.appendLine("运行时长：${formatUptime(statsJson.optLong("uptime"))}")
            sb.appendLine("DNS 查询：$queries，拦截：${statsJson.optLong("dnsBlocked")}")
            sb.appendLine(
                "缓存命中：$cached / $cacheLookups（${String.format(Locale.US, "%.1f", hitRate)}%，仅统计进入缓存路径的查询），" +
                    "stale：${statsJson.optLong("dnsStale")}，否定缓存：${statsJson.optLong("dnsNegative")}，" +
                    "并发合并：${statsJson.optLong("dnsCoalesced")}",
            )
            sb.appendLine(
                "备用查询：${statsJson.optLong("dnsFallback")}（主上游失败 ${statsJson.optLong("dnsFallbackFail")} / " +
                    "熔断 ${statsJson.optLong("dnsFallbackBreaker")} / 竞速胜出 ${statsJson.optLong("dnsFallbackRace")} / " +
                    "策略复核 ${statsJson.optLong("dnsFallbackReview")}），TCP 重试：${statsJson.optLong("dnsTcpRetry")}，" +
                    "rebind 拦截：${statsJson.optLong("dnsRebind")}，AAAA 拦截：${statsJson.optLong("dnsAaaaBlocked")}",
            )
            sb.appendLine(
                "连接：当前 ${statsJson.optLong("activeConns")} / 累计 ${statsJson.optLong("totalConns")}；" +
                    "上行 ${formatBytes(statsJson.optLong("up"))}，下行 ${formatBytes(statsJson.optLong("down"))}",
            )
            sb.appendLine(
                "上游查询平均耗时：${statsJson.optLong("dnsAvgMs")} ms；" +
                    "本地拦截/缓存平均：${statsJson.optLong("dnsLocalAvgMs")} ms",
            )
            sb.appendLine("DoT/DoQ 拦截：${statsJson.optLong("dotBlocked")} 次")
            sb.appendLine("直连熔断抑制拨号：${statsJson.optLong("dialBreakerRejected")} 次")
            sb.appendLine(
                "MITM：连接 ${statsJson.optLong("mitmConns")}，失败 ${statsJson.optLong("mitmFailed")}，" +
                    "改写 ${statsJson.optLong("mitmRewritten")}，请求 ${statsJson.optLong("mitmReqs")}，" +
                    "无规则 ${statsJson.optLong("mitmNoRule")}，h2 失败 ${statsJson.optLong("mitmH2Failed")}，" +
                    "QUIC 迫降 ${statsJson.optLong("mitmQuicBlocked")}",
            )
            val tcpMs = statsJson.optLong("outboundTcpMs")
            val tcpCount = statsJson.optLong("outboundTcpOk") + statsJson.optLong("outboundTcpFail")
            val tlsMs = statsJson.optLong("outboundTlsMs")
            val tlsCount = statsJson.optLong("outboundTlsOk") + statsJson.optLong("outboundTlsFail")
            sb.appendLine(
                "出站拨号：TCP OK ${statsJson.optLong("outboundTcpOk")} / 失败 ${statsJson.optLong("outboundTcpFail")}，" +
                    "平均 ${if (tcpCount > 0) tcpMs / tcpCount else 0} ms；TLS OK ${statsJson.optLong("outboundTlsOk")} / " +
                    "失败 ${statsJson.optLong("outboundTlsFail")}，平均 ${if (tlsCount > 0) tlsMs / tlsCount else 0} ms",
            )
            sb.appendLine(
                "MITM 上游池：h1 命中 ${statsJson.optLong("mitmPoolH1Hit")} / 未命中 ${statsJson.optLong("mitmPoolH1Miss")}，" +
                    "放回 ${statsJson.optLong("mitmPoolH1Reuse")} / 淘汰 ${statsJson.optLong("mitmPoolH1Evict")}；" +
                    "h2 命中 ${statsJson.optLong("mitmPoolH2Hit")} / 未命中 ${statsJson.optLong("mitmPoolH2Miss")}，" +
                    "复用 ${statsJson.optLong("mitmPoolH2Reuse")} / 淘汰 ${statsJson.optLong("mitmPoolH2Evict")}",
            )
            sb.appendLine(
                "MITM 证书缓存：命中 ${statsJson.optLong("mitmLeafCacheHit")} / 未命中 ${statsJson.optLong("mitmLeafCacheMiss")}，" +
                    "单飞等待 ${statsJson.optLong("mitmLeafWait")}，等待超时 ${statsJson.optLong("mitmLeafWaitTimeout")}，" +
                    "等待打满 ${statsJson.optLong("mitmLeafPendingFull")}，实际签发 ${statsJson.optLong("mitmLeafSign")}",
            )
            sb.appendLine("金融保护跳过 MITM：${statsJson.optLong("mitmFinanceSkipped")} 次")
            sb.appendLine(
                "MITM 未送达：客户端取消 ${statsJson.optLong("mitmCanceled")}，" +
                    "TLS 弃连 ${statsJson.optLong("mitmTlsAborted")}，" +
                    "临时放行跳过 ${statsJson.optLong("mitmBypassed")}，" +
                    "正文提前直通 ${statsJson.optLong("mitmBodyBypassed")}",
            )
            val bypassHosts = statsJson.optString("mitmBypassHosts")
            if (bypassHosts.isNotEmpty()) {
                sb.appendLine("MITM 临时放行域名（此间完全不解密）：$bypassHosts")
            }
            sb.appendLine(
                "主循环耗时：上轮 ${statsJson.optLong("loopRoundMsLast")} ms，峰值 ${statsJson.optLong("loopRoundMsMax")} ms；" +
                    "缓冲池未命中 ${statsJson.optLong("tunPoolMiss")} 次（rx ${statsJson.optLong("tunPoolMissRx")} / tx ${statsJson.optLong("tunPoolMissTx")}）",
            )
            sb.appendLine(
                "动态 UDP 目标：${statsJson.optLong("udpTargets")} 个（普通+DNS 合计数），" +
                    "预分配缓冲容量 ${formatBytes(statsJson.optLong("udpTargetBufKb") * 1024)}（物理页按实际流量提交）；" +
                    "DNS 旧回包按 generation 丢弃 ${statsJson.optLong("dnsStaleReply")} 次，" +
                    "UDP DNS 并发已满丢弃 ${statsJson.optLong("dnsOverloadDropped")} 次",
            )
            sb.appendLine(
                "TUN 发送：队列表满丢包 ${statsJson.optLong("tunTxDrop")}，backlog 溢出 ${statsJson.optLong("tunPendingDrop")}，" +
                    "背压 ${statsJson.optLong("tunTxBackpressure")}，写阻塞 ${statsJson.optLong("tunWriteWouldBlock")}，" +
                    "写错误 ${statsJson.optLong("tunWriteError")}，backlog 峰值 ${statsJson.optLong("tunPendingPeak")}",
            )
            val tunMtu = statsJson.optLong("tunMtu")
            val bbrOk = statsJson.optLong("tcpBbrOk")
            val bbrFail = statsJson.optLong("tcpBbrFail")
            val bbrSupport = when (statsJson.optLong("tcpBbrSupport")) {
                1L -> "支持"
                2L -> "不支持（已停止逐连接尝试）"
                else -> "未探测"
            }
            sb.appendLine(
                "TUN 实际 MTU：$tunMtu（壳 setMtu 与内核 iface 同值）；" +
                    "上游 socket 增益：SO_RCVBUF 峰值 ${formatBytes(statsJson.optLong("upstreamRcvbufMax"))}，" +
                    "SO_SNDBUF 峰值 ${formatBytes(statsJson.optLong("upstreamSndbufMax"))}",
            )
            sb.appendLine(
                "上游 BBR：本机$bbrSupport，生效 $bbrOk 条，失败 $bbrFail 条" +
                    if (bbrFail > 0) "（不支持时只记一次探测失败，自动回落 cubic，不影响连通）" else "",
            )
            val lat = statsJson.optJSONObject("dnsLatency")
            if (lat != null) {
                sb.appendLine(
                    "DNS 延迟分布：<10ms ${lat.optLong("lt10")}｜10-50ms ${lat.optLong("lt50")}｜" +
                        "50-100ms ${lat.optLong("lt100")}｜100-300ms ${lat.optLong("lt300")}｜" +
                        "300ms-1s ${lat.optLong("lt1000")}｜≥1s ${lat.optLong("ge1000")}",
                )
            }
            sb.appendLine()
            sb.appendLine("原始统计 JSON：")
            sb.appendLine(statsJson.toString(2))
        }

        sb.appendLine()
        sb.appendLine("===== 内存 =====")
        val rt = Runtime.getRuntime()
        val javaUsed = rt.totalMemory() - rt.freeMemory()
        sb.appendLine(
            "Java 堆：已用 ${formatBytes(javaUsed)} / 上限 ${formatBytes(rt.maxMemory())} " +
                "(total ${formatBytes(rt.totalMemory())}, free ${formatBytes(rt.freeMemory())})",
        )
        sb.appendLine("Native 堆已分配：${formatBytes(Debug.getNativeHeapAllocatedSize())}")
        runCatching {
            val dbg = Debug.MemoryInfo()
            Debug.getMemoryInfo(dbg)
            sb.appendLine("进程 PSS：${dbg.totalPss} KB")
        }
        runCatching {
            val am = context.getSystemService(ActivityManager::class.java)
            val mi = ActivityManager.MemoryInfo()
            am?.getMemoryInfo(mi)
            if (mi.totalMem > 0) {
                sb.appendLine(
                    "系统内存：可用 ${formatBytes(mi.availMem)} / 总计 ${formatBytes(mi.totalMem)}" +
                        if (mi.lowMemory) "（低内存状态）" else "",
                )
            }
        }
        sb.appendLine()

        sb.appendLine("===== 网络 =====")
        runCatching {
            val cm = context.getSystemService(ConnectivityManager::class.java)
            val active = cm?.activeNetwork
            val caps = active?.let { cm.getNetworkCapabilities(it) }
            sb.appendLine("活动网络：${caps?.let(::describeCaps) ?: "无"}")
            val underlying = cm?.allNetworks?.mapNotNull { n ->
                val c = cm.getNetworkCapabilities(n) ?: return@mapNotNull null
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
                if (!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
                describeCaps(c)
            }.orEmpty()
            if (underlying.isNotEmpty()) {
                sb.appendLine("可用底层网络：")
                underlying.forEach { sb.appendLine("  - $it") }
            }
        }
        sb.appendLine()

        sb.appendLine("===== 运行日志（最近 ${logs.runtime.size} 条）=====")
        if (logs.runtime.isEmpty()) {
            sb.appendLine("（无）")
        } else {
            val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
            logs.runtime.forEach { e ->
                sb.appendLine("${fmt.format(Date(e.ts))} [${e.level}] ${e.tag}: ${e.msg}")
            }
        }
        sb.appendLine()

        sb.appendLine("===== DNS 查询日志（最近 ${logs.dns.size} 条）=====")
        if (logs.dns.isEmpty()) {
            sb.appendLine("（无）")
        } else {
            val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
            logs.dns.forEach { e ->
                sb.appendLine(
                    "${fmt.format(Date(e.ts))} ${e.domain} ${e.qtype} ${e.action} ${e.detail} " +
                        "x${e.count} ${e.ms}ms",
                )
            }
        }
        return sb.toString()
    }

    private fun describeCaps(c: NetworkCapabilities): String {
        val transports = buildList {
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("Wi-Fi")
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("蜂窝")
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("以太网")
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("VPN")
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) add("蓝牙")
        }.ifEmpty { listOf("其他") }.joinToString("+")
        val validated = if (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) "已验证" else "未验证"
        val metered = if (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) "不计费" else "计费"
        return "$transports · $validated · $metered · 下行 ${c.linkDownstreamBandwidthKbps}kbps"
    }

    private fun countLines(file: java.io.File): Int {
        var lines = 0
        file.bufferedReader().use { r ->
            var line = r.readLine()
            while (line != null) {
                if (line.isNotBlank()) lines++
                line = r.readLine()
            }
        }
        return lines
    }

    private fun formatUptime(ms: Long): String {
        val sec = (ms / 1000).coerceAtLeast(0)
        val h = sec / 3600
        val m = (sec % 3600) / 60
        val s = sec % 60
        return if (h > 0) "${h}h ${m}m ${s}s" else "${m}m ${s}s"
    }
}
