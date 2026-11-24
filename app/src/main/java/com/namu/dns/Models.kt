package com.namu.dns

import kotlinx.serialization.Serializable
import org.json.JSONArray
import com.namu.dns.core.config.MitmConfig
import android.util.Base64
import org.json.JSONObject

data class NodeInfo(
    val name: String,
    val type: String,
    val server: String,
    val port: Int,
    val method: String? = null,
    val password: String? = null,
    val uuid: String? = null,
    val sni: String? = null,
    val insecure: Boolean = false,
    val tls: Boolean = true,
    val wsPath: String? = null,
    val wsHost: String? = null,
    val flow: String? = null,
    val group: String = "",
    var latency: Long? = null,
    var testing: Boolean = false,
) {
    private fun enc(s: String): String =
        java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")

    /** 还原成可再次导入的分享链接（ss / trojan / vless / socks5 / http）。 */
    fun shareLink(): String {
        val n = enc(name)
        val hostPort = if (server.contains(':') && !server.startsWith("[")) "[$server]:$port" else "$server:$port"
        return when (type) {
            "ss" -> {
                // SIP002：userinfo 用 URL-safe Base64（无填充），主机为 IPv6 时必须带方括号。
                val info = Base64.encodeToString(
                    "${method ?: "aes-128-gcm"}:${password ?: ""}".toByteArray(),
                    Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
                )
                "ss://$info@$hostPort#$n"
            }
            "trojan" -> buildString {
                append("trojan://${enc(password ?: "")}@$hostPort")
                val q = mutableListOf<String>()
                if (!sni.isNullOrBlank()) q.add("sni=${enc(sni)}")
                if (insecure) q.add("allowInsecure=1")
                if (!wsPath.isNullOrBlank()) {
                    q.add("type=ws")
                    q.add("path=${enc(wsPath)}")
                    wsHost?.takeIf { it.isNotBlank() }?.let { q.add("host=${enc(it)}") }
                }
                if (q.isNotEmpty()) append("?").append(q.joinToString("&"))
                append("#$n")
            }
            "vless" -> buildString {
                append("vless://${uuid ?: ""}@$hostPort?encryption=none&security=${if (tls) "tls" else "none"}")
                if (!sni.isNullOrBlank()) append("&sni=${enc(sni)}")
                if (!wsPath.isNullOrBlank() || !wsHost.isNullOrBlank()) {
                    append("&type=ws")
                    wsPath?.takeIf { it.isNotBlank() }?.let { append("&path=${enc(it)}") }
                    wsHost?.takeIf { it.isNotBlank() }?.let { append("&host=${enc(it)}") }
                } else {
                    append("&type=tcp")
                }
                if (insecure) append("&allowInsecure=1")
                flow?.takeIf { it.isNotBlank() }?.let { append("&flow=${enc(it)}") }
                append("#$n")
            }
            "vmess" -> {
                val ws = !wsPath.isNullOrBlank() || !wsHost.isNullOrBlank()
                val json = JSONObject().apply {
                    put("v", "2")
                    put("ps", name)
                    put("add", server)
                    put("port", port)
                    put("id", uuid ?: "")
                    put("aid", 0)
                    put("scy", method ?: "auto")
                    put("net", if (ws) "ws" else "tcp")
                    put("type", "none")
                    if (ws) {
                        put("path", wsPath ?: "/")
                        wsHost?.takeIf { it.isNotBlank() }?.let { put("host", it) }
                    }
                    put("tls", if (tls) "tls" else "")
                    sni?.takeIf { it.isNotBlank() }?.let { put("sni", it) }
                    if (insecure) put("allowInsecure", true)
                }
                "vmess://" + Base64.encodeToString(json.toString().toByteArray(), Base64.NO_WRAP)
            }
            "socks5" -> {
                val auth = if (!uuid.isNullOrBlank()) {
                    val u = enc(uuid!!)
                    val pw = password?.takeIf { it.isNotBlank() }?.let { ":" + enc(it) } ?: ""
                    "$u$pw@"
                } else ""
                "socks5://$auth$hostPort#$n"
            }
            "http" -> {
                val auth = if (!uuid.isNullOrBlank()) {
                    val u = enc(uuid!!)
                    val pw = password?.takeIf { it.isNotBlank() }?.let { ":" + enc(it) } ?: ""
                    "$u$pw@"
                } else ""
                (if (tls) "https://" else "http://") + "$auth$hostPort#$n"
            }
            else -> "$type://$hostPort#$n"
        }
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name)
        put("type", type)
        put("server", server)
        put("port", port)
        method?.let { put("method", it) }
        password?.let { put("password", it) }
        uuid?.let { put("uuid", it) }
        sni?.let { put("sni", it) }
        put("insecure", insecure)
        put("tls", tls)
        wsPath?.let { put("ws_path", it) }
        wsHost?.let { put("ws_host", it) }
        flow?.let { put("flow", it) }
        if (group.isNotBlank()) put("group", group)
    }

    val typeLabel: String
        get() = when (type) {
            "ss" -> "SS"
            "trojan" -> "Trojan"
            "vless" -> "VLESS"
            "vmess" -> "VMess"
            "socks5" -> "SOCKS5"
            "http" -> if (tls) "HTTPS" else "HTTP"
            else -> type.uppercase()
        }

    companion object {
        fun fromJson(o: JSONObject): NodeInfo = NodeInfo(
            name = o.optString("name"),
            type = o.optString("type"),
            server = o.optString("server"),
            port = o.optInt("port"),
            method = if (o.has("method") && !o.isNull("method")) o.optString("method") else null,
            password = if (o.has("password") && !o.isNull("password")) o.optString("password") else null,
            uuid = if (o.has("uuid") && !o.isNull("uuid")) o.optString("uuid") else null,
            sni = if (o.has("sni") && !o.isNull("sni")) o.optString("sni") else null,
            insecure = o.optBoolean("insecure", false),
            tls = o.optBoolean("tls", true),
            wsPath = if (o.has("ws_path") && !o.isNull("ws_path")) o.optString("ws_path") else null,
            wsHost = if (o.has("ws_host") && !o.isNull("ws_host")) o.optString("ws_host") else null,
            flow = if (o.has("flow") && !o.isNull("flow")) o.optString("flow") else null,
            group = o.optString("group", ""),
        )
    }
}

/** 模块 [Rule] 中的规则集引用：壳层拉取 URL 内容后按 kind 展开，action 为集合策略。 */
data class RuleSetRef(
    val kind: String,
    val url: String,
    val action: String,
)

/** D0 归因身份：内核与壳层共用的稳定规则标识，不下发到 UI 以外的位置。 */
@Serializable
data class RuleMeta(
    val section: String = "",
    val key: String = "",
    val ruleId: String = "",
    val sourceType: String = "",
    val sourceId: String = "",
    val sourceName: String = "",
    val order: Long = 0,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("section", section)
        put("key", key)
        put("ruleId", ruleId)
        put("sourceType", sourceType)
        put("sourceId", sourceId)
        put("sourceName", sourceName)
        put("order", order)
    }

    companion object {
        fun fromJson(o: JSONObject) = RuleMeta(
            section = o.optString("section"),
            key = o.optString("key"),
            ruleId = o.optString("ruleId"),
            sourceType = o.optString("sourceType"),
            sourceId = o.optString("sourceId"),
            sourceName = o.optString("sourceName"),
            order = o.optLong("order", 0),
        )
    }
}

@Serializable
data class RuleItem(
    val type: String,
    val value: String,
    val action: String,
    val source: String = "",
    /** B3 单条启用开关：禁用规则不下发内核（壳层过滤），旧 JSON 缺省启用。 */
    val enabled: Boolean = true,
    /** D0 归因身份；模块规则在重建时生成，手写配置在 nativeJson 时补默认身份。 */
    @kotlinx.serialization.Transient val meta: RuleMeta? = null,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("type", type)
        put("value", value)
        put("action", action)
        if (source.isNotBlank()) put("source", source)
        if (!enabled) put("enabled", false)
        meta?.let { put("meta", it.toJson()) }
    }

    companion object {
        fun fromJson(o: JSONObject) = RuleItem(
            o.optString("type", "DOMAIN-SUFFIX"),
            o.optString("value"),
            o.optString("action", "proxy"),
            o.optString("source", ""),
            o.optBoolean("enabled", true),
            if (o.has("meta") && !o.isNull("meta")) RuleMeta.fromJson(o.getJSONObject("meta")) else null,
        )
    }
}

data class LogEntry(
    val id: Long,
    val ts: Long,
    val level: String,
    val tag: String,
    val msg: String,
)

data class DnsLogEntry(
    val id: Long,
    val ts: Long,
    val domain: String,
    val qtype: String,
    val action: String,
    val detail: String,
    val ms: Long,
    /** 5 秒窗口内合并的重复查询次数；1 表示单条。 */
    val count: Long = 1,
)

/** 策略组单个成员的最近健康状态，来自内核 HealthRegistry 的 stats 导出。 */
data class GroupMemberHealth(
    val name: String,
    val node: Boolean,
    val tcpLatencyMs: Long? = null,
    val tcpStatus: String = "unknown",
    val udpLatencyMs: Long? = null,
    val udpStatus: String = "unknown",
)

/** 策略组健康快照；仅组页面可见时由 stats 轮询刷新。 */
data class GroupHealth(
    val name: String,
    val type: String,
    val lbMode: String = "consistent-hash",
    val switchInterval: Int = 30,
    val current: String? = null,
    val members: List<GroupMemberHealth> = emptyList(),
)

data class MitmHostRow(
    val host: String = "",
    val conns: Long = 0,
    val reqs: Long = 0,
    val failed: Long = 0,
    val canceled: Long = 0,
    val noRule: Long = 0,
    val rewritten: Long = 0,
)

data class StatsData(
    val up: Long = 0,
    val down: Long = 0,
    val dnsQueries: Long = 0,
    val dotBlocked: Long = 0,
    val dnsBlocked: Long = 0,
    val dnsCached: Long = 0,
    val dnsCacheLookups: Long = 0,
    val dnsStale: Long = 0,
    val dnsNegative: Long = 0,
    val dnsCoalesced: Long = 0,
    val dnsRebind: Long = 0,
    val dnsAaaaBlocked: Long = 0,
    val dnsTcpRetry: Long = 0,
    val dnsAvgMs: Long = 0,
    val dnsLocalAvgMs: Long = 0,
    val dnsLatLt10: Long = 0,
    val dnsLatLt50: Long = 0,
    val dnsLatLt100: Long = 0,
    val dnsLatLt300: Long = 0,
    val dnsLatLt1000: Long = 0,
    val dnsLatGe1000: Long = 0,
    val dnsFallback: Long = 0,
    val dnsFallbackFail: Long = 0,
    val dnsFallbackBreaker: Long = 0,
    val dnsFallbackRace: Long = 0,
    val dnsFallbackReview: Long = 0,
    /** DNS 动态 socket 被淘汰后，按 generation 丢弃的旧异步回包数。 */
    val dnsStaleReply: Long = 0,
    /** 普通+DNS 动态 UDP 目标数；以及这些 socket 的预分配缓冲容量（KiB，物理页懒提交）。 */
    val udpTargets: Long = 0,
    val udpTargetBufKb: Long = 0,
    val activeConns: Long = 0,
    val totalConns: Long = 0,
    val filterRules: Long = 0,
    val filterSkipped: Long = 0,
    val uptime: Long = 0,
    // MITM（内核 1.11）：解密连接 / 拒绝请求 / 响应改写 / 握手失败放行 / QUIC 拦截
    val mitmConns: Long = 0,
    val mitmRejected: Long = 0,
    val mitmRewritten: Long = 0,
    val mitmFailed: Long = 0,
    val mitmQuicBlocked: Long = 0,
    /** 域名命中但因「按 App MITM」范围而放行的连接数。 */
    val mitmAppSkipped: Long = 0,
    /** 金融保护放行的连接数（整包 UID / 金融域名 / 混合 App 关键字）。 */
    val mitmFinanceSkipped: Long = 0,
    /** 命中正文规则但按 Content-Type/大小提前直通的响应数。 */
    val mitmBodyBypassed: Long = 0,
    /** host 维度失败/无规则 top10；数据只在本机内存，不上报。 */
    val mitmFailedTop: List<MitmHostRow> = emptyList(),
    val mitmNoRuleTop: List<MitmHostRow> = emptyList(),
    // 按 App 分流：成功解析归属的连接数 / 有 UID 规则但归属未知的连接数
    val uidResolved: Long = 0,
    val uidUnknown: Long = 0,
    // TUN 出口诊断：TxToken 队列满丢包 / pending_out 硬上限丢弃 / backlog 峰值 / 背压 / 写阻塞 / 写错误
    val tunTxDrop: Long = 0,
    val tunPendingDrop: Long = 0,
    val tunPendingPeak: Long = 0,
    val tunTxBackpressure: Long = 0,
    val tunWriteWouldBlock: Long = 0,
    val tunWriteError: Long = 0,
    // 直连拨号熔断：冷却期内被抑制拨号的连接数（保持原失败时序，不立即 RST）
    val dialBreakerRejected: Long = 0,
    // 数据面判别仪表：本地接收缓冲满（窗口 0）次数 / 对端零窗口导致发送停滞次数
    val tcpRecvFull: Long = 0,
    val tcpSendStalled: Long = 0,
    // TCP 缓冲水位守卫拒绝的新连接数
    val tcpBufferDenied: Long = 0,
    // QUIC 假活回落：丢弃的 QUIC 包数 / 判为黑洞的目标数
    val quicFallback: Long = 0,
    val quicBlackholed: Long = 0,
    // 当前占着 512K 大档的 TCP socket 数（并发名额）
    val bigTierInUse: Long = 0,
    /** 策略组健康快照；内核 stats 的 groups 字段。 */
    val groupHealth: List<GroupHealth> = emptyList(),
) {
    companion object {
        fun fromJson(text: String): StatsData {
            return try {
                val o = JSONObject(text)
                StatsData(
                    up = o.optLong("up"),
                    down = o.optLong("down"),
                    dnsQueries = o.optLong("dnsQueries"),
                    dotBlocked = o.optLong("dotBlocked"),
                    dnsBlocked = o.optLong("dnsBlocked"),
                    dnsCached = o.optLong("dnsCached"),
                    dnsCacheLookups = o.optLong("dnsCacheLookups"),
                    dnsStale = o.optLong("dnsStale"),
                    dnsNegative = o.optLong("dnsNegative"),
                    dnsCoalesced = o.optLong("dnsCoalesced"),
                    dnsRebind = o.optLong("dnsRebind"),
                    dnsAaaaBlocked = o.optLong("dnsAaaaBlocked"),
                    dnsTcpRetry = o.optLong("dnsTcpRetry"),
                    dnsAvgMs = o.optLong("dnsAvgMs"),
                    dnsLocalAvgMs = o.optLong("dnsLocalAvgMs"),
                    dnsLatLt10 = o.optJSONObject("dnsLatency")?.optLong("lt10") ?: 0L,
                    dnsLatLt50 = o.optJSONObject("dnsLatency")?.optLong("lt50") ?: 0L,
                    dnsLatLt100 = o.optJSONObject("dnsLatency")?.optLong("lt100") ?: 0L,
                    dnsLatLt300 = o.optJSONObject("dnsLatency")?.optLong("lt300") ?: 0L,
                    dnsLatLt1000 = o.optJSONObject("dnsLatency")?.optLong("lt1000") ?: 0L,
                    dnsLatGe1000 = o.optJSONObject("dnsLatency")?.optLong("ge1000") ?: 0L,
                    dnsFallback = o.optLong("dnsFallback"),
                    dnsFallbackFail = o.optLong("dnsFallbackFail"),
                    dnsFallbackBreaker = o.optLong("dnsFallbackBreaker"),
                    dnsFallbackRace = o.optLong("dnsFallbackRace"),
                    dnsFallbackReview = o.optLong("dnsFallbackReview"),
                    dnsStaleReply = o.optLong("dnsStaleReply"),
                    udpTargets = o.optLong("udpTargets"),
                    udpTargetBufKb = o.optLong("udpTargetBufKb"),
                    activeConns = o.optLong("activeConns"),
                    totalConns = o.optLong("totalConns"),
                    filterRules = o.optLong("filterRules"),
                    filterSkipped = o.optLong("filterSkipped"),
                    uptime = o.optLong("uptime"),
                    mitmConns = o.optLong("mitmConns"),
                    mitmRejected = o.optLong("mitmRejected"),
                    mitmRewritten = o.optLong("mitmRewritten"),
                    mitmFailed = o.optLong("mitmFailed"),
                    mitmQuicBlocked = o.optLong("mitmQuicBlocked"),
                    mitmAppSkipped = o.optLong("mitmAppSkipped"),
                    mitmFinanceSkipped = o.optLong("mitmFinanceSkipped"),
                    mitmBodyBypassed = o.optLong("mitmBodyBypassed"),
                    mitmFailedTop = parseMitmHosts(o.optJSONObject("mitmHosts")?.optJSONArray("failedTop")),
                    mitmNoRuleTop = parseMitmHosts(o.optJSONObject("mitmHosts")?.optJSONArray("noRuleTop")),
                    uidResolved = o.optLong("uidResolved"),
                    uidUnknown = o.optLong("uidUnknown"),
                    tunTxDrop = o.optLong("tunTxDrop"),
                    tunPendingDrop = o.optLong("tunPendingDrop"),
                    tunPendingPeak = o.optLong("tunPendingPeak"),
                    tunTxBackpressure = o.optLong("tunTxBackpressure"),
                    tunWriteWouldBlock = o.optLong("tunWriteWouldBlock"),
                    tunWriteError = o.optLong("tunWriteError"),
                    dialBreakerRejected = o.optLong("dialBreakerRejected"),
                    tcpRecvFull = o.optLong("tcpRecvFull"),
                    tcpSendStalled = o.optLong("tcpSendStalled"),
                    tcpBufferDenied = o.optLong("tcpBufferDenied"),
                    quicFallback = o.optLong("quicFallback"),
                    quicBlackholed = o.optLong("quicBlackholed"),
                    bigTierInUse = o.optLong("bigTierInUse"),
                    groupHealth = o.optJSONArray("groups")?.let { arr ->
                        buildList {
                            for (i in 0 until arr.length()) {
                                val g = arr.optJSONObject(i) ?: continue
                                val members = mutableListOf<GroupMemberHealth>()
                                g.optJSONArray("members")?.let { ms ->
                                    for (j in 0 until ms.length()) {
                                        val m = ms.optJSONObject(j) ?: continue
                                        val h = m.optJSONObject("health")
                                        val tcp = h?.optJSONObject("tcp")
                                        val udp = h?.optJSONObject("udp")
                                        members.add(
                                            GroupMemberHealth(
                                                name = m.optString("name", ""),
                                                node = m.optBoolean("node", false),
                                                tcpLatencyMs = tcp?.optLong("latencyMs")?.takeIf { tcp.has("latencyMs") && !tcp.isNull("latencyMs") },
                                                tcpStatus = tcp?.optString("status", "unknown") ?: "unknown",
                                                udpLatencyMs = udp?.optLong("latencyMs")?.takeIf { udp.has("latencyMs") && !udp.isNull("latencyMs") },
                                                udpStatus = udp?.optString("status", "unknown") ?: "unknown",
                                            ),
                                        )
                                    }
                                }
                                add(
                                    GroupHealth(
                                        name = g.optString("name", ""),
                                        type = g.optString("type", "select"),
                                        lbMode = g.optString("lbMode", "consistent-hash"),
                                        switchInterval = g.optInt("switchInterval", 30),
                                        current = g.optString("current", "").takeIf { it.isNotBlank() },
                                        members = members,
                                    ),
                                )
                            }
                        }
                    } ?: emptyList(),
                )
            } catch (_: Exception) {
                StatsData()
            }
        }
    }
}

fun isValidAdsDomain(raw: String): Boolean {
    val d = raw.trim().lowercase()
    if (d.length !in 3..253 || !d.contains('.') || d.startsWith('.') || d.endsWith('.')) return false
    // 连续点表示空标签（bad..example.com），不是合法域名；否则 AdBlock 无效语法会被误导入。
    if (d.contains("..")) return false
    if (d.contains('/') || d.contains(':') || d.contains('*') || d.contains(' ') || d.contains('\n')) return false
    return d.all { (it in 'a'..'z') || (it in '0'..'9') || it == '-' || it == '_' || it == '.' }
}

fun normalizeAdsDomain(raw: String): String? {
    val d = raw.trim().lowercase().removePrefix("||").trimStart('|').trimEnd('^', '|')
    return if (isValidAdsDomain(d)) d.trim('.') else null
}

/**
 * M3 策略组。members 可引用节点或其他策略组；类型只支持 select / url-test / fallback。
 * 组定义属于配置文件，组选择属于设备侧 [AppConfig.groupSelections]。
 */
@Serializable
data class ProxyGroup(
    val name: String,
    val type: String = "select",
    val members: List<String> = emptyList(),
    val testUrl: String = "http://www.gstatic.com/generate_204",
    val interval: Int = 600,
    val timeout: Int = 5000,
    val tolerance: Int = 50,
    val failureThreshold: Int = 3,
    val recoveryThreshold: Int = 2,
    /** global：沿全局无节点策略；block：拦截；direct：直连。 */
    val noNodeAction: String = "global",
    /** load-balance 选路方式：consistent-hash（默认）/ round-robin。 */
    val lbMode: String = "consistent-hash",
    /** 自动切换最短间隔，秒；当前节点不可用时立即切换。 */
    val switchInterval: Int = 30,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name)
        put("type", type)
        put("members", JSONArray().apply { members.forEach { put(it) } })
        put("testUrl", testUrl)
        put("interval", interval)
        put("timeout", timeout)
        put("tolerance", tolerance)
        put("failureThreshold", failureThreshold)
        put("recoveryThreshold", recoveryThreshold)
        put("noNodeAction", noNodeAction)
        put("lbMode", lbMode)
        put("switchInterval", switchInterval)
    }

    companion object {
        fun fromJson(o: JSONObject): ProxyGroup {
            val members = mutableListOf<String>()
            o.optJSONArray("members")?.let { a ->
                for (i in 0 until a.length()) a.optString(i, "").trim().takeIf { it.isNotBlank() }?.let { members.add(it) }
            }
            return ProxyGroup(
                name = o.optString("name", "").trim(),
                type = o.optString("type", "select").trim().lowercase().let {
                    when (it) {
                        "url-test", "urltest", "fallback" -> it.replace("urltest", "url-test")
                        "load-balance", "loadbalance", "balance" -> "load-balance"
                        else -> "select"
                    }
                },
                members = members,
                testUrl = o.optString("testUrl", "http://www.gstatic.com/generate_204").ifBlank {
                    "http://www.gstatic.com/generate_204"
                },
                interval = o.optInt("interval", 600).coerceIn(5, 86_400),
                timeout = o.optInt("timeout", 5000).coerceIn(500, 30_000),
                tolerance = o.optInt("tolerance", 50).coerceIn(0, 30_000),
                failureThreshold = o.optInt("failureThreshold", 3).coerceIn(1, 20),
                recoveryThreshold = o.optInt("recoveryThreshold", 2).coerceIn(1, 20),
                noNodeAction = o.optString("noNodeAction", "global").let {
                    if (it == "block" || it == "direct") it else "global"
                },
                lbMode = o.optString("lbMode", "consistent-hash").trim().lowercase().let {
                    if (it == "round-robin" || it == "roundrobin" || it == "rr") "round-robin" else "consistent-hash"
                },
                switchInterval = o.optInt("switchInterval", 30).coerceIn(1, 86_400),
            )
        }
    }
}

@Serializable
data class RuleSource(
    val id: String,
    val url: String,
    val format: String = "adblock",
    val enabled: Boolean = true,
    val updatedAt: Long = 0L,
    val lines: Int = 0,
    val error: String = "",
    /** HTTP 条件请求元数据；304 时复用本地缓存。 */
    val etag: String = "",
    val lastModified: String = "",
    val lastAttemptAt: Long = 0L,
    /** 本次同步失败但仍有上一份可用缓存时置 true。 */
    val stale: Boolean = false,
    val cacheBytes: Long = 0L,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("url", url)
        put("format", format)
        put("enabled", enabled)
        put("updatedAt", updatedAt)
        put("lines", lines)
        put("error", error)
        put("etag", etag)
        put("lastModified", lastModified)
        put("lastAttemptAt", lastAttemptAt)
        put("stale", stale)
        put("cacheBytes", cacheBytes)
    }

    companion object {
        fun fromJson(o: JSONObject) = RuleSource(
            id = o.optString("id", "source"),
            url = o.optString("url"),
            format = o.optString("format", "adblock"),
            enabled = o.optBoolean("enabled", true),
            updatedAt = o.optLong("updatedAt", 0L),
            lines = o.optInt("lines", 0),
            error = o.optString("error", ""),
            etag = o.optString("etag", ""),
            lastModified = o.optString("lastModified", ""),
            lastAttemptAt = o.optLong("lastAttemptAt", 0L),
            stale = o.optBoolean("stale", false),
            cacheBytes = o.optLong("cacheBytes", 0L),
        )
    }
}


@Serializable
data class ModuleSource(
    val id: String,
    val name: String,
    val url: String,
    val app: String = "",
    val enabled: Boolean = true,
    val updatedAt: Long = 0L,
    val blockRules: Int = 0,
    val routeRules: Int = 0,
    val ignored: Int = 0,
    val error: String = "",
    /** [MITM] 域名 + [URL Rewrite] + [Header Rewrite] 的合并条数（放在末尾，兼容旧位置参数）。 */
    val mitmRules: Int = 0,
    /** AdBlock @@ 例外条数（放在末尾，兼容旧 JSON/旧位置参数）。 */
    val allowRules: Int = 0,
    /** 更新周期（秒）；0 表示只手动。 */
    val intervalSeconds: Long = 21600,
    val lastAttemptAt: Long = 0L,
    val etag: String = "",
    val lastModified: String = "",
    /** 上次拉取失败但本地旧缓存仍可用。 */
    val stale: Boolean = false,
    val cacheBytes: Long = 0L,
    /** S3：Profile 内模块顺序；-1 表示旧数据，按列表下标兜底。 */
    val order: Int = -1,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("url", url)
        put("app", app)
        put("enabled", enabled)
        put("updatedAt", updatedAt)
        put("blockRules", blockRules)
        put("routeRules", routeRules)
        put("mitmRules", mitmRules)
        put("allowRules", allowRules)
        put("ignored", ignored)
        put("error", error)
        put("intervalSeconds", intervalSeconds)
        put("lastAttemptAt", lastAttemptAt)
        put("etag", etag)
        put("lastModified", lastModified)
        put("stale", stale)
        put("cacheBytes", cacheBytes)
        if (order >= 0) put("order", order)
    }

    companion object {
        fun fromJson(o: JSONObject) = ModuleSource(
            id = o.optString("id"),
            name = o.optString("name"),
            url = o.optString("url"),
            app = o.optString("app"),
            enabled = o.optBoolean("enabled", true),
            updatedAt = o.optLong("updatedAt", 0L),
            blockRules = o.optInt("blockRules", 0),
            routeRules = o.optInt("routeRules", 0),
            mitmRules = o.optInt("mitmRules", 0),
            allowRules = o.optInt("allowRules", 0),
            ignored = o.optInt("ignored", 0),
            error = o.optString("error", ""),
            intervalSeconds = o.optLong("intervalSeconds", 21600L),
            lastAttemptAt = o.optLong("lastAttemptAt", 0L),
            etag = o.optString("etag", ""),
            lastModified = o.optString("lastModified", ""),
            stale = o.optBoolean("stale", false),
            cacheBytes = o.optLong("cacheBytes", 0L),
            order = o.optInt("order", -1),
        )
    }
}


/** 订阅服务端返回的 subscription-userinfo；expireAt 为毫秒时间戳，0 表示未知。 */
@kotlinx.serialization.Serializable
data class SubscriptionInfo(
    val upload: Long = 0,
    val download: Long = 0,
    val total: Long = 0,
    val expireAt: Long = 0,
    val updatedAt: Long = 0,
) {
    val used: Long get() = upload + download
    val remaining: Long get() = if (total > 0) (total - used).coerceAtLeast(0) else 0
    val usedPercent: Int get() = if (total > 0) ((used * 100 / total).coerceIn(0, 100)).toInt() else 0

    fun toJson(): JSONObject = JSONObject().apply {
        put("upload", upload)
        put("download", download)
        put("total", total)
        put("expireAt", expireAt)
        put("updatedAt", updatedAt)
    }

    companion object {
        fun fromJson(o: JSONObject) = SubscriptionInfo(
            upload = o.optLong("upload"),
            download = o.optLong("download"),
            total = o.optLong("total"),
            expireAt = o.optLong("expireAt"),
            updatedAt = o.optLong("updatedAt"),
        )
    }
}

data class AppConfig(
    var mode: String = "dns_only",
    var selected: String? = null,
    var nodes: List<NodeInfo> = emptyList(),
    var dnsUpstream: String = "system",
    var dnsFallback: String = "system",
    var dnsBootstrap: String = "",
    var dnsHeaderName: String = "",
    var dnsHeaderValue: String = "",
    var dnsCacheTtl: Int = 600,
    /** 本地拦截 NXDOMAIN 的 SOA/缓存 TTL（秒）。 */
    var blockTtl: Int = 60,
    /** 异常应答复核：默认只复核私网/保留/广播。 */
    var fallbackFilter: Boolean = true,
    /** 是否把非中国大陆 IP 也交给 fallback 复核；默认关闭。 */
    var fallbackGeoCheck: Boolean = false,
    var dnsQueryLog: Boolean = true,
    var remoteConfigUrl: String = "",
    var remoteConfigName: String = "",
    var remoteConfigUpdatedAt: Long = 0L,
    var remoteConfigInterval: Long = 21600_000L,
    var ruleSources: List<RuleSource> = emptyList(),
    var moduleSources: List<ModuleSource> = emptyList(),
    var blockEnabled: Boolean = true,
    var blockMode: String = "nxdomain",
    var cnDirect: Boolean = true,
    var finalPolicy: String = "proxy",
    var subscription: String = "",
    var rulesUrl: String = "",
    var customAds: List<String> = emptyList(),
    var autoUpdateRules: Boolean = true,
    /** 金融连接保护：支付/银行/账号安全连接不走 MITM，默认开启。 */
    var financeProtect: Boolean = true,
    var rulesUpdatedAt: Long = 0L,
    var allowDnsFallback: Boolean = true,
    var blockWhenNoNode: Boolean = true,
    var fakeIp: Boolean = false,
    var blockAaaa: Boolean = false,
    var sniff: Boolean = true,
    var autoSelectNode: Boolean = false,
    var autoClearLogs: Boolean = true,
    /** Root 设备上连接时临时关闭系统私人 DNS，断开后恢复；避免 DoT 绕过内核。 */
    var autoDisablePrivateDns: Boolean = false,
    /**
     * DNS-only 模式下是否全量接管流量（默认开）。
     *
     * 只接管 VPN 的 DNS 地址时，App 硬编码 8.8.8.8、DoT 853、App 自己的 DoH
     * 都不进 TUN，等于 DNS 泄漏。全量接管后这些流量都进 TUN：
     * 硬编码 DNS 被劫持到本地引擎，DoT 被 block_dot 拒绝。
     * 代价是所有流量过一遍 TUN（非 DNS 连接直连转发），性能敏感时可关闭。
     */
    var dnsOnlyFullRoute: Boolean = true,
    /** 蜂窝 UDP 假活（QUIC 黑洞）自动回落 TCP：长时间无回包即对同一目标丢弃 QUIC。 */
    var quicFallback: Boolean = true,
    /** TUN MTU：巨帧把本机腿包数降约 6 倍；壳与内核取同一值，establish 失败自动回退 1500。 */
    var mtu: Int = 9000,
    /** 上游 per-socket BBR（WAN 腿）；内核不支持时静默回退 cubic。 */
    var bbr: Boolean = true,
    /** system / light / dark；仅影响外壳配色，不进入内核配置。 */
    var themeMode: String = "system",
    /** 开机或默认网络恢复时自动启动 VPN。 */
    var autoConnect: Boolean = false,
    /** tcp / tls：首页测速和自动选节点共用。 */
    var pingMethod: String = "tcp",
    /** D2 轻量命中摘要开关：默认开；关闭后不再写盘，内存快照仍可用于本会话诊断。 */
    var hitHistoryEnabled: Boolean = true,
    /** S6：SSID 触发默认关；开启前必须由用户显式同意定位权限（opt-in）。 */
    var ssidTriggerEnabled: Boolean = false,
    var ssidTriggerNames: List<String> = emptyList(),
    /** 只有用户主动勾选后才申请定位权限并读取当前 SSID。 */
    var ssidLocationOptIn: Boolean = false,
    /**
     * 第 13 节 L3：最近一次移除系统 CA 的结果。仅用于区分「已卸载」与
     * 「从未安装」；残留异常时同时列出失败 namespace 供重试。
     */
    var caLastRemovalAt: Long = 0L,
    var caLastRemovalCleared: Int = 0,
    var caLastRemovalFailed: Int = 0,
    var caLastRemovalFailedNs: String = "",
    var subscriptionInfo: SubscriptionInfo? = null,
    var rules: List<RuleItem> = defaultRules(),
    var proxyGroups: List<ProxyGroup> = emptyList(),
    /** 设备侧组选择；跨重启/配置切换保留，不写入 .conf。 */
    var groupSelections: Map<String, String> = emptyMap(),
    /** MITM 分区（对齐小火箭，归属配置文件）；内核 1.11 接入后消费，1.10 忽略。 */
    var mitm: MitmConfig = MitmConfig(),
    /** 外部配置中未建模的根字段原文（JSON 对象字符串）；保存时按原 key 合并，避免导入后丢失。 */
    var configUnknown: String = "",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("mode", mode)
        put("selected", selected ?: "")
        put("dnsUpstream", dnsUpstream)
        put("dnsFallback", dnsFallback)
        put("dnsBootstrap", dnsBootstrap)
        put("dnsHeaderName", dnsHeaderName)
        put("dnsHeaderValue", dnsHeaderValue)
        put("dnsCacheTtl", dnsCacheTtl)
        put("blockTtl", blockTtl)
        put("fallbackFilter", fallbackFilter)
        put("fallbackGeoCheck", fallbackGeoCheck)
        put("dnsQueryLog", dnsQueryLog)
        put("remoteConfigUrl", remoteConfigUrl)
        put("remoteConfigName", remoteConfigName)
        put("remoteConfigUpdatedAt", remoteConfigUpdatedAt)
        put("remoteConfigInterval", remoteConfigInterval)
        put("ruleSources", JSONArray().apply { ruleSources.forEach { put(it.toJson()) } })
        put("moduleSources", JSONArray().apply { moduleSources.forEach { put(it.toJson()) } })
        put("blockEnabled", blockEnabled)
        put("blockMode", blockMode)
        put("cnDirect", cnDirect)
        put("finalPolicy", finalPolicy)
        put("subscription", subscription)
        put("rulesUrl", rulesUrl)
        put("customAds", JSONArray().apply { customAds.forEach { put(it) } })
        put("autoUpdateRules", autoUpdateRules)
        put("financeProtect", financeProtect)
        put("rulesUpdatedAt", rulesUpdatedAt)
        put("allowDnsFallback", allowDnsFallback)
        put("blockWhenNoNode", blockWhenNoNode)
        put("fakeIp", fakeIp)
        put("blockAaaa", blockAaaa)
        put("dnsOnlyFullRoute", dnsOnlyFullRoute)
        put("quicFallback", quicFallback)
        put("mtu", mtu)
        put("bbr", bbr)
        put("sniff", sniff)
        put("autoSelectNode", autoSelectNode)
        put("autoClearLogs", autoClearLogs)
        put("autoDisablePrivateDns", autoDisablePrivateDns)
        put("themeMode", themeMode)
        put("autoConnect", autoConnect)
        put("pingMethod", pingMethod)
        put("hitHistoryEnabled", hitHistoryEnabled)
        put("ssidTriggerEnabled", ssidTriggerEnabled)
        put("ssidTriggerNames", JSONArray().apply { ssidTriggerNames.forEach { put(it) } })
        put("ssidLocationOptIn", ssidLocationOptIn)
        put("caLastRemovalAt", caLastRemovalAt)
        put("caLastRemovalCleared", caLastRemovalCleared)
        put("caLastRemovalFailed", caLastRemovalFailed)
        put("caLastRemovalFailedNs", caLastRemovalFailedNs)
        subscriptionInfo?.let { put("subscriptionInfo", it.toJson()) }
        put("nodes", JSONArray().apply { nodes.forEach { put(it.toJson()) } })
        put("rules", JSONArray().apply { rules.forEach { put(it.toJson()) } })
        put("proxyGroups", JSONArray().apply { proxyGroups.forEach { put(it.toJson()) } })
        put("groupSelections", JSONObject().apply {
            groupSelections.forEach { (k, v) -> if (k.isNotBlank() && v.isNotBlank()) put(k, v) }
        })
        put("mitm", mitm.toJsonObject())
        // 未建模根字段原样合并；已知字段优先，不能被未知字段覆盖。
        if (configUnknown.isNotBlank()) {
            runCatching {
                val extra = JSONObject(configUnknown)
                extra.keys().forEach { key ->
                    if (key != "configUnknown" && !has(key)) put(key, extra.get(key))
                }
            }
        }
    }

    companion object {
        private val KNOWN_JSON_KEYS = setOf(
            "mode", "selected", "nodes", "dnsUpstream", "dnsFallback", "dnsBootstrap",
            "dnsHeaderName", "dnsHeaderValue", "dnsCacheTtl", "blockTtl", "fallbackFilter",
            "fallbackGeoCheck", "dnsQueryLog", "remoteConfigUrl", "remoteConfigName",
            "remoteConfigUpdatedAt", "remoteConfigInterval", "ruleSources", "moduleSources",
            "blockEnabled", "blockMode", "cnDirect", "finalPolicy", "subscription", "rulesUrl",
            "customAds", "autoUpdateRules", "financeProtect", "rulesUpdatedAt", "allowDnsFallback", "blockWhenNoNode",
            "fakeIp", "blockAaaa", "sniff", "autoSelectNode", "autoClearLogs",
            "autoDisablePrivateDns", "themeMode", "autoConnect", "pingMethod", "subscriptionInfo",
            "hitHistoryEnabled", "ssidTriggerEnabled", "ssidTriggerNames", "ssidLocationOptIn",
            "caLastRemovalAt", "caLastRemovalCleared", "caLastRemovalFailed", "caLastRemovalFailedNs",
            "rules", "proxyGroups", "groupSelections", "mitm", "mtu", "bbr", "quicFallback",
            "dnsOnlyFullRoute",
        )

        fun defaultRules() = listOf(
            RuleItem("IP-CIDR", "10.0.0.0/8", "direct"),
            RuleItem("IP-CIDR", "172.16.0.0/12", "direct"),
            RuleItem("IP-CIDR", "192.168.0.0/16", "direct"),
            RuleItem("IP-CIDR6", "fc00::/7", "direct"),
            RuleItem("IP-CIDR6", "fe80::/10", "direct"),
        )

        fun fromJson(text: String): AppConfig {
            val def = AppConfig()
            return try {
                val o = JSONObject(text)
                val nodes = mutableListOf<NodeInfo>()
                o.optJSONArray("nodes")?.let { arr ->
                    for (i in 0 until arr.length()) nodes.add(NodeInfo.fromJson(arr.getJSONObject(i)))
                }
                val customAds = mutableListOf<String>()
                o.optJSONArray("customAds")?.let { arr ->
                    for (i in 0 until arr.length()) {
                        val d = arr.optString(i, "").trim().lowercase()
                        if (isValidAdsDomain(d)) customAds.add(d)
                    }
                }
                val rules = mutableListOf<RuleItem>()
                o.optJSONArray("rules")?.let { arr ->
                    for (i in 0 until arr.length()) rules.add(RuleItem.fromJson(arr.getJSONObject(i)))
                }
                val ruleSources = mutableListOf<RuleSource>()
                o.optJSONArray("ruleSources")?.let { arr ->
                    for (i in 0 until arr.length()) {
                        val src = RuleSource.fromJson(arr.getJSONObject(i))
                        if (src.id.isNotBlank() && src.url.isNotBlank()) ruleSources.add(src)
                    }
                }
                val moduleSources = mutableListOf<ModuleSource>()
                o.optJSONArray("moduleSources")?.let { arr ->
                    for (i in 0 until arr.length()) {
                        val m = ModuleSource.fromJson(arr.getJSONObject(i))
                        if (m.id.isNotBlank() && m.url.isNotBlank()) moduleSources.add(m)
                    }
                }
                val proxyGroups = mutableListOf<ProxyGroup>()
                o.optJSONArray("proxyGroups")?.let { arr ->
                    for (i in 0 until arr.length()) {
                        val g = ProxyGroup.fromJson(arr.getJSONObject(i))
                        if (g.name.isNotBlank()) proxyGroups.add(g)
                    }
                }
                val groupSelections = mutableMapOf<String, String>()
                o.optJSONObject("groupSelections")?.let { obj ->
                    obj.keys().forEach { key ->
                        val v = obj.optString(key, "").trim()
                        if (key.isNotBlank() && v.isNotBlank()) groupSelections[key] = v
                    }
                }
                val unknown = JSONObject()
                o.keys().forEach { key ->
                    if (key !in KNOWN_JSON_KEYS) unknown.put(key, o.get(key))
                }
                AppConfig(
                    mode = o.optString("mode", def.mode),
                    selected = o.optString("selected", "").ifEmpty { nodes.firstOrNull()?.name },
                    nodes = nodes,
                    dnsUpstream = o.optString("dnsUpstream", def.dnsUpstream),
                    dnsFallback = o.optString("dnsFallback", def.dnsFallback),
                    dnsBootstrap = o.optString("dnsBootstrap", def.dnsBootstrap),
                    dnsHeaderName = o.optString("dnsHeaderName", def.dnsHeaderName),
                    dnsHeaderValue = o.optString("dnsHeaderValue", def.dnsHeaderValue),
                    dnsCacheTtl = o.optInt("dnsCacheTtl", def.dnsCacheTtl).coerceIn(30, 86400),
                    blockTtl = o.optInt("blockTtl", def.blockTtl).coerceIn(5, 600),
                    fallbackFilter = o.optBoolean("fallbackFilter", true),
                    fallbackGeoCheck = o.optBoolean("fallbackGeoCheck", false),
                    dnsQueryLog = o.optBoolean("dnsQueryLog", true),
                    remoteConfigUrl = o.optString("remoteConfigUrl", ""),
                    remoteConfigName = o.optString("remoteConfigName", ""),
                    remoteConfigUpdatedAt = o.optLong("remoteConfigUpdatedAt", 0L),
                    remoteConfigInterval = o.optLong("remoteConfigInterval", 21600_000L).coerceAtLeast(300_000L),
                    ruleSources = ruleSources,
                    moduleSources = moduleSources,
                    blockEnabled = o.optBoolean("blockEnabled", true),
                    blockMode = o.optString("blockMode", def.blockMode),
                    cnDirect = o.optBoolean("cnDirect", true),
                    finalPolicy = o.optString("finalPolicy", def.finalPolicy),
                    subscription = o.optString("subscription", ""),
                    rulesUrl = o.optString("rulesUrl", def.rulesUrl),
                    customAds = customAds.distinct(),
                    autoUpdateRules = o.optBoolean("autoUpdateRules", true),
                    financeProtect = o.optBoolean("financeProtect", true),
                    rulesUpdatedAt = o.optLong("rulesUpdatedAt", 0L),
                    allowDnsFallback = o.optBoolean("allowDnsFallback", true),
                    blockWhenNoNode = o.optBoolean("blockWhenNoNode", true),
                    fakeIp = o.optBoolean("fakeIp", false),
                    blockAaaa = o.optBoolean("blockAaaa", false),
                    dnsOnlyFullRoute = o.optBoolean("dnsOnlyFullRoute", true),
                    quicFallback = o.optBoolean("quicFallback", true),
                    mtu = o.optInt("mtu", 9000).coerceIn(1280, 9000),
                    bbr = o.optBoolean("bbr", true),
                    sniff = o.optBoolean("sniff", true),
                    autoSelectNode = o.optBoolean("autoSelectNode", false),
                    autoClearLogs = o.optBoolean("autoClearLogs", true),
                    autoDisablePrivateDns = o.optBoolean("autoDisablePrivateDns", false),
                    themeMode = o.optString("themeMode", "system").let {
                        if (it == "light" || it == "dark" || it == "system") it else "system"
                    },
                    autoConnect = o.optBoolean("autoConnect", false),
                    pingMethod = o.optString("pingMethod", "tcp").let { if (it == "tls") "tls" else "tcp" },
                    hitHistoryEnabled = o.optBoolean("hitHistoryEnabled", true),
                    ssidTriggerEnabled = o.optBoolean("ssidTriggerEnabled", false),
                    ssidTriggerNames = o.optJSONArray("ssidTriggerNames")?.let { a ->
                        (0 until a.length()).mapNotNull { i -> a.optString(i, "").trim().takeIf { it.isNotBlank() } }
                    } ?: emptyList(),
                    ssidLocationOptIn = o.optBoolean("ssidLocationOptIn", false),
                    caLastRemovalAt = o.optLong("caLastRemovalAt", 0L),
                    caLastRemovalCleared = o.optInt("caLastRemovalCleared", 0),
                    caLastRemovalFailed = o.optInt("caLastRemovalFailed", 0),
                    caLastRemovalFailedNs = o.optString("caLastRemovalFailedNs", ""),
                    subscriptionInfo = o.optJSONObject("subscriptionInfo")?.let { SubscriptionInfo.fromJson(it) },
                    // 缺 rules 键（旧配置/外部导入）时回退默认私网直连规则，而不是空表。
                    rules = if (o.has("rules")) rules else defaultRules(),
                    proxyGroups = proxyGroups,
                    groupSelections = groupSelections,
                    mitm = MitmConfig.fromJsonObject(o.optJSONObject("mitm")),
                    configUnknown = if (unknown.length() == 0) "" else unknown.toString(),
                )
            } catch (_: Exception) {
                def
            }
        }
    }
}

private fun parseMitmHosts(arr: JSONArray?): List<MitmHostRow> {
    if (arr == null) return emptyList()
    val out = ArrayList<MitmHostRow>(arr.length())
    for (i in 0 until arr.length()) {
        val o = arr.optJSONObject(i) ?: continue
        val host = o.optString("host")
        if (host.isBlank()) continue
        out += MitmHostRow(
            host = host,
            conns = o.optLong("conns"),
            reqs = o.optLong("reqs"),
            failed = o.optLong("failed"),
            canceled = o.optLong("canceled"),
            noRule = o.optLong("noRule"),
            rewritten = o.optLong("rewritten"),
        )
    }
    return out
}
