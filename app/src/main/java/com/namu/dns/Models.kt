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

@Serializable
data class RuleItem(
    val type: String,
    val value: String,
    val action: String,
    val source: String = "",
    /** B3 单条启用开关：禁用规则不下发内核（壳层过滤），旧 JSON 缺省启用。 */
    val enabled: Boolean = true,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("type", type)
        put("value", value)
        put("action", action)
        if (source.isNotBlank()) put("source", source)
        if (!enabled) put("enabled", false)
    }

    companion object {
        fun fromJson(o: JSONObject) = RuleItem(
            o.optString("type", "DOMAIN-SUFFIX"),
            o.optString("value"),
            o.optString("action", "proxy"),
            o.optString("source", ""),
            o.optBoolean("enabled", true),
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
    /** system / light / dark；仅影响外壳配色，不进入内核配置。 */
    var themeMode: String = "system",
    /** 开机或默认网络恢复时自动启动 VPN。 */
    var autoConnect: Boolean = false,
    /** tcp / tls：首页测速和自动选节点共用。 */
    var pingMethod: String = "tcp",
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
        put("rulesUpdatedAt", rulesUpdatedAt)
        put("allowDnsFallback", allowDnsFallback)
        put("blockWhenNoNode", blockWhenNoNode)
        put("fakeIp", fakeIp)
        put("blockAaaa", blockAaaa)
        put("sniff", sniff)
        put("autoSelectNode", autoSelectNode)
        put("autoClearLogs", autoClearLogs)
        put("autoDisablePrivateDns", autoDisablePrivateDns)
        put("themeMode", themeMode)
        put("autoConnect", autoConnect)
        put("pingMethod", pingMethod)
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
            "customAds", "autoUpdateRules", "rulesUpdatedAt", "allowDnsFallback", "blockWhenNoNode",
            "fakeIp", "blockAaaa", "sniff", "autoSelectNode", "autoClearLogs",
            "autoDisablePrivateDns", "themeMode", "autoConnect", "pingMethod", "subscriptionInfo",
            "rules", "proxyGroups", "groupSelections", "mitm",
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
                    rulesUpdatedAt = o.optLong("rulesUpdatedAt", 0L),
                    allowDnsFallback = o.optBoolean("allowDnsFallback", true),
                    blockWhenNoNode = o.optBoolean("blockWhenNoNode", true),
                    fakeIp = o.optBoolean("fakeIp", false),
                    blockAaaa = o.optBoolean("blockAaaa", false),
                    sniff = o.optBoolean("sniff", true),
                    autoSelectNode = o.optBoolean("autoSelectNode", false),
                    autoClearLogs = o.optBoolean("autoClearLogs", true),
                    autoDisablePrivateDns = o.optBoolean("autoDisablePrivateDns", false),
                    themeMode = o.optString("themeMode", "system").let {
                        if (it == "light" || it == "dark" || it == "system") it else "system"
                    },
                    autoConnect = o.optBoolean("autoConnect", false),
                    pingMethod = o.optString("pingMethod", "tcp").let { if (it == "tls") "tls" else "tcp" },
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
