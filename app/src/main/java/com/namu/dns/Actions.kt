package com.namu.dns

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import com.namu.dns.core.config.MitmConfig
import com.namu.dns.core.config.ModuleOrder
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

object Actions {
    private val settings get() = App.container.settings
    private val runtime get() = App.container.runtime
    private val messages get() = App.container.messages


    /** 把文本导出到「Download/NamuDNS」或应用外部目录，返回用户可见位置。 */
    suspend fun exportText(
        context: android.content.Context,
        fileName: String,
        content: String,
        mimeType: String = "text/plain",
    ): String = exportBytes(context, fileName, content.toByteArray(), mimeType)

    /** 二进制导出统一走公共下载目录；minSdk 31 使用 MediaStore，无需存储权限。 */
    suspend fun exportBytes(
        context: android.content.Context,
        fileName: String,
        bytes: ByteArray,
        mimeType: String = "application/octet-stream",
    ): String =
        withContext(Dispatchers.IO) {
            deleteExistingDownload(context, fileName)
            val values = android.content.ContentValues().apply {
                put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                put(android.provider.MediaStore.MediaColumns.MIME_TYPE, mimeType)
                put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, "Download/NamuDNS")
            }
            val resolver = context.contentResolver
            val uri = resolver.insert(
                android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                values,
            ) ?: throw RuntimeException("无法创建导出文件")
            resolver.openOutputStream(uri)?.use { it.write(bytes) }
                ?: throw RuntimeException("写入导出文件失败")
            "下载/NamuDNS/$fileName"
        }

    /** MITM 的 PEM/DER 也落公共下载目录，和模块 zip 使用同一出口径。 */
    suspend fun exportCertificateFiles(
        context: android.content.Context,
        exported: MitmManager.ExportResult,
    ): String = withContext(Dispatchers.IO) {
        runCatching {
            val pem = File(exported.pemPath).readText()
            val der = File(exported.derPath).readBytes()
            val p1 = exportBytes(context, "namu-ca.pem", pem.toByteArray(), "application/x-pem-file")
            val p2 = exportBytes(context, "namu-ca.crt", der, "application/x-x509-ca-cert")
            "$p1；$p2"
        }.getOrDefault("")
    }

    private fun deleteExistingDownload(context: android.content.Context, fileName: String) {
        runCatching {
            val collection = android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI
            val projection = arrayOf(android.provider.MediaStore.MediaColumns._ID)
            context.contentResolver.query(
                collection,
                projection,
                "${android.provider.MediaStore.MediaColumns.DISPLAY_NAME}=?",
                arrayOf(fileName),
                null,
            )?.use { c ->
                val idCol = c.getColumnIndexOrThrow(android.provider.MediaStore.MediaColumns._ID)
                while (c.moveToNext()) {
                    context.contentResolver.delete(
                        android.content.ContentUris.withAppendedId(collection, c.getLong(idCol)),
                        null,
                        null,
                    )
                }
            }
        }
    }

    data class NodeDiagnostic(
        val line: Int,
        val scheme: String,
        val category: String,
        val reason: String,
        /** 已由内核脱敏，可直接展示，不会包含密码/token/uuid。 */
        val raw: String,
    )

    data class ImportResult(
        val nodes: Int,
        val rules: Int,
        val warnings: List<String>,
        val finalPolicy: String?,
        val routing: Boolean,
        val subscriptionInfo: SubscriptionInfo? = null,
        val diagnostics: List<NodeDiagnostic> = emptyList(),
        val diagnosticCounts: Map<String, Int> = emptyMap(),
        val totalLines: Int = nodes,
        val skipped: Int = 0,
        val groups: Int = 0,
    )

    /** 解析 `subscription-userinfo: upload=...; download=...; total=...; expire=...`。 */
    internal fun parseSubscriptionUserInfo(raw: String?, now: Long = System.currentTimeMillis()): SubscriptionInfo? {
        if (raw.isNullOrBlank()) return null
        val values = raw.split(';')
            .mapNotNull { part ->
                val i = part.indexOf('=')
                if (i <= 0) null else part.substring(0, i).trim().lowercase() to part.substring(i + 1).trim()
            }
            .toMap()
        fun long(key: String): Long = runCatching { values[key]?.toLongOrNull() ?: 0L }.getOrDefault(0L)
        val upload = long("upload")
        val download = long("download")
        val total = long("total")
        val expireRaw = long("expire")
        // 少数服务端返回毫秒；标准值是秒。用阈值兼容两种。
        val expireAt = when {
            expireRaw <= 0 -> 0L
            expireRaw > 10_000_000_000L -> expireRaw
            else -> expireRaw * 1000L
        }
        if (upload == 0L && download == 0L && total == 0L && expireAt == 0L) return null
        return SubscriptionInfo(
            upload = upload,
            download = download,
            total = total,
            expireAt = expireAt,
            updatedAt = now,
        )
    }

    data class FetchResult(val text: String, val headers: Map<String, String>, val status: Int = 200)

    suspend fun fetchText(
        url: String,
        maxBytes: Int = 16 * 1024 * 1024,
        headers: Map<String, String> = emptyMap(),
    ): String = fetchTextResult(url, maxBytes, headers).text

    suspend fun fetchTextResult(
        url: String,
        maxBytes: Int = 16 * 1024 * 1024,
        headers: Map<String, String> = emptyMap(),
    ): FetchResult = withContext(Dispatchers.IO) {
        var current = url.trim()
        var redirects = 0
        while (true) {
            val conn = URL(current).openConnection() as HttpURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 20000
            // 手动处理重定向，确保自定义鉴权 Header 不会被 HttpURLConnection
            // 自动带到另一个域名。
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            conn.setRequestProperty("User-Agent", "NamuDNS/1.0")
            headers.forEach { (k, v) ->
                if (k.isNotBlank() && v.isNotBlank()) conn.setRequestProperty(k, v)
            }
            try {
                val code = conn.responseCode
                if (code == HttpURLConnection.HTTP_NOT_MODIFIED) {
                    val responseHeaders = conn.headerFields
                        .filterKeys { it != null }
                        .mapKeys { (key, _) -> key.lowercase() }
                        .mapValues { (_, values) -> values.firstOrNull().orEmpty() }
                    return@withContext FetchResult("", responseHeaders, 304)
                }
                if (code in 300..399) {
                    val location = conn.getHeaderField("Location")
                        ?: throw RuntimeException("HTTP $code 没有 Location")
                    val next = URL(URL(current), location).toString()
                    if (!next.startsWith("http://") && !next.startsWith("https://")) {
                        throw RuntimeException("拒绝跳转到非 HTTP(S) 地址")
                    }
                    // 订阅/规则内容可被中间人篡改节点列表：禁止 HTTPS 降级到明文 HTTP。
                    if (current.startsWith("https://") && next.startsWith("http://")) {
                        throw RuntimeException("拒绝 HTTPS→HTTP 降级跳转")
                    }
                    if (headers.isNotEmpty() && !sameHeaderOrigin(current, next)) {
                        throw RuntimeException("重定向到其他域名，已拒绝携带鉴权头")
                    }
                    redirects++
                    if (redirects > 3) throw RuntimeException("重定向次数过多")
                    current = next
                    continue
                }
                if (code !in 200..299) throw RuntimeException("HTTP $code")
                val declared = conn.contentLengthLong
                if (declared > maxBytes) throw RuntimeException("内容过大（${declared} 字节）")
                val out = ByteArrayOutputStream()
                conn.inputStream.use { input ->
                    val buf = ByteArray(8192)
                    var total = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > maxBytes) {
                            throw RuntimeException("内容超过 ${maxBytes / 1024 / 1024}MB 限制")
                        }
                        out.write(buf, 0, n)
                    }
                }
                val responseHeaders = conn.headerFields
                    .filterKeys { it != null }
                    .mapKeys { (key, _) -> key.lowercase() }
                    .mapValues { (_, values) -> values.firstOrNull().orEmpty() }
                return@withContext FetchResult(
                    text = out.toString(Charsets.UTF_8.name()),
                    headers = responseHeaders,
                    status = code,
                )
            } finally {
                conn.disconnect()
            }
        }
        @Suppress("UNREACHABLE_CODE")
        throw RuntimeException("下载失败")
    }

    private fun sameHeaderOrigin(from: String, to: String): Boolean {
        val a = runCatching { java.net.URI(from) }.getOrNull() ?: return false
        val b = runCatching { java.net.URI(to) }.getOrNull() ?: return false
        // 鉴权头只允许跟随「同源」跳转：协议、主机、有效端口三者都必须一致。
        // 只比 host 会让 https://sub.example.com:8443 或 http://same.host 也带走令牌。
        fun effectivePort(u: java.net.URI): Int = if (u.port > 0) u.port else if (u.scheme == "https") 443 else 80
        return a.scheme.equals(b.scheme, ignoreCase = true) &&
            a.scheme.equals("https", ignoreCase = true) &&
            a.host.equals(b.host, ignoreCase = true) &&
            effectivePort(a) == effectivePort(b)
    }

    private fun validateRules(text: String) {
        if (text.isBlank()) throw RuntimeException("规则内容为空")
        if (text.length > 8 * 1024 * 1024) throw RuntimeException("规则超过 8MB 限制")
        if (text.any { it.code < 0x09 || (it.code in 0x0E..0x1F) }) {
            throw RuntimeException("规则包含异常控制字符")
        }
    }

    /** 解析订阅里的策略组；Clash 的 load-balance 类型与 strategy 必须保留。 */
    internal fun importedProxyGroup(g: JSONObject): ProxyGroup? {
        val name = g.optString("name", "").trim()
        val members = mutableListOf<String>()
        g.optJSONArray("members")?.let { ms ->
            for (j in 0 until ms.length()) {
                ms.optString(j, "").trim().takeIf { it.isNotBlank() }?.let { members.add(it) }
            }
        }
        if (name.isBlank() || members.isEmpty()) return null
        val type = g.optString("type", "select").trim().lowercase().let {
            when (it) {
                "url-test", "urltest" -> "url-test"
                "fallback" -> "fallback"
                "load-balance", "loadbalance", "balance" -> "load-balance"
                else -> "select"
            }
        }
        val lb = g.optString("lb_mode", "")
            .ifBlank { g.optString("lbMode", "") }
            .ifBlank { g.optString("strategy", "") }
            .trim().lowercase()
        val lbMode = when (lb) {
            "consistent-hash", "consistenthash", "ch" -> "consistent-hash"
            // Clash 的 load-balance 默认 strategy 是 round-robin；缺失时不能反选成 hash。
            else -> "round-robin"
        }
        return ProxyGroup(
            name = name,
            type = type,
            members = members,
            testUrl = g.optString("test_url", g.optString("testUrl", "http://www.gstatic.com/generate_204")),
            interval = g.optInt("interval", 600),
            timeout = g.optInt("timeout", 5000),
            tolerance = g.optInt("tolerance", 50),
            failureThreshold = g.optInt("failure_threshold", g.optInt("failureThreshold", 3)),
            recoveryThreshold = g.optInt("recovery_threshold", g.optInt("recoveryThreshold", 2)),
            noNodeAction = g.optString("no_node_action", g.optString("noNodeAction", "global")),
            lbMode = lbMode,
            switchInterval = g.optInt("switch_interval", g.optInt("switchInterval", 30)),
        )
    }

    suspend fun importSubscription(
        rawInput: String,
        append: Boolean = false,
    ): ImportResult = withContext(Dispatchers.IO) {
        val isUrl = rawInput.trim().startsWith("http://") || rawInput.trim().startsWith("https://")
        val fetched = if (isUrl) fetchTextResult(rawInput.trim()) else null
        val raw = fetched?.text ?: rawInput
        val info = parseSubscriptionUserInfo(fetched?.headers?.get("subscription-userinfo"))
        val json = NativeCore.nativeParseSubscription(raw)
        val obj = JSONObject(json)
        val nodesArr = obj.optJSONArray("nodes") ?: throw RuntimeException("没有解析到节点")
        val nodes = mutableListOf<NodeInfo>()
        for (i in 0 until nodesArr.length()) {
            nodes.add(NodeInfo.fromJson(nodesArr.getJSONObject(i)))
        }
        // 记录来源分组：订阅取域名，剪贴板内容记为手动导入。
        val groupName = if (rawInput.trim().startsWith("http")) {
            runCatching { java.net.URI(rawInput.trim()).host }.getOrNull()?.ifBlank { "订阅" } ?: "订阅"
        } else {
            "手动导入"
        }
        val imported = nodes.map { it.copy(group = groupName) }
        val importedCount = imported.size
        val rulesArr = obj.optJSONArray("rules")
        val rules = mutableListOf<RuleItem>()
        if (rulesArr != null) {
            for (i in 0 until rulesArr.length()) {
                rules.add(RuleItem.fromJson(rulesArr.getJSONObject(i)))
            }
        }
        val groups = mutableListOf<ProxyGroup>()
        obj.optJSONArray("proxy_groups")?.let { arr ->
            for (i in 0 until arr.length()) {
                val g = arr.optJSONObject(i) ?: continue
                importedProxyGroup(g)?.let { groups.add(it) }
            }
        }
        val warnings = mutableListOf<String>()
        obj.optJSONArray("warnings")?.let { arr ->
            for (i in 0 until arr.length()) warnings.add(arr.optString(i))
        }
        val diagnostics = mutableListOf<NodeDiagnostic>()
        obj.optJSONArray("diagnostics")?.let { arr ->
            for (i in 0 until arr.length()) {
                val d = arr.optJSONObject(i) ?: continue
                diagnostics.add(
                    NodeDiagnostic(
                        line = d.optInt("line", 0),
                        scheme = d.optString("scheme", "?"),
                        category = d.optString("category", "invalid"),
                        reason = d.optString("reason", "已跳过"),
                        raw = d.optString("raw", ""),
                    )
                )
            }
        }
        val counts = linkedMapOf<String, Int>()
        obj.optJSONObject("diagnostic_counts")?.let { c ->
            listOf("unknown_scheme", "unsupported_protocol", "unsupported_param", "invalid").forEach { k ->
                val n = c.optInt(k, 0)
                if (n > 0) counts[k] = n
            }
        }
        val totalLines = obj.optInt("total_lines", nodes.size + diagnostics.size)
        val routing = obj.optBoolean("routing", false)
        val finalPolicy = obj.optString("final", "").ifBlank { null }
        if (nodes.isEmpty()) {
            if (diagnostics.isEmpty()) throw RuntimeException("没有解析到节点")
            // 全部条目都被跳过时也返回诊断，UI 能显示逐项原因；不触碰现有节点。
            return@withContext ImportResult(
                nodes = 0,
                rules = 0,
                warnings = warnings,
                finalPolicy = null,
                routing = false,
                subscriptionInfo = info,
                diagnostics = diagnostics,
                diagnosticCounts = counts,
                totalLines = totalLines,
                skipped = obj.optInt("unsupported", diagnostics.size),
            )
        }
        withContext(Dispatchers.Main) {
            val oldSelected = settings.current().selected
            val merged = if (append) {
                // 追加导入：同名节点以新导入的为准，其余保留原分组
                (settings.current().nodes.filterNot { old -> imported.any { it.name == old.name } } + imported)
            } else {
                imported
            }
            val keep = merged.any { it.name == oldSelected }
            val mergedGroups = if (groups.isEmpty()) {
                settings.current().proxyGroups
            } else {
                val base = settings.current().proxyGroups.filterNot { old -> groups.any { it.name == old.name } }
                base + groups
            }
            settings.update { current ->
                current.copy(
                    nodes = merged,
                    selected = if (keep) oldSelected else merged.firstOrNull()?.name,
                    rules = if (routing) rules else current.rules,
                    finalPolicy = finalPolicy ?: current.finalPolicy,
                    proxyGroups = mergedGroups,
                    groupSelections = current.groupSelections.filterKeys { key ->
                        mergedGroups.any { it.name == key }
                    },
                    subscriptionInfo = info ?: current.subscriptionInfo,
                )
            }
        }
        ImportResult(
            nodes = importedCount,
            rules = rules.size,
            warnings = warnings,
            finalPolicy = finalPolicy,
            routing = routing,
            subscriptionInfo = info,
            diagnostics = diagnostics,
            diagnosticCounts = counts,
            totalLines = totalLines,
            skipped = obj.optInt("unsupported", diagnostics.size),
            groups = groups.size,
        )
    }

    /** 下拉刷新/周期任务：重新拉取订阅并保留已有节点（同名覆盖），同时刷新 userinfo。 */
    suspend fun refreshSubscription(): ImportResult = withContext(Dispatchers.IO) {
        val url = settings.current().subscription.trim()
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw RuntimeException("当前配置没有订阅链接")
        }
        importSubscription(url, append = true)
    }

    /** 刷新结果必须带回 UI/后台：零节点不能再说「已刷新」。 */
    internal fun subscriptionRefreshMessage(result: ImportResult): String {
        if (result.nodes == 0) {
            val reason = result.diagnostics.firstOrNull()?.reason?.takeIf { it.isNotBlank() }
            return "订阅未解析到可用节点，已保留上次节点" +
                (reason?.let { "：$it" } ?: "")
        }
        val skipped = if (result.skipped > 0) "，跳过 ${result.skipped} 个" else ""
        return "订阅已刷新：可用 ${result.nodes} 个$skipped"
    }

    data class RuleSyncResult(
        val updated: Int,
        val lines: Int,
        val errors: List<String>,
    )

    data class RemoteConfigResult(
        val name: String,
        val sources: Int,
        val lines: Int,
        val errors: List<String>,
    )

    /**
     * 自定义 DNS Header 只发给与 DoH 上游同主机的 HTTPS URL。
     * 远端配置和规则集可能放在别的 CDN/域名，绝不能把鉴权头带过去。
     */
    private fun headerMapFor(cfg: AppConfig, url: String): Map<String, String> {
        if (cfg.dnsHeaderName.isBlank() || cfg.dnsHeaderValue.isBlank()) return emptyMap()
        val dnsHost = runCatching { java.net.URI(cfg.dnsUpstream).host }.getOrNull() ?: return emptyMap()
        val target = runCatching { java.net.URI(url) }.getOrNull() ?: return emptyMap()
        if (target.scheme != "https" || target.host != dnsHost) return emptyMap()
        return mapOf(cfg.dnsHeaderName.trim() to cfg.dnsHeaderValue)
    }

    private fun detectRuleSourceFormat(text: String, fallback: String): String {
        val heads = text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith("!") }
            .take(30)
            .toList()
        return when {
            heads.any { it.startsWith("proxies:") || it.startsWith("rules:") || it.startsWith("proxy-groups:") } -> "clash-yaml"
            heads.any { it.startsWith("DOMAIN") || it.startsWith("IP-CIDR") || it.startsWith("GEOIP") } -> "clash-rules"
            heads.any { it.startsWith("||") || it.startsWith("@@") || it.contains("$") } -> "adblock"
            heads.any { it.matches(Regex("^[A-Za-z0-9*._-]+$")) } -> "domain"
            else -> fallback
        }
    }

    /** 下载并原子替换所有规则源；单个源失败时保留它的上一份文件。 */
    suspend fun syncRuleSources(
        sources: List<RuleSource>? = null,
        profileName: String = App.container.config.activeName(),
    ): RuleSyncResult = withContext(Dispatchers.IO) {
        val selected = sources ?: GlobalRuleStore.state.ruleSets
        var updated = 0
        var totalLines = 0
        val errors = mutableListOf<String>()
        val results = mutableMapOf<String, RuleSource>()
        selected.filter { it.enabled }.forEach { src ->
            val file = ConfigStore.globalRuleSetFile(App.context, src.url)
            val now = System.currentTimeMillis()
            try {
                val conditional = buildMap {
                    if (file.length() > 0L && src.etag.isNotBlank()) put("If-None-Match", src.etag)
                    if (file.length() > 0L && src.lastModified.isNotBlank()) put("If-Modified-Since", src.lastModified)
                }
                val headers = headerMapFor(settings.current(), src.url) + conditional
                val fetched = fetchTextResult(src.url, maxBytes = 8 * 1024 * 1024, headers = headers)
                if (fetched.status == 304) {
                    val cachedLines = if (file.exists() && file.length() > 0) file.useLines { it.count() } else 0
                    results[src.id] = src.copy(
                        updatedAt = now,
                        lastAttemptAt = now,
                        lines = cachedLines,
                        error = "",
                        stale = false,
                        notModified = true,
                        etag = fetched.headers["etag"] ?: src.etag,
                        lastModified = fetched.headers["last-modified"] ?: src.lastModified,
                        cacheBytes = if (file.exists()) file.length() else 0,
                    )
                    updated += 1
                    totalLines += cachedLines
                    return@forEach
                }
                val text = fetched.text
                validateRules(text)
                ConfigStore.writeAtomicPublic(file, text)
                check(file.readText() == text) { "规则缓存写入失败" }
                val lines = text.lines().count()
                results[src.id] = src.copy(
                    updatedAt = now,
                    lastAttemptAt = now,
                    lines = lines,
                    error = "",
                    stale = false,
                    notModified = false,
                    etag = fetched.headers["etag"] ?: "",
                    lastModified = fetched.headers["last-modified"] ?: "",
                    cacheBytes = file.length(),
                    format = detectRuleSourceFormat(text, src.format),
                )
                updated += 1
                totalLines += lines
            } catch (e: Exception) {
                val msg = "${src.id}: ${e.message ?: "下载失败"}"
                errors.add(msg)
                val cached = file.exists() && file.length() > 0
                results[src.id] = src.copy(
                    lastAttemptAt = now,
                    error = e.message ?: "下载失败",
                    stale = cached,
                    cacheBytes = if (cached) file.length() else 0,
                    lines = if (cached) runCatching { file.useLines { it.count() } }.getOrDefault(src.lines) else src.lines,
                )
                if (cached) {
                    totalLines += results[src.id]?.lines ?: 0
                }
            }
        }
        withContext(Dispatchers.Main) {
            GlobalRuleStore.update(App.context) { st ->
                st.copy(ruleSets = st.ruleSets.map { source ->
                    results[source.id]?.takeIf { it.url == source.url }
                        ?.copy(enabled = source.enabled, origin = source.origin, order = source.order) ?: source
                })
            }
        }
        RuleSyncResult(updated, totalLines, errors)
    }

    data class ModuleResult(
        val name: String,
        val app: String,
        val blockRules: Int,
        val routeRules: Int,
        val mitmRules: Int,
        val ignored: Int,
        val allowRules: Int = 0,
    )

    /** 模块至少要产出一种能力：DNS 阻断/分流，或 MITM/URL/Header 重写。 */
    private fun hasUsableRules(parsed: ParsedModule): Boolean =
        parsed.blockLines.isNotEmpty() || parsed.routeRules.isNotEmpty() || parsed.ruleSets.isNotEmpty() ||
            parsed.mitmHostnames.isNotEmpty() || parsed.urlRewrites.isNotEmpty() ||
            parsed.headerRewrites.isNotEmpty() || parsed.loonRewrites.isNotEmpty() ||
            parsed.scripts.isNotEmpty() || parsed.scriptLines.isNotEmpty()

    private fun mitmRuleCount(parsed: ParsedModule): Int =
        parsed.mitmHostnames.size + parsed.urlRewrites.size + parsed.headerRewrites.size +
            parsed.loonRewrites.size + parsed.scripts.size

    /**
     * 下载 [Script] 的 script-path 正文并缓存。缓存按 URL 哈希落盘，
     * 模块重建时直接读本地文件，不联网；syncModules 会强制刷新。
     */
    private suspend fun hydrateScripts(parsed: ParsedModule, refresh: Boolean): ParsedModule =
        withContext(Dispatchers.IO) {
            if (parsed.scripts.isEmpty()) return@withContext parsed
            val rules = mutableListOf<com.namu.dns.core.config.ScriptConfig>()
            val issues = parsed.scriptIssues.toMutableList()
            parsed.scripts.take(64).forEach { rule ->
                var source = ""
                val cache = ConfigStore.scriptCacheFile(App.context, rule.scriptPath)
                if (!refresh && cache.exists() && cache.length() > 0) {
                    source = runCatching { cache.readText() }.getOrDefault("")
                }
                if (source.isBlank()) {
                    try {
                        source = fetchText(
                            rule.scriptPath,
                            maxBytes = 4 * 1024 * 1024,
                            headers = headerMapFor(settings.current(), rule.scriptPath),
                        )
                        if (source.any { it.code < 0x09 || (it.code in 0x0E..0x1F) }) {
                            throw RuntimeException("脚本包含异常控制字符")
                        }
                        cache.parentFile?.mkdirs()
                        val tmp = File(cache.parentFile, cache.name + ".tmp")
                        tmp.writeText(source)
                        if (!tmp.renameTo(cache)) {
                            cache.writeText(source)
                            tmp.delete()
                        }
                    } catch (e: Exception) {
                        issues.add("${rule.name}: 脚本下载失败 ${e.message ?: ""}".trim())
                    }
                }
                if (source.isNotBlank()) {
                    rules.add(rule.copy(source = source))
                }
            }
            val deps = parsed.dependencies.toMutableList()
            if (rules.isNotEmpty()) deps.add("脚本正文已缓存 ${rules.size} 条（内核 QuickJS 执行）")
            if (issues.isNotEmpty()) deps.add("脚本缺口 ${issues.size} 条，见导入预览")
            parsed.copy(scripts = rules, scriptIssues = issues.distinct(), dependencies = deps.distinct())
        }

    private fun moduleId(url: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(url.toByteArray())
            .joinToString("") { "%02x".format(it) }
        return "mod_${digest.take(10)}"
    }

    /** 拉取模块引用的规则集内容并缓存；失败保留旧缓存，rebuildModules 继续用旧内容。 */
    private suspend fun fetchRuleSets(parsed: ParsedModule) {
        parsed.ruleSets.forEach { rs ->
            runCatching {
                val text = fetchText(
                    rs.url,
                    maxBytes = 8 * 1024 * 1024,
                    headers = headerMapFor(settings.current(), rs.url),
                )
                if (text.isNotBlank()) ConfigStore.ruleSetFile(App.context, rs.url).writeText(text)
            }
        }
    }

    private fun saveModuleFile(id: String, text: String) {
        val file = ConfigStore.moduleFile(App.context, id)
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.parentFile?.mkdirs()
        tmp.writeText(text)
        if (!tmp.renameTo(file)) {
            file.writeText(text)
            tmp.delete()
        }
    }

    /** 从 URL 导入一个小火箭式模块；同一个 URL 再次导入会更新原模块。 */
    suspend fun importModule(url: String, displayName: String = ""): ModuleResult = withContext(Dispatchers.IO) {
        val target = url.trim()
        ModuleFetchPolicy.urlError(target, allowLocal = true)?.let { throw RuntimeException(it) }
        val text = fetchText(
            target,
            maxBytes = ModuleFetchPolicy.MAX_BYTES,
            headers = headerMapFor(settings.current(), target),
        )
        ModuleFetchPolicy.controlCharError(text)?.let { throw RuntimeException(it) }
        val parsed = hydrateScripts(ModuleParser.parse(text), refresh = true)
        if (!hasUsableRules(parsed)) {
            throw RuntimeException("模块里没有可用的 DNS/分流或 MITM/重写规则")
        }
        saveParsedModule(target, displayName, text, parsed)
    }

    data class ModulePreview(
        val url: String,
        val name: String,
        val text: String,
        val parsed: ParsedModule,
        val duplicateBlock: Int,
        val duplicateRoute: Int,
        /** 3.0.18：模块附带 DNS 参数摘要；导入预览提示，经确认才合并。 */
        val dnsNotes: List<String> = emptyList(),
    )

    /** 导入前预览：只下载和解析，不落盘；同时统计与现有模块重复的规则条数。 */
    suspend fun previewModule(url: String, displayName: String = ""): ModulePreview = withContext(Dispatchers.IO) {
        val target = url.trim()
        ModuleFetchPolicy.urlError(target, allowLocal = true)?.let { throw RuntimeException(it) }
        val text = fetchText(target, maxBytes = ModuleFetchPolicy.MAX_BYTES, headers = headerMapFor(settings.current(), target))
        previewModuleText(target, text, displayName)
    }

    /**
     * 本地文件导入预览：source 使用 `local://文件名`，syncModules 会跳过它，
     * 不会把本地模块误当成远端地址重新下载。
     */
    suspend fun previewModuleText(
        source: String,
        rawText: String,
        displayName: String = "",
    ): ModulePreview = withContext(Dispatchers.IO) {
        val target = source.trim()
        if (target.isBlank()) throw RuntimeException("模块来源为空")
        val text = rawText.removePrefix("\uFEFF")
        ModuleFetchPolicy.sizeError(text.toByteArray().size.toLong())?.let { throw RuntimeException(it) }
        ModuleFetchPolicy.controlCharError(text)?.let { throw RuntimeException(it) }
        val parsed = hydrateScripts(ModuleParser.parse(text), refresh = false)
        if (!hasUsableRules(parsed)) {
            throw RuntimeException("模块里没有可用的 DNS/分流或 MITM/重写规则")
        }
        val existingBlocks = HashSet<String>()
        val existingRoutes = HashSet<String>()
        GlobalRuleStore.state.modules.filter { it.url != target }.forEach { src ->
            val f = ConfigStore.moduleFile(App.context, src.id)
            if (f.exists() && f.length() > 0) {
                runCatching { ModuleParser.parse(f.readText()) }.getOrNull()?.let { old ->
                    existingBlocks.addAll(old.blockLines)
                    old.routeRules.forEach { existingRoutes.add("${it.type}|${it.value}|${it.action}") }
                }
            }
        }
        ModulePreview(
            url = target,
            name = displayName.trim().ifBlank {
                parsed.name.ifBlank {
                    target.removePrefix("local://").substringAfter("://").substringBefore('/').ifBlank { "模块" }
                }
            },
            text = text,
            parsed = parsed,
            duplicateBlock = parsed.blockLines.count { it in existingBlocks },
            duplicateRoute = parsed.routeRules.count { "${it.type}|${it.value}|${it.action}" in existingRoutes },
            dnsNotes = buildList {
                if (parsed.dnsPolicies.isNotEmpty()) add("按域名 DNS 策略 ${parsed.dnsPolicies.size} 条")
                parsed.generalOptions["always-real-ip"]?.let { add("always-real-ip：$it") }
                listOf("ipv6" to "IPv6 开关", "prefer-ipv6" to "IPv6 优先", "hijack-dns" to "DNS 接管开关").forEach { (k, label) ->
                    parsed.generalOptions[k]?.let { add("$label：$it") }
                }
            },
        )
    }

    /** 预览确认后直接落盘导入，不再重复下载。 */
    suspend fun importPreview(preview: ModulePreview, approveDns: Boolean = false): ModuleResult {
        saveParsedModule(preview.url, preview.name, preview.text, preview.parsed, dnsApproved = approveDns)
        return ModuleResult(
            preview.name,
            preview.parsed.app,
            preview.parsed.blockLines.size,
            preview.parsed.routeRules.size,
            mitmRuleCount(preview.parsed),
            preview.parsed.ignored,
            preview.parsed.allowLines.size,
        )
    }

    private suspend fun saveParsedModule(
        target: String,
        displayName: String,
        text: String,
        parsed: ParsedModule,
        dnsApproved: Boolean? = null,
    ): ModuleResult {
        val existing = GlobalRuleStore.state.modules.firstOrNull { it.url == target }
        val id = existing?.id ?: moduleId(target)
        saveModuleFile(id, text)
        fetchRuleSets(parsed)
        val source = ModuleSource(
            id = id,
            name = displayName.trim().ifBlank { parsed.name.ifBlank { target.removePrefix("local://").substringAfter("://").substringBefore('/').ifBlank { "模块" } } },
            url = target,
            app = parsed.app,
            iconUrl = parsed.iconUrl,
            enabled = existing?.enabled ?: true,
            updatedAt = System.currentTimeMillis(),
            blockRules = parsed.blockLines.size,
            routeRules = parsed.routeRules.size,
            mitmRules = mitmRuleCount(parsed),
            allowRules = parsed.allowLines.size,
            ignored = parsed.ignored,
            error = "",
            intervalSeconds = existing?.intervalSeconds ?: 21600L,
            lastAttemptAt = System.currentTimeMillis(),
            etag = existing?.etag ?: "",
            lastModified = existing?.lastModified ?: "",
            stale = false,
            cacheBytes = text.toByteArray().size.toLong(),
            dnsApproved = dnsApproved ?: existing?.dnsApproved ?: false,
            order = existing?.order ?: -1,
        )
        withContext(Dispatchers.Main) {
            GlobalRuleStore.update(App.context) { st ->
                st.copy(modules = st.modules.filterNot { it.url == target } + source)
            }
            ConfigStore.rebuildModules(App.context, settings.current())
        }
        return ModuleResult(
            source.name,
            source.app,
            source.blockRules,
            source.routeRules,
            source.mitmRules,
            source.ignored,
            source.allowRules,
        )
    }

    data class ModuleSyncResult(val updated: Int, val errors: List<String>)

    /**
     * 同步结果写回时以「当前模块对象」为准，只合并下载/解析产出的字段。
     * 同步是慢操作：用户可能在下载期间手动关闭模块、改周期或改 URL。若直接
     * 用入队时的整条 [synced] 覆盖，会把 enabled=true 的旧状态复活，或把新
     * URL 的模块写回旧地址。enabled/intervalSeconds/url 等用户字段一律保留。
     */
    internal fun mergeModuleSyncState(current: ModuleSource, synced: ModuleSource): ModuleSource =
        current.copy(
            name = synced.name,
            app = synced.app,
            iconUrl = synced.iconUrl,
            updatedAt = synced.updatedAt,
            blockRules = synced.blockRules,
            routeRules = synced.routeRules,
            mitmRules = synced.mitmRules,
            allowRules = synced.allowRules,
            ignored = synced.ignored,
            error = synced.error,
            lastAttemptAt = synced.lastAttemptAt,
            etag = synced.etag,
            lastModified = synced.lastModified,
            stale = synced.stale,
            cacheBytes = synced.cacheBytes,
            notModified = synced.notModified,
        )

    /** 同一 id 但 URL 已在同步期间被用户改掉时，旧下载结果必须丢弃。 */
    internal fun mergeModuleSyncResults(
        current: List<ModuleSource>,
        results: Map<String, ModuleSource>,
    ): List<ModuleSource> = current.map { cur ->
        val synced = results[cur.id]
        if (synced == null || synced.url != cur.url) cur
        else mergeModuleSyncState(cur, synced)
    }

    /**
     * 拉取模块：未传 moduleId 时只处理全部启用模块；传入时只同步指定模块（含停用模块）。
     * HTTPS → 条件请求 → 校验 → 原子落盘；失败时保留上一份 good 文件，只标 stale，不清空。
     */
    suspend fun syncModules(moduleId: String? = null): ModuleSyncResult = withContext(Dispatchers.IO) {
        var updated = 0
        val errors = mutableListOf<String>()
        val results = mutableMapOf<String, ModuleSource>()
        GlobalRuleStore.state.modules.filter { src ->
            if (moduleId == null) src.enabled else src.id == moduleId
        }.forEach { src ->
            if (!src.url.startsWith("https://")) {
                results[src.id] = src.copy(
                    error = "远程模块只允许 HTTPS，已保留旧缓存",
                    stale = ConfigStore.moduleFile(App.context, src.id).let { it.exists() && it.length() > 0 },
                    lastAttemptAt = System.currentTimeMillis(),
                )
                errors.add("${src.name}: 非 HTTPS 源未更新")
                return@forEach
            }
            val file = ConfigStore.moduleFile(App.context, src.id)
            val now = System.currentTimeMillis()
            try {
                val conditional = buildMap {
                    if (file.length() > 0L) {
                        if (src.etag.isNotBlank()) put("If-None-Match", src.etag)
                        if (src.lastModified.isNotBlank()) put("If-Modified-Since", src.lastModified)
                    }
                }
                val fetched = fetchTextResult(
                    src.url,
                    maxBytes = 4 * 1024 * 1024,
                    headers = headerMapFor(settings.current(), src.url) + conditional,
                )
                if (fetched.status == 304) {
                    if (!file.exists() || file.length() == 0L) throw RuntimeException("304 但没有本地缓存")
                    results[src.id] = src.copy(
                        lastAttemptAt = now, error = "", stale = false, notModified = true,
                        cacheBytes = file.length(),
                        etag = fetched.headers["etag"] ?: src.etag,
                        lastModified = fetched.headers["last-modified"] ?: src.lastModified,
                    )
                    updated++
                    return@forEach
                }
                ModuleFetchPolicy.contentTypeError(fetched.headers["content-type"])
                    ?.let { throw RuntimeException(it) }
                val text = fetched.text
                ModuleFetchPolicy.sizeError(text.toByteArray().size.toLong())?.let { throw RuntimeException(it) }
                ModuleFetchPolicy.controlCharError(text)?.let { throw RuntimeException(it) }
                val parsed = hydrateScripts(ModuleParser.parse(text), refresh = true)
                if (!hasUsableRules(parsed)) throw RuntimeException("没有可用的 DNS/分流或 MITM/重写规则")
                if (file.exists()) file.copyTo(File(file.parentFile, file.name + ".bak"), overwrite = true)
                saveModuleFile(src.id, text)
                fetchRuleSets(parsed)
                results[src.id] = src.copy(
                    name = src.name.ifBlank { parsed.name },
                    app = parsed.app.ifBlank { src.app },
                    iconUrl = parsed.iconUrl,
                    updatedAt = now,
                    lastAttemptAt = now,
                    blockRules = parsed.blockLines.size,
                    routeRules = parsed.routeRules.size,
                    mitmRules = mitmRuleCount(parsed),
                    allowRules = parsed.allowLines.size,
                    ignored = parsed.ignored,
                    error = "",
                    stale = false,
                    notModified = false,
                    cacheBytes = file.length(),
                    etag = fetched.headers["etag"] ?: "",
                    lastModified = fetched.headers["last-modified"] ?: "",
                )
                updated++
            } catch (e: Exception) {
                val msg = "${src.name}: ${e.message ?: "下载失败"}"
                errors.add(msg)
                val cached = file.exists() && file.length() > 0
                results[src.id] = src.copy(
                    lastAttemptAt = now,
                    error = e.message ?: "下载失败",
                    stale = cached,
                    cacheBytes = if (cached) file.length() else 0,
                )
            }
        }
        withContext(Dispatchers.Main) {
            // 只合并同步字段，不在写回时复活用户刚关闭的模块。
            GlobalRuleStore.update(App.context) { st ->
                st.copy(modules = mergeModuleSyncResults(st.modules, results))
            }
            ConfigStore.rebuildModules(App.context, settings.current())
        }
        if (updated > 0 && runtime.current().connected) {
            withContext(Dispatchers.Main) { ApplyCoordinator.requestApply(App.context, "配置变更") }
        }
        ModuleSyncResult(updated, errors)
    }

    suspend fun setModuleEnabled(id: String, enabled: Boolean) = withContext(Dispatchers.Main) {
        GlobalRuleStore.update(App.context) { st ->
            st.copy(modules = st.modules.map { if (it.id == id) it.copy(enabled = enabled) else it })
        }
        ConfigStore.rebuildModules(App.context, settings.current())
        if (runtime.current().connected) ApplyCoordinator.requestApply(App.context, "配置变更")
    }

    /** U2：只改 Profile 内模块顺序，重建规则后热重载，identity 不变。 */
    suspend fun moveModule(from: Int, to: Int) = withContext(Dispatchers.Main) {
        val moved = ModuleOrder.move(GlobalRuleStore.orderedModules(), from, to)
        GlobalRuleStore.update(App.context) { st -> st.copy(modules = moved) }
        ConfigStore.rebuildModules(App.context, settings.current())
        if (runtime.current().connected) ApplyCoordinator.requestApply(App.context, "配置变更")
    }

    /** 长按拖拽松手后一次落盘，避免拖动过程中反复重建规则。 */
    suspend fun reorderModule(id: String, to: Int) = withContext(Dispatchers.Main) {
        val ordered = GlobalRuleStore.orderedModules()
        val from = ordered.indexOfFirst { it.id == id }
        if (from >= 0) {
            val moved = ModuleOrder.move(ordered, from, to)
            GlobalRuleStore.update(App.context) { st -> st.copy(modules = moved) }
            ConfigStore.rebuildModules(App.context, settings.current())
            if (runtime.current().connected) ApplyCoordinator.requestApply(App.context, "配置变更")
        }
    }

    /** 编辑模块的 #!app 分组元数据；这不是系统级 UID 隔离开关。 */
    suspend fun setModuleApp(id: String, app: String) = withContext(Dispatchers.Main) {
        GlobalRuleStore.update(App.context) { st ->
            st.copy(modules = st.modules.map { if (it.id == id) it.copy(app = app.trim()) else it })
        }
    }

    suspend fun deleteModule(id: String) = withContext(Dispatchers.Main) {
        GlobalRuleStore.update(App.context) { st -> st.copy(modules = st.modules.filterNot { it.id == id }) }
        ConfigStore.rebuildModules(App.context, settings.current())
        runCatching { ConfigStore.moduleFile(App.context, id).delete() }
        if (runtime.current().connected) ApplyCoordinator.requestApply(App.context, "配置变更")
    }

    private suspend fun applyRemoteConfig(o: JSONObject, url: String, profileName: String): Pair<AppConfig, List<RuleSource>> = withContext(Dispatchers.Main) {
        val version = o.optInt("version", 1)
        if (version !in 1..2) throw RuntimeException("不支持的配置版本：$version")
        val dns = o.optJSONObject("dns")
        val routing = o.optJSONObject("routing")
        val explicitFallback = dns?.takeIf { it.has("fallback") && !it.isNull("fallback") }?.optString("fallback")?.trim()
        var headerName = dns?.optString("header_name", "")?.trim().orEmpty()
        var headerValue = dns?.optString("header_value", "")?.trim().orEmpty()
        dns?.optJSONObject("headers")?.let { h ->
            val key = h.keys().asSequence().firstOrNull()
            if (!key.isNullOrBlank()) {
                headerName = key
                headerValue = h.optString(key, "")
            }
        }
        val sources = mutableListOf<RuleSource>()
        o.optJSONArray("rule_sources")?.let { arr ->
            for (i in 0 until arr.length()) {
                val item = arr.optJSONObject(i) ?: continue
                val id = item.optString("id", "source_$i").trim()
                val ruleUrl = item.optString("url", "").trim()
                if (ruleUrl.isBlank()) continue
                sources.add(
                    RuleSource(
                        id = id.ifBlank { "source_$i" },
                        url = ruleUrl,
                        format = item.optString("format", "adblock"),
                        enabled = item.optBoolean("enabled", true),
                    ),
                )
            }
        }
        val legacyRuleUrl = o.optString("rules_url", "").trim()
        if (sources.isEmpty() && legacyRuleUrl.isNotBlank()) {
            sources.add(RuleSource("ads", legacyRuleUrl, "adblock", true))
        }
        if (sources.map { it.id }.distinct().size != sources.size) {
            throw RuntimeException("rule_sources 中存在重复 id")
        }

        val next = App.container.config.saveProfile(profileName) { current ->
            current.copy(
                mode = o.optString("mode", current.mode),
                remoteConfigUrl = url,
                remoteConfigName = o.optString("name", current.remoteConfigName),
                remoteConfigUpdatedAt = System.currentTimeMillis(),
                remoteConfigInterval = (o.optLong("update_interval", 21600L) * 1000L).coerceIn(300_000L, 7L * 24 * 3600_000L),
                dnsUpstream = dns?.optString("upstream", current.dnsUpstream) ?: current.dnsUpstream,
                dnsFallback = explicitFallback ?: current.dnsFallback,
                dnsBootstrap = dns?.optString("bootstrap", current.dnsBootstrap) ?: current.dnsBootstrap,
                dnsHeaderName = headerName,
                dnsHeaderValue = headerValue,
                dnsCacheTtl = (dns?.optInt("cache_ttl", current.dnsCacheTtl) ?: current.dnsCacheTtl).coerceIn(30, 86400),
                dnsQueryLog = dns?.optBoolean("query_log", current.dnsQueryLog) ?: current.dnsQueryLog,
                dnsPolicies = dns?.optJSONArray("policies")?.let { arr ->
                    (0 until arr.length()).mapNotNull { i ->
                        val o = arr.optJSONObject(i) ?: return@mapNotNull null
                        val p = o.optString("pattern").trim()
                        val sv = o.optString("servers").trim()
                        if (p.isBlank() || sv.isBlank()) null else com.namu.dns.core.config.DnsPolicyRule(p, sv)
                    }
                } ?: current.dnsPolicies,
                dnsHijack = if (dns?.has("hijack") == true) dns.optBoolean("hijack") else current.dnsHijack,
                allowDnsFallback = when {
                    dns?.has("fail_closed") == true -> !dns.optBoolean("fail_closed")
                    explicitFallback != null -> explicitFallback.isNotBlank()
                    else -> current.allowDnsFallback
                },
                cnDirect = routing?.optBoolean("cn_direct", current.cnDirect) ?: current.cnDirect,
                finalPolicy = routing?.optString("final_policy", current.finalPolicy) ?: current.finalPolicy,
                ruleSources = if (sources.isEmpty()) current.ruleSources else sources,
            )
        } ?: throw RuntimeException("远端配置保存失败")
        next to next.ruleSources
    }

    /** 拉取远端 manifest，应用 DNS/模式/规则源，然后同步规则文件。 */
    suspend fun importRemoteConfig(
        url: String,
        profileName: String = App.container.config.activeName(),
    ): RemoteConfigResult = withContext(Dispatchers.IO) {
        val profile = withContext(Dispatchers.Main) { App.container.config.loadProfile(profileName) }
            ?: throw RuntimeException("配置无法读取")
        val raw = fetchText(
            url,
            maxBytes = 2 * 1024 * 1024,
            headers = headerMapFor(profile, url),
        )
        val o = try {
            JSONObject(raw)
        } catch (e: Exception) {
            throw RuntimeException("配置不是有效 JSON：${e.message}")
        }
        val currentUrl = withContext(Dispatchers.Main) { App.container.config.loadProfile(profileName)?.remoteConfigUrl }
        if (currentUrl == null || (currentUrl != profile.remoteConfigUrl && currentUrl != url.trim())) {
            throw RuntimeException("远端配置地址已改变")
        }
        val (cfg, sources) = applyRemoteConfig(o, url.trim(), profileName)
        val sync = if (sources.any { it.enabled }) syncRuleSources(sources, profileName)
            else RuleSyncResult(0, 0, emptyList())
        RemoteConfigResult(
            name = cfg.remoteConfigName.ifBlank { "远端配置" },
            sources = sources.size,
            lines = sync.lines,
            errors = sync.errors,
        )
    }

    suspend fun updateAdsRules(
        url: String,
        profileName: String = App.container.config.activeName(),
    ): Int = withContext(Dispatchers.IO) {
        val text = fetchText(url, maxBytes = 8 * 1024 * 1024, headers = headerMapFor(settings.current(), url))
        validateRules(text)
        val file = ConfigStore.globalRuleSetFile(App.context, url)
        ConfigStore.writeAtomicPublic(file, text)
        check(file.readText() == text) { "规则缓存写入失败" }
        withContext(Dispatchers.Main) {
            GlobalRuleStore.update(App.context) { st ->
                val exist = st.ruleSets.firstOrNull { it.url == url }
                val src = (exist ?: RuleSource(id = "legacy-ads-url", url = url)).copy(
                    updatedAt = System.currentTimeMillis(),
                    lines = text.lines().size,
                    error = "",
                    stale = false,
                    cacheBytes = file.length(),
                    format = detectRuleSourceFormat(text, exist?.format ?: "adblock"),
                )
                st.copy(ruleSets = st.ruleSets.filterNot { it.url == url } + src)
            }
            ConfigStore.rebuildModules(App.context, settings.current())
        }
        text.lines().size
    }

    /** 启动时按需拉取广告规则；成功后返回 true。 */
    suspend fun autoUpdateRulesIfDue(): Boolean = withContext(Dispatchers.IO) {
        val (profileName, cfg) = withContext(Dispatchers.Main) {
            App.container.config.activeName() to settings.current()
        }
        if (!cfg.autoUpdateRules) return@withContext false
        if (cfg.remoteConfigUrl.isNotBlank()) {
            val age = System.currentTimeMillis() - cfg.remoteConfigUpdatedAt
            if (cfg.remoteConfigUpdatedAt > 0 && age < cfg.remoteConfigInterval) return@withContext false
            return@withContext try {
                importRemoteConfig(cfg.remoteConfigUrl, profileName)
                true
            } catch (_: Exception) {
                false
            }
        }
        val globalSets = GlobalRuleStore.state.ruleSets
        if (globalSets.isNotEmpty()) {
            val now = System.currentTimeMillis()
            val due = globalSets.filter { it.enabled && now - it.lastAttemptAt >= 12L * 60 * 60 * 1000 }
            if (due.isEmpty()) return@withContext false
            return@withContext try {
                syncRuleSources(due, profileName).updated > 0
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                false
            }
        }
        false
    }

    suspend fun updateCnIp(url: String): Int = withContext(Dispatchers.IO) {
        val text = fetchText(url, maxBytes = 16 * 1024 * 1024)
        if (text.isBlank()) throw RuntimeException("IP 库内容为空")
        val file = File(App.context.filesDir, "cnip.txt")
        val tmp = File(App.context.filesDir, "cnip.txt.tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(file)) {
            tmp.copyTo(file, overwrite = true)
            tmp.delete()
        }
        text.lines().size
    }

    suspend fun ping(host: String, port: Int, method: String = "tcp"): Long? = withContext(Dispatchers.IO) {
        if (method == "tls") pingTls(host, port) else pingTcp(host, port)
    }

    private fun pingTcp(host: String, port: Int): Long? {
        val start = System.currentTimeMillis()
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 3000)
            }
            System.currentTimeMillis() - start
        } catch (_: Exception) {
            null
        }
    }

    /** TLS 握手测速：适合 TLS 节点，能覆盖 TCP 端口通但证书握手被墙的情况。 */
    private fun pingTls(host: String, port: Int): Long? {
        val start = System.currentTimeMillis()
        return try {
            val raw = SSLSocketFactory.getDefault().createSocket()
            raw.connect(InetSocketAddress(host, port), 3000)
            raw.soTimeout = 3000
            (raw as SSLSocket).use { socket -> socket.startHandshake() }
            System.currentTimeMillis() - start
        } catch (_: Exception) {
            null
        }
    }

    /** 并发测速（最多 6 个），按需自动选择延迟最低的节点。 */
    suspend fun autoTestNodes(): Int = withContext(Dispatchers.IO) {
        val snapshot = settings.current()
        if (snapshot.nodes.isEmpty()) return@withContext 0
        val semaphore = Semaphore(6)
        val results = coroutineScope {
            snapshot.nodes.map { node ->
                async {
                    semaphore.withPermit {
                        node.name to ping(node.server, node.port, snapshot.pingMethod)
                    }
                }
            }.awaitAll()
        }
        val best = results
            .filter { it.second != null }
            .minByOrNull { it.second!! }
        withContext(Dispatchers.Main) {
            val current = settings.current()
            val bestName = best?.first
            val nextSelected = if (current.autoSelectNode && bestName != null && current.nodes.any { it.name == bestName }) {
                bestName
            } else {
                current.selected
            }
            val changed = nextSelected != current.selected
            settings.update { latest ->
                latest.copy(
                    nodes = latest.nodes.map { node ->
                        val ms = results.firstOrNull { it.first == node.name }?.second
                        if (ms != null) node.copy(latency = ms) else node
                    },
                    selected = nextSelected,
                )
            }
            if (changed && runtime.current().connected) ApplyCoordinator.requestApply(App.context, "配置变更")
        }
        results.count { it.second != null }
    }

    /** MITM 总开关（设备级）：写全局 → 重建合并 → 运行中热重载。 */
    suspend fun setMitmEnabled(enabled: Boolean) = updateScope { it.copy(enabled = enabled) }

    /** 手动 MITM 域名（支持 *.example.com 通配）。 */
    suspend fun setMitmHostnames(hostnames: List<String>) = updateScope { it.copy(hostnames = hostnames) }

    /** 永不 MITM 的跳过域名（银行/支付等）。 */
    suspend fun setMitmSkip(hostnames: List<String>) = updateScope { it.copy(skipHostnames = hostnames) }

    /** 灰度：MITM 上游连接池；默认关闭，只影响新连接。 */
    suspend fun setMitmPoolEnabled(on: Boolean) =
        updateScope { it.copy(poolEnabled = on, poolIdleSecs = it.poolIdleSecs) }

    /**
     * 按 App MITM：mode = all / allow / deny，apps 是包名列表。
     * 写配置后重建模块并热重载；包名到 UID 的展开在下发内核时完成。
     */
    suspend fun setMitmApps(mode: String, apps: List<String>) =
        updateScope { it.copy(appMode = mode, apps = apps) }

    /**
     * 脚本参数当前值：写配置后只把新值推给运行中的内核，不重建 MITM/不重编译脚本。
     * 下一次启动会通过 buildNative 下发同一份覆盖值。
     */
    suspend fun setMitmScriptArguments(script: com.namu.dns.core.config.ScriptConfig, values: Map<String, String>) =
        withContext(Dispatchers.IO) {
            val key = ConfigStore.scriptArgumentKey(script)
            GlobalRuleStore.update(App.context) { st ->
                st.copy(scriptArguments = st.scriptArguments + (key to values))
            }
            val next = settings.current()
            if (runtime.current().connected) {
                val payload = JSONObject().apply {
                    put("key", key)
                    put("values", JSONObject(values as Map<*, *>))
                }
                NativeCore.nativeSetScriptArguments(payload.toString())
            }
            next
        }

    private suspend fun updateScope(transform: (GlobalRuleStore.MitmScope) -> GlobalRuleStore.MitmScope) =
        withContext(Dispatchers.IO) {
            GlobalRuleStore.update(App.context) { st -> st.copy(scope = transform(st.scope)) }
            ConfigStore.rebuildModules(App.context, settings.current())
            if (runtime.current().connected) ApplyCoordinator.requestApply(App.context, "配置变更")
        }

    // ---------- 3.0.18 全局规则/模块操作 ----------

    private suspend fun applyGlobal(transform: (GlobalRuleStore.State) -> GlobalRuleStore.State) =
        withContext(Dispatchers.Main) {
            GlobalRuleStore.update(App.context, transform)
            ConfigStore.rebuildModules(App.context, settings.current())
            if (runtime.current().connected) ApplyCoordinator.requestApply(App.context, "配置变更")
        }

    /** 3.0.18：独立导入规则集 → 一条全局模块记录（DNS 过滤）。 */
    suspend fun importRuleSet(url: String, displayName: String = ""): Int = withContext(Dispatchers.IO) {
        val target = url.trim()
        if (target.isBlank()) throw RuntimeException("规则集来源为空")
        val text = fetchText(target, maxBytes = 8 * 1024 * 1024, headers = headerMapFor(settings.current(), target))
        validateRules(text)
        val file = ConfigStore.globalRuleSetFile(App.context, target)
        ConfigStore.writeAtomicPublic(file, text)
        check(file.readText() == text) { "规则缓存写入失败" }
        withContext(Dispatchers.Main) {
            GlobalRuleStore.update(App.context) { st ->
                val exist = st.ruleSets.firstOrNull { it.url == target }
                val src = (exist ?: RuleSource(id = moduleId(target), url = target)).copy(
                    updatedAt = System.currentTimeMillis(),
                    lines = text.lines().size,
                    error = "",
                    stale = false,
                    cacheBytes = file.length(),
                    format = detectRuleSourceFormat(text, exist?.format ?: "adblock"),
                )
                st.copy(ruleSets = st.ruleSets.filterNot { it.url == target } + src)
            }
            ConfigStore.rebuildModules(App.context, settings.current())
        }
        text.lines().size
    }

    suspend fun setRuleSetEnabled(id: String, on: Boolean) =
        applyGlobal { st -> st.copy(ruleSets = st.ruleSets.map { if (it.id == id) it.copy(enabled = on) else it }) }
    suspend fun setLocalRulesEnabled(on: Boolean) = applyGlobal { it.copy(localRulesEnabled = on) }
    suspend fun setLocalMitmEnabled(on: Boolean) = applyGlobal { it.copy(localMitmEnabled = on) }
    suspend fun setExtraMitmEnabled(id: String, on: Boolean) =
        applyGlobal { st -> st.copy(extraMitm = st.extraMitm.map { if (it.id == id) it.copy(enabled = on) else it }) }
    suspend fun updateLocalRules(transform: (List<RuleItem>) -> List<RuleItem>) =
        applyGlobal { it.copy(localRules = transform(it.localRules)) }
    suspend fun updateLocalAds(transform: (List<String>) -> List<String>) =
        applyGlobal { it.copy(localAds = transform(it.localAds)) }
    suspend fun updateLocalMitm(transform: (GlobalRuleStore.MitmContent) -> GlobalRuleStore.MitmContent) =
        applyGlobal { it.copy(localMitm = transform(it.localMitm)) }
    suspend fun updateExtraMitm(id: String, transform: (GlobalRuleStore.MitmContent) -> GlobalRuleStore.MitmContent) =
        applyGlobal { st -> st.copy(extraMitm = st.extraMitm.map { if (it.id == id) it.copy(content = transform(it.content)) else it }) }
    suspend fun deleteRuleSet(id: String) = applyGlobal { it.copy(ruleSets = it.ruleSets.filterNot { s -> s.id == id }) }
    suspend fun deleteExtraMitm(id: String) = applyGlobal { it.copy(extraMitm = it.extraMitm.filterNot { e -> e.id == id }) }
    suspend fun setModuleDnsApproved(id: String, approved: Boolean) =
        applyGlobal { st -> st.copy(modules = st.modules.map { if (it.id == id) it.copy(dnsApproved = approved) else it }) }

    /** 长按拖拽：模块/规则集/来源重写统一排序；本地伪模块置顶不参与。 */
    suspend fun reorderEntry(id: String, to: Int) = withContext(Dispatchers.Main) {
        val rest = GlobalRuleStore.displayEntries()
            .filter { it.id != GlobalRuleStore.ID_LOCAL_RULES && it.id != GlobalRuleStore.ID_LOCAL_MITM }
        val from = rest.indexOfFirst { it.id == id }
        if (from < 0 || rest.isEmpty()) return@withContext
        val ids = rest.map { it.id }.toMutableList()
        val item = ids.removeAt(from.coerceIn(0, ids.lastIndex))
        ids.add(to.coerceIn(0, ids.size), item)
        val orderOf = ids.withIndex().associate { (i, k) -> k to i }
        GlobalRuleStore.update(App.context) { st ->
            st.copy(
                modules = st.modules.map { m -> orderOf[m.id]?.let { m.copy(order = it) } ?: m },
                ruleSets = st.ruleSets.map { r -> orderOf[GlobalRuleStore.ID_RULESET_PREFIX + r.id]?.let { r.copy(order = it) } ?: r },
                extraMitm = st.extraMitm.map { e -> orderOf[e.id]?.let { e.copy(order = it) } ?: e },
            )
        }
        ConfigStore.rebuildModules(App.context, settings.current())
        if (runtime.current().connected) ApplyCoordinator.requestApply(App.context, "配置变更")
    }
}
