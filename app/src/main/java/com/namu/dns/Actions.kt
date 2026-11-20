package com.namu.dns

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import com.namu.dns.core.config.MitmConfig
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
    suspend fun exportText(context: android.content.Context, fileName: String, content: String): String =
        withContext(Dispatchers.IO) {
            if (android.os.Build.VERSION.SDK_INT >= 29) {
                val values = android.content.ContentValues().apply {
                    put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                    put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, "Download/NamuDNS")
                }
                val resolver = context.contentResolver
                val uri = resolver.insert(
                    android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    values,
                ) ?: throw RuntimeException("无法创建导出文件")
                resolver.openOutputStream(uri)?.use { it.write(content.toByteArray()) }
                    ?: throw RuntimeException("写入导出文件失败")
                "下载/NamuDNS/$fileName"
            } else {
                val dir = File(context.getExternalFilesDir(null), "logs").apply { mkdirs() }
                val f = File(dir, fileName).also { it.writeText(content) }
                f.absolutePath
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
                if (code == 304) {
                    val responseHeaders = conn.headerFields
                        .filterKeys { it != null }
                        .mapKeys { (key, _) -> key.lowercase() }
                        .mapValues { (_, values) -> values.firstOrNull().orEmpty() }
                    return@withContext FetchResult("", responseHeaders, 304)
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
                val name = g.optString("name", "").trim()
                val members = mutableListOf<String>()
                g.optJSONArray("members")?.let { ms ->
                    for (j in 0 until ms.length()) {
                        ms.optString(j, "").trim().takeIf { it.isNotBlank() }?.let { members.add(it) }
                    }
                }
                if (name.isBlank() || members.isEmpty()) continue
                groups.add(
                    ProxyGroup(
                        name = name,
                        type = g.optString("type", "select").lowercase().let {
                            when (it) {
                                "url-test", "urltest", "fallback" -> it.replace("urltest", "url-test")
                                else -> "select"
                            }
                        },
                        members = members,
                        testUrl = g.optString("test_url", "http://www.gstatic.com/generate_204"),
                        interval = g.optInt("interval", 600),
                        timeout = g.optInt("timeout", 5000),
                        tolerance = g.optInt("tolerance", 50),
                        failureThreshold = g.optInt("failure_threshold", 3),
                        recoveryThreshold = g.optInt("recovery_threshold", 2),
                        noNodeAction = g.optString("no_node_action", "global"),
                    )
                )
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
    suspend fun refreshSubscription(): Boolean = withContext(Dispatchers.IO) {
        val url = settings.current().subscription.trim()
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw RuntimeException("当前配置没有订阅链接")
        }
        importSubscription(url, append = true)
        true
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
        sources: List<RuleSource> = settings.current().ruleSources,
    ): RuleSyncResult = withContext(Dispatchers.IO) {
        var updated = 0
        var totalLines = 0
        val errors = mutableListOf<String>()
        val results = mutableMapOf<String, RuleSource>()
        sources.filter { it.enabled }.forEach { src ->
            val file = ConfigStore.ruleSourceFile(App.context, src.id)
            val now = System.currentTimeMillis()
            try {
                val conditional = buildMap {
                    if (src.etag.isNotBlank()) put("If-None-Match", src.etag)
                    if (src.lastModified.isNotBlank()) put("If-Modified-Since", src.lastModified)
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
                val tmp = File(file.parentFile, file.name + ".tmp")
                val backup = File(file.parentFile, file.name + ".bak")
                tmp.writeText(text)
                if (file.exists()) file.copyTo(backup, overwrite = true)
                if (!tmp.renameTo(file)) {
                    tmp.copyTo(file, overwrite = true)
                    tmp.delete()
                }
                val lines = text.lines().count()
                results[src.id] = src.copy(
                    updatedAt = now,
                    lastAttemptAt = now,
                    lines = lines,
                    error = "",
                    stale = false,
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
            val current = settings.current()
            val next = current.ruleSources.map { results[it.id] ?: it }
            settings.set(current.copy(ruleSources = next))
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
        parsed.blockLines.isNotEmpty() || parsed.routeRules.isNotEmpty() ||
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
        if (!target.startsWith("http://") && !target.startsWith("https://")) {
            throw RuntimeException("模块地址必须是 http/https URL")
        }
        val text = fetchText(
            target,
            maxBytes = 4 * 1024 * 1024,
            headers = headerMapFor(settings.current(), target),
        )
        if (text.any { it.code < 0x09 || (it.code in 0x0E..0x1F) }) {
            throw RuntimeException("模块包含异常控制字符")
        }
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
    )

    /** 导入前预览：只下载和解析，不落盘；同时统计与现有模块重复的规则条数。 */
    suspend fun previewModule(url: String, displayName: String = ""): ModulePreview = withContext(Dispatchers.IO) {
        val target = url.trim()
        if (!target.startsWith("http://") && !target.startsWith("https://")) {
            throw RuntimeException("模块地址必须是 http/https URL")
        }
        val text = fetchText(target, maxBytes = 4 * 1024 * 1024, headers = headerMapFor(settings.current(), target))
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
        if (text.toByteArray().size > 4 * 1024 * 1024) throw RuntimeException("模块超过 4MB")
        if (text.any { it.code < 0x09 || (it.code in 0x0E..0x1F) }) {
            throw RuntimeException("模块包含异常控制字符")
        }
        val parsed = hydrateScripts(ModuleParser.parse(text), refresh = false)
        if (!hasUsableRules(parsed)) {
            throw RuntimeException("模块里没有可用的 DNS/分流或 MITM/重写规则")
        }
        val existingBlocks = HashSet<String>()
        val existingRoutes = HashSet<String>()
        settings.current().moduleSources.filter { it.url != target }.forEach { src ->
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
        )
    }

    /** 预览确认后直接落盘导入，不再重复下载。 */
    suspend fun importPreview(preview: ModulePreview): ModuleResult {
        saveParsedModule(preview.url, preview.name, preview.text, preview.parsed)
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
    ): ModuleResult {
        val existing = settings.current().moduleSources.firstOrNull { it.url == target }
        val id = existing?.id ?: moduleId(target)
        saveModuleFile(id, text)
        val source = ModuleSource(
            id = id,
            name = displayName.trim().ifBlank { parsed.name.ifBlank { target.removePrefix("local://").substringAfter("://").substringBefore('/').ifBlank { "模块" } } },
            url = target,
            app = parsed.app,
            enabled = existing?.enabled ?: true,
            updatedAt = System.currentTimeMillis(),
            blockRules = parsed.blockLines.size,
            routeRules = parsed.routeRules.size,
            mitmRules = mitmRuleCount(parsed),
            allowRules = parsed.allowLines.size,
            ignored = parsed.ignored,
            error = "",

        )
        withContext(Dispatchers.Main) {
            val current = settings.current()
            val next = current.copy(
                moduleSources = current.moduleSources.filterNot { it.url == target } + source,
            )
            settings.set(next)
            ConfigStore.rebuildModules(App.context, next)
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

    /** 重新拉取所有启用模块；单个失败保留上一份文件。 */
    suspend fun syncModules(): ModuleSyncResult = withContext(Dispatchers.IO) {
        var updated = 0
        val errors = mutableListOf<String>()
        val results = mutableMapOf<String, ModuleSource>()
        settings.current().moduleSources.filter { it.enabled && it.url.startsWith("http") }.forEach { src ->
            try {
                val text = fetchText(
                    src.url,
                    maxBytes = 4 * 1024 * 1024,
                    headers = headerMapFor(settings.current(), src.url),
                )
                val parsed = hydrateScripts(ModuleParser.parse(text), refresh = true)
                if (!hasUsableRules(parsed)) {
                    throw RuntimeException("没有可用的 DNS/分流或 MITM/重写规则")
                }
                saveModuleFile(src.id, text)
                results[src.id] = src.copy(
                    name = src.name.ifBlank { parsed.name },
                    app = parsed.app.ifBlank { src.app },
                    updatedAt = System.currentTimeMillis(),
                    blockRules = parsed.blockLines.size,
                    routeRules = parsed.routeRules.size,
                    mitmRules = mitmRuleCount(parsed),
                    allowRules = parsed.allowLines.size,
                    ignored = parsed.ignored,
                    error = "",
                )
                updated++
            } catch (e: Exception) {
                val msg = "${src.name}: ${e.message ?: "下载失败"}"
                errors.add(msg)
                results[src.id] = src.copy(error = e.message ?: "下载失败")
            }
        }
        withContext(Dispatchers.Main) {
            val current = settings.current()
            val next = current.copy(
                moduleSources = current.moduleSources.map { results[it.id] ?: it },
            )
            settings.set(next)
            ConfigStore.rebuildModules(App.context, next)
        }
        if (updated > 0 && runtime.current().connected) {
            withContext(Dispatchers.Main) { NamuVpnService.reload(App.context) }
        }
        ModuleSyncResult(updated, errors)
    }

    suspend fun setModuleEnabled(id: String, enabled: Boolean) = withContext(Dispatchers.Main) {
        val current = settings.current()
        val next = current.copy(
            moduleSources = current.moduleSources.map { if (it.id == id) it.copy(enabled = enabled) else it },
        )
        settings.set(next)
        ConfigStore.rebuildModules(App.context, next)
        if (runtime.current().connected) NamuVpnService.reload(App.context)
    }

    suspend fun deleteModule(id: String) = withContext(Dispatchers.Main) {
        val current = settings.current()
        val next = current.copy(moduleSources = current.moduleSources.filterNot { it.id == id })
        settings.set(next)
        ConfigStore.rebuildModules(App.context, next)
        runCatching { ConfigStore.moduleFile(App.context, id).delete() }
        if (runtime.current().connected) NamuVpnService.reload(App.context)
    }

    private suspend fun applyRemoteConfig(o: JSONObject, url: String): Pair<AppConfig, List<RuleSource>> {
        val version = o.optInt("version", 1)
        if (version !in 1..2) throw RuntimeException("不支持的配置版本：$version")
        val dns = o.optJSONObject("dns")
        val routing = o.optJSONObject("routing")
        val failClosed = dns?.optBoolean("fail_closed", false) ?: false
        val fallback = dns?.optString("fallback", "223.5.5.5")?.trim().orEmpty()
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

        val current = settings.current()
        val next = current.copy(
            mode = o.optString("mode", current.mode),
            remoteConfigUrl = url,
            remoteConfigName = o.optString("name", current.remoteConfigName),
            remoteConfigUpdatedAt = System.currentTimeMillis(),
            remoteConfigInterval = (o.optLong("update_interval", 21600L) * 1000L).coerceIn(300_000L, 7L * 24 * 3600_000L),
            dnsUpstream = dns?.optString("upstream", current.dnsUpstream) ?: current.dnsUpstream,
            dnsFallback = fallback.ifBlank { current.dnsFallback },
            dnsBootstrap = dns?.optString("bootstrap", current.dnsBootstrap) ?: current.dnsBootstrap,
            dnsHeaderName = headerName,
            dnsHeaderValue = headerValue,
            dnsCacheTtl = (dns?.optInt("cache_ttl", current.dnsCacheTtl) ?: current.dnsCacheTtl).coerceIn(30, 86400),
            dnsQueryLog = dns?.optBoolean("query_log", current.dnsQueryLog) ?: current.dnsQueryLog,
            allowDnsFallback = !failClosed && fallback.isNotBlank(),
            cnDirect = routing?.optBoolean("cn_direct", current.cnDirect) ?: current.cnDirect,
            finalPolicy = routing?.optString("final_policy", current.finalPolicy) ?: current.finalPolicy,
            ruleSources = if (sources.isEmpty()) current.ruleSources else sources,
        )
        withContext(Dispatchers.Main) {
            settings.set(next)
        }
        return next to next.ruleSources
    }

    /** 拉取远端 manifest，应用 DNS/模式/规则源，然后同步规则文件。 */
    suspend fun importRemoteConfig(url: String): RemoteConfigResult = withContext(Dispatchers.IO) {
        val raw = fetchText(
            url,
            maxBytes = 2 * 1024 * 1024,
            headers = headerMapFor(settings.current(), url),
        )
        val o = try {
            JSONObject(raw)
        } catch (e: Exception) {
            throw RuntimeException("配置不是有效 JSON：${e.message}")
        }
        val (cfg, sources) = applyRemoteConfig(o, url.trim())
        val sync = syncRuleSources(sources)
        if (runtime.current().connected) {
            withContext(Dispatchers.Main) { NamuVpnService.reload(App.context) }
        }
        RemoteConfigResult(
            name = cfg.remoteConfigName.ifBlank { "远端配置" },
            sources = sources.size,
            lines = sync.lines,
            errors = sync.errors,
        )
    }

    suspend fun updateAdsRules(url: String): Int = withContext(Dispatchers.IO) {
        val text = fetchText(url, maxBytes = 8 * 1024 * 1024, headers = headerMapFor(settings.current(), url))
        validateRules(text)
        val file = ConfigStore.rulesFile(App.context)
        val tmp = File(file.parentFile, "ads_url.txt.tmp")
        val backup = File(file.parentFile, "ads_url.txt.bak")
        tmp.writeText(text)
        if (file.exists()) file.copyTo(backup, overwrite = true)
        if (!tmp.renameTo(file)) {
            tmp.copyTo(file, overwrite = true)
            tmp.delete()
        }
        val now = System.currentTimeMillis()
        withContext(Dispatchers.Main) {
            settings.update { it.copy(rulesUpdatedAt = now) }
        }
        text.lines().size
    }

    /** 启动时按需拉取广告规则；成功后返回 true。 */
    suspend fun autoUpdateRulesIfDue(): Boolean = withContext(Dispatchers.IO) {
        val cfg = settings.current()
        if (!cfg.autoUpdateRules) return@withContext false
        if (cfg.remoteConfigUrl.isNotBlank()) {
            val age = System.currentTimeMillis() - cfg.remoteConfigUpdatedAt
            if (cfg.remoteConfigUpdatedAt > 0 && age < cfg.remoteConfigInterval) return@withContext false
            return@withContext try {
                importRemoteConfig(cfg.remoteConfigUrl)
                true
            } catch (_: Exception) {
                false
            }
        }
        if (cfg.rulesUrl.isBlank()) return@withContext false
        val file = ConfigStore.rulesFile(App.context)
        val fresh = file.exists() && file.length() > 0 &&
            System.currentTimeMillis() - cfg.rulesUpdatedAt < 12L * 60 * 60 * 1000
        if (fresh) return@withContext false
        try {
            updateAdsRules(cfg.rulesUrl)
            withContext(Dispatchers.Main) {
                if (runtime.current().connected) NamuVpnService.reload(App.context)
            }
            true
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                messages.show("规则源同步失败：${e.message ?: "网络错误"}")
            }
            false
        }
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
            if (changed && runtime.current().connected) NamuVpnService.reload(App.context)
        }
        results.count { it.second != null }
    }

    /** MITM 总开关：写配置 → 重建模块 MITM 合并 → 运行中热重载。 */
    suspend fun setMitmEnabled(enabled: Boolean) = updateMitm { it.copy(enabled = enabled) }

    /** 手动 MITM 域名（支持 *.example.com 通配）。 */
    suspend fun setMitmHostnames(hostnames: List<String>) = updateMitm { it.copy(hostnames = hostnames) }

    /** 永不 MITM 的跳过域名（银行/支付等）。 */
    suspend fun setMitmSkip(hostnames: List<String>) = updateMitm { it.copy(skipHostnames = hostnames) }

    private suspend fun updateMitm(transform: (MitmConfig) -> MitmConfig) = withContext(Dispatchers.IO) {
        val next = settings.update { cfg -> cfg.copy(mitm = transform(cfg.mitm)) }
        ConfigStore.rebuildModules(App.context, next)
        if (runtime.current().connected) NamuVpnService.reload(App.context)
    }
}
