package com.namu.dns

import android.content.Context
import android.os.Build
import com.namu.dns.core.config.ScriptConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

object ConfigStore {
    /** 配置文件落盘统一走单线程队列：不阻塞主线程，且保证写入顺序。 */
    private val fileIo = java.util.concurrent.Executors.newSingleThreadExecutor()

    fun submitFileIo(task: () -> Unit) {
        fileIo.execute { runCatching { task() } }
    }

    fun baseConfigFile(context: Context): File = File(context.filesDir, "default.json")

    fun ensureAssets(context: Context, settings: com.namu.dns.core.repository.SettingsRepository) {
        val stamp = settings.assetStamp()
        val dir = context.filesDir
        if (!baseConfigFile(context).exists()) {
            // 首次安装时拷贝内置的基础配置；失败则回退到当前内存配置。
            try {
                context.assets.open("default.json").use { input ->
                    baseConfigFile(context).outputStream().use { output -> input.copyTo(output) }
                }
            } catch (_: Exception) {
                try { baseConfigFile(context).writeText(settings.current().toJson().toString(2)) } catch (_: Exception) {}
            }
        }
        // 1.7 的默认规则带有 github/google -> proxy；没有节点时这两条会被无节点策略阻断。
        // 只迁移一次，之后用户手动添加的同名规则不会被反复删除。
        if (!settings.defaultRulesMigrated()) {
            val cfg = settings.current()
            val legacy = setOf(
                RuleItem("DOMAIN-SUFFIX", "github.com", "proxy"),
                RuleItem("DOMAIN-SUFFIX", "google.com", "proxy"),
            )
            if (cfg.nodes.isEmpty() && cfg.rules.any { it in legacy }) {
                settings.update { it.copy(rules = it.rules.filterNot { rule -> rule in legacy }) }
            }
            settings.markDefaultRulesMigrated()
        }
        // 不再内置广告规则：删除旧版本内置的 ads.txt，仅保留用户从 URL 下载的规则
        val bundledAds = File(dir, "ads.txt")
        if (bundledAds.exists()) bundledAds.delete()
        val downloaded = File(dir, "ads_url.txt")
        val legacyCustom = File(dir, "ads_custom.txt")
        // 旧版 ads_custom.txt 只迁移一次。否则用户删掉最后一条本地域名后，
        // 下次启动仍会从旧文件把它“复活”。
        if (!settings.legacyAdsMigrated()) {
            if (legacyCustom.exists() && legacyCustom.length() > 0) {
                val cfg = settings.current()
                if (cfg.customAds.isEmpty()) {
                    val domains = legacyCustom.readLines()
                        .mapNotNull { normalizeAdsDomain(it) }
                        .distinct()
                    if (domains.isNotEmpty()) settings.update { it.copy(customAds = domains) }
                }
            }
            settings.markLegacyAdsMigrated()
        }
        // 下载中断或文件损坏时回滚到上一份可用规则
        if (!downloaded.exists() || downloaded.length() == 0L) {
            val backup = File(dir, "ads_url.txt.bak")
            if (backup.exists() && backup.length() > 0) {
                try { backup.copyTo(downloaded, overwrite = true) } catch (_: Exception) {}
            }
        }
        File(dir, "ads_url.txt.tmp").delete()
        File(dir, "modules").mkdirs()
        // 多规则源同样在下载中断时保留上一份可用文件
        val cfg = settings.current()
        // 模块文件变化后重建合并规则；启动时也保证聚合文件存在。
        if (cfg.moduleSources.isNotEmpty()) rebuildModules(context, cfg)
        cfg.ruleSources.forEach { src ->
            val target = ruleSourceFile(context, src.id)
            val backup = File(target.parentFile, target.name + ".bak")
            if (!target.exists() || target.length() == 0L) {
                if (backup.exists() && backup.length() > 0) {
                    try { backup.copyTo(target, overwrite = true) } catch (_: Exception) {}
                }
            }
            File(target.parentFile, target.name + ".tmp").delete()
        }
        val names = listOf("cn_domains.txt", "cnip.txt")
        val needCopy = stamp != BuildConfig.VERSION_CODE ||
            names.any { !File(dir, it).exists() }
        if (!needCopy) return
        names.forEach { name ->
            try {
                val target = File(dir, name)
                if (stamp != BuildConfig.VERSION_CODE || !target.exists()) {
                    context.assets.open(name).use { input ->
                        target.outputStream().use { output -> input.copyTo(output) }
                    }
                }
            } catch (_: Exception) {
            }
        }
        settings.setAssetStamp(BuildConfig.VERSION_CODE)
    }

    fun buildNative(context: Context, cfg: AppConfig): String {
        val dir = context.filesDir
        val ads = mutableListOf<File>()
        // 有远端 manifest 的多规则源时，以 manifest 为准；否则兼容旧的单 rulesUrl。
        if (cfg.ruleSources.isEmpty()) {
            val downloaded = File(dir, "ads_url.txt")
            if (downloaded.exists() && downloaded.length() > 0) ads.add(downloaded)
        } else {
            cfg.ruleSources.filter { it.enabled }.forEach { src ->
                val f = ruleSourceFile(context, src.id)
                if (f.exists() && f.length() > 0) ads.add(f)
            }
        }
        // 手动维护的本地广告域名，与服务器 URL 规则相互独立。
        val custom = File(dir, "ads_custom.txt")
        custom.writeText(
            cfg.customAds.mapNotNull { normalizeAdsDomain(it) }
                .distinct()
                .joinToString("\n") { "||$it^" },
        )
        if (custom.length() > 0) ads.add(custom)

        // 小火箭式模块：启用中的模块规则合并到本地过滤/分流。
        val moduleBlock = moduleBlockFile(context)
        if (cfg.moduleSources.any { it.enabled } && moduleBlock.exists() && moduleBlock.length() > 0) {
            ads.add(moduleBlock)
        }

        val root = JSONObject()
        // MITM/Host 分区：active 配置 + 启用模块合并。DNS 也要读同一份 Host 映射。
        val moduleMitm = if (cfg.moduleSources.any { it.enabled }) {
            runCatching { JSONObject(moduleMitmFile(context).readText()) }.getOrNull()
        } else null
        root.put("mode", cfg.mode)
        root.put("selected", cfg.selected ?: "")
        root.put("final_policy", cfg.finalPolicy)
        root.put("block_enabled", cfg.blockEnabled)
        root.put("block_mode", cfg.blockMode)
        root.put("cn_direct", cfg.cnDirect)
        root.put("block_when_no_node", cfg.blockWhenNoNode)
        root.put("fake_ip", cfg.fakeIp)
        // Fake-IP 映射落盘（内核 1.1.0：mihomo/sing-box cache_file 同款），重启后连接层仍能反查域名
        root.put("fake_ip_file", File(context.filesDir, "namu_fakeip.json").absolutePath)
        root.put("sniff", cfg.sniff)
        root.put("mtu", cfg.mtu.coerceIn(1280, 9000))
        root.put("bbr", cfg.bbr)
        root.put("block_dot", true)
        // 「system」表示手机当前底层网络的 DNS；下发前转成内核可用的 UDP 地址。
        val sysDns = SystemDns.selection(context)
        val effectiveUpstream = if (SystemDns.isFollow(cfg.dnsUpstream) || cfg.dnsUpstream.isBlank()) {
            sysDns.primaryUpstream ?: SystemDns.FAIL_CLOSED
        } else {
            cfg.dnsUpstream
        }
        val effectiveFallback = if (SystemDns.isFollow(cfg.dnsFallback) || cfg.dnsFallback.isBlank()) {
            sysDns.secondaryUpstream.orEmpty()
        } else {
            cfg.dnsFallback
        }
        root.put(
            "dns",
            JSONObject().apply {
                put("upstream", effectiveUpstream)
                put("fallback", if (cfg.allowDnsFallback) effectiveFallback else "")
                put("bootstrap", cfg.dnsBootstrap)
                put("headers", JSONObject().apply {
                    if (cfg.dnsHeaderName.isNotBlank() && cfg.dnsHeaderValue.isNotBlank()) {
                        put(cfg.dnsHeaderName.trim(), cfg.dnsHeaderValue)
                    }
                })
                // [Host] 是 DNS 配置态：当前配置优先，模块只补未占用的 key。
                put("hosts", JSONObject().apply {
                    val merged = LinkedHashMap<String, String>()
                    cfg.mitm.hostMappings.forEach { (k, v) ->
                        if (k.isNotBlank() && v.isNotBlank()) merged[k.trim().lowercase()] = v.trim()
                    }
                    moduleMitm?.optJSONObject("hostMappings")?.let { h ->
                        h.keys().forEach { k ->
                            val v = h.optString(k, "").trim()
                            val key = k.trim().lowercase()
                            if (key.isNotBlank() && v.isNotBlank() && !merged.containsKey(key)) merged[key] = v
                        }
                    }
                    merged.forEach { (k, v) -> put(k, v) }
                })
                put("cache_ttl", cfg.dnsCacheTtl)
                put("cache_size", 2048)
                put("block_ttl", cfg.blockTtl)
                put("negative_ttl", 30)
                put("fallback_filter", cfg.fallbackFilter)
                put("fallback_geo_check", cfg.fallbackGeoCheck)
                put("query_log", cfg.dnsQueryLog)
                put("block_aaaa", cfg.blockAaaa)
                // 缓存落盘（sing-box cache_file 同款）：重启后热域直接命中
                put("cache_file", File(context.filesDir, "namu_cache.json").absolutePath)
            },
        )
        root.put("nodes", JSONArray().apply { cfg.nodes.forEach { put(it.toJson()) } })
        val moduleRules = if (cfg.moduleSources.any { it.enabled }) {
            runCatching { JSONArray(moduleRulesFile(context).readText()) }.getOrNull()
        } else null
        root.put("proxy_groups", JSONArray().apply {
            cfg.proxyGroups.forEach { g ->
                put(JSONObject().apply {
                    put("name", g.name)
                    put("type", g.type)
                    put("members", JSONArray().apply { g.members.forEach { put(it) } })
                    put("test_url", g.testUrl)
                    put("interval", g.interval)
                    put("timeout", g.timeout)
                    put("tolerance", g.tolerance)
                    put("failure_threshold", g.failureThreshold)
                    put("recovery_threshold", g.recoveryThreshold)
                    put("no_node_action", g.noNodeAction)
                })
            }
        })
        root.put("group_selections", JSONObject().apply {
            cfg.groupSelections.forEach { (k, v) -> if (k.isNotBlank() && v.isNotBlank()) put(k, v) }
        })
        root.put("rules", JSONArray().apply {
            // 包名类规则在这里展开成 UID：内核只认数值 UID，包名映射属于壳层职责。
            // 未安装的包会解析不到 uid，此时跳过该条并记日志，避免下发一条永远不命中的规则。
            val (expanded, unresolved) = AppUidResolver.expand(context, cfg.rules.filter { it.enabled })
            if (unresolved.isNotEmpty()) {
                android.util.Log.w("NamuUid", "包名规则未解析（应用可能未安装）：$unresolved")
            }
            expanded.forEach { put(it.copy(source = it.source.ifBlank { "配置" }).toJson()) }
            if (moduleRules != null) {
                for (i in 0 until moduleRules.length()) put(moduleRules.get(i))
            }
        })
        // MITM 分区：active 配置 + 启用模块合并。内核 1.11 消费；
        // url_rewrites/header_rewrites 下发原始模块规则行，由内核统一解析成结构化规则。
        root.put("mitm", JSONObject().apply {
            val hosts = LinkedHashSet(cfg.mitm.hostnames)
            val skips = LinkedHashSet(cfg.mitm.skipHostnames)
            val urls = LinkedHashSet(cfg.mitm.urlRewrites)
            val headers = LinkedHashSet(cfg.mitm.headerRewrites)
            val loon = LinkedHashSet(cfg.mitm.loonRewrites)
            val body = LinkedHashSet(cfg.mitm.bodyRewrites)
            val wsRules = LinkedHashSet(cfg.mitm.wsRewrites)
            val scripts = LinkedHashMap<String, ScriptConfig>()
            cfg.mitm.scripts.forEach { scripts[scriptKey(it)] = it }
            moduleMitm?.let { m ->
                m.optJSONArray("hostnames")?.let { a -> for (i in 0 until a.length()) hosts.add(a.optString(i)) }
                m.optJSONArray("skipHostnames")?.let { a -> for (i in 0 until a.length()) skips.add(a.optString(i)) }
                m.optJSONArray("urlRewrites")?.let { a -> for (i in 0 until a.length()) urls.add(a.optString(i)) }
                m.optJSONArray("headerRewrites")?.let { a -> for (i in 0 until a.length()) headers.add(a.optString(i)) }
                m.optJSONArray("loonRewrites")?.let { a -> for (i in 0 until a.length()) loon.add(a.optString(i)) }
                m.optJSONArray("bodyRewrites")?.let { a -> for (i in 0 until a.length()) body.add(a.optString(i)) }
                m.optJSONArray("wsRewrites")?.let { a -> for (i in 0 until a.length()) wsRules.add(a.optString(i)) }
                m.optJSONArray("scripts")?.let { a ->
                    for (i in 0 until a.length()) {
                        a.optJSONObject(i)?.let { o ->
                            val sc = ScriptConfig.fromJsonObject(o)
                            scripts[scriptKey(sc)] = sc
                        }
                    }
                }
            }
            put("enabled", cfg.mitm.enabled)
            put("hostnames", JSONArray(hosts.toList()))
            put("skip_hostnames", JSONArray(skips.toList()))
            put("url_rewrites", JSONArray(urls.toList()))
            put("header_rewrites", JSONArray(headers.toList()))
            // Loon [Rewrite] 与 Surge [URL Rewrite] 分开下发，内核不把一种语法推导成另一种。
            put("loon_rewrites", JSONArray(loon.toList()))
            put("body_rewrites", JSONArray(body.toList()))
            put("websocket_rewrites", JSONArray(wsRules.toList()))
            // ScriptConfig.toJsonObject 使用 camelCase，Rust serde 已按 camelCase 对齐。
            // 参数当前值按脚本键覆盖模块默认值；只影响 $argument，不参与源码展开。
            put("scripts", JSONArray(scripts.values.map { sc ->
                cfg.mitm.scriptArguments[scriptArgumentKey(sc)]?.let { sc.copy(argumentValues = it) } ?: sc
            }.map { it.toJsonObject() }))
            put("script_store_file", File(File(dir, "scripts"), "store.json").absolutePath)
            // Map Local 相对 data-path 的基准目录；`$notification` 队列供服务轮询发系统通知。
            put("mock_base_dir", context.filesDir.absolutePath)
            put("notification_file", File(context.filesDir, "script_notifications.jsonl").absolutePath)
            put("environment", JSONObject().apply {
                put("app", "南门DNS")
                put("appVersion", BuildConfig.VERSION_NAME)
                put("buildVersion", BuildConfig.VERSION_CODE.toString())
                put("version", BuildConfig.VERSION_NAME)
                put("system", "Android")
                put("systemVersion", Build.VERSION.RELEASE)
                put("device", Build.MODEL)
                put("language", java.util.Locale.getDefault().language)
                put("timezone", java.util.TimeZone.getDefault().id)
                put("packageName", context.packageName)
            })
            // CA 必须与 MitmManager.caFile 保持一致；未导出前内核会自行生成。
            put("ca_file", File(File(dir, "mitm"), "ca.pem").absolutePath)
            put("body_limit", 2 * 1024 * 1024)
            put("fail_open_ttl", 300)
            put("upstream_insecure", false)
            // 按 App MITM：配置里保留包名（可读、换机可重解析），下发前才展开成 UID。
            val mitmUids = AppUidResolver.resolveUids(context, cfg.mitm.apps).first
            put("app_mode", cfg.mitm.appMode)
            put("app_uids", JSONArray(mitmUids))
            // 金融保护：支付/银行连接在 MITM 判定之前排除，默认开启。
            put("finance", FinanceProtect.toJson(context, cfg.financeProtect))
        })
        root.put(
            "ads_files",
            JSONArray().apply { ads.forEach { put(it.absolutePath) } },
        )
        root.put("cn_domains_file", File(dir, "cn_domains.txt").absolutePath)
        root.put("cn_ip_file", File(dir, "cnip.txt").absolutePath)
        return root.toString()
    }

    fun rulesFile(context: Context): File = File(context.filesDir, "ads_url.txt")

    fun ruleSourceFile(context: Context, id: String): File {
        val safe = id.lowercase().replace(Regex("[^a-z0-9_-]"), "_").take(40)
            .ifBlank { "source" }
        return File(context.filesDir, "rules_$safe.txt")
    }

    /** 规则集内容缓存：按 URL 哈希命名，拉取失败时保留旧内容继续展开。 */
    fun ruleSetFile(context: Context, url: String): File {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(url.toByteArray()).joinToString("") { "%02x".format(it) }.take(16)
        return File(context.filesDir, "ruleset_$digest.txt")
    }

    fun moduleFile(context: Context, id: String): File {
        val safe = id.lowercase().replace(Regex("[^a-z0-9_-]"), "_").take(40)
            .ifBlank { "module" }
        return File(File(context.filesDir, "modules"), "module_$safe.sgmodule")
    }

    fun moduleBlockFile(context: Context): File = File(context.filesDir, "modules_block.txt")

    fun moduleRulesFile(context: Context): File = File(context.filesDir, "modules_rules.json")

    fun moduleMitmFile(context: Context): File = File(context.filesDir, "modules_mitm.json")

    fun scriptCacheFile(context: Context, url: String): File {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(url.toByteArray())
            .joinToString("") { "%02x".format(it) }
        return File(File(context.filesDir, "scripts"), "script_${digest.take(32)}.js")
    }

    fun scriptKey(rule: ScriptConfig): String =
        "${rule.phase}|${rule.pattern}|${rule.name}|${rule.scriptPath}"

    /** 与 Rust CompiledScriptRule.key 对齐；脚本路径变化不影响参数覆盖。 */
    fun scriptArgumentKey(rule: ScriptConfig): String =
        "${rule.phase.trim().lowercase()}|${rule.pattern.trim()}|${rule.name}"

    /**
     * 把所有启用模块的规则重新合并成一份 DNS 阻断文件 + 一份分流规则 JSON。
     * 模块被关闭/删除时，旧聚合文件会被清空，不会继续生效。
     */
    fun rebuildModules(context: Context, cfg: AppConfig) {
        val blocks = LinkedHashSet<String>()
        val allows = LinkedHashSet<String>()
        val routes = mutableListOf<RuleItem>()
        val mitmHosts = LinkedHashSet<String>()
        val mitmSkips = LinkedHashSet<String>()
        val generalOptions = LinkedHashMap<String, String>()
        val mitmOptions = LinkedHashMap<String, String>()
        val urlRewrites = LinkedHashSet<String>()
        val headerRewrites = LinkedHashSet<String>()
        val loonRewrites = LinkedHashSet<String>()
        val bodyRewrites = LinkedHashSet<String>()
        val wsRewrites = LinkedHashSet<String>()
        val hostMappings = LinkedHashMap<String, String>()
        val scripts = LinkedHashMap<String, ScriptConfig>()
        val scriptIssues = LinkedHashSet<String>()
        val ruleSetIssues = LinkedHashSet<String>()
        var ignored = 0
        cfg.moduleSources.filter { it.enabled }.forEach { src ->
            val file = moduleFile(context, src.id)
            if (!file.exists() || file.length() == 0L) return@forEach
            val parsed = runCatching { ModuleParser.parse(file.readText()) }.getOrNull()
            if (parsed == null) {
                ruleSetIssues.add("${src.name.ifBlank { "模块" }}：模块正文解析失败，整份模块不会生效")
                return@forEach
            }
            blocks.addAll(parsed.blockLines)
            allows.addAll(parsed.allowLines)
            routes.addAll(parsed.routeRules.map { it.copy(source = src.name.ifBlank { "模块" }) })
            // 规则集：用已缓存内容展开；未缓存/为空时跳过（导入/同步阶段负责拉取）。
            // 展开结果与跳过原因统一进 modules_mitm.json，避免「一条都没生效」无人察觉。
            parsed.ruleSets.forEach rsLoop@{ rs ->
                val cache = ruleSetFile(context, rs.url)
                val label = rs.url.substringAfterLast('/').ifBlank { rs.url }.take(36)
                if (!cache.exists() || cache.length() == 0L) {
                    ruleSetIssues.add("${label}：内容未缓存，整个规则集不会生效（同步模块后重试）")
                    return@rsLoop
                }
                val content = runCatching { cache.readText() }.getOrDefault("")
                val res = RuleSetExpander.expandDetailed(
                    rs.kind,
                    content,
                    rs.action,
                    src.name.ifBlank { "模块" } + "·规则集",
                )
                routes.addAll(res.items)
                if (res.note != null || res.items.isEmpty()) {
                    ruleSetIssues.add(
                        "$label：${res.format} 展开 ${res.items.size} 条" +
                            (res.note?.let { "，$it" } ?: ""),
                    )
                }
            }
            mitmHosts.addAll(parsed.mitmHostnames)
            mitmSkips.addAll(parsed.mitmSkipHostnames)
            parsed.generalOptions.forEach { (k, v) -> if (!generalOptions.containsKey(k)) generalOptions[k] = v }
            parsed.mitmOptions.forEach { (k, v) -> if (!mitmOptions.containsKey(k)) mitmOptions[k] = v }
            urlRewrites.addAll(parsed.urlRewrites)
            headerRewrites.addAll(parsed.headerRewrites)
            loonRewrites.addAll(parsed.loonRewrites)
            bodyRewrites.addAll(parsed.bodyRewrites)
            wsRewrites.addAll(parsed.wsRewrites)
            parsed.hostMappings.forEach { (k, v) ->
                // 先加载的模块优先；重复 key 不让后加载模块静默覆盖。
                if (!hostMappings.containsKey(k)) hostMappings[k] = v
            }
            parsed.scripts.forEach { rule ->
                var src = rule.source
                if (src.isBlank() && rule.scriptPath.isNotBlank()) {
                    val cache = scriptCacheFile(context, rule.scriptPath)
                    if (cache.exists() && cache.length() > 0) {
                        src = runCatching { cache.readText() }.getOrDefault("")
                    }
                }
                if (src.isBlank()) {
                    scriptIssues.add("${rule.name}: 脚本正文未缓存，不会执行")
                } else {
                    scripts[scriptKey(rule)] = rule.copy(source = src)
                }
            }
            parsed.scriptIssues.forEach { scriptIssues.add(it) }
            ignored += parsed.ignored
        }
        // block 与 allow 必须写入同一个过滤文件：FilterEngine 按文件顺序处理 @@ 例外。
        writeAtomic(moduleBlockFile(context), (blocks + allows).joinToString("\n"))
        writeAtomic(
            moduleRulesFile(context),
            JSONArray().apply {
                routes.distinctBy { "${it.type}|${it.value}|${it.action}" }
                    .forEach { put(it.toJson()) }
            }.toString(),
        )
        writeAtomic(
            moduleMitmFile(context),
            JSONObject().apply {
                put("hostnames", JSONArray(mitmHosts.toList()))
                put("skipHostnames", JSONArray(mitmSkips.toList()))
                put("generalOptions", JSONObject(generalOptions as Map<*, *>))
                put("mitmOptions", JSONObject(mitmOptions as Map<*, *>))
                put("urlRewrites", JSONArray(urlRewrites.toList()))
                put("headerRewrites", JSONArray(headerRewrites.toList()))
                put("loonRewrites", JSONArray(loonRewrites.toList()))
                put("bodyRewrites", JSONArray(bodyRewrites.toList()))
                put("wsRewrites", JSONArray(wsRewrites.toList()))
                put("hostMappings", JSONObject(hostMappings as Map<*, *>))
                put("scripts", JSONArray(scripts.values.map { it.toJsonObject() }))
                put("scriptIssues", JSONArray(scriptIssues.toList()))
                put("ruleSetIssues", JSONArray(ruleSetIssues.toList()))
                put("ignoredRules", ignored)
            }.toString(),
        )
    }

    fun writeAtomicPublic(file: File, text: String) = writeAtomic(file, text)

    private fun writeAtomic(file: File, text: String) {
        try {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(text)
            if (!tmp.renameTo(file)) {
                file.writeText(text)
                tmp.delete()
            }
        } catch (_: Exception) {
        }
    }

    /** 所有当前会参与本地过滤的规则文件。 */
    fun ruleFiles(context: Context, cfg: AppConfig): List<File> {
        val files = mutableListOf<File>()
        if (cfg.ruleSources.isEmpty()) {
            rulesFile(context).takeIf { it.exists() && it.length() > 0 }?.let { files.add(it) }
        } else {
            cfg.ruleSources.filter { it.enabled }.forEach { src ->
                ruleSourceFile(context, src.id).takeIf { it.exists() && it.length() > 0 }?.let { files.add(it) }
            }
        }
        File(context.filesDir, "ads_custom.txt").takeIf { it.exists() && it.length() > 0 }?.let { files.add(it) }
        moduleBlockFile(context).takeIf {
            cfg.moduleSources.any { m -> m.enabled } && it.exists() && it.length() > 0
        }?.let { files.add(it) }
        return files
    }
}
