package com.namu.dns

import android.content.Context
import android.os.Build
import com.namu.dns.core.config.ScriptConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

object ConfigStore {
    /** S3：模块顺序以显式 order 为准；旧模块 order=-1 时按列表下标兜底，不重排。 */
    fun orderedModules(cfg: AppConfig): List<ModuleSource> =
        cfg.moduleSources.withIndex()
            .sortedWith(compareBy({ if (it.value.order >= 0) it.value.order else Int.MAX_VALUE / 2 + it.index }, { it.index }))
            .map { it.value }

    internal fun scriptNodeEnvironment(node: NodeInfo): Map<String, String> = mapOf(
        "nodeName" to node.name,
        "nodeType" to node.type,
        "nodeServer" to node.server,
        "nodePort" to node.port.toString(),
    )

    internal fun profileRoutingRules(cfg: AppConfig): List<RuleItem> =
        if (cfg.mode == "rule") cfg.rules.filter {
            it.enabled && isImportedRoutingRule(it) &&
                it.type !in NON_ROUTING_TYPES && it.type !in FINAL_RULE_TYPES
        } else emptyList()

    internal fun routingRules(
        cfg: AppConfig,
        global: GlobalRuleStore.State,
        modules: List<RuleItem> = emptyList(),
        expand: (List<RuleItem>) -> List<RuleItem>,
    ): List<RuleItem> {
        val local = if (global.localRulesEnabled) {
            global.localRules.filter { it.enabled && it.type !in NON_ROUTING_TYPES }
        } else emptyList()
        val seen = local.mapTo(HashSet()) { routingRuleKey(it) }
        val profile = profileRoutingRules(cfg).filter { seen.add(routingRuleKey(it)) }
        val (subscriptions, config) = profile.partition(::isSubscriptionRoutingRule)
        var order = 0L
        return expand(local).map { rule ->
            prepareRoutingRule(rule, "本地规则", GlobalRuleStore.ID_LOCAL_RULES, "dns", order++)
        } + expand(config).map { rule ->
            prepareRoutingRule(rule, "当前配置", "config", "route", order++)
        } + modules + expand(subscriptions).map { rule ->
            prepareRoutingRule(rule, "订阅", rule.subscriptionSource.ifBlank { "config" }, "route", order++)
        }
    }

    private val PROFILE_RULE_SOURCES = setOf("Clash 导入", "[Rule]")
    private val NON_ROUTING_TYPES = setOf("URL-REGEX", "USER-AGENT")
    private val FINAL_RULE_TYPES = setOf("FINAL", "MATCH")

    private fun isSubscriptionRoutingRule(rule: RuleItem): Boolean =
        rule.subscriptionSource.isNotBlank() || rule.source == "订阅"

    internal fun isImportedRoutingRule(rule: RuleItem): Boolean =
        isSubscriptionRoutingRule(rule) || rule.source in PROFILE_RULE_SOURCES

    private fun routingRuleKey(rule: RuleItem): String =
        "${rule.type}|${rule.value}|${rule.action}|${rule.extendedMatch}|${rule.preMatch}|${rule.noResolve}"

    private fun prepareRoutingRule(
        rule: RuleItem,
        sourceName: String,
        sourceId: String,
        section: String,
        order: Long,
    ): RuleItem = rule.copy(
        action = buildString {
            append(rule.action)
            if (rule.extendedMatch) append(",extended-matching")
            if (rule.preMatch && rule.action == "block") append(",pre-matching")
        },
        source = rule.source.ifBlank { sourceName },
        meta = rule.meta ?: makeMeta(
            section, "${rule.type}|${rule.value}|${rule.action}", sourceId, sourceName, order,
        ),
    )

    private fun shortRuleId(vararg parts: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(parts.joinToString("|").toByteArray())
        return digest.joinToString("") { "%02x".format(it) }.take(12)
    }

    private fun makeMeta(
        section: String,
        key: String,
        sourceId: String,
        sourceName: String,
        order: Long,
    ): RuleMeta = RuleMeta(
        section = section,
        key = key,
        ruleId = shortRuleId(sourceId, section, key),
        sourceType = section,
        sourceId = sourceId.ifBlank { "config" },
        sourceName = sourceName.ifBlank { "当前配置" },
        order = order,
    )

    /** 配置文件自身的规则身份；模块规则优先，手写/当前配置只在同名 key 上补位。 */
    private fun configMeta(section: String, key: String, order: Long): RuleMeta =
        makeMeta(section, key, "config", "当前配置", order)

    /** 配置文件落盘统一走单线程队列：不阻塞主线程，且保证写入顺序。 */
    private val fileIo = java.util.concurrent.Executors.newSingleThreadExecutor()

    fun submitFileIo(task: () -> Unit) {
        fileIo.execute { runCatching { task() } }
    }

    /** 等待已入队的配置写入，然后读取或写入指定方案。 */
    fun <T> runProfileFileIo(task: () -> T): T =
        fileIo.submit(java.util.concurrent.Callable { task() }).get()

    fun baseConfigFile(context: Context): File = File(context.filesDir, "default.json")

    fun ensureAssets(context: Context, settings: com.namu.dns.core.repository.SettingsRepository, config: com.namu.dns.core.repository.ConfigRepository) {
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
        // 3.0.18：规则/模块全局化迁移（幂等），必须先于聚合重建。
        GlobalRuleStore.migrateIfNeeded(context, config)
        // 多规则源同样在下载中断时保留上一份可用文件
        val cfg = settings.current()
        // 模块文件变化后重建合并规则；启动时也保证聚合文件存在。
        rebuildModules(context, cfg)
        val profileCacheMigration = File(dir, "profile_rule_cache_migrated")
        if (!profileCacheMigration.exists()) {
            runCatching {
                if (cfg.rulesUrl.isNotBlank() && downloaded.length() > 0L && !rulesFile(context, cfg.rulesUrl, settings.activeConfigName()).exists()) {
                    downloaded.copyTo(rulesFile(context, cfg.rulesUrl, settings.activeConfigName()), overwrite = false)
                }
                cfg.ruleSources.forEach { source ->
                    val legacy = ruleSourceFile(context, source.id)
                    val target = ruleSourceFile(context, source, settings.activeConfigName())
                    if (legacy.length() > 0L && !target.exists()) legacy.copyTo(target)
                }
                profileCacheMigration.writeText("1")
            }
        }
        GlobalRuleStore.state.ruleSets.forEach { src ->
            val target = globalRuleSetFile(context, src.url)
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

    fun buildNative(context: Context, cfg: AppConfig, profileName: String = ConfigFileStore.activeName(context)): String {
        val dir = context.filesDir
        val ads = mutableListOf<File>()
        // 有远端 manifest 的多规则源时，以 manifest 为准；否则兼容旧的单 rulesUrl。
        GlobalRuleStore.enabledRuleSets().forEach { src ->
            val f = globalRuleSetFile(context, src.url)
            if (f.exists() && f.length() > 0) ads.add(f)
        }
        // 手动维护的本地广告域名，与服务器 URL 规则相互独立。
        val custom = File(dir, "ads_custom.txt")
        custom.writeText(
            (if (GlobalRuleStore.state.localRulesEnabled) GlobalRuleStore.state.localAds else emptyList())
                .mapNotNull { normalizeAdsDomain(it) }
                .distinct()
                .joinToString("\n") { "||$it^" },
        )
        if (custom.length() > 0) ads.add(custom)

        // 小火箭式模块：启用中的模块规则合并到本地过滤/分流。
        val moduleBlock = moduleBlockFile(context)
        if (GlobalRuleStore.enabledModules().isNotEmpty() && moduleBlock.exists() && moduleBlock.length() > 0) {
            ads.add(moduleBlock)
        }

        val root = JSONObject()
        // MITM/Host 分区：active 配置 + 启用模块合并。DNS 也要读同一份 Host 映射。
        val moduleMitm = if (GlobalRuleStore.enabledModules().isNotEmpty()) {
            runCatching { JSONObject(moduleMitmFile(context).readText()) }.getOrNull()
        } else null
        val hostMeta = LinkedHashMap<String, RuleMeta>()
        moduleMitm?.optJSONArray("ruleMeta")?.let { a ->
            for (i in 0 until a.length()) {
                val m = a.optJSONObject(i)?.let { RuleMeta.fromJson(it) }
                if (m != null && m.section == "host") hostMeta[m.key] = m
            }
        }
        var hostMetaOrder = (hostMeta.values.maxOfOrNull { it.order } ?: -1L) + 1
        cfg.mitm.hostMappings.forEach { (k, _) ->
            val key = k.trim().lowercase()
            if (key.isNotBlank()) hostMeta[key] = configMeta("host", key, hostMetaOrder++)
        }
        root.put("mode", cfg.mode)
        // 仅过滤/DNS-only 全部直连，节点不参与转发：不下发节点表，
        // 节点表的问题（重名、坏字段、订阅残留）不再拖累这两种模式的启动。
        val nodelessMode = cfg.mode == "filter_only" || cfg.mode == "dns_only"
        root.put("selected", if (nodelessMode) "" else cfg.selected ?: "")
        root.put("final_policy", cfg.finalPolicy)
        root.put("block_enabled", cfg.blockEnabled)
        root.put("block_mode", cfg.blockMode)
        root.put("cn_direct", cfg.cnDirect)
        root.put("block_when_no_node", cfg.blockWhenNoNode)
        root.put("fake_ip", cfg.fakeIp)
        // Fake-IP 映射落盘（内核 1.1.0：mihomo/sing-box cache_file 同款），重启后连接层仍能反查域名
        root.put("fake_ip_file", File(context.filesDir, "namu_fakeip.json").absolutePath)
        // D2/D3：轻量命中摘要与小时历史；关闭命中摘要后内核不写盘。
        root.put("hit_history_file", File(File(context.filesDir, "stats"), "history.json").absolutePath)
        root.put("sniff", cfg.sniff)
        root.put(
            "ipv6",
            cfg.ipv6
                ?: moduleMitm?.optJSONObject("generalOptions")?.takeIf { it.has("ipv6") }
                    ?.let { it.optString("ipv6").equals("true", true) || it.optString("ipv6") == "1" }
                ?: true,
        )
        root.put(
            "prefer_ipv6",
            cfg.preferIpv6
                ?: moduleMitm?.optJSONObject("generalOptions")?.takeIf { it.has("prefer-ipv6") }
                    ?.let { it.optString("prefer-ipv6").equals("true", true) || it.optString("prefer-ipv6") == "1" }
                ?: false,
        )
        root.put("skip_proxy", JSONArray().apply { cfg.skipProxyHosts.forEach { put(it) } })
        root.put("mtu", cfg.mtu.coerceIn(1280, 9000))
        root.put("bbr", cfg.bbr)
        root.put("tun_rx_checksum_verify", cfg.tunRxChecksumVerify)
        root.put("quicFallback", cfg.quicFallback)
        root.put("block_dot", true)
        // 「system」表示手机当前底层网络的 DNS；下发前转成内核可用的 UDP 地址。
        val sysDns = SystemDns.selection(context)
        fun resolveDnsList(raw: String, systemValue: String?): String = raw.split(',', '\n')
            .map { it.trim() }.filter { it.isNotBlank() }
            .joinToString(",") { value ->
                if (SystemDns.isFollow(value)) systemValue.orEmpty() else value
            }
        val effectiveUpstream = resolveDnsList(cfg.dnsUpstream, sysDns.primaryUpstream ?: SystemDns.FAIL_CLOSED)
            .ifBlank { sysDns.primaryUpstream ?: SystemDns.FAIL_CLOSED }
        val effectiveFallback = resolveDnsList(cfg.dnsFallback, sysDns.secondaryUpstream)
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
                put("host_meta", JSONArray(hostMeta.values.map { it.toJson() }))
                put("cache_ttl", cfg.dnsCacheTtl)
                put("cache_size", 2048)
                put("block_ttl", cfg.blockTtl)
                put("negative_ttl", 30)
                put("fallback_filter", cfg.fallbackFilter)
                put("fallback_geo_check", cfg.fallbackGeoCheck)
                put("query_log", cfg.dnsQueryLog)
                put("block_aaaa", cfg.blockAaaa)
                // [DNS] 按域名策略：当前配置优先，模块只补未占用的 pattern。
                put("policies", JSONArray().apply {
                    val merged = LinkedHashMap<String, String>()
                    cfg.dnsPolicies.forEach {
                        if (it.pattern.isNotBlank() && it.servers.isNotBlank()) merged[it.pattern.trim().lowercase()] = it.servers.trim()
                    }
                    moduleMitm?.optJSONArray("dnsPolicies")?.let { arr ->
                        for (i in 0 until arr.length()) {
                            val o = arr.optJSONObject(i) ?: continue
                            val k = o.optString("pattern").trim().lowercase()
                            val v = o.optString("servers").trim()
                            if (k.isNotBlank() && v.isNotBlank() && !merged.containsKey(k)) merged[k] = v
                        }
                    }
                    merged.forEach { (k, v) -> put(JSONObject().put("pattern", k).put("servers", v)) }
                })
                // always-real-ip / fake-ip-filter：当前配置优先，模块只补未占用条目。
                put("fake_ip_filter", JSONArray().apply {
                    val merged = LinkedHashSet<String>()
                    cfg.alwaysRealIp.forEach { if (it.isNotBlank()) merged += it.trim().lowercase() }
                    moduleMitm?.optJSONArray("alwaysRealIp")?.let { arr ->
                        for (i in 0 until arr.length()) {
                            val v = arr.optString(i).trim().lowercase()
                            if (v.isNotBlank()) merged += v
                        }
                    }
                    merged.forEach { put(it) }
                })
                put(
                    "hijack",
                    cfg.dnsHijack
                        ?: moduleMitm?.optJSONObject("generalOptions")?.takeIf { it.has("hijack-dns") }
                            ?.let { com.namu.dns.core.config.parseHijackDns(it.optString("hijack-dns")) }
                        ?: true,
                )
                // 缓存落盘（sing-box cache_file 同款）：重启后热域直接命中
                put("cache_file", File(context.filesDir, "namu_cache.json").absolutePath)
            },
        )
        root.put("nodes", JSONArray().apply {
            if (!nodelessMode) cfg.nodes.forEach { put(it.toJson(includeSource = false)) }
        })
        val moduleRules = if (GlobalRuleStore.enabledModules().isNotEmpty()) {
            runCatching { JSONArray(moduleRulesFile(context).readText()) }.getOrNull()
        } else null
        root.put("proxy_groups", JSONArray().apply {
            if (!nodelessMode) cfg.proxyGroups.forEach { g ->
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
                    put("lb_mode", g.lbMode)
                    put("switch_interval", g.switchInterval)
                })
            }
        })
        root.put("group_selections", JSONObject().apply {
            cfg.groupSelections.forEach { (k, v) -> if (k.isNotBlank() && v.isNotBlank()) put(k, v) }
        })
        root.put("rules", JSONArray().apply {
            val modules = (0 until (moduleRules?.length() ?: 0)).mapNotNull { i ->
                moduleRules?.optJSONObject(i)?.let(RuleItem::fromJson)
            }
            routingRules(cfg, GlobalRuleStore.state, modules) { rules ->
                val routed = rules.flatMap { rule ->
                    if (rule.type != "RULE-SET" && rule.type != "DOMAIN-SET") return@flatMap listOf(rule)
                    val source = GlobalRuleStore.state.ruleSets.firstOrNull { it.id == rule.value || it.url == rule.value }
                    val file = if (source != null) globalRuleSetFile(context, source.url) else ruleSetFile(context, rule.value)
                    val content = runCatching { file.readText() }.getOrDefault("")
                    if (content.isBlank()) {
                        android.util.Log.w("NamuRules", "规则集尚无本地缓存：${rule.value}")
                        emptyList()
                    } else RuleSetExpander.expand(rule.type, content, rule.action, "规则集 ${rule.value}")
                        .map { it.copy(extendedMatch = rule.extendedMatch, preMatch = rule.preMatch, noResolve = it.noResolve || rule.noResolve) }
                }
                val (expanded, unresolved) = AppUidResolver.expand(context, routed)
                if (unresolved.isNotEmpty()) {
                    android.util.Log.w("NamuUid", "包名规则未解析（应用可能未安装）：$unresolved")
                }
                expanded
            }.forEach { put(it.toJson()) }
        })
        // MITM 分区：active 配置 + 启用模块合并。内核 1.11 消费；
        // url_rewrites/header_rewrites 下发原始模块规则行，由内核统一解析成结构化规则。
        val mitmMeta = LinkedHashMap<String, RuleMeta>()
        moduleMitm?.optJSONArray("ruleMeta")?.let { a ->
            for (i in 0 until a.length()) {
                val m = a.optJSONObject(i)?.let { RuleMeta.fromJson(it) }
                if (m != null && m.section != "host") mitmMeta["${m.section}|${m.key}"] = m
            }
        }
        var mitmMetaOrder = (mitmMeta.values.maxOfOrNull { it.order } ?: -1L) + 1
        fun putLocalMitmMeta(section: String, key: String) {
            mitmMeta["$section|$key"] = makeMeta(section, key, GlobalRuleStore.ID_LOCAL_MITM, "本地重写与脚本", mitmMetaOrder++)
        }
        val gm = GlobalRuleStore.state
        val localForMeta = (if (gm.localMitmEnabled) listOf(gm.localMitm) else emptyList()) +
            GlobalRuleStore.enabledExtraMitm().map { it.content }
        localForMeta.forEach { c ->
            c.urlRewrites.forEach { putLocalMitmMeta("url", it) }
            c.headerRewrites.forEach { putLocalMitmMeta("header", it) }
            c.loonRewrites.forEach { putLocalMitmMeta("loon", it) }
            c.bodyRewrites.forEach { putLocalMitmMeta("body", it) }
            c.wsRewrites.forEach { putLocalMitmMeta("ws", it) }
            c.scripts.forEach { putLocalMitmMeta("script", scriptKey(it)) }
        }
        root.put("mitm", JSONObject().apply {
            val g = GlobalRuleStore.state
            val localContents = (if (g.localMitmEnabled) listOf(g.localMitm) else emptyList()) +
                GlobalRuleStore.enabledExtraMitm().map { it.content }
            val hosts = LinkedHashSet(g.scope.hostnames)
            val skips = LinkedHashSet(g.scope.skipHostnames)
            val urls = LinkedHashSet<String>()
            val headers = LinkedHashSet<String>()
            val loon = LinkedHashSet<String>()
            val body = LinkedHashSet<String>()
            val wsRules = LinkedHashSet<String>()
            val scripts = LinkedHashMap<String, ScriptConfig>()
            localContents.forEach { c ->
                urls.addAll(c.urlRewrites); headers.addAll(c.headerRewrites); loon.addAll(c.loonRewrites)
                body.addAll(c.bodyRewrites); wsRules.addAll(c.wsRewrites)
                c.scripts.forEach { sc -> scripts.putIfAbsent(scriptKey(sc), sc) }
            }
            val mitmLocalRules = if (g.localRulesEnabled) g.localRules else emptyList()
            mitmLocalRules.filter { it.enabled && it.type == "URL-REGEX" }.forEach { rule ->
                loon.add("${rule.value} ${rule.action}")
            }
            mitmLocalRules.filter { it.enabled && it.type == "USER-AGENT" }.forEach { rule ->
                val regex = buildString {
                    append("(?i)^")
                    rule.value.forEach { c ->
                        when (c) {
                            '*' -> append(".*")
                            '?' -> append('.')
                            else -> append(Regex.escape(c.toString()))
                        }
                    }
                    append('$')
                }
                val quoted = regex.replace("\\", "\\\\").replace("\"", "\\\"")
                loon.add("^.*$ ${rule.action} user-agent-regex \"$quoted\"")
            }
            scripts.values.toList().forEach { sc ->
                val key = scriptKey(sc)
                if (sc.meta == null) scripts[key] = sc.copy(meta = makeMeta("script", key, GlobalRuleStore.ID_LOCAL_MITM, "本地重写与脚本", 0))
            }
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
            put("enabled", g.scope.enabled)
            // 上游复用属于 MITM 配置的一部分：备份/导出必须一起带上，
            // 否则恢复后连接池会退回默认关闭，和备份前的行为不一致。
            put("pool_enabled", g.scope.poolEnabled)
            put("pool_idle_secs", g.scope.poolIdleSecs)
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
                g.scriptArguments[scriptArgumentKey(sc)]?.let { sc.copy(argumentValues = it) } ?: sc
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
                // S5 NodeInfo：脚本可读取当前节点摘要；不含密码/UUID 等凭据。
                val node = cfg.nodes.firstOrNull { it.name == cfg.selected } ?: cfg.nodes.firstOrNull()
                if (node != null) {
                    scriptNodeEnvironment(node).forEach { (key, value) -> put(key, value) }
                }
            })
            put("rule_meta", JSONArray(mitmMeta.values.map { it.toJson() }))
            // CA 必须与 MitmManager.caFile 保持一致；未导出前内核会自行生成。
            put("ca_file", File(File(dir, "mitm"), "ca.pem").absolutePath)
            put("body_limit", 2 * 1024 * 1024)
            put("fail_open_ttl", 300)
            put("upstream_insecure", false)
            // 按 App MITM：配置里保留包名（可读、换机可重解析），下发前才展开成 UID。
            val (mitmUids, unresolved) = AppUidResolver.resolveUids(context, g.scope.apps)
            put("app_mode", g.scope.appMode)
            put("app_uids", JSONArray(mitmUids))
            put("app_scope_incomplete", g.scope.appMode == "deny" && unresolved.isNotEmpty())
            // 金融保护：支付/银行连接在 MITM 判定之前排除，默认开启。
            put("finance", FinanceProtect.toJson(context, cfg.financeProtect))
        })
        root.put(
            "rule_meta",
            JSONArray().apply {
                moduleMitm?.optJSONArray("dnsRuleMeta")?.let { a ->
                    for (i in 0 until a.length()) put(a.get(i))
                }
            },
        )
        root.put(
            "ads_files",
            JSONArray().apply { ads.forEach { put(it.absolutePath) } },
        )
        root.put("cn_domains_file", File(dir, "cn_domains.txt").absolutePath)
        root.put("cn_ip_file", File(dir, "cnip.txt").absolutePath)
        return root.toString()
    }

    /** S6：Profile 名单 + 模块 [General] 的 ssid-trigger 合并；仍要求本地 opt-in。 */
    fun effectiveSsidTriggers(context: Context, cfg: AppConfig): List<String> {
        val out = LinkedHashSet(cfg.ssidTriggerNames.map { it.trim() }.filter { it.isNotBlank() })
        runCatching { JSONObject(moduleMitmFile(context).readText()) }
            .getOrNull()
            ?.optJSONObject("generalEffects")
            ?.optJSONArray("ssidTriggers")
            ?.let { a -> for (i in 0 until a.length()) a.optString(i, "").trim().takeIf { it.isNotBlank() }?.let { out.add(it) } }
        return out.toList()
    }

    fun rulesFile(context: Context): File = File(context.filesDir, "ads_url.txt")

    fun rulesFile(context: Context, url: String, profileName: String = ConfigFileStore.activeName(context)): File =
        ruleSetFile(context, "ads-url:$profileName\n$url")

    fun ruleSourceFile(context: Context, source: RuleSource, profileName: String = ConfigFileStore.activeName(context)): File =
        ruleSetFile(context, "rule-source:$profileName\n${source.url}")

    /** 3.0.18：规则集缓存全局共享，不再随配置方案隔离。 */
    fun globalRuleSetFile(context: Context, url: String): File =
        ruleSetFile(context, "rule-source-global\n$url")

    private fun ruleSourceFile(context: Context, id: String): File {
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
        val moduleDnsPolicies = mutableListOf<com.namu.dns.core.config.DnsPolicyRule>()
        val mitmOptions = LinkedHashMap<String, String>()
        val urlRewrites = LinkedHashSet<String>()
        val headerRewrites = LinkedHashSet<String>()
        val loonRewrites = LinkedHashSet<String>()
        val bodyRewrites = LinkedHashSet<String>()
        val wsRewrites = LinkedHashSet<String>()
        val hostMappings = LinkedHashMap<String, String>()
        val scripts = LinkedHashMap<String, ScriptConfig>()
        val dnsMeta = LinkedHashMap<String, RuleMeta>()
        val mitmMeta = LinkedHashMap<String, RuleMeta>()
        var ruleOrder = 0L
        val scriptIssues = LinkedHashSet<String>()
        val ruleSetIssues = LinkedHashSet<String>()
        var ignored = 0
        GlobalRuleStore.orderedModules().filter { it.enabled }.forEach { src ->
            val file = moduleFile(context, src.id)
            if (!file.exists() || file.length() == 0L) return@forEach
            val parsed = runCatching { ModuleParser.parse(file.readText()) }.getOrNull()
            if (parsed == null) {
                ruleSetIssues.add("${src.name.ifBlank { "模块" }}｜模块正文解析失败，整份模块不会生效")
                return@forEach
            }
            parsed.blockLines.forEach { line ->
                if (blocks.add(line)) {
                    dnsMeta[line] = makeMeta("dns", line, src.id, src.name, ruleOrder++)
                }
            }
            parsed.allowLines.forEach { line ->
                if (allows.add(line)) {
                    dnsMeta[line] = makeMeta("dns", line, src.id, src.name, ruleOrder++)
                }
            }
            parsed.routeRules.forEach { rule ->
                routes.add(
                    rule.copy(
                        source = src.name.ifBlank { "模块" },
                        meta = makeMeta("route", "${rule.type}|${rule.value}|${rule.action}", src.id, src.name, ruleOrder++),
                    ),
                )
            }
            // 规则集：用已缓存内容展开；未缓存/为空时跳过（导入/同步阶段负责拉取）。
            // 展开结果与跳过原因统一进 modules_mitm.json，避免「一条都没生效」无人察觉。
            parsed.ruleSets.forEach rsLoop@{ rs ->
                val cache = ruleSetFile(context, rs.url)
                val label = rs.url.substringAfterLast('/').ifBlank { rs.url }.take(36)
                if (!cache.exists() || cache.length() == 0L) {
                    ruleSetIssues.add("${src.name.ifBlank { "模块" }}｜${label}：内容未缓存，整个规则集不会生效（同步模块后重试）")
                    return@rsLoop
                }
                val content = runCatching { cache.readText() }.getOrDefault("")
                val res = RuleSetExpander.expandDetailed(
                    rs.kind,
                    content,
                    rs.action,
                    src.name.ifBlank { "模块" } + "·规则集",
                )
                routes.addAll(
                    res.items.map { rule ->
                        rule.copy(
                            meta = rule.meta ?: makeMeta(
                                "route",
                                "${rule.type}|${rule.value}|${rule.action}",
                                src.id,
                                src.name.ifBlank { "模块" } + "·规则集",
                                ruleOrder++,
                            ),
                        )
                    },
                )
                if (res.note != null || res.items.isEmpty()) {
                    ruleSetIssues.add(
                        "${src.name.ifBlank { "模块" }}｜$label：${res.format} 展开 ${res.items.size} 条" +
                            (res.note?.let { "，$it" } ?: ""),
                    )
                }
            }
            mitmHosts.addAll(parsed.mitmHostnames)
            mitmSkips.addAll(parsed.mitmSkipHostnames)
            // 3.0.18：模块附带 DNS 参数须经导入预览确认（dnsApproved）才合并。
            if (src.dnsApproved) {
                parsed.generalOptions.forEach { (k, v) -> if (!generalOptions.containsKey(k)) generalOptions[k] = v }
                parsed.dnsPolicies.forEach { moduleDnsPolicies += it }
            }
            parsed.mitmOptions.forEach { (k, v) -> if (!mitmOptions.containsKey(k)) mitmOptions[k] = v }
            parsed.urlRewrites.forEach { line ->
                if (urlRewrites.add(line)) {
                    mitmMeta["url|$line"] = makeMeta("url", line, src.id, src.name, ruleOrder++)
                }
            }
            parsed.headerRewrites.forEach { line ->
                if (headerRewrites.add(line)) {
                    mitmMeta["header|$line"] = makeMeta("header", line, src.id, src.name, ruleOrder++)
                }
            }
            parsed.loonRewrites.forEach { line ->
                if (loonRewrites.add(line)) {
                    mitmMeta["loon|$line"] = makeMeta("loon", line, src.id, src.name, ruleOrder++)
                }
            }
            parsed.bodyRewrites.forEach { line ->
                if (bodyRewrites.add(line)) {
                    mitmMeta["body|$line"] = makeMeta("body", line, src.id, src.name, ruleOrder++)
                }
            }
            parsed.wsRewrites.forEach { line ->
                if (wsRewrites.add(line)) {
                    mitmMeta["ws|$line"] = makeMeta("ws", line, src.id, src.name, ruleOrder++)
                }
            }
            parsed.hostMappings.forEach { (k, v) ->
                // 先加载的模块优先；重复 key 不让后加载模块静默覆盖。
                val key = k.trim().lowercase()
                if (!hostMappings.containsKey(key)) {
                    hostMappings[key] = v
                    mitmMeta["host|$key"] = makeMeta("host", key, src.id, src.name, ruleOrder++)
                }
            }
            val legacyChain = parsed.generalOptions["legacy-chain"]
                ?.let { it.equals("true", ignoreCase = true) || it == "1" } ?: false
            parsed.scripts.forEach { rule ->
                var body = rule.source
                if (body.isBlank() && rule.scriptPath.isNotBlank()) {
                    val cache = scriptCacheFile(context, rule.scriptPath)
                    if (cache.exists() && cache.length() > 0) {
                        body = runCatching { cache.readText() }.getOrDefault("")
                    }
                }
                if (body.isBlank()) {
                    scriptIssues.add("${src.name.ifBlank { "模块" }}｜${rule.name}: 脚本正文未缓存，不会执行")
                } else {
                    val key = scriptKey(rule)
                    if (!scripts.containsKey(key)) {
                        val meta = makeMeta("script", key, src.id, src.name, ruleOrder++)
                        mitmMeta["script|$key"] = meta
                        scripts[key] = rule.copy(
                            source = body,
                            meta = meta,
                            legacyChain = rule.legacyChain || legacyChain,
                        )
                    }
                }
            }
            parsed.scriptIssues.forEach { scriptIssues.add("${src.name.ifBlank { "模块" }}｜$it") }
            ignored += parsed.ignored
        }
        // 3.0.18：本地重写与脚本（含其他方案启用项）并入同一聚合，归因到伪模块。
        val localContents = (if (GlobalRuleStore.state.localMitmEnabled) listOf(GlobalRuleStore.state.localMitm) else emptyList()) +
            GlobalRuleStore.enabledExtraMitm().map { it.content }
        localContents.forEach { c ->
            c.urlRewrites.forEach { line ->
                if (urlRewrites.add(line)) mitmMeta["url|$line"] = makeMeta("url", line, GlobalRuleStore.ID_LOCAL_MITM, "本地重写与脚本", ruleOrder++)
            }
            c.headerRewrites.forEach { line ->
                if (headerRewrites.add(line)) mitmMeta["header|$line"] = makeMeta("header", line, GlobalRuleStore.ID_LOCAL_MITM, "本地重写与脚本", ruleOrder++)
            }
            c.loonRewrites.forEach { line ->
                if (loonRewrites.add(line)) mitmMeta["loon|$line"] = makeMeta("loon", line, GlobalRuleStore.ID_LOCAL_MITM, "本地重写与脚本", ruleOrder++)
            }
            c.bodyRewrites.forEach { line ->
                if (bodyRewrites.add(line)) mitmMeta["body|$line"] = makeMeta("body", line, GlobalRuleStore.ID_LOCAL_MITM, "本地重写与脚本", ruleOrder++)
            }
            c.wsRewrites.forEach { line ->
                if (wsRewrites.add(line)) mitmMeta["ws|$line"] = makeMeta("ws", line, GlobalRuleStore.ID_LOCAL_MITM, "本地重写与脚本", ruleOrder++)
            }
            c.scripts.forEach { rule ->
                val key = scriptKey(rule)
                if (!scripts.containsKey(key)) {
                    val meta = makeMeta("script", key, GlobalRuleStore.ID_LOCAL_MITM, "本地重写与脚本", ruleOrder++)
                    mitmMeta["script|$key"] = meta
                    scripts[key] = rule.copy(meta = meta)
                }
            }
        }
        // S6：模块 General 里只影响壳行为的键在写盘前映射一次。
        val generalEffects = com.namu.dns.core.config.ModuleGeneral.parse(generalOptions)
        mitmSkips.addAll(generalEffects.skipHosts)
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
                put("dnsPolicies", JSONArray(moduleDnsPolicies.map { JSONObject().put("pattern", it.pattern).put("servers", it.servers) }))
                put("alwaysRealIp", JSONArray(generalEffects.alwaysRealIp))
                put("mitmOptions", JSONObject(mitmOptions as Map<*, *>))
                put("urlRewrites", JSONArray(urlRewrites.toList()))
                put("headerRewrites", JSONArray(headerRewrites.toList()))
                put("loonRewrites", JSONArray(loonRewrites.toList()))
                put("bodyRewrites", JSONArray(bodyRewrites.toList()))
                put("wsRewrites", JSONArray(wsRewrites.toList()))
                put("hostMappings", JSONObject(hostMappings as Map<*, *>))
                put("scripts", JSONArray(scripts.values.map { it.toJsonObject() }))
                put("dnsRuleMeta", JSONArray(dnsMeta.values.map { it.toJson() }))
                put("ruleMeta", JSONArray(mitmMeta.values.map { it.toJson() }))
                put("scriptIssues", JSONArray(scriptIssues.toList()))
                put("ruleSetIssues", JSONArray(ruleSetIssues.toList()))
                put("generalEffects", JSONObject().apply {
                    put("skipHosts", JSONArray(generalEffects.skipHosts))
                    put("ssidTriggers", JSONArray(generalEffects.ssidTriggers))
                    put("testUrl", generalEffects.testUrl)
                    put("testTimeout", generalEffects.testTimeout)
                    put("forceCloseConnections", generalEffects.forceCloseConnections)
                })
                put("ignoredRules", ignored)
            }.toString(),
        )
    }

    fun writeAtomicPublic(file: File, text: String) = writeAtomic(file, text)

    private fun writeAtomic(file: File, text: String) {
        try {
            file.parentFile?.mkdirs()
            val temporary = File.createTempFile(".${file.name}-", ".tmp", file.parentFile)
            try {
                temporary.writeText(text)
                try {
                    java.nio.file.Files.move(
                        temporary.toPath(), file.toPath(),
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    )
                } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                    java.nio.file.Files.move(temporary.toPath(), file.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                }
            } finally {
                temporary.delete()
            }
        } catch (_: Exception) {
        }
    }

    /** 所有当前会参与本地过滤的规则文件。 */
    fun ruleFiles(context: Context, cfg: AppConfig): List<File> {
        val files = mutableListOf<File>()
        GlobalRuleStore.enabledRuleSets().forEach { src ->
            globalRuleSetFile(context, src.url).takeIf { it.exists() && it.length() > 0 }?.let { files.add(it) }
        }
        File(context.filesDir, "ads_custom.txt").takeIf { it.exists() && it.length() > 0 }?.let { files.add(it) }
        moduleBlockFile(context).takeIf {
            GlobalRuleStore.enabledModules().isNotEmpty() && it.exists() && it.length() > 0
        }?.let { files.add(it) }
        return files
    }
}
