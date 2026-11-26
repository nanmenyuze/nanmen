package com.namu.dns

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.namu.dns.core.config.MitmConfig
import com.namu.dns.core.config.ScriptConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * 3.0.18 壳层重构：规则/模块全局共享。
 *
 * 配置方案只保留 DNS 解析参数；本地规则、独立规则集、DNS 过滤模块、
 * 重写与脚本模块的启停和顺序全局唯一，切换 DNS 配置不影响拦截/分流/HTTPS 改写。
 *
 * 迁移（幂等）：备份旧配置与规则缓存后，把当前方案的规则/模块/顺序/缓存迁到全局；
 * 其他方案独有的规则与模块保留为停用项并标明来源。
 */
object GlobalRuleStore {
    data class MitmContent(
        val urlRewrites: List<String> = emptyList(),
        val headerRewrites: List<String> = emptyList(),
        val loonRewrites: List<String> = emptyList(),
        val bodyRewrites: List<String> = emptyList(),
        val wsRewrites: List<String> = emptyList(),
        val scripts: List<ScriptConfig> = emptyList(),
    ) {
        val isEmpty: Boolean
            get() = urlRewrites.isEmpty() && headerRewrites.isEmpty() && loonRewrites.isEmpty() &&
                bodyRewrites.isEmpty() && wsRewrites.isEmpty() && scripts.isEmpty()

        fun toJson(): JSONObject = JSONObject().apply {
            put("urlRewrites", JSONArray(urlRewrites))
            put("headerRewrites", JSONArray(headerRewrites))
            put("loonRewrites", JSONArray(loonRewrites))
            put("bodyRewrites", JSONArray(bodyRewrites))
            put("wsRewrites", JSONArray(wsRewrites))
            put("scripts", JSONArray(scripts.map { it.toJsonObject() }))
        }

        companion object {
            fun fromJson(o: JSONObject?): MitmContent {
                if (o == null) return MitmContent()
                fun arr(k: String): List<String> {
                    val a = o.optJSONArray(k) ?: return emptyList()
                    return (0 until a.length()).map { a.optString(it) }.filter { it.isNotBlank() }
                }
                val scripts = mutableListOf<ScriptConfig>()
                o.optJSONArray("scripts")?.let { a ->
                    for (i in 0 until a.length()) a.optJSONObject(i)?.let { scripts.add(ScriptConfig.fromJsonObject(it)) }
                }
                return MitmContent(arr("urlRewrites"), arr("headerRewrites"), arr("loonRewrites"), arr("bodyRewrites"), arr("wsRewrites"), scripts)
            }

            fun fromMitm(m: MitmConfig): MitmContent = MitmContent(
                m.urlRewrites, m.headerRewrites, m.loonRewrites, m.bodyRewrites, m.wsRewrites, m.scripts,
            )
        }
    }

    /** HTTPS 解密总开关/应用范围/手动域名：设备级，归设置页。 */
    data class MitmScope(
        val enabled: Boolean = false,
        val hostnames: List<String> = emptyList(),
        val skipHostnames: List<String> = emptyList(),
        val appMode: String = "all",
        val apps: List<String> = emptyList(),
        val poolEnabled: Boolean = false,
        val poolIdleSecs: Long = 30,
    ) {
        fun toJson(): JSONObject = JSONObject().apply {
            put("enabled", enabled)
            put("hostnames", JSONArray(hostnames))
            put("skipHostnames", JSONArray(skipHostnames))
            put("appMode", appMode)
            put("apps", JSONArray(apps))
            put("poolEnabled", poolEnabled)
            put("poolIdleSecs", poolIdleSecs)
        }

        companion object {
            fun fromJson(o: JSONObject?): MitmScope {
                if (o == null) return MitmScope()
                fun arr(k: String): List<String> {
                    val a = o.optJSONArray(k) ?: return emptyList()
                    return (0 until a.length()).map { a.optString(it) }.filter { it.isNotBlank() }
                }
                return MitmScope(
                    o.optBoolean("enabled", false), arr("hostnames"), arr("skipHostnames"),
                    o.optString("appMode", "all"), arr("apps"),
                    o.optBoolean("poolEnabled", false), o.optLong("poolIdleSecs", 30),
                )
            }

            fun fromMitm(m: MitmConfig): MitmScope = MitmScope(
                m.enabled, m.hostnames, m.skipHostnames, m.appMode, m.apps, m.poolEnabled, m.poolIdleSecs,
            )
        }
    }

    /** 其他方案独有的重写/脚本：停用项保留，标明来源，启用后才参与合并。 */
    data class ExtraMitm(
        val id: String,
        val name: String,
        val origin: String,
        val enabled: Boolean = false,
        val order: Int = -1,
        val content: MitmContent = MitmContent(),
    ) {
        fun toJson(): JSONObject = JSONObject().apply {
            put("id", id)
            put("name", name)
            put("origin", origin)
            put("enabled", enabled)
            put("order", order)
            put("content", content.toJson())
        }

        companion object {
            fun fromJson(o: JSONObject) = ExtraMitm(
                o.optString("id"), o.optString("name"), o.optString("origin"),
                o.optBoolean("enabled", false), o.optInt("order", -1),
                MitmContent.fromJson(o.optJSONObject("content")),
            )
        }
    }

    data class State(
        val modules: List<ModuleSource> = emptyList(),
        val ruleSets: List<RuleSource> = emptyList(),
        val localRules: List<RuleItem> = emptyList(),
        val localRulesEnabled: Boolean = true,
        val localAds: List<String> = emptyList(),
        val localMitm: MitmContent = MitmContent(),
        val localMitmEnabled: Boolean = true,
        val extraMitm: List<ExtraMitm> = emptyList(),
        val scope: MitmScope = MitmScope(),
        val scriptArguments: Map<String, Map<String, String>> = emptyMap(),
    ) {
        val localRulesVisible: Boolean get() = localRules.isNotEmpty() || localAds.isNotEmpty()
        val localMitmVisible: Boolean get() = !localMitm.isEmpty

        fun toJson(): JSONObject = JSONObject().apply {
            put("modules", JSONArray(modules.map { it.toJson() }))
            put("ruleSets", JSONArray(ruleSets.map { it.toJson() }))
            put("localRules", JSONArray(localRules.map { it.toJson() }))
            put("localRulesEnabled", localRulesEnabled)
            put("localAds", JSONArray(localAds))
            put("localMitm", localMitm.toJson())
            put("localMitmEnabled", localMitmEnabled)
            put("extraMitm", JSONArray(extraMitm.map { it.toJson() }))
            put("scope", scope.toJson())
            put("scriptArguments", JSONObject().apply {
                scriptArguments.forEach { (k, v) -> put(k, JSONObject(v as Map<*, *>)) }
            })
        }

        companion object {
            fun fromJson(o: JSONObject): State {
                fun <T> arr(k: String, f: (JSONObject) -> T?): List<T> {
                    val a = o.optJSONArray(k) ?: return emptyList()
                    return (0 until a.length()).mapNotNull { a.optJSONObject(it)?.let(f) }
                }
                val args = LinkedHashMap<String, Map<String, String>>()
                o.optJSONObject("scriptArguments")?.let { a ->
                    a.keys().forEach { k ->
                        val v = a.optJSONObject(k) ?: return@forEach
                        val m = LinkedHashMap<String, String>()
                        v.keys().forEach { kk -> m[kk] = v.optString(kk, "") }
                        args[k] = m
                    }
                }
                val adsArray = o.optJSONArray("localAds")
                return State(
                    modules = arr("modules") { ModuleSource.fromJson(it) },
                    ruleSets = arr("ruleSets") { RuleSource.fromJson(it) },
                    localRules = arr("localRules") { RuleItem.fromJson(it) },
                    localRulesEnabled = o.optBoolean("localRulesEnabled", true),
                    localAds = (0 until (adsArray?.length() ?: 0)).mapNotNull {
                        adsArray?.optString(it)
                    }.filter { it.isNotBlank() },
                    localMitm = MitmContent.fromJson(o.optJSONObject("localMitm")),
                    localMitmEnabled = o.optBoolean("localMitmEnabled", true),
                    extraMitm = arr("extraMitm") { ExtraMitm.fromJson(it) },
                    scope = MitmScope.fromJson(o.optJSONObject("scope")),
                    scriptArguments = args,
                )
            }
        }
    }

    /** 模块列表统一显示条目：本地规则置顶（仅显示），其余按 order。 */
    sealed class Entry {
        abstract val id: String
        abstract val name: String
        abstract val enabled: Boolean
        abstract val order: Int

        data class LocalRules(override val enabled: Boolean, val ruleCount: Int, val adsCount: Int) : Entry() {
            override val id = ID_LOCAL_RULES
            override val name = "本地规则"
            override val order = Int.MIN_VALUE
        }

        data class LocalMitm(override val enabled: Boolean, val count: Int) : Entry() {
            override val id = ID_LOCAL_MITM
            override val name = "本地重写与脚本"
            override val order = Int.MIN_VALUE + 1
        }

        data class Remote(val module: ModuleSource) : Entry() {
            override val id = module.id
            override val name = module.name.ifBlank { "模块" }
            override val enabled = module.enabled
            override val order = module.order
        }

        data class RuleSet(val source: RuleSource) : Entry() {
            override val id = ID_RULESET_PREFIX + source.id
            override val name = source.url.substringAfterLast('/').ifBlank { source.url }.take(36)
            override val enabled = source.enabled
            override val order = source.order
        }

        data class Extra(val item: ExtraMitm) : Entry() {
            override val id = item.id
            override val name = item.name
            override val enabled = item.enabled
            override val order = item.order
        }
    }

    const val ID_LOCAL_RULES = "__local_rules__"
    const val ID_LOCAL_MITM = "__local_mitm__"
    const val ID_RULESET_PREFIX = "ruleset:"

    var state by mutableStateOf(State())
        internal set

    fun file(context: Context): File = File(context.filesDir, "global_rules.json")

    fun load(context: Context) {
        state = runCatching { State.fromJson(JSONObject(file(context).readText())) }.getOrDefault(State())
    }

    fun persist(context: Context) {
        ConfigStore.writeAtomicPublic(file(context), state.toJson().toString())
    }

    fun update(context: Context, transform: (State) -> State) {
        state = transform(state)
        persist(context)
    }

    fun orderedModules(): List<ModuleSource> =
        state.modules.withIndex()
            .sortedWith(compareBy({ if (it.value.order >= 0) it.value.order else Int.MAX_VALUE / 2 + it.index }, { it.index }))
            .map { it.value }

    /** 显示序：本地规则/本地重写置顶（置顶只影响显示），其余按 order 稳定排序。 */
    fun displayEntries(): List<Entry> {
        val s = state
        val rest = mutableListOf<Entry>()
        orderedModules().forEach { rest.add(Entry.Remote(it)) }
        s.ruleSets.forEach { rest.add(Entry.RuleSet(it)) }
        s.extraMitm.forEach { rest.add(Entry.Extra(it)) }
        val sorted = rest.withIndex()
            .sortedWith(compareBy({ if (it.value.order >= 0) it.value.order else Int.MAX_VALUE / 2 + it.index }, { it.index }))
            .map { it.value }
        val head = mutableListOf<Entry>()
        if (s.localRulesVisible) head.add(Entry.LocalRules(s.localRulesEnabled, s.localRules.size, s.localAds.size))
        if (s.localMitmVisible) head.add(Entry.LocalMitm(s.localMitmEnabled, mitmCount(s.localMitm)))
        return head + sorted
    }

    fun mitmCount(c: MitmContent): Int =
        c.urlRewrites.size + c.headerRewrites.size + c.loonRewrites.size + c.bodyRewrites.size + c.wsRewrites.size + c.scripts.size

    fun entry(id: String): Entry? = displayEntries().firstOrNull { it.id == id }

    /** 参与合并的启用模块（全局顺序）。 */
    fun enabledModules(): List<ModuleSource> = orderedModules().filter { it.enabled }

    fun enabledRuleSets(): List<RuleSource> = state.ruleSets.filter { it.enabled }

    fun enabledExtraMitm(): List<ExtraMitm> =
        state.extraMitm.filter { it.enabled }
            .sortedWith(compareBy({ if (it.order >= 0) it.order else Int.MAX_VALUE / 2 }, { it.id }))

    // ---------- 迁移 ----------

    fun migrationFlag(context: Context): File = File(context.filesDir, "global_rules_migrated")

    /**
     * 幂等迁移：备份旧配置与规则缓存 → 当前方案规则/模块/顺序/缓存迁全局 →
     * 其他方案独有项停用保留并标来源。重复执行不会重复导入。
     */
    fun migrateIfNeeded(context: Context, config: com.namu.dns.core.repository.ConfigRepository) {
        if (migrationFlag(context).exists()) {
            load(context)
            return
        }
        val dir = context.filesDir
        runCatching {
            val backup = File(dir, "migration_backup")
            backup.mkdirs()
            ConfigStore.baseConfigFile(context).takeIf { it.exists() }?.copyTo(File(backup, "default.json"), overwrite = true)
            File(dir, "configs").listFiles()?.forEach { f ->
                if (f.isFile) runCatching { f.copyTo(File(backup, "profile_${f.name}"), overwrite = true) }
            }
            listOf("modules_block.txt", "modules_rules.json", "modules_mitm.json", "global_rules.json").forEach { n ->
                File(dir, n).takeIf { it.exists() }?.copyTo(File(backup, n), overwrite = true)
            }
            File(dir, "modules").takeIf { it.exists() }?.copyRecursively(File(backup, "modules"), overwrite = true)
            // 规则缓存原件一并备份（全局/ per-profile 哈希缓存与旧单 rulesUrl 缓存）。
            val cacheBackup = File(backup, "rule_cache").apply { mkdirs() }
            dir.listFiles()?.forEach { f ->
                if (f.isFile && (f.name.startsWith("ruleset_") || f.name == "ads_url.txt")) {
                    runCatching { f.copyTo(File(cacheBackup, f.name), overwrite = true) }
                }
            }
        }
        val activeName = config.activeName()
        val active = config.current()
        val others = runCatching {
            config.configFiles().filter { it.name != activeName }.mapNotNull { p ->
                config.loadProfile(p.name)?.let { p.name to it }
            }
        }.getOrDefault(emptyList())
        state = buildMigratedState(active, others)
        // 缓存迁全局：当前方案规则集缓存改全局命名；旧单 rulesUrl 缓存一并接管。
        state.ruleSets.forEach { src ->
            runCatching {
                val from = if (src.id == "legacy-ads-url") ConfigStore.rulesFile(context, src.url, activeName)
                else ConfigStore.ruleSourceFile(context, src, activeName)
                val to = ConfigStore.globalRuleSetFile(context, src.url)
                if (from.length() > 0L && !to.exists()) from.copyTo(to)
            }
        }
        persist(context)
        runCatching { migrationFlag(context).writeText("1") }
    }

    /** 纯函数迁移映射：便于单测验证幂等与来源标注。 */
    fun buildMigratedState(active: AppConfig, others: List<Pair<String, AppConfig>>): State {
        val modules = active.moduleSources.map { it.copy(dnsApproved = true, origin = "") }.toMutableList()
        val baseRuleSets = if (active.ruleSources.isEmpty() && active.rulesUrl.isNotBlank()) {
            listOf(RuleSource(id = "legacy-ads-url", url = active.rulesUrl))
        } else active.ruleSources
        val ruleSets = baseRuleSets.map { it.copy(origin = "") }.toMutableList()
        val localRules = active.rules.toMutableList()
        val localAds = active.customAds.toMutableList()
        val localMitm = MitmContent.fromMitm(active.mitm)
        val extra = mutableListOf<ExtraMitm>()
        val ruleKeys = localRules.map { "${it.type}|${it.value}|${it.action}" }.toMutableSet()
        val moduleIds = modules.map { it.id }.toMutableSet()
        val setIds = ruleSets.map { it.id }.toMutableSet()
        var extraOrder = 100000
        others.forEach { (name, cfg) ->
            cfg.rules.forEach { r ->
                val key = "${r.type}|${r.value}|${r.action}"
                if (ruleKeys.add(key)) localRules.add(r.copy(enabled = false, source = "方案 $name"))
            }
            cfg.customAds.forEach { d ->
                val norm = normalizeAdsDomain(d) ?: return@forEach
                if (norm in localAds) return@forEach
                // 其他方案独有的拦截域名保留为停用规则并标来源，不直接全局启用。
                val key = "DOMAIN-SUFFIX|$norm|block"
                if (ruleKeys.add(key)) {
                    localRules.add(RuleItem("DOMAIN-SUFFIX", norm, "block", source = "方案 $name", enabled = false))
                }
            }
            cfg.moduleSources.forEach { m ->
                if (moduleIds.add(m.id)) modules.add(m.copy(enabled = false, dnsApproved = false, origin = name))
            }
            cfg.ruleSources.forEach { rs ->
                if (setIds.add(rs.id)) ruleSets.add(rs.copy(enabled = false, origin = name))
            }
            val content = MitmContent.fromMitm(cfg.mitm)
            val unique = MitmContent(
                content.urlRewrites.filter { it !in localMitm.urlRewrites },
                content.headerRewrites.filter { it !in localMitm.headerRewrites },
                content.loonRewrites.filter { it !in localMitm.loonRewrites },
                content.bodyRewrites.filter { it !in localMitm.bodyRewrites },
                content.wsRewrites.filter { it !in localMitm.wsRewrites },
                content.scripts.filter { sc -> localMitm.scripts.none { ConfigStore.scriptKey(it) == ConfigStore.scriptKey(sc) } },
            )
            if (!unique.isEmpty) {
                extra.add(ExtraMitm("extra_${name.hashCode().toUInt().toString(16)}", "重写与脚本", name, false, extraOrder++, unique))
            }
        }
        return State(
            modules = modules,
            ruleSets = ruleSets,
            localRules = localRules,
            localAds = localAds,
            localMitm = localMitm,
            extraMitm = extra,
            scope = MitmScope.fromMitm(active.mitm),
            scriptArguments = active.mitm.scriptArguments,
        )
    }
}