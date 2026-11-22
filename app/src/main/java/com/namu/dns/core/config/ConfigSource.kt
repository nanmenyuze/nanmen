package com.namu.dns.core.config

import com.namu.dns.AppConfig
import com.namu.dns.NodeInfo
import com.namu.dns.ProxyGroup
import com.namu.dns.RuleItem
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.json.JSONObject

/**
 * M2 配置来源抽象：识别 -> 诊断 -> 预览 -> 可选导入。
 *
 * 只有 NativeJsonParser 会把文本文档转换成 ConfigFile 并允许落入配置仓库；
 * Clash/Loon/小火箭解析器先提供识别、计数、错误引用定位和未知段保留，
 * 避免“只要 YAML/段落能解析就立刻启用”。
 */
enum class ConfigFormat(val label: String) {
    NATIVE("南门DNS 原生 JSON"),
    CLASH("Clash YAML"),
    LOON("Loon .conf"),
    SHADOWROCKET("小火箭 .conf"),
    UNKNOWN("无法识别"),
}

enum class ConfigIssueLevel { INFO, WARNING, ERROR }

data class ConfigIssue(
    val level: ConfigIssueLevel,
    /** 可定位的 JSON 路径或段落行，如 `ruleSources[1].id`、`[Rule] line 12`。 */
    val path: String,
    val message: String,
)

data class ConfigSourcePreview(
    val format: ConfigFormat,
    val displayName: String,
    val modelVersion: Int = 0,
    val canImport: Boolean = false,
    val supported: List<String> = emptyList(),
    val partial: List<String> = emptyList(),
    val skipped: List<String> = emptyList(),
    val unknown: List<String> = emptyList(),
    val issues: List<ConfigIssue> = emptyList(),
    val nodes: Int = 0,
    val groups: Int = 0,
    val rules: Int = 0,
    val modules: Int = 0,
    val mitmRules: Int = 0,
    val rawBytes: Int = 0,
    val reason: String = "",
) {
    val errors: List<ConfigIssue> get() = issues.filter { it.level == ConfigIssueLevel.ERROR }
    val warnings: List<ConfigIssue> get() = issues.filter { it.level == ConfigIssueLevel.WARNING }
}

data class ConfigSourceResult(
    val preview: ConfigSourcePreview,
    /** 可导入配置；Loon/小火箭/Clash 解析成功时也有值。 */
    val config: ConfigFile? = null,
    /** 配置内联节点；M4 起 Loon/小火箭会把节点导入设备节点列表。 */
    val nodes: List<NodeInfo> = emptyList(),
)

interface ConfigSourceParser {
    val format: ConfigFormat
    fun score(text: String): Int
    fun parse(text: String, fallback: AppConfig): ConfigSourceResult
}

object ConfigSourceRegistry {
    private val parsers = listOf(
        NativeJsonParser,
        ClashConfigParser,
        LoonConfigParser,
        ShadowrocketConfigParser,
    )

    fun preview(text: String, fallback: AppConfig = AppConfig()): ConfigSourcePreview =
        parse(text, fallback).preview

    fun parse(text: String, fallback: AppConfig = AppConfig()): ConfigSourceResult {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) {
            return ConfigSourceResult(
                ConfigSourcePreview(
                    format = ConfigFormat.UNKNOWN,
                    displayName = "空内容",
                    canImport = false,
                    issues = listOf(ConfigIssue(ConfigIssueLevel.ERROR, "$", "配置内容为空")),
                ),
            )
        }
        val chosen = parsers.maxByOrNull { it.score(trimmed) }
        val result = chosen?.parse(trimmed, fallback)
        if (result != null && chosen.score(trimmed) > 0) return result
        return ConfigSourceResult(
            ConfigSourcePreview(
                format = ConfigFormat.UNKNOWN,
                displayName = "未知配置格式",
                canImport = false,
                rawBytes = trimmed.length,
                issues = listOf(
                    ConfigIssue(ConfigIssueLevel.ERROR, "$", "不是原生 JSON、Clash YAML、Loon 或小火箭配置"),
                ),
            ),
        )
    }
}

private object NativeJsonParser : ConfigSourceParser {
    override val format = ConfigFormat.NATIVE

    override fun score(text: String): Int {
        if (!text.startsWith("{")) return 0
        return try {
            val root = JSONObject(text)
            when {
                root.has("general") -> 100
                root.has("dnsUpstream") || root.has("mode") || root.has("rules") -> 90
                else -> 10
            }
        } catch (_: Exception) {
            5
        }
    }

    override fun parse(text: String, fallback: AppConfig): ConfigSourceResult {
        val cfg = ConfigFile.fromExternal(text, fallback)
        if (cfg == null) {
            return ConfigSourceResult(
                ConfigSourcePreview(
                    format = format,
                    displayName = "原生 JSON（解析失败）",
                    canImport = false,
                    rawBytes = text.length,
                    issues = listOf(ConfigIssue(ConfigIssueLevel.ERROR, "$", "JSON 结构或字段无效")),
                ),
            )
        }
        val issues = mutableListOf<ConfigIssue>()
        val supported = mutableListOf<String>()
        val partial = mutableListOf<String>()
        val unknown = cfg.unknownRoot.keys.toList().sorted()
        if (cfg.modelVersion < ConfigFile.CURRENT_VERSION) {
            issues += ConfigIssue(
                ConfigIssueLevel.WARNING,
                "version",
                "旧模型 v${cfg.modelVersion}，保存时迁移到 v${ConfigFile.CURRENT_VERSION}",
            )
        }
        supported += "general"
        if (cfg.rules.isNotEmpty()) supported += "rules(${cfg.rules.size})"
        if (cfg.proxyGroups.isNotEmpty()) {
            supported += "proxyGroups(${cfg.proxyGroups.size})"
            val groupIssues = ProxyGroupValidation.validate(
                cfg.proxyGroups,
                fallback.nodes.map { it.name },
                emptyMap(),
            )
            issues += groupIssues
        }
        if (cfg.ruleSources.isNotEmpty()) supported += "ruleSources(${cfg.ruleSources.size})"
        if (cfg.modules.isNotEmpty()) supported += "modules(${cfg.modules.size})"
        if (cfg.customAds.isNotEmpty()) supported += "customAds(${cfg.customAds.size})"
        if (cfg.mitm.hostnames.isNotEmpty() || cfg.mitm.urlRewrites.isNotEmpty() || cfg.mitm.headerRewrites.isNotEmpty()) {
            supported += "mitm"
        } else {
            partial += "mitm(空)"
        }
        if (unknown.isNotEmpty()) {
            partial += "未知根字段 ${unknown.size} 个（原文保留）"
        }
        // 重复名称/引用定位
        cfg.ruleSources.forEachIndexed { i, src ->
            if (src.id.isBlank()) issues += ConfigIssue(ConfigIssueLevel.ERROR, "ruleSources[$i].id", "规则源 id 为空")
            if (src.url.isBlank()) issues += ConfigIssue(ConfigIssueLevel.ERROR, "ruleSources[$i].url", "规则源 URL 为空")
        }
        duplicates(cfg.ruleSources.map { it.id }).forEach {
            issues += ConfigIssue(ConfigIssueLevel.ERROR, "ruleSources", "重复规则源 id：$it")
        }
        cfg.modules.forEachIndexed { i, m ->
            if (m.id.isBlank()) issues += ConfigIssue(ConfigIssueLevel.ERROR, "modules[$i].id", "模块 id 为空")
            if (m.url.isBlank()) issues += ConfigIssue(ConfigIssueLevel.ERROR, "modules[$i].url", "模块 URL 为空")
        }
        duplicates(cfg.modules.map { it.id }).forEach {
            issues += ConfigIssue(ConfigIssueLevel.ERROR, "modules", "重复模块 id：$it")
        }
        duplicates(cfg.customAds).forEach {
            issues += ConfigIssue(ConfigIssueLevel.WARNING, "customAds", "重复自定义域名：$it")
        }
        duplicates(cfg.rules.map { "${it.type}|${it.value}|${it.action}" }).forEach {
            issues += ConfigIssue(ConfigIssueLevel.WARNING, "rules", "重复规则：$it")
        }
        return ConfigSourceResult(
            preview = ConfigSourcePreview(
                format = format,
                displayName = "南门DNS 原生配置 v${cfg.modelVersion}",
                modelVersion = cfg.modelVersion,
                canImport = issues.none { it.level == ConfigIssueLevel.ERROR },
                supported = supported,
                partial = partial,
                unknown = unknown,
                issues = issues,
                rules = cfg.rules.size,
                modules = cfg.modules.size,
                mitmRules = cfg.mitm.hostnames.size + cfg.mitm.urlRewrites.size + cfg.mitm.headerRewrites.size,
                rawBytes = text.length,
                reason = "可导入；未知根字段会随配置保存",
            ),
            config = cfg,
        )
    }

    private fun duplicates(values: List<String>): List<String> =
        values.filter { it.isNotBlank() }.groupingBy { it }.eachCount().filter { it.value > 1 }.keys.toList()
}

private object ClashConfigParser : ConfigSourceParser {
    override val format = ConfigFormat.CLASH

    override fun score(text: String): Int {
        var score = 0
        if (Regex("(?m)^\\s*proxies:").containsMatchIn(text)) score += 40
        if (Regex("(?m)^\\s*proxy-groups:").containsMatchIn(text)) score += 30
        if (Regex("(?m)^\\s*rules:").containsMatchIn(text)) score += 20
        if (Regex("(?m)^\\s*mixed-port:").containsMatchIn(text)) score += 10
        return score
    }

    override fun parse(text: String, fallback: AppConfig): ConfigSourceResult {
        val sectionLines = text.lineSequence().toList()
        val sections = mutableMapOf<String, Int>()
        val proxies = mutableListOf<String>()
        val groups = mutableListOf<String>()
        val groupTypes = mutableMapOf<String, String>()
        val groupMembers = linkedMapOf<String, MutableList<String>>()
        val rules = mutableListOf<String>()
        var section = ""
        var group = ""
        sectionLines.forEach { raw ->
            val line = raw.trimEnd()
            val top = Regex("^([A-Za-z0-9_-]+):\\s*$").find(line)?.groupValues?.get(1)
            if (top != null) {
                section = top
                sections[top] = (sections[top] ?: 0) + 1
                group = ""
                return@forEach
            }
            if (section == "proxies" && line.trimStart().startsWith("- ")) {
                val name = Regex("name\\s*:\\s*[\"']?([^\"',}]+)").find(line)?.groupValues?.get(1)?.trim()
                if (!name.isNullOrBlank()) proxies += name
            } else if (section == "proxy-groups") {
                val item = Regex("^\\s*-\\s*name\\s*:\\s*[\"']?([^\"',}]+)").find(line)?.groupValues?.get(1)?.trim()
                if (!item.isNullOrBlank()) {
                    groups += item
                    group = item
                    groupMembers.getOrPut(item) { mutableListOf() }
                } else if (group.isNotBlank()) {
                    val trimmed = line.trim()
                    if (trimmed.startsWith("type:")) {
                        groupTypes[group] = trimmed.removePrefix("type:").trim().trim('"', '\'').lowercase()
                    } else if (trimmed.startsWith("- ")) {
                        val member = trimmed.removePrefix("- ").trim().trim('"', '\'')
                        if (member.isNotBlank()) groupMembers.getOrPut(group) { mutableListOf() } += member
                    }
                }
            } else if (section == "rules" && line.trimStart().startsWith("- ")) {
                rules += line.trim().removePrefix("- ").trim()
            }
        }
        val issues = mutableListOf<ConfigIssue>()
        duplicates(proxies).forEach { issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxies", "重复节点名：$it") }
        duplicates(groups).forEach { issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxy-groups", "重复策略组名：$it") }
        val names = (proxies + groups).toSet()
        groupMembers.forEach { (g, members) ->
            val builtins = members.filter { it.equals("DIRECT", true) || it.equals("REJECT", true) || it.equals("PROXY", true) }
            if (builtins.isNotEmpty()) {
                issues += ConfigIssue(ConfigIssueLevel.WARNING, "proxy-groups[$g]", "组内内置策略 ${builtins.joinToString()} 未作为成员导入")
            }
            members.forEachIndexed { index, member ->
                if (member !in names && member !in builtins) {
                    issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxy-groups[$g].proxies[$index]", "引用不存在的节点/策略组：$member")
                }
            }
        }
        val groupDefs = groups.mapNotNull { name ->
            val members = groupMembers[name].orEmpty()
                .filterNot { it.equals("DIRECT", true) || it.equals("REJECT", true) || it.equals("PROXY", true) }
                .distinct()
            if (members.isEmpty()) {
                issues += ConfigIssue(ConfigIssueLevel.WARNING, "proxy-groups[$name]", "空策略组已跳过")
                null
            } else {
                ProxyGroup(
                    name = name,
                    type = when (groupTypes[name]) {
                        "url-test", "urltest" -> "url-test"
                        "fallback" -> "fallback"
                        else -> "select"
                    },
                    members = members,
                )
            }
        }
        val known = setOf(
            "port", "socks-port", "mixed-port", "allow-lan", "mode", "log-level",
            "external-controller", "dns", "proxies", "proxy-groups", "rules", "tun",
        )
        val unknown = sections.keys.filter { it !in known }.sorted()
        // Clash 已实现子集：把规则/策略组/DNS 模式和 final 目标转成原生配置；
        // proxies 仍属于设备节点列表，不写进 .conf，节点走订阅导入。
        val mode = Regex("(?m)^mode\\s*:\\s*([A-Za-z]+)").find(text)
            ?.groupValues?.get(1)?.lowercase()
            ?.let { if (it == "global" || it == "direct" || it == "rule") it else "rule" }
            ?: "rule"
        var finalPolicy = "proxy"
        val nativeRules = mutableListOf<RuleItem>()
        var unsupportedRuleCount = 0
        fun actionOf(raw: String, path: String): String {
            return when {
                // 组名优先，兼容名为 Proxy 的默认策略组。
                raw in groups -> raw
                raw in proxies -> "node:$raw"
                raw.equals("DIRECT", true) -> "direct"
                raw.equals("REJECT", true) || raw.equals("REJECT-DROP", true) -> "block"
                raw.equals("PROXY", true) -> "proxy"
                else -> {
                    issues += ConfigIssue(ConfigIssueLevel.WARNING, path, "目标策略未定义：$raw，按 proxy 导入")
                    "proxy"
                }
            }
        }
        rules.forEachIndexed { index, line ->
            val parts = line.split(',')
            if (parts.size < 2) {
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "rules[$index]", "规则格式无效：$line")
                return@forEachIndexed
            }
            val kind = parts[0].trim().uppercase()
            if (kind == "MATCH" || kind == "FINAL") {
                finalPolicy = actionOf(parts.getOrNull(1)?.trim().orEmpty(), "rules[$index]")
                return@forEachIndexed
            }
            val value = parts.getOrNull(1)?.trim().orEmpty()
            val type = when (kind) {
                "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD",
                "IP-CIDR", "IP-CIDR6", "GEOIP", "PORT" -> kind
                else -> null
            }
            if (type == null || value.isBlank()) {
                unsupportedRuleCount++
            } else {
                nativeRules += RuleItem(
                    type = type,
                    value = value,
                    action = actionOf(parts.getOrNull(2)?.trim().orEmpty(), "rules[$index]"),
                    source = "Clash 导入",
                )
            }
        }
        if (nativeRules.isEmpty() && groupDefs.isEmpty()) {
            issues += ConfigIssue(ConfigIssueLevel.ERROR, "rules", "没有可导入的受支持规则或策略组")
        }
        if (unsupportedRuleCount > 0) {
            issues += ConfigIssue(ConfigIssueLevel.WARNING, "rules", "跳过 $unsupportedRuleCount 条未实现规则")
        }
        val canImport = issues.none { it.level == ConfigIssueLevel.ERROR }
        val config = if (canImport) {
            ConfigFile(
                modelVersion = ConfigFile.CURRENT_VERSION,
                general = GeneralConfig(mode = mode, finalPolicy = finalPolicy),
                rules = nativeRules.distinctBy { "${it.type}|${it.value}|${it.action}" },
                proxyGroups = groupDefs,
                sourceFormat = ConfigFile.SOURCE_CLASH,
            )
        } else null
        return ConfigSourceResult(
            preview = ConfigSourcePreview(
                format = format,
                displayName = "Clash 配置（规则/策略组可导入）",
                modelVersion = ConfigFile.CURRENT_VERSION,
                canImport = canImport,
                supported = listOf(
                    "proxies(${proxies.size})",
                    "proxy-groups(${groupDefs.size})",
                    "rules(${nativeRules.size})",
                ),
                partial = listOf("dns", "tun", "节点仍走订阅导入；组目标已保留为策略组名"),
                skipped = listOf("script", "rule-providers", "listeners", "experimental"),
                unknown = unknown,
                issues = issues,
                nodes = proxies.size,
                groups = groupDefs.size,
                rules = nativeRules.size,
                mitmRules = 0,
                rawBytes = text.length,
                reason = if (canImport) {
                    "已导入规则/策略组；proxies 节点不写入配置文件，请用订阅导入节点"
                } else {
                    "存在错误引用/重复名称/无可用规则或策略组，修正后才能导入"
                },
            ),
            config = config,
        )
    }
}

private object LoonConfigParser : ConfigSourceParser {
    override val format = ConfigFormat.LOON

    override fun score(text: String): Int {
        if (Regex("(?m)^\\[URL Rewrite\\]").containsMatchIn(text)) return 55
        return if (Regex("(?m)^\\[(General|Proxy|Rule|MITM)\\]").containsMatchIn(text)) 80 else 0
    }

    override fun parse(text: String, fallback: AppConfig): ConfigSourceResult =
        parseSectionConfig(text, format, "Loon 配置（节点/组/规则/DNS 导入）", loon = true)
}

private object ShadowrocketConfigParser : ConfigSourceParser {
    override val format = ConfigFormat.SHADOWROCKET

    override fun score(text: String): Int {
        if (Regex("(?m)^\\[URL Rewrite\\]").containsMatchIn(text)) return 90
        return if (Regex("(?m)^\\[(General|Proxy|Rule|MITM)\\]").containsMatchIn(text)) 75 else 0
    }

    override fun parse(text: String, fallback: AppConfig): ConfigSourceResult =
        parseSectionConfig(text, format, "小火箭配置（节点/组/规则/DNS 导入）", loon = false)
}

private fun parseSectionConfig(
    text: String,
    format: ConfigFormat,
    displayName: String,
    loon: Boolean,
): ConfigSourceResult {
    val issues = mutableListOf<ConfigIssue>()
    val sections = mutableListOf<String>()
    val unknownSections = mutableListOf<String>()
    val nodes = mutableListOf<NodeInfo>()
    val groupBuilders = linkedMapOf<String, ProxyGroupBuilder>()
    val rawRules = mutableListOf<Pair<Int, String>>()
    val hostMappings = linkedMapOf<String, String>()
    var section = ""
    var lineNo = 0
    var dnsUpstream = ""
    var dnsFallback = ""
    var blockAaaa = false
    var finalPolicy = "proxy"

    fun options(parts: List<String>): Map<String, String> =
        parts.mapNotNull { token ->
            val i = token.indexOf('=')
            if (i <= 0) null else token.substring(0, i).trim().lowercase() to token.substring(i + 1).trim().trim('"', '\'')
        }.toMap()

    text.lineSequence().forEach { raw ->
        lineNo++
        val line = raw.trim()
        if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) return@forEach
        if (line.startsWith("[") && line.endsWith("]")) {
            section = line.substring(1, line.length - 1).trim()
            sections += section
            return@forEach
        }
        val lower = section.lowercase()
        if (lower == "general") {
            val i = line.indexOf('=')
            if (i <= 0) return@forEach
            val key = line.substring(0, i).trim().lowercase()
            val value = line.substring(i + 1).trim().trim('"', '\'')
            when (key) {
                "dns-server", "doh-server", "dns-over-https" -> {
                    if (dnsUpstream.isBlank() && value.isNotBlank()) {
                        dnsUpstream = normalizeDnsUpstream(value.substringBefore(',').trim())
                    }
                    if (value.contains(',')) {
                        issues += ConfigIssue(ConfigIssueLevel.INFO, "[General] line $lineNo", "仅使用第一个 DNS 上游；后备请用 dns-fallback")
                    }
                }
                "dns-fallback" -> if (dnsFallback.isBlank()) dnsFallback = value.substringBefore(',').trim()
                "ipv6" -> if (value.equals("false", true) || value == "0") blockAaaa = true
            }
            return@forEach
        }
        if (lower == "proxy") {
            val i = line.indexOf('=')
            if (i <= 0) return@forEach
            val name = line.substring(0, i).trim()
            val parts = splitCsv(line.substring(i + 1))
            val parsed = parseLoonNode(name, parts, lineNo, issues)
            if (parsed != null) nodes += parsed
            return@forEach
        }
        if (lower == "proxy group") {
            val i = line.indexOf('=')
            if (i <= 0) return@forEach
            val name = line.substring(0, i).trim()
            val parts = splitCsv(line.substring(i + 1))
            if (parts.isEmpty()) return@forEach
            val type = parts[0].trim().lowercase()
            if (type !in setOf("select", "url-test", "fallback", "load-balance")) {
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "[Proxy Group] line $lineNo", "未知策略组类型：${parts[0]}")
                return@forEach
            }
            val rawMembers = parts.drop(1).map { it.trim() }.filter { it.isNotBlank() && !it.contains('=') }
            val members = rawMembers.filterNot {
                it.equals("DIRECT", true) || it.equals("REJECT", true) || it.equals("PROXY", true)
            }
            val opt = options(parts.drop(1))
            groupBuilders[name] = ProxyGroupBuilder(
                name = name,
                type = type,
                members = members,
                testUrl = opt["url"] ?: opt["test-url"] ?: "http://www.gstatic.com/generate_204",
                interval = opt["interval"]?.toIntOrNull() ?: 600,
                timeout = opt["timeout"]?.toIntOrNull() ?: 5000,
                tolerance = opt["tolerance"]?.toIntOrNull() ?: 50,
                failureThreshold = opt["failure-threshold"]?.toIntOrNull() ?: 3,
                recoveryThreshold = opt["recovery-threshold"]?.toIntOrNull() ?: 2,
                noNodeAction = opt["no-node-action"] ?: "global",
                lbMode = opt["strategy"] ?: opt["lb-mode"] ?: opt["lbmode"] ?: "consistent-hash",
                switchInterval = opt["switch-interval"]?.toIntOrNull() ?: 30,
            )
            return@forEach
        }
        if (lower == "host") {
            val i = line.indexOf('=')
            if (i > 0) {
                val key = line.substring(0, i).trim().lowercase().trim('.')
                val value = line.substring(i + 1).trim()
                if (key.isNotBlank() && value.isNotBlank()) hostMappings[key] = value
            }
            return@forEach
        }
        if (lower == "rule") {
            rawRules += lineNo to line
        }
    }

    val nodeNames = nodes.map { it.name }.toSet()
    val groupNames = groupBuilders.keys
    val groupDefs = groupBuilders.values.map { it.toProxyGroup() }.filter { it.members.isNotEmpty() }
    val nativeRules = mutableListOf<RuleItem>()
    var skippedRules = 0
    var appRules = 0
    rawRules.forEach { (line, raw) ->
        val parts = splitCsv(raw)
        if (parts.size < 2) {
            issues += ConfigIssue(ConfigIssueLevel.ERROR, "[Rule] line $line", "规则格式无效：$raw")
            return@forEach
        }
        val kind = parts[0].trim().uppercase()
        if (kind == "FINAL" || kind == "MATCH") {
            val target = parts.last().trim()
            if (target.isNotBlank()) finalPolicy = targetAction(target, nodeNames, groupNames, issues, "[Rule] line $line")
            return@forEach
        }
        // 按 App 分流：UID 用数值直接下发；包名类规则保留包名，等内核启动前
        // 由壳层用 PackageManager 解析成 UID 再展开（换机/重装后才能自动重解析）。
        if (kind in setOf("UID", "PROCESS-NAME", "APP", "APP-NAME")) {
            val value = parts.drop(1).dropLast(1).joinToString(",").trim()
            if (value.isBlank()) {
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "[Rule] line $line", "规则缺少值")
                return@forEach
            }
            if (kind == "UID" && value.toIntOrNull() == null) {
                issues += ConfigIssue(
                    ConfigIssueLevel.ERROR,
                    "[Rule] line $line",
                    "UID 规则的值必须是数字：$value",
                )
                return@forEach
            }
            val action = targetAction(parts.last().trim(), nodeNames, groupNames, issues, "[Rule] line $line")
            nativeRules += RuleItem(type = kind, value = value, action = action, source = "[Rule]")
            appRules++
            return@forEach
        }
        if (kind == "PROCESS-PATH") {
            appRules++
            issues += ConfigIssue(
                ConfigIssueLevel.WARNING,
                "[Rule] line $line",
                "PROCESS-PATH 需要路径到包名的映射，尚未支持，已跳过",
            )
            return@forEach
        }
        val type = when (kind) {
            "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD",
            "IP-CIDR", "IP-CIDR6", "GEOIP", "PORT" -> kind
            else -> null
        }
        if (type == null) {
            skippedRules++
            issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Rule] line $line", "跳过未实现规则类型：$kind")
            return@forEach
        }
        val valueParts = parts.drop(1).dropLast(1)
        if (valueParts.isEmpty() || valueParts.joinToString(",").isBlank()) {
            issues += ConfigIssue(ConfigIssueLevel.ERROR, "[Rule] line $line", "规则缺少值")
            return@forEach
        }
        val target = parts.last().trim()
        val action = targetAction(target, nodeNames, groupNames, issues, "[Rule] line $line")
        nativeRules += RuleItem(type = type, value = valueParts.joinToString(",").trim(), action = action, source = "[Rule]")
    }

    val knownSections = if (loon) {
        setOf("General", "Proxy", "Proxy Group", "Rule", "MITM", "Rewrite", "URL Rewrite", "Header Rewrite", "Host")
    } else {
        setOf("General", "Proxy", "Proxy Group", "Rule", "MITM", "URL Rewrite", "Header Rewrite", "Host")
    }
    sections.distinct().forEach { if (it !in knownSections) unknownSections += it }
    val supported = mutableListOf<String>()
    if (nodes.isNotEmpty()) supported += "Proxy(${nodes.size})"
    if (groupDefs.isNotEmpty()) supported += "Proxy Group(${groupDefs.size})"
    if (nativeRules.isNotEmpty()) supported += "Rule(${nativeRules.size})"
    if (dnsUpstream.isNotBlank() || dnsFallback.isNotBlank()) supported += "DNS"
    val partial = mutableListOf<String>()
    val skipped = mutableListOf<String>()
    sections.distinct().forEach {
        when (it) {
            "Proxy", "Proxy Group", "Rule" -> Unit
            "General" -> if (dnsUpstream.isBlank() && dnsFallback.isBlank()) partial += "[General] 未找到 dns-server/doh-server"
            "MITM" -> partial += "[MITM] 配置已识别，MITM 需在 MITM 页面单独启用"
            "URL Rewrite", "Header Rewrite" -> partial += "[$it] 仅识别，未自动启用"
            "Host" -> if (hostMappings.isNotEmpty()) supported += "Host(${hostMappings.size})" else partial += "[Host] 未找到映射"
            "Rewrite", "Script" -> skipped += "[$it]"
        }
    }
    if (appRules > 0) supported += "按 App 规则($appRules 条)"
    if (skippedRules > 0) skipped += "未实现规则 $skippedRules 条"
    val errors = issues.any { it.level == ConfigIssueLevel.ERROR }
    val canImport = !errors && (nodes.isNotEmpty() || groupDefs.isNotEmpty() || nativeRules.isNotEmpty())
    val config = if (canImport) {
        ConfigFile(
            modelVersion = ConfigFile.CURRENT_VERSION,
            general = GeneralConfig(
                mode = "rule",
                dnsUpstream = dnsUpstream.ifBlank { "system" },
                dnsFallback = dnsFallback.ifBlank { "system" },
                blockAaaa = blockAaaa,
                finalPolicy = finalPolicy,
            ),
            rules = nativeRules.distinctBy { "${it.type}|${it.value}|${it.action}" },
            proxyGroups = groupDefs,
            mitm = MitmConfig(hostMappings = hostMappings),
            sourceFormat = if (loon) ConfigFile.SOURCE_LOON else ConfigFile.SOURCE_SHADOWROCKET,
            unknownRoot = buildJsonObject {
                if (unknownSections.isNotEmpty()) put("sourceUnknownSections", JsonPrimitive(unknownSections.joinToString(",")))
            },
        )
    } else null
    return ConfigSourceResult(
        preview = ConfigSourcePreview(
            format = format,
            displayName = displayName,
            modelVersion = ConfigFile.CURRENT_VERSION,
            canImport = canImport,
            supported = supported,
            partial = partial,
            skipped = skipped,
            unknown = unknownSections,
            issues = issues,
            nodes = nodes.size,
            groups = groupDefs.size,
            rules = nativeRules.size,
            rawBytes = text.length,
            reason = if (canImport) {
                "可导入节点/策略组/规则/DNS；未知段落保留在 sourceUnknownSections"
            } else {
                "没有可导入内容或存在应用/UID 规则错误；不会启用"
            },
        ),
        config = config,
        nodes = nodes,
    )
}

private data class ProxyGroupBuilder(
    val name: String,
    val type: String,
    val members: List<String>,
    val testUrl: String,
    val interval: Int,
    val timeout: Int,
    val tolerance: Int,
    val failureThreshold: Int,
    val recoveryThreshold: Int,
    val noNodeAction: String,
    val lbMode: String,
    val switchInterval: Int,
) {
    fun toProxyGroup(): ProxyGroup = ProxyGroup(
        name = name,
        type = type,
        members = members,
        testUrl = testUrl,
        interval = interval,
        timeout = timeout,
        tolerance = tolerance,
        failureThreshold = failureThreshold,
        recoveryThreshold = recoveryThreshold,
        noNodeAction = noNodeAction,
        lbMode = lbMode,
        switchInterval = switchInterval,
    )
}

private fun splitCsv(raw: String): List<String> =
    raw.split(',').map { it.trim().trim('"', '\'') }

private fun normalizeDnsUpstream(raw: String): String {
    val v = raw.trim()
    if (v.isBlank() || v.equals("system", true)) return ""
    return when {
        v.startsWith("http://") || v.startsWith("https://") || v.startsWith("udp://") ||
            v.startsWith("tcp://") || v.startsWith("tls://") || v.startsWith("quic://") -> v
        v.contains(':') && !v.contains('/') -> "udp://$v"
        else -> v
    }
}

private fun targetAction(
    target: String,
    nodeNames: Set<String>,
    groupNames: Set<String>,
    issues: MutableList<ConfigIssue>,
    path: String,
): String {
    val t = target.trim()
    return when {
        // 组名优先：Loon/Clash 常把默认组直接命名为 Proxy。
        t in groupNames -> t
        t in nodeNames -> "node:$t"
        t.equals("DIRECT", true) -> "direct"
        t.equals("REJECT", true) || t.equals("REJECT-DROP", true) -> "block"
        t.equals("PROXY", true) -> "proxy"
        else -> {
            issues += ConfigIssue(ConfigIssueLevel.WARNING, path, "目标策略未定义：$t，按 proxy 导入")
            "proxy"
        }
    }
}

private fun parseLoonNode(
    name: String,
    parts: List<String>,
    line: Int,
    issues: MutableList<ConfigIssue>,
): NodeInfo? {
    if (name.isBlank() || parts.isEmpty()) return null
    val typeRaw = parts[0].trim().lowercase()
    val server = parts.getOrNull(1)?.trim().orEmpty()
    val port = parts.getOrNull(2)?.toIntOrNull() ?: 0
    if (server.isBlank() || port !in 1..65535) {
        issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Proxy] line $line", "节点 $name 缺少有效 server/port")
        return null
    }
    val opts = parts.drop(3).mapNotNull { token ->
        val i = token.indexOf('=')
        if (i <= 0) null else token.substring(0, i).trim().lowercase() to token.substring(i + 1).trim().trim('"', '\'')
    }.toMap()
    val type = when (typeRaw) {
        "ss", "shadowsocks" -> "ss"
        "trojan" -> "trojan"
        "vless" -> "vless"
        "vmess" -> "vmess"
        "socks5", "socks" -> "socks5"
        "http", "https" -> "http"
        else -> {
            issues += ConfigIssue(
                ConfigIssueLevel.WARNING,
                "[Proxy] line $line",
                "$typeRaw 协议未实现，已跳过（Reality/Hysteria2/TUIC 需单独排期）",
            )
            return null
        }
    }
    if (opts["plugin"].orEmpty().isNotBlank()) {
        issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Proxy] line $line", "SS SIP003 plugin 未实现，已跳过 $name")
        return null
    }
    if (opts["security"].equals("reality", true) || opts["reality"].orEmpty().isNotBlank()) {
        issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Proxy] line $line", "VLESS/Trojan Reality 未实现，已跳过 $name")
        return null
    }
    val flow = opts["flow"].orEmpty()
    if (flow.isNotBlank()) {
        issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Proxy] line $line", "XTLS flow=$flow 未实现，已跳过 $name")
        return null
    }
    val transport = opts["transport"] ?: opts["network"] ?: opts["type"] ?: "tcp"
    val ws = transport.equals("ws", true) || transport.equals("websocket", true)
    if (transport !in setOf("tcp", "ws", "websocket")) {
        issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Proxy] line $line", "$type 传输 $transport 未实现，已跳过 $name")
        return null
    }
    val tls = when (type) {
        "trojan" -> opts["tls"]?.let { it != "false" && it != "0" } ?: true
        "vless" -> opts["security"]?.let { it.equals("tls", true) || it.equals("xtls", true) }
            ?: opts["tls"]?.let { it != "false" && it != "0" } ?: false
        "vmess" -> opts["security"]?.let { it.equals("tls", true) }
            ?: opts["tls"]?.let { it != "false" && it != "0" } ?: false
        "http" -> typeRaw == "https" || opts["tls"]?.let { it != "false" } == true
        else -> false
    }
    val node = when (type) {
        "ss" -> NodeInfo(
            name = name, type = "ss", server = server, port = port,
            method = parts.getOrNull(3)?.takeIf { it.isNotBlank() } ?: "aes-128-gcm",
            password = parts.getOrNull(4)?.takeIf { it.isNotBlank() } ?: opts["password"],
            tls = false,
        )
        "trojan" -> NodeInfo(
            name = name, type = "trojan", server = server, port = port,
            password = parts.getOrNull(3)?.takeIf { it.isNotBlank() } ?: opts["password"],
            sni = opts["sni"] ?: opts["peer"], insecure = opts["skip-cert-verify"] == "true",
            tls = true, wsPath = if (ws) opts["path"] ?: "/" else null,
            wsHost = if (ws) opts["host"] else null,
        )
        "vless" -> {
            val uuid = parts.getOrNull(3)?.takeIf { it.isNotBlank() } ?: opts["uuid"]
            if (uuid.isNullOrBlank()) {
                issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Proxy] line $line", "VLESS 缺少 UUID，已跳过 $name")
                return null
            }
            NodeInfo(
                name = name, type = "vless", server = server, port = port, uuid = uuid,
                sni = opts["sni"] ?: opts["servername"], insecure = opts["allowinsecure"] == "1" || opts["skip-cert-verify"] == "true",
                tls = tls, wsPath = if (ws) opts["path"] ?: "/" else null,
                wsHost = if (ws) opts["host"] else null,
            )
        }
        "vmess" -> {
            val uuid = parts.getOrNull(3)?.takeIf { it.isNotBlank() && !it.contains('=') } ?: opts["uuid"] ?: opts["username"]
            if (uuid.isNullOrBlank()) {
                issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Proxy] line $line", "VMess 缺少 UUID，已跳过 $name")
                return null
            }
            val aid = opts["alterid"]?.toIntOrNull() ?: 0
            if (aid > 0) {
                issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Proxy] line $line", "VMess 不支持 alterId>0，已跳过 $name")
                return null
            }
            val cipher = opts["cipher"] ?: "auto"
            if (cipher !in setOf("auto", "aes-128-gcm", "chacha20-poly1305")) {
                issues += ConfigIssue(ConfigIssueLevel.WARNING, "[Proxy] line $line", "VMess 不支持 cipher=$cipher，已跳过 $name")
                return null
            }
            val useWs = ws || opts["ws"] == "true"
            NodeInfo(
                name = name, type = "vmess", server = server, port = port, uuid = uuid,
                method = cipher, sni = opts["sni"] ?: opts["servername"],
                insecure = opts["allowinsecure"] == "1" || opts["skip-cert-verify"] == "true",
                tls = tls, wsPath = if (useWs) opts["ws-path"] ?: opts["path"] ?: "/" else null,
                wsHost = if (useWs) opts["ws-host"] ?: opts["host"] else null,
            )
        }
        "socks5" -> NodeInfo(
            name = name, type = "socks5", server = server, port = port,
            uuid = parts.getOrNull(3)?.takeIf { it.isNotBlank() } ?: opts["username"],
            password = parts.getOrNull(4)?.takeIf { it.isNotBlank() } ?: opts["password"],
            tls = false,
        )
        else -> NodeInfo(
            name = name, type = "http", server = server, port = port,
            uuid = parts.getOrNull(3)?.takeIf { it.isNotBlank() } ?: opts["username"],
            password = parts.getOrNull(4)?.takeIf { it.isNotBlank() } ?: opts["password"],
            tls = tls,
        )
    }
    return node
}

private fun clashAction(raw: String): String = when (raw.trim().uppercase()) {
    "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "BLOCK" -> "block"
    "DIRECT" -> "direct"
    else -> "proxy"
}

private fun duplicates(values: List<String>): List<String> =
    values.filter { it.isNotBlank() }.groupingBy { it }.eachCount().filter { it.value > 1 }.keys.toList()
