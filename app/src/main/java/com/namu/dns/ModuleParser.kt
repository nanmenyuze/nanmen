package com.namu.dns

import com.namu.dns.core.config.ScriptConfig
import org.json.JSONArray
import org.json.JSONObject

/**
 * 解析小火箭 .sgmodule 的规则子集，以及简单的 JSON 模块。
 *
 * 支持：
 *  - #!name= / #!desc= / #!app= 元数据
 *  - [Rule] 中的 DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX /
 *    IP-CIDR / IP-CIDR6 / PORT
 *    REJECT/BLOCK 会转成 DNS 阻断或内核规则，DIRECT/PROXY 会转成分流规则
 *  - [Filter] / [Adblock] 或纯文本中的 ||domain^（后缀）、|domain|（精确）、
 *    hosts、裸域名（按后缀处理）、@@ 例外
 *
 * 支持 [MITM] hostname（含通配）、[URL Rewrite]、[Header Rewrite]：解析后存入配置文件
 * mitm 分区，由内核 1.11+ 执行；内核未接入时外壳仅存储/展示，不生效。
 *
 * M5 起逐段解析 Loon 插件：[Argument]、[General]、[Rule]、[Rewrite]、[Host]、
 * [Script]、[MITM]。每段都记录「可执行 / 已存储 / 部分支持 / 不支持」状态与依赖；
 * [Rewrite] 的旧版与新版语法送入内核执行，Surge 的 [URL Rewrite] 仍走独立解析。
 *
 * 不支持 [Script]、[Host] 映射、参数替换等需要脚本引擎或运行时变量的能力；
 * 这些行仍计入 ignored，同时通过 sectionStatus / dependencies 明确展示功能缺口。
 */
data class ModuleSectionStatus(
    val section: String,
    val lines: Int,
    val supported: Int,
    /** executed | stored | partial | unsupported | ignored */
    val status: String,
    val detail: String,
)

data class ParsedModule(
    val name: String,
    val app: String,
    val blockLines: List<String>,
    val routeRules: List<RuleItem>,
    val ignored: Int,
    /** [MITM] hostname 列表（支持通配），合并进 active 配置 mitm.hostnames。 */
    val mitmHostnames: List<String> = emptyList(),
    /** [URL Rewrite] 原始规则行，由内核解析执行。 */
    val urlRewrites: List<String> = emptyList(),
    /** [Header Rewrite] 原始规则行。 */
    val headerRewrites: List<String> = emptyList(),
    /** AdBlock 的 @@ 例外行，写入 modules_block.txt 由 FilterEngine 处理。 */
    val allowLines: List<String> = emptyList(),
    /** 跳过原因分类计数，用于导入预览。 */
    val ignoredReasons: Map<String, Int> = emptyMap(),
    /** [Rule] 中目标策略不支持（例如丢失了策略组名）的分流目标。 */
    val lostRouteTargets: List<String> = emptyList(),
    /** [Rule] 中的 RULE-SET / DOMAIN-SET 引用（待拉取展开）。 */
    val ruleSets: List<RuleSetRef> = emptyList(),
    /** Loon [Rewrite] 原始行（旧版/新版），由内核解析执行。 */
    val loonRewrites: List<String> = emptyList(),
    /** [Argument] 参数定义（仅记录，内核不执行运行时替换）。 */
    val arguments: Map<String, String> = emptyMap(),
    /** [Host] 域名映射（仅记录，当前内核没有 Host 覆盖能力）。 */
    val hostMappings: Map<String, String> = emptyMap(),
    /** [Script] 原始行。 */
    val scriptLines: List<String> = emptyList(),
    /** [Script] 结构化规则；source 在导入时下载并缓存，解析阶段为空。 */
    val scripts: List<ScriptConfig> = emptyList(),
    /** 脚本规则解析/下载失败的条目说明。 */
    val scriptIssues: List<String> = emptyList(),
    /** 逐段可执行状态与依赖说明。 */
    val sectionStatus: List<ModuleSectionStatus> = emptyList(),
    /** 全局依赖缺口，例如脚本引擎、Host 映射、参数替换。 */
    val dependencies: List<String> = emptyList(),
)

object ModuleParser {
    private val supportedRouteTypes = setOf(
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD",
        "IP-CIDR", "IP-CIDR6", "GEOIP", "PORT", "PROTOCOL",
    )

    fun parse(rawText: String): ParsedModule {
        val text = rawText.removePrefix("\uFEFF")
        val trimmed = text.trim()
        if (trimmed.startsWith("{")) return parseJson(trimmed)

        var name = ""
        var app = ""
        var section = ""
        val ignoredReasons = linkedMapOf<String, Int>()
        fun ignore(reason: String) {
            ignoredReasons[reason] = (ignoredReasons[reason] ?: 0) + 1
        }
        val blocks = LinkedHashSet<String>()
        val allows = LinkedHashSet<String>()
        val routes = mutableListOf<RuleItem>()
        val ruleSets = mutableListOf<RuleSetRef>()
        val lostTargets = LinkedHashSet<String>()
        val mitmHosts = LinkedHashSet<String>()
        val urlRewrites = mutableListOf<String>()
        val headerRewrites = mutableListOf<String>()
        val loonRewrites = mutableListOf<String>()
        val arguments = linkedMapOf<String, String>()
        val hostMappings = linkedMapOf<String, String>()
        val scriptLines = mutableListOf<String>()
        val scripts = mutableListOf<ScriptConfig>()
        val scriptIssues = mutableListOf<String>()

        data class Acc(var lines: Int = 0, var ok: Int = 0)
        val sectionAcc = linkedMapOf<String, Acc>()
        fun acc(name: String): Acc = sectionAcc.getOrPut(name) { Acc() }

        text.lineSequence().forEach { raw ->
            val line = raw.trim()
            if (line.isEmpty()) return@forEach
            when {
                line.startsWith("#!name=") -> name = line.substringAfter('=').trim()
                line.startsWith("#!desc=") -> Unit
                line.startsWith("#!app=") -> app = line.substringAfter('=').trim()
                line.startsWith("[") && line.endsWith("]") -> {
                    section = line.substring(1, line.length - 1).trim().lowercase()
                }
                line.startsWith("#") || line.startsWith("!") || line.startsWith(";") -> Unit
                section == "rule" -> {
                    acc(section).lines++
                    val parsed = parseRuleLine(line)
                    parsed.urlRewrite?.let { urlRewrites.add(it) }
                    parsed.ruleSet?.let { ruleSets.add(it) }
                    if (parsed.block != null) blocks.add(parsed.block)
                    if (parsed.route != null) routes.add(parsed.route)
                    if (parsed.ignoredReason == null) acc(section).ok++
                    parsed.ignoredReason?.let(::ignore)
                    parsed.lostTarget?.let { lostTargets.add(it) }
                }
                section == "filter" || section == "adblock" || section.isBlank() -> {
                    val key = section.ifBlank { "adblock" }
                    acc(key).lines++
                    val parsed = parseBlockLine(line)
                    if (parsed.block != null) blocks.add(parsed.block)
                    if (parsed.allow != null) allows.add(parsed.allow)
                    if (parsed.block != null || parsed.allow != null) acc(key).ok++
                    parsed.reason?.let(::ignore)
                }
                section == "mitm" -> {
                    acc(section).lines++
                    var acceptedHostLine = false
                    when {
                        line.startsWith("hostname", ignoreCase = true) -> {
                            line.substringAfter('=', "")
                                .replace(Regex("^\\s*%APPEND%\\s*", RegexOption.IGNORE_CASE), "")
                                .split(',')
                                .map { it.trim() }
                                .forEach { h ->
                                    if (cleanMitmHost(h) != null) {
                                        mitmHosts.add(cleanMitmHost(h)!!)
                                        acceptedHostLine = true
                                    } else ignore("invalid_mitm_host")
                                }
                        }
                        line.contains('=') -> {
                            // 其他 MITM 选项（例如 skip）当前内核无对应语义，记录但不假装执行。
                            ignore("unsupported_mitm_option")
                        }
                        else -> {
                            val h = cleanMitmHost(line)
                            if (h != null) {
                                mitmHosts.add(h)
                                acceptedHostLine = true
                            } else ignore("invalid_mitm_host")
                        }
                    }
                    if (acceptedHostLine) acc(section).ok++
                }
                section == "url rewrite" -> {
                    acc(section).lines++
                    urlRewrites.add(line)
                    acc(section).ok++
                }
                section == "header rewrite" -> {
                    acc(section).lines++
                    headerRewrites.add(line)
                    acc(section).ok++
                }
                section == "rewrite" -> {
                    acc(section).lines++
                    if (loonRewriteSupported(line)) {
                        loonRewrites.add(line)
                        acc(section).ok++
                    } else {
                        ignore("unsupported_loon_action")
                    }
                }
                section == "argument" -> {
                    acc(section).lines++
                    val key = line.substringBefore('=', "").trim()
                    if (key.isNotBlank() && line.contains('=')) {
                        arguments[key] = line.substringAfter('=').trim()
                    }
                    ignore("runtime_argument")
                }
                section == "general" -> {
                    acc(section).lines++
                    ignore("general_option")
                }
                section == "host" -> {
                    acc(section).lines++
                    val key = line.substringBefore('=', "").trim().lowercase()
                    val value = line.substringAfter('=', "").trim()
                    if (key.isNotBlank() && value.isNotBlank()) hostMappings[key] = value
                    ignore("host_mapping")
                }
                section == "script" -> {
                    acc(section).lines++
                    scriptLines.add(line)
                    val parsed = parseScriptLine(line, arguments)
                    if (parsed.first != null) {
                        scripts.add(parsed.first!!)
                        acc(section).ok++
                    } else if (parsed.second != null) {
                        ignore("script_rule_invalid")
                        scriptIssues.add(parsed.second!!)
                    }
                }
                else -> {
                    acc(section.ifBlank { "unknown" }).lines++
                    ignore("unsupported_section")
                }
            }
        }
        // [Argument] 可能出现在 [Script] 之后；统一把最终参数并入每条脚本。
        scripts.replaceAll { rule ->
            val merged = LinkedHashMap(rule.arguments)
            arguments.forEach { (k, v) -> if (!merged.containsKey(k)) merged[k] = v }
            rule.copy(arguments = merged)
        }
        val statuses = sectionAcc.map { (key, a) ->
            val name = when (key) {
                "rewrite" -> "Rewrite"
                "url rewrite" -> "URL Rewrite"
                "header rewrite" -> "Header Rewrite"
                "mitm" -> "MITM"
                "argument" -> "Argument"
                "general" -> "General"
                "host" -> "Host"
                "script" -> "Script"
                "rule" -> "Rule"
                "adblock" -> "AdBlock"
                else -> key.replaceFirstChar { it.uppercase() }
            }
            val (status, detail) = when (key) {
                "rule", "filter", "adblock" -> "executed" to "DNS 阻断/分流规则已合并到当前配置"
                "mitm" -> "stored" to "域名列表已写入 MITM 配置；需启用 MITM 并安装 CA"
                "url rewrite" -> "stored" to "Surge 旧式 [URL Rewrite] 交给内核的 Surge 解析器，不按 Loon 语法推断"
                "header rewrite" -> "stored" to "Surge [Header Rewrite] 交给内核执行"
                "rewrite" -> if (a.ok > 0) {
                    "stored" to "Loon [Rewrite] 已编译执行；jq、data-path、复杂条件等缺口见依赖说明"
                } else {
                    "unsupported" to "全部动作暂不支持"
                }
                "argument" -> "partial" to "参数只记录，不做 \${region} 式运行时替换"
                "general" -> "partial" to "General 全局项只记录，不改变内核 DNS/TUN 行为"
                "host" -> "partial" to "Host 映射只记录，当前内核不做域名到 IP 的本地覆盖"
                "script" -> if (a.ok > 0) {
                    "partial" to "已解析 ${a.ok} 条脚本，由内核 QuickJS 执行；正文在导入时下载缓存，API 覆盖见 M6 能力矩阵"
                } else {
                    "unsupported" to "脚本规则无法解析（缺少 phase/pattern/script-path）"
                }
                else -> "ignored" to "未识别段落，原文保留但不执行"
            }
            ModuleSectionStatus(name, a.lines, a.ok, status, detail)
        }
        val dependencies = buildList {
            if (scripts.isNotEmpty()) add("QuickJS 脚本运行时（内置，Promise/async 微任务已支持）；binary-body-mode/Uint8Array 已支持，require/本地文件读取不支持，setTimeout 按 Loon 语义只执行一次")
            if (scriptLines.isNotEmpty() && scripts.isEmpty()) add("脚本规则（未解析，[Script] 不执行）")
            if (arguments.isNotEmpty()) add("参数替换（未实现，\${argument} 不展开）")
            if (hostMappings.isNotEmpty()) add("Host 映射（未实现）")
            if (sectionAcc["general"]?.lines ?: 0 > 0) add("General 全局项（仅记录）")
        }
        return ParsedModule(
            name = name.ifBlank { app },
            app = app,
            blockLines = blocks.toList(),
            routeRules = routes.distinctBy { "${it.type}|${it.value}|${it.action}" },
            ruleSets = ruleSets.distinctBy { "${it.kind}|${it.url}" },
            ignored = ignoredReasons.values.sum(),
            mitmHostnames = mitmHosts.toList(),
            urlRewrites = urlRewrites.distinct(),
            headerRewrites = headerRewrites.distinct(),
            allowLines = allows.toList(),
            ignoredReasons = ignoredReasons,
            lostRouteTargets = lostTargets.toList(),
            loonRewrites = loonRewrites.distinct(),
            arguments = arguments,
            hostMappings = hostMappings,
            scriptLines = scriptLines.toList(),
            scripts = scripts.distinctBy { "${it.phase}|${it.pattern}|${it.scriptPath}|${it.name}" },
            scriptIssues = scriptIssues.toList(),
            sectionStatus = statuses,
            dependencies = dependencies,
        )
    }

    private fun parseJson(text: String): ParsedModule {
        val o = JSONObject(text)
        val name = o.optString("name", "")
        val app = o.optString("app", "")
        val blocks = LinkedHashSet<String>()
        val allows = LinkedHashSet<String>()
        val ignoredReasons = linkedMapOf<String, Int>()
        fun ignore(reason: String) {
            ignoredReasons[reason] = (ignoredReasons[reason] ?: 0) + 1
        }
        o.optJSONArray("domains")?.let { arr ->
            for (i in 0 until arr.length()) {
                val host = cleanHost(arr.optString(i, ""))
                if (host != null) blocks.add("||$host^") else ignore("invalid_domain")
            }
        }
        o.optJSONArray("block")?.let { arr ->
            for (i in 0 until arr.length()) {
                val parsed = parseBlockLine(arr.optString(i, ""))
                if (parsed.block != null) blocks.add(parsed.block)
                if (parsed.allow != null) allows.add(parsed.allow)
                parsed.reason?.let(::ignore)
            }
        }
        o.optJSONArray("allow")?.let { arr ->
            for (i in 0 until arr.length()) {
                val parsed = parseBlockLine("@@${arr.optString(i, "")}")
                if (parsed.allow != null) allows.add(parsed.allow) else ignore(parsed.reason ?: "invalid_adblock")
            }
        }
        val routes = mutableListOf<RuleItem>()
        val lostTargets = LinkedHashSet<String>()
        o.optJSONArray("rules")?.let { arr ->
            for (i in 0 until arr.length()) {
                when (val item = arr.opt(i)) {
                    is String -> {
                        val parsed = parseRuleLine(item)
                        if (parsed.block != null) blocks.add(parsed.block)
                        if (parsed.route != null) routes.add(parsed.route)
                        parsed.ignoredReason?.let(::ignore)
                        parsed.lostTarget?.let { lostTargets.add(it) }
                    }
                    is JSONObject -> {
                        val type = item.optString("type").uppercase()
                        val value = item.optString("value")
                        val action = item.optString("action", "block")
                        val parsed = makeRule(type, value, action)
                        if (parsed.block != null) blocks.add(parsed.block)
                        if (parsed.route != null) routes.add(parsed.route)
                        parsed.ignoredReason?.let(::ignore)
                        parsed.lostTarget?.let { lostTargets.add(it) }
                    }
                    else -> ignore("invalid_json_rule")
                }
            }
        }
        return ParsedModule(
            name = name.ifBlank { app },
            app = app,
            blockLines = blocks.toList(),
            routeRules = routes.distinctBy { "${it.type}|${it.value}|${it.action}" },
            ignored = ignoredReasons.values.sum(),
            allowLines = allows.toList(),
            ignoredReasons = ignoredReasons,
            lostRouteTargets = lostTargets.toList(),
        )
    }

    private data class ParsedRule(
        val block: String? = null,
        val route: RuleItem? = null,
        val ignoredReason: String? = null,
        val lostTarget: String? = null,
        val urlRewrite: String? = null,
        val ruleSet: RuleSetRef? = null,
    )

    private data class BlockParse(
        val block: String? = null,
        val allow: String? = null,
        val reason: String? = null,
    )

    private val loonSimpleActions = setOf(
        "header", "302", "307", "reject", "reject-200", "reject-img", "reject-dict", "reject-array",
        "header-add", "header-del", "header-replace", "header-replace-regex",
        "request-header-add", "request-header-del", "request-header-replace", "request-header-replace-regex",
        "response-header-add", "response-header-del", "response-header-replace", "response-header-replace-regex",
        "request-body-replace-regex", "request-body-json-add", "request-body-json-replace",
        "request-body-json-del", "request-body-json-delete",
        "response-body-replace-regex", "response-body-json-add", "response-body-json-replace",
        "response-body-json-del", "response-body-json-delete",
        "mock-request-body", "mock-response-body",
    )

    /**
     * 模块预览用的 Loon [Rewrite] 支持判断。真正执行以内核解析器为准；
     * 这里只把明确不支持的 jq、data-path、脚本和复杂条件标出来，避免界面虚假承诺。
     */
    private fun loonRewriteSupported(line: String): Boolean {
        val lower = line.lowercase()
        if (lower.startsWith("request if ") || lower.startsWith("response if ")) {
            if (lower.contains("&&") || lower.contains("||") || lower.contains(" script(")) return false
            val thenPart = lower.substringAfter(" then ", "")
            if (thenPart.isBlank()) return false
            val supportedFns = listOf(
                "url.replace(", "redirect(", "request.header.add(", "request.header.del(",
                "request.header.delete(", "request.header.replace(", "request.header.replace_regex(",
                "response.header.add(", "response.header.del(", "response.header.delete(",
                "response.header.replace(", "response.header.replace_regex(",
                "request.body.replace(", "request.body.replace_regex(",
                "response.body.replace(", "response.body.replace_regex(",
                "request.json.add(", "request.json.replace(", "request.json.delete(", "request.json.del(",
                "response.json.add(", "response.json.replace(", "response.json.delete(", "response.json.del(",
            )
            return thenPart.split(';').map { it.trim() }.all { call -> supportedFns.any { call.startsWith(it) } }
        }
        val parts = line.split(Regex("\\s+")).filter { it.isNotBlank() }
        // 动作可能在末位（Loon 官方写法 `url target header|302`），也可能在第二位
        // （`url reject-dict`、旧版 `url - action`）。两种都认，避免预览把能跑的规则标成不支持。
        val last = parts.lastOrNull()?.lowercase()
        val second = parts.getOrNull(1)?.lowercase()
        val action = when {
            parts.size >= 3 && last in loonSimpleActions -> last!!
            second == "-" && parts.size >= 3 -> parts[2].lowercase()
            else -> second
        } ?: return false
        if (action !in loonSimpleActions) return false
        if (action.contains("json-jq") || action.endsWith("-jq")) return false
        if (action.startsWith("mock-") && lower.contains("data-path=")) return false
        return true
    }

    private fun parseRuleLine(raw: String): ParsedRule {
        val parts = raw.split(',')
        if (parts.size < 3) return ParsedRule(ignoredReason = "invalid_rule")
        val type = parts[0].trim().uppercase()
        if (type == "URL-REGEX" || type == "RULE-SET" || type == "DOMAIN-SET") {
            // 值可能含逗号（正则/URL 查询串）：首段类型、末段动作，中间拼回完整值。
            val value = parts.subList(1, parts.size - 1).joinToString(",").trim().trim('"')
            return makeRule(type, value, parts.last().trim())
        }
        return makeRule(type, parts[1].trim(), parts[2].trim())
    }

    private fun makeRule(type: String, value: String, rawAction: String): ParsedRule {
        if (type == "URL-REGEX") {
            // Surge URL-REGEX REJECT 语义 = 对完整 URL 正则匹配后拒绝，
            // 转交内核 MITM 重写引擎执行。
            val action = rawAction.trim().uppercase()
            if (action != "REJECT" && !action.startsWith("REJECT-") && action != "BLOCK") {
                return ParsedRule(ignoredReason = "unsupported_rule_target", lostTarget = rawAction.trim())
            }
            if (runCatching { Regex(value) }.isFailure) return ParsedRule(ignoredReason = "invalid_rule")
            return ParsedRule(urlRewrite = "$value reject")
        }
        if (type == "RULE-SET" || type == "DOMAIN-SET") {
            // 规则集引用：壳层拉取 URL 内容后展开为普通规则，集合策略覆盖行内策略。
            if (!value.startsWith("http://") && !value.startsWith("https://")) {
                return ParsedRule(ignoredReason = "invalid_rule")
            }
            val a = rawAction.trim().uppercase()
            val isReject = a == "REJECT" || a.startsWith("REJECT-") || a == "BLOCK"
            val policy = when {
                isReject -> "block"
                a == "DIRECT" -> "direct"
                a == "PROXY" -> "proxy"
                else -> return ParsedRule(ignoredReason = "unsupported_rule_target", lostTarget = rawAction.trim())
            }
            return ParsedRule(ruleSet = RuleSetRef(type, value, policy))
        }
        if (type !in supportedRouteTypes) return ParsedRule(ignoredReason = "unsupported_rule_type")
        val action = rawAction.trim().uppercase()
        val isReject = action == "REJECT" || action == "REJECT-DROP" ||
            action == "REJECT-TINYGIF" || action == "REJECT-NO-DROP" || action == "BLOCK"
        val routeAction = when {
            isReject -> "block"
            action == "DIRECT" -> "direct"
            action == "PROXY" -> "proxy"
            else -> null
        }
        if (routeAction == null) {
            return ParsedRule(ignoredReason = "unsupported_rule_target", lostTarget = rawAction.trim())
        }
        if (!validateRuleValue(type, value)) return ParsedRule(ignoredReason = "invalid_rule")

        val block = if (isReject) {
            when (type) {
                "DOMAIN-SUFFIX" -> cleanHost(value)?.let { "||$it^" }
                "DOMAIN" -> cleanHost(value)?.let { "|$it|" }
                else -> null
            }
        } else null
        return ParsedRule(
            block = block,
            route = RuleItem(type, value.trim(), routeAction),
        )
    }

    private fun validateRuleValue(type: String, value: String): Boolean {
        val v = value.trim()
        if (v.isEmpty()) return false
        return when (type) {
            "DOMAIN", "DOMAIN-SUFFIX" -> cleanHost(v) != null
            "DOMAIN-KEYWORD" -> v.none { it.isWhitespace() }
            "DOMAIN-REGEX" -> runCatching { Regex(v) }.isSuccess
            "DOMAIN-WILDCARD" -> v.none { it.isWhitespace() } && ('*' in v || v.contains('?'))
            "GEOIP" -> v.equals("CN", ignoreCase = true)
            "PORT" -> v.toIntOrNull()?.let { it in 1..65535 } == true
            "PROTOCOL" -> v.equals("TCP", ignoreCase = true) || v.equals("UDP", ignoreCase = true)
            "IP-CIDR" -> validCidr(v, ipv6 = false)
            "IP-CIDR6" -> validCidr(v, ipv6 = true)
            else -> false
        }
    }

    private fun validCidr(value: String, ipv6: Boolean): Boolean {
        val parts = value.split('/')
        if (parts.size != 2) return false
        val prefix = parts[1].toIntOrNull() ?: return false
        if (ipv6) {
            if (prefix !in 0..128 || !parts[0].contains(':')) return false
            return runCatching {
                java.net.InetAddress.getByName(parts[0]) is java.net.Inet6Address
            }.getOrDefault(false)
        }
        if (prefix !in 0..32) return false
        val octets = parts[0].split('.')
        if (octets.size != 4) return false
        return octets.all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
    }

    private fun parseBlockLine(raw: String): BlockParse {
        val line = raw.trim()
        if (line.isEmpty() || line.startsWith("#") || line.startsWith("!") || line.startsWith("/")) {
            return BlockParse()
        }
        if (line.contains("##") || line.contains("#@#")) {
            return BlockParse(reason = "invalid_adblock")
        }
        val allow = line.startsWith("@@")
        val body = if (allow) line.removePrefix("@@").trim() else line
        if (body.isEmpty()) return BlockParse(reason = "invalid_adblock")
        // $ 选项（$third-party、$script 等）在当前 DNS/规则引擎没有等价语义，
        // 直接剥离会扩大拦截范围；这里明确计入跳过。
        if (body.contains('$')) return BlockParse(reason = "unsupported_adblock_option")
        if (!allow) {
            val parts = body.split(Regex("\\s+"))
            if (parts.size >= 2 && parts[0] in setOf("0.0.0.0", "127.0.0.1", "::1")) {
                val host = cleanHost(parts[1]) ?: return BlockParse(reason = "invalid_adblock")
                return BlockParse(block = "|$host|")
            }
        }
        val hostPart = body.substringBefore('#').trim()
        if (hostPart.isEmpty()) return BlockParse(reason = "invalid_adblock")
        val host = cleanHost(hostPart) ?: return BlockParse(reason = "invalid_adblock")
        val prefix = if (allow) "@@" else ""
        return if (hostPart.startsWith("||")) {
            BlockParse(allow = if (allow) "$prefix||$host^" else null, block = if (allow) null else "||$host^")
        } else if (hostPart.startsWith("|")) {
            BlockParse(allow = if (allow) "$prefix|$host|" else null, block = if (allow) null else "|$host|")
        } else {
            // 裸域名在 AdBlock 列表里按后缀语义处理；精确匹配必须使用 |domain|。
            BlockParse(allow = if (allow) "$prefix||$host^" else null, block = if (allow) null else "||$host^")
        }
    }

    private fun cleanHost(raw: String): String? {
        val d = raw.trim().lowercase()
            .removePrefix("||")
            .trimStart('|')
            .trimEnd('^', '|')
            .trim('.')
        return if (isValidAdsDomain(d)) d else null
    }

    /** MITM hostname：允许 *.example.com 通配前缀，其余按合法域名校验。 */
    /**
     * 解析 Loon / 小火箭 [Script] 行。支持：
     * `http-request <url-regex> script-path=<url>, requires-body=1, max-size=..., timeout=...`
     * 以及 `type=request, pattern=..., script-path=...` 形式。
     * 不认识的键只会被忽略，不会把整条脚本当成可执行。
     */
    private fun parseScriptLine(raw: String, moduleArgs: Map<String, String>): Pair<ScriptConfig?, String?> {
        val line = raw.trim()
        if (line.isEmpty()) return null to "空脚本行"
        val tokens = splitScriptTokens(line)
        var phase = ""
        var pattern = ""
        var scriptPath = ""
        var tag = ""
        var requiresBody = false
        var maxSize = 2 * 1024 * 1024
        var timeoutMs = 5000
        var argumentText = ""
        var enabled = true
        var binaryBody = false
        // Loon 允许 `名称 = type=...` 的具名写法；名称和等号是两个 token，
        // 不能把名称当成 URL 正则，也不能让独立的 `=` 覆盖 pattern。
        val namedTag = tokens.firstOrNull()?.takeIf { it != "=" && tokens.getOrNull(1) == "=" }
        if (!namedTag.isNullOrBlank()) tag = namedTag
        for ((idx, token) in tokens.withIndex()) {
            if (namedTag != null && (token == namedTag || token == "=")) continue
            val eq = token.indexOf('=')
            if (eq > 0) {
                val key = token.substring(0, eq).trim().lowercase()
                val value = token.substring(eq + 1).trim().trim('"', '\'')
                when (key) {
                    "type", "phase" -> phase = value.lowercase()
                    "pattern" -> pattern = value
                    "script-path", "scriptpath", "script_path" -> scriptPath = value
                    "tag", "name" -> tag = value
                    "requires-body", "requiresbody" -> requiresBody =
                        value.lowercase() in setOf("1", "true", "yes", "on")
                    "max-size", "maxsize" -> maxSize = value.toIntOrNull() ?: maxSize
                    "timeout" -> {
                        val n = value.toIntOrNull() ?: 0
                        timeoutMs = if (n in 1..60) n * 1000 else n.coerceAtLeast(50)
                    }
                    "argument", "arguments" -> argumentText = value
                    "enable" -> enabled = value.lowercase() !in setOf("0", "false", "no", "off")
                    "binary-body-mode", "binarybodymode" -> binaryBody =
                        value.lowercase() in setOf("1", "true", "yes", "on")
                }
            } else if (idx == 0) {
                when (token.lowercase()) {
                    "http-request", "request" -> phase = "request"
                    "http-response", "response" -> phase = "response"
                    else -> if (!token.contains('=') && pattern.isBlank()) pattern = token
                }
            } else if (pattern.isBlank()) {
                pattern = token
            }
        }
        phase = when {
            phase.contains("request") && !phase.contains("response") -> "request"
            phase.contains("response") -> "response"
            else -> ""
        }
        if (!enabled) return null to null
        if (phase.isBlank()) return null to "缺少 request/response 阶段: ${line.take(80)}"
        if (pattern.isBlank()) return null to "缺少 URL 匹配正则: ${line.take(80)}"
        if (scriptPath.isBlank()) return null to "缺少 script-path: ${line.take(80)}"
        if (!scriptPath.startsWith("http://") && !scriptPath.startsWith("https://")) {
            return null to "script-path 只支持 http/https: $scriptPath"
        }
        val args = LinkedHashMap(moduleArgs)
        return ScriptConfig(
            name = tag.ifBlank { pattern.take(48) },
            phase = phase,
            pattern = pattern,
            source = "",
            arguments = args,
            timeoutMs = timeoutMs.coerceIn(50, 10_000),
            maxSize = if (maxSize <= 0) 2 * 1024 * 1024 else maxSize.coerceIn(4096, 8 * 1024 * 1024),
            requiresBody = requiresBody || binaryBody,
            binaryBodyMode = binaryBody,
            scriptPath = scriptPath,
            argumentText = argumentText,
        ) to null
    }

    /** 逗号/空白分隔，但保留引号内的空格和逗号。 */
    private fun splitScriptTokens(line: String): List<String> {
        val out = mutableListOf<String>()
        val cur = StringBuilder()
        var quote = '\u0000'
        for (ch in line) {
            when {
                quote != '\u0000' -> {
                    cur.append(ch)
                    if (ch == quote) quote = '\u0000'
                }
                ch == '"' || ch == '\'' -> {
                    quote = ch
                    cur.append(ch)
                }
                ch == ',' || ch.isWhitespace() -> {
                    if (cur.isNotBlank()) {
                        out.add(cur.toString().trim())
                        cur.clear()
                    }
                }
                else -> cur.append(ch)
            }
        }
        if (cur.isNotBlank()) out.add(cur.toString().trim())
        return out
    }

    private fun cleanMitmHost(raw: String): String? {
        val d = raw.trim().lowercase().trim('.')
        if (d.isEmpty()) return null
        if (d.startsWith("*.")) {
            return if (isValidAdsDomain(d.removePrefix("*."))) d else null
        }
        if (d.contains('*') || d.contains('?')) {
            // 中段通配（m*.maps.example.com）：去掉通配符后骨架必须是合法域名。
            val skeleton = d.replace("*", "").replace("?", "")
            return if (isValidAdsDomain(skeleton)) d else null
        }
        return if (isValidAdsDomain(d)) d else null
    }
}
