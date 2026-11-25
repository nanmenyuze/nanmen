package com.namu.dns

import com.namu.dns.core.config.ScriptConfig
import org.json.JSONArray
import org.json.JSONObject

/**
 * 解析小火箭 .sgmodule 的规则子集，以及简单的 JSON 模块。
 *
 * 支持：
 *  - #!name= / #!desc= / #!app= / #!icon= 元数据
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
 * [Script]、[MITM]、[WebSocket Rewrite]。每段都记录「可执行 / 已存储 / 部分支持 / 不支持」状态与依赖；
 * [Rewrite] 的旧版与新版语法送入内核执行，Surge 的 [URL Rewrite] 仍走独立解析。
 *
 * [Script] 支持 v2 条件树、Argument 运行时注入与 $environment/$utils/require；
 * 无法解析的行计入 ignored，并通过 sectionStatus / dependencies 明确展示功能缺口。
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
    /** [MITM] skip 列表：显式排除、永不解密的域名。 */
    val mitmSkipHostnames: List<String> = emptyList(),
    /** [MITM] 已识别但不改变隧道的细项（tcp-connection/client-cert 等）。 */
    val mitmOptions: Map<String, String> = emptyMap(),
    /** [General] 已解析的全局项；DNS/TUN 类由壳层按能力选择性接入。 */
    val generalOptions: Map<String, String> = emptyMap(),
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
    /** Surge [Body Rewrite] 原始行：http-request/http-response <url> <regex> <replacement>。 */
    val bodyRewrites: List<String> = emptyList(),
    /** [WebSocket Rewrite] 原始行（南门自有语法），由内核 h1 Upgrade 帧改写执行。 */
    val wsRewrites: List<String> = emptyList(),
    /** [Argument] 参数定义；键 → 默认值。 */
    val arguments: Map<String, String> = emptyMap(),
    /** [Argument] 声明类型（string / number / boolean）；内核据此注入正确的 JS 类型。 */
    val argumentTypes: Map<String, String> = emptyMap(),
    /** [Host] 域名映射：直接 IP、CNAME 别名或 server:上游。 */
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
    val iconUrl: String = "",
)

object ModuleParser {
    private val supportedRouteTypes = setOf(
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD",
        "IP-CIDR", "IP-CIDR6", "GEOIP", "PORT", "PROTOCOL", "UID",
    )

    fun readIconUrl(lines: Sequence<String>): String =
        lines.map { it.removePrefix("\uFEFF").trim() }
            .takeWhile { !it.startsWith("[") }
            .firstOrNull { it.substringBefore('=').trim() == "#!icon" && '=' in it }
            ?.substringAfter('=')?.trim().orEmpty()

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
        val mitmSkips = LinkedHashSet<String>()
        val mitmOptions = linkedMapOf<String, String>()
        val generalOptions = linkedMapOf<String, String>()
        val urlRewrites = mutableListOf<String>()
        val headerRewrites = mutableListOf<String>()
        val loonRewrites = mutableListOf<String>()
        val bodyRewrites = mutableListOf<String>()
        val wsRewrites = mutableListOf<String>()
        val arguments = linkedMapOf<String, String>()
        val argumentTypes = linkedMapOf<String, String>()
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
                            val key = line.substringBefore('=').trim().lowercase()
                            val value = line.substringAfter('=').trim()
                            if (key == "skip" || key == "skip-hostnames" || key == "skip_hostnames") {
                                value.split(',').map { it.trim() }.filter { it.isNotEmpty() }.forEach { h ->
                                    cleanMitmHost(h.replace(Regex("^\\s*%APPEND%\\s*", RegexOption.IGNORE_CASE), "").trim())?.let {
                                        mitmSkips.add(it); acceptedHostLine = true
                                    }
                                }
                            } else {
                                // Loon MITM 细项：hostname/skip 执行，其余保留供审计与后续接入，
                                // 不再以「不支持」丢弃整行。
                                if (key.isNotEmpty()) mitmOptions[key] = value
                                acceptedHostLine = true
                            }
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
                section == "body rewrite" -> {
                    acc(section).lines++
                    val normalized = normalizeBodyRewrite(line)
                    if (normalized != null) {
                        bodyRewrites.add(normalized)
                        acc(section).ok++
                    } else {
                        ignore("body_rewrite_invalid")
                    }
                }
                section == "map local" -> {
                    acc(section).lines++
                    val (translated, issue) = mapLocalToLoon(line)
                    if (translated != null) {
                        loonRewrites.add(translated)
                        acc(section).ok++
                    } else {
                        ignore(issue ?: "invalid_map_local")
                    }
                }
                section == "map remote" -> {
                    acc(section).lines++
                    val (translated, issue) = mapRemoteToLoon(line)
                    if (translated != null) {
                        loonRewrites.add(translated)
                        acc(section).ok++
                    } else {
                        ignore(issue ?: "invalid_map_remote")
                    }
                }
                section == "websocket rewrite" -> {
                    acc(section).lines++
                    val action = line.substringBefore(' ', "").trim().lowercase()
                    if (action == "ws-block" || action == "ws-text-replace") {
                        wsRewrites.add(line)
                        acc(section).ok++
                    } else {
                        ignore("unsupported_websocket_action")
                    }
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
                    val decl = parseArgumentDecl(line)
                    if (decl != null) {
                        arguments[decl.first] = decl.second.first
                        argumentTypes[decl.first] = decl.second.second
                        acc(section).ok++
                    } else {
                        ignore("invalid_argument")
                    }
                }
                section == "general" -> {
                    acc(section).lines++
                    val key = line.substringBefore('=', "").trim().lowercase()
                    val value = line.substringAfter('=', "").trim()
                    if (key.isNotEmpty()) {
                        generalOptions[key] = value
                        // General 不是每条都能映射到本机 TUN/DNS；能识别的先完整保留，
                        // 由 ConfigStore 选择 DNS 覆盖、跳过域名等可执行项接入。
                        if (key in supportedGeneralOptions) acc(section).ok++ else ignore("general_option")
                    } else ignore("general_option")
                }
                section == "host" -> {
                    acc(section).lines++
                    val key = line.substringBefore('=', "").trim().lowercase()
                    val value = line.substringAfter('=', "").trim()
                    val issue = validateHostMapping(key, value)
                    if (issue == null) {
                        hostMappings[key] = value
                        acc(section).ok++
                    } else {
                        ignore(issue)
                    }
                }
                section == "script" -> {
                    acc(section).lines++
                    scriptLines.add(line)
                    val parsed = parseScriptV2(line, arguments, argumentTypes)
                        ?: parseScriptLine(line, arguments, argumentTypes)
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
        // 参数不再做编译期字符串展开：Rewrite 行保留原样，脚本只通过 $argument 注入，
        // 避免把用户输入拼进正则/URL/脚本源码。
        // [Argument] 可能出现在 [Script] 之后；统一把最终参数并入每条脚本。
        scripts.replaceAll { rule ->
            val merged = LinkedHashMap(rule.arguments)
            arguments.forEach { (k, v) -> if (!merged.containsKey(k)) merged[k] = v }
            rule.copy(
                arguments = merged,
                argumentTypes = argumentTypes.filterKeys { merged.containsKey(it) },
            )
        }
        val statuses = sectionAcc.map { (key, a) ->
            val name = when (key) {
                "rewrite" -> "Rewrite"
                "url rewrite" -> "URL Rewrite"
                "header rewrite" -> "Header Rewrite"
                "body rewrite" -> "Body Rewrite"
                "websocket rewrite" -> "WebSocket Rewrite"
                "map local" -> "Map Local"
                "map remote" -> "Map Remote"
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
                "mitm" -> {
                    val bits = buildList {
                        if (mitmHosts.isNotEmpty()) add("${mitmHosts.size} 个 hostname")
                        if (mitmSkips.isNotEmpty()) add("${mitmSkips.size} 个 skip")
                        if (mitmOptions.isNotEmpty()) add("${mitmOptions.size} 个细项")
                    }
                    "executed" to "MITM 配置已下发${bits.joinToString("、")?.let { "（$it）" } ?: ""}；需启用 MITM 并安装 CA"
                }
                "url rewrite" -> "stored" to "Surge 旧式 [URL Rewrite] 交给内核的 Surge 解析器，不按 Loon 语法推断"
                "header rewrite" -> "stored" to "Surge [Header Rewrite] 双向执行（请求头 + 响应头）"
                "body rewrite" -> if (a.ok > 0) {
                    "stored" to "已翻译 ${a.ok} 条 Body Rewrite；jq 支持路径/管道/数组对象构造/map/select/del/算术/排序/编码函数"
                } else {
                    "unsupported" to "Body Rewrite 需要 http-request/http-response + URL/regex/replacement 或 jq 子集"
                }
                "websocket rewrite" -> if (a.ok > 0) {
                    "stored" to "已 ${a.ok} 条 WebSocket 规则；仅 h1 Upgrade 帧改写，未命中时零代价透传"
                } else {
                    "unsupported" to "WebSocket 规则无法解析（支持 ws-block / ws-text-replace）"
                }
                "map local" -> if (a.ok > 0) {
                    "executed" to "已翻译 ${a.ok} 条 Map Local（data 内联 / data-path / file），按路径返回 mock 响应"
                } else {
                    "unsupported" to "Map Local 需要 data、data-path 或 file 之一"
                }
                "map remote" -> if (a.ok > 0) {
                    "executed" to "已翻译 ${a.ok} 条 Map Remote 为 URL 前缀改写，跨域请求按新 host 直连/走代理"
                } else {
                    "unsupported" to "Map Remote 需要 <源URL> <目标URL> 两段"
                }
                "rewrite" -> if (a.ok > 0) {
                    "stored" to "Loon [Rewrite] 已编译执行；完整 jq、data-path/file、复合条件均已接入"
                } else {
                    "unsupported" to "全部动作暂不支持"
                }
                "argument" -> if (a.ok > 0) {
                    "executed" to "参数已解析并按声明类型注入 \$argument；运行期修改不重编译脚本"
                } else {
                    "unsupported" to "Argument 需要 key=默认值（可选 select/input/switch 与 type）"
                }
                "general" -> if (a.ok > 0) {
                    "stored" to "已解析 ${a.ok}/${a.lines} 项 General；DNS/跳过域名等可执行项由壳层接入，TUN 路由项保留审计"
                } else {
                    "stored" to "General 已保留原文；未识别的键不改变内核行为"
                }
                "host" -> if (a.ok > 0 && a.lines == a.ok) {
                    "executed" to "Host 映射已下发 DNS；IP/别名在本地生效，server 仅复用现有上游客户端"
                } else if (a.ok > 0) {
                    "partial" to "已 ${a.ok}/${a.lines} 条 Host 映射生效；server:system / http:// 等写法已拒绝"
                } else {
                    "unsupported" to "Host 值无法解析（需 IP、CNAME 别名或 server:上游）"
                }
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
            if (scripts.isNotEmpty()) add("QuickJS 脚本运行时（内置，Promise/async 微任务已支持）；binary-body-mode/Uint8Array 已支持，require(crypto/base64/util) 已支持，本地文件读取不开放")
            if (scriptLines.isNotEmpty() && scripts.isEmpty()) add("脚本规则（未解析，[Script] 不执行）")
            if (arguments.isNotEmpty()) add("参数注入：只把当前值按声明类型塞进 \$argument，不做编译期字符串展开")
            if (hostMappings.isNotEmpty()) add("Host 映射已接入 DNS；server: 只复用现有 UDP/DoT/DoH 客户端，server:system 不支持")
            if (generalOptions.isNotEmpty()) add("General 已解析：skip-proxy/bypass 可映射跳过域名，TUN 路由项保留审计")
            if (mitmSkips.isNotEmpty()) add("MITM skip 域名已合并进 skip_hostnames")
        }
        return ParsedModule(
            name = name.ifBlank { app },
            app = app,
            blockLines = blocks.toList(),
            routeRules = routes.distinctBy { "${it.type}|${it.value}|${it.action}" },
            ruleSets = ruleSets.distinctBy { "${it.kind}|${it.url}" },
            ignored = ignoredReasons.values.sum(),
            mitmHostnames = mitmHosts.toList(),
            mitmSkipHostnames = mitmSkips.toList(),
            mitmOptions = mitmOptions,
            generalOptions = generalOptions,
            urlRewrites = urlRewrites.distinct(),
            headerRewrites = headerRewrites.distinct(),
            allowLines = allows.toList(),
            ignoredReasons = ignoredReasons,
            lostRouteTargets = lostTargets.toList(),
            loonRewrites = loonRewrites.distinct(),
            bodyRewrites = bodyRewrites.distinct(),
            wsRewrites = wsRewrites.distinct(),
            arguments = arguments,
            argumentTypes = argumentTypes,
            hostMappings = hostMappings,
            scriptLines = scriptLines.toList(),
            scripts = scripts.distinctBy { "${it.phase}|${it.pattern}|${it.condition}|${it.scriptPath}|${it.name}" },
            scriptIssues = scriptIssues.toList(),
            sectionStatus = statuses,
            dependencies = dependencies,
            iconUrl = readIconUrl(text.lineSequence()),
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
        val hostMappings = linkedMapOf<String, String>()
        for (field in listOf("hosts", "hostMappings")) {
            o.optJSONObject(field)?.let { h ->
                h.keys().forEach { rawKey ->
                    val key = rawKey.trim().lowercase()
                    val value = h.optString(rawKey, "").trim()
                    if (validateHostMapping(key, value) == null) hostMappings[key] = value
                    else ignore("host_mapping_invalid")
                }
            }
        }
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
            hostMappings = hostMappings,
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
        "request-body-json-del", "request-body-json-delete", "request-body-json-jq", "request-body-jq",
        "response-body-replace-regex", "response-body-json-add", "response-body-json-replace",
        "response-body-json-del", "response-body-json-delete", "response-body-json-jq", "response-body-jq",
        "mock-request-body", "mock-response-body",
    )

    /** Loon/小火箭 [General] 里可被本机识别并审计的键；未列出的键保留原文但不计成功。 */
    private val supportedGeneralOptions = setOf(
        "skip-proxy", "bypass", "bypass-tun", "tun-excluded-routes", "dns-server", "dns-fallback",
        "always-real-ip", "hijack-dns", "ipv6", "prefer-ipv6", "force-close-connections",
        "proxy-test-url", "internet-test-url", "test-timeout", "allow-wifi-access", "wifi-assist",
        "dns-cache", "dns-cache-size", "geoip-maxmind", "skip-cert-verify",
        // S6：SSID 触发只解析名单；是否启用由本地 opt-in 决定。
        "ssid-trigger", "ssid-trigger-names",
    )

    /**
     * 模块预览用的 Loon [Rewrite] 支持判断。真正执行以内核解析器为准；
     * jq / data-path / 复合条件都已接入；这里只拒绝混入 script 动作或无法解析的行。
     */
    private fun loonRewriteSupported(line: String): Boolean {
        val lower = line.lowercase()
        if (lower.startsWith("request if ") || lower.startsWith("response if ")) {
            // 复合条件（&&/||、header/参数比较）由内核 LoonCond 条件树求值；
            // 壳层只拒绝 rewrite 段里混入 script 动作的行。
            if (lower.contains(" script(")) return false
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
        // jq 动作可以是 -jq 后缀，也可以是 `body-json-jq` 别名；内核统一走完整 jq 解析器。
        if (action.contains("json-jq") || action.endsWith("-jq")) return true
        if (action.startsWith("mock-") && (lower.contains("data-path=") || lower.contains("file="))) return true
        return true
    }

    private fun parseRuleLine(raw: String): ParsedRule {
        // 值可能含逗号（DOMAIN-REGEX 的 {m,n} 量词、URL 查询串、规则集 URL 参数），
        // 由 RuleLineParser 统一按策略位置切分：首段类型、末段（或第三段）动作、中间拼回完整值。
        val line = RuleLineParser.split(raw) ?: return ParsedRule(ignoredReason = "invalid_rule")
        return makeRule(line.type, line.value, line.action)
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
            "UID" -> v.toLongOrNull()?.let { it in 0..4_294_967_295L } == true
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
    /** 展开插件参数：`${region}` → 默认值；保留 `${url}` 与 `${request...}` 等运行时变量。 */
    private fun indexOfIgnoreCase(text: String, needle: String, start: Int = 0): Int =
        text.lowercase().indexOf(needle.lowercase(), start)

    /**
     * [Map Local] 行 → Loon `mock-response-body` 行。
     * 支持 data= 内联、data-path/file 本地文件；后者交给内核在 mock_base_dir 下读取。
     * status-code / header 原样带进 mock，内核 parse_mock 已支持。
     */
    private fun mapLocalToLoon(raw: String): Pair<String?, String?> {
        val line = raw.trim()
        val firstSpace = line.indexOfFirst { it.isWhitespace() }
        if (firstSpace <= 0) return null to "invalid_map_local"
        val url = line.substring(0, firstSpace).trim()
        if (url.isEmpty()) return null to "invalid_map_local"
        val params = splitMapArgs(line.substring(firstSpace + 1))
        var dataType = ""
        var data: String? = null
        var dataFile: String? = null
        var statusCode: String? = null
        val headers = mutableListOf<String>()
        for (token in params) {
            val eq = token.indexOf('=')
            if (eq <= 0) continue
            val key = token.substring(0, eq).trim().lowercase()
            var value = token.substring(eq + 1).trim()
            val quoted = value.length >= 2 &&
                ((value.startsWith("\"") && value.endsWith("\"")) ||
                    (value.startsWith("'") && value.endsWith("'"))
                )
            if (quoted) {
                value = value.substring(1, value.length - 1)
            }
            when (key) {
                "data-type" -> dataType = value
                "data" -> data = value
                "status-code" -> statusCode = value
                "header" -> if (value.contains(':')) headers.add(value)
                "data-path", "file" -> dataFile = value
            }
        }
        val body = data
        val file = dataFile
        if (body == null && file == null) return null to "unsupported_map_local_no_data"
        if (dataType.isBlank()) {
            val probe = body?.trimStart().orEmpty()
            dataType = if (probe.startsWith("{") || probe.startsWith("[") ||
                file?.substringAfterLast('.', "")?.lowercase() in setOf("json", "geojson")
            ) "json" else "text"
        }
        fun esc(v: String): String = v.replace("\\", "\\\\").replace("\"", "\\\"")
        val sb = if (body != null) {
            StringBuilder("$url mock-response-body data-type=$dataType data=\"${esc(body)}\"")
        } else {
            StringBuilder("$url mock-response-body data-type=$dataType data-path=\"${esc(file!!)}\"")
        }
        if (!statusCode.isNullOrBlank() && statusCode!!.toIntOrNull() != null) {
            sb.append(" status-code=$statusCode")
        }
        headers.forEach { sb.append(" header=\"${esc(it)}\"") }
        return sb.toString() to null
    }

    /**
     * Surge [Map Remote]：`<源URL前缀> <目标URL>` → Loon URL 替换。
     * 源按字面前缀转正则并捕获剩余路径；目标若已含 $1/${1} 则尊重用户模板，
     * 否则自动拼接捕获段，保留查询串与尾部路径。
     */
    private fun mapRemoteToLoon(raw: String): Pair<String?, String?> {
        val line = raw.trim()
        val firstSpace = line.indexOfFirst { it.isWhitespace() }
        if (firstSpace <= 0) return null to "invalid_map_remote"
        val source = line.substring(0, firstSpace).trim()
        val target = line.substring(firstSpace + 1).trim().trim('"', '\'')
        if (source.isEmpty() || target.isEmpty()) return null to "invalid_map_remote"
        if (!target.startsWith("http://") && !target.startsWith("https://") && !target.startsWith("/")) {
            return null to "invalid_map_remote_target"
        }
        // 已是正则的源（以 ^ 开头或显式 /.../）直接沿用；否则按字面 URL 前缀转义。
        val pattern: String
        val replacement: String
        if (source.startsWith("^") || (source.startsWith("/") && source.lastIndexOf('/') > 0)) {
            pattern = source
            replacement = if (target.contains("$1") || target.contains("${'$'}{1}")) target else target + "\$1"
        } else {
            val prefix = source.trimEnd('/')
            val escaped = regexEscape(prefix)
            pattern = if (source.endsWith("/")) {
                "^$escaped/(.*)$"
            } else {
                "^$escaped(.*)$"
            }
            val base = if (target.contains("$1") || target.contains("${'$'}{1}")) {
                target
            } else if (source.endsWith("/")) {
                target.trimEnd('/') + "/\$1"
            } else {
                target.trimEnd('/') + "\$1"
            }
            replacement = base
        }
        return "$pattern $replacement header" to null
    }

    /** Rust regex 不支持 \Q...\E，逐字符转义元字符。 */
    private fun regexEscape(value: String): String {
        val meta = "\\^$.|?*+()[]{}"
        val sb = StringBuilder(value.length * 2)
        for (c in value) {
            if (c in meta) sb.append('\\')
            sb.append(c)
        }
        return sb.toString()
    }

    /** Map Local 参数按空白切分，但保留引号内空格与 JSON {} / [] 内的空格。 */
    private fun splitMapArgs(raw: String): List<String> {
        val out = mutableListOf<String>()
        val cur = StringBuilder()
        var quote = false
        var escape = false
        var depth = 0
        fun flush() {
            if (cur.isNotEmpty()) { out.add(cur.toString()); cur.clear() }
        }
        for (ch in raw) {
            if (escape) {
                cur.append(ch)
                escape = false
                continue
            }
            when {
                // 反斜杠转义在引号内外都成立：Surge Body Rewrite 的正文正则常把
                // 双引号写成 \"，不能让它切换引号状态，否则整行会被切成 2 个 token。
                ch == '\\' -> { cur.append(ch); escape = true }
                ch == '"' -> { quote = !quote; cur.append(ch) }
                !quote && (ch == '{' || ch == '[') -> { depth++; cur.append(ch) }
                !quote && (ch == '}' || ch == ']') -> { depth--; cur.append(ch) }
                !quote && depth == 0 && ch.isWhitespace() -> flush()
                else -> cur.append(ch)
            }
        }
        flush()
        return out
    }

    /** 从 Script v2 条件里提取 URL 预筛正则；顶层 || 或无 ${'$'}{url} 分支时返回 .*。 */
    private fun scriptConditionPrefilter(condition: String): String {
        if (condition.contains("||")) return ".*"
        val marker = "${'$'}{url}"
        val idx = condition.indexOf(marker)
        if (idx < 0) return ".*"
        var rest = condition.substring(idx + marker.length).trim()
        if (!rest.startsWith("~=")) return ".*"
        rest = rest.removePrefix("~=").trim()
        // 截到下一个 && 之前；正则字面量本身可能包含 &&，但 Loon 条件里极少见。
        val literal = rest.substringBefore("&&").trim()
        return regexLiteral(literal) ?: ".*"
    }

    /**
     * Loon 3.5.1 Script v2：
     * `request if ${url} ~= /re/ then script("a.js", {${x}}) with requires_body=true, timeout=5, tag="x"`
     * 条件表达式原样透传给内核 LoonCond 求值，支持 &&/||/header 条件；
     * 内核不认的形式会显式报错，不再按旧语法误解析成「看起来生效、实际不执行」。
     * cron 无调度器，明确拒绝。
     */
    private fun parseScriptV2(
        raw: String,
        moduleArgs: Map<String, String>,
        moduleTypes: Map<String, String>,
    ): Pair<ScriptConfig?, String?>? {
        val lower = raw.trim().lowercase()
        if (!lower.startsWith("request if ") && !lower.startsWith("response if ") &&
            !lower.startsWith("cron ") && !lower.startsWith("network-changed ") &&
            !lower.startsWith("generic ")
        ) {
            return null
        }
        if (lower.startsWith("cron ")) {
            val m = Regex("""^cron\s+"([^"]+)"\s+(.+)$""", RegexOption.IGNORE_CASE).find(raw.trim())
                ?: return null to "cron 需要 cron \"...\" script-path=...: ${raw.take(80)}"
            val expr = m.groupValues[1].trim()
            val cronIssue = validateCronExpr(expr)
            if (cronIssue != null) return null to "cron 表达式$cronIssue: $expr"
            val rest = m.groupValues[2].trim()
            // 同时接受 cron "expr" script-path=... 与 cron "expr" script("url") 两种写法。
            val call = Regex("""^script\s*\(\s*"([^"]+)"\s*(?:,\s*\{[^)]*\})?\s*\)""").find(rest)
            val normalized = if (call != null) "type=cron script-path=${call.groupValues[1]}" else "type=cron $rest"
            val parsed = parseScriptLine(normalized, moduleArgs, moduleTypes)
            val rule = parsed.first ?: return parsed
            return rule.copy(phase = "cron", pattern = ".*", cron = expr, trigger = "cron") to null
        }
        if (lower.startsWith("network-changed ") || lower.startsWith("generic ")) {
            val kind = if (lower.startsWith("network-changed ")) "network-changed" else "generic"
            val rest = raw.trim().substring(kind.length).trim()
            val parsed = parseScriptLine("type=cron " + rest, moduleArgs, moduleTypes)
            val rule = parsed.first ?: return parsed
            return rule.copy(phase = "cron", pattern = ".*", trigger = kind) to null
        }
        val line = raw.trim()
        val thenIdx = indexOfIgnoreCase(line, " then ")
        if (thenIdx <= 0) return null to "Script v2 缺少 then: ${line.take(80)}"
        val phase = if (line.lowercase().startsWith("request if ")) "request" else "response"
        val condRaw = line.substring(line.indexOf(" if ") + 4, thenIdx).trim()
        val condition = condRaw.substringBefore(" as ").trim()
        if (condition.isBlank()) return null to "Script v2 条件为空: ${line.take(80)}"
        // pattern 只做预筛：有 URL 分支时沿用其正则，无 URL 分支或顶层 || 时放宽到 .*，
        // 精确命中交给内核 LoonCond 条件树（按实际请求/响应头求值）。
        val pattern = scriptConditionPrefilter(condition)
        val actionRaw = line.substring(thenIdx + 6).trim()
        val call = Regex("""^script\s*\(\s*"([^"]+)"\s*(?:,\s*\{[^)]*\})?\s*\)""").find(actionRaw)
            ?: return null to "Script v2 动作只支持 script(\"http(s)://...\"): ${actionRaw.take(80)}"
        val scriptPath = call.groupValues[1].trim()
        val withRaw = actionRaw.substring(call.range.last + 1).trim().removePrefix("with").trim()
        var requiresBody = false
        var binaryBody = false
        var timeoutMs = 5000
        var tag = ""
        var enabled = true
        var enableParam = ""
        for (opt in splitTopLevel(withRaw)) {
            val i = opt.indexOf('=')
            if (i <= 0) continue
            val key = opt.substring(0, i).trim().lowercase()
            val value = opt.substring(i + 1).trim().trim('"', '\'')
            when (key) {
                "requires_body", "requires-body" -> requiresBody = value.lowercase() in setOf("1", "true", "yes", "on")
                "binary_body_mode", "binary-body-mode" -> binaryBody = value.lowercase() in setOf("1", "true", "yes", "on")
                "timeout" -> {
                    val n = value.toIntOrNull() ?: 0
                    timeoutMs = if (n in 1..60) n * 1000 else n.coerceAtLeast(50)
                }
                "tag", "name" -> tag = value
                "enable", "enabled" -> {
                    // Loon 只认 enable；`${name}` 交给插件开关在运行期决定，
                    // 不能在这里烘焙成 bool，否则用户拨动开关不会生效。
                    val ref = Regex("""^\$\{([^}]+)}$""").find(value.trim())
                    if (ref != null) enableParam = ref.groupValues[1].trim()
                    else enabled = value.lowercase() !in setOf("0", "false", "no", "off")
                }
            }
        }
        if (!scriptPath.startsWith("http://") && !scriptPath.startsWith("https://")) {
            return null to "script-path 只支持 http/https: $scriptPath"
        }
        val args = LinkedHashMap(moduleArgs)
        return ScriptConfig(
            name = tag.ifBlank { scriptPath.substringAfterLast('/').ifBlank { pattern.take(48) } },
            phase = phase,
            pattern = pattern,
            condition = condition,
            source = "",
            arguments = args,
            argumentTypes = moduleTypes.filterKeys { args.containsKey(it) },
            timeoutMs = timeoutMs.coerceIn(50, 10_000),
            maxSize = 2 * 1024 * 1024,
            requiresBody = requiresBody || binaryBody,
            binaryBodyMode = binaryBody,
            scriptPath = scriptPath,
            enabled = enabled,
            enableParam = enableParam,
        ) to null
    }

    private fun validateCronExpr(expr: String): String? {
        val fields = expr.trim().split(Regex("""\s+""")).filter { it.isNotBlank() }
        if (fields.size != 5) return "必须是 5 段"
        if (fields.any { it.any { c -> !(c.isDigit() || c == '*' || c == '/' || c == ',' || c == '-') } }) {
            return "含不支持的字符"
        }
        val ranges = listOf(0 to 59, 0 to 23, 1 to 31, 1 to 12, 0 to 7)
        for ((idx, field) in fields.withIndex()) {
            val issue = validateCronField(field, ranges[idx].first, ranges[idx].second)
            if (issue != null) return "第 ${idx + 1} 段$issue"
        }
        return null
    }

    /** 与 Rust cron 解析保持一致：支持 *、星号斜杠步进、a-b、a-b 斜杠步进、逗号列表。 */
    private fun validateCronField(field: String, min: Int, max: Int): String? {
        for (part in field.split(',')) {
            if (part.isBlank()) return "有空项"
            val slash = part.split('/')
            if (slash.size > 2) return "步进格式错误"
            val base = slash[0]
            if (slash.size == 2) {
                val step = slash[1].toIntOrNull()
                if (step == null || step <= 0) return "步进必须为正整数"
            }
            if (base == "*") continue
            val dash = base.split('-')
            if (dash.size > 2) return "范围格式错误"
            val lo = dash[0].toIntOrNull() ?: return "不是数字"
            val hi = if (dash.size == 2) (dash[1].toIntOrNull() ?: return "范围终点不是数字") else lo
            if (lo < min || hi > max) return "超出 $min-$max"
            if (lo > hi) return "范围起止颠倒"
        }
        return null
    }

    /** 提取 `/regex/` 字面量；内部允许转义斜杠，取最后一个未转义 `/` 收尾。 */
    private fun regexLiteral(raw: String): String? {
        val t = raw.trim()
        if (!t.startsWith("/")) return null
        var end = -1
        var escaped = false
        for (i in 1 until t.length) {
            val c = t[i]
            if (escaped) { escaped = false; continue }
            if (c == '\\') { escaped = true; continue }
            if (c == '/') end = i
        }
        if (end <= 0) return null
        return t.substring(1, end).ifBlank { null }
    }

    /** 按顶层逗号切分，尊重引号与 {} 嵌套。 */
    private fun splitTopLevel(raw: String): List<String> {
        val out = mutableListOf<String>()
        val cur = StringBuilder()
        var depth = 0
        var quote = '\u0000'
        for (ch in raw) {
            when {
                quote != '\u0000' -> {
                    cur.append(ch)
                    if (ch == quote) quote = '\u0000'
                }
                ch == '"' || ch == '\'' -> {
                    quote = ch
                    cur.append(ch)
                }
                ch == '{' || ch == '(' -> { depth++; cur.append(ch) }
                ch == '}' || ch == ')' -> { depth--; cur.append(ch) }
                ch == ',' && depth == 0 -> {
                    if (cur.isNotBlank()) out.add(cur.toString().trim())
                    cur.clear()
                }
                else -> cur.append(ch)
            }
        }
        if (cur.isNotBlank()) out.add(cur.toString().trim())
        return out
    }

    private fun parseScriptLine(raw: String, moduleArgs: Map<String, String>, moduleTypes: Map<String, String> = emptyMap()): Pair<ScriptConfig?, String?> {
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
        var enableParam = ""
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
                    "enable" -> {
                        // Loon 只认 enable；`${name}` 留给运行期按开关求值。
                        val ref = Regex("""^\$\{([^}]+)}$""").find(value.trim())
                        if (ref != null) enableParam = ref.groupValues[1].trim()
                        else enabled = value.lowercase() !in setOf("0", "false", "no", "off")
                    }
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
            phase.contains("cron") -> "cron"
            phase.contains("request") && !phase.contains("response") -> "request"
            phase.contains("response") -> "response"
            else -> ""
        }
        // 禁用不等于解析失败：条目照常产出并标 disabled，界面可见、内核不跑。
        if (phase == "cron" && pattern.isBlank()) pattern = ".*"
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
            argumentTypes = moduleTypes.filterKeys { args.containsKey(it) },
            timeoutMs = timeoutMs.coerceIn(50, 10_000),
            maxSize = if (maxSize <= 0) 2 * 1024 * 1024 else maxSize.coerceIn(4096, 8 * 1024 * 1024),
            requiresBody = requiresBody || binaryBody,
            binaryBodyMode = binaryBody,
            scriptPath = scriptPath,
            argumentText = argumentText,
            enabled = enabled,
            enableParam = enableParam,
        ) to null
    }

    /** 逗号/空白分隔，但保留引号内的空格和逗号。 */
    /**
     * 解析 Loon [Argument] 声明，返回 key -> (默认值, 类型)。
     * 支持 `input,"Loon",type=string`、`select,"CN","US",type=string`、
     * `input,9.99,type=number`、`switch,true,type=boolean`；未写 type 时
     * switch 判 boolean，其余按 string。number 解析失败降为 string，不注入 NaN。
     */
    private fun parseArgumentDecl(raw: String): Pair<String, Pair<String, String>>? {
        val line = raw.trim()
        val eq = line.indexOf('=')
        if (eq <= 0) return null
        val key = line.substring(0, eq).trim()
        if (key.isEmpty()) return null
        val tokens = splitScriptTokens(line.substring(eq + 1))
        if (tokens.isEmpty()) return null
        val control = tokens[0].lowercase()
        val hasControl = control in setOf("input", "select", "switch", "checkbox", "text", "password", "slider")
        var declared = ""
        val candidates = mutableListOf<String>()
        for (token in if (hasControl) tokens.drop(1) else tokens) {
            val i = token.indexOf('=')
            if (i > 0) {
                val k = token.substring(0, i).trim().lowercase()
                if (k == "type") declared = token.substring(i + 1).trim().trim('"', '\'').lowercase()
                // tag / desc / enable 等展示字段不参与取值
                continue
            }
            candidates.add(token.trim().trim('"', '\''))
        }
        val value = candidates.firstOrNull() ?: ""
        var type = when {
            declared in setOf("string", "number", "boolean") -> declared
            control == "switch" -> "boolean"
            else -> "string"
        }
        val normalized = when (type) {
            "boolean" -> if (value.lowercase() in setOf("1", "true", "yes", "on")) "true" else "false"
            "number" -> if (value.toDoubleOrNull() != null) value else {
                type = "string"
                value
            }
            else -> value
        }
        return key to (normalized to type)
    }

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

    private fun normalizeBodyRewrite(line: String): String? {
        val tokens = splitMapArgs(line)
        if (tokens.size != 4) return null
        val action = tokens[0].trim().lowercase()
        if (action != "http-request" && action != "http-response") return null
        val url = unquoteToken(tokens[1])
        if (url.isBlank()) return null
        if (tokens[2].trim().equals("jq", ignoreCase = true)) {
            val expr = unquoteToken(tokens[3])
            if (!miniJqSupported(expr)) return null
            return "$action ${tokens[1]} jq ${tokens[3]}"
        }
        val pattern = unquoteToken(tokens[2])
        return runCatching {
            Regex(url)
            Regex(pattern)
            "$action ${tokens[1]} ${tokens[2]} ${tokens[3]}"
        }.getOrNull()
    }

    /** mini jq 的解析期白名单：只允许三种表达式，其余在导入时就拒绝。 */
    private fun miniJqSupported(expr: String): Boolean {
        val e = expr.trim()
        if (e.startsWith("del(") && e.endsWith(")")) {
            return miniJqPath(e.substring(4, e.length - 1))
        }
        val eq = e.indexOf(" = ")
        if (eq >= 0) {
            val path = e.substring(0, eq).trim()
            val value = e.substring(eq + 3).trim()
            if (value.contains('=')) return false
            if (!miniJqPath(path)) return false
            return runCatching {
                // 包进对象属性再解析，既校验完整 JSON 字面量，也避免 nextValue 的尾部宽容。
                JSONObject("{\"v\":$value}").get("v")
            }.isSuccess
        }
        return miniJqPath(e)
    }

    private fun miniJqPath(raw: String): Boolean {
        val e = raw.trim()
        if (!e.startsWith(".")) return false
        val p = e.removePrefix(".")
        if (p.isEmpty() || p.contains("..")) return false
        var i = 0
        while (i < p.length) {
            val start = i
            while (i < p.length && (p[i].isLetterOrDigit() || p[i] == '_' || p[i] == '-')) i++
            if (i == start) return false
            while (i < p.length && p[i] == '[') {
                i++
                val n0 = i
                while (i < p.length && p[i].isDigit()) i++
                if (i == n0 || i >= p.length || p[i] != ']') return false
                i++
            }
            if (i == p.length) return true
            if (p[i] != '.') return false
            i++
            if (i == p.length) return false
        }
        return true
    }

    private fun unquoteToken(raw: String): String {
        val s = raw.trim()
        return if (s.length >= 2 && (s.first() == '"' || s.first() == '\'') && s.last() == s.first()) {
            s.substring(1, s.length - 1)
                .replace("\\\"", "\"")
                .replace("\\'", "'")
        } else s
    }

    private fun validateHostMapping(key: String, value: String): String? {
        if (key.isBlank()) return "host_mapping_invalid"
        val base = if (key.startsWith("*.")) key.removePrefix("*.") else key
        if (base.isBlank() || key.count { it == '*' } > 1 || !isValidAdsDomain(base)) {
            return "host_mapping_invalid"
        }
        if (value.isBlank()) return "host_mapping_invalid"
        if (value.startsWith("server:", ignoreCase = true)) {
            val server = value.substringAfter(':').trim()
            if (server.equals("system", ignoreCase = true)) return "host_server_system_unsupported"
            if (server.startsWith("http://", ignoreCase = true)) return "host_server_http_unsupported"
            if (server.startsWith("https://", ignoreCase = true) ||
                server.startsWith("tls://", ignoreCase = true) ||
                server.startsWith("dot://", ignoreCase = true) ||
                server.startsWith("udp://", ignoreCase = true) ||
                (!server.contains("://") && server.isNotBlank())
            ) return null
            return "host_server_scheme_unsupported"
        }
        val parts = value.split(',', ' ', '\t').map { it.trim() }.filter { it.isNotEmpty() }
        if (parts.isNotEmpty() && parts.all { isIpLiteral(it) }) return null
        if (parts.size == 1 && isValidAdsDomain(parts[0].trim('.'))) return null
        return "host_mapping_invalid"
    }

    private fun isIpLiteral(raw: String): Boolean {
        val s = raw.trim()
        val v4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$").matchEntire(s)
        if (v4 != null) {
            return (1..4).all { i ->
                val n = v4.groupValues[i].toIntOrNull()
                n != null && n in 0..255
            }
        }
        if (!s.contains(':')) return false
        return runCatching { java.net.InetAddress.getByName(s); true }.getOrDefault(false)
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
