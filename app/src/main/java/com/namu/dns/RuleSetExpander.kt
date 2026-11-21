package com.namu.dns

import org.json.JSONObject

/**
 * 规则集内容展开器（纯逻辑，可单测）。
 *
 * 端上拉到的规则集不止 Surge 文本一种载体，常见还有 Clash 的 `payload:` YAML
 * 与 sing-box 的 source JSON。三种都按同一套语义展开，集合策略覆盖行内策略；
 * 逐条无法表达的（IP/端口/进程等）统计进 [ExpandResult.skipped] 并给出原因，
 * 让上层能提示「这个规则集一条都没生效」，而不是静默产出空列表。
 *
 * 支持：
 * - Surge/Loon 文本：每行 `TYPE,value[,policy][,no-resolve]`，值可含逗号（正则量词）。
 * - Clash `payload:`：`- 'DOMAIN-SUFFIX,x'`、`+.x`（后缀）、`*.x`（通配）、裸域名。
 * - sing-box source JSON：`{"rules":[{"domain":[],"domain_suffix":[],...}]}`；
 *   含 ip_cidr / port / invert 等非域名条件时整条跳过（AND 语义，绝不只留域名条件误杀）。
 * - DOMAIN-SET：域名列表。
 *
 * 二进制 `.srs` 端上不解析，直接返回明确原因。
 */
object RuleSetExpander {
    private val LIST_TYPES = setOf(
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD",
        "IP-CIDR", "IP-CIDR6", "GEOIP", "PORT", "PROTOCOL",
    )
    private val SINGBOX_KEYS = listOf("domain", "domain_suffix", "domain_keyword", "domain_regex")

    data class ExpandResult(
        val items: List<RuleItem>,
        /** text / clash-yaml / sing-box-json / domain-set / binary / empty */
        val format: String,
        val skipped: Int,
        val note: String? = null,
    )

    fun expand(kind: String, content: String, action: String, source: String): List<RuleItem> =
        expandDetailed(kind, content, action, source).items

    fun expandDetailed(kind: String, content: String, action: String, source: String): ExpandResult {
        if (content.isBlank()) return ExpandResult(emptyList(), "empty", 1, "内容为空")
        if (looksBinary(content)) {
            return ExpandResult(
                emptyList(),
                "binary",
                1,
                "二进制规则集（.srs）端上不解析，请改用 source JSON 或 Clash YAML 版本",
            )
        }
        val trimmed = content.trimStart()
        if (trimmed.startsWith("{")) {
            parseSingBoxJson(content, action, source)?.let { return it }
        }
        if (kind == "DOMAIN-SET") return parseDomainList(content, action, source)
        return parseTextRules(content, action, source)
    }

    // ---- sing-box source JSON ----

    private fun parseSingBoxJson(content: String, action: String, source: String): ExpandResult? {
        val root = runCatching { JSONObject(content) }.getOrNull() ?: return null
        val rules = root.optJSONArray("rules") ?: return null
        val out = mutableListOf<RuleItem>()
        var skipped = 0
        val skippedKeys = linkedSetOf<String>()
        for (i in 0 until rules.length()) {
            val rule = rules.optJSONObject(i)
            if (rule == null) {
                skipped++
                continue
            }
            val extra = rule.keys().asSequence().filter { it !in SINGBOX_KEYS }.toList()
            if (extra.isNotEmpty()) {
                // sing-box 条件之间是 AND：有非域名条件就整条跳过，避免误杀。
                skipped++
                extra.take(2).forEach { skippedKeys.add(it) }
                continue
            }
            var added = 0
            for (key in SINGBOX_KEYS) {
                val arr = rule.optJSONArray(key) ?: continue
                val type = when (key) {
                    "domain" -> "DOMAIN"
                    "domain_suffix" -> "DOMAIN-SUFFIX"
                    "domain_keyword" -> "DOMAIN-KEYWORD"
                    else -> "DOMAIN-REGEX"
                }
                for (j in 0 until arr.length()) {
                    val v = arr.optString(j, "").trim()
                    if (v.isEmpty()) continue
                    if (type == "DOMAIN-REGEX" && runCatching { Regex(v) }.isFailure) continue
                    out.add(RuleItem(type, v, action, source))
                    added++
                }
            }
            if (added == 0) skipped++
        }
        val note = buildNote(skipped, skippedKeys, "条规则")
        return ExpandResult(out, "sing-box-json", skipped, note)
    }

    // ---- DOMAIN-SET 纯域名列表 ----

    private fun parseDomainList(content: String, action: String, source: String): ExpandResult {
        val out = mutableListOf<RuleItem>()
        var skipped = 0
        for (raw in content.lineSequence()) {
            val line = raw.trim().trim('"').trim('\'')
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) continue
            if (line.any { it.isWhitespace() }) {
                skipped++
                continue
            }
            when {
                line.startsWith("*.") -> out.add(RuleItem("DOMAIN-WILDCARD", line, action, source))
                line.startsWith(".") -> out.add(RuleItem("DOMAIN-SUFFIX", line.removePrefix("."), action, source))
                else -> out.add(RuleItem("DOMAIN", line, action, source))
            }
        }
        return ExpandResult(out, "domain-set", skipped, buildNote(skipped, emptySet(), "行"))
    }

    // ---- Surge 文本 / Clash payload ----

    private fun parseTextRules(content: String, action: String, source: String): ExpandResult {
        val out = mutableListOf<RuleItem>()
        var skipped = 0
        val skippedTypes = linkedSetOf<String>()
        var clash = false
        for (raw in content.lineSequence()) {
            var line = raw.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) continue
            if (line.equals("payload:", ignoreCase = true)) {
                clash = true
                continue
            }
            if (line.startsWith("- ")) {
                clash = true
                line = line.removePrefix("- ").trim()
            }
            if (line.startsWith("[") || line.endsWith("]")) {
                // Clash 行内写法 payload: ['DOMAIN,a', 'DOMAIN,b']
                clash = true
                line = line.removePrefix("[").removeSuffix("]").trim()
            }
            for (entry in splitInlineList(line)) {
                val added = parseTextEntry(entry, action, source, out, skippedTypes)
                if (!added) skipped++
            }
        }
        val note = buildNote(skipped, skippedTypes, "行")
        return ExpandResult(out, if (clash) "clash-yaml" else "text", skipped, note)
    }

    private fun splitInlineList(line: String): List<String> {
        if (!line.contains("', '") && !line.contains("\", \"")) return listOf(line)
        return line.split("', '", "\", \"")
            .map { it.trim(',', ' ', '\'', '"') }
            .filter { it.isNotEmpty() }
    }

    private fun parseTextEntry(
        entry: String,
        action: String,
        source: String,
        out: MutableList<RuleItem>,
        skippedTypes: MutableSet<String>,
    ): Boolean {
        val e = entry.trim().trim('"').trim('\'').trim()
        if (e.isEmpty()) return false
        if (e.startsWith("+.")) {
            val v = e.removePrefix("+.")
            if (v.isEmpty() || v.any { it.isWhitespace() }) return false
            out.add(RuleItem("DOMAIN-SUFFIX", v, action, source))
            return true
        }
        if (e.startsWith("*.")) {
            if (e.any { it.isWhitespace() }) return false
            out.add(RuleItem("DOMAIN-WILDCARD", e, action, source))
            return true
        }
        if (',' !in e) {
            // Clash 允许裸域名，按精确匹配处理。
            if (e.any { it.isWhitespace() }) return false
            out.add(RuleItem("DOMAIN", e, action, source))
            return true
        }
        val line = RuleLineParser.split(e, requireAction = false) ?: return false
        if (line.type !in LIST_TYPES) {
            skippedTypes.add(line.type)
            return false
        }
        if (line.type == "DOMAIN-REGEX" && runCatching { Regex(line.value) }.isFailure) return false
        out.add(RuleItem(line.type, line.value, action, source))
        return true
    }

    // ---- 工具 ----

    private fun buildNote(skipped: Int, types: Set<String>, unit: String): String? {
        if (skipped <= 0) return null
        val typesText = if (types.isEmpty()) "" else "（${types.joinToString("/")} 等类型端上不支持）"
        return "跳过 $skipped $unit$typesText"
    }

    /** .srs 是二进制格式；用控制字符占比判断，避免把中文注释误判成二进制。 */
    private fun looksBinary(s: String): Boolean {
        if (s.startsWith("SRS")) return true
        val sample = s.take(2048)
        if (sample.isEmpty()) return false
        var bad = 0
        for (c in sample) {
            if (c.code < 0x20 && c != '\n' && c != '\r' && c != '\t') bad++
            if (c.code == 0x7f) bad++
        }
        return bad > 8 && bad * 10 > sample.length
    }
}
