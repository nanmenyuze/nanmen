package com.namu.dns

/**
 * 规则集内容展开器（纯逻辑，可单测）：
 * - RULE-SET：Surge/Loon 规则列表，每行 `TYPE,value[,policy]`；
 *   集合策略（RULE-SET 行的动作）覆盖行内策略；不支持的类型跳过不静默错配。
 * - DOMAIN-SET：域名列表，`.x`=后缀（含 apex）、`*.x`=通配子域、裸域名=精确。
 * 展开结果交给 RuleEngine 执行，与手写规则同一条判定路径。
 */
object RuleSetExpander {
    private val LIST_TYPES = setOf(
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD",
        "IP-CIDR", "IP-CIDR6", "GEOIP", "PORT", "PROTOCOL",
    )

    fun expand(kind: String, content: String, action: String, source: String): List<RuleItem> {
        val out = mutableListOf<RuleItem>()
        for (raw in content.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) continue
            if (kind == "DOMAIN-SET") {
                val d = line.trim('"')
                if (d.isEmpty() || d.any { it.isWhitespace() }) continue
                when {
                    d.startsWith("*.") -> out.add(RuleItem("DOMAIN-WILDCARD", d, action, source))
                    d.startsWith(".") -> out.add(RuleItem("DOMAIN-SUFFIX", d.removePrefix("."), action, source))
                    else -> out.add(RuleItem("DOMAIN", d, action, source))
                }
            } else {
                val parts = line.split(',')
                if (parts.size < 2) continue
                val t = parts[0].trim().uppercase()
                val v = parts[1].trim().trim('"')
                if (t !in LIST_TYPES || v.isEmpty()) continue
                // 集合策略覆盖行内策略（Surge RULE-SET 语义）。
                out.add(RuleItem(t, v, action, source))
            }
        }
        return out
    }
}
