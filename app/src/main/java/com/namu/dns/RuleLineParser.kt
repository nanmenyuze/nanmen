package com.namu.dns

/**
 * RULE 行的 CSV 拆分（纯逻辑，可单测）。
 *
 * 值的中间段可能自带逗号：DOMAIN-REGEX 的量词 `{1,3}`、URL-REGEX 的查询串、
 * 规则集 URL 的参数。所以不能硬取 `parts[1]`/`parts[2]`，必须按策略位置切：
 * - 策略优先取末段；
 * - 末段不是策略时（`IP-CIDR,x,DIRECT,no-resolve` 这类尾随参数），回退到第三段；
 * - 类型与策略之间的所有段拼回成完整值。
 *
 * 规则集行允许不带策略（集合策略覆盖行内策略），此时 [requireAction]=false：
 * 只剥掉 `no-resolve` 等已知尾随选项，其余整段都算值。
 */
object RuleLineParser {
    private val POLICIES = setOf(
        "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "REJECT-NO-DROP", "BLOCK", "DIRECT", "PROXY",
    )
    private val TRAILING_OPTIONS = setOf(
        "no-resolve", "no-drop", "pre-matching", "force-remote-dns", "dns-failed", "extended-matching",
    )

    data class Line(
        val type: String,
        val value: String,
        /** 空串表示该行未写策略（仅 requireAction=false 时出现）。 */
        val action: String,
        val trailing: List<String>,
    )

    fun isPolicy(token: String): Boolean {
        val t = token.trim().uppercase()
        return t in POLICIES || t.startsWith("REJECT-")
    }

    fun split(raw: String, requireAction: Boolean = true): Line? {
        val parts = raw.split(',')
        if (parts.size < 2) return null
        val type = parts[0].trim().uppercase()
        if (type.isEmpty()) return null
        val lastIdx = parts.size - 1
        if (parts.size < 3) {
            if (requireAction) return null
            val v = parts[1].trim().trim('"')
            return if (v.isEmpty()) null else Line(type, v, "", emptyList())
        }
        var actionIdx = when {
            isPolicy(parts[lastIdx]) -> lastIdx
            isPolicy(parts[2]) -> 2
            else -> -1
        }
        if (actionIdx == -1) {
            if (requireAction) {
                // 保持旧语义：末段当作策略位，交给上层判 unsupported。
                actionIdx = lastIdx
            } else {
                var end = parts.size
                val trailing = mutableListOf<String>()
                while (end > 1 && parts[end - 1].trim().lowercase() in TRAILING_OPTIONS) {
                    trailing.add(0, parts[end - 1].trim())
                    end--
                }
                val value = parts.subList(1, end).joinToString(",").trim().trim('"')
                if (value.isEmpty()) return null
                return Line(type, value, "", trailing)
            }
        }
        if (actionIdx < 1) return null
        val value = parts.subList(1, actionIdx).joinToString(",").trim().trim('"')
        if (value.isEmpty()) return null
        val trailing = parts.subList(actionIdx + 1, parts.size)
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        return Line(type, value, parts[actionIdx].trim(), trailing)
    }
}
