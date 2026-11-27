package com.namu.dns.core.config

import com.namu.dns.ProxyGroup
import com.namu.dns.RuleItem

/**
 * 导入/刷新前的整份路由校验。
 *
 * 策略组自身的空组、循环、失效成员由 [ProxyGroupValidation] 负责；这里补上
 * 「规则动作 / FINAL 指向的策略组或节点是否仍然存在」以及来源归属提示。
 * 校验失败时调用方必须放弃本次写入，继续使用界面、磁盘和运行内核里的上一版配置。
 */
object RoutingValidation {
    private val BUILTIN_ACTIONS = setOf(
        "direct", "dir", "proxy", "proxies", "block", "reject", "deny", "", "null",
    )

    fun validate(
        groups: List<ProxyGroup>,
        nodeNames: Collection<String>,
        rules: List<RuleItem>,
        finalPolicy: String,
        finalPolicySource: String = "",
        selections: Map<String, String> = emptyMap(),
    ): List<ConfigIssue> {
        val issues = ProxyGroupValidation.validate(groups, nodeNames, selections).toMutableList()
        val groupNames = groups.map { it.name.trim() }.filter { it.isNotBlank() }.toSet()
        val nodes = nodeNames.map { it.trim() }.filter { it.isNotBlank() }.toSet()
        val duplicates = groups.filter { it.name.isNotBlank() }.groupingBy { it.name.trim() }
            .eachCount().filterValues { it > 1 }.keys

        fun actionTarget(action: String): String =
            action.split(',').firstOrNull()?.trim().orEmpty()

        fun checkTarget(target: String, path: String, what: String, legacyHint: Boolean = false) {
            val t = target.trim()
            if (t.lowercase() in BUILTIN_ACTIONS) return
            val name = if (t.startsWith("node:")) t.removePrefix("node:").trim() else t
            val isNode = name in nodes
            val isGroup = name in groupNames
            when {
                t.startsWith("node:") && !isNode -> issues += ConfigIssue(
                    ConfigIssueLevel.ERROR,
                    path,
                    "$what 指向已删除的节点：$name" + legacyHintSuffix(legacyHint),
                )
                !t.startsWith("node:") && isGroup && name in duplicates -> issues += ConfigIssue(
                    ConfigIssueLevel.ERROR,
                    path,
                    "$what 命中的策略组名重复，无法唯一解析：$name",
                )
                !t.startsWith("node:") && !isGroup && !isNode -> issues += ConfigIssue(
                    ConfigIssueLevel.ERROR,
                    path,
                    "$what 指向已删除的策略组或节点：$name" + legacyHintSuffix(legacyHint),
                )
                !t.startsWith("node:") && isNode && isGroup -> issues += ConfigIssue(
                    ConfigIssueLevel.ERROR,
                    path,
                    "$what 的 $name 同时是节点和策略组，引用有歧义",
                )
            }
        }

        rules.forEachIndexed { index, rule ->
            if (!rule.enabled) return@forEachIndexed
            if (rule.type.uppercase() in setOf("FINAL", "MATCH")) return@forEachIndexed
            val legacy = rule.subscriptionSource.isBlank() && rule.source == "订阅"
            checkTarget(actionTarget(rule.action), "rules[$index].action", "规则 ${rule.type},${rule.value}", legacy)
        }
        val finalLegacy = finalPolicy.isNotBlank() && finalPolicySource.isBlank()
        checkTarget(actionTarget(finalPolicy), "finalPolicy", "FINAL", finalLegacy)
        return issues
    }

    private fun legacyHintSuffix(legacy: Boolean): String =
        if (legacy) "（旧版来源不确定，请检查配置）" else ""

    fun errorText(issues: List<ConfigIssue>): String =
        issues.filter { it.level == ConfigIssueLevel.ERROR }
            .joinToString("\n") { "· ${it.message}" }
}
