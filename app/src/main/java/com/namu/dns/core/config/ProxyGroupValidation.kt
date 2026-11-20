package com.namu.dns.core.config

import com.namu.dns.ProxyGroup

/**
 * 策略组的壳层诊断，用于导入预览和编辑页即时提示。
 * 运行时仍以内核 StrategySet 为准；这里只做同规则的前置检查，避免明显错误被静默保存。
 */
object ProxyGroupValidation {
    fun validate(
        groups: List<ProxyGroup>,
        nodeNames: Collection<String>,
        selections: Map<String, String> = emptyMap(),
    ): List<ConfigIssue> {
        val issues = mutableListOf<ConfigIssue>()
        val names = groups.map { it.name.trim() }.filter { it.isNotBlank() }
        names.groupingBy { it }.eachCount().filter { it.value > 1 }.keys.forEach {
            issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxyGroups", "策略组名重复：$it")
        }
        val groupByName = groups.filter { it.name.isNotBlank() }.groupBy { it.name.trim() }
        val nodes = nodeNames.filter { it.isNotBlank() }.toSet()
        groups.forEachIndexed { i, g ->
            val name = g.name.trim()
            if (name.isBlank()) {
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxyGroups[$i].name", "策略组名称为空")
                return@forEachIndexed
            }
            if (g.type !in setOf("select", "url-test", "fallback")) {
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxyGroups[$i].type", "未知类型：${g.type}")
            }
            if (g.members.isEmpty()) {
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxyGroups[$i].members", "策略组没有成员")
            }
            g.members.groupingBy { it }.eachCount().filter { it.value > 1 }.keys.forEach {
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxyGroups[$i].members", "成员重复：$it")
            }
            if (name in g.members) {
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxyGroups[$i].members", "策略组不能引用自身")
            }
            if (g.interval !in 5..86_400) {
                issues += ConfigIssue(ConfigIssueLevel.WARNING, "proxyGroups[$i].interval", "检查间隔应在 5–86400 秒")
            }
            if (g.timeout !in 500..30_000) {
                issues += ConfigIssue(ConfigIssueLevel.WARNING, "proxyGroups[$i].timeout", "超时应在 500–30000 毫秒")
            }
            if (g.tolerance !in 0..30_000) {
                issues += ConfigIssue(ConfigIssueLevel.WARNING, "proxyGroups[$i].tolerance", "切换容差应在 0–30000 毫秒")
            }
            if (g.noNodeAction !in setOf("global", "block", "direct")) {
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxyGroups[$i].noNodeAction", "未知无可用节点策略")
            }
            g.members.forEachIndexed { mi, raw ->
                val m = raw.trim()
                val isNode = m in nodes
                val isGroup = m in groupByName
                val nodeDup = nodeNames.count { it.trim() == m } > 1
                val groupDup = (groupByName[m]?.size ?: 0) > 1
                when {
                    isNode && isGroup -> issues += ConfigIssue(
                        ConfigIssueLevel.ERROR, "proxyGroups[$i].members[$mi]",
                        "成员 $m 同时是节点和策略组，引用有歧义",
                    )
                    !isNode && !isGroup -> issues += ConfigIssue(
                        ConfigIssueLevel.ERROR, "proxyGroups[$i].members[$mi]",
                        "成员不存在：$m（节点已删除或名称已变更）",
                    )
                    isNode && nodeDup -> issues += ConfigIssue(
                        ConfigIssueLevel.ERROR, "proxyGroups[$i].members[$mi]",
                        "成员 $m 命中重复节点名，无法唯一解析",
                    )
                    isGroup && groupDup -> issues += ConfigIssue(
                        ConfigIssueLevel.ERROR, "proxyGroups[$i].members[$mi]",
                        "成员 $m 命中重复策略组名，无法唯一解析",
                    )
                }
            }
        }

        // 三色 DFS 检测嵌套循环；环上的组全部不可启用。
        val state = mutableMapOf<String, Int>()
        val stack = mutableListOf<String>()
        fun visit(name: String) {
            if (state[name] == 1) {
                val pos = stack.indexOf(name).coerceAtLeast(0)
                val path = (stack.subList(pos, stack.size) + name).joinToString(" -> ")
                issues += ConfigIssue(ConfigIssueLevel.ERROR, "proxyGroups", "策略组嵌套循环不能启用：$path")
                return
            }
            if (state[name] == 2) return
            state[name] = 1
            stack.add(name)
            groupByName[name]?.firstOrNull()?.members?.forEach { m ->
                if (m in groupByName) visit(m)
            }
            stack.removeAt(stack.size - 1)
            state[name] = 2
        }
        groupByName.keys.forEach { if (state[it] != 2) visit(it) }

        selections.forEach { (group, selected) ->
            val g = groupByName[group]?.firstOrNull() ?: return@forEach
            if (g.members.none { it == selected }) {
                issues += ConfigIssue(
                    ConfigIssueLevel.ERROR,
                    "groupSelections.$group",
                    "已选成员 $selected 不在组中（节点更新或配置已变更）",
                )
            }
        }
        return issues
    }

    fun hasErrors(issues: List<ConfigIssue>): Boolean = issues.any { it.level == ConfigIssueLevel.ERROR }

    /** 供编辑页过滤自身与已形成循环的候选组。 */
    fun wouldCreateCycle(groups: List<ProxyGroup>, editing: String, members: Collection<String>): Boolean {
        // 把“正在编辑的组”用候选成员放进图里，否则遍历到它时会被当成不存在而漏掉环。
        val map = groups.filter { it.name != editing }.associateBy { it.name } +
            (editing to ProxyGroup(name = editing, members = members.toList()))
        fun reaches(from: String, target: String, seen: MutableSet<String>): Boolean {
            if (from == target) return true
            if (!seen.add(from)) return false
            val g = map[from] ?: return false
            return g.members.any { it in map && reaches(it, target, seen) }
        }
        return members.any { it in map && reaches(it, editing, mutableSetOf()) }
    }
}
