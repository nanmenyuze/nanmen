package com.namu.dns.core.config

import com.namu.dns.AppConfig

/** S1：组只在所属 Profile 内解析；跨 Profile 同名组不做全局消歧。 */
data class ProfileIssue(
    val level: String = "error",
    val code: String = "",
    val message: String = "",
    val group: String = "",
)

data class ProfileValidation(
    val profile: String = "",
    val issues: List<ProfileIssue> = emptyList(),
    val groupMap: Map<String, String> = emptyMap(),
) {
    val ok: Boolean get() = issues.none { it.level == "error" }
    val errors: List<ProfileIssue> get() = issues.filter { it.level == "error" }
    val warnings: List<ProfileIssue> get() = issues.filter { it.level != "error" }
}

object GroupValidator {
    /**
     * 校验 Profile 内的组引用：
     * - 组名唯一；
     * - 成员必须是本 Profile 的节点、组，或内置策略；
     * - 组引用不能成环；
     * - groupSelections 只能指向本 Profile 的组。
     *
     * 不把同名组跨 Profile 合并，调用方传入的 AppConfig 已经是单份 .conf 的视图。
     */
    fun validate(profile: String, cfg: AppConfig): ProfileValidation {
        val issues = mutableListOf<ProfileIssue>()
        val groups = cfg.proxyGroups
        val byName = LinkedHashMap<String, Int>()
        groups.forEachIndexed { index, g ->
            val name = g.name.trim()
            if (name.isBlank()) {
                issues += ProfileIssue(code = "empty_group_name", message = "第 ${index + 1} 个组没有名字", group = name)
            } else if (byName.put(name, index) != null) {
                issues += ProfileIssue(code = "duplicate_group", message = "组名重复：$name", group = name)
            }
            if (g.members.isEmpty()) {
                issues += ProfileIssue(level = "warning", code = "empty_group", message = "组 $name 没有成员", group = name)
            }
        }
        val nodeNames = cfg.nodes.map { it.name.trim() }.filter { it.isNotBlank() }.toSet()
        val groupNames = byName.keys
        val memberEdges = LinkedHashMap<String, MutableList<String>>()
        groups.forEach { g ->
            val name = g.name.trim()
            val edges = mutableListOf<String>()
            g.members.forEach { raw ->
                val m = raw.trim()
                if (m.isBlank()) return@forEach
                when {
                    m.equals("DIRECT", true) || m.equals("REJECT", true) || m.equals("REJECT-DROP", true) -> Unit
                    nodeNames.contains(m) -> Unit
                    groupNames.contains(m) -> {
                        if (m == name) {
                            issues += ProfileIssue(code = "self_group_ref", message = "组 $name 不能引用自身", group = name)
                        } else {
                            edges += m
                        }
                    }
                    else -> issues += ProfileIssue(
                        code = "missing_group_member",
                        message = "组 $name 的成员 $m 不在本 Profile 的节点/组中",
                        group = name,
                    )
                }
            }
            memberEdges[name] = edges
        }
        // 三色 DFS：发现组之间的环，避免运行时无限解析。
        val visiting = mutableSetOf<String>()
        val visited = mutableSetOf<String>()
        fun dfs(name: String): Boolean {
            if (visited.contains(name)) return false
            if (!visiting.add(name)) return true
            memberEdges[name]?.forEach { next -> if (dfs(next)) return true }
            visiting.remove(name)
            visited.add(name)
            return false
        }
        groupNames.forEach { name ->
            if (dfs(name)) {
                issues += ProfileIssue(code = "group_cycle", message = "组引用成环：$name", group = name)
            }
        }
        cfg.groupSelections.forEach { (group, selected) ->
            if (!groupNames.contains(group)) {
                issues += ProfileIssue(
                    level = "warning",
                    code = "stale_group_selection",
                    message = "组选择指向不存在的组：$group",
                    group = group,
                )
            }
            if (selected.isNotBlank() && !nodeNames.contains(selected) && !groupNames.contains(selected) &&
                !selected.equals("DIRECT", true) && !selected.equals("REJECT", true)
            ) {
                issues += ProfileIssue(
                    level = "warning",
                    code = "missing_group_selection",
                    message = "组 $group 当前选择 $selected 不在本 Profile 中",
                    group = group,
                )
            }
        }
        return ProfileValidation(
            profile = profile,
            issues = issues,
            // 旧→新映射表：新模型的组 id 仍是「Profile 名 + 组名」，迁移和回滚都按这张表。
            groupMap = groups.associate { g ->
                g.name to "$profile\u0000${g.name}"
            },
        )
    }
}
