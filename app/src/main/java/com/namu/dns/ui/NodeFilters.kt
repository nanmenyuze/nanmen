package com.namu.dns.ui

import com.namu.dns.NodeInfo

/** B2 节点排序：default 原序 / latency 已测升序未测殿后 / name 字母 / group 分组后字母。 */
internal fun sortNodes(nodes: List<NodeInfo>, mode: String): List<NodeInfo> = when (mode) {
    "latency" -> nodes.sortedBy { it.latency ?: Long.MAX_VALUE }
    "name" -> nodes.sortedBy { it.name.lowercase() }
    "group" -> nodes.sortedWith(
        compareBy({ it.group.ifBlank { "未分组" } }, { it.name.lowercase() }),
    )
    else -> nodes
}

internal fun filterNodes(nodes: List<NodeInfo>, query: String): List<NodeInfo> {
    val q = query.trim()
    if (q.isEmpty()) return nodes
    return nodes.filter {
        it.name.contains(q, ignoreCase = true) ||
            it.server.contains(q, ignoreCase = true) ||
            it.group.contains(q, ignoreCase = true) ||
            it.type.contains(q, ignoreCase = true)
    }
}
