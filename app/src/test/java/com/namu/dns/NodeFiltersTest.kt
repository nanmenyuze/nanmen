package com.namu.dns

import com.namu.dns.ui.filterNodes
import org.junit.Assert.assertEquals
import org.junit.Test

class NodeFiltersTest {
    private val nodes = listOf(
        NodeInfo("香港 01", "ss", "hk.example.com", 443, group = "香港"),
        NodeInfo("日本 02", "vless", "jp.example.com", 8443, group = "日本"),
        NodeInfo("备用", "trojan", "backup.example.net", 443, group = "香港"),
    )

    @Test
    fun `empty query returns all nodes`() {
        assertEquals(nodes, filterNodes(nodes, ""))
    }

    @Test
    fun `filters by name server and group ignoring case`() {
        assertEquals(listOf("香港 01", "日本 02"), filterNodes(nodes, "EXAMPLE.COM").map { it.name })
        assertEquals(listOf("香港 01", "备用"), filterNodes(nodes, "香港").map { it.name })
        assertEquals(listOf("日本 02"), filterNodes(nodes, "Vless").map { it.name })
    }
}
