package com.namu.dns

import com.namu.dns.ui.sortNodes
import org.junit.Assert.assertEquals
import org.junit.Test

/** B2 节点排序（TDD：先于实现编写）。 */
class NodeSortTest {
    private fun node(name: String, latency: Long? = null, group: String = "") =
        NodeInfo(name = name, type = "ss", server = "s.example.com", port = 443, latency = latency, group = group)

    @Test
    fun `default mode keeps original order`() {
        val list = listOf(node("b"), node("a"), node("c"))
        assertEquals(list, sortNodes(list, "default"))
    }

    @Test
    fun `latency mode sorts tested ascending and untested last`() {
        val list = listOf(node("slow", 300), node("none"), node("fast", 100), node("mid", 200))
        assertEquals(listOf("fast", "mid", "slow", "none"), sortNodes(list, "latency").map { it.name })
    }

    @Test
    fun `name mode is case insensitive alphabetical`() {
        val list = listOf(node("Beta"), node("alpha"), node("Gamma"))
        assertEquals(listOf("alpha", "Beta", "Gamma"), sortNodes(list, "name").map { it.name })
    }

    @Test
    fun `group mode groups then names`() {
        val list = listOf(node("b", group = "z"), node("a", group = "a"), node("c", group = "a"))
        assertEquals(listOf("a", "c", "b"), sortNodes(list, "group").map { it.name })
    }

    @Test
    fun `unknown mode falls back to original order`() {
        val list = listOf(node("b"), node("a"))
        assertEquals(list, sortNodes(list, "whatever"))
    }
}

/** B3 规则单条启用开关：模型兼容性（TDD：先于实现编写）。 */
class RuleEnabledTest {
    @Test
    fun `rule enabled defaults to true`() {
        assertEquals(true, RuleItem("DOMAIN", "a.com", "direct").enabled)
    }

    @Test
    fun `disabled rule survives org json round trip`() {
        val r = RuleItem("DOMAIN", "a.com", "direct", enabled = false)
        val decoded = RuleItem.fromJson(r.toJson())
        assertEquals(false, decoded.enabled)
        assertEquals(r.type, decoded.type)
        assertEquals(r.value, decoded.value)
    }

    @Test
    fun `legacy json without enabled key defaults to true`() {
        val legacy = org.json.JSONObject("""{"type":"DOMAIN","value":"a.com","action":"direct"}""")
        assertEquals(true, RuleItem.fromJson(legacy).enabled)
    }

    @Test
    fun `enabled rule json stays compact`() {
        // 启用态不写 enabled 键，旧壳/内核看到的 JSON 与之前完全一致
        val json = RuleItem("DOMAIN", "a.com", "direct").toJson()
        assertEquals(false, json.has("enabled"))
    }
}
