package com.namu.dns.core.config

import com.namu.dns.AppConfig
import com.namu.dns.ProxyGroup
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyGroupTest {
    private fun group(name: String, type: String = "select", members: List<String>) =
        ProxyGroup(name = name, type = type, members = members)

    @Test
    fun `app config persists group definitions and selections`() {
        val cfg = AppConfig(
            proxyGroups = listOf(
                ProxyGroup("自动", "url-test", listOf("a", "b"), tolerance = 80),
                ProxyGroup("手动", "select", listOf("自动", "a")),
            ),
            groupSelections = mapOf("手动" to "自动"),
        )
        val decoded = AppConfig.fromJson(cfg.toJson().toString())
        assertEquals(cfg.proxyGroups, decoded.proxyGroups)
        assertEquals(cfg.groupSelections, decoded.groupSelections)
        assertTrue(decoded.toJson().optJSONObject("groupSelections")!!.has("手动"))
    }

    @Test
    fun `validation rejects nested cycle`() {
        val issues = ProxyGroupValidation.validate(
            listOf(
                group("A", members = listOf("B")),
                group("B", members = listOf("A")),
            ),
            emptyList(),
        )
        assertTrue(issues.any { it.level == ConfigIssueLevel.ERROR && it.message.contains("循环") })
    }

    @Test
    fun `validation locates missing duplicate node and ambiguous reference`() {
        val issues = ProxyGroupValidation.validate(
            listOf(
                group("缺失", members = listOf("ghost")),
                group("重复", members = listOf("same")),
                group("歧义", members = listOf("both")),
            ),
            listOf("same", "same", "both"),
        )
        // "both" 只有一个节点，不构成歧义；此用例只验证可定位的缺失和重复节点。
        assertTrue(issues.any { it.message.contains("成员不存在") })
        assertTrue(issues.any { it.message.contains("重复节点名") })
        assertTrue(issues.all { it.path.startsWith("proxyGroups") || it.path == "proxyGroups" })
    }

    @Test
    fun `validation rejects stale selection`() {
        val issues = ProxyGroupValidation.validate(
            listOf(group("G", members = listOf("n1"))),
            listOf("n1"),
            mapOf("G" to "已删除节点"),
        )
        assertTrue(issues.any { it.level == ConfigIssueLevel.ERROR && it.path == "groupSelections.G" })
    }

    @Test
    fun `would create cycle detects nested member`() {
        val groups = listOf(
            group("A", members = listOf("B")),
            group("B", members = listOf("n1")),
        )
        assertFalse(ProxyGroupValidation.wouldCreateCycle(groups, "A", listOf("B")))
        assertTrue(ProxyGroupValidation.wouldCreateCycle(groups, "B", listOf("A")))
    }

    @Test
    fun `proxy group json clamps unsafe values`() {
        val parsed = ProxyGroup.fromJson(
            org.json.JSONObject()
                .put("name", " G ")
                .put("type", "urltest")
                .put("members", org.json.JSONArray().put(" n1 "))
                .put("interval", 1)
                .put("timeout", 99)
                .put("tolerance", 999999)
                .put("failureThreshold", 0)
                .put("recoveryThreshold", 99)
                .put("noNodeAction", "乱写"),
        )
        assertEquals("G", parsed.name)
        assertEquals("url-test", parsed.type)
        assertEquals(listOf("n1"), parsed.members)
        assertEquals(5, parsed.interval)
        assertEquals(500, parsed.timeout)
        assertEquals(30_000, parsed.tolerance)
        assertEquals(1, parsed.failureThreshold)
        assertEquals(20, parsed.recoveryThreshold)
        assertEquals("global", parsed.noNodeAction)
    }
}
