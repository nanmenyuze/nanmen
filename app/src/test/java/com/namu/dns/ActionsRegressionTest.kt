package com.namu.dns

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ActionsRegressionTest {
    private fun group(
        type: String = "load-balance",
        strategy: String? = null,
        switchInterval: Int = 30,
    ): JSONObject = JSONObject().apply {
        put("name", "负载均衡")
        put("type", type)
        put("members", JSONArray().put("a").put("b"))
        if (strategy != null) put("strategy", strategy)
        put("switch_interval", switchInterval)
    }

    @Test
    fun `load balance group keeps strategy and switch interval`() {
        val g = Actions.importedProxyGroup(group(strategy = "consistent-hash", switchInterval = 45))!!
        assertEquals("load-balance", g.type)
        assertEquals("consistent-hash", g.lbMode)
        assertEquals(45, g.switchInterval)
        assertEquals(listOf("a", "b"), g.members)
    }

    @Test
    fun `load balance defaults to round robin like clash`() {
        val g = Actions.importedProxyGroup(group(strategy = null))!!
        assertEquals("round-robin", g.lbMode)
    }

    @Test
    fun `module sync keeps user enabled and interval`() {
        val current = ModuleSource(
            id = "m1",
            name = "旧名",
            url = "https://example.com/m.sgmodule",
            enabled = false,
            intervalSeconds = 60,
        )
        val synced = current.copy(
            name = "新名",
            enabled = true,
            blockRules = 7,
            etag = "\"x\"",
            cacheBytes = 12,
            iconUrl = "https://example.com/icon.png",
        )
        val merged = Actions.mergeModuleSyncState(current, synced)
        assertFalse(merged.enabled)
        assertEquals(60, merged.intervalSeconds)
        assertEquals(current.url, merged.url)
        assertEquals(7, merged.blockRules)
        assertEquals(synced.iconUrl, merged.iconUrl)
        assertEquals("\"x\"", merged.etag)
    }

    @Test
    fun `module icon is read from header without affecting rules`() {
        val url = "https://example.com/icon.png?v=2"
        val text = "#!icon = $url\n[Rule]\nDOMAIN,ads.example.com,REJECT"
        assertEquals(url, ModuleParser.parse(text).iconUrl)
        assertEquals(url, ModuleParser.readIconUrl(("\uFEFF" + text).lineSequence()))
        assertEquals(
            ModuleParser.parse(text.substringAfter('\n')).blockLines,
            ModuleParser.parse(text).blockLines,
        )
        assertEquals("", ModuleParser.parse("[Rule]\n#!icon=$url").iconUrl)
        assertEquals(url, ModuleParser.parse("#!icon=$url").iconUrl)
    }

    @Test
    fun `module icon round trip distinguishes missing and empty values`() {
        val old = ModuleSource.fromJson(JSONObject("""{"id":"m1","name":"模块","url":"local://m1"}"""))
        assertNull(old.iconUrl)
        val icon = old.copy(iconUrl = "https://example.com/icon.png")
        assertEquals(icon, ModuleSource.fromJson(icon.toJson()))
        val noIcon = old.copy(iconUrl = "")
        assertEquals(noIcon, ModuleSource.fromJson(noIcon.toJson()))
    }

    @Test
    fun `module sync result is dropped when url changed during download`() {
        val before = ModuleSource("m1", "A", "https://old.example/m.sgmodule")
        val synced = before.copy(blockRules = 9, enabled = true)
        val after = before.copy(url = "https://new.example/m.sgmodule", enabled = false)
        val merged = Actions.mergeModuleSyncResults(listOf(after), mapOf("m1" to synced))
        assertEquals(after, merged.single())
    }

    @Test
    fun `zero node subscription keeps previous nodes and explains`() {
        val result = Actions.ImportResult(
            nodes = 0,
            rules = 0,
            warnings = emptyList(),
            finalPolicy = null,
            routing = false,
            diagnostics = listOf(Actions.NodeDiagnostic(1, "ss", "parse", "缺少密码", "")),
        )
        val message = Actions.subscriptionRefreshMessage(result)
        assertTrue(message.contains("未解析到可用节点"))
        assertTrue(message.contains("已保留上次节点"))
        assertTrue(message.contains("缺少密码"))
    }

    @Test
    fun `partial subscription reports skipped count`() {
        val result = Actions.ImportResult(
            nodes = 2,
            rules = 0,
            warnings = emptyList(),
            finalPolicy = null,
            routing = false,
            skipped = 3,
        )
        assertEquals("订阅已刷新：可用 2 个，跳过 3 个", Actions.subscriptionRefreshMessage(result))
    }
}
