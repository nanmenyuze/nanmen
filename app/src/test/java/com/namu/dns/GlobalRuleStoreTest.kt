package com.namu.dns

import com.namu.dns.core.config.MitmConfig
import com.namu.dns.core.config.ScriptConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 3.0.18 全局模块存储：显示序/置顶语义/迁移映射/JSON 往返。 */
class GlobalRuleStoreTest {
    private fun module(id: String, order: Int, enabled: Boolean = true) =
        ModuleSource(id = id, name = id, url = "https://example.com/$id.sgmodule", enabled = enabled, order = order)

    @Test
    fun stateJsonRoundTrip() {
        val st = GlobalRuleStore.State(
            modules = listOf(module("m1", 0)),
            ruleSets = listOf(RuleSource(id = "rs1", url = "https://example.com/a.txt", order = 1)),
            localRules = listOf(RuleItem("DOMAIN-SUFFIX", "ads.com", "block")),
            localAds = listOf("ads.example.com"),
            localMitm = GlobalRuleStore.MitmContent(urlRewrites = listOf("^https://a.com/x reject")),
            extraMitm = listOf(
                GlobalRuleStore.ExtraMitm("e1", "重写与脚本", "方案B", false, 5, GlobalRuleStore.MitmContent(headerRewrites = listOf("h"))),
            ),
            scope = GlobalRuleStore.MitmScope(enabled = true, hostnames = listOf("*.a.com")),
            scriptArguments = mapOf("request|p|n" to mapOf("k" to "v")),
        )
        val back = GlobalRuleStore.State.fromJson(st.toJson())
        assertEquals(st.modules, back.modules)
        assertEquals(st.ruleSets, back.ruleSets)
        assertEquals(st.localRules, back.localRules)
        assertEquals(st.localAds, back.localAds)
        assertEquals(st.localMitm, back.localMitm)
        assertEquals(st.extraMitm, back.extraMitm)
        assertEquals(st.scope, back.scope)
        assertEquals(st.scriptArguments, back.scriptArguments)
    }

    @Test
    fun localPseudoHiddenWhenEmptyAndPinnedWhenVisible() {
        val saved = GlobalRuleStore.state
        try {
            GlobalRuleStore.state = GlobalRuleStore.State(modules = listOf(module("m1", 0)))
            assertTrue(GlobalRuleStore.displayEntries().none { it.id == GlobalRuleStore.ID_LOCAL_RULES })
            GlobalRuleStore.state = GlobalRuleStore.State(
                modules = listOf(module("m1", 0)),
                localRules = listOf(RuleItem("DOMAIN", "a.com", "direct")),
            )
            val entries = GlobalRuleStore.displayEntries()
            assertEquals(GlobalRuleStore.ID_LOCAL_RULES, entries.first().id)
            // 置顶只影响显示：合并顺序仍按模块 order。
            assertEquals(listOf("m1"), GlobalRuleStore.orderedModules().map { it.id })
        } finally {
            GlobalRuleStore.state = saved
        }
    }

    @Test
    fun displayOrderAcrossKinds() {
        val saved = GlobalRuleStore.state
        try {
            GlobalRuleStore.state = GlobalRuleStore.State(
                modules = listOf(module("m1", 1)),
                ruleSets = listOf(RuleSource(id = "rs1", url = "https://example.com/a.txt", order = 0)),
            )
            val rest = GlobalRuleStore.displayEntries()
            assertEquals(listOf(GlobalRuleStore.ID_RULESET_PREFIX + "rs1", "m1"), rest.map { it.id })
        } finally {
            GlobalRuleStore.state = saved
        }
    }

    @Test
    fun migrationKeepsActiveAndDisablesForeignWithOrigin() {
        val active = AppConfig(
            rules = listOf(RuleItem("DOMAIN-SUFFIX", "ads.com", "block")),
            customAds = listOf("local.ads"),
            moduleSources = listOf(module("m1", 0)),
            ruleSources = listOf(RuleSource(id = "rs1", url = "https://example.com/a.txt")),
            mitm = MitmConfig(urlRewrites = listOf("^https://a.com/x reject"), enabled = true),
        )
        val other = AppConfig(
            rules = listOf(
                RuleItem("DOMAIN-SUFFIX", "ads.com", "block"),
                RuleItem("DOMAIN", "other.com", "proxy"),
            ),
            moduleSources = listOf(module("m1", 0), module("m2", 1)),
            ruleSources = listOf(RuleSource(id = "rs2", url = "https://example.com/b.txt")),
            mitm = MitmConfig(urlRewrites = listOf("^https://b.com/y reject")),
        )
        val st = GlobalRuleStore.buildMigratedState(active, listOf("方案B" to other))
        assertEquals(listOf("m1", "m2"), st.modules.map { it.id })
        assertTrue(st.modules[0].enabled)
        assertTrue(st.modules[0].dnsApproved)
        assertFalse(st.modules[1].enabled)
        assertEquals("方案B", st.modules[1].origin)
        assertEquals(2, st.localRules.size)
        assertFalse(st.localRules[1].enabled)
        assertEquals("方案 方案B", st.localRules[1].source)
        assertEquals(listOf("rs1", "rs2"), st.ruleSets.map { it.id })
        assertFalse(st.ruleSets[1].enabled)
        assertEquals(1, st.extraMitm.size)
        assertFalse(st.extraMitm[0].enabled)
        assertEquals("方案B", st.extraMitm[0].origin)
        assertTrue(st.scope.enabled)
        // 幂等：同一输入重复映射结果一致。
        assertEquals(st, GlobalRuleStore.buildMigratedState(active, listOf("方案B" to other)))
    }

    @Test
    fun migrationDisablesForeignAdsAsRules() {
        val active = AppConfig(rules = emptyList(), customAds = listOf("local.ads"))
        val other = AppConfig(rules = emptyList(), customAds = listOf("local.ads", "foreign.ads"))
        val st = GlobalRuleStore.buildMigratedState(active, listOf("方案B" to other))
        assertEquals(listOf("local.ads"), st.localAds)
        assertEquals(1, st.localRules.size)
        assertEquals("DOMAIN-SUFFIX", st.localRules[0].type)
        assertEquals("foreign.ads", st.localRules[0].value)
        assertEquals("block", st.localRules[0].action)
        assertFalse(st.localRules[0].enabled)
        assertEquals("方案 方案B", st.localRules[0].source)
    }

    @Test
    fun legacyRulesUrlBecomesRuleSetModule() {
        val active = AppConfig(rulesUrl = "https://example.com/ads.txt")
        val st = GlobalRuleStore.buildMigratedState(active, emptyList())
        assertEquals(1, st.ruleSets.size)
        assertEquals("https://example.com/ads.txt", st.ruleSets[0].url)
        assertTrue(st.ruleSets[0].enabled)
    }

    @Test
    fun mitmContentCountAndEmpty() {
        val c = GlobalRuleStore.MitmContent(
            urlRewrites = listOf("a"),
            scripts = listOf(ScriptConfig(name = "s")),
        )
        assertEquals(2, GlobalRuleStore.mitmCount(c))
        assertTrue(GlobalRuleStore.MitmContent().isEmpty)
        assertFalse(c.isEmpty)
    }
}