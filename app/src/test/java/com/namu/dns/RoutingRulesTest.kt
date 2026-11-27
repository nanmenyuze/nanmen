package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutingRulesTest {

    @Test
    fun `imported profile rules merge with local rules and dedupe`() {
        val cfg = AppConfig(
            mode = "rule",
            rules = listOf(
                RuleItem("DOMAIN-SUFFIX", "a.example", "block", source = "订阅"),
                RuleItem("DOMAIN-SUFFIX", "b.example", "proxy", source = "订阅"),
                RuleItem("FINAL", "", "direct", source = "订阅"),
            ),
        )
        val global = GlobalRuleStore.State(
            localRules = listOf(RuleItem("DOMAIN-SUFFIX", "a.example", "block", source = "本地规则")),
        )
        val merged = ConfigStore.routingRules(cfg, global) { it }
        assertEquals(2, merged.size)
        assertEquals("本地规则", merged[0].source)
        assertEquals("订阅", merged[1].source)
        assertTrue(merged.none { it.type == "FINAL" })
    }

    @Test
    fun `profile rules only participate in rule mode`() {
        val cfg = AppConfig(
            mode = "filter_only",
            rules = listOf(RuleItem("DOMAIN-SUFFIX", "a.example", "block", source = "订阅")),
        )
        val out = ConfigStore.routingRules(cfg, GlobalRuleStore.State()) { it }
        assertTrue(out.isEmpty())
    }

    @Test
    fun `subscription group names colliding with builtin actions get aliases`() {
        val groups = listOf(
            ProxyGroup(name = "proxy", type = "select", members = listOf("n")),
            ProxyGroup(name = "正常组", type = "select", members = listOf("n")),
        )
        val aliases = Actions.subscriptionGroupAliases(groups)
        assertEquals("proxy（策略组）", aliases["proxy"])
        assertTrue(aliases["正常组"] == null)
        assertEquals("node:新名", Actions.subscriptionRuleTarget("node:旧名", emptyMap(), mapOf("旧名" to "新名")))
        assertEquals("proxy（策略组）", Actions.subscriptionRuleTarget("proxy", aliases, emptyMap()))
    }
}
