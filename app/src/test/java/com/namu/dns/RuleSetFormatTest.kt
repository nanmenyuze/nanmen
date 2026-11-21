package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 规则集载体兼容与 RULE 行 CSV 拆分回归：
 * - DOMAIN-REGEX 的 `{m,n}` 量词含逗号，不能被当成动作分隔；
 * - `IP-CIDR,x,POLICY,no-resolve` 这类尾随参数不能顶掉动作；
 * - Clash `payload:` YAML、sing-box source JSON 都要能展开；
 * - 二进制 .srs 必须给出明确原因，不能静默产出空列表。
 */
class RuleSetFormatTest {
    @Test
    fun domainRegexQuantifierWithCommaKeepsWholeValue() {
        val p = ModuleParser.parse("[Rule]\nDOMAIN-REGEX,^ads{1,3}\\.x\\.com$,REJECT")
        assertEquals(0, p.ignored)
        assertEquals(1, p.routeRules.size)
        assertEquals("DOMAIN-REGEX", p.routeRules[0].type)
        assertEquals("^ads{1,3}\\.x\\.com$", p.routeRules[0].value)
        assertEquals("block", p.routeRules[0].action)
    }

    @Test
    fun trailingOptionDoesNotStealPolicy() {
        val p = ModuleParser.parse("[Rule]\nIP-CIDR,10.1.0.0/16,DIRECT,no-resolve")
        assertEquals(1, p.routeRules.size)
        assertEquals("10.1.0.0/16", p.routeRules[0].value)
        assertEquals("direct", p.routeRules[0].action)
    }

    @Test
    fun clashPayloadExpandsCompletely() {
        val content = """
            payload:
              - 'DOMAIN-SUFFIX,douyin.com'
              - '+.bytedance.com'
              - '*.wild.example.com'
              - 'DOMAIN-REGEX,^ads{1,3}\.x\.com$'
              - 'IP-CIDR,10.0.0.0/8,no-resolve'
              - 'USER-AGENT,WeChat*'
        """.trimIndent()
        val r = RuleSetExpander.expandDetailed("RULE-SET", content, "block", "s")
        assertEquals("clash-yaml", r.format)
        assertEquals(5, r.items.size)
        assertEquals(1, r.skipped)
        assertNotNull(r.note)
        assertEquals("DOMAIN-SUFFIX", r.items[0].type)
        assertEquals("bytedance.com", r.items[1].value)
        assertEquals("DOMAIN-WILDCARD", r.items[2].type)
        assertEquals("^ads{1,3}\\.x\\.com$", r.items[3].value)
        assertEquals("IP-CIDR", r.items[4].type)
        assertTrue(r.items.all { it.action == "block" })
    }

    @Test
    fun singBoxSourceJsonExpandsDomainConditions() {
        val json = """
            {"version":1,"rules":[
              {"domain":["exact.example.com"],"domain_suffix":["ads.example.com"]},
              {"ip_cidr":["10.0.0.0/8"],"domain":["should-not-expand.example.com"]}
            ]}
        """.trimIndent()
        val r = RuleSetExpander.expandDetailed("RULE-SET", json, "proxy", "s")
        assertEquals("sing-box-json", r.format)
        assertEquals(2, r.items.size)
        assertEquals(1, r.skipped)
        assertTrue(r.note!!.contains("ip_cidr"))
        assertEquals("DOMAIN", r.items[0].type)
        assertEquals("DOMAIN-SUFFIX", r.items[1].type)
    }

    @Test
    fun binarySrsReportsExplicitReason() {
        val r = RuleSetExpander.expandDetailed("RULE-SET", "SRS\u0000\u0001\u0002binary", "block", "s")
        assertEquals("binary", r.format)
        assertEquals(0, r.items.size)
        assertNotNull(r.note)
    }

    @Test
    fun emptyContentIsReported() {
        val r = RuleSetExpander.expandDetailed("RULE-SET", "   \n", "block", "s")
        assertEquals("empty", r.format)
        assertNotNull(r.note)
    }
}
