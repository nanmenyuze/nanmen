package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 规则集（RULE-SET / DOMAIN-SET）与 PROTOCOL 规则类型回归。
 * 规则集由壳层拉取缓存后展开为普通规则，集合策略覆盖行内策略；
 * PROTOCOL(TCP/UDP) 由内核按连接类型匹配。
 */
class RuleSetCompatTest {
    @Test
    fun moduleParserCollectsRuleSetRefs() {
        val text = """
            #!name=规则集测试
            [Rule]
            RULE-SET,https://example.com/list.txt,PROXY
            DOMAIN-SET,https://example.com/domains.txt,REJECT
            DOMAIN-SUFFIX,ads.example.com,REJECT
        """.trimIndent()
        val p = ModuleParser.parse(text)
        assertEquals(2, p.ruleSets.size)
        assertEquals("RULE-SET", p.ruleSets[0].kind)
        assertEquals("https://example.com/list.txt", p.ruleSets[0].url)
        assertEquals("proxy", p.ruleSets[0].action)
        assertEquals("DOMAIN-SET", p.ruleSets[1].kind)
        assertEquals("block", p.ruleSets[1].action)
        assertFalse(p.ignoredReasons.containsKey("unsupported_rule_type"))
        assertEquals(1, p.routeRules.size)
    }

    @Test
    fun ruleSetInvalidPolicyOrUrlIsDiagnosed() {
        val p = ModuleParser.parse(
            "[Rule]\nRULE-SET,https://example.com/l.txt,SomeGroup\nDOMAIN-SET,ftp://x/y,REJECT"
        )
        assertEquals(0, p.ruleSets.size)
        assertTrue(p.lostRouteTargets.contains("SomeGroup"))
        assertTrue(p.ignoredReasons.containsKey("invalid_rule"))
    }

    @Test
    fun protocolRuleAcceptedAndValidated() {
        val p = ModuleParser.parse(
            "[Rule]\nPROTOCOL,UDP,REJECT\nPROTOCOL,TCP,DIRECT\nPROTOCOL,ICMP,DIRECT"
        )
        assertEquals(2, p.routeRules.size)
        assertEquals("PROTOCOL", p.routeRules[0].type)
        assertEquals("block", p.routeRules[0].action)
        assertEquals(1, p.ignoredReasons["invalid_rule"])
    }

    @Test
    fun ruleSetExpanderAppliesSetPolicyAndSkipsUnsupported() {
        val content = "# comment\nDOMAIN-SUFFIX,ads.example.com\nDOMAIN,exact.example.com,DIRECT\nIP-CIDR,10.0.0.0/8\nUSER-AGENT,Mozilla*\n\n"
        val rules = RuleSetExpander.expand("RULE-SET", content, "proxy", "测试模块")
        assertEquals(3, rules.size)
        assertTrue(rules.all { it.action == "proxy" })
        assertTrue(rules.all { it.source == "测试模块" })
        assertEquals("DOMAIN-SUFFIX", rules[0].type)
        assertEquals("IP-CIDR", rules[2].type)
    }

    @Test
    fun domainSetExpanderForms() {
        val content = ".example.com\nexact.example.com\n*.wild.example.com\n# c\n"
        val rules = RuleSetExpander.expand("DOMAIN-SET", content, "block", "s")
        assertEquals(3, rules.size)
        assertEquals("DOMAIN-SUFFIX", rules[0].type)
        assertEquals("example.com", rules[0].value)
        assertEquals("DOMAIN", rules[1].type)
        assertEquals("exact.example.com", rules[1].value)
        assertEquals("DOMAIN-WILDCARD", rules[2].type)
        assertEquals("*.wild.example.com", rules[2].value)
        assertTrue(rules.all { it.action == "block" })
    }
}
