package com.namu.dns

import com.namu.dns.ui.ruleValueError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 逻辑规则（AND/OR/NOT）与 SCRIPT 规则的壳层解析/校验回归。 */
class RuleLogicScriptTest {
    @Test
    fun logicExprValidation() {
        assertTrue(ruleLogicExprOk("((DOMAIN,a.com),(PORT,443))"))
        assertTrue(ruleLogicExprOk("((OR,((DOMAIN-SUFFIX,a.com),(DOMAIN-SUFFIX,b.com))),(NOT,((DOMAIN,skip.a.com))))"))
        assertTrue(ruleLogicExprOk("((SCRIPT,adjudge))"))
        assertFalse(ruleLogicExprOk("((DOMAIN,a.com)"))
        assertFalse(ruleLogicExprOk("((NOT,((DOMAIN,a.com),(DOMAIN,b.com))))"))
        assertFalse(ruleLogicExprOk("((UNKNOWN,a.com))"))
        assertFalse(ruleLogicExprOk("((DOMAIN,))"))
    }

    @Test
    fun moduleParsesLogicAndScriptRules() {
        val parsed = ModuleParser.parse(
            """
            [Rule]
            AND,((DOMAIN-SUFFIX,ads.com),(PORT,443)),REJECT
            OR,((DOMAIN-KEYWORD,tracker),(DOMAIN-SUFFIX,analytics.io)),REJECT
            NOT,((DOMAIN-SUFFIX,good.com)),DIRECT
            SCRIPT,adjudge,REJECT
            AND,((DOMAIN,a.com),REJECT
            NOT,((DOMAIN,a.com),(DOMAIN,b.com)),DIRECT
            """.trimIndent(),
        )
        assertEquals(4, parsed.routeRules.size)
        assertEquals("AND", parsed.routeRules[0].type)
        assertEquals("((DOMAIN-SUFFIX,ads.com),(PORT,443))", parsed.routeRules[0].value)
        assertEquals("block", parsed.routeRules[0].action)
        assertEquals("direct", parsed.routeRules[2].action)
        assertEquals("SCRIPT", parsed.routeRules[3].type)
        assertEquals("adjudge", parsed.routeRules[3].value)
    }

    @Test
    fun ruleValueErrorForLogicAndScript() {
        assertNull(ruleValueError("AND", "((DOMAIN,a.com),(PORT,443))"))
        assertTrue(ruleValueError("AND", "((DOMAIN,a.com)") != null)
        assertTrue(ruleValueError("NOT", "((DOMAIN,a.com),(DOMAIN,b.com))") != null)
        assertTrue(ruleValueError("SCRIPT", "bad name") != null)
        assertNull(ruleValueError("SCRIPT", "adjudge"))
    }
}