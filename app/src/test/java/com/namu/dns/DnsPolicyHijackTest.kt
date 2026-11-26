package com.namu.dns

import com.namu.dns.core.config.ConfigSourceRegistry
import com.namu.dns.core.config.parseHijackDns
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** [DNS] 按域名策略与 hijack-dns 的壳层解析回归。 */
class DnsPolicyHijackTest {
    @Test
    fun configSourceParsesDnsSectionAndHijack() {
        val r = ConfigSourceRegistry.parse(
            """
            [General]
            hijack-dns = false
            [DNS]
            example.com = 1.1.1.1
            *.ads.example.com = 8.8.8.8,9.9.9.9
            [Rule]
            DOMAIN-SUFFIX,ads.com,REJECT
            """.trimIndent(),
        )
        val g = r.config?.general
        assertTrue(g != null)
        assertEquals(2, g!!.dnsPolicies.size)
        assertEquals("example.com", g.dnsPolicies[0].pattern)
        assertEquals("8.8.8.8,9.9.9.9", g.dnsPolicies[1].servers)
        assertEquals(false, g.dnsHijack)
    }

    @Test
    fun configSourceHijackDefaultUnset() {
        val r = ConfigSourceRegistry.parse(
            """
            [General]
            dns-server = 223.5.5.5
            [Rule]
            DOMAIN-SUFFIX,ads.com,REJECT
            """.trimIndent(),
        )
        assertNull(r.config?.general?.dnsHijack)
    }

    @Test
    fun moduleParsesDnsPolicies() {
        val parsed = ModuleParser.parse(
            """
            [DNS]
            example.com = 1.1.1.1
            *.ads.example.com = server:9.9.9.9
            badline
            """.trimIndent(),
        )
        assertEquals(2, parsed.dnsPolicies.size)
        assertEquals("*.ads.example.com", parsed.dnsPolicies[1].pattern)
    }

    @Test
    fun hijackValueSemantics() {
        assertFalse(parseHijackDns("false"))
        assertFalse(parseHijackDns("OFF"))
        assertFalse(parseHijackDns("0"))
        assertTrue(parseHijackDns("true"))
        assertTrue(parseHijackDns("*:53"))
        assertTrue(parseHijackDns("any:53"))
        assertTrue(parseHijackDns("8.8.8.8:53,1.1.1.1:53"))
    }
}