package com.namu.dns

import com.namu.dns.core.config.ConfigSourceRegistry
import com.namu.dns.core.config.ModuleGeneral
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** IPv6 总开关与 prefer-ipv6 的壳层解析/隧道规格回归。 */
class Ipv6PolicyTest {
    @Test
    fun configSourceParsesIpv6Keys() {
        val r = ConfigSourceRegistry.parse(
            """
            [General]
            ipv6 = false
            prefer-ipv6 = true
            [Rule]
            DOMAIN-SUFFIX,ads.com,REJECT
            """.trimIndent(),
        )
        val g = r.config?.general
        assertTrue(g != null)
        assertEquals(false, g!!.ipv6)
        assertEquals(true, g.preferIpv6)
        assertTrue("ipv6=false 应等效关闭 AAAA", g.blockAaaa)
    }

    @Test
    fun tunnelSpecFollowsIpv6Switch() {
        assertTrue(tunnelSpec(AppConfig()).ipv6)
        assertFalse(tunnelSpec(AppConfig().copy(ipv6 = false)).ipv6)
        assertTrue(tunnelSpec(AppConfig().copy(ipv6 = true)).ipv6)
    }

    @Test
    fun moduleGeneralIpv6Effects() {
        val e = ModuleGeneral.parse(mapOf("ipv6" to "false", "prefer-ipv6" to "1"))
        assertEquals(false, e.ipv6)
        assertEquals(true, e.preferIpv6)
        val unset = ModuleGeneral.parse(emptyMap())
        assertEquals(null, unset.ipv6)
        assertEquals(null, unset.preferIpv6)
    }
}
