package com.namu.dns

import com.namu.dns.core.config.ConfigSourceRegistry
import com.namu.dns.core.config.ModuleGeneral
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** always-real-ip / fake-ip-filter 的壳层解析与模块效果回归。 */
class AlwaysRealIpTest {
    @Test
    fun configSourceParsesAlwaysRealIp() {
        val r = ConfigSourceRegistry.parse(
            """
            [General]
            always-real-ip = *.lan, example.com, *.msftncsi.com
            [Rule]
            DOMAIN-SUFFIX,ads.com,REJECT
            """.trimIndent(),
        )
        val g = r.config?.general
        assertTrue(g != null)
        assertEquals(listOf("*.lan", "example.com", "*.msftncsi.com"), g!!.alwaysRealIp)
    }

    @Test
    fun configSourceAcceptsFakeIpFilterAlias() {
        val r = ConfigSourceRegistry.parse(
            """
            [General]
            fake-ip-filter = +.example.org
            [Rule]
            DOMAIN-SUFFIX,ads.com,REJECT
            """.trimIndent(),
        )
        assertEquals(listOf("+.example.org"), r.config?.general?.alwaysRealIp)
    }

    @Test
    fun moduleGeneralSplitsAlwaysRealIp() {
        val e = ModuleGeneral.parse(mapOf("always-real-ip" to "*.lan, *.local"))
        assertEquals(listOf("*.lan", "*.local"), e.alwaysRealIp)
        assertTrue(ModuleGeneral.parse(emptyMap()).alwaysRealIp.isEmpty())
    }

    @Test
    fun appConfigJsonRoundTrip() {
        val cfg = AppConfig().copy(alwaysRealIp = listOf("example.com", "*.lan"))
        val back = AppConfig.fromJson(cfg.toJson().toString())
        assertEquals(cfg.alwaysRealIp, back.alwaysRealIp)
    }
}
