package com.namu.dns

import com.namu.dns.core.config.ConfigDnsInput
import com.namu.dns.core.config.ConfigFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * DNS-only 接管范围是唯一同时影响「防 DNS 泄漏」和「吞吐/功耗」的开关，
 * 默认值必须锁死为开启，旧配置缺字段时也要回落到开启。
 */
class AppConfigDnsRouteTest {

    @Test
    fun `full route defaults to on`() {
        assertTrue(AppConfig().dnsOnlyFullRoute)
    }

    @Test
    fun `missing field in old json falls back to on`() {
        // 老版本导出的配置没有这个字段：不能被解析成 false，否则升级后 DNS 又泄漏。
        val cfg = AppConfig.fromJson("""{"mode":"dns_only","dnsUpstream":"system"}""")
        assertTrue(cfg.dnsOnlyFullRoute)
    }

    @Test
    fun `explicit off is preserved`() {
        val cfg = AppConfig.fromJson("""{"mode":"dns_only","dnsOnlyFullRoute":false}""")
        assertFalse(cfg.dnsOnlyFullRoute)
    }

    @Test
    fun `roundtrips through toJson`() {
        val cfg = AppConfig().copy(dnsOnlyFullRoute = false)
        val back = AppConfig.fromJson(cfg.toJson().toString())
        assertFalse(back.dnsOnlyFullRoute)
    }

    @Test
    fun `fresh defaults disable special DNS review and domestic direct routing`() {
        val cfg = AppConfig.freshDefaults()
        assertFalse(cfg.fallbackFilter)
        assertFalse(cfg.fallbackGeoCheck)
        assertFalse(cfg.cnDirect)
        assertTrue(cfg.allowDnsFallback)
        assertEquals(null, cfg.dnsHijack)
        assertEquals("proxy", cfg.finalPolicy)
        assertTrue(cfg.dnsOnlyFullRoute)

        val restored = ConfigFile.fromJson(ConfigFile.fromAppConfig(cfg).toJson()).toAppConfig()
        assertFalse(restored.fallbackFilter)
        assertFalse(restored.cnDirect)
    }

    @Test
    fun `old profiles keep their implicit options and explicit values`() {
        val old = AppConfig.fromJson("""{"mode":"dns_only"}""")
        assertTrue(old.fallbackFilter)
        assertTrue(old.cnDirect)
        val explicit = AppConfig.fromJson("""{"fallbackFilter":true,"cnDirect":true,"dnsHijack":false}""")
        assertTrue(explicit.fallbackFilter)
        assertTrue(explicit.cnDirect)
        assertEquals(false, explicit.dnsHijack)
    }

    @Test
    fun `rule flags and skip proxy survive json roundtrip`() {
        val original = AppConfig(
            rules = listOf(RuleItem("DOMAIN-SUFFIX", "example.com", "block", extendedMatch = true, preMatch = true)),
            skipProxyHosts = listOf("direct.example"),
        )
        val restored = AppConfig.fromJson(original.toJson().toString())
        assertTrue(restored.rules.single().extendedMatch)
        assertTrue(restored.rules.single().preMatch)
        assertEquals(listOf("direct.example"), restored.skipProxyHosts)
    }

    @Test
    fun `multiple dns addresses are validated individually`() {
        assertEquals(null, ConfigDnsInput.error("223.5.5.5,https://dns.example/dns-query"))
        assertTrue(ConfigDnsInput.error("223.5.5.5,not a host") != null)
        assertTrue(ConfigDnsInput.error("system,223.5.5.5") != null)
    }
}
