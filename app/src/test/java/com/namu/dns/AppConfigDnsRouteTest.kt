package com.namu.dns

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
}
