package com.namu.dns

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsDefaultsMigrationTest {
    private fun legacy() = AppConfig(
        dnsUpstream = "https://dns.alidns.com/dns-query",
        dnsFallback = "223.5.5.5",
        dnsBootstrap = "",
        dnsHeaderName = "",
        dnsHeaderValue = "",
        remoteConfigUrl = "",
        remoteConfigName = "",
    )

    @Test
    fun `default config follows system dns`() {
        assertTrue(SystemDns.isFollow(AppConfig().dnsUpstream))
        assertTrue(SystemDns.isFollow(AppConfig().dnsFallback))
    }

    @Test
    fun `legacy built-in defaults are detected`() {
        assertTrue(DnsDefaultsMigration.isLegacyDefault(legacy()))
    }

    @Test
    fun `custom doh is not overwritten`() {
        assertFalse(
            DnsDefaultsMigration.isLegacyDefault(
                legacy().copy(dnsHeaderName = "Authorization", dnsHeaderValue = "Bearer x"),
            ),
        )
    }

    @Test
    fun `remote config is not overwritten`() {
        assertFalse(
            DnsDefaultsMigration.isLegacyDefault(
                legacy().copy(remoteConfigName = "remote", remoteConfigUrl = "https://example.com/c.json"),
            ),
        )
    }
}
