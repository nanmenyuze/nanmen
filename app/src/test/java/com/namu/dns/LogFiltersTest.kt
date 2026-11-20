package com.namu.dns

import com.namu.dns.ui.filterDnsLogs
import com.namu.dns.ui.filterRuntimeLogs
import org.junit.Assert.assertEquals
import org.junit.Test

class LogFiltersTest {
    private val runtime = listOf(
        LogEntry(1, 0, "E", "dns", "upstream timeout"),
        LogEntry(2, 0, "W", "route", "fallback used"),
        LogEntry(3, 0, "I", "vpn", "connected"),
        LogEntry(4, 0, "ERROR", "dns", "rebind blocked"),
    )

    private val dns = listOf(
        DnsLogEntry(1, 0, "ads.example.com", "A", "拦截", "本地规则", 1, 1),
        DnsLogEntry(2, 0, "api.example.com", "A", "放行", "上游", 2, 1),
        DnsLogEntry(3, 0, "bad.example.com", "AAAA", "失败", "上游无响应", 0, 1),
    )

    @Test
    fun `runtime filters by level and keyword`() {
        assertEquals(listOf(1L, 4L), filterRuntimeLogs(runtime, "E", "").map { it.id })
        assertEquals(listOf(2L), filterRuntimeLogs(runtime, "W", "").map { it.id })
        assertEquals(listOf(1L, 4L), filterRuntimeLogs(runtime, "all", "DNS").map { it.id })
        assertEquals(4, filterRuntimeLogs(runtime, "all", "").size)
    }

    @Test
    fun `runtime level key normalizes words`() {
        assertEquals("E", com.namu.dns.ui.runtimeLevelKey("ERROR"))
        assertEquals("W", com.namu.dns.ui.runtimeLevelKey("warn"))
        assertEquals("I", com.namu.dns.ui.runtimeLevelKey("INFO"))
    }

    @Test
    fun `dns filters by action and domain`() {
        assertEquals(listOf(1L), filterDnsLogs(dns, "拦截", "").map { it.id })
        assertEquals(listOf(2L), filterDnsLogs(dns, "放行", "").map { it.id })
        assertEquals(listOf(1L), filterDnsLogs(dns, "all", "ADS").map { it.id })
        assertEquals(3, filterDnsLogs(dns, "all", "").size)
    }
}
