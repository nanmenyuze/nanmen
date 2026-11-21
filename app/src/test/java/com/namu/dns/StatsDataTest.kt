package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Test

class StatsDataTest {
    @Test
    fun `parses kernel dns advancement fields`() {
        val data = StatsData.fromJson(
            """
            {
              "activeConns": 7,
              "totalConns": 42,
              "uptime": 123000,
              "dnsStale": 3,
              "dnsNegative": 4,
              "dnsCoalesced": 5,
              "dnsRebind": 6,
              "dnsAaaaBlocked": 8,
              "dnsTcpRetry": 9,
              "dnsLatency": {"lt10": 10, "lt50": 20, "lt100": 30, "lt300": 40, "lt1000": 50, "ge1000": 60}
            }
            """.trimIndent(),
        )
        assertEquals(7L, data.activeConns)
        assertEquals(42L, data.totalConns)
        assertEquals(123000L, data.uptime)
        assertEquals(3L, data.dnsStale)
        assertEquals(4L, data.dnsNegative)
        assertEquals(5L, data.dnsCoalesced)
        assertEquals(6L, data.dnsRebind)
        assertEquals(8L, data.dnsAaaaBlocked)
        assertEquals(9L, data.dnsTcpRetry)
        assertEquals(10L, data.dnsLatLt10)
        assertEquals(20L, data.dnsLatLt50)
        assertEquals(30L, data.dnsLatLt100)
        assertEquals(40L, data.dnsLatLt300)
        assertEquals(50L, data.dnsLatLt1000)
        assertEquals(60L, data.dnsLatGe1000)
    }

    @Test
    fun `parses mitm counters from kernel json`() {
        val data = StatsData.fromJson(
            """
            {
              "mitmConns": 11,
              "mitmRejected": 12,
              "mitmRewritten": 13,
              "mitmFailed": 14,
              "mitmQuicBlocked": 15
            }
            """.trimIndent(),
        )
        assertEquals(11L, data.mitmConns)
        assertEquals(12L, data.mitmRejected)
        assertEquals(13L, data.mitmRewritten)
        assertEquals(14L, data.mitmFailed)
        assertEquals(15L, data.mitmQuicBlocked)
    }

    @Test
    fun `parses tun egress diagnostics from kernel json`() {
        val data = StatsData.fromJson(
            """
            {
              "tunTxDrop": 2,
              "tunPendingDrop": 3,
              "tunPendingPeak": 700,
              "tunTxBackpressure": 6,
              "tunWriteWouldBlock": 4,
              "tunWriteError": 5
            }
            """.trimIndent(),
        )
        assertEquals(2L, data.tunTxDrop)
        assertEquals(3L, data.tunPendingDrop)
        assertEquals(700L, data.tunPendingPeak)
        assertEquals(6L, data.tunTxBackpressure)
        assertEquals(4L, data.tunWriteWouldBlock)
        assertEquals(5L, data.tunWriteError)
    }
}
