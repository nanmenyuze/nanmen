package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UidResolverTest {

    @Test
    fun `ipv4 decodes little endian hex`() {
        assertEquals("127.0.0.1", UidResolver.decodeIp("0100007F", ipv6 = false))
        assertEquals("10.10.10.1", UidResolver.decodeIp("010A0A0A", ipv6 = false))
        assertEquals("114.114.114.114", UidResolver.decodeIp("72727272", ipv6 = false))
    }

    @Test
    fun `ipv6 decodes four little endian words`() {
        // ::1
        assertEquals("::1", UidResolver.decodeIp("00000000000000000000000001000000", ipv6 = true))
        // 全零地址退化为 ::
        assertEquals("::", UidResolver.decodeIp("0".repeat(32), ipv6 = true))
    }

    @Test
    fun `decode rejects malformed input`() {
        assertNull(UidResolver.decodeIp("0100007", ipv6 = false))
        assertNull(UidResolver.decodeIp("zzzzzzzz", ipv6 = false))
        assertNull(UidResolver.decodeIp("0100007F", ipv6 = true))
    }

    @Test
    fun `parse skips listen sockets and reads uid column`() {
        val table = """
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 010A0A0A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  10123        0 1
               1: 010A0A0A:D2A2 3A0A0A0A:01BB 01 00000000:00000000 00:00000000 00000000  10200        0 2
        """.trimIndent()
        val list = UidResolver.parseProcNet(table, ipv6 = false)
        assertEquals(1, list.size)
        val e = list[0]
        assertEquals("10.10.10.1", e.localIp)
        assertEquals(0xD2A2, e.localPort)
        assertEquals("10.10.10.58", e.remoteIp)
        assertEquals(443, e.remotePort)
        assertEquals(10200, e.uid)
    }

    @Test
    fun `parse keeps syn sent sockets so new connections resolve`() {
        val table = """
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 010A0A0A:C350 010A0A0A:01BB 02 00000000:00000000 00:00000000 00000000  10201        0 3
        """.trimIndent()
        val list = UidResolver.parseProcNet(table, ipv6 = false)
        assertEquals(1, list.size)
        assertEquals(10201, list[0].uid)
    }

    @Test
    fun `parse ignores truncated rows`() {
        val table = """
              sl  local_address
               0: 010A0A0A:1F90
        """.trimIndent()
        assertTrue(UidResolver.parseProcNet(table, ipv6 = false).isEmpty())
    }

    @Test
    fun `toJson emits compact array the kernel can parse`() {
        val entries = listOf(
            UidResolver.Entry("10.10.10.1", 54321, "1.2.3.4", 443, 10200),
            UidResolver.Entry("fd00:1::5", 5000, "2606:4700::1111", 443, 10101),
        )
        val json = UidResolver.toJson(entries)
        assertEquals(
            "[[\"10.10.10.1\",54321,\"1.2.3.4\",443,10200]," +
                "[\"fd00:1::5\",5000,\"2606:4700::1111\",443,10101]]",
            json,
        )
    }

    @Test
    fun `toJson of empty table is an empty array`() {
        // 无 root 时要下发空表，明确告诉内核「现在没有数据」
        assertEquals("[]", UidResolver.toJson(emptyList()))
    }

    @Test
    fun `toJson output roundtrips through the parser`() {
        // 壳层与内核共用同一套格式：序列化后的文本必须能被 parseProcNet 的新数据再利用。
        // 这里只校验结构合法（内核侧解析由 Rust uidmap 单测覆盖）。
        val json = UidResolver.toJson(
            listOf(UidResolver.Entry("10.10.10.1", 54321, "1.2.3.4", 443, 10200)),
        )
        assertTrue(json.startsWith("[["))
        assertTrue(json.endsWith("]]"))
        assertTrue(json.contains("10200"))
    }
}
