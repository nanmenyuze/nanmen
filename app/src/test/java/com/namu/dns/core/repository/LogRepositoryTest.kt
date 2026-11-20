package com.namu.dns.core.repository

import com.namu.dns.DnsLogEntry
import com.namu.dns.LogEntry
import com.namu.dns.core.runtime.DefaultRuntimeRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LogRepositoryTest {
    private class FakeSource(
        var runtimeBatch: List<LogEntry> = emptyList(),
        var dnsBatch: List<DnsLogEntry> = emptyList(),
    ) : LogSource {
        var clearedRuntime = false
        var clearedDns = false
        override fun logs(sinceId: Long): List<LogEntry> = runtimeBatch
        override fun dnsLogs(sinceId: Long): List<DnsLogEntry> = dnsBatch
        override fun clearLogs() { clearedRuntime = true }
        override fun clearDnsLogs() { clearedDns = true }
    }

    @Test
    fun `poll appends only ids after sinceId and caps history`() {
        val runtime = DefaultRuntimeRepository()
        runtime.markConnected(0)
        val source = FakeSource(
            runtimeBatch = listOf(
                LogEntry(1, 1, "I", "old", "old"),
                LogEntry(2, 1, "I", "new", "new"),
            ),
            dnsBatch = listOf(DnsLogEntry(1, 1, "a.com", "A", "block", "", 1)),
        )
        val repo = DefaultLogRepository(runtime, source, pollIntervalMs = 3_600_000L, maxEntries = 2, autoPoll = false)
        repo.poll()
        // 首次 sinceId=0：先把 native 环形缓冲里已有的日志全部接进来。
        assertEquals(listOf(1L, 2L), repo.current().runtime.map { it.id })
        assertEquals(1, repo.current().dns.size)

        source.runtimeBatch = listOf(LogEntry(3, 2, "I", "third", "third"))
        repo.poll()
        assertEquals(listOf(2L, 3L), repo.current().runtime.map { it.id })
    }

    @Test
    fun `clear resets cursor and calls native clear`() {
        val runtime = DefaultRuntimeRepository()
        runtime.markConnected(0)
        val source = FakeSource(runtimeBatch = listOf(LogEntry(7, 1, "I", "t", "m")))
        val repo = DefaultLogRepository(runtime, source, pollIntervalMs = 3_600_000L, autoPoll = false)
        repo.poll()
        assertEquals(7L, repo.current().runtime.single().id)

        repo.clearRuntime()
        assertTrue(repo.current().runtime.isEmpty())
        assertTrue(source.clearedRuntime)

        // 游标归零后，同样的 id 会再次被接收（native 已清空，正常不会重复）。
        source.runtimeBatch = listOf(LogEntry(8, 2, "I", "t", "m"))
        repo.poll()
        assertEquals(8L, repo.current().runtime.single().id)
    }
}
