package com.namu.dns.core.repository

import com.namu.dns.StatsData
import com.namu.dns.core.runtime.DefaultRuntimeRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StatsRepositoryTest {
    private class FakeSource(var next: StatsData = StatsData()) : StatsSource {
        override fun read(): StatsData = next
    }

    @Test
    fun `rates use frame delta and survive disconnect`() {
        val runtime = DefaultRuntimeRepository()
        val source = FakeSource(StatsData(up = 100, down = 200))
        var clock = 1_000L
        val repo = DefaultStatsRepository(runtime, source, now = { clock }, pollIntervalMs = 3_600_000L, autoPoll = false)

        runtime.markConnected(900)
        repo.poll()
        assertTrue(repo.current().sessionActive)
        assertEquals(0L, repo.current().upRate)

        clock += 1_000L
        source.next = StatsData(up = 300, down = 600)
        repo.poll()
        assertEquals(200L, repo.current().upRate)
        assertEquals(400L, repo.current().downRate)
        assertEquals(300L, repo.current().stats.up)
        assertEquals(1, repo.current().speedSamples.size)
        assertEquals(200L, repo.current().speedSamples.single().up)
        assertEquals(400L, repo.current().speedSamples.single().down)

        runtime.markStopping()
        repo.poll()
        assertFalse(repo.current().sessionActive)
        assertEquals(0L, repo.current().upRate)
        // 停止后保留最后一次会话统计，供“本次会话”展示。
        assertEquals(300L, repo.current().stats.up)
        assertEquals(600L, repo.current().stats.down)
    }

    @Test
    fun `resetSession drops counters and rebuilds baseline`() {
        val runtime = DefaultRuntimeRepository()
        runtime.markConnected(0)
        val source = FakeSource(StatsData(up = 10, down = 10))
        var clock = 0L
        val repo = DefaultStatsRepository(runtime, source, now = { clock }, pollIntervalMs = 3_600_000L, autoPoll = false)
        repo.poll()
        repo.resetSession()
        assertEquals(StatsData(), repo.current().stats)
        assertEquals(0L, repo.current().upRate)
        assertTrue(repo.current().sessionActive)
    }
}
