package com.namu.dns.core.repository

import com.namu.dns.StatsData
import com.namu.dns.core.runtime.DefaultRuntimeRepository
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StatsRepositoryTest {
    private class FakeSource(var next: StatsData = StatsData()) : StatsSource {
        override fun read(): StatsData = next
    }

    private class CountingSource : StatsSource {
        @Volatile var reads = 0
        override fun read(): StatsData {
            reads++
            return StatsData(up = reads.toLong(), down = reads.toLong())
        }
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

    @Test
    fun `returning to foreground refreshes immediately regardless of interval`() = runBlocking {
        // A1：轮询间隔设得极大（模拟后台 5s 档），回前台仍应立即补一帧，
        // 证明补帧不依赖轮询周期；速率按实际采样间隔差分不受影响。
        val prevFg = AppForeground.state.value
        try {
            AppForeground.state.value = false
            val runtime = DefaultRuntimeRepository()
            runtime.markConnected(0)
            val source = CountingSource()
            DefaultStatsRepository(
                runtime, source,
                pollIntervalMs = 3_600_000L,
                backgroundPollIntervalMs = 3_600_000L,
                autoPoll = true,
            )
            // 回前台 → 收集器立即 poll()。
            AppForeground.state.value = true
            withTimeout(3_000L) {
                while (source.reads == 0) kotlinx.coroutines.delay(10)
            }
            assertTrue("回前台应立即补帧", source.reads >= 1)
        } finally {
            AppForeground.state.value = prevFg
        }
    }
}
