package com.namu.dns.core.stats

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SpeedSamplerTest {
    @Test
    fun `one second windows produce long rates`() {
        val sampler = SpeedSampler()
        assertTrue(sampler.add(0, 0, 1_000).isEmpty())
        assertEquals(1, sampler.add(1024, 2048, 2_000).size)
        assertEquals(1024, sampler.snapshot().last().up)
        assertEquals(2048, sampler.snapshot().last().down)

        // 同一秒内的补帧不产生新点
        assertEquals(1, sampler.add(1024, 2048, 2_500).size)

        assertEquals(2, sampler.add(3072, 6144, 3_000).size)
        assertEquals(2048, sampler.snapshot().last().up)
        assertEquals(4096, sampler.snapshot().last().down)
    }

    @Test
    fun `ring keeps last sixty points`() {
        val sampler = SpeedSampler()
        sampler.add(0, 0, 0)
        for (i in 1..70) {
            sampler.add(i * 1000L, i * 2000L, i * 1000L)
        }
        assertEquals(60, sampler.snapshot().size)
        assertEquals(1_000L, sampler.snapshot().last().up)
        assertEquals(2_000L, sampler.snapshot().last().down)
    }

    @Test
    fun `counter reset rebuilds baseline`() {
        val sampler = SpeedSampler()
        sampler.add(0, 0, 0)
        sampler.add(1000, 1000, 1000)
        assertEquals(1, sampler.snapshot().size)
        // 服务重启后累计值变小，不能算出负数速率
        assertTrue(sampler.add(10, 10, 2000).isEmpty())
        assertEquals(1000L, sampler.add(1010, 1010, 3000).last().up)
    }
}
