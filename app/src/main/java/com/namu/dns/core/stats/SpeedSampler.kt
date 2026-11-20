package com.namu.dns.core.stats

/** 1 秒粒度的上行/下行速率点，单位 byte/s。 */
data class SpeedSample(
    val up: Long,
    val down: Long,
)

/**
 * 对累计 up/down 做差分，并按 1 秒窗口维护最近 60 个点。
 * 单纯用 Long 计算，不经过 Float，避免 >16MB 时精度抖动。
 */
class SpeedSampler(
    private val capacity: Int = 60,
    private val intervalMs: Long = 1000L,
) {
    private val points = ArrayDeque<SpeedSample>(capacity)
    private var sampleUp = 0L
    private var sampleDown = 0L
    private var sampleAt = 0L
    private var hasBaseline = false

    fun reset() {
        points.clear()
        sampleUp = 0L
        sampleDown = 0L
        sampleAt = 0L
        hasBaseline = false
    }

    fun snapshot(): List<SpeedSample> = points.toList()

    /**
     * 传入累计流量与当前时间；不足 1 秒的补帧只更新基线，不产生新点。
     * 计数器变小视为服务重启，自动重建基线。
     */
    fun add(up: Long, down: Long, atMs: Long): List<SpeedSample> {
        if (!hasBaseline || up < sampleUp || down < sampleDown || atMs < sampleAt) {
            reset()
            sampleUp = up
            sampleDown = down
            sampleAt = atMs
            hasBaseline = true
            return snapshot()
        }
        val elapsed = atMs - sampleAt
        if (elapsed < intervalMs) return snapshot()

        val upRate = ((up - sampleUp).coerceAtLeast(0L) * 1000L) / elapsed
        val downRate = ((down - sampleDown).coerceAtLeast(0L) * 1000L) / elapsed
        points.addLast(SpeedSample(upRate, downRate))
        while (points.size > capacity) points.removeFirst()

        sampleUp = up
        sampleDown = down
        sampleAt = atMs
        return snapshot()
    }
}
