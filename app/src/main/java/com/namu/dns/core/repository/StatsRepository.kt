package com.namu.dns.core.repository

import android.os.SystemClock
import com.namu.dns.NativeCore
import com.namu.dns.StatsData
import com.namu.dns.core.runtime.RuntimeRepository
import com.namu.dns.core.stats.SpeedSample
import com.namu.dns.core.stats.SpeedSampler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class StatsUiState(
    val stats: StatsData = StatsData(),
    /** 由 up/down 总量差分得到，单位 byte/s。 */
    val upRate: Long = 0,
    val downRate: Long = 0,
    /** 当前连接是否仍在累计；断开后 stats 保留为最后一次会话统计。 */
    val sessionActive: Boolean = false,
    /** 最近 60 个 1 秒速率点，供 sparkline 使用。 */
    val speedSamples: List<SpeedSample> = emptyList(),
)

interface StatsRepository {
    val state: StateFlow<StatsUiState>
    fun current(): StatsUiState
    fun poll()
    fun resetSession()
}

interface StatsSource {
    fun read(): StatsData
}

/** App 前后台标志：由 MainActivity onStart/onStop 驱动，供统计轮询自适应。
 *  默认 true（进程刚起、UI 未上报时按前台对待，避免漏刷）。 */
object AppForeground {
    val state = MutableStateFlow(true)
}

object NativeStatsSource : StatsSource {
    override fun read(): StatsData = StatsData.fromJson(NativeCore.nativeStats())
}

class DefaultStatsRepository(
    private val runtime: RuntimeRepository,
    private val source: StatsSource = NativeStatsSource,
    private val now: () -> Long = { SystemClock.elapsedRealtime() },
    private val pollIntervalMs: Long = 1000L,
    private val backgroundPollIntervalMs: Long = 5000L,
    autoPoll: Boolean = true,
) : StatsRepository {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Any()
    private val _state = MutableStateFlow(StatsUiState())
    override val state: StateFlow<StatsUiState> = _state.asStateFlow()

    private var lastStats: StatsData? = null
    private var lastAtMs: Long = 0L
    private val sampler = SpeedSampler()

    init {
        if (autoPoll) {
            scope.launch {
                while (isActive) {
                    if (runtime.current().connected) poll()
                    // A1 自适应：前台 1s 保 UI 流畅，后台 5s 降 JNI/序列化/耗电。
                    // 速率在 poll() 内按实际采样间隔差分，间隔变化不影响口径。
                    delay(if (AppForeground.state.value) pollIntervalMs else backgroundPollIntervalMs)
                }
            }
            // 回前台立即补一帧，避免从 5s 档切回时 UI 滞后最多一秒。
            scope.launch {
                AppForeground.state.collect { fg -> if (fg) poll() }
            }
        }
    }

    override fun current(): StatsUiState = _state.value

    override fun poll() {
        // 自动轮询和服务状态切换后的补帧可能并发；把 JNI 读取一起放进锁内，
        // 避免旧帧晚到、覆盖新帧后算出错误的差分速率。
        synchronized(lock) {
            if (!runtime.current().connected) {
                if (_state.value.sessionActive) {
                    _state.value = _state.value.copy(upRate = 0, downRate = 0, sessionActive = false)
                }
                return
            }
            val raw = try {
                source.read()
            } catch (_: Throwable) {
                return
            }
            val at = now()
            if (!_state.value.sessionActive) {
                // 新连接刚开始：先清掉上一次会话，再按第一帧建立基线。
                lastStats = null
                lastAtMs = 0L
                sampler.reset()
            }
            val previous = lastStats
            val upRate: Long
            val downRate: Long
            if (previous != null && lastAtMs > 0L) {
                val dt = (at - lastAtMs).coerceAtLeast(1L)
                upRate = ((raw.up - previous.up).coerceAtLeast(0L) * 1000L) / dt
                downRate = ((raw.down - previous.down).coerceAtLeast(0L) * 1000L) / dt
            } else {
                upRate = 0L
                downRate = 0L
            }
            lastStats = raw
            lastAtMs = at
            _state.value = StatsUiState(
                stats = raw,
                upRate = upRate,
                downRate = downRate,
                sessionActive = true,
                speedSamples = sampler.add(raw.up, raw.down, at),
            )
        }
    }

    override fun resetSession() {
        synchronized(lock) {
            lastStats = null
            lastAtMs = 0L
            sampler.reset()
            _state.value = StatsUiState(
                stats = StatsData(),
                sessionActive = runtime.current().connected,
            )
        }
    }
}
