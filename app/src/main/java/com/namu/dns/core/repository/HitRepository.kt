package com.namu.dns.core.repository

import com.namu.dns.NativeCore
import com.namu.dns.core.runtime.RuntimeRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

/** D4 四态；顺序即优先级：loading 只出现在首帧，error 压过 empty/success。 */
enum class ShellPhase { LOADING, EMPTY, ERROR, SUCCESS }

/** D0/D1 的模块命中行；UI 按窗口命中与今日命中分别展示，不混用。 */
data class HitSourceStat(
    val sourceType: String = "unknown",
    val sourceId: String = "unknown",
    val sourceName: String = "未归因",
    val hitsToday: Long = 0,
    val hitsTotal: Long = 0,
    val order: Long = 0,
    val ruleId: String = "",
    val windowHits: Long = 0,
) {
    val key: String get() = "$sourceType|$sourceId"
}

/** D2 最近命中；字段白名单与内核一致。 */
data class RecentHit(
    val seq: Long = 0,
    val ts: Long = 0,
    val domain: String = "",
    val action: String = "block",
    val ruleId: String = "",
    val sourceType: String = "",
    val sourceId: String = "",
    val sourceName: String = "未归因",
    val order: Long = 0,
)

data class HourBucket(
    val hourTs: Long = 0,
    val queries: Long = 0,
    val blocked: Long = 0,
    val cacheLookups: Long = 0,
    val cacheHit: Long = 0,
    val perSourceHits: Map<String, Long> = emptyMap(),
)

data class HitsSnapshot(
    val available: Boolean = false,
    val seq: Long = 0,
    val day: Long = 0,
    val dayStartMs: Long = 0,
    val hitsTotal: Long = 0,
    val sources: List<HitSourceStat> = emptyList(),
    val ring: List<RecentHit> = emptyList(),
    val buckets: List<HourBucket> = emptyList(),
    val historyError: Boolean = false,
    val historyMessage: String = "",
    val serverNowMs: Long = System.currentTimeMillis(),
    val ringCapacity: Int = 200,
    val ringPersisted: Int = 50,
)

/** 数据页窗口派生指标；24h/7d 共用同一套求和口径。 */
data class HitsWindow(
    val hours: Int = 24,
    val queries: Long = 0,
    val blocked: Long = 0,
    val cacheLookups: Long = 0,
    val cacheHit: Long = 0,
    val perSource: List<HitSourceStat> = emptyList(),
    val points: List<HourBucket> = emptyList(),
) {
    val blockedRate: Double?
        get() = if (queries > 0) blocked.toDouble() / queries else null
    val cacheRate: Double?
        get() = if (cacheLookups > 0) cacheHit.toDouble() / cacheLookups else null
    val peakBlocked: Long
        get() = points.maxOfOrNull { it.blocked } ?: 0L
}

data class HitsUiState(
    val phase: ShellPhase = ShellPhase.LOADING,
    val snapshot: HitsSnapshot = HitsSnapshot(),
    val window: HitsWindow = HitsWindow(),
    val windowHours: Int = 24,
    val message: String = "",
    /** true 时 UI 展示「重试」；仅 error 态使用。 */
    val canRetry: Boolean = false,
    /** 未启动的空态需要引导到 VPN 授权；历史为空且未运行时为 true。 */
    val needsVpnGuide: Boolean = false,
    val historyEnabled: Boolean = true,
)

/** ShellFacade 是壳层读命中数据的唯一出口：JNI 解析、四态判断、窗口聚合都在这里。 */
class ShellFacade(
    private val source: HitsSource = NativeHitsSource,
    private val runtime: RuntimeRepository,
    private val now: () -> Long = { System.currentTimeMillis() },
) {
    fun load(since: Long = 0, windowHours: Int = 24, historyEnabled: Boolean = true): HitsUiState {
        val raw = try {
            source.read(since)
        } catch (e: Throwable) {
            return error("命中快照读取失败：${e.message ?: "未知错误"}", HitsSnapshot(serverNowMs = now()))
        }
        val snap = try {
            parseSnapshot(raw)
        } catch (e: Throwable) {
            return error("命中快照解析失败：${e.message ?: "未知错误"}", HitsSnapshot(serverNowMs = now()))
        }
        if (snap.historyError) {
            return error(
                snap.historyMessage.ifBlank { "命中历史文件损坏，已停止写入" },
                snap,
                windowHours,
            ).copy(canRetry = true, historyEnabled = historyEnabled)
        }
        val connected = runtime.current().connected
        val window = aggregate(snap, windowHours)
        val phase = when {
            !connected && snap.ring.isEmpty() && window.queries == 0L -> ShellPhase.EMPTY
            connected && window.queries == 0L && snap.ring.isEmpty() -> ShellPhase.EMPTY
            else -> ShellPhase.SUCCESS
        }
        val message = when {
            phase == ShellPhase.EMPTY && !connected -> "尚未启动 VPN，命中摘要会在启动后开始记录"
            phase == ShellPhase.EMPTY -> "已启动，等待本窗口第一条查询"
            window.queries == 0L -> "本窗口暂无查询"
            else -> ""
        }
        return HitsUiState(
            phase = phase,
            snapshot = snap,
            window = window,
            windowHours = windowHours,
            message = message,
            needsVpnGuide = phase == ShellPhase.EMPTY && !connected,
            historyEnabled = historyEnabled,
        )
    }

    fun repair(): Boolean = source.repair()

    fun clear() = source.clear()

    fun setEnabled(enabled: Boolean): Boolean = source.setEnabled(enabled)

    private fun error(message: String, snap: HitsSnapshot, hours: Int = 24): HitsUiState =
        HitsUiState(
            phase = ShellPhase.ERROR,
            snapshot = snap,
            window = aggregate(snap, hours),
            windowHours = hours,
            message = message,
            canRetry = true,
        )
}

interface HitsSource {
    fun read(since: Long): String
    fun repair(): Boolean
    fun clear()
    fun setEnabled(enabled: Boolean): Boolean
}

object NativeHitsSource : HitsSource {
    override fun read(since: Long): String = NativeCore.nativeHits(since)
    override fun repair(): Boolean = NativeCore.nativeHitsRepair()
    override fun clear() = NativeCore.nativeClearHits()
    override fun setEnabled(enabled: Boolean): Boolean = NativeCore.nativeSetHitHistoryEnabled(enabled)
}

object HitSnapshotParser {
    fun parse(raw: String): HitsSnapshot = parseSnapshot(raw)
}

internal fun parseSnapshot(raw: String): HitsSnapshot {
    if (raw.isBlank()) return HitsSnapshot()
    val o = JSONObject(raw)
    val sources = o.optJSONArray("sources")?.let { a ->
        (0 until a.length()).mapNotNull { i ->
            a.optJSONObject(i)?.let { s ->
                HitSourceStat(
                    sourceType = s.optString("sourceType", "unknown"),
                    sourceId = s.optString("sourceId", "unknown"),
                    sourceName = s.optString("sourceName", "未归因"),
                    hitsToday = s.optLong("hitsToday", 0),
                    hitsTotal = s.optLong("hitsTotal", 0),
                    order = s.optLong("order", 0),
                    ruleId = s.optString("ruleId", ""),
                )
            }
        }.sortedWith(compareByDescending<HitSourceStat> { it.hitsToday }.thenBy { it.order })
    } ?: emptyList()
    val ring = o.optJSONArray("ring")?.let { a ->
        (0 until a.length()).mapNotNull { i ->
            a.optJSONObject(i)?.let { e ->
                RecentHit(
                    seq = e.optLong("seq", 0),
                    ts = e.optLong("ts", 0),
                    domain = e.optString("domain", ""),
                    action = e.optString("action", "block"),
                    ruleId = e.optString("ruleId", ""),
                    sourceType = e.optString("sourceType", ""),
                    sourceId = e.optString("sourceId", ""),
                    sourceName = e.optString("sourceName", "未归因"),
                    order = e.optLong("order", 0),
                )
            }
        }.sortedByDescending { it.seq }
    } ?: emptyList()
    val buckets = o.optJSONObject("history")?.optJSONArray("buckets")?.let { a ->
        (0 until a.length()).mapNotNull { i ->
            a.optJSONObject(i)?.let { b ->
                val per = buildMap {
                    b.optJSONObject("perSourceHits")?.let { m ->
                        m.keys().forEach { k -> put(k, m.optLong(k, 0)) }
                    }
                }
                HourBucket(
                    hourTs = b.optLong("hourTs", 0),
                    queries = b.optLong("queries", 0),
                    blocked = b.optLong("blocked", 0),
                    cacheLookups = b.optLong("cacheLookups", 0),
                    cacheHit = b.optLong("cacheHit", 0),
                    perSourceHits = per,
                )
            }
        }.sortedBy { it.hourTs }
    } ?: emptyList()
    return HitsSnapshot(
        available = o.optBoolean("available", false),
        seq = o.optLong("seq", 0),
        day = o.optLong("day", 0),
        dayStartMs = o.optLong("dayStartMs", 0),
        hitsTotal = o.optLong("hitsTotal", 0),
        sources = sources,
        ring = ring,
        buckets = buckets,
        historyError = o.optJSONObject("history")?.optBoolean("error", false) ?: false,
        historyMessage = o.optJSONObject("history")?.optString("message", "") ?: "",
        serverNowMs = o.optLong("serverNowMs", System.currentTimeMillis()),
        ringCapacity = o.optInt("ringCapacity", 200),
        ringPersisted = o.optInt("ringPersisted", 50),
    )
}

internal fun aggregate(snap: HitsSnapshot, hours: Int): HitsWindow {
    val hourSec = 3600L
    val nowHour = (snap.serverNowMs / 1000L / hourSec) * hourSec
    val take = hours.coerceIn(1, 168)
    val from = nowHour - (take - 1) * hourSec
    val points = snap.buckets.filter { it.hourTs in from..nowHour }
    val per = LinkedHashMap<String, Long>()
    points.forEach { b ->
        b.perSourceHits.forEach { (k, v) -> per[k] = (per[k] ?: 0L) + v }
    }
    val sourceByKey = snap.sources.associateBy { it.key }
    val rows = per.entries.sortedByDescending { it.value }.map { (key, hits) ->
        val parts = key.split('|', limit = 2)
        sourceByKey[key]?.copy(windowHits = hits) ?: HitSourceStat(
            sourceType = parts.getOrElse(0) { "unknown" },
            sourceId = parts.getOrElse(1) { "unknown" },
            sourceName = if (parts.getOrElse(0) { "unknown" } == "unknown") "未归因" else key,
            windowHits = hits,
        )
    }
    return HitsWindow(
        hours = take,
        queries = points.sumOf { it.queries },
        blocked = points.sumOf { it.blocked },
        cacheLookups = points.sumOf { it.cacheLookups },
        cacheHit = points.sumOf { it.cacheHit },
        perSource = rows,
        points = points,
    )
}

internal data class HitModuleStat(val name: String, val hits: Long)

/**
 * 同一模块的 DNS/URL/脚本命中行按 sourceId 合并，并优先使用模块当前名称。
 * 旧快照里可能只有 `script|mod_x` 这类内部键，直接展示会把内部 ID 露给用户。
 */
internal fun hitModuleDistribution(
    rows: List<HitSourceStat>,
    knownNames: Map<String, String>,
): List<HitModuleStat> = rows.groupBy { row ->
    row.sourceId.takeUnless { it.isBlank() || it == "unknown" }.orEmpty()
}.map { (id, rowsForSource) ->
    val displayName = knownNames[id]?.takeIf { it.isNotBlank() }
        ?: rowsForSource.firstNotNullOfOrNull { row ->
            row.sourceName.takeUnless {
                it.isBlank() || it == "未归因" || it == row.key || it == row.sourceId
            }
        }
        ?: "未归因"
    HitModuleStat(displayName, rowsForSource.sumOf { it.windowHits })
}.groupBy { it.name }.flatMap { (name, rowsForName) ->
    if (name == "未归因") listOf(HitModuleStat(name, rowsForName.sumOf { it.hits })) else rowsForName
}.sortedByDescending { it.hits }

/** 7d 图按设备本地自然日聚合 7 个点；24h 图直接使用 24 个小时点。 */
data class DayPoint(val label: String, val blocked: Long, val queries: Long)

fun windowPoints(snap: HitsSnapshot, window: HitsWindow, days: Boolean = false): List<DayPoint> {
    if (!days) {
        return window.points.map { b ->
            val h = java.util.Calendar.getInstance().apply {
                timeInMillis = b.hourTs * 1000L
                set(java.util.Calendar.MINUTE, 0)
                set(java.util.Calendar.SECOND, 0)
                set(java.util.Calendar.MILLISECOND, 0)
            }.get(java.util.Calendar.HOUR_OF_DAY)
            DayPoint(String.format(java.util.Locale.US, "%02d", h), b.blocked, b.queries)
        }
    }
    val byDay = LinkedHashMap<String, DayPoint>()
    window.points.forEach { b ->
        val cal = java.util.Calendar.getInstance().apply { timeInMillis = b.hourTs * 1000L }
        val key = String.format(
            java.util.Locale.US,
            "%04d-%02d-%02d",
            cal.get(java.util.Calendar.YEAR),
            cal.get(java.util.Calendar.MONTH) + 1,
            cal.get(java.util.Calendar.DAY_OF_MONTH),
        )
        val old = byDay[key]
        byDay[key] = DayPoint(
            label = String.format(java.util.Locale.US, "%02d/%02d", cal.get(java.util.Calendar.MONTH) + 1, cal.get(java.util.Calendar.DAY_OF_MONTH)),
            blocked = (old?.blocked ?: 0L) + b.blocked,
            queries = (old?.queries ?: 0L) + b.queries,
        )
    }
    return byDay.values.toList().takeLast(7)
}

interface HitRepository {
    val state: StateFlow<HitsUiState>
    fun current(): HitsUiState
    fun poll()
    fun setWindow(hours: Int)
    fun repair()
    fun clear()
    fun setEnabled(enabled: Boolean)
}

class DefaultHitRepository(
    private val runtime: RuntimeRepository,
    private val facade: ShellFacade = ShellFacade(runtime = runtime),
    private val pollIntervalMs: Long = 2000L,
    autoPoll: Boolean = true,
) : HitRepository {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Any()
    private val _state = MutableStateFlow(HitsUiState())
    override val state: StateFlow<HitsUiState> = _state.asStateFlow()
    private var windowHours = 24

    init {
        poll()
        if (autoPoll) scope.launch {
            while (isActive) {
                poll()
                delay(pollIntervalMs)
            }
        }
    }

    override fun current(): HitsUiState = _state.value

    override fun poll() {
        synchronized(lock) {
            val previous = _state.value
            val next = try {
                facade.load(
                    since = 0,
                    windowHours = windowHours,
                    historyEnabled = previous.historyEnabled,
                )
            } catch (e: Throwable) {
                previous.copy(phase = ShellPhase.ERROR, message = e.message ?: "命中数据读取失败", canRetry = true)
            }
            // 保持首帧 loading：首次成功返回前不把空快照误判成 empty。
            _state.value = if (previous.phase == ShellPhase.LOADING && next.snapshot.seq == 0L && next.phase == ShellPhase.SUCCESS) {
                next
            } else next
        }
    }

    override fun setWindow(hours: Int) {
        windowHours = if (hours >= 168) 168 else 24
        poll()
    }

    override fun repair() {
        facade.repair()
        poll()
    }

    override fun clear() {
        facade.clear()
        poll()
    }

    override fun setEnabled(enabled: Boolean) {
        facade.setEnabled(enabled)
        _state.value = _state.value.copy(historyEnabled = enabled)
        poll()
    }
}
