package com.namu.dns.core.repository

import com.namu.dns.DnsLogEntry
import com.namu.dns.LogEntry
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
import org.json.JSONArray

data class LogsUiState(
    val runtime: List<LogEntry> = emptyList(),
    val dns: List<DnsLogEntry> = emptyList(),
)

interface LogRepository {
    val state: StateFlow<LogsUiState>
    fun current(): LogsUiState
    fun poll()
    fun clearRuntime()
    fun clearDns()
}

interface LogSource {
    fun logs(sinceId: Long): List<LogEntry>
    fun dnsLogs(sinceId: Long): List<DnsLogEntry>
    fun clearLogs()
    fun clearDnsLogs()
}

object NativeLogSource : LogSource {
    override fun logs(sinceId: Long): List<LogEntry> {
        val arr = JSONArray(NativeCore.nativeLogs(sinceId))
        return buildList {
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                add(
                    LogEntry(
                        id = o.optLong("id"),
                        ts = o.optLong("ts"),
                        level = o.optString("level", "I"),
                        tag = o.optString("tag"),
                        msg = o.optString("msg"),
                    ),
                )
            }
        }
    }

    override fun dnsLogs(sinceId: Long): List<DnsLogEntry> {
        val arr = JSONArray(NativeCore.nativeDnsLogs(sinceId))
        return buildList {
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                add(
                    DnsLogEntry(
                        id = o.optLong("id"),
                        ts = o.optLong("ts"),
                        domain = o.optString("domain"),
                        qtype = o.optString("qtype"),
                        action = o.optString("action"),
                        detail = o.optString("detail"),
                        ms = o.optLong("ms"),
                        count = o.optLong("count", 1),
                    ),
                )
            }
        }
    }

    override fun clearLogs() = NativeCore.nativeClearLogs()
    override fun clearDnsLogs() = NativeCore.nativeClearDnsLogs()
}

class DefaultLogRepository(
    private val runtime: RuntimeRepository,
    private val source: LogSource = NativeLogSource,
    private val pollIntervalMs: Long = 1000L,
    private val maxEntries: Int = 300,
    autoPoll: Boolean = true,
) : LogRepository {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Any()
    private val _state = MutableStateFlow(LogsUiState())
    override val state: StateFlow<LogsUiState> = _state.asStateFlow()

    private var lastRuntimeId = 0L
    private var lastDnsId = 0L

    init {
        if (autoPoll) scope.launch {
            while (isActive) {
                if (runtime.current().connected) poll()
                delay(pollIntervalMs)
            }
        }
    }

    override fun current(): LogsUiState = _state.value

    override fun poll() {
        if (!runtime.current().connected) return
        synchronized(lock) {
            runCatching {
                val newRuntime = source.logs(lastRuntimeId)
                    .filter { it.id > lastRuntimeId }
                if (newRuntime.isNotEmpty()) {
                    lastRuntimeId = maxOf(lastRuntimeId, newRuntime.maxOf { it.id })
                    _state.value = _state.value.copy(
                        runtime = (_state.value.runtime + newRuntime).takeLast(maxEntries),
                    )
                }
            }
            runCatching {
                val newDns = source.dnsLogs(lastDnsId)
                    .filter { it.id > lastDnsId }
                if (newDns.isNotEmpty()) {
                    lastDnsId = maxOf(lastDnsId, newDns.maxOf { it.id })
                    _state.value = _state.value.copy(
                        dns = (_state.value.dns + newDns).takeLast(maxEntries),
                    )
                }
            }
        }
    }

    override fun clearRuntime() {
        synchronized(lock) {
            // native clear 与游标/StateFlow 同一把锁：避免清空后立刻 poll 又把旧缓冲读回来。
            runCatching { source.clearLogs() }
            lastRuntimeId = 0L
            _state.value = _state.value.copy(runtime = emptyList())
        }
    }

    override fun clearDns() {
        synchronized(lock) {
            runCatching { source.clearDnsLogs() }
            lastDnsId = 0L
            _state.value = _state.value.copy(dns = emptyList())
        }
    }
}
