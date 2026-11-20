package com.namu.dns.core.runtime

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

data class RuntimeState(
    val connected: Boolean = false,
    val starting: Boolean = false,
    val stopping: Boolean = false,
    val lastStartupMs: Long = 0L,
)

interface RuntimeRepository {
    val state: StateFlow<RuntimeState>
    fun current(): RuntimeState
    fun markStarting()
    fun markConnected(startupMs: Long)
    fun markStartFailed()
    fun markStopping()
    fun markStopped()
}

class DefaultRuntimeRepository : RuntimeRepository {
    private val _state = MutableStateFlow(RuntimeState())
    override val state: StateFlow<RuntimeState> = _state.asStateFlow()

    override fun current(): RuntimeState = _state.value

    override fun markStarting() {
        _state.update { it.copy(starting = true, stopping = false, connected = false) }
    }

    override fun markConnected(startupMs: Long) {
        _state.update {
            it.copy(
                connected = true,
                starting = false,
                stopping = false,
                lastStartupMs = if (startupMs > 0L) startupMs else it.lastStartupMs,
            )
        }
    }

    override fun markStartFailed() {
        _state.update { it.copy(connected = false, starting = false) }
    }

    override fun markStopping() {
        _state.update { it.copy(stopping = true, connected = false, starting = false) }
    }

    override fun markStopped() {
        _state.update { it.copy(stopping = false, connected = false, starting = false) }
    }
}
