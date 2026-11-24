package com.namu.dns.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.namu.dns.Actions
import com.namu.dns.AppConfig
import com.namu.dns.core.AppContainer
import com.namu.dns.core.repository.HitRepository
import com.namu.dns.core.repository.HitsUiState
import com.namu.dns.core.repository.LogRepository
import com.namu.dns.core.repository.LogsUiState
import com.namu.dns.core.repository.NodeRepository
import com.namu.dns.core.repository.SettingsRepository
import com.namu.dns.core.repository.StatsRepository
import com.namu.dns.core.repository.StatsUiState
import com.namu.dns.core.runtime.MessageRepository
import com.namu.dns.core.runtime.RuntimeRepository
import com.namu.dns.core.runtime.RuntimeState
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn

data class DataUiState(
    val config: AppConfig = AppConfig(),
    val runtime: RuntimeState = RuntimeState(),
    val stats: StatsUiState = StatsUiState(),
    val logs: LogsUiState = LogsUiState(),
    val hits: HitsUiState = HitsUiState(),
)

class DataViewModel(
    private val settings: SettingsRepository,
    private val runtime: RuntimeRepository,
    private val stats: StatsRepository,
    private val hits: HitRepository,
    private val logs: LogRepository,
    private val nodes: NodeRepository,
    private val messages: MessageRepository,
) : ViewModel() {
    val state: StateFlow<DataUiState> = combine(
        settings.config,
        runtime.state,
        stats.state,
        hits.state,
        logs.state,
    ) { config, runtime, stats, hitState, logs ->
        DataUiState(config, runtime, stats, logs, hitState)
    }.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        DataUiState(settings.current(), runtime.current(), stats.current(), logs.current(), hits.current()),
    )

    fun setAutoClearLogs(enabled: Boolean) {
        settings.update { it.copy(autoClearLogs = enabled) }
    }

    fun setHitWindow(hours: Int) = hits.setWindow(hours)

    fun clearHits() = hits.clear()

    fun repairHits() = hits.repair()

    fun setHitHistoryEnabled(enabled: Boolean) {
        settings.update { it.copy(hitHistoryEnabled = enabled) }
        hits.setEnabled(enabled)
    }

    fun clearAllNodes() {
        nodes.update { it.copy(nodes = emptyList(), selected = null) }
    }

    suspend fun syncRules(): Int? {
        val url = settings.current().rulesUrl
        if (url.isBlank()) {
            messages.show("当前配置没有 rulesUrl")
            return null
        }
        return try {
            val n = Actions.updateAdsRules(url)
            messages.show("规则源已同步：$n 条")
            n
        } catch (e: Exception) {
            messages.show(e.message ?: "规则同步失败")
            null
        }
    }

    fun showMessage(message: String) = messages.show(message)

    companion object {
        fun factory(container: AppContainer) = viewModelFactory {
            initializer {
                DataViewModel(
                    settings = container.settings,
                    runtime = container.runtime,
                    stats = container.stats,
                    hits = container.hits,
                    logs = container.logs,
                    nodes = container.nodes,
                    messages = container.messages,
                )
            }
        }
    }
}
