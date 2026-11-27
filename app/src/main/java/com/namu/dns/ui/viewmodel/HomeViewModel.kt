package com.namu.dns.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.namu.dns.Actions
import com.namu.dns.AppConfig
import com.namu.dns.NodeInfo
import com.namu.dns.core.AppContainer
import com.namu.dns.core.repository.HitRepository
import com.namu.dns.core.repository.HitsUiState
import com.namu.dns.core.repository.NodeRepository
import com.namu.dns.core.repository.SettingsRepository
import com.namu.dns.core.repository.StatsRepository
import com.namu.dns.core.repository.StatsUiState
import com.namu.dns.core.runtime.MessageRepository
import com.namu.dns.core.runtime.RuntimeRepository
import com.namu.dns.core.runtime.RuntimeState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class HomeUiState(
    val config: AppConfig = AppConfig(),
    val runtime: RuntimeState = RuntimeState(),
    val stats: StatsUiState = StatsUiState(),
    /** U1：首页状态卡、最近 3 条与快捷指标都从 D2/D4 的同一个出口读。 */
    val hits: HitsUiState = HitsUiState(),
)

/** 连通性测试状态放到 ViewModel，切到服务器/数据页再回来不会丢。 */
data class HomeTestState(
    val testing: Boolean = false,
    val result: String? = null,
)

class HomeViewModel(
    private val settings: SettingsRepository,
    private val runtime: RuntimeRepository,
    private val stats: StatsRepository,
    private val nodes: NodeRepository,
    private val messages: MessageRepository,
    private val hits: HitRepository? = null,
    private val ping: suspend (NodeInfo) -> Long? = { node ->
        Actions.probeNodes(listOf(node)).firstOrNull()?.second
    },
) : ViewModel() {
    private val emptyHits = MutableStateFlow(HitsUiState())

    val state: StateFlow<HomeUiState> = combine(
        settings.config,
        runtime.state,
        stats.state,
        hits?.state ?: emptyHits,
    ) { config, runtime, stats, hitState ->
        HomeUiState(config, runtime, stats, hitState)
    }.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        HomeUiState(settings.current(), runtime.current(), stats.current(), hits?.current() ?: HitsUiState()),
    )

    private val _testState = MutableStateFlow(HomeTestState())
    val testState: StateFlow<HomeTestState> = _testState.asStateFlow()

    fun setMode(mode: String) {
        if (settings.current().mode == mode) return
        settings.update {
            // 纯过滤不代理：final 必须落到直连，否则无节点时会把流量判成代理再兜底拦截。
            if (mode == "filter_only") it.copy(mode = mode, finalPolicy = "direct", finalPolicySource = "")
            else it.copy(mode = mode)
        }
    }

    fun selectNode(name: String) = nodes.select(name)

    fun deleteNode(name: String) {
        nodes.update { cfg ->
            val rest = cfg.nodes.filterNot { it.name == name }
            cfg.copy(
                nodes = rest,
                selected = if (cfg.selected == name) rest.firstOrNull()?.name else cfg.selected,
            )
        }
    }

    fun testSelectedNode() {
        if (_testState.value.testing) return
        val cfg = settings.current()
        val node = cfg.nodes.firstOrNull { it.name == cfg.selected } ?: cfg.nodes.firstOrNull()
        if (node == null) {
            messages.show("请先在服务器列表中添加节点")
            return
        }
        viewModelScope.launch {
            _testState.value = HomeTestState(testing = true)
            val ms = ping(node)
            settings.update { latest ->
                latest.copy(nodes = latest.nodes.map {
                    if (it == node.copy(latency = it.latency, testing = it.testing)) it.copy(latency = ms) else it
                })
            }
            _testState.value = HomeTestState(testing = false, result = ms?.let { "$it ms" } ?: "测速失败")
        }
    }

    fun showMessage(message: String) = messages.show(message)

    fun setHitsWindow(hours: Int) = hits?.setWindow(hours)

    fun retryHits() = hits?.poll()

    fun clearHits() = hits?.clear()

    companion object {
        fun factory(container: AppContainer) = viewModelFactory {
            initializer {
                HomeViewModel(
                    settings = container.settings,
                    runtime = container.runtime,
                    stats = container.stats,
                    nodes = container.nodes,
                    messages = container.messages,
                    hits = container.hits,
                )
            }
        }
    }
}
