package com.namu.dns.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.namu.dns.Actions
import com.namu.dns.NodeInfo
import com.namu.dns.core.AppContainer
import com.namu.dns.core.repository.SettingsRepository
import com.namu.dns.core.runtime.MessageRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** 单节点测速状态放到 ViewModel，切到首页/数据页再回来仍在转圈。 */
class NodesViewModel(
    private val settings: SettingsRepository,
    private val messages: MessageRepository,
    private val ping: suspend (NodeInfo) -> Long? = { node ->
        Actions.probeNodes(listOf(node), settings.current().pingUrl).firstOrNull()?.second
    },
) : ViewModel() {
    private val _testing = MutableStateFlow<String?>(null)
    val testing: StateFlow<String?> = _testing.asStateFlow()

    fun test(node: NodeInfo) {
        if (_testing.value != null) return
        viewModelScope.launch {
            _testing.value = node.name
            val ms = ping(node)
            settings.update { current ->
                current.copy(
                    nodes = current.nodes.map {
                        if (it == node.copy(latency = it.latency, testing = it.testing)) it.copy(latency = ms) else it
                    },
                )
            }
            messages.show(if (ms == null) "${node.name} 测速失败" else "${node.name}：${ms}ms")
            _testing.value = null
        }
    }

    companion object {
        fun factory(container: AppContainer) = viewModelFactory {
            initializer {
                NodesViewModel(container.settings, container.messages)
            }
        }
    }
}
