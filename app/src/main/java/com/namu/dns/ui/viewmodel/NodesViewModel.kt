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
import com.namu.dns.testIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class NodesViewModel(
    private val settings: SettingsRepository,
    private val messages: MessageRepository,
    private val probe: suspend (List<NodeInfo>) -> List<Pair<String, Long?>> = { Actions.probeNodes(it) },
) : ViewModel() {
    private val _testing = MutableStateFlow<Set<String>>(emptySet())
    val testing: StateFlow<Set<String>> = _testing.asStateFlow()
    private val _failed = MutableStateFlow<Set<NodeInfo>>(emptySet())
    val failed: StateFlow<Set<NodeInfo>> = _failed.asStateFlow()

    fun testAll() = testNodes(settings.current().nodes)

    fun test(node: NodeInfo) = testNodes(listOf(node))

    private fun testNodes(nodes: List<NodeInfo>) {
        if (nodes.isEmpty() || _testing.value.isNotEmpty()) return
        val profile = settings.activeConfigName()
        val snapshot = nodes.distinctBy { it.name }
        _testing.value = snapshot.mapTo(HashSet()) { it.name }
        viewModelScope.launch {
            var succeeded = 0
            var failedCount = 0
            try {
                // 内核每次最多并发六个，分批返回结果，可以边测边更新列表。
                for (batch in snapshot.chunked(6)) {
                    val results = probe(batch).toMap()
                    if (settings.activeConfigName() != profile) return@launch
                    val tested = batch.associateBy { it.name }
                    val accepted = settings.update { current ->
                        current.copy(nodes = Actions.applyNodeLatencies(current.nodes, tested, results))
                    }.nodes.filter { node ->
                        node.name in results && tested[node.name]?.testIdentity() == node.testIdentity()
                    }
                    val identities = accepted.map { it.testIdentity() }
                    _failed.value = (_failed.value - identities.toSet()) +
                        accepted.filter { results[it.name] == null }.map { it.testIdentity() }
                    succeeded += accepted.count { results[it.name] != null }
                    failedCount += accepted.count { results[it.name] == null }
                    _testing.value = _testing.value - tested.keys
                }
                val message = when {
                    succeeded + failedCount == 0 -> "未取得测速结果"
                    snapshot.size == 1 && succeeded == 1 -> "${snapshot.first().name} 测速完成"
                    snapshot.size == 1 -> "${snapshot.first().name} 测速失败"
                    else -> "测速完成，可用 ${succeeded} 个，失败 ${failedCount} 个"
                }
                messages.show(message)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                messages.show("测速失败，请重试")
            } finally {
                _testing.value = emptySet()
            }
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
