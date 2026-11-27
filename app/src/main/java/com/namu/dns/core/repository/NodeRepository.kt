package com.namu.dns.core.repository

import com.namu.dns.Actions
import com.namu.dns.AppConfig
import com.namu.dns.NodeInfo

interface NodeRepository {
    fun nodes(): List<NodeInfo>
    fun selected(): String?
    fun select(name: String)
    fun replace(nodes: List<NodeInfo>, selected: String? = null)
    fun update(config: (AppConfig) -> AppConfig): AppConfig
    suspend fun testAll(): Int
}

class DefaultNodeRepository(
    private val settings: SettingsRepository,
) : NodeRepository {
    override fun nodes(): List<NodeInfo> = settings.current().nodes

    override fun selected(): String? = settings.current().selected

    override fun select(name: String) {
        if (settings.current().selected == name) return
        settings.update { it.copy(selected = name) }
    }

    override fun replace(nodes: List<NodeInfo>, selected: String?) {
        settings.update { cfg ->
            cfg.copy(
                nodes = nodes,
                selected = selected ?: cfg.selected?.takeIf { name -> nodes.any { it.name == name } }
                    ?: nodes.firstOrNull()?.name,
            )
        }
    }

    override fun update(config: (AppConfig) -> AppConfig): AppConfig = settings.update(config)

    override suspend fun testAll(): Int = Actions.testAllNodes()
}
