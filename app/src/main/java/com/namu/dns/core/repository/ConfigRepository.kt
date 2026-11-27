package com.namu.dns.core.repository

import com.namu.dns.AppConfig
import com.namu.dns.ConfigFileStore
import com.namu.dns.NodeInfo
import com.namu.dns.core.config.ConfigFile
import com.namu.dns.core.config.ConfigSourceRegistry
import com.namu.dns.core.config.GroupValidator

data class ConfigEntry(
    val name: String,
    val size: Long,
    val modified: Long,
    val active: Boolean,
    val isDefault: Boolean,
)

interface ConfigRepository {
    fun current(): AppConfig
    fun set(config: AppConfig)
    fun update(transform: (AppConfig) -> AppConfig): AppConfig
    fun save()

    fun configFiles(): List<ConfigEntry>
    fun activeName(): String
    fun loadProfile(name: String): AppConfig?
    fun saveProfile(name: String, transform: (AppConfig) -> AppConfig): AppConfig?
    fun validateProfile(name: String): String?
    fun copyProfile(from: String, name: String): Boolean

    /** 切换 active 配置：整体替换配置字段，节点/订阅保留；成功后触发 onApplied。 */
    fun switchTo(name: String): Boolean

    /** 新建基础方案；复制当前配置使用 copyProfile。 */
    fun create(name: String): Boolean

    /** 导入旧扁平或新嵌套 JSON；同名拒绝。 */
    fun import(name: String, text: String): Boolean
    fun import(name: String, text: String, sourceUrl: String?): Boolean

    /** 删除；default.conf 永远拒绝。删掉当前配置时回落到 default。 */
    fun delete(name: String): Boolean
}

class DefaultConfigRepository(
    private val settings: SettingsRepository,
    private val files: ConfigFileGateway,
    private val onApplied: (AppConfig) -> Unit = {},
    private val onSwitched: ((String, AppConfig, AppConfig) -> Unit)? = null,
) : ConfigRepository {
    override fun current(): AppConfig = settings.current()

    override fun set(config: AppConfig) = settings.set(config)

    override fun update(transform: (AppConfig) -> AppConfig): AppConfig = settings.update(transform)

    override fun save() = settings.save()

    override fun configFiles(): List<ConfigEntry> {
        files.ensureDefault(settings.current())
        return files.list(settings.activeConfigName())
    }

    override fun activeName(): String = settings.activeConfigName()

    override fun loadProfile(name: String): AppConfig? {
        val n = ConfigFileStore.sanitize(name)
        val current = settings.current()
        if (n == activeName()) return current
        return files.load(n, current)?.let { withImportedNodes(it, files.importedNodes(n)) }
    }

    override fun validateProfile(name: String): String? {
        val config = loadProfile(name) ?: return "配置无法读取"
        return profileError(name, config)
    }

    override fun saveProfile(name: String, transform: (AppConfig) -> AppConfig): AppConfig? {
        val n = ConfigFileStore.sanitize(name)
        val current = loadProfile(n) ?: return null
        val next = transform(current)
        if (next == current) return current
        if (profileError(n, next) != null || !files.save(n, next)) return null
        if (n == activeName()) {
            settings.applySavedProfile(n, next)
            onApplied(next)
        }
        return next
    }

    override fun switchTo(name: String): Boolean {
        val n = ConfigFileStore.sanitize(name)
        val loaded = loadProfile(n) ?: return false
        if (profileError(n, loaded) != null) return false
        val beforeName = activeName()
        if (n == beforeName) return true
        val before = settings.current()
        settings.applySavedProfile(n, loaded)
        if (onSwitched != null) onSwitched(beforeName, before, loaded) else onApplied(loaded)
        return true
    }

    override fun create(name: String): Boolean {
        val n = ConfigFileStore.sanitize(name)
        if (files.exists(n)) return false
        return files.save(n, AppConfig.freshDefaults())
    }

    override fun copyProfile(from: String, name: String): Boolean {
        val n = ConfigFileStore.sanitize(name)
        if (files.exists(n)) return false
        val source = loadProfile(from) ?: return false
        return saveImportedProfile(n, source, files.importedNodes(ConfigFileStore.sanitize(from)))
    }

    override fun import(name: String, text: String): Boolean = import(name, text, null)

    override fun import(name: String, text: String, sourceUrl: String?): Boolean {
        val n = ConfigFileStore.sanitize(name)
        if (files.exists(n)) return false
        val current = settings.current()
        val result = ConfigSourceRegistry.parse(text, current)
        if (!result.preview.canImport) return false
        val parsed = result.config ?: return false
        val next = withImportedNodes(parsed.toAppConfig(current), result.nodes).copy(
            remoteConfigUrl = sourceUrl.orEmpty(),
            remoteConfigName = if (sourceUrl.isNullOrBlank()) "" else n,
            remoteConfigUpdatedAt = if (sourceUrl.isNullOrBlank()) 0L else System.currentTimeMillis(),
        )
        if (profileError(n, next) != null) return false
        return saveImportedProfile(n, next, result.nodes)
    }

    private fun saveImportedProfile(name: String, config: AppConfig, nodes: List<NodeInfo>): Boolean {
        if (!files.save(name, config)) return false
        if (nodes.isEmpty() || files.saveImportedNodes(name, nodes)) return true
        files.delete(name)
        return false
    }

    private fun withImportedNodes(config: AppConfig, imported: List<NodeInfo>): AppConfig {
        if (imported.isEmpty()) return config
        val nodes = (config.nodes + imported).distinctBy { it.name }
        return config.copy(nodes = nodes, selected = config.selected ?: nodes.firstOrNull()?.name)
    }

    private fun profileError(name: String, config: AppConfig): String? =
        com.namu.dns.core.config.ConfigDnsInput.error(config.dnsUpstream.ifBlank { "system" })
            ?: config.dnsFallback.takeIf { config.allowDnsFallback && it.isNotBlank() }
                ?.let(com.namu.dns.core.config.ConfigDnsInput::error)
            ?: GroupValidator.validate(name, config).errors
                .firstOrNull()?.let { it.message }

    override fun delete(name: String): Boolean {
        val n = ConfigFileStore.sanitize(name)
        if (n == ConfigFileStore.DEFAULT_NAME) return false
        if (!files.exists(n)) return false
        val fallback = if (activeName() == n) {
            files.ensureDefault(settings.current())
            files.load(ConfigFileStore.DEFAULT_NAME, settings.current()) ?: return false
        } else null
        if (!files.delete(n)) return false

        if (fallback != null) {
            settings.applySavedProfile(ConfigFileStore.DEFAULT_NAME, fallback)
            onApplied(fallback)
        }
        return true
    }
}
