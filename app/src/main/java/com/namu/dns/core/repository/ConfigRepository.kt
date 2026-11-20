package com.namu.dns.core.repository

import com.namu.dns.AppConfig
import com.namu.dns.ConfigFileStore
import com.namu.dns.core.config.ConfigFile
import com.namu.dns.core.config.ConfigSourceRegistry

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

    /** 切换 active 配置：整体替换配置字段，节点/订阅保留；成功后触发 onApplied。 */
    fun switchTo(name: String): Boolean

    /** 以当前配置为模板新建；不自动切换。 */
    fun create(name: String): Boolean

    /** 导入旧扁平或新嵌套 JSON；同名拒绝。 */
    fun import(name: String, text: String): Boolean

    /** 删除；default.conf 永远拒绝。删掉当前配置时回落到 default。 */
    fun delete(name: String): Boolean
}

class DefaultConfigRepository(
    private val settings: SettingsRepository,
    private val files: ConfigFileGateway,
    private val onApplied: (AppConfig) -> Unit = {},
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

    override fun switchTo(name: String): Boolean {
        val n = ConfigFileStore.sanitize(name)
        val loaded = files.load(n, settings.current()) ?: return false
        // 先改 active 名，再写内存配置：persist 会用新 active 名刷新 .conf，
        // 顺序反了会把旧配置文件覆盖成新配置内容。
        settings.setActiveConfigName(n)
        settings.set(loaded)
        onApplied(settings.current())
        return true
    }

    override fun create(name: String): Boolean {
        val n = ConfigFileStore.sanitize(name)
        if (files.exists(n)) return false
        return files.save(n, settings.current())
    }

    override fun import(name: String, text: String): Boolean {
        val n = ConfigFileStore.sanitize(name)
        if (files.exists(n)) return false
        // 非原生格式（Clash/Loon/小火箭）只做识别/预览，不因为解析成功就启用。
        val current = settings.current()
        val result = ConfigSourceRegistry.parse(text, current)
        if (!result.preview.canImport) return false
        val parsed = result.config ?: return false
        val next = parsed.toAppConfig(current)
        if (result.nodes.isEmpty()) {
            return files.save(n, next)
        }
        // Loon/小火箭配置把节点内联在文件里；节点仍属于设备侧，不写进 .conf。
        // 先写好新配置，再激活它，避免把导入内容覆盖到当前 active .conf。
        val first = result.nodes.firstOrNull()?.name
        val merged = next.copy(
            nodes = result.nodes,
            selected = if (next.selected != null && result.nodes.any { it.name == next.selected }) next.selected else first,
        )
        if (!files.save(n, merged)) return false
        settings.setActiveConfigName(n)
        settings.set(merged)
        onApplied(merged)
        return true
    }

    override fun delete(name: String): Boolean {
        val n = ConfigFileStore.sanitize(name)
        if (n == ConfigFileStore.DEFAULT_NAME) return false
        if (!files.exists(n)) return false
        if (!files.delete(n)) return false

        if (settings.activeConfigName() == n) {
            files.ensureDefault(settings.current())
            val fallback = files.load(ConfigFileStore.DEFAULT_NAME, settings.current())
            settings.setActiveConfigName(ConfigFileStore.DEFAULT_NAME)
            if (fallback != null) {
                settings.set(fallback)
                onApplied(settings.current())
            }
        }
        return true
    }
}
