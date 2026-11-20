package com.namu.dns

import android.content.Context
import com.namu.dns.core.config.ConfigFile
import java.io.File

/**
 * 小火箭式配置文件：每份配置是独立文件，切换时整体替换 DNS、规则、模块清单，
 * 服务器节点与订阅保持不变（节点属于「服务器列表」，不属于配置文件）。
 */
object ConfigFileStore {
    const val DEFAULT_NAME = "default.conf"

    data class FileInfo(
        val name: String,
        val size: Long,
        val modified: Long,
        val active: Boolean,
        val isDefault: Boolean,
    )

    private fun dir(context: Context): File =
        File(context.filesDir, "configs").apply { if (!exists()) mkdirs() }

    private fun file(context: Context, name: String): File = File(dir(context), name)

    fun activeName(context: Context): String = App.container.settings.activeConfigName()

    fun setActive(context: Context, name: String) {
        App.container.settings.setActiveConfigName(name)
    }

    /** 只保存配置相关字段，节点/订阅不写进配置文件。 */
    private fun snapshot(cfg: AppConfig): String = ConfigFile.fromAppConfig(cfg).toJson()

    fun save(context: Context, name: String, cfg: AppConfig): Boolean = try {
        val f = file(context, sanitize(name))
        // 每次覆盖前保留上一版；失败或用户回退时可恢复。
        if (f.exists() && f.length() > 0) {
            runCatching { f.copyTo(File(f.parentFile, f.name + ".bak"), overwrite = true) }
        }
        val expected = snapshot(cfg)
        ConfigStore.writeAtomicPublic(f, expected)
        // writeAtomicPublic 吞异常；写后必须确认文件真实落地且内容一致，否则恢复上一版。
        if (!f.exists() || f.length() == 0L || runCatching { f.readText() }.getOrNull() != expected) {
            restoreBackup(f)
            false
        } else {
            true
        }
    } catch (_: Exception) {
        false
    }

    /** 读取配置文件，并把当前的服务器节点/订阅带回去，得到可直接使用的完整配置。 */
    fun loadInto(context: Context, name: String, current: AppConfig): AppConfig? = try {
        val text = file(context, name).readText()
        val parsed = ConfigFile.fromExternal(text, current) ?: return null
        parsed.toAppConfig(current)
    } catch (_: Exception) {
        null
    }

    /** 手动回退到最近一次保存前的 .bak；没有备份则返回 false。 */
    fun restore(context: Context, name: String): Boolean = try {
        val f = file(context, sanitize(name))
        restoreBackup(f)
    } catch (_: Exception) {
        false
    }

    fun hasBackup(context: Context, name: String): Boolean {
        val f = file(context, sanitize(name))
        return backupFile(f) != null
    }

    private fun backupFile(f: File): File? = sequenceOf(
        File(f.parentFile, f.name + ".bak"),
        File(f.parentFile, f.name + ".legacy.bak"),
    ).firstOrNull { it.exists() && it.length() > 0L }

    private fun restoreBackup(f: File): Boolean {
        val backup = backupFile(f) ?: return false
        return runCatching {
            backup.copyTo(f, overwrite = true)
            true
        }.getOrDefault(false)
    }

    /**
     * 2.2 一次性幂等迁移：旧版 .conf 是扁平 AppConfig JSON，缺 general 分区。
     * - 已有 general：跳过，不覆盖用户后来的修改
     * - 旧格式：以当前全局设置为底，旧文件已有键覆盖，再写成新格式
     * - default.conf 不存在时用当前全局设置创建
     */
    fun migrateLegacy(context: Context, current: AppConfig): ConfigFileMigration.Result =
        ConfigFileMigration.migrate(dir(context), current)

    fun list(context: Context): List<FileInfo> = list(context, activeName(context))

    fun list(context: Context, active: String): List<FileInfo> {
        val files = dir(context).listFiles { f -> f.isFile && f.name.endsWith(".conf") } ?: return emptyList()
        return files.map { f ->
            FileInfo(
                name = f.name,
                size = f.length(),
                modified = f.lastModified(),
                active = f.name == active,
                isDefault = f.name == DEFAULT_NAME,
            )
        }.sortedWith(compareByDescending<FileInfo> { it.isDefault }.thenByDescending { it.modified })
    }

    fun exists(context: Context, name: String): Boolean = file(context, sanitize(name)).exists()

    fun ensureDefault(context: Context, cfg: AppConfig) {
        if (!exists(context, DEFAULT_NAME)) save(context, DEFAULT_NAME, cfg)
    }

    fun create(context: Context, name: String, cfg: AppConfig): Boolean {
        val n = sanitize(name)
        if (exists(context, n)) return false
        return save(context, n, cfg)
    }

    fun delete(context: Context, name: String): Boolean {
        if (name == DEFAULT_NAME) return false
        return file(context, sanitize(name)).delete()
    }

    fun exportText(context: Context, name: String): String? = try {
        file(context, sanitize(name)).readText()
    } catch (_: Exception) {
        null
    }

    /** 设置变化时顺带刷新当前配置文件，避免设置改了但 .conf 还是旧的。 */
    fun saveIfActive(context: Context, cfg: AppConfig) {
        val name = activeName(context)
        if (exists(context, name)) save(context, name, cfg)
    }

    fun sanitize(raw: String): String {
        val base = raw.trim().ifBlank { "未命名.conf" }
        val cleaned = base.replace(Regex("[\\\\/:*?\"<>|]"), "_")
        return if (cleaned.endsWith(".conf")) cleaned else "$cleaned.conf"
    }
}
