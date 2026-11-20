package com.namu.dns

import com.namu.dns.core.config.ConfigFile
import org.json.JSONObject
import java.io.File

/**
 * 配置文件格式迁移 + 崩溃恢复。只负责磁盘上的 .conf 文件，不碰 DataStore 里的全局设置。
 *
 * 规则：
 * - 带 general 且 version >= CURRENT 的文件：跳过，不覆盖用户后来的修改
 * - 旧扁平 JSON / 缺 version 的 2.x 文件：先备份为 `.legacy.bak`，再迁移到当前模型
 * - 写临时文件后原子替换；替换/校验失败时从备份恢复
 * - 启动时先 recover：清理残留 .tmp，目标损坏且备份可用时回退
 */
object ConfigFileMigration {
    data class Result(
        val scanned: Int,
        val migrated: Int,
        val skipped: Int,
        val failed: Int,
        val createdDefault: Boolean,
        val recovered: Int = 0,
        val restored: Int = 0,
    )

    fun migrate(dir: File, current: AppConfig): Result {
        if (!dir.exists()) dir.mkdirs()
        val recovery = recover(dir)
        var scanned = 0
        var migrated = 0
        var skipped = 0
        var failed = 0
        var createdDefault = false

        val defaultFile = File(dir, ConfigFileStore.DEFAULT_NAME)
        if (!defaultFile.exists()) {
            if (writeAtomic(defaultFile, ConfigFile.fromAppConfig(current).toJson(), backup = null)) {
                createdDefault = true
                scanned++
                migrated++
            } else {
                failed++
            }
        }

        val files: Array<File> = dir.listFiles { f: File -> f.isFile && f.name.endsWith(".conf") } ?: emptyArray()
        files.sortedBy { it.name }.forEach { f: File ->
            // 新建的 default.conf 已在上面计入 migrated，这里不再作为“跳过”重复统计。
            if (createdDefault && f.name == ConfigFileStore.DEFAULT_NAME) return@forEach
            scanned++
            val text = runCatching { f.readText() }.getOrElse {
                failed++
                return@forEach
            }
            val root = try {
                JSONObject(text)
            } catch (_: Exception) {
                failed++
                return@forEach
            }
            val alreadyCurrent = root.has("general") &&
                root.optInt("version", 1) >= ConfigFile.CURRENT_VERSION
            if (alreadyCurrent) {
                skipped++
                return@forEach
            }

            // 迁移前留一份旧格式备份，重复迁移不覆盖它。
            val backup = File(f.parentFile, f.name + ".legacy.bak")
            if (!backup.exists()) {
                runCatching { f.copyTo(backup) }
            }
            val converted = runCatching {
                val cfg = if (root.has("general")) {
                    ConfigFile.fromExternal(text, current)
                } else {
                    ConfigFile.fromLegacyJson(text, current)
                }
                cfg?.copy(modelVersion = ConfigFile.CURRENT_VERSION)?.toJson()
            }.getOrNull()
            if (converted == null) {
                failed++
                return@forEach
            }
            if (writeAtomic(f, converted, backup)) {
                migrated++
            } else {
                failed++
            }
        }

        return Result(
            scanned = scanned,
            migrated = migrated,
            skipped = skipped,
            failed = failed,
            createdDefault = createdDefault,
            recovered = recovery.recovered,
            restored = recovery.restored,
        )
    }

    data class RecoveryResult(val recovered: Int, val restored: Int)

    /**
     * 启动恢复：处理中断写入留下的 `.tmp`，以及目标被截断但备份还在的情况。
     * 只接受合法 JSON，不用 ConfigFile.fromJson 的“失败返回空对象”兜底。
     */
    fun recover(dir: File): RecoveryResult {
        if (!dir.exists()) return RecoveryResult(0, 0)
        var recovered = 0
        var restored = 0
        val confFiles = dir.listFiles { f: File -> f.isFile && f.name.endsWith(".conf") } ?: emptyArray()
        val backupFiles = dir.listFiles { f: File -> f.isFile && f.name.endsWith(".legacy.bak") } ?: emptyArray()
        val tmpFiles = dir.listFiles { f: File -> f.isFile && f.name.endsWith(".conf.tmp") } ?: emptyArray()
        val targets = (confFiles.toList() + backupFiles.map {
            val base = it.name.removeSuffix(".legacy.bak")
            File(dir, if (base.endsWith(".conf")) base else "$base.conf")
        } + tmpFiles.map {
            File(dir, it.name.removeSuffix(".tmp"))
        }).distinctBy { it.name }
        targets.forEach { f ->
            val tmp = File(f.parentFile, f.name + ".tmp")
            val backup = File(f.parentFile, f.name + ".legacy.bak")
            val validTarget = isValidJson(f)
            if (validTarget) {
                // 已有合法目标：残留 tmp 是没完成的写入，丢弃即可。
                if (tmp.exists() && tmp.delete()) recovered++
                return@forEach
            }
            if (!f.exists() && tmp.exists() && isValidJson(tmp)) {
                if (tmp.renameTo(f)) recovered++
                return@forEach
            }
            if (backup.exists() && isValidJson(backup)) {
                runCatching { backup.copyTo(f, overwrite = true) }
                restored++
                if (tmp.exists()) tmp.delete()
            } else if (tmp.exists() && isValidJson(tmp)) {
                runCatching { tmp.copyTo(f, overwrite = true) }
                recovered++
                tmp.delete()
            }
        }
        return RecoveryResult(recovered, restored)
    }

    private fun isValidJson(file: File): Boolean {
        if (!file.exists() || file.length() == 0L) return false
        return runCatching {
            JSONObject(file.readText())
            true
        }.getOrDefault(false)
    }

    private fun writeAtomic(file: File, text: String, backup: File?): Boolean {
        val parent = file.parentFile ?: return false
        if (!parent.exists()) parent.mkdirs()
        val tmp = File(parent, file.name + ".tmp")
        return runCatching {
            tmp.writeText(text)
            // 备份由 migrate 在写入前保留，成功写入后也不删除，供用户手动回退。
            if (!tmp.renameTo(file)) {
                tmp.copyTo(file, overwrite = true)
                tmp.delete()
            }
            // 写后校验：不合法则回滚旧文件。
            if (!isValidJson(file)) {
                if (backup != null && backup.exists() && isValidJson(backup)) {
                    backup.copyTo(file, overwrite = true)
                }
                false
            } else {
                true
            }
        }.getOrDefault(false)
    }
}
