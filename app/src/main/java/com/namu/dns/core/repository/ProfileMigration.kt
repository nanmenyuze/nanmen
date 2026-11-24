package com.namu.dns.core.repository

import android.content.Context
import com.namu.dns.AppConfig
import com.namu.dns.core.config.ConfigFile
import com.namu.dns.core.config.GroupValidator
import org.json.JSONObject
import java.io.File
import java.io.FileFilter

data class ProfileMigrationItem(
    val profile: String,
    val changed: Boolean,
    val ok: Boolean,
    val groupCount: Int,
    val selectionCount: Int,
    val message: String = "",
)

data class ProfileMigrationReport(
    val applied: Boolean = false,
    val items: List<ProfileMigrationItem> = emptyList(),
    val backupDir: String = "",
    val rolledBack: Boolean = false,
) {
    val ok: Boolean get() = items.all { it.ok }
    val changedCount: Int get() = items.count { it.changed }
    fun summary(): String = buildString {
        append(if (applied) "迁移已应用" else "迁移预演")
        append("：")
        append("${items.count { it.ok }}/${items.size} 份 Profile 可迁移")
        if (changedCount > 0) append("，$changedCount 份待写入")
        val bad = items.filterNot { it.ok }
        if (bad.isNotEmpty()) append("，失败：").append(bad.joinToString("；") { "${it.profile}(${it.message})" })
    }
}

/**
 * S2：2.9 → 3.0 Profile 的无损迁移。
 *
 * 只做一件事：把旧的设备全局 groupSelections 复制进每份 .conf，并把版本升到 4。
 * 节点/订阅仍在设备侧；组仍只在各自 Profile 内解析。
 * 所有写盘前先 dry-run，写盘时保留 .pre3.bak，可整批回滚。
 */
object ProfileMigration {
    private const val MANIFEST = ".profile-migration-v4.json"

    fun dryRun(context: Context, fallback: AppConfig): ProfileMigrationReport =
        run(context.filesDir, fallback, apply = false)

    fun apply(context: Context, fallback: AppConfig): ProfileMigrationReport =
        run(context.filesDir, fallback, apply = true)

    fun dryRun(filesDir: File, fallback: AppConfig): ProfileMigrationReport =
        run(filesDir, fallback, apply = false)

    fun apply(filesDir: File, fallback: AppConfig): ProfileMigrationReport =
        run(filesDir, fallback, apply = true)

    fun run(filesDir: File, fallback: AppConfig, apply: Boolean): ProfileMigrationReport {
        val dir = File(filesDir, "configs")
        val files: Array<File> = dir.listFiles(FileFilter { f -> f.isFile && f.name.endsWith(".conf") }) ?: emptyArray()
        val items = mutableListOf<ProfileMigrationItem>()
        val plans = mutableListOf<Triple<File, ConfigFile, String>>()
        files.forEach { f ->
            val text = runCatching { f.readText() }.getOrNull()
            if (text.isNullOrBlank()) {
                items += ProfileMigrationItem(profile = f.name, changed = false, ok = false, groupCount = 0, selectionCount = 0, message = "无法读取")
                return@forEach
            }
            val cfg = ConfigFile.fromExternal(text, fallback)
            if (cfg == null) {
                items += ProfileMigrationItem(profile = f.name, changed = false, ok = false, groupCount = 0, selectionCount = 0, message = "解析失败")
                return@forEach
            }
            val root = runCatching { JSONObject(text) }.getOrNull()
            val missingSelections = root?.let { !it.has("groupSelections") || it.isNull("groupSelections") } ?: true
            val next = if (missingSelections) {
                cfg.copy(groupSelections = cfg.groupSelections ?: fallback.groupSelections)
            } else cfg
            val app = next.toAppConfig(fallback)
            val validation = GroupValidator.validate(f.name, app)
            val changed = missingSelections || cfg.modelVersion < ConfigFile.CURRENT_VERSION
            if (!validation.ok) {
                items += ProfileMigrationItem(
                    profile = f.name,
                    changed = changed,
                    ok = false,
                    groupCount = app.proxyGroups.size,
                    selectionCount = app.groupSelections.size,
                    message = validation.errors.joinToString("；") { it.message },
                )
                return@forEach
            }
            plans += Triple(f, next, text)
            items += ProfileMigrationItem(
                profile = f.name,
                changed = changed,
                ok = true,
                groupCount = app.proxyGroups.size,
                selectionCount = app.groupSelections.size,
                message = if (changed) "补齐 Profile 组选择/版本" else "已是最新",
            )
        }
        val backupDir = File(dir, "profile-migration-backup")
        if (apply && items.any { it.ok && it.changed }) {
            backupDir.mkdirs()
            val manifest = JSONObject().apply { put("version", 4); put("createdAt", System.currentTimeMillis()) }
            val names = mutableListOf<String>()
            plans.forEach { (f, next, _) ->
                // 只在本次确实需要改写的 Profile 上备份；备份不覆盖已有文件。
                val backup = File(backupDir, f.name)
                if (!backup.exists()) runCatching { f.copyTo(backup, overwrite = false) }
                val written = writeRaw(f, next.toJson())
                if (!written) {
                    items += ProfileMigrationItem(profile = f.name, changed = true, ok = false, groupCount = 0, selectionCount = 0, message = "写入失败，已保留备份")
                } else {
                    names += f.name
                }
            }
            manifest.put("profiles", names)
            runCatching { File(dir, MANIFEST).writeText(manifest.toString()) }
        }
        return ProfileMigrationReport(
            applied = apply,
            items = items,
            backupDir = backupDir.absolutePath,
        )
    }

    /** 原子写入；测试可直接传临时目录，生产仍走 ConfigFileStore 的路径规则。 */
    private fun writeRaw(target: File, text: String): Boolean = try {
        JSONObject(text)
        target.parentFile?.mkdirs()
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeText(text)
        if (target.exists()) target.delete()
        tmp.renameTo(target)
        target.exists() && target.length() > 0L && target.readText() == text
    } catch (_: Exception) {
        false
    }

    /** 回滚到迁移前；只恢复清单里记录过的 Profile，不碰用户后来新建的配置。 */
    fun rollback(context: Context): ProfileMigrationReport = rollback(context.filesDir)

    fun rollback(filesDir: File): ProfileMigrationReport {
        val dir = File(filesDir, "configs")
        val manifestFile = File(dir, MANIFEST)
        val manifest = runCatching { JSONObject(manifestFile.readText()) }.getOrNull()
            ?: return ProfileMigrationReport(rolledBack = false)
        val names = manifest.optJSONArray("profiles")?.let { a ->
            (0 until a.length()).mapNotNull { i -> a.optString(i, "").takeIf { it.isNotBlank() } }
        } ?: emptyList()
        val backupDir = File(dir, "profile-migration-backup")
        val items = names.map { name ->
            val backup = File(backupDir, name)
            val ok = backup.exists() && runCatching { backup.copyTo(File(dir, name), overwrite = true) }.isSuccess
            ProfileMigrationItem(profile = name, changed = true, ok = ok, groupCount = 0, selectionCount = 0, message = if (ok) "已回滚" else "备份缺失")
        }
        val allOk = items.isNotEmpty() && items.all { it.ok }
        // 回滚完成后删清单，避免下次启动把同一批备份再覆盖一遍当前配置。
        if (allOk) runCatching { manifestFile.delete() }
        return ProfileMigrationReport(applied = false, items = items, backupDir = backupDir.absolutePath, rolledBack = allOk)
    }

    /** 迁移后的语义等价检查：忽略 version 与仅用于迁移的 groupSelections 后比较。 */
    fun semanticEqual(before: String, after: String): Boolean {
        fun sorted(value: Any?): String = when (value) {
            null -> "null"
            is JSONObject -> value.keys().asSequence().sorted().joinToString(",", "{", "}") { k -> "$k:${sorted(value.opt(k))}" }
            is org.json.JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { i -> sorted(value.opt(i)) }
            is String -> org.json.JSONObject.quote(value)
            else -> value.toString()
        }
        fun normalize(text: String): String? {
            val root = runCatching { JSONObject(text) }.getOrNull() ?: return null
            root.remove("version")
            root.remove("groupSelections")
            root.remove("configUnknown")
            return sorted(root)
        }
        val a = normalize(before) ?: return false
        val b = normalize(after) ?: return false
        return a == b
    }
}
