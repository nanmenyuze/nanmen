package com.namu.dns

import android.content.Context
import com.namu.dns.core.config.ConfigFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * M7 完整备份：应用配置（含节点、订阅、策略组、模块清单） + 所有本地 .conf 原文。
 *
 * 备份包含节点密码/UUID、订阅地址和模块 URL，属于敏感数据；只写到用户选择的本地文件，
 * 不上传；恢复前整包校验，避免半包覆盖。
 */
object M7Backup {
    const val SCHEMA = 1
    private const val MAX_BYTES = 32 * 1024 * 1024

    data class BackupInfo(
        val appVersion: String,
        val activeConfig: String,
        val configVersion: Int,
        val files: Map<String, String>,
        val config: AppConfig,
    )

    data class RestoreResult(
        val files: Int,
        val nodes: Int,
        val activeConfig: String,
        val warnings: List<String> = emptyList(),
    )

    /** 生成完整 JSON 备份；调用方负责用 SAF/MediaStore 落盘。 */
    fun exportJson(context: Context): String {
        val cfg = App.container.settings.current()
        val files = ConfigFileStore.list(context).mapNotNull { info ->
            ConfigFileStore.exportText(context, info.name)?.let { info.name to it }
        }.toMap()
        return JSONObject().apply {
            put("schema", SCHEMA)
            put("createdAt", System.currentTimeMillis())
            put("appVersion", BuildConfig.VERSION_NAME)
            put("versionCode", BuildConfig.VERSION_CODE)
            put("activeConfig", ConfigFileStore.activeName(context))
            put("configVersion", ConfigFile.CURRENT_VERSION)
            put("app", cfg.toJson())
            put("configFiles", JSONObject().apply {
                files.forEach { (name, text) -> put(name, text) }
            })
        }.toString(2)
    }

    suspend fun export(context: Context): String = withContext(Dispatchers.IO) {
        val ts = java.text.SimpleDateFormat("yyyyMMdd-HHmmss", java.util.Locale.US)
            .format(java.util.Date())
        Actions.exportText(
            context,
            "南门DNS-备份-$ts.json",
            exportJson(context),
            mimeType = "application/json",
        )
    }

    /** 只校验和解析，不落盘；单元测试与恢复预览共用。 */
    fun inspect(raw: String): BackupInfo {
        require(raw.toByteArray().size <= MAX_BYTES) { "备份文件超过 32 MiB" }
        val root = JSONObject(raw)
        require(root.optInt("schema", 0) == SCHEMA) {
            "不是南门DNS M7 备份（schema=${root.optInt("schema", 0)}）"
        }
        val app = root.optJSONObject("app") ?: throw IllegalArgumentException("备份缺少 app 配置")
        require(app.length() > 0) { "app 配置为空" }
        val cfg = AppConfig.fromJson(app.toString())
        val filesObj = root.optJSONObject("configFiles")
        val files = mutableMapOf<String, String>()
        if (filesObj != null) {
            filesObj.keys().forEach { name ->
                val text = filesObj.optString(name, "")
                require(text.isNotBlank()) { "配置文件 $name 为空" }
                runCatching { JSONObject(text) }.getOrElse {
                    throw IllegalArgumentException("配置文件 $name 不是合法 JSON")
                }
                files[ConfigFileStore.sanitize(name)] = text
            }
        }
        val requestedActive = root.optString("activeConfig", ConfigFileStore.DEFAULT_NAME)
        return BackupInfo(
            appVersion = root.optString("appVersion", "?"),
            activeConfig = ConfigFileStore.sanitize(requestedActive),
            configVersion = root.optInt("configVersion", ConfigFile.CURRENT_VERSION),
            files = files,
            config = cfg,
        )
    }

    /**
     * 校验并恢复。会先验证所有 .conf 都是合法 JSON，再写入；任何一项失败都不写入。
     * 恢复后由调用方触发内核重载。
     */
    fun restore(context: Context, raw: String): RestoreResult {
        val info = inspect(raw)
        val active = info.activeConfig
        val warnings = mutableListOf<String>()
        if (info.files.isNotEmpty() && active !in info.files) {
            warnings += "备份中没有当前配置 $active，将新建为当前配置"
        }

        // 校验完再落盘，避免第二份文件失败时前半包已覆盖。
        info.files.forEach { (name, text) ->
            check(ConfigFileStore.writeRaw(context, name, text)) { "写入 $name 失败" }
        }
        ConfigFileStore.setActive(context, active)
        App.container.settings.set(info.config)
        // 让 active .conf 与恢复后的内存配置保持一致；节点/订阅不写入 .conf。
        if (!ConfigFileStore.exists(context, active)) {
            check(ConfigFileStore.save(context, active, info.config)) { "创建 $active 失败" }
        }
        ConfigStore.rebuildModules(context, info.config)
        return RestoreResult(
            files = info.files.size,
            nodes = info.config.nodes.size,
            activeConfig = active,
            warnings = warnings,
        )
    }
}
