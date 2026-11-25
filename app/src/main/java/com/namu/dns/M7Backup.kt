package com.namu.dns

import android.content.Context
import com.namu.dns.core.config.ConfigFile
import java.io.File
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
        /** 本地导入/缓存的模块正文；key 为 files/modules 下的文件名。 */
        val moduleFiles: Map<String, String> = emptyMap(),
        /** script-path 正文缓存；key 为 files/scripts 下的文件名。 */
        val scriptFiles: Map<String, String> = emptyMap(),
        /** 模块规则集缓存；key 为 files 下的 ruleset_*.txt。 */
        val ruleSetFiles: Map<String, String> = emptyMap(),
        val profileNodes: Map<String, List<NodeInfo>> = emptyMap(),
    )

    data class RestoreResult(
        val files: Int,
        val nodes: Int,
        val activeConfig: String,
        /** 当前配置中正文可用、能参与 rebuildModules 的启用模块数。 */
        val modules: Int = 0,
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
            // 本地导入的模块正文不在 .conf 里；只备模块清单会让新机恢复后「有模块但没规则」。
            put("profileNodes", JSONObject().apply {
                files.keys.forEach { name -> ConfigFileStore.exportImportedNodes(context, name)?.let { put(name, it) } }
            })
            put("moduleFiles", readFiles(File(context.filesDir, "modules"), MODULE_FILE_RE))
            put("scriptFiles", readFiles(File(context.filesDir, "scripts"), SCRIPT_FILE_RE))
            put("ruleSetFiles", readFiles(context.filesDir, RULESET_FILE_RE))
        }.toString(2)
    }

    private val MODULE_FILE_RE = Regex("""module_[a-z0-9_-]{1,40}\.sgmodule""")
    private val SCRIPT_FILE_RE = Regex("""script_[0-9a-f]{32}\.js""")
    private val RULESET_FILE_RE = Regex("""ruleset_[0-9a-f]{16}\.txt""")

    /** 只备份符合命名规则的文件，恢复时再校验一次，拒绝路径分隔符/..。 */
    private fun readFiles(dir: File, nameRe: Regex): JSONObject {
        val out = JSONObject()
        dir.listFiles()?.forEach { f ->
            if (f.isFile && nameRe.matches(f.name) && f.length() > 0) {
                runCatching { f.readText() }.getOrNull()?.let { out.put(f.name, it) }
            }
        }
        return out
    }

    private fun readFiles(root: JSONObject?, key: String, nameRe: Regex): Map<String, String> {
        val obj = root?.optJSONObject(key) ?: return emptyMap()
        val out = linkedMapOf<String, String>()
        obj.keys().forEach { name ->
            require(nameRe.matches(name)) { "备份包含非法文件名 $name" }
            val text = obj.optString(name, "")
            require(text.isNotBlank()) { "备份文件 $name 为空" }
            out[name] = text
        }
        return out
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
        val profileNodes = linkedMapOf<String, List<NodeInfo>>()
        root.optJSONObject("profileNodes")?.let { all ->
            all.keys().forEach { name ->
                require(name in files) { "备用节点没有对应配置 $name" }
                val nodes = all.getJSONArray(name)
                profileNodes[name] = List(nodes.length()) { NodeInfo.fromJson(nodes.getJSONObject(it)) }
            }
        }
        val requestedActive = root.optString("activeConfig", ConfigFileStore.DEFAULT_NAME)
        return BackupInfo(
            appVersion = root.optString("appVersion", "?"),
            activeConfig = ConfigFileStore.sanitize(requestedActive),
            configVersion = root.optInt("configVersion", ConfigFile.CURRENT_VERSION),
            files = files,
            config = cfg,
            moduleFiles = readFiles(root, "moduleFiles", MODULE_FILE_RE),
            scriptFiles = readFiles(root, "scriptFiles", SCRIPT_FILE_RE),
            ruleSetFiles = readFiles(root, "ruleSetFiles", RULESET_FILE_RE),
            profileNodes = profileNodes,
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
            val profileNodes = info.profileNodes[name].orEmpty()
            if (profileNodes.isEmpty()) ConfigFileStore.clearImportedNodes(context, name)
            else check(ConfigFileStore.saveImportedNodes(context, name, profileNodes)) { "写入 $name 的备用节点失败" }
        }
        // 模块正文与依赖先恢复；rebuildModules 只读这些文件，不联网。
        var restoredAssets = 0
        info.moduleFiles.forEach { (name, text) ->
            check(writeFile(File(File(context.filesDir, "modules"), name), text)) { "写入模块 $name 失败" }
            restoredAssets++
        }
        info.scriptFiles.forEach { (name, text) ->
            check(writeFile(File(File(context.filesDir, "scripts"), name), text)) { "写入脚本 $name 失败" }
            restoredAssets++
        }
        info.ruleSetFiles.forEach { (name, text) ->
            check(writeFile(File(context.filesDir, name), text)) { "写入规则集 $name 失败" }
            restoredAssets++
        }
        ConfigFileStore.setActive(context, active)
        App.container.settings.set(info.config)
        // 让 active .conf 与恢复后的内存配置保持一致；节点/订阅不写入 .conf。
        if (!ConfigFileStore.exists(context, active)) {
            check(ConfigFileStore.save(context, active, info.config)) { "创建 $active 失败" }
        }
        ConfigStore.rebuildModules(context, info.config)
        val enabledModules = info.config.moduleSources.filter { it.enabled }
        val liveModules = enabledModules.count {
            ConfigStore.moduleFile(context, it.id).let { f -> f.exists() && f.length() > 0L }
        }
        val missing = enabledModules.filterNot {
            ConfigStore.moduleFile(context, it.id).let { f -> f.exists() && f.length() > 0L }
        }
        missing.take(8).forEach { warnings += "模块 ${it.name.ifBlank { it.id }} 缺正文，未生效" }
        // 规则集/脚本依赖缺失时 rebuildModules 会写进 modules_mitm.json；恢复结果一并带出。
        runCatching {
            val mitm = JSONObject(ConfigStore.moduleMitmFile(context).readText())
            for (key in listOf("ruleSetIssues", "scriptIssues")) {
                val arr = mitm.optJSONArray(key) ?: continue
                for (i in 0 until minOf(arr.length(), 8)) {
                    val issue = arr.optString(i, "")
                    if (issue.isNotBlank()) warnings += issue
                }
            }
        }
        return RestoreResult(
            files = info.files.size + restoredAssets,
            nodes = info.config.nodes.size,
            activeConfig = active,
            modules = liveModules,
            warnings = warnings.distinct(),
        )
    }

    private fun writeFile(file: File, text: String): Boolean {
        file.parentFile?.mkdirs()
        ConfigStore.writeAtomicPublic(file, text)
        return runCatching { file.exists() && file.length() > 0L && file.readText() == text }
            .getOrDefault(false)
    }
}
