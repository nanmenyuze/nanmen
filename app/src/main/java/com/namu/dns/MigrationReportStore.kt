package com.namu.dns

import android.content.Context
import com.namu.dns.core.config.ConfigFile
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * M7 启动维护报告：记录 .conf 版本迁移和崩溃恢复结果。
 *
 * 只记录计数和文件名，不写节点密码、订阅地址或规则正文。
 */
object MigrationReportStore {
    private const val PREFS = "namu_maintenance"
    private const val KEY = "last_migration"

    fun record(context: Context, result: ConfigFileMigration.Result) {
        val report = JSONObject().apply {
            put("at", System.currentTimeMillis())
            put("scanned", result.scanned)
            put("migrated", result.migrated)
            put("skipped", result.skipped)
            put("failed", result.failed)
            put("createdDefault", result.createdDefault)
            put("recovered", result.recovered)
            put("restored", result.restored)
            put("configVersion", ConfigFile.CURRENT_VERSION)
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY, report.toString()).apply()
    }

    fun read(context: Context): JSONObject? = runCatching {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY, null) ?: return null
        JSONObject(raw)
    }.getOrNull()

    fun summary(context: Context): String {
        val r = read(context) ?: return "本次启动未记录迁移（首次安装或尚未启动）"
        val at = r.optLong("at")
        val time = if (at > 0) {
            SimpleDateFormat("MM-dd HH:mm", Locale.US).format(Date(at))
        } else {
            "未知时间"
        }
        val migrated = r.optInt("migrated")
        val skipped = r.optInt("skipped")
        val failed = r.optInt("failed")
        val recovered = r.optInt("recovered")
        val restored = r.optInt("restored")
        return when {
            failed > 0 -> "$time · $failed 个配置迁移失败，需检查备份"
            recovered > 0 || restored > 0 -> "$time · 恢复 $recovered 个临时文件、回退 $restored 个配置"
            migrated > 0 -> "$time · 已迁移 $migrated 个配置（跳过 $skipped 个已是最新）"
            else -> "$time · 配置均为 v${r.optInt("configVersion", ConfigFile.CURRENT_VERSION)}，无需迁移"
        }
    }
}
