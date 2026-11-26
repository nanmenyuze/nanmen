package com.namu.dns

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.json.JSONObject
import java.io.File

/**
 * 3.0.18 统一应用入口：DNS 配置切换、模块启停/排序/同步结果都走这里。
 *
 * - 服务确认前显示「应用中」；
 * - 成功后更新生效状态并冻结一份「上一份可用」壳快照；
 * - 失败时恢复上一份可用配置与模块规则（内核回滚由服务负责）。
 */
object ApplyCoordinator {
    data class ApplyResult(val ok: Boolean, val message: String, val at: Long)

    var applying by mutableStateOf(false)
        private set
    var lastResult by mutableStateOf<ApplyResult?>(null)
        private set

    /** 内核最近一次确认生效的完整配置 JSON；诊断据此显示实际状态。 */
    var lastAppliedJson by mutableStateOf<String?>(null)
        private set

    private data class ShellSnapshot(
        val globalJson: String,
        val profileName: String,
        val profileFileText: String?,
        val settingsJson: String,
        val aggregates: Map<String, String>,
    )

    private var lastGoodShell: ShellSnapshot? = null

    private fun captureShell(context: Context): ShellSnapshot {
        val dir = context.filesDir
        val name = ConfigFileStore.activeName(context)
        val profileFile = File(File(dir, "configs"), name)
        return ShellSnapshot(
            globalJson = runCatching { GlobalRuleStore.file(context).readText() }.getOrDefault(""),
            profileName = name,
            profileFileText = runCatching { profileFile.readText() }.getOrNull(),
            settingsJson = App.container.settings.current().toJson().toString(),
            aggregates = listOf("modules_block.txt", "modules_rules.json", "modules_mitm.json").associateWith { n ->
                runCatching { File(dir, n).readText() }.getOrDefault("")
            },
        )
    }

    /** 唯一应用入口：置「应用中」后交给服务；未连接时落盘即视为生效待连接。 */
    fun requestApply(context: Context, reason: String) {
        if (!NamuVpnService.isRunning()) {
            applying = false
            lastResult = ApplyResult(true, "已保存（$reason），连接后生效", System.currentTimeMillis())
            lastGoodShell = captureShell(context)
            return
        }
        applying = true
        NamuVpnService.reload(context)
    }

    /** 配置方案切换：同样走统一应用状态。 */
    fun requestProfileSwitch(context: Context, target: String, oldName: String, oldConfig: AppConfig) {
        if (!NamuVpnService.isRunning()) {
            applying = false
            lastResult = ApplyResult(true, "已切换方案（连接后生效）", System.currentTimeMillis())
            lastGoodShell = captureShell(context)
            return
        }
        applying = true
        NamuVpnService.reloadProfile(context, target, oldName, oldConfig)
    }

    /** 服务热重载/重启确认后回调；失败恢复上一份可用壳状态。 */
    fun onServiceResult(context: Context, ok: Boolean, message: String, appliedJson: String?) {
        applying = false
        lastResult = ApplyResult(ok, message, System.currentTimeMillis())
        if (ok) {
            if (appliedJson != null) lastAppliedJson = appliedJson
            lastGoodShell = captureShell(context)
        } else {
            restoreShell(context)
        }
    }

    private fun restoreShell(context: Context) {
        val snap = lastGoodShell ?: return
        runCatching {
            ConfigStore.writeAtomicPublic(GlobalRuleStore.file(context), snap.globalJson)
            snap.aggregates.forEach { (n, text) ->
                ConfigStore.writeAtomicPublic(File(context.filesDir, n), text)
            }
            snap.profileFileText?.let { text ->
                ConfigStore.writeAtomicPublic(File(File(context.filesDir, "configs"), snap.profileName), text)
            }
            GlobalRuleStore.load(context)
            runCatching {
                App.container.settings.restoreSilent(AppConfig.fromJson(snap.settingsJson))
            }
        }
    }

    /** 诊断摘要：内核实际生效的 DNS 配置 / 已加载模块与规则数 / 最近应用结果。 */
    fun kernelStateSummary(context: Context): List<String> {
        val out = mutableListOf<String>()
        val json = runCatching { JSONObject(lastAppliedJson ?: "") }.getOrNull()
        if (json != null && json.length() > 0) {
            val dns = json.optJSONObject("dns")
            out.add("生效 DNS 上游：${dns?.optString("upstream").orEmpty().ifBlank { "（未连接）" }}")
            out.add("生效 fallback：${dns?.optString("fallback").orEmpty().ifBlank { "关闭" }}")
            out.add("生效 hijack：${dns?.optBoolean("hijack", true)}，block_aaaa：${dns?.optBoolean("block_aaaa", false)}")
            out.add("生效 ipv6：${json.optBoolean("ipv6", true)}，prefer_ipv6：${json.optBoolean("prefer_ipv6", false)}")
            out.add("生效 Fake-IP 排除：${dns?.optJSONArray("fake_ip_filter")?.length() ?: 0} 条，按域名策略：${dns?.optJSONArray("policies")?.length() ?: 0} 条")
            out.add("内核已加载分流规则：${json.optJSONArray("rules")?.length() ?: 0} 条")
        } else {
            out.add("内核生效配置：尚未连接或尚未应用")
        }
        val g = GlobalRuleStore.state
        out.add("启用模块：${GlobalRuleStore.enabledModules().size} 个，启用规则集：${GlobalRuleStore.enabledRuleSets().size} 个")
        out.add("本地规则：${g.localRules.size} 条（启用=${g.localRulesEnabled}），本地拦截域名：${g.localAds.size} 条")
        out.add("本地重写与脚本：${GlobalRuleStore.mitmCount(g.localMitm)} 条（启用=${g.localMitmEnabled}），来源方案重写项：${g.extraMitm.size} 个")
        val r = lastResult
        out.add(
            if (r == null) "最近应用：无记录"
            else "最近应用：${if (r.ok) "成功" else "失败"} · ${r.message} · ${java.text.SimpleDateFormat("MM-dd HH:mm:ss", java.util.Locale.US).format(java.util.Date(r.at))}",
        )
        if (applying) out.add("当前状态：应用中")
        return out
    }
}