package com.namu.dns.ui.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.namu.dns.Actions
import com.namu.dns.MitmManager
import com.namu.dns.RootCaManager
import com.namu.dns.TrustModuleGenerator
import com.namu.dns.core.AppContainer
import com.namu.dns.core.runtime.MessageRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * M2 架构对齐：MITM 页的 busy/CA 状态与证书操作收进 ViewModel，
 * 切页再回来状态不丢（与 HomeViewModel/NodesViewModel 同款）。
 * 所有外部操作经构造注入，JVM 单测可用 fake 完整覆盖（见 MitmViewModelTest）。
 */
class MitmViewModel(
    private val messages: MessageRepository,
    private val caExistsCheck: () -> Boolean,
    private val export: suspend () -> MitmManager.ExportResult,
    private val generateModule: suspend (pemPath: String, systemName: String) -> TrustModuleGenerator.Result,
    private val applyEnabled: suspend (Boolean) -> Unit,
    private val applyHostnames: suspend (List<String>) -> Unit,
    private val applySkip: suspend (List<String>) -> Unit,
    private val applyApps: suspend (String, List<String>) -> Unit,
    private val applyScriptArgs: suspend (com.namu.dns.core.config.ScriptConfig, Map<String, String>) -> Unit = { _, _ -> },
    private val applyPool: suspend (Boolean) -> Unit = {},
    private val exportDirFallback: () -> String = { "" },
    private val caFingerprintCheck: () -> String? = { null },
    private val systemCertCheck: (systemName: String) -> Boolean = { _ -> false },
    private val trustSnapshotCheck: suspend (systemName: String) -> RootCaManager.TrustSnapshot =
        { RootCaManager.TrustSnapshot() },
    private val publishExport: suspend (MitmManager.ExportResult) -> String = { "" },
    private val readInjectionLog: suspend () -> String = { "" },
    private val publishLog: suspend (String) -> String = { "" },
) : ViewModel() {

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    private val _caExists = MutableStateFlow(caExistsCheck())
    val caExists: StateFlow<Boolean> = _caExists.asStateFlow()

    private val _caFingerprint = MutableStateFlow(caFingerprintCheck())
    val caFingerprint: StateFlow<String?> = _caFingerprint.asStateFlow()

    private val _systemCertInstalled = MutableStateFlow(false)
    val systemCertInstalled: StateFlow<Boolean> = _systemCertInstalled.asStateFlow()

    private val _trust = MutableStateFlow(RootCaManager.TrustSnapshot())
    val trust: StateFlow<RootCaManager.TrustSnapshot> = _trust.asStateFlow()

    private var lastSystemName = ""

    /** 页面回到前台时重新核对 CA、指纹与系统证书区，避免状态仍旧。 */
    fun refresh() {
        viewModelScope.launch {
            val exists = withContext(Dispatchers.IO) { caExistsCheck() }
            val fingerprint = withContext(Dispatchers.IO) { caFingerprintCheck() }
            val systemName = if (exists) {
                withContext(Dispatchers.IO) { runCatching { export().systemName }.getOrDefault("") }
            } else {
                ""
            }
            lastSystemName = systemName
            val snapshot = withContext(Dispatchers.IO) {
                if (systemName.isBlank()) {
                    RootCaManager.TrustSnapshot(
                        visibleInSelf = systemCertCheck(systemName),
                        detail = "证书尚未生成或导出，无法核验系统区",
                    )
                } else {
                    runCatching { trustSnapshotCheck(systemName) }
                        .getOrElse { RootCaManager.TrustSnapshot(detail = it.message.orEmpty()) }
                }
            }
            _caExists.value = exists
            _caFingerprint.value = fingerprint
            _trust.value = snapshot
            _systemCertInstalled.value = snapshot.visibleInSelf
        }
    }

    /** 打开前确保 CA 已生成，否则内核无法开始握手；生成失败则不启用。 */
    fun setEnabled(on: Boolean) {
        if (_busy.value) return
        viewModelScope.launch {
            _busy.value = true
            try {
                if (on && !caExistsCheck()) {
                    val r = export()
                    _caExists.value = caExistsCheck()
                    _caFingerprint.value = caFingerprintCheck()
                    lastSystemName = r.systemName
                    if (!r.ok) {
                        messages.show("CA 生成失败：${r.error}")
                        return@launch
                    }
                }
                applyEnabled(on)
            } finally {
                _busy.value = false
            }
        }
    }

    fun saveHostnames(list: List<String>) {
        viewModelScope.launch { applyHostnames(list) }
    }

    fun saveSkip(list: List<String>) {
        viewModelScope.launch { applySkip(list) }
    }

    /** 按 App MITM：all / allow / deny + 包名列表。 */
    fun setApps(mode: String, apps: List<String>) {
        viewModelScope.launch { applyApps(mode, apps) }
    }

    /** 只更新 $argument 注入值；不重建内核、不重编译脚本。 */
    fun setScriptArguments(script: com.namu.dns.core.config.ScriptConfig, values: Map<String, String>) {
        viewModelScope.launch { applyScriptArgs(script, values) }
    }

    /** 灰度开关：MITM 上游连接复用；默认关，切换后热重载只影响新连接。 */
    fun setPoolEnabled(on: Boolean) {
        viewModelScope.launch { applyPool(on) }
    }

    /** generic 仅手动触发；返回启动条数，0 表示没有匹配脚本或 VPN 未运行。 */
    fun triggerGeneric() {
        val n = runCatching { com.namu.dns.NativeCore.nativeTriggerScripts("generic") }.getOrDefault(-1)
        messages.show(
            when {
                n > 0 -> "已触发 $n 条 generic 脚本（后台串行执行）"
                n == 0 -> "没有匹配的 generic 脚本"
                else -> "内核未运行，无法触发脚本"
            },
        )
    }

    /** 导出由 Magisk 管理的系统 CA 模块。 */
    fun generateTrustModule() = withExport { r ->
        val result = generateModule(r.pemPath, r.systemName)
        if (result.ok) {
            _systemCertInstalled.value = systemCertCheck(r.systemName)
            messages.show(
                "模块已导出到 ${result.path}。请在模块管理器中从存储安装，重启后重新核验。",
            )
        } else {
            messages.show("模块生成失败：${result.error}")
        }
    }

    /** 同时导出开机日志和 App 此刻看到的证书状态。 */
    fun exportInjectionLog() {
        if (_busy.value) return
        viewModelScope.launch {
            _busy.value = true
            try {
                val systemName = lastSystemName
                val (log, snapshot) = withContext(Dispatchers.IO) {
                    val log = runCatching { readInjectionLog() }.getOrDefault("")
                    val snapshot = if (systemName.isBlank()) {
                        RootCaManager.TrustSnapshot(detail = "当前未取得 CA 文件名")
                    } else {
                        runCatching { trustSnapshotCheck(systemName) }.getOrElse {
                            RootCaManager.TrustSnapshot(detail = "实时核验异常：${it.javaClass.simpleName}")
                        }
                    }
                    log to snapshot
                }
                val stamp = java.text.SimpleDateFormat("yyyyMMdd-HHmmss", java.util.Locale.US)
                    .format(java.util.Date())
                val report = buildString {
                    appendLine("南门DNS 注入日志 $stamp")
                    appendLine()
                    appendLine(log.ifBlank { "未读到开机注入日志" })
                    appendLine()
                    appendLine("=== 当前 App 核验 ===")
                    appendLine("cert=$systemName")
                    appendLine("root=${snapshot.root.kind}, available=${snapshot.root.available}")
                    appendLine("current_boot=${snapshot.bootId}")
                    appendLine("target=${snapshot.target}")
                    appendLine("module_cert_matches=${snapshot.moduleCertMatches}")
                    appendLine("resolved_state=${RootCaManager.resolveTrustState(_caExists.value, snapshot)}")
                    appendLine("mount_roots=${snapshot.topSources.joinToString(" | ")}")
                    appendLine("conflict_sources=${snapshot.conflictSources.joinToString(" | ")}")
                    appendLine("zygote_count=${snapshot.zygoteChecks.size}")
                    for (check in snapshot.zygoteChecks) {
                        appendLine("${check.process}: ids=${check.directoryIds.joinToString(",")}, " +
                            "mount_matches=${check.ownsTarget}, cert_readable=${check.certificateReadable}, " +
                            "cert_matches=${check.certificateMatches}")
                        for (mount in check.targetMounts) {
                            appendLine("${check.process}: mountinfo=$mount")
                        }
                    }
                    if (snapshot.detail.isNotBlank()) appendLine("detail=${snapshot.detail}")
                }
                val path = runCatching { publishLog(report) }.getOrDefault("")
                messages.show(
                    if (path.isBlank()) "日志导出失败，请稍后重试"
                    else "日志已导出到 $path，可直接打开或分享",
                )
            } finally {
                _busy.value = false
            }
        }
    }


    private suspend fun refreshTrust(systemName: String) {
        if (systemName.isBlank()) return
        val snapshot = withContext(Dispatchers.IO) {
            runCatching { trustSnapshotCheck(systemName) }
                .getOrElse { RootCaManager.TrustSnapshot(detail = it.message.orEmpty()) }
        }
        _trust.value = snapshot
        _systemCertInstalled.value = snapshot.visibleInSelf
    }

    fun exportOnly() = withExport { r ->
        val publicPath = publishExport(r)
        if (publicPath.isNotBlank()) {
            messages.show("已导出到 $publicPath：namu-ca.pem（PEM）/ namu-ca.crt（DER）")
        } else {
            val dir = File(r.derPath).parent ?: exportDirFallback()
            messages.show("已导出到 $dir：namu-ca.pem / namu-ca.crt（DER）")
        }
    }

    private fun withExport(after: suspend (MitmManager.ExportResult) -> Unit) {
        if (_busy.value) return
        viewModelScope.launch {
            _busy.value = true
            try {
                val r = export()
                _caExists.value = caExistsCheck()
                _caFingerprint.value = caFingerprintCheck()
                lastSystemName = r.systemName
                if (r.ok) after(r) else messages.show("证书导出失败：${r.error}")
            } finally {
                _busy.value = false
            }
        }
    }

    companion object {
        fun factory(container: AppContainer, context: Context) = viewModelFactory {
            initializer {
                val app = context.applicationContext
                MitmViewModel(
                    messages = container.messages,
                    caExistsCheck = { MitmManager.caFile(app).exists() },
                    export = { MitmManager.export(app) },
                    generateModule = { pem, name -> TrustModuleGenerator.generate(app, pem, name) },
                    applyEnabled = { Actions.setMitmEnabled(it) },
                    applyHostnames = { Actions.setMitmHostnames(it) },
                    applySkip = { Actions.setMitmSkip(it) },
                    applyApps = { mode, apps -> Actions.setMitmApps(mode, apps) },
                    applyScriptArgs = { script, values -> Actions.setMitmScriptArguments(script, values) },
                    applyPool = { Actions.setMitmPoolEnabled(it) },
                    exportDirFallback = { MitmManager.exportDir(app).absolutePath },
                    caFingerprintCheck = { MitmManager.caFingerprint(app) },
                    systemCertCheck = { name -> MitmManager.systemCertInstalled(app, name) },
                    trustSnapshotCheck = { name -> RootCaManager.inspect(app, name) },
                    publishExport = { r -> Actions.exportCertificateFiles(app, r) },
                    readInjectionLog = { RootCaManager.diagnosticLog() },
                    publishLog = { text -> Actions.exportText(app, "namu_mitm_inject_log.txt", text) },
                )
            }
        }
    }
}
