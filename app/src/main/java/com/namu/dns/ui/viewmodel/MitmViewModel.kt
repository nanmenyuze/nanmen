package com.namu.dns.ui.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.namu.dns.Actions
import com.namu.dns.MitmManager
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
    private val exportDirFallback: () -> String = { "" },
    private val caFingerprintCheck: () -> String? = { null },
    private val systemCertCheck: (systemName: String) -> Boolean = { _ -> false },
) : ViewModel() {

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    private val _caExists = MutableStateFlow(caExistsCheck())
    val caExists: StateFlow<Boolean> = _caExists.asStateFlow()

    private val _caFingerprint = MutableStateFlow(caFingerprintCheck())
    val caFingerprint: StateFlow<String?> = _caFingerprint.asStateFlow()

    private val _systemCertInstalled = MutableStateFlow(false)
    val systemCertInstalled: StateFlow<Boolean> = _systemCertInstalled.asStateFlow()

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
            val systemInstalled = withContext(Dispatchers.IO) {
                systemName.takeIf { it.isNotBlank() }?.let(systemCertCheck) ?: false
            }
            _caExists.value = exists
            _caFingerprint.value = fingerprint
            _systemCertInstalled.value = systemInstalled
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

    /** 生成 KernelSU/Magisk 系统信任模块（开机早期挂载、重启不丢）。 */
    fun generateTrustModule() = withExport { r ->
        val result = generateModule(r.pemPath, r.systemName)
        if (result.ok) {
            _systemCertInstalled.value = systemCertCheck(r.systemName)
            messages.show("系统信任模块已生成：${result.path}。用 KernelSU/Magisk「从存储安装」该模块后重启，所有 App 即信任此 CA（重启不丢）。")
        } else {
            messages.show("模块生成失败：${result.error}")
        }
    }

    fun exportOnly() = withExport { r ->
        val dir = File(r.derPath).parent ?: exportDirFallback()
        messages.show("已导出到 $dir：namu-ca.pem / namu-ca.crt（DER）")
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
                    exportDirFallback = { MitmManager.exportDir(app).absolutePath },
                    caFingerprintCheck = { MitmManager.caFingerprint(app) },
                    systemCertCheck = { name -> MitmManager.systemCertInstalled(app, name) },
                )
            }
        }
    }
}
