package com.namu.dns.ui

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.Actions
import com.namu.dns.GlobalRuleStore
import com.namu.dns.App
import com.namu.dns.AppConfig
import com.namu.dns.MitmManager
import com.namu.dns.RootCaManager
import com.namu.dns.core.AppContainer
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.config.ConfigFile
import com.namu.dns.ui.viewmodel.MitmViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

internal class ProfileEditor(val name: String, private val container: AppContainer, initial: AppConfig) {
    private var snapshot by mutableStateOf(initial)
    val isActive: Boolean get() = name == container.config.activeName()

    fun current(): AppConfig = if (isActive) container.settings.config.value else snapshot

    fun update(transform: (AppConfig) -> AppConfig): Boolean {
        val saved = container.config.saveProfile(name, transform)
        if (saved == null) {
            container.messages.show("保存失败：$name")
            return false
        }
        snapshot = saved
        return true
    }

    fun refresh() {
        container.config.loadProfile(name)?.let { snapshot = it }
    }
}

@Composable
internal fun rememberProfileEditor(name: String): ProfileEditor? {
    val container = LocalAppContainer.current
    val deviceConfig by container.settings.config.collectAsStateWithLifecycle()
    // Navigate back from a section with the latest on-disk information for inactive profiles.
    val editor = remember(name) { container.config.loadProfile(name)?.let { ProfileEditor(name, container, it) } }
    LaunchedEffect(editor, deviceConfig) { editor?.refresh() }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { editor?.refresh() }
    if (editor == null) {
        GroupCard { SettingsRow("配置无法读取", value = name, showDivider = false) }
    }
    return editor
}

internal suspend fun prepareProfileCa(config: AppConfig, context: Context): Boolean =
    !config.mitm.enabled || MitmManager.caFile(context).exists() || MitmManager.export(context).ok

internal suspend fun exportProfile(name: String) {
    val container = App.container
    try {
        val config = container.config.loadProfile(name) ?: error("配置无法读取")
        val location = Actions.exportText(container.context, name, ConfigFile.fromAppConfig(config).toJson())
        container.messages.show("已导出到 $location")
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        container.messages.show("导出失败：${e.message}")
    }
}

@Composable
internal fun ConfigHostsScreen(editor: ProfileEditor) {
    val hosts = editor.current().mitm.hostMappings
    var editing by remember { mutableStateOf(false) }
    DetailList {
        SectionHeader("域名映射", trailing = { TextAction("编辑") { editing = true } })
        GroupCard {
            if (hosts.isEmpty()) {
                SettingsRow("暂无映射", chevron = true, onClick = { editing = true }, showDivider = false)
            }
            hosts.entries.forEachIndexed { index, (host, address) ->
                SettingsRow(host, value = address, chevron = true, onClick = { editing = true }, showDivider = index < hosts.size - 1)
            }
        }
    }
    if (editing) HostMapDialog(
        initial = hosts,
        onDismiss = { editing = false },
        onDone = { map ->
            if (editor.update { it.copy(mitm = it.mitm.copy(hostMappings = map)) }) editing = false
        },
    )
}

@Composable
internal fun ConfigRewriteScreen(editor: ProfileEditor, kind: String) {
    val config = editor.current()
    var editing by remember { mutableStateOf(false) }
    var text by remember { mutableStateOf("") }
    val values = when (kind) {
        "URL 重写" -> config.mitm.urlRewrites
        "头部重写" -> config.mitm.headerRewrites
        else -> config.mitm.bodyRewrites
    }
    DetailList {
        SectionHeader(kind)
        GroupCard {
            SettingsRow(
                title = "编辑重写规则",
                subtitle = if (kind == "URL 重写") "每行一条；支持 reject 族 / 302 / 307 / mock / header / body" else "每行一条，保存后立即写入当前配置",
                value = "${values.size} 条",
                chevron = true,
                showDivider = false,
                onClick = { text = values.joinToString("\n"); editing = true },
            )
        }
        Spacer(Modifier.height(24.dp))
    }
    if (editing) {
        NamuDialog(
            title = kind,
            confirmText = "保存",
            onDismiss = { editing = false },
            onConfirm = {
                val entries = text.lines().map(String::trim).filter(String::isNotEmpty).distinct()
                if (editor.update { current ->
                    current.copy(mitm = when (kind) {
                        "URL 重写" -> current.mitm.copy(urlRewrites = entries)
                        "头部重写" -> current.mitm.copy(headerRewrites = entries)
                        else -> current.mitm.copy(bodyRewrites = entries)
                    })
                }) editing = false
            },
        ) {
            NamuTextField(
                text,
                { text = it },
                if (kind == "URL 重写") "每行一条，例如：\n^https://a.com/ad reject-dict\n^https://a.com/old https://a.com/new 302\n^https://a.com/x mock-response-body data-type=json data={\"code\":0}" else "每行一条",
                maxLines = 12,
            )
        }
    }
}

@Composable
internal fun HttpsScopeSection(onOpenCertificate: () -> Unit) {
    val scope = GlobalRuleStore.state.scope
    val container = LocalAppContainer.current
    val context = container.context
    val coroutine = rememberCoroutineScope()
    val vm: MitmViewModel = viewModel(factory = MitmViewModel.factory(container, context))
    val trust by vm.trust.collectAsStateWithLifecycle()
    val exists by vm.caExists.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { vm.refresh() }
    // 从系统设置/模块管理器装完证书返回时，页面还停在旧状态，必须重新核验。
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { vm.refresh() }
    val ready = RootCaManager.resolveTrustState(exists, trust) == RootCaManager.TrustState.ACTIVE
    var preparing by remember { mutableStateOf(false) }
    var field by remember { mutableStateOf<String?>(null) }
    var apps by remember { mutableStateOf(false) }
    var text by remember { mutableStateOf("") }

    SectionHeader("HTTPS 解密")
    GroupCard {
        SwitchRow("启用 HTTPS 解密", subtitle = if (preparing) "正在准备证书" else "设备级总开关；模块声明的解密域名仍受此控制", checked = scope.enabled) { enabled ->
            if (preparing) return@SwitchRow
            coroutine.launch {
                preparing = true
                try {
                    if (MitmManager.caFile(context).exists() || MitmManager.export(context).ok) {
                        Actions.setMitmEnabled(enabled)
                    } else container.messages.show("CA 准备失败")
                } finally {
                    preparing = false
                }
            }
        }
        SettingsRow("手动解密域名", value = "${scope.hostnames.size} 个", chevron = true, onClick = {
            field = "手动解密域名"; text = scope.hostnames.joinToString("\n")
        })
        SettingsRow("排除域名", value = "${scope.skipHostnames.size} 个", chevron = true, onClick = {
            field = "排除域名"; text = scope.skipHostnames.joinToString("\n")
        })
        SettingsRow("应用范围", value = when (scope.appMode) {
            "allow" -> "仅 ${scope.apps.size} 个应用"
            "deny" -> "排除 ${scope.apps.size} 个应用"
            else -> "全部应用"
        }, chevron = true, showDivider = false, onClick = { apps = true })
    }
    SectionHeader("证书")
    GroupCard {
        SettingsRow("MITM 证书", value = if (ready) "已生效" else "未核验生效",
            chevron = true, showDivider = false, onClick = onOpenCertificate)
    }
    SectionHeader("高级")
    GroupCard {
        SwitchRow("上游连接复用（实验）", checked = scope.poolEnabled, showDivider = false) { enabled ->
            coroutine.launch { Actions.setMitmPoolEnabled(enabled) }
        }
    }
    if (apps) {
        AppScopeDialog(scope.appMode, scope.apps, onDismiss = { apps = false }) { mode, selection ->
            coroutine.launch { Actions.setMitmApps(mode, selection) }
            apps = false
        }
    }
    field?.let { title ->
        NamuDialog(
            title = title,
            confirmText = "保存",
            onDismiss = { field = null },
            onConfirm = {
                val values = MitmManager.parseHostList(text)
                val k = title
                coroutine.launch {
                    if (k == "手动解密域名") Actions.setMitmHostnames(values) else Actions.setMitmSkip(values)
                }
                field = null
            },
        ) {
            NamuTextField(text, { text = it }, "每行一条", maxLines = 9)
        }
    }
}
