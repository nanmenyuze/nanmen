package com.namu.dns.ui

import androidx.compose.runtime.mutableIntStateOf
import com.namu.dns.core.LocalDockClearance

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountTree
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.automirrored.outlined.LibraryBooks
import androidx.compose.material.icons.outlined.BugReport
import androidx.compose.material.icons.outlined.Insights
import androidx.compose.material.icons.outlined.Lan
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.automirrored.outlined.Rule
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.SwapVert
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.Actions
import com.namu.dns.BuildConfig
import com.namu.dns.ConfigStore
import com.namu.dns.CrashGuard
import com.namu.dns.MigrationReportStore
import com.namu.dns.NativeCore
import com.namu.dns.NetworkStatus
import com.namu.dns.UiPrefs
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.config.MitmConfig
import com.namu.dns.core.config.ModuleGeneral
import com.namu.dns.core.config.SsidTrigger
import com.namu.dns.ui.viewmodel.SettingsViewModel
import kotlinx.coroutines.launch
import org.json.JSONObject

private val settingsBlue = Color(0xFF3B82F6)
private val settingsPurple = Color(0xFFA855F7)
private val settingsGreen = Color(0xFF22C58B)
private val settingsGray = Color(0xFF6B7280)

@Composable
fun SettingsScreen(
    onOpenConfig: () -> Unit,
    onOpenMitm: () -> Unit,
    onOpenDiagnostics: () -> Unit,
    onOpenAdvanced: () -> Unit,
) {
    val container = LocalAppContainer.current
    val activeProfile by container.settings.activeProfile.collectAsStateWithLifecycle()
    val vm: SettingsViewModel = viewModel(factory = SettingsViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val cfg = state.config
    var showTheme by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        MainPageTopBar("设置")
        SectionHeader("配置")
        GroupCard {
            SettingsRow(
                title = "配置管理",
                value = activeProfile,
                icon = Icons.Outlined.Folder,
                chevron = true,
                showDivider = false,
                onClick = onOpenConfig,
            )
        }

        SectionHeader("MITM")
        GroupCard {
            SettingsRow(
                title = "MITM 证书",
                icon = Icons.Outlined.Security,
                iconBackground = settingsGreen,
                chevron = true,
                showDivider = false,
                onClick = onOpenMitm,
            )
        }

        SectionHeader("偏好")
        GroupCard {
            SettingsRow(
                title = "外观",
                value = when (cfg.themeMode) {
                    "light" -> "浅色"
                    "dark" -> "深色"
                    else -> "跟随系统"
                },
                icon = Icons.Outlined.Palette,
                iconBackground = settingsPurple,
                chevron = true,
                showDivider = false,
                onClick = { showTheme = true },
            )
        }

        SectionHeader("其他")
        GroupCard {
            SettingsRow(
                title = "运行数据与诊断",
                icon = Icons.Outlined.Insights,
                iconBackground = settingsBlue,
                chevron = true,
                onClick = onOpenDiagnostics,
            )
            SettingsRow(
                title = "高级设置",
                icon = Icons.Outlined.Tune,
                iconBackground = settingsGray,
                chevron = true,
                showDivider = false,
                onClick = onOpenAdvanced,
            )
        }
        Spacer(Modifier.height(LocalDockClearance.current + 30.dp))
    }
    if (showTheme) {
        ChoiceDialog(
            title = "外观",
            options = listOf(
                "system" to "跟随系统",
                "light" to "浅色",
                "dark" to "深色",
            ),
            selected = cfg.themeMode,
            onSelect = {
                vm.setThemeMode(it)
                showTheme = false
            },
            onDismiss = { showTheme = false },
        )
    }

}

@Composable
fun AdvancedSettingsScreen(onOpenLogs: () -> Unit, onRestart: () -> Unit) {
    val container = LocalAppContainer.current
    val vm: SettingsViewModel = viewModel(factory = SettingsViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val cfg = state.config
    var showDonate by remember { mutableStateOf(false) }
    var showBackup by remember { mutableStateOf(false) }
    var showMigration by remember { mutableStateOf(false) }
    var showPrivacy by remember { mutableStateOf(false) }
    var showSsidNames by remember { mutableStateOf(false) }
    var showGeneral by remember { mutableStateOf(false) }
    var showScriptArgs by remember { mutableStateOf(false) }
    var permissionEpoch by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { permissionEpoch++ }
    val ssidState = remember(cfg.ssidTriggerEnabled, cfg.ssidLocationOptIn, cfg.ssidTriggerNames, permissionEpoch) {
        SsidTrigger.state(context, cfg)
    }
    val moduleGeneral = remember(cfg.moduleSources) {
        runCatching {
            val o = JSONObject(ConfigStore.moduleMitmFile(context).readText())
            ModuleGeneral.parse(o.optJSONObject("generalOptions")?.let { g ->
                g.keys().asSequence().associateWith { g.optString(it) }
            } ?: emptyMap())
        }.getOrDefault(ModuleGeneral.parse(emptyMap()))
    }
    val scriptCount = cfg.mitm.scripts.count { it.arguments.isNotEmpty() }
    val scriptArgCount = cfg.mitm.scripts.sumOf { it.arguments.size }
    var network by remember { mutableStateOf(NetworkStatus.current(context)) }
    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(2500)
            network = NetworkStatus.current(context)
        }
    }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("模块和自动触发")
        GroupCard {
            SettingsRow(
                title = "[General]",
                subtitle = if (moduleGeneral.raw.isEmpty()) "模块通用项：未声明" else "模块通用项：${moduleGeneral.raw.size} 个键，只映射壳行为",
                icon = Icons.AutoMirrored.Outlined.LibraryBooks,
                chevron = true,
                onClick = { showGeneral = true },
            )
            SettingsRow(
                title = "脚本运行参数",
                subtitle = if (scriptCount == 0) "当前模块没有声明 [Argument]" else "$scriptCount 个脚本 · $scriptArgCount 项，可运行期修改",
                chevron = true,
                onClick = {
                    if (scriptCount == 0) vm.showMessage("当前没有可编辑的脚本参数")
                    else showScriptArgs = true
                },
            )
            SettingsRow(
                title = "自动连接",
                subtitle = "开机或默认网络恢复后自动连接；设备级开关，与 SSID 触发各自独立",
                icon = Icons.Outlined.Sync,
                rightContent = {
                    IosSwitch(
                        checked = cfg.autoConnect,
                        onCheckedChange = { vm.setAutoConnect(it) },
                    )
                },
            )
            SettingsRow(
                title = "SSID 触发",
                subtitle = "默认关；开启后只在本机比较当前 Wi-Fi 名称",
                rightContent = {
                    IosSwitch(checked = cfg.ssidTriggerEnabled, onCheckedChange = { on ->
                        vm.setSsidEnabled(on)
                        if (!on) vm.setSsidLocationOptIn(false)
                    })
                },
            )
            if (cfg.ssidTriggerEnabled) {
                SettingsRow(
                    title = "读取当前 Wi-Fi 名称",
                    subtitle = "named-SSID 高级 opt-in；只做本地名单比较，不采集位置、不上报",
                    rightContent = {
                        IosSwitch(
                            checked = cfg.ssidLocationOptIn,
                            onCheckedChange = { vm.setSsidLocationOptIn(it) },
                        )
                    },
                )
                SettingsRow(
                    title = "位置权限",
                    subtitle = when {
                        ssidState.hasPermission -> "已授权；用于读取当前 SSID，不采集位置轨迹"
                        !cfg.ssidLocationOptIn -> "先开启上一项，再按需申请系统权限"
                        else -> "未授权；点右侧按钮进入系统权限，与 SSID 开关独立"
                    },
                    rightContent = {
                        val label = if (ssidState.hasPermission) "已授权" else "去授权"
                        MiniTextAction(label, color = if (ssidState.hasPermission) NamuColors.Green else NamuColors.Brand) {
                            if (!cfg.ssidLocationOptIn) vm.showMessage("请先开启「读取当前 Wi-Fi 名称」")
                            else permissionLauncher.launch(SsidTrigger.requiredPermissions().toTypedArray())
                        }
                    },
                    onClick = null,
                )
                SettingsRow(
                    title = "SSID 名单",
                    subtitle = if (ssidState.currentSsid.isBlank() || !ssidState.hasPermission) {
                        "仅名单内 Wi-Fi 生效；当前未读取"
                    } else {
                        "当前：${ssidState.currentSsid}${if (ssidState.matched) " · 命中" else ""}"
                    },
                    value = "${cfg.ssidTriggerNames.size} 个",
                    chevron = true,
                    showDivider = false,
                    onClick = { showSsidNames = true },
                )
            }
        }

        SectionHeader("应用与网络")
        GroupCard {
            SettingsRow(
                title = "金融连接保护",
                subtitle = "支付、银行、账号安全连接不走 MITM；银行类 App 整包跳过，微信支付宝按域名排除",
                icon = Icons.Outlined.Security,
                rightContent = {
                    IosSwitch(
                        checked = cfg.financeProtect,
                        onCheckedChange = { vm.setFinanceProtect(it) },
                    )
                },
            )
            SettingsRow(
                title = "运行日志",
                subtitle = "查看内核、规则匹配与连接记录",
                icon = Icons.Outlined.BugReport,
                chevron = true,
                onClick = onOpenLogs,
            )
            SettingsRow(
                title = "私人 DNS 接管",
                subtitle = "Root：连接时临时关闭系统 Private DNS，断开后恢复，避免 DoT 绕过内核",
                rightContent = {
                    IosSwitch(
                        checked = cfg.autoDisablePrivateDns,
                        onCheckedChange = {
                            vm.setAutoDisablePrivateDns(it)
                        },
                    )
                },
            )
            SettingsRow(
                title = "重新查看引导",
                subtitle = "重新播放首次使用的三页引导",
                showDivider = false,
                onClick = {
                    UiPrefs.setVpnGuideDone(false)
                    UiPrefs.setOnboardingDone(false)
                },
            )
        }
        SectionHeader("隧道")
        GroupCard {
            SettingsRow(
                title = "当前网络",
                subtitle = network.detail,
                value = network.label,
                icon = Icons.Outlined.Lan,
            )
            SwitchRow(title = "巨帧 MTU", subtitle = "${cfg.mtu} 字节", checked = cfg.mtu == 9000) {
                container.settings.update { current -> current.copy(mtu = if (it) 9000 else 1500) }
                if (container.runtime.current().connected) onRestart()
            }
            SwitchRow(title = "上游 BBR", checked = cfg.bbr) {
                container.settings.update { current -> current.copy(bbr = it) }
            }
            SwitchRow(title = "QUIC 自动回落", checked = cfg.quicFallback, showDivider = false) {
                container.settings.update { current -> current.copy(quicFallback = it) }
                if (container.runtime.current().connected) onRestart()
            }
        }

        SectionHeader("备份与维护")
        GroupCard {
            SettingsRow(
                title = "备份与恢复",
                subtitle = "导出节点、订阅、策略组和全部 .conf；恢复前会整包校验",
                icon = Icons.Outlined.SwapVert,
                chevron = true,
                onClick = { showBackup = true },
            )
            SettingsRow(
                title = "版本迁移与崩溃恢复",
                subtitle = MigrationReportStore.summary(context),
                value = if (CrashGuard.lastCrash(context) != null) "有崩溃记录" else null,
                icon = Icons.Outlined.BugReport,
                chevron = true,
                onClick = { showMigration = true },
            )
            SettingsRow(
                title = "隐私与系统限制",
                subtitle = "本地数据、证书边界、Private DNS 和 Root/非 Root 说明",
                icon = Icons.Outlined.Security,
                chevron = true,
                showDivider = false,
                onClick = { showPrivacy = true },
            )
        }

        SectionHeader("关于")
        GroupCard {
            SettingsRow("版本", value = BuildConfig.VERSION_NAME)
            SettingsRow("内核", value = "nanmen_core · ${runCatching { NativeCore.nativeVersion() }.getOrDefault("unknown")}")
            SettingsRow("代理协议", value = "SS · Trojan · VLESS")
            SettingsRow("DNS", value = "DoH · DoT · UDP")
            SettingsRow(
                "支持作者",
                subtitle = "自愿打赏 · 不解锁任何功能",
                chevron = true,
                onClick = { showDonate = true },
            )
        }

        Spacer(Modifier.height(LocalDockClearance.current + 30.dp))
    }

    if (showDonate) {
        DonateDialog(onDismiss = { showDonate = false })
    }
    if (showBackup) {
        BackupRestoreDialog(onDismiss = { showBackup = false })
    }
    if (showMigration) {
        MigrationReportDialog(onDismiss = { showMigration = false })
    }
    if (showPrivacy) {
        PrivacyAndLimitsDialog(
            onDismiss = { showPrivacy = false },
        )
    }
    if (showSsidNames) {
        var text by remember { mutableStateOf(cfg.ssidTriggerNames.joinToString("\n")) }
        NamuDialog(
            title = "SSID 名单",
            message = "每行一个 Wi-Fi 名称，仅在本机比较；支持模块 [General] 与 Profile 名单合并。",
            confirmText = "保存",
            onDismiss = { showSsidNames = false },
            onConfirm = {
                vm.setSsidNames(text)
                showSsidNames = false
            },
        ) {
            NamuTextField(
                value = text,
                onChange = { text = it },
                placeholder = "HomeWiFi\nOffice-5G",
                singleLine = false,
                maxLines = 8,
            )
        }
    }
    if (showGeneral) {
        GeneralEffectsDialog(general = moduleGeneral, onDismiss = { showGeneral = false })
    }
    if (showScriptArgs) {
        ScriptArgumentsDialog(
            scripts = cfg.mitm.scripts.filter { it.arguments.isNotEmpty() },
            saved = cfg.mitm.scriptArguments,
            onSave = { script, values ->
                scope.launch {
                    Actions.setMitmScriptArguments(script, values)
                    vm.showMessage("已更新 ${script.name.ifBlank { script.pattern }} 的运行参数")
                }
            },
            onDismiss = { showScriptArgs = false },
        )
    }
}

@Composable
private fun GeneralEffectsDialog(
    general: com.namu.dns.core.config.ModuleGeneralEffects,
    onDismiss: () -> Unit,
) {
    NamuDialog(
        title = "[General]",
        message = "模块 [General] 只映射壳行为；不覆盖用户设置的 TUN / 内核参数。",
        confirmText = "关闭",
        onDismiss = onDismiss,
        onConfirm = onDismiss,
    ) {
        @Composable
        fun line(label: String, value: String) {
            Text(label, fontSize = 12.sp, color = NamuColors.TextSub, modifier = Modifier.padding(top = 8.dp))
            Text(value.ifBlank { "未声明" }, fontSize = 13.sp, color = NamuColors.TextMain)
        }
        line("ssid-trigger", general.ssidTriggers.joinToString(", "))
        line("skip-proxy / bypass", general.skipHosts.joinToString(", "))
        line("proxy-test-url / internet-test-url", general.testUrl)
        line("test-timeout", if (general.testTimeout > 0) "${general.testTimeout}s" else "")
        line("force-close-connections", if (general.forceCloseConnections) "true" else "")
        if (general.raw.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            Text("原始键（${general.raw.size}）", fontSize = 12.sp, color = NamuColors.TextSub)
            general.raw.entries.sortedBy { it.key }.forEach { (k, v) ->
                Text("$k = $v", fontSize = 11.sp, color = NamuColors.TextSub, lineHeight = 16.sp)
            }
        }
    }
}
