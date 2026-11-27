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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.BuildConfig
import com.namu.dns.ConfigStore
import com.namu.dns.GlobalRuleStore
import com.namu.dns.CrashGuard
import com.namu.dns.MigrationReportStore
import com.namu.dns.NativeCore
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.config.MitmConfig
import com.namu.dns.core.config.ModuleGeneral
import com.namu.dns.core.config.SsidTrigger
import com.namu.dns.ui.viewmodel.SettingsViewModel
import org.json.JSONObject


@Suppress("ProduceStateDoesNotAssignValue")
@Composable
fun SettingsScreen(
    onOpenMitm: () -> Unit,
    onOpenAdvanced: () -> Unit,
) {
    val container = LocalAppContainer.current
    val vm: SettingsViewModel = viewModel(factory = SettingsViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val cfg = state.config
    var showTheme by remember { mutableStateOf(false) }
    var showBackup by remember { mutableStateOf(false) }
    val context = LocalContext.current

    MainPageChrome(title = "设置") {
        Spacer(Modifier.height(6.dp))
        HttpsScopeSection(onOpenCertificate = onOpenMitm)
        Spacer(Modifier.height(20.dp))
        GroupCard {
            SettingsRow(
                title = "外观",
                value = when (cfg.themeMode) {
                    "light" -> "浅色"
                    "dark" -> "深色"
                    else -> "跟随系统"
                },
                chevron = true,
                onClick = { showTheme = true },
            )
            SettingsRow(
                title = "自动连接",
                subtitle = "开机或默认网络恢复后自动连接",
                rightContent = {
                    IosSwitch(checked = cfg.autoConnect, onCheckedChange = { vm.setAutoConnect(it) })
                },
                showDivider = false,
            )
        }
        Spacer(Modifier.height(20.dp))
        GroupCard {
            SettingsRow(
                title = "备份与恢复",
                subtitle = "导出节点、订阅、策略组和全部 .conf",
                chevron = true,
                onClick = { showBackup = true },
            )
            SettingsRow(
                title = "高级设置",
                chevron = true,
                showDivider = false,
                onClick = onOpenAdvanced,
            )
        }
        Spacer(Modifier.height(LocalDockClearance.current + 30.dp))
    }
    if (showBackup) {
        BackupRestoreDialog(onDismiss = { showBackup = false })
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
fun AdvancedSettingsScreen(onRestart: () -> Unit) {
    val container = LocalAppContainer.current
    val vm: SettingsViewModel = viewModel(factory = SettingsViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val cfg = state.config
    var showDonate by remember { mutableStateOf(false) }
    var showMigration by remember { mutableStateOf(false) }
    var showPrivacy by remember { mutableStateOf(false) }
    var showSsidNames by remember { mutableStateOf(false) }
    var showGeneral by remember { mutableStateOf(false) }
    var permissionEpoch by remember { mutableIntStateOf(0) }
    val context = LocalContext.current
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { permissionEpoch++ }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { permissionEpoch++ }
    val globalRules = GlobalRuleStore.state
    val ssidNames = remember(cfg.ssidTriggerEnabled, cfg.ssidTriggerNames, globalRules, permissionEpoch) {
        if (cfg.ssidTriggerEnabled) ConfigStore.effectiveSsidTriggers(context, cfg) else emptyList()
    }
    val ssidState = remember(cfg.ssidTriggerEnabled, cfg.ssidLocationOptIn, ssidNames, permissionEpoch) {
        SsidTrigger.state(context, cfg, ssidNames)
    }
    val moduleGeneral = remember(GlobalRuleStore.state) {
        runCatching {
            val o = JSONObject(ConfigStore.moduleMitmFile(context).readText())
            ModuleGeneral.parse(o.optJSONObject("generalOptions")?.let { g ->
                g.keys().asSequence().associateWith { g.optString(it) }
            } ?: emptyMap())
        }.getOrDefault(ModuleGeneral.parse(emptyMap()))
    }
    DetailList {
        SectionHeader("模块和自动触发")
        GroupCard {
            if (moduleGeneral.raw.isNotEmpty()) {
                SettingsRow(
                    title = "[General]",
                    subtitle = "模块通用项：${moduleGeneral.raw.size} 个键，只映射壳行为",
                    chevron = true,
                    onClick = { showGeneral = true },
                )
            }
            SettingsRow(
                title = "Wi-Fi 自动连接",
                subtitle = "网络切换时，在名单内的 Wi-Fi 上自动连接",
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
                    subtitle = "用于匹配下方的 Wi-Fi 名单",
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
                        !cfg.ssidLocationOptIn -> "先开启「读取当前 Wi-Fi 名称」"
                        ssidState.hasPermission -> "已授权"
                        else -> "系统要求授权后才能读取 Wi-Fi 名称"
                    },
                    rightContent = {
                        if (cfg.ssidLocationOptIn && !ssidState.hasPermission) {
                            MiniTextAction("去授权", color = NamuColors.Brand) {
                                permissionLauncher.launch(
                                    (SsidTrigger.requiredPermissions() + android.Manifest.permission.ACCESS_COARSE_LOCATION)
                                        .toTypedArray(),
                                )
                            }
                        }
                    },
                    onClick = null,
                )
                SettingsRow(
                    title = "SSID 名单",
                    subtitle = if (ssidState.currentSsid.isBlank() || !ssidState.hasPermission) {
                        "当前未读取到 Wi-Fi 名称"
                    } else {
                        "当前：${ssidState.currentSsid}${if (ssidState.matched) " · 命中" else ""}"
                    },
                    value = "${ssidNames.size} 个",
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
                rightContent = {
                    IosSwitch(
                        checked = cfg.financeProtect,
                        onCheckedChange = {
                            vm.setFinanceProtect(it)
                            if (GlobalRuleStore.state.scope.enabled && container.runtime.current().connected) onRestart()
                        },
                    )
                },
            )
            SettingsRow(
                title = "私人 DNS 接管",
                subtitle = "需要 Root，下次启动 VPN 时生效，断开后恢复系统设置",
                showDivider = false,
                rightContent = {
                    IosSwitch(
                        checked = cfg.autoDisablePrivateDns,
                        onCheckedChange = {
                            vm.setAutoDisablePrivateDns(it)
                        },
                    )
                },
            )
        }
        SectionHeader("隧道")
        GroupCard {
            SwitchRow(title = "巨帧 MTU", subtitle = "${cfg.mtu} 字节", checked = cfg.mtu == 9000) {
                container.settings.update { current -> current.copy(mtu = if (it) 9000 else 1500) }
                if (container.runtime.current().connected) onRestart()
            }
            SwitchRow(title = "上游 BBR", subtitle = "系统支持时对新建上游 TCP 连接生效", checked = cfg.bbr) {
                container.settings.update { current -> current.copy(bbr = it) }
                if (container.runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "QUIC 自动回落",
                subtitle = "UDP 443 持续无响应时，由应用尝试回退 TCP",
                checked = cfg.quicFallback,
                showDivider = false,
            ) {
                container.settings.update { current -> current.copy(quicFallback = it) }
                if (container.runtime.current().connected) onRestart()
            }
        }

        SectionHeader("备份与维护")
        GroupCard {
            SettingsRow(
                title = "版本迁移与崩溃恢复",
                subtitle = MigrationReportStore.summary(context),
                value = if (CrashGuard.lastCrash(context) != null) "有崩溃记录" else null,
                chevron = true,
                onClick = { showMigration = true },
            )
            SettingsRow(
                title = "隐私与系统限制",
                subtitle = "本地数据、证书边界、Private DNS 和 Root/非 Root 说明",
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
