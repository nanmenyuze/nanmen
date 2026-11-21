package com.namu.dns.ui

import com.namu.dns.core.LocalDockClearance

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.Lan
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.SwapVert
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.BuildConfig
import com.namu.dns.CrashGuard
import com.namu.dns.MigrationReportStore
import com.namu.dns.NetworkStatus
import com.namu.dns.UiPrefs
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.ui.viewmodel.SettingsViewModel

@Composable
fun SettingsScreen(onRestart: () -> Unit, onOpenLogs: () -> Unit, onOpenMitm: () -> Unit) {
    val container = LocalAppContainer.current
    val vm: SettingsViewModel = viewModel(factory = SettingsViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val cfg = state.config
    var showPingMethod by remember { mutableStateOf(false) }
    var showTheme by remember { mutableStateOf(false) }
    var showDonate by remember { mutableStateOf(false) }
    var showBackup by remember { mutableStateOf(false) }
    var showMigration by remember { mutableStateOf(false) }
    var showPrivacy by remember { mutableStateOf(false) }
    val context = LocalContext.current
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
        SectionHeader("高级")
        GroupCard {
            SettingsRow(
                title = "延迟测试方法",
                value = pingMethodLabel(cfg.pingMethod),
                icon = Icons.Rounded.Speed,
                chevron = true,
                onClick = { showPingMethod = true },
            )
            SettingsRow(
                title = "MITM 去广告",
                subtitle = if (cfg.mitm.enabled) {
                    "已启用 · 证书、域名与改写规则在此管理"
                } else {
                    "HTTPS 解密按 URL 去广告，需安装 CA 证书"
                },
                icon = Icons.Rounded.Security,
                chevron = true,
                onClick = onOpenMitm,
            )
            SettingsRow(
                title = "诊断",
                subtitle = "查看内核运行日志与 DNS 查询记录",
                icon = Icons.Rounded.BugReport,
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
                title = "自动连接",
                subtitle = "开机或默认网络恢复时，在未连接状态下自动启动 VPN",
                rightContent = {
                    IosSwitch(
                        checked = cfg.autoConnect,
                        onCheckedChange = { vm.setAutoConnect(it) },
                    )
                },
            )
            SettingsRow(
                title = "外观",
                value = when (cfg.themeMode) {
                    "light" -> "浅色"
                    "dark" -> "深色"
                    else -> "跟随系统"
                },
                icon = Icons.Rounded.Tune,
                chevron = true,
                onClick = { showTheme = true },
            )
            SettingsRow(
                title = "重新查看引导",
                subtitle = "重新播放首次使用的三页引导",
                showDivider = false,
                onClick = { UiPrefs.setOnboardingDone(false) },
            )
        }
        if (showTheme) {
            ChoiceDialog(
                title = "外观",
                message = "选择浅色、深色，或跟随系统深色模式",
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

        SectionHeader("隧道")
        GroupCard {
            SettingsRow(
                title = "当前网络",
                subtitle = network.detail,
                value = network.label,
                icon = Icons.Rounded.Lan,
            )
            SettingsRow(
                title = "隧道",
                subtitle = "TUN 接管全部 DNS，MTU 1500",
                value = if (cfg.fakeIp) "Fake-IP" else "直连",
                icon = Icons.Rounded.Lan,
                chevron = false,
            )
            SettingsRow(
                title = "代理",
                subtitle = "节点流量走 ${cfg.finalPolicy} 策略",
                value = when (cfg.mode) {
                    "global" -> "全局"
                    "dns_only" -> "仅 DNS"
                    "filter_only" -> "纯过滤"
                    else -> "规则"
                },
                icon = Icons.Rounded.Layers,
                chevron = false,
            )
            SettingsRow(
                title = "TCP",
                subtitle = "连接由内核逐条转发，断流即释放",
                value = "按需",
                icon = Icons.Rounded.SwapVert,
                chevron = false,
            )
            SettingsRow(
                title = "UDP",
                subtitle = "DNS 走 UDP 直通，其他 UDP 按规则代理",
                value = "跟随规则",
                icon = Icons.Rounded.Memory,
                showDivider = false,
            )
        }

        SectionHeader("维护")
        GroupCard {
            SettingsRow(
                title = "备份与恢复",
                subtitle = "导出节点、订阅、策略组和全部 .conf；恢复前会整包校验",
                icon = Icons.Rounded.SwapVert,
                chevron = true,
                onClick = { showBackup = true },
            )
            SettingsRow(
                title = "版本迁移与崩溃恢复",
                subtitle = MigrationReportStore.summary(context),
                value = if (CrashGuard.lastCrash(context) != null) "有崩溃记录" else null,
                icon = Icons.Rounded.BugReport,
                chevron = true,
                onClick = { showMigration = true },
            )
            SettingsRow(
                title = "隐私与系统限制",
                subtitle = "本地数据、证书边界、Private DNS 和 Root/非 Root 说明",
                icon = Icons.Rounded.Security,
                chevron = true,
                showDivider = false,
                onClick = { showPrivacy = true },
            )
        }

        SectionHeader("关于")
        GroupCard {
            SettingsRow("版本", value = BuildConfig.VERSION_NAME)
            SettingsRow("内核", value = "nanmen_core · 1.13.4")
            SettingsRow("代理协议", value = "SS · Trojan · VLESS")
            SettingsRow("DNS", value = "DoH · DoT · UDP")
            SettingsRow(
                "支持作者",
                subtitle = "自愿打赏 · 不解锁任何功能",
                chevron = true,
                onClick = { showDonate = true },
            )
            SettingsRow(
                "当前配置",
                value = cfg.remoteConfigName.ifBlank { "基础配置" },
                showDivider = false,
            )
        }

        SectionHeader("说明")
        GroupCard {
            SettingsRow(
                title = "配置文件",
                subtitle = "通用、自定义规则和规则集 URL 都在「策略 → 规则 → 当前配置」里管理。",
                showDivider = false,
            )
        }

        FooterText("服务器在首页管理；DNS 查询与运行日志在「数据」页。")
        Spacer(Modifier.height(LocalDockClearance.current + 30.dp))
    }

    if (showPingMethod) {
        ChoiceDialog(
            title = "延迟测试方法",
            message = "TCP 握手兼容所有节点；TLS 握手只适合 TLS 节点，能额外发现端口可连但握手失败的情况。自动选节点也使用这里的方法。",
            options = listOf(
                "tcp" to "TCP 握手（推荐）",
                "tls" to "TLS 握手",
            ),
            selected = cfg.pingMethod,
            onSelect = {
                vm.setPingMethod(it)
                showPingMethod = false
            },
            onDismiss = { showPingMethod = false },
        )
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
            onOpenMitm = onOpenMitm,
        )
    }
}
