package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.Diagnostics
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.LocalDockClearance
import com.namu.dns.core.repository.ShellPhase
import com.namu.dns.ui.viewmodel.DataViewModel
import com.namu.dns.ui.viewmodel.MitmViewModel
import kotlinx.coroutines.launch

/**
 * 设置 → 运行数据与诊断。四个区块：DNS 与拦截、流量与连接、MITM 统计、日志与导出。
 * 指标标明「本次运行」或「近 24 小时」；当前模式未采集时显示「未采集」，实测为零才显示 0。
 * 证书安装日志与证书页共用 MitmViewModel 的同一套导出逻辑。
 */
@Composable
fun DiagnosticsScreen(
    onOpenDnsAnalytics: () -> Unit,
    onOpenDnsLogs: () -> Unit,
    onOpenRuntimeLogs: () -> Unit,
    onOpenMitmDetails: () -> Unit,
) {
    val container = LocalAppContainer.current
    val vm: DataViewModel = viewModel(factory = DataViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val mitmVm: MitmViewModel = viewModel(factory = MitmViewModel.factory(container, ctx))
    val mitmBusy by mitmVm.busy.collectAsStateWithLifecycle()
    var showLive by remember { mutableStateOf(false) }
    var showClearLogs by remember { mutableStateOf(false) }

    val stats = state.stats.stats
    val cfg = state.config
    val runtime = state.runtime
    // 与证书页同款：进入页面先核验一次，导出安装日志时才能带上当前 CA 文件名。
    LaunchedEffect(Unit) { mitmVm.refresh() }

    // 本次运行是否真的采到过数据：从未连接过 = 未采集，连接过实测为 0 才显示 0。
    val sessionSampled = state.stats.sessionActive || stats.uptime > 0L
    val observesConnections = cfg.mode != "dns_only" || cfg.dnsOnlyFullRoute
    val mitmSampled = cfg.mitm.enabled || stats.mitmConns > 0L

    // DNS 与拦截优先用命中历史窗口（近 24 小时 / 近 7 天）；历史不可用时退回本次运行口径。
    val hits = state.hits
    val useWindow = hits.phase == ShellPhase.SUCCESS
    val dnsPeriod = when {
        useWindow && hits.windowHours >= 168 -> "近 7 天"
        useWindow -> "近 24 小时"
        else -> "本次运行"
    }
    val dnsQueries = if (useWindow) hits.window.queries else stats.dnsQueries
    val dnsBlocked = if (useWindow) hits.window.blocked else stats.dnsBlocked
    val dnsCollected = useWindow || sessionSampled
    val hitRate = if (dnsQueries > 0) dnsBlocked * 100.0 / dnsQueries else null

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("DNS 与拦截", trailing = { PeriodTag(dnsPeriod) })
        GroupCard {
            Row(Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 10.dp)) {
                DiagMetric("查询数", dnsQueries.toString(), dnsCollected, Modifier.weight(1f))
                DiagMetric("拦截数", dnsBlocked.toString(), dnsCollected, Modifier.weight(1f))
                DiagMetric(
                    "命中率",
                    hitRate?.let { String.format(java.util.Locale.US, "%.1f%%", it) } ?: "—",
                    dnsCollected,
                    Modifier.weight(1f),
                )
            }
            SettingsRow(
                title = "趋势与命中域名",
                subtitle = "查询趋势、按模块分布与命中历史",
                chevron = true,
                onClick = onOpenDnsAnalytics,
            )
            SettingsRow(
                title = "DNS 记录",
                subtitle = "域名、拦截/放行、缓存或上游、耗时",
                value = "${state.logs.dns.size} 条",
                chevron = true,
                showDivider = false,
                onClick = onOpenDnsLogs,
            )
        }

        SectionHeader("流量与连接", trailing = { PeriodTag("本次运行") })
        GroupCard {
            val trafficCollected = observesConnections && sessionSampled
            Row(Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 10.dp)) {
                DiagMetric("上传", formatBytes(stats.up), trafficCollected, Modifier.weight(1f))
                DiagMetric("下载", formatBytes(stats.down), trafficCollected, Modifier.weight(1f))
                DiagMetric("连接数", stats.activeConns.toString(), trafficCollected, Modifier.weight(1f))
            }
            SettingsRow(
                title = "实时连接与规则命中",
                subtitle = if (observesConnections) "查看连接、归属应用和命中规则"
                    else "仅系统 DNS 模式不采集普通连接",
                value = if (trafficCollected) "${stats.activeConns} 活跃" else null,
                chevron = observesConnections,
                showDivider = false,
                onClick = if (observesConnections) ({ showLive = true }) else null,
            )
        }

        SectionHeader("MITM 统计", trailing = { PeriodTag("本次运行") })
        GroupCard {
            Row(Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 10.dp)) {
                DiagMetric("解密", stats.mitmConns.toString(), mitmSampled, Modifier.weight(1f))
                DiagMetric("改写", stats.mitmRewritten.toString(), mitmSampled, Modifier.weight(1f))
                DiagMetric("失败", stats.mitmFailed.toString(), mitmSampled, Modifier.weight(1f))
            }
            SettingsRow(
                title = "逐域名数据",
                subtitle = if (mitmSampled) "按 host 统计连接、失败、无规则与改写"
                    else "MITM 未启用，当前模式未采集",
                chevron = true,
                showDivider = false,
                onClick = onOpenMitmDetails,
            )
        }

        SectionHeader("日志与导出")
        GroupCard {
            SettingsRow(
                title = "运行日志",
                subtitle = "内核、规则匹配与连接记录",
                value = "${state.logs.runtime.size} 条",
                chevron = true,
                onClick = onOpenRuntimeLogs,
            )
            SettingsRow(
                title = "自动删除",
                subtitle = "每次连接前清空上一次的运行日志与 DNS 记录",
                rightContent = {
                    IosSwitch(
                        checked = cfg.autoClearLogs,
                        onCheckedChange = { vm.setAutoClearLogs(it) },
                    )
                },
            )
            SettingsRow(
                title = "立即清空",
                subtitle = "清空当前运行日志与 DNS 记录，不影响命中历史",
                chevron = true,
                onClick = { showClearLogs = true },
            )
            SettingsRow(
                title = "导出诊断报告",
                subtitle = "日志、内核版本、运行时长、请求数、缓存命中率、DNS 延迟分布和内存统计",
                chevron = true,
                onClick = {
                    scope.launch {
                        try {
                            val where = Diagnostics.export(ctx)
                            vm.showMessage("诊断报告已导出：$where")
                        } catch (e: Exception) {
                            vm.showMessage(e.message ?: "导出诊断报告失败")
                        }
                    }
                },
            )
            SettingsRow(
                title = "导出证书安装日志",
                subtitle = "开机注入日志与当前证书核验；与证书页共用同一导出",
                value = if (mitmBusy) "处理中…" else null,
                chevron = true,
                showDivider = false,
                onClick = { mitmVm.exportInjectionLog() },
            )
        }

        FooterText("「本次运行」从本次 VPN 连接开始累计，断开后保留最后一次会话；「近 24 小时」来自本机命中历史。当前模式未采集的指标显示「未采集」。")
        Spacer(Modifier.height(LocalDockClearance.current + 30.dp))
    }

    if (showLive) {
        LiveConnectionsDialog(
            stats = stats,
            cfg = cfg,
            runtimeState = runtime,
            logs = state.logs.runtime,
            onDismiss = { showLive = false },
        )
    }
    if (showClearLogs) {
        NamuDialog(
            title = "清空日志？",
            message = "将清空当前运行日志与 DNS 记录；命中历史与统计不受影响。",
            confirmText = "清空",
            confirmColor = NamuColors.Red,
            onConfirm = {
                vm.clearLogsNow()
                showClearLogs = false
            },
            onDismiss = { showClearLogs = false },
        ) {}
    }
}

/** 区块右上角的统计口径标签：本次运行 / 近 24 小时 / 近 7 天。 */
@Composable
private fun PeriodTag(text: String) {
    Text(text, fontSize = 12.sp, color = NamuColors.TextSub)
}

/** 与数据页 DataMetric 同款字阶；未采集时降字阶灰显，避免把「未采集」当成 0。 */
@Composable
private fun DiagMetric(label: String, value: String, collected: Boolean, modifier: Modifier = Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            if (collected) value else "未采集",
            fontSize = if (collected) 21.sp else 15.sp,
            fontWeight = FontWeight.SemiBold,
            color = if (collected) NamuColors.TextMain else NamuColors.TextTertiary,
        )
        Spacer(Modifier.height(3.dp))
        Text(label, fontSize = 12.sp, color = NamuColors.TextSub)
    }
}