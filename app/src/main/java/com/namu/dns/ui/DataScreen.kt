package com.namu.dns.ui

import com.namu.dns.core.LocalDockClearance
import com.namu.dns.AppUidResolver
import com.namu.dns.UidTablePublisher

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.History
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import android.content.Intent
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.Diagnostics
import com.namu.dns.NamuVpnService
import com.namu.dns.NetworkStatus
import com.namu.dns.PrivateDnsController
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.ui.viewmodel.DataViewModel
import kotlinx.coroutines.launch

@Composable
fun DataScreen(
    onOpenLogs: () -> Unit,
    onOpenDnsLogs: () -> Unit,
    onOpenNodes: () -> Unit,
    onRestart: () -> Unit,
) {
    val container = LocalAppContainer.current
    val vm: DataViewModel = viewModel(factory = DataViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val stats = state.stats.stats
    val cfg = state.config
    val runtime = state.runtime
    val clipboard = LocalClipboardManager.current
    var confirmDeleteAll by remember { mutableStateOf(false) }
    var showLive by remember { mutableStateOf(false) }
    var showRuleTest by remember { mutableStateOf(false) }
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    Column(
        Modifier
            .fillMaxSize()
            .background(NamuColors.Bg)
            .verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("流量统计")
        GroupCard {
            Row(Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 6.dp)) {
                DataMetric("上行", formatBytes(stats.up), Modifier.weight(1f))
                DataMetric("下行", formatBytes(stats.down), Modifier.weight(1f))
                DataMetric("DNS 拦截", stats.dnsBlocked.toString(), Modifier.weight(1f))
            }
            SpeedLegend(
                Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 4.dp),
            )
            SpeedSparkline(
                samples = state.stats.speedSamples,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(58.dp)
                    .padding(horizontal = 16.dp),
            )
            Text(
                "实时 ↑ ${formatBytes(state.stats.upRate)}/s   ↓ ${formatBytes(state.stats.downRate)}/s" +
                    if (state.stats.sessionActive) "" else "（本次会话已结束）",
                modifier = Modifier.padding(bottom = 8.dp),
                fontSize = 11.sp,
                color = NamuColors.TextSub,
                textAlign = TextAlign.Center,
            )
            Text(
                "TUN 发送：队列丢包 ${stats.tunTxDrop} · 背压 ${stats.tunTxBackpressure} · " +
                    "backlog 溢出 ${stats.tunPendingDrop} · 写阻塞 ${stats.tunWriteWouldBlock} · 峰值 ${stats.tunPendingPeak}",
                modifier = Modifier.padding(bottom = 8.dp),
                fontSize = 11.sp,
                color = if (stats.tunTxDrop > 0 || stats.tunPendingDrop > 0) NamuColors.Orange else NamuColors.TextSub,
                textAlign = TextAlign.Center,
            )
            Text(
                "判别：接收满 ${stats.tcpRecvFull} · 发送停滞 ${stats.tcpSendStalled} · " +
                    "QUIC 回落 ${stats.quicFallback} · 缓冲拒绝 ${stats.tcpBufferDenied}",
                modifier = Modifier.padding(bottom = 8.dp),
                fontSize = 11.sp,
                color = if (stats.tcpRecvFull > 0 || stats.tcpSendStalled > 0) NamuColors.Orange else NamuColors.TextSub,
                textAlign = TextAlign.Center,
            )
            Row(Modifier.fillMaxWidth().padding(bottom = 12.dp)) {
                DataMetric("活跃连接", stats.activeConns.toString(), Modifier.weight(1f))
                DataMetric("运行时长", formatUptime(stats.uptime), Modifier.weight(1f))
                DataMetric("总连接", stats.totalConns.toString(), Modifier.weight(1f))
            }
        }

        SectionHeader("DNS")
        GroupCard {
            Row(Modifier.fillMaxWidth().padding(vertical = 16.dp)) {
                DataMetric("查询", stats.dnsQueries.toString(), Modifier.weight(1f))
                DataMetric("缓存命中", stats.dnsCached.toString(), Modifier.weight(1f))
                DataMetric("上游平均", "${stats.dnsAvgMs} ms", Modifier.weight(1f))
            }
            val cacheLookups = stats.dnsCacheLookups
            val cacheRate = if (cacheLookups > 0) stats.dnsCached * 100.0 / cacheLookups else 0.0
            Text(
                "缓存查询命中率：${String.format(java.util.Locale.US, "%.1f", cacheRate)}%（${stats.dnsCached}/$cacheLookups）",
                fontSize = 11.sp,
                color = NamuColors.TextSub,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp),
            )
            Text(
                "本地拦截/缓存平均：${stats.dnsLocalAvgMs} ms · DoT/DoQ 853 拦截：${stats.dotBlocked} 次 · AAAA 拦截：${stats.dnsAaaaBlocked}",
                fontSize = 11.sp,
                color = NamuColors.TextSub,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp),
            )
            Text(
                "stale ${stats.dnsStale} · 负缓存 ${stats.dnsNegative} · 并发合并 ${stats.dnsCoalesced} · " +
                    "rebind ${stats.dnsRebind} · 回落 ${stats.dnsFallback}（失败 ${stats.dnsFallbackFail} / 熔断 ${stats.dnsFallbackBreaker}）",
                fontSize = 11.sp,
                color = NamuColors.TextSub,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp),
            )
            DnsLatencyBars(stats)
            if (stats.dnsFallback > 0) {
                Text(
                    "备用查询：${stats.dnsFallback}（失败 ${stats.dnsFallbackFail} / 熔断 ${stats.dnsFallbackBreaker} / " +
                        "竞速 ${stats.dnsFallbackRace} / 复核 ${stats.dnsFallbackReview}）",
                    fontSize = 11.sp,
                    color = NamuColors.TextSub,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp),
                )
            }
            val privateDnsBypass = remember(runtime.connected) { PrivateDnsController.bypassing(ctx) }
            if (runtime.connected && stats.dnsQueries == 0L && stats.uptime > 30_000) {
                Text(
                    if (privateDnsBypass) {
                        "已拦截 DoT 853，但 30 秒内仍无 DNS 进入内核。strict 模式不会回落，需手动关闭私人 DNS；opportunistic 可再等几秒或重连。"
                    } else {
                        "已连接但没有任何 DNS 查询进入内核，应用可能在用 DoH / HTTPDNS 绕过，或 DoT 仍在重试。"
                    },
                    fontSize = 12.sp,
                    color = NamuColors.Orange,
                    modifier = Modifier
                        .clickable {
                            scope.launch {
                                val ok = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                                    PrivateDnsController.disable(ctx.applicationContext)
                                }
                                if (ok) {
                                    vm.showMessage("已关闭私人 DNS，正在重连")
                                    onRestart()
                                } else {
                                    vm.showMessage("Root 授权失败，已打开系统私人 DNS 设置")
                                    runCatching {
                                        ctx.startActivity(
                                            Intent("android.settings.PRIVATE_DNS_SETTINGS")
                                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                                        )
                                    }
                                }
                            }
                        }
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                )
            }
        }

        if (cfg.mitm.enabled || stats.mitmConns > 0) {
            SectionHeader("MITM 去广告")
            GroupCard {
                Row(Modifier.fillMaxWidth().padding(vertical = 16.dp)) {
                    DataMetric("解密连接", stats.mitmConns.toString(), Modifier.weight(1f))
                    DataMetric("拒绝请求", stats.mitmRejected.toString(), Modifier.weight(1f))
                    DataMetric("改写响应", stats.mitmRewritten.toString(), Modifier.weight(1f))
                }
                Text(
                    "握手失败放行 ${stats.mitmFailed} · QUIC 拦截回落 TCP ${stats.mitmQuicBlocked} · " +
                        if (cfg.mitm.enabled) "MITM 已启用" else "MITM 未启用",
                    fontSize = 11.sp,
                    color = NamuColors.TextSub,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp),
                )
            }
        }

        if (cfg.rules.any { AppUidResolver.isAppRule(it) } || stats.uidResolved > 0 || stats.uidUnknown > 0) {
            SectionHeader("按 App 分流")
            GroupCard {
                Row(Modifier.fillMaxWidth().padding(vertical = 16.dp)) {
                    DataMetric("已识别归属", stats.uidResolved.toString(), Modifier.weight(1f))
                    DataMetric("归属未知", stats.uidUnknown.toString(), Modifier.weight(1f))
                    DataMetric("下发条目", UidTablePublisher.lastCount.toString(), Modifier.weight(1f))
                }
                // 归属未知持续增长 = 规则不生效，必须让人看见原因而不是以为已经生效。
                val hint = when {
                    UidTablePublisher.lastError != null -> UidTablePublisher.lastError!!
                    stats.uidUnknown > 0 -> "部分连接查不到归属：请确认已授予 Root，UID 规则只对查到的连接生效"
                    else -> "规则只对归属识别成功的连接生效"
                }
                Text(
                    hint,
                    fontSize = 11.sp,
                    color = NamuColors.TextSub,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp),
                )
            }
        }

        SectionHeader("诊断")
        GroupCard {
            SettingsRow(
                title = "命中诊断",
                subtitle = "输入域名或 IPv4，按当前配置和模块规则展示命中结果",
                chevron = true,
                onClick = { showRuleTest = true },
            )
            SettingsRow(
                title = "同步规则源",
                subtitle = if (cfg.rulesUrl.isBlank()) {
                    "当前配置没有设置 rulesUrl"
                } else {
                    "下载 ${cfg.rulesUrl.substringAfterLast('/').take(32)} 并重载内核"
                },
                chevron = true,
                onClick = {
                    if (cfg.rulesUrl.isBlank()) {
                        vm.showMessage("当前配置没有 rulesUrl")
                    } else {
                        scope.launch {
                            val n = vm.syncRules()
                            if (n != null && runtime.connected) NamuVpnService.reload(ctx)
                        }
                    }
                },
            )
            SettingsRow(
                title = "导出诊断报告",
                subtitle = "日志、内核版本、运行时长、请求数、缓存命中率、DNS 延迟分布和内存统计",
                chevron = true,
                showDivider = false,
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
        }

        SectionHeader("连接")
        GroupCard {
            val net = NetworkStatus.current(ctx)
            SettingsRow(
                title = "实时连接",
                subtitle = "逐连接五元组、归属应用、动作与命中规则",
                value = "${stats.activeConns} 活跃",
                chevron = true,
                onClick = { showLive = true },
            )
            SettingsRow(
                title = "当前网络",
                subtitle = net.detail,
                value = net.label,
            )
            SettingsRow(
                title = "状态",
                value = when {
                    runtime.stopping -> "正在关闭…"
                    runtime.connected -> "已连接"
                    else -> "未连接"
                },
                valueColor = when {
                    runtime.stopping -> NamuColors.Orange
                    runtime.connected -> NamuColors.Green
                    else -> NamuColors.TextSub
                },
            )
            SettingsRow(
                title = "服务器",
                value = container.nodeLabel(),
            )
            SettingsRow(
                title = "全局路由",
                value = when (cfg.mode) {
                    "global" -> "代理"
                    "dns_only" -> "直连"
                    "filter_only" -> "纯过滤"
                    else -> "配置"
                },
                showDivider = false,
            )
        }

        SectionHeader("日志")
        GroupCard {
            SettingsRow(
                title = "自动删除",
                subtitle = "每次连接前清空上一次的运行日志与 DNS 记录",
                icon = Icons.Rounded.History,
                rightContent = {
                    IosSwitch(
                        checked = cfg.autoClearLogs,
                        onCheckedChange = {
                            vm.setAutoClearLogs(it)
                        },
                    )
                },
            )
            SettingsRow(
                title = "DNS 查询",
                subtitle = "域名、拦截/放行、缓存或上游、耗时",
                value = "${state.logs.dns.size} 条",
                chevron = true,
                onClick = onOpenDnsLogs,
            )
            SettingsRow(
                title = "运行日志",
                subtitle = "DNS、规则匹配与连接记录",
                value = "${state.logs.runtime.size} 条",
                chevron = true,
                showDivider = false,
                onClick = onOpenLogs,
            )
        }

        SectionHeader("服务器节点")
        GroupCard {
            SettingsRow(
                title = "导入节点…",
                subtitle = "从订阅链接、Base64 或 Clash 配置导入",
                icon = Icons.Rounded.FileDownload,
                chevron = true,
                onClick = onOpenNodes,
            )
            SettingsRow(
                title = "导出节点",
                subtitle = "把当前 ${cfg.nodes.size} 个节点链接复制到剪贴板",
                icon = Icons.Rounded.FileUpload,
                chevron = false,
                onClick = {
                    val text = cfg.nodes.joinToString("\n") { it.shareLink() }
                    if (text.isBlank()) {
                        vm.showMessage("还没有可导出的节点")
                    } else {
                        clipboard.setText(AnnotatedString(text))
                        vm.showMessage("已复制 ${cfg.nodes.size} 个节点链接")
                    }
                },
            )
            SettingsRow(
                title = "删除所有节点",
                icon = Icons.Rounded.Delete,
                iconTint = NamuColors.Red,
                chevron = false,
                showDivider = false,
                onClick = {
                    if (cfg.nodes.isEmpty()) vm.showMessage("当前没有节点")
                    else confirmDeleteAll = true
                },
            )
        }

        FooterText("流量统计从本次 VPN 连接开始累计；断开后保留最后一次会话统计，下次连接时重置。")
        Spacer(Modifier.height(LocalDockClearance.current + 34.dp))
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
    if (showRuleTest) {
        RuleTestDialog(onDismiss = { showRuleTest = false })
    }
    if (confirmDeleteAll) {
        AlertDialog(
            onDismissRequest = { confirmDeleteAll = false },
            title = { Text("删除所有节点？") },
            text = { Text("将清空当前 ${cfg.nodes.size} 个服务器节点，订阅链接和配置不受影响。") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDeleteAll = false
                    vm.clearAllNodes()
                    if (runtime.connected) onRestart()
                    vm.showMessage("已删除所有节点")
                }) { Text("删除", color = NamuColors.Red) }
            },
            dismissButton = {
                TextButton(onClick = { confirmDeleteAll = false }) { Text("取消") }
            },
        )
    }
}

@Composable
private fun DataMetric(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, fontSize = 21.sp, fontWeight = FontWeight.SemiBold, color = NamuColors.TextMain)
        Spacer(Modifier.height(3.dp))
        Text(label, fontSize = 12.sp, color = NamuColors.TextSub)
    }
}


private fun formatUptime(ms: Long): String {
    if (ms <= 0L) return "-"
    val totalSec = ms / 1000L
    val h = totalSec / 3600
    val m = (totalSec % 3600) / 60
    val sec = totalSec % 60
    return if (h > 0) "${h}h ${m}m" else if (m > 0) "${m}m ${sec}s" else "${sec}s"
}
