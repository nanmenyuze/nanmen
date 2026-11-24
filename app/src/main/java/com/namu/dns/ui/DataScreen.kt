package com.namu.dns.ui

import com.namu.dns.core.LocalDockClearance
import com.namu.dns.AppUidResolver
import com.namu.dns.UidTablePublisher

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Insights
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
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
import com.namu.dns.core.config.RoutingMode
import com.namu.dns.core.repository.HitsUiState
import com.namu.dns.core.repository.ShellPhase
import com.namu.dns.core.repository.windowPoints
import com.namu.dns.ui.viewmodel.DataViewModel
import kotlinx.coroutines.launch

@Composable
fun DataScreen(
    onOpenLogs: () -> Unit,
    onOpenDnsLogs: () -> Unit,
    onRestart: () -> Unit,
    onStartVpn: () -> Unit = {},
) {
    val container = LocalAppContainer.current
    val vm: DataViewModel = viewModel(factory = DataViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val stats = state.stats.stats
    val cfg = state.config
    val runtime = state.runtime
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
        SectionHeader("DNS 过滤与查询统计")
        HitWindowSelector(selected = state.hits.windowHours) { vm.setHitWindow(it) }
        GroupCard {
            HitAnalytics(
                state = state.hits,
                onRetry = { vm.repairHits() },
                onStartVpn = onStartVpn,
                onHistoryEnabled = { vm.setHitHistoryEnabled(it) },
                onClear = { vm.clearHits() },
            )
        }

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
                "判别：接收满 ${msToText(stats.tcpRecvFull)} · 发送停滞 ${msToText(stats.tcpSendStalled)} · " +
                    "QUIC 黑洞 ${stats.quicBlackholed} · 丢弃 ${stats.quicFallback} · " +
                    "大档 ${stats.bigTierInUse}/128 · 缓冲拒绝 ${stats.tcpBufferDenied}",
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
                        "正文提前直通 ${stats.mitmBodyBypassed} · " +
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
            val observesConnections = cfg.mode != "dns_only" || cfg.dnsOnlyFullRoute
            SettingsRow(
                title = "实时连接",
                subtitle = if (observesConnections) "查看连接、归属应用和命中规则"
                    else "仅系统 DNS 模式不采集普通连接",
                value = if (observesConnections) "${stats.activeConns} 活跃" else null,
                chevron = observesConnections,
                onClick = if (observesConnections) ({ showLive = true }) else null,
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
                title = "运行模式",
                value = RoutingMode.fromConfig(cfg.mode).title,
                showDivider = false,
            )
        }

        SectionHeader("日志")
        GroupCard {
            SettingsRow(
                title = "自动删除",
                subtitle = "每次连接前清空上一次的运行日志与 DNS 记录",
                icon = Icons.Outlined.History,
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

/** 判别仪表是「条件成立期间累计毫秒」，这里换算成秒，避免大数字看不出量级。 */
private fun msToText(ms: Long): String =
    if (ms < 1000) "${ms}ms" else "%.1fs".format(ms / 1000.0)



@Composable
private fun HitWindowSelector(selected: Int, onSelect: (Int) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 2.dp)
            .heightIn(min = 48.dp)
            .background(NamuColors.Fill, RoundedCornerShape(12.dp))
            .padding(3.dp),
    ) {
        listOf(24 to "24 小时", 168 to "7 天").forEach { (hours, label) ->
            val active = selected == hours
            Box(
                Modifier.weight(1f).heightIn(min = 42.dp)
                    .clip(RoundedCornerShape(9.dp))
                    .background(if (active) NamuColors.Card else androidx.compose.ui.graphics.Color.Transparent)
                    .clickable { onSelect(hours) },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label,
                    fontSize = 13.sp,
                    fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal,
                    color = if (active) NamuColors.Brand else NamuColors.TextSub,
                )
            }
        }
    }
}

@Composable
private fun HitAnalytics(
    state: HitsUiState,
    onRetry: () -> Unit,
    onStartVpn: () -> Unit,
    onHistoryEnabled: (Boolean) -> Unit,
    onClear: () -> Unit,
) {
    when (state.phase) {
        ShellPhase.LOADING -> NamuLoadingPanel("正在读取命中历史…")
        ShellPhase.EMPTY -> NamuEmptyPanel(
            title = if (state.needsVpnGuide) "先启动 VPN" else "本窗口暂无查询",
            body = if (state.needsVpnGuide) {
                "启动后只在本机保存域名、模块与时间；不保存 path、query、body、headers。"
            } else {
                "当前窗口没有查询；最近命中仍保留在本机，可随时清空。"
            },
            action = if (state.needsVpnGuide) "启动 VPN" else null,
            onAction = if (state.needsVpnGuide) onStartVpn else null,
            icon = Icons.Outlined.Insights,
        )
        ShellPhase.ERROR -> NamuErrorPanel(state.message, onRetry = onRetry)
        ShellPhase.SUCCESS -> {
            val win = state.window
            val points = windowPoints(state.snapshot, win, days = state.windowHours >= 168)
            Row(Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 8.dp)) {
                DataMetric(win.queries.toString(), "查询", Modifier.weight(1f))
                DataMetric(win.blocked.toString(), "已拦截", Modifier.weight(1f))
            }
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                NamuIcon(Icons.Outlined.Insights, tint = NamuColors.Brand, size = 18.dp)
                Spacer(Modifier.width(6.dp))
                Text(
                    if (state.windowHours >= 168) "近 7 天 DNS 查询趋势" else "近 24 小时 DNS 查询趋势",
                    fontSize = 12.sp, color = NamuColors.TextSub, modifier = Modifier.weight(1f),
                )
                Text("峰值 ${points.maxOfOrNull { it.queries } ?: 0L}", fontSize = 12.sp, color = NamuColors.TextMain)
            }
            HitTrendChart(points, Modifier.fillMaxWidth().height(132.dp).padding(horizontal = 16.dp, vertical = 6.dp))
            Row(Modifier.fillMaxWidth().padding(horizontal = 18.dp)) {
                Text(points.firstOrNull()?.label ?: "—", fontSize = 10.sp, color = NamuColors.TextTertiary)
                Spacer(Modifier.weight(1f))
                Text(points.lastOrNull()?.label ?: "—", fontSize = 10.sp, color = NamuColors.TextTertiary)
            }
            if (win.queries == 0L) {
                Text(
                    "本窗口暂无查询",
                    modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
                    fontSize = 12.sp, color = NamuColors.TextSub, textAlign = TextAlign.Center,
                )
            }
            RowDivider(16.dp)
            val cacheRate = win.cacheRate
            Column(Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("缓存命中率", style = NamuTokens.Type.Body, modifier = Modifier.weight(1f))
                    Text(cacheRate.percent(), style = NamuTokens.Type.Title, color = NamuColors.TextMain)
                }
                if (cacheRate != null) {
                    val fraction = cacheRate.toFloat().coerceIn(0f, 1f)
                    Box(Modifier.fillMaxWidth().padding(top = 7.dp).height(5.dp).background(
                        NamuColors.TrackOff, RoundedCornerShape(8.dp),
                    )) {
                        if (fraction > 0f) {
                            Box(Modifier.fillMaxWidth(fraction).height(5.dp).background(
                                NamuColors.Brand, RoundedCornerShape(8.dp),
                            ))
                        }
                    }
                }
                Text(
                    "${win.cacheHit} / ${win.cacheLookups} 次缓存查询 · 拦截率 ${win.blockedRate.percent()}",
                    style = NamuTokens.Type.Caption,
                    color = NamuColors.TextSub,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
            if (win.perSource.isNotEmpty()) {
                RowDivider(16.dp)
                Text(
                    "按模块分布",
                    modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 4.dp),
                    fontSize = 12.sp, color = NamuColors.TextSub,
                )
                val max = win.perSource.maxOfOrNull { it.windowHits }?.coerceAtLeast(1L) ?: 1L
                win.perSource.take(6).forEach { row ->
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            row.sourceName.ifBlank { "未归因" },
                            fontSize = 12.sp, color = NamuColors.TextMain,
                            maxLines = 1, overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.width(120.dp),
                        )
                        Box(
                            Modifier.weight(1f).height(5.dp).clip(RoundedCornerShape(50))
                                .background(NamuColors.Fill),
                        ) {
                            Box(
                                Modifier.fillMaxWidth((row.windowHits.toFloat() / max).coerceIn(0.02f, 1f))
                                    .height(5.dp).clip(RoundedCornerShape(50))
                                    .background(NamuColors.Brand),
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        Text("${row.windowHits}", fontSize = 11.sp, color = NamuColors.TextSub)
                    }
                }
            }
            RowDivider(16.dp)
            Row(
                Modifier.fillMaxWidth().heightIn(min = 52.dp).padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("记录命中摘要", fontSize = 13.sp, color = NamuColors.TextMain)
                    Text("只存域名、模块、时间；可关闭，关闭后不再写盘。", fontSize = 11.sp, color = NamuColors.TextSub)
                }
                IosSwitch(checked = state.historyEnabled, onCheckedChange = onHistoryEnabled)
                MiniTextAction("清空", color = NamuColors.Red) { onClear() }
            }
        }
    }
}

@Composable
private fun HitTrendChart(points: List<com.namu.dns.core.repository.DayPoint>, modifier: Modifier = Modifier) {
    if (points.isEmpty()) {
        Box(modifier, contentAlignment = Alignment.Center) {
            Text("暂无趋势数据", fontSize = 12.sp, color = NamuColors.TextTertiary)
        }
        return
    }
    val max = points.maxOf { it.queries }.coerceAtLeast(1L)
    Canvas(modifier) {
        val pad = 4f
        val w = size.width
        val h = size.height
        val step = if (points.size <= 1) 0f else (w - pad * 2) / (points.size - 1)
        repeat(3) { i ->
            val y = pad + (h - pad * 2) * i / 2f
            drawLine(
                NamuColors.Separator.copy(alpha = 0.7f),
                Offset(0f, y),
                Offset(w, y),
                strokeWidth = 1f,
            )
        }
        val line = Path()
        points.forEachIndexed { i, p ->
            val x = if (points.size == 1) w / 2 else pad + step * i
            val y = h - pad - (h - pad * 2) * (p.queries.toFloat() / max)
            if (i == 0) line.moveTo(x, y) else line.lineTo(x, y)
        }
        val area = Path().apply {
            addPath(line)
            lineTo(pad + step * (points.size - 1), h - pad)
            lineTo(pad, h - pad)
            close()
        }
        if (points.size > 1) drawPath(area, NamuColors.Brand.copy(alpha = 0.12f))
        drawPath(line, NamuColors.Brand, style = Stroke(width = 2f))
        points.forEachIndexed { i, p ->
            if (p.queries <= 0L) return@forEachIndexed
            val x = if (points.size == 1) w / 2 else pad + step * i
            val y = h - pad - (h - pad * 2) * (p.queries.toFloat() / max)
            drawCircle(NamuColors.Brand, radius = 2.4f, center = Offset(x, y))
        }
    }
}

private fun Number?.percent(): String = this?.let { "${(it.toDouble() * 100).toInt()}%" } ?: "—"
