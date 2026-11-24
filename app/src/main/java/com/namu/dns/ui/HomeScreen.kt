package com.namu.dns.ui

import com.namu.dns.core.LocalDockClearance

import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Layers
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material.icons.outlined.Router
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.NetworkStatus
import com.namu.dns.PrivateDnsController
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.repository.RecentHit
import com.namu.dns.core.repository.ShellPhase
import com.namu.dns.ui.viewmodel.HomeViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Suppress("ProduceStateDoesNotAssignValue")
@Composable
fun HomeScreen(
    onToggle: () -> Unit,
    onOpenNodes: () -> Unit,
    onRestart: () -> Unit,
    onOpenData: () -> Unit = {},
    onOpenConfig: () -> Unit,
    onOpenModules: () -> Unit,
    onOpenMitm: () -> Unit,
) {
    val container = LocalAppContainer.current
    val vm: HomeViewModel = viewModel(factory = HomeViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val cfg = state.config
    val connected = state.runtime.connected
    val stopping = state.runtime.stopping
    val starting = state.runtime.starting
    val stats = state.stats.stats
    val hits = state.hits
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val privateDnsBypass = remember(connected) { PrivateDnsController.bypassing(context) }
    val selectedNode = remember(cfg.nodes, cfg.selected) {
        cfg.nodes.firstOrNull { it.name == cfg.selected } ?: cfg.nodes.firstOrNull()
    }

    val network by produceState(NetworkStatus.current(context), context) {
        while (true) {
            delay(2_500)
            value = NetworkStatus.current(context)
        }
    }

    val status = when {
        stopping -> "正在停止"
        starting -> "正在启动"
        !connected -> "未连接"
        !state.stats.sessionActive || stats.dnsQueries == 0L -> "等待 DNS 查询"
        cfg.blockEnabled -> "过滤运行中"
        else -> "DNS 已接管"
    }
    val statusSub = when {
        stopping -> "等待 VPN 隧道关闭"
        starting -> "正在建立 VPN 隧道"
        !connected -> "打开开关启动 VPN"
        !cfg.blockEnabled -> "VPN 已连接 · 广告过滤关闭"
        else -> "本机处理 DNS，不上传请求内容"
    }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        WorkbenchStatusCard(
            status = status,
            subtitle = if (connected && !stopping && state.stats.sessionActive) {
                val seconds = stats.uptime / 1000
                "已运行 %02d:%02d:%02d".format(seconds / 3600, seconds / 60 % 60, seconds % 60)
            } else statusSub,
            checked = connected || starting,
            enabled = !stopping,
            onToggle = onToggle,
        )

        SectionHeader("配置与代理")
        GroupCard {
            SettingsRow(
                title = "当前配置",
                value = container.config.activeName(),
                icon = Icons.Outlined.Description,
                chevron = true,
                onClick = onOpenConfig,
            )
            SettingsRow(
                title = "代理",
                subtitle = buildString {
                    append(
                        when (cfg.mode) {
                            "dns_only" -> "仅系统 DNS"
                            "filter_only" -> "仅过滤"
                            "global" -> "全局代理"
                            else -> "自动分流"
                        },
                    )
                    append(" · ${cfg.nodes.size} 个节点")
                    val ms = selectedNode?.latency ?: 0L
                    if (ms > 0L) append(" · $ms ms")
                },
                value = when {
                    cfg.mode == "dns_only" || cfg.mode == "filter_only" -> "未使用代理"
                    selectedNode == null -> "未配置"
                    else -> selectedNode.name
                },
                icon = Icons.Outlined.Router,
                chevron = true,
                onClick = onOpenNodes,
            )
            SettingsRow(
                title = "已启用模块",
                value = cfg.moduleSources.count { it.enabled }.toString(),
                icon = Icons.Outlined.Layers,
                chevron = true,
                onClick = onOpenModules,
            )
            SettingsRow(
                title = "当前网络",
                value = network.label,
                icon = Icons.Outlined.Wifi,
            )
            SettingsRow(
                title = "证书与 HTTPS 过滤",
                value = if (cfg.mitm.enabled) "已启用" else "未启用",
                icon = Icons.Outlined.Shield,
                chevron = true,
                showDivider = false,
                onClick = onOpenMitm,
            )
        }

        if (hits.phase == ShellPhase.EMPTY && hits.needsVpnGuide) {
            GroupCard {
                NamuEmptyPanel(
                    title = "先启动 VPN",
                    body = "启动后只在本机记录域名、模块和时间；不保存 path / query / body / headers。",
                    action = "启动 VPN",
                    onAction = onToggle,
                    icon = Icons.Outlined.Shield,
                    modifier = Modifier.padding(vertical = 2.dp),
                )
            }
        } else if (hits.phase == ShellPhase.ERROR) {
            GroupCard {
                NamuErrorPanel(hits.message, onRetry = { vm.retryHits() })
            }
        }

        // 未启动时只保留一张授权空态，避免连续两张「没有命中」重复。
        if (!(hits.phase == ShellPhase.EMPTY && hits.needsVpnGuide)) {
        SectionHeader("最近命中", trailing = {
            MiniTextAction("查看全部", onClick = onOpenData)
        })
        GroupCard {
            when {
                hits.phase == ShellPhase.LOADING -> NamuLoadingPanel("正在读取最近命中…")
                hits.phase == ShellPhase.ERROR -> NamuErrorPanel(hits.message, onRetry = { vm.retryHits() })
                hits.snapshot.ring.isEmpty() -> NamuEmptyPanel(
                    title = if (connected) "这个窗口还没有查询" else "启动 VPN 后这里会出现命中",
                    body = "最近命中最长保留 3 条展示；完整列表在数据页。",
                    icon = Icons.Outlined.Dns,
                )
                else -> {
                    val recent = hits.snapshot.ring.take(3)
                    recent.forEachIndexed { index, hit ->
                        RecentHitRow(hit, showDivider = index != recent.lastIndex)
                    }
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 42.dp).padding(horizontal = 16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        NamuIcon(Icons.Outlined.Info, tint = NamuColors.TextTertiary, size = 16.dp)
                        Spacer(Modifier.width(6.dp))
                        Text(
                            "仅记录域名、模块与时间；请求记录默认关。",
                            style = NamuTokens.Type.Caption,
                            color = NamuColors.TextSub,
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
        }

        }

        if (connected && privateDnsBypass && stats.dnsQueries == 0L && stats.uptime > 30_000) {
            GroupCard {
                SettingsRow(
                    title = "私人 DNS 正在绕过内核",
                    subtitle = "内核已拦截 ${PrivateDnsController.specifier(context).ifBlank { "上游" }} 的 DoT 853，" +
                        "但 30 秒内没有 DNS 进入。strict 模式不会回落，需要手动关闭；opportunistic 可再等几秒。",
                    icon = Icons.Outlined.Info,
                    chevron = true,
                    showDivider = false,
                    onClick = {
                        scope.launch {
                            val ok = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                                PrivateDnsController.disable(context.applicationContext)
                            }
                            if (ok) {
                                vm.showMessage("已关闭私人 DNS，正在重连")
                                onRestart()
                            } else {
                                vm.showMessage("Root 授权失败，已打开系统私人 DNS 设置")
                                runCatching {
                                    context.startActivity(
                                        android.content.Intent("android.settings.PRIVATE_DNS_SETTINGS")
                                            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
                                    )
                                }
                            }
                        }
                    },
                )
            }
        }

        if (cfg.nodes.isEmpty() && cfg.mode != "filter_only" && cfg.mode != "dns_only" &&
            (cfg.mode == "global" || cfg.finalPolicy == "proxy")
        ) {
            GroupCard {
                SettingsRow(
                    title = "没有可用节点",
                    subtitle = "当前为 ${if (cfg.mode == "global") "全局代理" else "代理优先"}，" +
                        "所有需要代理的流量都会退回直连。点此添加节点。",
                    icon = Icons.Outlined.Info,
                    chevron = true,
                    showDivider = false,
                    onClick = onOpenNodes,
                )
            }
        }

        Spacer(Modifier.height(LocalDockClearance.current + 34.dp))
    }
}

@Composable
private fun WorkbenchStatusCard(
    status: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean,
    onToggle: () -> Unit,
) {
    GroupCard {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f).padding(end = 12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).background(
                        if (checked && enabled) NamuColors.Green else NamuColors.TextTertiary, CircleShape,
                    ))
                    Spacer(Modifier.width(10.dp))
                    Text(status, style = NamuTokens.Type.Title, color = NamuColors.TextMain)
                }
                Spacer(Modifier.height(2.dp))
                Text(subtitle, style = NamuTokens.Type.Caption, color = NamuColors.TextSub)
            }
            IosSwitch(checked = checked, onCheckedChange = { onToggle() }, enabled = enabled)
        }
    }
}

@Composable
private fun RecentHitRow(hit: RecentHit, showDivider: Boolean) {
    val blocked = hit.action.equals("block", ignoreCase = true) || hit.action.equals("reject", ignoreCase = true)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 58.dp).padding(horizontal = 16.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier.size(30.dp).clip(CircleShape).background(if (blocked) NamuColors.Red.copy(alpha = 0.10f) else NamuColors.Brand.copy(alpha = 0.10f)),
            contentAlignment = Alignment.Center,
        ) {
            NamuIcon(
                if (blocked) Icons.Outlined.Block else Icons.Outlined.CheckCircle,
                tint = if (blocked) NamuColors.Red else NamuColors.Brand,
                size = 17.dp,
            )
        }
        Spacer(Modifier.width(11.dp))
        Column(Modifier.weight(1f)) {
            Text(hit.domain.ifBlank { "未知域名" }, style = NamuTokens.Type.Body, color = NamuColors.TextMain, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Spacer(Modifier.height(2.dp))
            Text(
                "${hit.sourceName.ifBlank { "未归因" }} · ${formatAgo(hit.ts)}",
                style = NamuTokens.Type.Caption,
                color = NamuColors.TextSub,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(8.dp))
        PillBadge(if (blocked) "拦截" else "放行", if (blocked) NamuColors.Red else NamuColors.Green)
    }
    if (showDivider) RowDivider(52.dp)
}
