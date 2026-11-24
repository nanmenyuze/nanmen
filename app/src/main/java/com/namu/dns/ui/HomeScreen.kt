package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.outlined.ArrowDownward
import androidx.compose.material.icons.outlined.ArrowUpward
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Insights
import androidx.compose.material.icons.outlined.Router
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.NetworkStatus
import com.namu.dns.PrivateDnsController
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.LocalDockClearance
import com.namu.dns.core.config.RoutingMode
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
    onOpenDnsLogs: () -> Unit,
    onOpenData: () -> Unit,
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
    val hitSummary = when (hits.phase) {
        ShellPhase.LOADING -> "正在读取"
        ShellPhase.ERROR -> "统计暂不可用"
        ShellPhase.EMPTY -> "暂无命中"
        ShellPhase.SUCCESS -> {
            val period = if (hits.windowHours >= 168) "近 7 天" else "近 24 小时"
            "$period · ${hits.window.blocked} 次"
        }
    }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val privateDnsBypass = remember(connected) { PrivateDnsController.bypassing(context) }
    val selectedNode = remember(cfg.nodes, cfg.selected) {
        cfg.nodes.firstOrNull { it.name == cfg.selected } ?: cfg.nodes.firstOrNull()
    }
    val selectedLatency = selectedNode?.latency ?: 0L
    val mode = RoutingMode.fromConfig(cfg.mode)
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
        else -> "已连接 · 过滤关闭"
    }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(Modifier.widthIn(max = 560.dp).fillMaxWidth().padding(top = 4.dp)) {
            val sessionActive = connected && state.stats.sessionActive
            WorkbenchStatusCard(
                status = status,
                mode = mode,
                modeEnabled = !starting && !stopping,
                connected = connected && !stopping,
                onModeChange = { selected ->
                    val current = container.settings.current()
                    if (container.settings.applyRouting(selected.modeFor(current.mode), current.dnsOnlyFullRoute) &&
                        container.runtime.current().connected
                    ) onRestart()
                },
                uptime = if (sessionActive) {
                    val seconds = stats.uptime / 1000
                    "%02d:%02d:%02d".format(seconds / 3600, seconds / 60 % 60, seconds % 60)
                } else null,
                upload = if (sessionActive) "${formatBytes(state.stats.upRate)}/s" else "—",
                download = if (sessionActive) "${formatBytes(state.stats.downRate)}/s" else "—",
                checked = connected || starting,
                enabled = !stopping,
                onToggle = onToggle,
            )

            Column(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    HomeShortcutCard(
                        title = "拦截命中",
                        subtitle = hitSummary,
                        icon = Icons.Outlined.Insights,
                        modifier = Modifier.weight(1f),
                        onClick = onOpenData,
                    )
                    HomeShortcutCard(
                        title = "节点与订阅",
                        subtitle = when {
                            selectedNode == null -> "未添加节点"
                            mode == RoutingMode.Direct -> "${cfg.nodes.size} 个节点"
                            selectedLatency > 0 -> "${selectedNode.name} · $selectedLatency ms"
                            else -> selectedNode.name
                        },
                        icon = Icons.Outlined.Router,
                        modifier = Modifier.weight(1f),
                        onClick = onOpenNodes,
                    )
                }
                Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    HomeShortcutCard(
                        title = "DNS 记录",
                        icon = Icons.Outlined.Dns,
                        modifier = Modifier.weight(1f),
                        onClick = onOpenDnsLogs,
                    )
                    HomeShortcutCard(
                        title = "当前网络",
                        subtitle = network.label,
                        icon = Icons.Outlined.Wifi,
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            if (connected && privateDnsBypass && stats.dnsQueries == 0L && stats.uptime > 30_000) {
                GroupCard {
                    SettingsRow(
                        title = "私人 DNS 正在绕过内核",
                        subtitle = "30 秒内未收到 DNS 查询，点此处理。",
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
                        subtitle = "代理流量会回退直连，点此添加节点。",
                        icon = Icons.Outlined.Info,
                        chevron = true,
                        showDivider = false,
                        onClick = onOpenNodes,
                    )
                }
            }

            Spacer(Modifier.height(LocalDockClearance.current + 20.dp))
        }
    }
}

private val RoutingMode.homeLabel: String
    get() = when (this) {
        RoutingMode.Direct -> "仅过滤"
        RoutingMode.Rules -> "自动分流"
        RoutingMode.Proxy -> "全局代理"
    }

private val homeAccent: Color
    get() = if (NamuColors.isDark) Color(0xFF9BBFFF) else NamuColors.Brand

@Composable
private fun WorkbenchStatusCard(
    status: String,
    mode: RoutingMode,
    modeEnabled: Boolean,
    connected: Boolean,
    uptime: String?,
    upload: String,
    download: String,
    checked: Boolean,
    enabled: Boolean,
    onModeChange: (RoutingMode) -> Unit,
    onToggle: () -> Unit,
) {
    val shape = RoundedCornerShape(24.dp)
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp)
            .clip(shape)
            .background(
                Brush.linearGradient(
                    listOf(NamuColors.Card, NamuColors.Card, if (NamuColors.isDark) Color(0xFF202938) else Color(0xFFF3F7FF)),
                ),
            )
            .border(1.dp, NamuColors.Separator, shape)
            .padding(start = 18.dp, end = 18.dp, top = 12.dp, bottom = 16.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            HomeRoutingPicker(mode, modeEnabled, onModeChange)
            IosSwitch(checked = checked, onCheckedChange = { onToggle() }, enabled = enabled)
        }
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(7.dp).background(
                    if (connected) NamuColors.Green else NamuColors.TextTertiary,
                    CircleShape,
                ),
            )
            Spacer(Modifier.width(8.dp))
            Text(status, style = NamuTokens.Type.Title, color = NamuColors.TextMain)
        }
        Text(
            uptime ?: "—",
            modifier = Modifier.padding(top = 2.dp),
            style = NamuTokens.Type.Display.copy(fontSize = 38.sp, lineHeight = 44.sp, fontFeatureSettings = "tnum"),
            color = if (uptime != null) NamuColors.TextMain else NamuColors.TextTertiary,
            maxLines = 1,
        )
        Text("运行时长", style = NamuTokens.Type.Caption, color = NamuColors.TextSub)
        Spacer(Modifier.height(16.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            NetworkRateTile("上传", upload, Icons.Outlined.ArrowUpward, Modifier.weight(1f))
            NetworkRateTile("下载", download, Icons.Outlined.ArrowDownward, Modifier.weight(1f))
        }
    }
}

@Composable
private fun HomeRoutingPicker(mode: RoutingMode, enabled: Boolean, onModeChange: (RoutingMode) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        Box(
            Modifier.heightIn(min = 48.dp)
                .clip(RoundedCornerShape(12.dp))
                .clickable(enabled = enabled, onClickLabel = "切换流量模式", role = Role.Button) { expanded = true },
            contentAlignment = Alignment.CenterStart,
        ) {
            Row(
                Modifier.clip(RoundedCornerShape(50)).background(NamuColors.Brand.copy(alpha = 0.09f))
                    .padding(start = 12.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(mode.homeLabel, style = NamuTokens.Type.Caption, fontWeight = FontWeight.SemiBold, color = homeAccent)
                NamuIcon(Icons.Filled.ArrowDropDown, tint = homeAccent, size = 18.dp)
            }
        }
        DropdownMenu(expanded = expanded && enabled, onDismissRequest = { expanded = false }) {
            RoutingMode.entries.forEach { option ->
                DropdownMenuItem(
                    text = {
                        Text(option.homeLabel, color = if (option == mode) homeAccent else NamuColors.TextMain)
                    },
                    onClick = {
                        expanded = false
                        onModeChange(option)
                    },
                )
            }
        }
    }
}

@Composable
private fun NetworkRateTile(label: String, rate: String, icon: ImageVector, modifier: Modifier) {
    val shape = RoundedCornerShape(12.dp)
    Column(
        modifier.clip(shape).background(NamuColors.Card)
            .border(1.dp, NamuColors.Separator, shape)
            .padding(horizontal = 12.dp, vertical = 9.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            NamuIcon(icon, tint = homeAccent, size = 14.dp)
            Spacer(Modifier.width(4.dp))
            Text(label, style = NamuTokens.Type.Caption, color = NamuColors.TextSub)
        }
        Text(
            rate,
            style = NamuTokens.Type.Body.copy(fontFeatureSettings = "tnum"),
            fontWeight = FontWeight.SemiBold,
            color = NamuColors.TextMain,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun HomeShortcutCard(
    title: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    onClick: (() -> Unit)? = null,
) {
    val shape = RoundedCornerShape(16.dp)
    Column(
        modifier.fillMaxHeight().heightIn(min = 106.dp)
            .clip(shape)
            .background(NamuColors.Card)
            .border(1.dp, NamuColors.Separator, shape)
            .then(if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier)
            .padding(horizontal = 13.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier.size(32.dp).clip(RoundedCornerShape(10.dp))
                    .background(NamuColors.Brand.copy(alpha = 0.09f)),
                contentAlignment = Alignment.Center,
            ) {
                NamuIcon(icon, tint = homeAccent, size = 18.dp)
            }
            if (onClick != null) Chevron()
        }
        Column {
            Text(title, style = NamuTokens.Type.Body, fontWeight = FontWeight.SemiBold, color = NamuColors.TextMain)
            if (subtitle != null) {
                Text(
                    subtitle,
                    style = NamuTokens.Type.Caption,
                    color = NamuColors.TextSub,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}
