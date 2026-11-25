package com.namu.dns.ui

import androidx.compose.foundation.Canvas
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
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.outlined.ArrowDownward
import androidx.compose.material.icons.outlined.ArrowUpward
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Router
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.TrendingUp
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.MitmManager
import com.namu.dns.NetworkStatus
import com.namu.dns.PrivateDnsController
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.LocalDockClearance
import com.namu.dns.core.config.RoutingMode
import com.namu.dns.core.repository.ShellPhase
import com.namu.dns.ui.viewmodel.HomeViewModel
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Suppress("ProduceStateDoesNotAssignValue")
@Composable
fun HomeScreen(
    onToggle: () -> Unit,
    onOpenNodes: () -> Unit,
    onRestart: () -> Unit,
    onOpenDnsLogs: () -> Unit,
    onOpenData: () -> Unit,
    onOpenQuickEdit: () -> Unit,
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
    val certificateStatus by produceState("读取中", context, cfg.mitm.enabled) {
        value = withContext(Dispatchers.IO) {
            val caExists = MitmManager.caFile(context).exists()
            val der = MitmManager.caDer(context)
            val trusted = der != null && listOf(
                File("/apex/com.android.conscrypt/cacerts"),
                File("/system/etc/security/cacerts"),
            ).any { dir ->
                dir.listFiles()?.any { file ->
                    file.isFile && file.name.endsWith(".0") &&
                        MitmManager.systemCertDerMatches(file, der)
                } == true
            }
            when {
                trusted -> "已就绪"
                caExists -> "未信任"
                else -> "未生成"
            }
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
        Column(Modifier.widthIn(max = 560.dp).fillMaxWidth()) {
            Row(
                Modifier.fillMaxWidth().statusBarsPadding()
                    .padding(start = 20.dp, end = 16.dp, top = 16.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    "南门 DNS",
                    fontSize = 28.sp,
                    lineHeight = 34.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (NamuColors.isDark) Color(0xFFFFA45E) else Color(0xFFEF7D22),
                )
                HomeRoutingPicker(
                    mode = mode,
                    enabled = !starting && !stopping,
                    onModeChange = { selected ->
                        val current = container.settings.current()
                        if (container.settings.applyRouting(selected.modeFor(current.mode), current.dnsOnlyFullRoute) &&
                            container.runtime.current().connected
                        ) onRestart()
                    },
                )
            }

            val sessionActive = connected && state.stats.sessionActive
            WorkbenchStatusCard(
                status = status,
                connected = connected && !stopping,
                uptime = if (sessionActive) {
                    val seconds = stats.uptime / 1000
                    "%02d:%02d:%02d".format(seconds / 3600, seconds / 60 % 60, seconds % 60)
                } else null,
                upload = if (sessionActive) "${formatBytes(state.stats.upRate)}/s" else "—",
                download = if (sessionActive) "${formatBytes(state.stats.downRate)}/s" else "—",
                samples = state.stats.speedSamples,
                checked = connected || starting,
                enabled = !stopping,
                onToggle = onToggle,
            )

            Column(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    HomeShortcutCard(
                        title = "拦截命中",
                        subtitle = hitSummary,
                        icon = Icons.Outlined.TrendingUp,
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
                        subtitle = if (stats.dnsQueries > 0) "${stats.dnsQueries} 次查询" else "暂无查询",
                        icon = Icons.Outlined.Dns,
                        modifier = Modifier.weight(1f),
                        onClick = onOpenDnsLogs,
                    )
                    HomeShortcutCard(
                        title = "配置文件",
                        subtitle = container.config.activeName(),
                        icon = Icons.Outlined.Description,
                        modifier = Modifier.weight(1f),
                        onClick = onOpenQuickEdit,
                    )
                }
                Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    HomeShortcutCard(
                        title = "证书状态",
                        subtitle = certificateStatus,
                        icon = Icons.Outlined.Shield,
                        modifier = Modifier.weight(1f),
                        onClick = onOpenMitm,
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
                                val ok = withContext(Dispatchers.IO) {
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
    connected: Boolean,
    uptime: String?,
    upload: String,
    download: String,
    samples: List<com.namu.dns.core.stats.SpeedSample>,
    checked: Boolean,
    enabled: Boolean,
    onToggle: () -> Unit,
) {
    val shape = RoundedCornerShape(24.dp)
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp)
            .shadow(6.dp, shape)
            .clip(shape)
            .background(
                Brush.linearGradient(
                    listOf(
                        NamuColors.Card,
                        NamuColors.Card,
                        if (NamuColors.isDark) Color(0xFF202938) else Color(0xFFF3F7FF),
                    ),
                ),
            )
            .padding(start = 18.dp, end = 18.dp, top = 16.dp, bottom = 16.dp),
    ) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(8.dp).background(
                        if (connected) NamuColors.Green else NamuColors.TextTertiary,
                        CircleShape,
                    ),
                )
                Spacer(Modifier.width(8.dp))
                Text(status, style = NamuTokens.Type.Title, color = NamuColors.TextMain)
            }
            IosSwitch(checked = checked, onCheckedChange = { onToggle() }, enabled = enabled)
        }
        Row(
            Modifier.fillMaxWidth().padding(top = 12.dp),
            verticalAlignment = Alignment.Bottom,
        ) {
            Column(Modifier.weight(1f)) {
                Text("运行时长", style = NamuTokens.Type.Caption, color = NamuColors.TextSub)
                Spacer(Modifier.height(2.dp))
                Text(
                    uptime ?: "—",
                    style = NamuTokens.Type.Display.copy(
                        fontSize = 34.sp,
                        lineHeight = 40.sp,
                        fontFeatureSettings = "tnum",
                    ),
                    color = if (uptime != null) NamuColors.TextMain else NamuColors.TextTertiary,
                    maxLines = 1,
                )
            }
            if (samples.isNotEmpty()) {
                HomeSpeedSparkline(
                    samples = samples.map { it.down },
                    modifier = Modifier.weight(1.08f).height(56.dp)
                        .padding(start = 16.dp, bottom = 3.dp),
                )
            }
        }
        Spacer(Modifier.height(16.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            NetworkRateTile("上传", upload, Icons.Outlined.ArrowUpward, Modifier.weight(1f))
            NetworkRateTile("下载", download, Icons.Outlined.ArrowDownward, Modifier.weight(1f))
        }
    }
}

@Composable
private fun HomeSpeedSparkline(samples: List<Long>, modifier: Modifier = Modifier) {
    Canvas(modifier) {
        if (samples.isEmpty()) return@Canvas
        val maxValue = maxOf(samples.maxOrNull() ?: 0L, 1024L).toDouble()
        val top = 3.dp.toPx()
        val bottom = size.height - 2.dp.toPx()
        val drawHeight = (bottom - top).coerceAtLeast(1f)
        val points = samples.mapIndexed { index, value ->
            val x = if (samples.size == 1) size.width else size.width * index / (samples.size - 1)
            val y = bottom - (value.toDouble() / maxValue).coerceIn(0.0, 1.0).toFloat() * drawHeight
            Offset(x, y)
        }
        val line = Path().apply {
            moveTo(points.first().x, points.first().y)
            for (index in 1 until points.size) {
                val previous = points[index - 1]
                val current = points[index]
                val middleX = (previous.x + current.x) / 2f
                cubicTo(middleX, previous.y, middleX, current.y, current.x, current.y)
            }
        }
        val fill = Path().apply {
            addPath(line)
            lineTo(size.width, bottom)
            lineTo(0f, bottom)
            close()
        }
        drawPath(
            path = fill,
            brush = Brush.verticalGradient(
                listOf(NamuColors.Blue.copy(alpha = .18f), NamuColors.Blue.copy(alpha = 0f)),
                startY = top,
                endY = bottom,
            ),
        )
        drawPath(
            path = line,
            color = NamuColors.Blue,
            style = Stroke(width = 1.8.dp.toPx(), cap = StrokeCap.Round),
        )
    }
}

@Composable
private fun HomeRoutingPicker(mode: RoutingMode, enabled: Boolean, onModeChange: (RoutingMode) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        Box(
            Modifier.heightIn(min = 44.dp)
                .clip(RoundedCornerShape(12.dp))
                .clickable(enabled = enabled, onClickLabel = "切换流量模式", role = Role.Button) { expanded = true },
            contentAlignment = Alignment.Center,
        ) {
            Row(
                Modifier.clip(RoundedCornerShape(50)).background(NamuColors.Card)
                    .border(1.dp, NamuColors.Separator.copy(alpha = .7f), RoundedCornerShape(50))
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
                    text = { Text(option.homeLabel, color = if (option == mode) homeAccent else NamuColors.TextMain) },
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
        modifier.clip(shape)
            .background(if (NamuColors.isDark) Color(0xFF262A31) else Color(0xFFF4F5F7))
            .padding(horizontal = 12.dp, vertical = 9.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            NamuIcon(icon, tint = NamuColors.TextSub, size = 14.dp)
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
        modifier.fillMaxHeight().heightIn(min = 102.dp)
            .shadow(4.dp, shape)
            .clip(shape)
            .background(NamuColors.Card)
            .then(if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier)
            .padding(horizontal = 14.dp, vertical = 13.dp),
        verticalArrangement = Arrangement.spacedBy(9.dp),
    ) {
        NamuIcon(icon, tint = NamuColors.TextSub, size = 23.dp)
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
