package com.namu.dns.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.outlined.ArrowDownward
import androidx.compose.material.icons.outlined.ArrowUpward
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.PrivateDnsController
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.LocalDockClearance
import com.namu.dns.core.config.RoutingMode
import com.namu.dns.ui.viewmodel.HomeViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.sin

@Suppress("ProduceStateDoesNotAssignValue")
@Composable
fun HomeScreen(
    onToggle: () -> Unit,
    onOpenNodes: () -> Unit,
    onRestart: () -> Unit,
) {
    val container = LocalAppContainer.current
    val vm: HomeViewModel = viewModel(factory = HomeViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val cfg = state.config
    val connected = state.runtime.connected
    val stopping = state.runtime.stopping
    val starting = state.runtime.starting
    val stats = state.stats.stats
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val privateDnsBypass = remember(connected) { PrivateDnsController.bypassing(context) }
    val selectedNode = remember(cfg.nodes, cfg.selected) {
        cfg.nodes.firstOrNull { it.name == cfg.selected } ?: cfg.nodes.firstOrNull()
    }
    val selectedLatency = selectedNode?.latency ?: 0L
    val mode = RoutingMode.fromConfig(cfg.mode)
    val missingProxyNode = cfg.nodes.isEmpty() && (mode == RoutingMode.Proxy ||
        (mode == RoutingMode.Rules && cfg.finalPolicy == "proxy"))

    val status = when {
        stopping -> "正在停止"
        starting -> "正在启动"
        !connected -> "未连接"
        !state.stats.sessionActive || stats.dnsQueries == 0L -> "等待 DNS 查询"
        cfg.blockEnabled -> "过滤运行中"
        else -> "已连接 · 过滤关闭"
    }

    MainPageChrome(
        title = "南门 DNS",
        trailing = {
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
        },
    ) {
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
                checked = connected,
                pendingLabel = when {
                    stopping -> "正在停止"
                    starting -> "正在启动"
                    else -> null
                },
                enabled = !stopping,
                onToggle = onToggle,
            )

            SectionHeader("快捷入口")
            GroupCard {
                SettingsRow(
                    title = "节点与订阅",
                    subtitle = if (missingProxyNode) "没有可用节点，代理流量将直连" else null,
                    value = when {
                        selectedNode == null -> "未添加节点"
                        mode == RoutingMode.Direct -> "未使用代理"
                        selectedLatency > 0 -> "${selectedNode.name} · $selectedLatency ms"
                        else -> selectedNode.name
                    },
                    chevron = true,
                    showDivider = false,
                    onClick = onOpenNodes,
                )
            }

            if (connected && privateDnsBypass && stats.dnsQueries == 0L && stats.uptime > 30_000) {
                Spacer(Modifier.height(12.dp))
                GroupCard {
                    SettingsRow(
                        title = "私人 DNS 正在绕过内核",
                        subtitle = "30 秒内未收到 DNS 查询，点此处理。",
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

            Spacer(Modifier.height(LocalDockClearance.current + 20.dp))
    }
}

private val RoutingMode.homeLabel: String
    get() = when (this) {
        RoutingMode.Direct -> "仅过滤"
        RoutingMode.Rules -> "规则分流"
        RoutingMode.Proxy -> "全局代理"
    }

private val homeAccent: Color
    get() = if (NamuColors.isDark) Color(0xFF9BBFFF) else NamuColors.Blue

@Composable
private fun WorkbenchStatusCard(
    status: String,
    connected: Boolean,
    uptime: String?,
    upload: String,
    download: String,
    checked: Boolean,
    pendingLabel: String?,
    enabled: Boolean,
    onToggle: () -> Unit,
) {
    val glowOpacity = animateFloatAsState(
        targetValue = if (connected) 1f else 0f,
        animationSpec = tween(durationMillis = if (connected) 360 else 160),
        label = "runtime-glow-visibility",
    )
    val statusColor = if (connected) NamuColors.Green else NamuColors.TextTertiary
    val accent = homeAccent
    SoftCard {
        Column(Modifier.fillMaxWidth().padding(start = 18.dp, end = 18.dp, top = 18.dp, bottom = 20.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier.size(8.dp)
                            .drawBehind {
                                val opacity = glowOpacity.value
                                if (opacity > 0f) {
                                    drawCircle(
                                        brush = Brush.radialGradient(
                                            colors = listOf(accent.copy(alpha = .30f * opacity), Color.Transparent),
                                            center = center,
                                            radius = 9.dp.toPx(),
                                        ),
                                        radius = 9.dp.toPx(),
                                    )
                                }
                            }
                            .background(statusColor, CircleShape),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        status,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = NamuColors.TextMain,
                    )
                }
                IosSwitch(
                    checked = checked,
                    onCheckedChange = { onToggle() },
                    enabled = enabled,
                    pendingLabel = pendingLabel,
                )
            }
            Spacer(Modifier.height(12.dp))
            RuntimeTimer(
                uptime = uptime,
                visible = connected,
                opacity = { glowOpacity.value },
            )
            Spacer(Modifier.height(16.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                HomeRateColumn("上传", upload, Icons.Outlined.ArrowUpward, Modifier.weight(1f))
                HomeRateColumn("下载", download, Icons.Outlined.ArrowDownward, Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun RuntimeTimer(uptime: String?, visible: Boolean, opacity: () -> Float) {
    var timeEnd by remember { mutableFloatStateOf(0f) }
    val phase = remember { Animatable(0f) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(visible, lifecycle) {
        if (visible) {
            lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
                phase.snapTo(0f)
                phase.animateTo(1f, infiniteRepeatable(tween(3600, easing = LinearEasing)))
            }
        }
    }
    val light = homeAccent
    val sharpLight = if (NamuColors.isDark) Color(0xFFC9E1FF) else Color.White
    Box(Modifier.fillMaxWidth()) {
        Canvas(Modifier.matchParentSize()) {
            val alpha = opacity()
            val start = timeEnd + 10.dp.toPx()
            val end = size.width - 8.dp.toPx()
            if (alpha <= 0f || timeEnd <= 0f || end - start < 40.dp.toPx()) return@Canvas
            val origin = Offset(start, size.height * .78f)
            val destination = Offset(end, size.height * .41f)
            val control = Offset((start + end) * .5f, size.height * .48f)
            val curve = Path().apply {
                moveTo(origin.x, origin.y)
                quadraticTo(control.x, control.y, destination.x, destination.y)
            }
            val washRadius = (end - start) * .9f
            drawCircle(
                brush = Brush.radialGradient(
                    listOf(light.copy(alpha = .10f * alpha), Color.Transparent),
                    center = destination,
                    radius = washRadius,
                ),
                radius = washRadius,
                center = destination,
            )
            drawPath(
                curve,
                brush = Brush.horizontalGradient(
                    listOf(Color.Transparent, light.copy(alpha = .28f * alpha), light.copy(alpha = .06f * alpha)),
                    startX = start,
                    endX = end,
                ),
                style = Stroke(width = 1.dp.toPx(), cap = StrokeCap.Round),
            )

            val t = phase.value
            val remaining = 1f - t
            val point = origin * (remaining * remaining) + control * (2f * remaining * t) + destination * (t * t)
            val pulse = sin(Math.PI * t).toFloat().coerceIn(0f, 1f) * alpha
            val haloRadius = 8.dp.toPx()
            drawCircle(
                Brush.radialGradient(
                    listOf(light.copy(alpha = .48f * pulse), Color.Transparent),
                    center = point,
                    radius = haloRadius,
                ),
                radius = haloRadius,
                center = point,
            )
            drawCircle(light.copy(alpha = .56f * pulse), radius = 2.8.dp.toPx(), center = point)
            drawCircle(sharpLight.copy(alpha = .94f * pulse), radius = 1.7.dp.toPx(), center = point)
        }
        Column(Modifier.fillMaxWidth()) {
            Text("运行时长", style = NamuTokens.Type.Caption, color = NamuColors.TextSub)
            Text(
                uptime ?: "—:—:—",
                modifier = Modifier.fillMaxWidth(),
                style = NamuTokens.Type.Display.copy(
                    fontSize = 48.sp,
                    lineHeight = 58.sp,
                    fontWeight = FontWeight.Medium,
                    letterSpacing = (-1.2).sp,
                    fontFeatureSettings = "tnum",
                ),
                color = if (uptime != null) NamuColors.TextMain else NamuColors.TextTertiary,
                maxLines = 1,
                onTextLayout = { timeEnd = if (it.lineCount > 0) it.getLineRight(0) else 0f },
            )
        }
    }
}

@Composable
private fun HomeRateColumn(label: String, rate: String, icon: ImageVector, modifier: Modifier) {
    Column(
        modifier.clip(RoundedCornerShape(NamuTokens.RadiusControl)).background(NamuColors.Fill)
            .padding(horizontal = 12.dp, vertical = 9.dp),
        verticalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            NamuIcon(icon, tint = NamuColors.TextSub, size = 14.dp)
            Spacer(Modifier.width(4.dp))
            Text(label, fontSize = 12.sp, color = NamuColors.TextSub)
        }
        Text(
            rate,
            fontSize = 17.sp,
            fontWeight = FontWeight.SemiBold,
            style = TextStyle(fontFeatureSettings = "tnum"),
            color = NamuColors.TextMain,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun HomeRoutingPicker(mode: RoutingMode, enabled: Boolean, onModeChange: (RoutingMode) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val open = expanded && enabled
    val interaction = remember { MutableInteractionSource() }
    val rotation by animateFloatAsState(
        targetValue = if (open) 180f else 0f,
        animationSpec = spring(dampingRatio = NamuTokens.PressDamping, stiffness = NamuTokens.PressStiffness),
        label = "routing-menu-arrow",
    )
    LaunchedEffect(enabled) { if (!enabled) expanded = false }

    Box {
        Box(
            Modifier.heightIn(min = 44.dp)
                .menuPressMotion(interaction)
                .clip(CircleShape)
                .semantics { stateDescription = if (open) "已展开" else "已收起" }
                .clickable(
                    interactionSource = interaction,
                    indication = null,
                    enabled = enabled,
                    onClickLabel = "切换流量模式",
                    role = Role.Button,
                ) { expanded = !expanded },
            contentAlignment = Alignment.Center,
        ) {
            Row(
                Modifier.background(if (open) NamuColors.FillPressed else NamuColors.Card, CircleShape)
                    .padding(start = 12.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(mode.homeLabel, style = NamuTokens.Type.Caption, fontWeight = FontWeight.SemiBold, color = homeAccent)
                Box(Modifier.graphicsLayer { rotationZ = rotation }) {
                    NamuIcon(Icons.Filled.ArrowDropDown, tint = homeAccent, size = 18.dp)
                }
            }
        }
        FloatingMenu(
            expanded = open,
            onDismissRequest = { expanded = false },
            modifier = Modifier.widthIn(min = 168.dp, max = 220.dp),
        ) {
            RoutingMode.entries.forEach { option ->
                val isSelected = option == mode
                DropdownMenuItem(
                    text = {
                        Text(
                            option.homeLabel,
                            fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                            color = if (isSelected) homeAccent else NamuColors.TextMain,
                        )
                    },
                    modifier = Modifier.semantics { selected = isSelected },
                    trailingIcon = if (isSelected) ({ CheckMark(color = homeAccent) }) else null,
                    onClick = {
                        expanded = false
                        if (!isSelected) onModeChange(option)
                    },
                )
            }
        }
    }
}
