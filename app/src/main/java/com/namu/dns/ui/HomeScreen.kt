package com.namu.dns.ui

import com.namu.dns.core.LocalDockClearance

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cloud
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.Actions
import com.namu.dns.NodeInfo
import com.namu.dns.PrivateDnsController
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.ui.viewmodel.HomeViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(onToggle: () -> Unit, onOpenNodes: () -> Unit, onRestart: () -> Unit) {
    val container = LocalAppContainer.current
    val vm: HomeViewModel = viewModel(factory = HomeViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val cfg = state.config
    val connected = state.runtime.connected
    val stopping = state.runtime.stopping
    val starting = state.runtime.starting
    val stats = state.stats.stats
    var showMode by remember { mutableStateOf(false) }
    var infoNode by remember { mutableStateOf<NodeInfo?>(null) }
    var refreshing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val testState by vm.testState.collectAsStateWithLifecycle()
    val haptic = LocalHapticFeedback.current
    val privateDnsBypass = remember(connected) { PrivateDnsController.bypassing(context) }

    val selectedNode = remember(cfg.nodes, cfg.selected) {
        cfg.nodes.firstOrNull { it.name == cfg.selected } ?: cfg.nodes.firstOrNull()
    }

    fun refreshSubscription() {
        if (refreshing) return
        scope.launch {
            refreshing = true
            try {
                val result = Actions.refreshSubscription()
                vm.showMessage(Actions.subscriptionRefreshMessage(result))
            } catch (e: Exception) {
                vm.showMessage(e.message ?: "订阅刷新失败")
            } finally {
                refreshing = false
            }
        }
    }

    PullToRefreshBox(
        isRefreshing = refreshing,
        onRefresh = { refreshSubscription() },
        modifier = Modifier.fillMaxSize(),
    ) {
    Column(
        Modifier
            .fillMaxSize()
            .background(NamuColors.Bg)
            .verticalScroll(rememberScrollState()),
    ) {
        val hasSessionStats = connected && state.stats.sessionActive
        val status = when {
            stopping -> "正在停止"
            starting -> "正在启动"
            !connected -> "未连接"
            !hasSessionStats || stats.dnsQueries == 0L -> "等待 DNS 查询"
            cfg.blockEnabled -> "DNS 过滤已开启"
            else -> "DNS 已接管"
        }
        Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f).padding(end = 12.dp).animateContentSize()) {
                    Text(status, color = NamuColors.TextMain, fontSize = 28.sp,
                        lineHeight = 34.sp, fontWeight = FontWeight.SemiBold)
                    Text(
                        when {
                            stopping -> "等待 VPN 隧道关闭"
                            starting -> "正在建立 VPN 隧道"
                            !connected -> "打开开关启动 VPN"
                            !cfg.blockEnabled -> "VPN 已连接 · 广告过滤关闭"
                            else -> "VPN 已连接"
                        },
                        color = NamuColors.TextSub, fontSize = 14.sp,
                    )
                }
                IosSwitch(checked = connected || starting, onCheckedChange = { onToggle() }, enabled = !stopping)
            }
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth()) {
                SessionCount("本次查询", stats.dnsQueries.takeIf { hasSessionStats }, Modifier.weight(1f))
                SessionCount("已拦截", stats.dnsBlocked.takeIf { hasSessionStats }, Modifier.weight(1f))
            }
        }

        GroupCard {
            SettingsRow(
                title = "全局路由",
                value = when (cfg.mode) {
                    "global" -> "代理"
                    "dns_only" -> "直连"
                    "filter_only" -> "纯过滤"
                    else -> "配置"
                },
                icon = Icons.Rounded.Settings,
                chevron = true,
                onClick = { showMode = true },
            )
            SettingsRow(
                title = "代理节点",
                value = selectedNode?.name ?: "未配置",
                chevron = true,
                onClick = onOpenNodes,
            )
            SettingsRow(
                title = "连通性测试",
                subtitle = when {
                    testState.testing -> "正在测试当前服务器…"
                    else -> testState.result?.let { "上次结果 $it" } ?: "点右侧 T 按钮测速"
                },
                icon = Icons.Rounded.Speed,
                showDivider = cfg.subscriptionInfo != null,
                rightContent = {
                    TestDotButton(testing = testState.testing)
                },
                onClick = {
                    if (testState.testing) return@SettingsRow
                    val node = selectedNode
                    if (node == null) {
                        vm.showMessage("请先在服务器列表中添加节点")
                        onOpenNodes()
                    } else {
                        vm.testSelectedNode()
                    }
                },
            )
            cfg.subscriptionInfo?.let { info ->
                SettingsRow(
                    title = "订阅",
                    subtitle = buildString {
                        append(if (info.total > 0) "已用 ${formatBytes(info.used)} / ${formatBytes(info.total)}" else "已用 ${formatBytes(info.used)}")
                        append(" · ")
                        append(if (info.expireAt > 0) "到期 ${subscriptionExpiry(info)}" else "到期未知")
                        if (info.updatedAt > 0) append(" · 更新 ${formatAgo(info.updatedAt)}")
                    },
                    value = if (info.total > 0) "剩余 ${formatBytes(info.remaining)}" else "流量未知",
                    valueColor = if (info.usedPercent >= 90) NamuColors.Orange else NamuColors.Blue,
                    icon = Icons.Rounded.Cloud,
                    chevron = true,
                    showDivider = false,
                    onClick = { refreshSubscription() },
                )
            }
        }

        if (connected && privateDnsBypass && stats.dnsQueries == 0L && stats.uptime > 30_000) {
            GroupCard {
                SettingsRow(
                    title = "私人 DNS 正在绕过内核",
                    subtitle = "内核已拦截 ${PrivateDnsController.specifier(context).ifBlank { "上游" }} 的 DoT 853，" +
                        "但 30 秒内没有 DNS 进入。strict 模式不会回落，需要手动关闭；opportunistic 可再等几秒。",
                    icon = Icons.Rounded.Info,
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

        // 纯过滤模式本来就不需要节点，不该提示「没有可用节点」打扰用户。
        if (cfg.nodes.isEmpty() && cfg.mode != "filter_only" && cfg.mode != "dns_only" &&
            (cfg.mode == "global" || cfg.finalPolicy == "proxy")
        ) {
            GroupCard {
                SettingsRow(
                    title = "没有可用节点",
                    subtitle = "当前为 ${if (cfg.mode == "global") "全局代理" else "代理优先"}，" +
                        "所有需要代理的流量都会退回直连。点此添加节点。",
                    icon = Icons.Rounded.Info,
                    chevron = true,
                    showDivider = false,
                    onClick = onOpenNodes,
                )
            }
        }

        SectionHeader("服务器", trailing = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextAction("添加") { onOpenNodes() }
                Spacer(Modifier.width(12.dp))
                TextAction("管理") { onOpenNodes() }
            }
        })
        if (cfg.nodes.isEmpty()) {
            GroupCard {
                SettingsRow(
                    title = "添加服务器",
                    subtitle = "导入 Clash 订阅或 Base64 节点链接",
                    chevron = true,
                    showDivider = false,
                    onClick = onOpenNodes,
                )
            }
        } else {
            val expanded = remember { mutableStateMapOf<String, Boolean>() }
            val groups = remember(cfg.nodes) { cfg.nodes.groupBy { it.group.ifBlank { "未分组" } } }
            groups.forEach { (group, list) ->
                val open = expanded[group] ?: true
                GroupSectionHeader(
                    title = group,
                    count = list.size,
                    expanded = open,
                    onToggle = { expanded[group] = !open },
                )
                GroupCard {
                    AnimatedVisibility(
                        visible = open,
                        enter = expandVertically(tween(240)) + fadeIn(tween(180)),
                        exit = shrinkVertically(tween(200)) + fadeOut(tween(120)),
                    ) {
                        Column {
                            list.forEachIndexed { index, node ->
                                HomeNodeRow(
                                    node = node,
                                    selected = node.name == (selectedNode?.name ?: ""),
                                    showDivider = index != list.lastIndex,
                                    onInfo = { infoNode = node },
                                    onClick = {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        if (cfg.selected != node.name) {
                                            vm.selectNode(node.name)
                                            if (connected) onRestart()
                                        }
                                    },
                                )
                            }
                        }
                    }
                }
            }
        }
        FooterText("按订阅来源分组；点分组标题展开或收起，点服务器即可切换，连接中切换会自动重连。")

        Spacer(Modifier.height(LocalDockClearance.current + 34.dp))
    }
    }

    infoNode?.let { node ->
        NodeInfoDialog(
            node = node,
            selected = node.name == (selectedNode?.name ?: ""),
            onSelect = {
                infoNode = null
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                if (cfg.selected != node.name) {
                    vm.selectNode(node.name)
                    if (connected) onRestart()
                }
            },
            onDelete = {
                infoNode = null
                vm.deleteNode(node.name)
                if (connected) onRestart()
            },
            onDismiss = { infoNode = null },
        )
    }

    if (showMode) {
        ChoiceDialog(
            title = "全局路由",
            message = "选择流量的处理方式，返回首页后立即生效",
            options = listOf(
                "rule" to "配置（按规则分流）",
                "global" to "代理（全部流量走节点）",
                "filter_only" to "纯过滤（全量接管，不代理只拦截）",
                "dns_only" to "直连（仅 DNS 过滤）",
            ),
            selected = cfg.mode,
            onSelect = { key ->
                showMode = false
                if (cfg.mode != key) {
                    vm.setMode(key)
                    if (connected) onRestart()
                }
            },
            onDismiss = { showMode = false },
        )
    }
}

@Composable
private fun GroupSectionHeader(
    title: String,
    count: Int,
    expanded: Boolean,
    onToggle: () -> Unit,
) {
    val angle by animateFloatAsState(if (expanded) 0f else -90f, tween(200), label = "group-chevron")
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .padding(start = 20.dp, end = 16.dp, top = 20.dp, bottom = 7.dp)
            .clickable { onToggle() },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            title,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            color = NamuColors.TextSub,
            letterSpacing = 0.5.sp,
            modifier = Modifier.weight(1f),
        )
        Text("$count", fontSize = 12.sp, color = NamuColors.TextTertiary)
        Spacer(Modifier.width(4.dp))
        Icon(
            Icons.Rounded.KeyboardArrowDown,
            contentDescription = if (expanded) "收起" else "展开",
            tint = NamuColors.TextTertiary,
            modifier = Modifier.size(16.dp).rotate(angle),
        )
    }
}

@Composable
private fun TestDotButton(testing: Boolean) {
    Box(Modifier.size(48.dp), contentAlignment = Alignment.Center) {
        Box(
            Modifier
                .size(26.dp)
                .clip(RoundedCornerShape(50))
                .border(BorderStroke(1.dp, NamuColors.Blue), RoundedCornerShape(50)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                if (testing) "…" else "T",
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = NamuColors.Blue,
            )
        }
    }
}

private val NodeInfo.badge: String
    get() = when (type) {
        "ss" -> "SS"
        "trojan" -> "TR"
        "vless" -> "VL"
        "vmess" -> "VM"
        "socks5" -> "S5"
        else -> "H"
    }

@Composable
private fun HomeNodeRow(
    node: NodeInfo,
    selected: Boolean,
    showDivider: Boolean,
    onInfo: () -> Unit,
    onClick: () -> Unit,
) {
    val color = when (node.type) {
        "ss" -> NamuColors.Teal
        "trojan" -> NamuColors.Blue
        "vless" -> NamuColors.Green
        "vmess" -> NamuColors.Blue
        "socks5" -> NamuColors.Orange
        else -> NamuColors.TextSub
    }
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(if (pressed) 0.985f else 1f, spring(stiffness = 420f), label = "node-scale")
    val pressBg by animateColorAsState(
        if (pressed) NamuColors.FillPressed else Color.Transparent,
        tween(120),
        label = "node-press",
    )
    Column(
        Modifier
            .fillMaxWidth()
            .graphicsLayer { scaleX = scale; scaleY = scale }
            .background(pressBg)
            .clickable(interactionSource = interaction, indication = null) { onClick() },
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 58.dp)
                .padding(horizontal = 16.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .size(30.dp)
                    .clip(RoundedCornerShape(50))
                    .background(color.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center,
            ) {
                Text(node.badge, color = color, fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    node.name,
                    fontSize = 16.sp,
                    color = NamuColors.TextMain,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    "${node.typeLabel} · ${node.server}:${node.port}",
                    fontSize = 11.sp,
                    color = NamuColors.TextSub,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            val latency = node.latency
            if (latency != null) {
                Text(
                    "$latency ms",
                    fontSize = 12.sp,
                    color = when {
                        latency < 150 -> NamuColors.Green
                        latency < 400 -> NamuColors.Orange
                        else -> NamuColors.Red
                    },
                )
            }
            Spacer(Modifier.width(8.dp))
            if (selected) {
                Box(
                    Modifier
                        .size(8.dp)
                        .clip(RoundedCornerShape(50))
                        .background(NamuColors.Blue),
                )
                Spacer(Modifier.width(8.dp))
            }
            IconButton(onClick = onInfo, modifier = Modifier.size(48.dp)) {
                Box(
                    Modifier
                        .size(24.dp)
                        .clip(RoundedCornerShape(50))
                        .background(NamuColors.Blue),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        Icons.Rounded.Info,
                        contentDescription = "服务器详情",
                        tint = Color.White,
                        modifier = Modifier.size(14.dp),
                    )
                }
            }
        }
        if (showDivider) RowDivider(58.dp)
    }
}


@Composable
private fun SessionCount(label: String, count: Long?, modifier: Modifier) {
    Column(modifier) {
        Text(label, color = NamuColors.TextSub, fontSize = 13.sp)
        Text(count?.toString() ?: "—", color = NamuColors.TextMain, fontSize = 24.sp,
            fontWeight = FontWeight.Medium)
    }
}
