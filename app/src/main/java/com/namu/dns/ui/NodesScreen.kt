package com.namu.dns.ui

import android.content.Context
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.CloudOff
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.SearchOff
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.Actions
import com.namu.dns.UiPrefs
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.config.RoutingMode
import com.namu.dns.NodeInfo
import com.namu.dns.ui.viewmodel.NodesViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodesScreen(onRestart: () -> Unit, onBack: () -> Unit = {}) {
    val container = LocalAppContainer.current
    val vm: NodesViewModel = viewModel(factory = NodesViewModel.factory(container))
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val testingOne by vm.testing.collectAsStateWithLifecycle()
    val runtime = container.runtime
    val messages = container.messages
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val haptic = LocalHapticFeedback.current
    var showSub by remember { mutableStateOf(false) }
    var showAddNode by remember { mutableStateOf(false) }
    var showPingMethod by remember { mutableStateOf(false) }
    var pingUrlDraft by remember { mutableStateOf("") }
    var query by remember { mutableStateOf("") }
    var refreshing by remember { mutableStateOf(false) }
    var selectionMode by remember { mutableStateOf(false) }
    var showDeleteConfirm by remember { mutableStateOf(false) }
    var showDeleteAllConfirm by remember { mutableStateOf(false) }
    var detailNode by remember { mutableStateOf<NodeInfo?>(null) }
    val selected = remember { mutableStateMapOf<String, Boolean>() }
    val scope = rememberCoroutineScope()

    fun reloadIfUsingProxy() {
        if (runtime.current().connected && RoutingMode.fromConfig(settings.current().mode) != RoutingMode.Direct) {
            onRestart()
        }
    }

    fun selectNode(name: String) {
        if (settings.current().selected == name) return
        settings.update { it.copy(selected = name) }
        reloadIfUsingProxy()
    }

    val prefs = remember { context.getSharedPreferences("namu_nodes", Context.MODE_PRIVATE) }
    var collapsed by remember {
        mutableStateOf(prefs.getStringSet("collapsed_groups", emptySet())?.toSet() ?: emptySet())
    }
    fun toggleGroup(group: String) {
        val next = if (group in collapsed) collapsed - group else collapsed + group
        collapsed = next
        prefs.edit().putStringSet("collapsed_groups", next).apply()
    }
    fun clearSelection() {
        selected.clear()
        selectionMode = false
    }
    fun deleteSelected() {
        val names = selected.keys.toSet()
        if (names.isEmpty()) return
        settings.update { current ->
            val rest = current.nodes.filterNot { it.name in names }
            current.copy(
                nodes = rest,
                selected = if (current.selected in names) rest.firstOrNull()?.name else current.selected,
            )
        }
        clearSelection()
        showDeleteConfirm = false
        reloadIfUsingProxy()
    }

    val sortMode = UiPrefs.nodeSort
    val filtered = remember(cfg.nodes, query, sortMode) { sortNodes(filterNodes(cfg.nodes, query), sortMode) }
    val duplicateNames = remember(cfg.nodes) {
        cfg.nodes.groupingBy { it.name }.eachCount().filterValues { it > 1 }.keys
    }
    val groups = remember(filtered) {
        filtered.groupBy { it.group.ifBlank { "未分组" } }
    }

    PullToRefreshBox(
        isRefreshing = refreshing,
        onRefresh = {
            if (!refreshing) {
                scope.launch {
                    refreshing = true
                    try {
                        val result = Actions.refreshSubscription()
                        messages.show(Actions.subscriptionRefreshMessage(result))
                    } catch (e: Exception) {
                        messages.show(e.message ?: "订阅刷新失败")
                    } finally {
                        refreshing = false
                    }
                }
            }
        },
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            Modifier.fillMaxSize().background(NamuColors.Bg),
            contentPadding = PaddingValues(bottom = 34.dp),
        ) {
            item {
                SecondaryTopBar("代理", onBack = onBack)
                SectionHeader("订阅")
                GroupCard {
                    SettingsRow(
                        title = "导入 / 更新订阅",
                        subtitle = if (cfg.nodes.isEmpty()) "支持 Clash 配置和 Base64 节点链接" else "当前共 ${cfg.nodes.size} 个服务器",
                        chevron = true,
                        showDivider = true,
                        onClick = { showSub = true },
                    )
                    SettingsRow(
                        title = "手动添加节点",
                        subtitle = "按协议逐项填写；SS / Trojan / VLESS / VMess / SOCKS5",
                        chevron = true,
                        onClick = { showAddNode = true },
                    )
                    SettingsRow(
                        title = "导出节点",
                        subtitle = "复制可分享的节点链接",
                        onClick = {
                            val links = settings.current().nodes.mapNotNull { it.shareLink().takeIf(String::isNotBlank) }
                            if (links.isEmpty()) {
                                messages.show("还没有可导出的节点")
                            } else {
                                clipboard.setText(AnnotatedString(links.joinToString("\n")))
                                messages.show("已复制 ${links.size} 个节点链接")
                            }
                        },
                    )
                    SettingsRow(
                        title = "删除所有节点",
                        showDivider = false,
                        onClick = {
                            if (settings.current().nodes.isEmpty()) messages.show("当前没有节点")
                            else showDeleteAllConfirm = true
                        },
                    )
                }
            }
            cfg.subscriptionInfo?.let { info ->
                item { SubscriptionCard(info) }
            }
            item {
                SectionHeader("测速与自动选择")
                GroupCard {
                    SettingsRow(
                        title = "测速 URL",
                        value = runCatching { java.net.URI(cfg.pingUrl).host }.getOrNull() ?: cfg.pingUrl,
                        chevron = true,
                        onClick = {
                            pingUrlDraft = cfg.pingUrl
                            showPingMethod = true
                        },
                    )
                    SwitchRow(
                        title = "自动选择最快节点",
                        subtitle = "WorkManager 每 15 分钟测速，按端到端转发延迟选择；也可手动点测速",
                        checked = cfg.autoSelectNode,
                        showDivider = false,
                    ) {
                        settings.update { current -> current.copy(autoSelectNode = it) }
                    }
                }
            }
            item {
                Column(Modifier.padding(horizontal = NamuTokens.Space16, vertical = 8.dp)) {
                    NamuTextField(
                        value = query,
                        onChange = { query = it },
                        placeholder = "搜索名称、地址或分组",
                        singleLine = true,
                    )
                }
            }
            item {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("排序", fontSize = 12.sp, color = NamuColors.TextSub)
                    Spacer(Modifier.width(4.dp))
                    listOf("default" to "默认", "latency" to "延迟", "name" to "名称", "group" to "分组").forEach { (mode, label) ->
                        MiniTextAction(
                            if (UiPrefs.nodeSort == mode) "● $label" else label,
                            color = if (UiPrefs.nodeSort == mode) NamuColors.Blue else NamuColors.TextSub,
                        ) { UiPrefs.setNodeSort(mode) }
                    }
                }
            }
            if (selectionMode) {
                item {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = NamuTokens.Space16, vertical = 4.dp)
                            .clip(RoundedCornerShape(NamuTokens.RadiusCard))
                            .background(NamuColors.Card)
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("已选 ${selected.size} 个", fontSize = 13.sp, color = NamuColors.TextMain)
                        Spacer(Modifier.weight(1f))
                        TextAction("删除", color = NamuColors.Red) {
                            if (selected.isNotEmpty()) showDeleteConfirm = true
                        }
                        Spacer(Modifier.width(10.dp))
                        TextAction("取消") { clearSelection() }
                    }
                }
            }
            if (filtered.isEmpty()) {
                item {
                    EmptyState(
                        title = if (cfg.nodes.isEmpty()) "还没有服务器" else "没有匹配的服务器",
                        subtitle = if (cfg.nodes.isEmpty()) {
                            "点击上方「导入 / 更新订阅」，导入 Clash 或 Base64 节点链接。"
                        } else {
                            "换一个名称、地址或分组关键词试试。"
                        },
                        icon = if (cfg.nodes.isEmpty()) Icons.Rounded.CloudOff else Icons.Rounded.SearchOff,
                    )
                }
            } else {
                groups.forEach { (group, list) ->
                    val open = query.isNotBlank() || group !in collapsed
                    item(key = "group:$group") {
                        NodeGroupHeader(
                            title = group,
                            count = list.size,
                            expanded = open,
                            onToggle = { toggleGroup(group) },
                        )
                    }
                    if (open) {
                        itemsIndexed(
                            list,
                            key = { index, node ->
                                if (node.name in duplicateNames) "legacy-node:$index:$group"
                                else "node:${node.name}"
                            },
                        ) { index, node ->
                            NodeRow(
                                node = node,
                                selected = node.name == cfg.selected,
                                testing = testingOne == node.name,
                                selectionMode = selectionMode,
                                checked = selected[node.name] == true,
                                showDivider = index != list.lastIndex,
                                onClick = {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    if (selectionMode) {
                                        if (selected[node.name] == true) selected.remove(node.name)
                                        else selected[node.name] = true
                                    } else selectNode(node.name)
                                },
                                onLongPress = {
                                    selectionMode = true
                                    selected[node.name] = true
                                },
                                onTest = { vm.test(node) },
                                onInfo = { detailNode = node },
                            )
                        }
                    }
                }
            }
            item {
                if (cfg.nodes.isNotEmpty()) {
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        FooterText("长按服务器多选删除；搜索时分组会自动展开。延迟图例：<150ms 绿 · <400ms 橙 · 其余红 · — 未测速。")
                    }
                }
            }
        }
    }

    if (showPingMethod) {
        NamuDialog(
            title = "测速 URL",
            message = "经代理协议真实转发一个 GET 请求，确认收到有效的 HTTP 响应。入口握手快但转发不通的节点不会被误选。",
            confirmText = "保存",
            onConfirm = {
                val u = pingUrlDraft.trim()
                if (u.startsWith("http://") || u.startsWith("https://")) {
                    settings.update { current -> current.copy(pingUrl = u) }
                }
                showPingMethod = false
            },
            onDismiss = { showPingMethod = false },
        ) {
            NamuTextField(
                value = pingUrlDraft,
                onChange = { pingUrlDraft = it },
                placeholder = "https://www.gstatic.com/generate_204",
                singleLine = true,
            )
        }
    }
    if (showSub) {
        SubscriptionDialog(
            onDismiss = { showSub = false },
            onDone = {
                showSub = false
            },
        )
    }
    if (showAddNode) {
        AddNodeDialog(
            onDismiss = { showAddNode = false },
            onDone = { node ->
                val saved = settings.update { current ->
                    val existing = current.nodes.mapTo(HashSet()) { it.name }
                    val unique = Actions.nameSubscriptionNodes(listOf(node.copy(source = "local://manual")), existing).single()
                    current.copy(
                        nodes = current.nodes + unique,
                        selected = current.selected ?: unique.name,
                    )
                }
                showAddNode = false
                messages.show("已添加 ${saved.nodes.last().name}")
                reloadIfUsingProxy()
            },
        )
    }
    if (showDeleteConfirm) {
        NamuDialog(
            title = "删除 ${selected.size} 个服务器？",
            message = "只会删除当前配置里的节点，订阅地址和规则不受影响。",
            confirmText = "删除",
            confirmColor = NamuColors.Red,
            onConfirm = { deleteSelected() },
            onDismiss = { showDeleteConfirm = false },
        ) {}
    }
    detailNode?.let { node ->
        NodeInfoDialog(
            node = node,
            selected = cfg.selected == node.name,
            onSelect = {
                detailNode = null
                selectNode(node.name)
            },
            onDelete = {
                detailNode = null
                settings.update { current ->
                    val remaining = current.nodes.filterNot { it.name == node.name }
                    current.copy(
                        nodes = remaining,
                        selected = if (current.selected == node.name) remaining.firstOrNull()?.name else current.selected,
                    )
                }
                reloadIfUsingProxy()
            },
            onDismiss = { detailNode = null },
        )
    }
    if (showDeleteAllConfirm) {
        NamuDialog(
            title = "删除所有节点？",
            message = "将清空设备中的 ${cfg.nodes.size} 个节点，保留订阅链接和规则配置。",
            confirmText = "删除",
            confirmColor = NamuColors.Red,
            onConfirm = {
                showDeleteAllConfirm = false
                settings.update { it.copy(nodes = emptyList(), selected = null) }
                clearSelection()
                reloadIfUsingProxy()
                messages.show("已删除所有节点")
            },
            onDismiss = { showDeleteAllConfirm = false },
        ) {}
    }
}

@Composable
private fun NodeGroupHeader(
    title: String,
    count: Int,
    expanded: Boolean,
    onToggle: () -> Unit,
) {
    val angle by animateFloatAsState(if (expanded) 0f else -90f, tween(200), label = "node-group-chevron")
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .padding(start = 20.dp, end = 16.dp, top = 16.dp, bottom = 6.dp)
            .clickable(onClick = onToggle),
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

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun NodeRow(
    node: NodeInfo,
    selected: Boolean,
    testing: Boolean,
    selectionMode: Boolean,
    checked: Boolean,
    showDivider: Boolean,
    onClick: () -> Unit,
    onLongPress: () -> Unit,
    onTest: () -> Unit,
    onInfo: () -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val pressBg by animateColorAsState(
        if (pressed) NamuColors.CardPressed else Color.Transparent,
        tween(120),
        label = "node-press",
    )
    val color = when (node.type) {
        "ss" -> NamuColors.Teal
        "trojan" -> NamuColors.Blue
        "vless" -> NamuColors.Green
        "vmess" -> NamuColors.Blue
        "socks5" -> NamuColors.Orange
        else -> NamuColors.TextSub
    }
    Column(
        Modifier
            .fillMaxWidth()
            .background(pressBg)
            .combinedClickable(
                interactionSource = interaction,
                indication = null,
                onClick = onClick,
                onLongClick = onLongPress,
            ),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 62.dp)
                .padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (selectionMode) {
                Box(
                    Modifier
                        .size(20.dp)
                        .clip(CircleShape)
                        .border(1.dp, if (checked) NamuColors.Blue else NamuColors.TextTertiary, CircleShape)
                        .background(if (checked) NamuColors.Blue else Color.Transparent),
                    contentAlignment = Alignment.Center,
                ) {
                    if (checked) {
                        Icon(Icons.Rounded.Check, null, tint = Color.White, modifier = Modifier.size(14.dp))
                    }
                }
                Spacer(Modifier.width(10.dp))
            }
            Box(
                Modifier
                    .size(38.dp)
                    .clip(RoundedCornerShape(NamuTokens.RadiusControl))
                    .background(color.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Text(node.typeLabel, color = color, fontSize = 11.sp, fontWeight = FontWeight.Bold)
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
                    "${node.server}:${node.port}",
                    fontSize = 12.sp,
                    color = NamuColors.TextSub,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (testing) {
                CircularProgressIndicator(Modifier.size(17.dp), color = NamuColors.TextSub, strokeWidth = 2.dp)
            } else {
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
                } else {
                    Text("—", fontSize = 12.sp, color = NamuColors.TextTertiary)
                }
                Spacer(Modifier.width(8.dp))
                Box(
                    Modifier
                        .heightIn(min = 48.dp)
                        .widthIn(min = 48.dp)
                        .clip(RoundedCornerShape(NamuTokens.RadiusControl))
                        .background(NamuColors.Blue.copy(alpha = 0.10f))
                        .clickable { onTest() },
                    contentAlignment = Alignment.Center,
                ) {
                    Text("测", fontSize = 12.sp, color = NamuColors.Blue)
                }
            }
            if (!selectionMode) {
                IconButton(onClick = onInfo) {
                    Icon(Icons.Rounded.Info, "节点详情", tint = NamuColors.TextSub, modifier = Modifier.size(17.dp))
                }
            }
            if (!selectionMode && selected) {
                Spacer(Modifier.width(10.dp))
                CheckMark()
            } else {
                Spacer(Modifier.width(10.dp))
            }
        }
        if (showDivider) RowDivider(66.dp)
    }
}


internal fun pingMethodLabel(method: String): String = if (method == "tls") "TLS 握手" else "TCP 握手"
