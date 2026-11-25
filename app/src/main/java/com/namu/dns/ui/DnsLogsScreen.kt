package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.SearchOff
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.Actions
import kotlinx.coroutines.launch
import com.namu.dns.DnsLogEntry
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun DnsLogsScreen() {
    var autoScroll by remember { mutableStateOf(true) }
    val container = LocalAppContainer.current
    val logState by container.logs.state.collectAsStateWithLifecycle()
    val messages = container.messages
    val logs = logState.dns
    var actionFilter by remember { mutableStateOf("all") }
    var query by remember { mutableStateOf("") }
    val filtered = filterDnsLogs(logs, actionFilter, query)
    val clipboard = LocalClipboardManager.current
    val listState = rememberLazyListState()
    // 用户手动上滑看历史时自动暂停跟随，避免被新日志拽回底部（A3）。
    // Compose 1.7 的 LazyColumn 不暴露 interactionSource，用滚动状态区分手势与程序滚动。
    var programmaticScroll by remember { mutableStateOf(false) }
    LaunchedEffect(listState) {
        snapshotFlow { listState.isScrollInProgress }
            .collect { scrolling ->
                if (scrolling && !programmaticScroll) autoScroll = false
            }
    }
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val timeFmt = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }

    LaunchedEffect(filtered.size, autoScroll) {
        if (autoScroll && filtered.isNotEmpty()) {
            programmaticScroll = true
            try {
                listState.animateScrollToItem(filtered.size - 1)
            } finally {
                programmaticScroll = false
            }
        }
    }

    Column(Modifier.fillMaxSize().background(NamuColors.Bg)) {
        // 与配置/数据页统一：操作条做成卡片，不再是浮在背景上的裸文字。
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp)
                .clip(RoundedCornerShape(NamuTokens.RadiusControl))
                .background(NamuColors.Card)
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("显示 ${filtered.size} / ${logs.size} 条查询", fontSize = 12.sp, color = NamuColors.TextSub)
            Spacer(Modifier.weight(1f))
            MiniTextAction(
                "导出",
                enabled = logs.isNotEmpty(),
            ) {
                scope.launch {
                    try {
                        val ts = java.text.SimpleDateFormat("yyyyMMdd-HHmmss", java.util.Locale.US).format(java.util.Date())
                        val body = logs.joinToString("\n") {
                            "${timeFmt.format(Date(it.ts))} ${it.domain} ${it.qtype} ${it.action} ${it.detail} " +
                                "x${it.count} ${it.ms}ms"
                        }
                        val where = Actions.exportText(ctx, "namu_log_$ts.txt", body)
                        messages.show("已导出：$where")
                    } catch (e: Exception) {
                        messages.show(e.message ?: "导出失败")
                    }
                }
            }
            Spacer(Modifier.width(6.dp))
            MiniTextAction(if (autoScroll) "暂停滚动" else "回到最新") { autoScroll = !autoScroll }
            Spacer(Modifier.width(6.dp))
            MiniTextAction(
                "清空",
                enabled = logs.isNotEmpty(),
            ) { container.logs.clearDns() }
        }

        LogFilterBar(
            chips = listOf(
                "all" to "全部",
                "拦截" to "拦截",
                "放行" to "放行",
                "失败" to "失败",
                "过滤" to "过滤",
            ),
            selected = actionFilter,
            onSelect = { actionFilter = it },
            query = query,
            onQueryChange = { query = it },
            placeholder = "搜索域名",
        )

        if (filtered.isEmpty()) {
            EmptyState(
                title = if (logs.isEmpty()) "暂无 DNS 查询" else "没有匹配的查询",
                subtitle = if (logs.isEmpty()) {
                    "连接 VPN 后，这里会显示域名、类型、本地拦截/放行和上游结果。"
                } else {
                    "调整动作或域名后重试。点按条目展开全文，长按复制单条。"
                },
                icon = if (logs.isEmpty()) Icons.Rounded.Dns else Icons.Rounded.SearchOff,
            )
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 12.dp)
                    .clip(RoundedCornerShape(NamuTokens.RadiusCard))
                    .background(NamuColors.Card),
                contentPadding = PaddingValues(vertical = 4.dp),
            ) {
                items(filtered, key = { it.id }) { entry ->
                    Column(Modifier.animateItem()) {
                        DnsLogRow(entry, timeFmt) {
                            val text = buildString {
                                append(timeFmt.format(Date(entry.ts))).append(' ')
                                append(entry.domain).append(' ').append(entry.qtype).append(' ')
                                append(entry.action).append(' ').append(entry.detail)
                                if (entry.count > 1) append(" · 5 秒 ").append(entry.count).append(" 次")
                                if (entry.ms > 0) append(' ').append(entry.ms).append("ms")
                            }
                            clipboard.setText(AnnotatedString(text))
                            messages.show("已复制单条查询")
                        }
                        Box(
                            Modifier.fillMaxWidth().padding(start = 16.dp).height(0.5.dp).background(NamuColors.Separator),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DnsLogRow(entry: DnsLogEntry, timeFmt: SimpleDateFormat, onCopy: () -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val actionColor = when (entry.action) {
        "拦截" -> NamuColors.Red
        "失败", "过滤" -> NamuColors.Orange
        else -> NamuColors.Green
    }
    Row(
        Modifier
            .fillMaxWidth()
            .pointerInput(entry.id) {
                detectTapGestures(
                    onTap = { expanded = !expanded },
                    onLongPress = { onCopy() },
                )
            }
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(timeFmt.format(Date(entry.ts)), fontSize = 11.sp, color = NamuColors.TextSub, fontFamily = FontFamily.Monospace)
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(
                entry.domain,
                fontSize = 13.sp,
                color = NamuColors.TextMain,
                fontFamily = FontFamily.Monospace,
                maxLines = if (expanded) Int.MAX_VALUE else 2,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(2.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(entry.qtype, fontSize = 10.sp, color = NamuColors.TextTertiary, fontFamily = FontFamily.Monospace)
                Spacer(Modifier.width(6.dp))
                Text(
                    entry.detail + if (entry.count > 1) " · 5 秒 ${entry.count} 次" else "",
                    fontSize = 10.sp,
                    color = NamuColors.TextSub,
                    maxLines = if (expanded) Int.MAX_VALUE else 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (entry.ms > 0) {
                    Spacer(Modifier.width(6.dp))
                    Text("${entry.ms}ms", fontSize = 10.sp, color = NamuColors.TextTertiary)
                }
            }
        }
        Spacer(Modifier.width(8.dp))
        Text(entry.action, fontSize = 12.sp, color = actionColor, fontWeight = FontWeight.Medium)
    }
}
