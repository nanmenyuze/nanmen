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
import androidx.compose.material.icons.automirrored.rounded.Article
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
import androidx.compose.ui.graphics.Color
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
import com.namu.dns.LogEntry
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun LogsScreen() {
    var autoScroll by remember { mutableStateOf(true) }
    val container = LocalAppContainer.current
    val logState by container.logs.state.collectAsStateWithLifecycle()
    val messages = container.messages
    val logs = logState.runtime
    var levelFilter by remember { mutableStateOf("all") }
    var query by remember { mutableStateOf("") }
    val filtered = filterRuntimeLogs(logs, levelFilter, query)
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
                .padding(horizontal = NamuTokens.Space16, vertical = 6.dp)
                .clip(RoundedCornerShape(NamuTokens.RadiusCard))
                .background(NamuColors.Card)
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("显示 ${filtered.size} / ${logs.size} 条", fontSize = 12.sp, color = NamuColors.TextSub)
            Spacer(Modifier.weight(1f))
            MiniTextAction(
                "导出",
                enabled = logs.isNotEmpty(),
            ) {
                scope.launch {
                    try {
                        val ts = java.text.SimpleDateFormat("yyyyMMdd-HHmmss", java.util.Locale.US).format(java.util.Date())
                        val body = logs.joinToString("\n") { "${timeFmt.format(Date(it.ts))} [${it.level}] ${it.tag}: ${it.msg}" }
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
            ) { container.logs.clearRuntime() }
        }

        LogFilterBar(
            chips = listOf("all" to "全部", "E" to "E", "W" to "W", "I" to "I"),
            selected = levelFilter,
            onSelect = { levelFilter = it },
            query = query,
            onQueryChange = { query = it },
            placeholder = "搜索关键字 / tag",
        )

        if (filtered.isEmpty()) {
            EmptyState(
                title = if (logs.isEmpty()) "暂无日志" else "没有匹配的日志",
                subtitle = if (logs.isEmpty()) {
                    "连接 VPN 后，DNS 拦截、规则匹配和连接记录会显示在这里。"
                } else {
                    "调整级别或关键字后重试。点按条目展开全文，长按复制单条。"
                },
                icon = if (logs.isEmpty()) Icons.AutoMirrored.Rounded.Article else Icons.Rounded.SearchOff,
            )
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = NamuTokens.Space16)
                    .clip(RoundedCornerShape(NamuTokens.RadiusCard))
                    .background(NamuColors.Card),
                contentPadding = PaddingValues(vertical = 6.dp),
            ) {
                items(filtered, key = { it.id }) { entry ->
                    Column(Modifier.animateItem()) {
                        LogRow(entry, timeFmt) {
                            val text = buildString {
                                append(timeFmt.format(Date(entry.ts)))
                                append(" [").append(entry.level).append("]")
                                if (entry.tag.isNotBlank()) append(" ").append(entry.tag)
                                append(": ").append(entry.msg)
                            }
                            clipboard.setText(AnnotatedString(text))
                            messages.show("已复制单条日志")
                        }
                        Box(
                            Modifier
                                .fillMaxWidth()
                                .padding(start = 16.dp)
                                .height(0.5.dp)
                                .background(NamuColors.Separator),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun LogRow(entry: LogEntry, timeFmt: SimpleDateFormat, onCopy: () -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val (levelColor, levelText) = when (entry.level.uppercase()) {
        "E", "ERROR" -> NamuColors.Red to "E"
        "W", "WARN" -> NamuColors.Orange to "W"
        else -> NamuColors.Green to "I"
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
        Text(
            timeFmt.format(Date(entry.ts)),
            fontSize = 11.sp,
            color = NamuColors.TextSub,
            fontFamily = FontFamily.Monospace,
        )
        Spacer(Modifier.width(8.dp))
        Box(
            Modifier
                .padding(top = 1.dp)
                .width(16.dp)
                .height(16.dp)
                .background(levelColor.copy(alpha = 0.12f), androidx.compose.foundation.shape.RoundedCornerShape(4.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Text(levelText, fontSize = 10.sp, color = levelColor, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(
                entry.msg,
                fontSize = 12.sp,
                color = NamuColors.TextMain,
                fontFamily = FontFamily.Monospace,
                maxLines = if (expanded) Int.MAX_VALUE else 4,
                overflow = TextOverflow.Ellipsis,
                lineHeight = 16.sp,
            )
            if (entry.tag.isNotBlank()) {
                Spacer(Modifier.height(1.dp))
                Text(entry.tag, fontSize = 10.sp, color = NamuColors.TextTertiary)
            }
        }
    }
}
