package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.Actions
import com.namu.dns.ConfigStore
import com.namu.dns.GlobalRuleStore
import com.namu.dns.core.LocalAppContainer
import kotlinx.coroutines.launch

/** 3.0.18：本地重写与脚本伪模块详情（全局共享）。 */
@Composable
internal fun LocalMitmDetailScreen() {
    MitmContentDetail(
        title = "本地重写与脚本",
        enabled = GlobalRuleStore.state.localMitmEnabled,
        content = GlobalRuleStore.state.localMitm,
        onToggle = { on -> Actions.setLocalMitmEnabled(on) },
        onUpdate = { transform -> Actions.updateLocalMitm(transform) },
    )
}

/** 其他方案独有的重写/脚本：停用项保留，标明来源。 */
@Composable
internal fun ExtraMitmDetailScreen(id: String) {
    val item = GlobalRuleStore.state.extraMitm.firstOrNull { it.id == id }
    if (item == null) {
        DetailMissing("来源方案重写项不存在或已删除")
        return
    }
    val scope = rememberCoroutineScope()
    val container = LocalAppContainer.current
    var confirmDelete by remember { mutableStateOf(false) }
    DetailList {
        MitmContentDetail(
            title = item.name,
            subtitle = "来源方案 ${item.origin} · 启用后才参与合并",
            enabled = item.enabled,
            content = item.content,
            onToggle = { on -> Actions.setExtraMitmEnabled(id, on) },
            onUpdate = { transform -> Actions.updateExtraMitm(id, transform) },
        )
        Spacer(Modifier.height(16.dp))
        GroupCard {
            Text(
                "删除该项",
                modifier = Modifier.fillMaxWidth().clickable { confirmDelete = true }.padding(vertical = 16.dp),
                color = NamuColors.Red,
                fontSize = 15.sp,
                textAlign = TextAlign.Center,
            )
        }
        Spacer(Modifier.height(24.dp))
    }
    if (confirmDelete) {
        NamuDialog(
            title = "删除该项",
            message = "确定删除来源方案 ${item.origin} 的重写与脚本？",
            confirmText = "删除",
            onDismiss = { confirmDelete = false },
            onConfirm = {
                confirmDelete = false
                scope.launch { Actions.deleteExtraMitm(id) }
            },
        )
    }
}

@Composable
private fun MitmContentDetail(
    title: String,
    subtitle: String? = null,
    enabled: Boolean,
    content: GlobalRuleStore.MitmContent,
    onToggle: suspend (Boolean) -> Unit,
    onUpdate: suspend ((GlobalRuleStore.MitmContent) -> GlobalRuleStore.MitmContent) -> Unit,
) {
    val scope = rememberCoroutineScope()
    var editing by remember { mutableStateOf<String?>(null) }
    var text by remember { mutableStateOf("") }
    DetailList {
        SectionHeader(title)
        GroupCard {
            SwitchRow("启用", subtitle = subtitle ?: "全局共享，切换 DNS 配置不影响", checked = enabled) { on ->
                scope.launch { onToggle(on) }
            }
            MitmKindRow("URL 重写", content.urlRewrites.size, true) {
                text = content.urlRewrites.joinToString("\n"); editing = "URL 重写"
            }
            MitmKindRow("头部重写", content.headerRewrites.size, true) {
                text = content.headerRewrites.joinToString("\n"); editing = "头部重写"
            }
            MitmKindRow("Loon 重写", content.loonRewrites.size, true) {
                text = content.loonRewrites.joinToString("\n"); editing = "Loon 重写"
            }
            MitmKindRow("正文重写", content.bodyRewrites.size, true) {
                text = content.bodyRewrites.joinToString("\n"); editing = "正文重写"
            }
            MitmKindRow("WebSocket 重写", content.wsRewrites.size, true) {
                text = content.wsRewrites.joinToString("\n"); editing = "WebSocket 重写"
            }
            SettingsRow("脚本", value = "${content.scripts.size} 条", showDivider = false)
        }
        if (content.scripts.isNotEmpty()) {
            SectionHeader("脚本清单")
            GroupCard {
                content.scripts.forEachIndexed { i, sc ->
                    SettingsRow(
                        sc.name.ifBlank { "未命名脚本" },
                        subtitle = "${sc.phase} · ${sc.pattern}",
                        showDivider = i != content.scripts.lastIndex,
                    )
                }
            }
        }
        Spacer(Modifier.height(24.dp))
    }
    editing?.let { kind ->
        NamuDialog(
            title = kind,
            confirmText = "保存",
            onDismiss = { editing = null },
            onConfirm = {
                val entries = text.lines().map(String::trim).filter(String::isNotEmpty).distinct()
                val k = kind
                scope.launch {
                    onUpdate { c ->
                        when (k) {
                            "URL 重写" -> c.copy(urlRewrites = entries)
                            "头部重写" -> c.copy(headerRewrites = entries)
                            "Loon 重写" -> c.copy(loonRewrites = entries)
                            "正文重写" -> c.copy(bodyRewrites = entries)
                            else -> c.copy(wsRewrites = entries)
                        }
                    }
                }
                editing = null
            },
        ) {
            NamuTextField(text, { text = it }, "每行一条", maxLines = 12)
        }
    }
}

@Composable
private fun MitmKindRow(title: String, count: Int, divider: Boolean, onClick: () -> Unit) {
    SettingsRow(title, value = "$count 条", chevron = true, showDivider = divider, onClick = onClick)
}

/** 独立规则集模块记录详情：内容预览 + 同步状态 + 删除。 */
@Composable
internal fun RuleSetDetailScreen(id: String) {
    val container = LocalAppContainer.current
    val scope = rememberCoroutineScope()
    val source = GlobalRuleStore.state.ruleSets.firstOrNull { it.id == id }
    if (source == null) {
        DetailMissing("规则集不存在或已删除")
        return
    }
    var confirmDelete by remember { mutableStateOf(false) }
    val preview = remember(source.url, source.cacheBytes) {
        runCatching {
            ConfigStore.globalRuleSetFile(container.context, source.url).readLines().take(60).joinToString("\n")
        }.getOrDefault("")
    }
    DetailList {
        SectionHeader("规则集")
        GroupCard {
            SwitchRow("启用", subtitle = "全局共享的 DNS 过滤规则集", checked = source.enabled) { on ->
                scope.launch { Actions.setRuleSetEnabled(id, on) }
            }
            SettingsRow("来源", subtitle = source.url, showDivider = true)
            SettingsRow("规模", value = "${source.lines} 条", showDivider = true)
            SettingsRow(
                "最近同步",
                value = when {
                    source.stale -> "失败，使用旧缓存"
                    source.error.isNotBlank() -> source.error
                    source.updatedAt > 0 -> "成功"
                    else -> "尚未同步"
                },
                showDivider = false,
            )
        }
        if (source.origin.isNotBlank()) {
            SectionHeader("来源")
            GroupCard { SettingsRow("迁移自方案", value = source.origin, showDivider = false) }
        }
        if (preview.isNotBlank()) {
            SectionHeader("内容预览")
            GroupCard {
                Text(
                    preview,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                    fontSize = 11.sp,
                    lineHeight = 17.sp,
                    fontFamily = FontFamily.Monospace,
                    color = NamuColors.TextMain,
                )
            }
        }
        Spacer(Modifier.height(16.dp))
        GroupCard {
            Text(
                "删除规则集",
                modifier = Modifier.fillMaxWidth().clickable { confirmDelete = true }.padding(vertical = 16.dp),
                color = NamuColors.Red,
                fontSize = 15.sp,
                textAlign = TextAlign.Center,
            )
        }
        Spacer(Modifier.height(24.dp))
    }
    if (confirmDelete) {
        NamuDialog(
            title = "删除规则集",
            message = "确定删除该规则集模块记录？本地缓存保留但不再参与过滤。",
            confirmText = "删除",
            onDismiss = { confirmDelete = false },
            onConfirm = {
                confirmDelete = false
                scope.launch { Actions.deleteRuleSet(id) }
            },
        )
    }
}

@Composable
internal fun DetailMissing(message: String) {
    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).padding(24.dp),
        horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally,
        verticalArrangement = androidx.compose.foundation.layout.Arrangement.Center,
    ) {
        Text(message, fontSize = 16.sp, color = NamuColors.TextSub)
    }
}