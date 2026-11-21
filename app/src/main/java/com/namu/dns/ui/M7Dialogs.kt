package com.namu.dns.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.AppConfig
import com.namu.dns.CrashGuard
import com.namu.dns.LiveConn
import com.namu.dns.LiveConnStore
import com.namu.dns.LogEntry
import com.namu.dns.M7Backup
import com.namu.dns.MigrationReportStore
import com.namu.dns.NamuVpnService
import com.namu.dns.NetworkStatus
import com.namu.dns.StatsData
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.runtime.RuntimeState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun BackupRestoreDialog(onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val container = LocalAppContainer.current
    val scope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var pendingText by remember { mutableStateOf<String?>(null) }
    var pendingSummary by remember { mutableStateOf("") }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            loading = true
            status = null
            try {
                val text = withContext(Dispatchers.IO) {
                    ctx.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                        ?: error("无法读取备份文件")
                }
                val info = M7Backup.inspect(text)
                pendingSummary = "当前配置 ${info.activeConfig} · " +
                    "${info.files.size} 个配置 · ${info.config.nodes.size} 个节点 · " +
                    "应用版本 ${info.appVersion}"
                pendingText = text
            } catch (e: Exception) {
                status = e.message ?: "读取备份失败"
            } finally {
                loading = false
            }
        }
    }

    pendingText?.let { text ->
        NamuDialog(
            title = "恢复这份备份？",
            message = "会覆盖当前应用配置和本地 .conf。恢复前建议先导出一份当前备份。",
            confirmText = "恢复",
            confirmColor = NamuColors.Red,
            loading = loading,
            onDismiss = { pendingText = null },
            onConfirm = {
                scope.launch {
                    loading = true
                    try {
                        val r = M7Backup.restore(ctx, text)
                        val warn = if (r.warnings.isEmpty()) "" else "；${r.warnings.joinToString("；")}"
                        container.messages.show(
                            "已恢复 ${r.files} 个配置、${r.nodes} 个节点，当前配置 ${r.activeConfig}$warn",
                        )
                        if (container.runtime.current().connected) NamuVpnService.reload(ctx)
                        pendingText = null
                        onDismiss()
                    } catch (e: Exception) {
                        status = "恢复失败：${e.message ?: "未知错误"}"
                        pendingText = null
                    } finally {
                        loading = false
                    }
                }
            },
        ) {
            Text(pendingSummary, fontSize = 12.sp, color = NamuColors.TextSub, lineHeight = 17.sp)
        }
        return
    }

    NamuDialog(
        title = "备份与恢复",
        message = "备份包含节点密码/UUID、订阅地址、策略组、模块清单和全部本地配置，只保存到本地，不上传。",
        confirmText = "导出备份",
        loading = loading,
        onDismiss = onDismiss,
        onConfirm = {
            scope.launch {
                loading = true
                status = null
                try {
                    val where = M7Backup.export(ctx)
                    status = "已导出：$where"
                } catch (e: Exception) {
                    status = e.message ?: "导出失败"
                } finally {
                    loading = false
                }
            }
        },
    ) {
        TextButton(
            onClick = { filePicker.launch(arrayOf("application/json", "text/plain", "*/*")) },
            enabled = !loading,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("选择备份文件恢复", fontSize = 14.sp, color = NamuColors.Blue)
        }
        status?.let {
            Text(
                it,
                fontSize = 11.sp,
                color = if (it.startsWith("已导出")) NamuColors.Green else NamuColors.Red,
                lineHeight = 16.sp,
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            )
        }
        Text(
            "恢复会替换当前配置；备份里的规则、模块和 MITM 域名会一起回来。",
            fontSize = 11.sp,
            color = NamuColors.TextSub,
            lineHeight = 16.sp,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
fun MigrationReportDialog(onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val migration = MigrationReportStore.read(ctx)
    val crash = CrashGuard.lastCrash(ctx)
    NamuDialog(
        title = "版本迁移与崩溃恢复",
        confirmText = "关闭",
        showDismiss = false,
        onConfirm = onDismiss,
        onDismiss = onDismiss,
    ) {
        Column(
            Modifier.fillMaxWidth().heightIn(max = 360.dp).verticalScroll(rememberScrollState()),
        ) {
            Text(
                "配置版本：v${migration?.optInt("configVersion") ?: 3}",
                fontSize = 13.sp,
                color = NamuColors.TextMain,
                fontWeight = FontWeight.Medium,
            )
            Spacer(Modifier.height(5.dp))
            Text(
                migration?.let {
                    "扫描 ${it.optInt("scanned")} · 迁移 ${it.optInt("migrated")} · " +
                        "跳过 ${it.optInt("skipped")} · 失败 ${it.optInt("failed")}\n" +
                        "启动恢复：清理 ${it.optInt("recovered")} · 回退 ${it.optInt("restored")}"
                } ?: "尚未记录启动迁移。",
                fontSize = 12.sp,
                color = NamuColors.TextSub,
                lineHeight = 17.sp,
            )
            Spacer(Modifier.height(10.dp))
            Text("最近崩溃留痕", fontSize = 13.sp, color = NamuColors.TextMain, fontWeight = FontWeight.Medium)
            Spacer(Modifier.height(4.dp))
            Text(
                CrashGuard.summary(ctx),
                fontSize = 12.sp,
                color = if (crash == null) NamuColors.TextSub else NamuColors.Orange,
                lineHeight = 17.sp,
            )
            if (crash != null) {
                Spacer(Modifier.height(8.dp))
                Text(
                    crash.optString("stack").lineSequence().take(8).joinToString("\n"),
                    fontSize = 10.sp,
                    color = NamuColors.TextSub,
                    lineHeight = 14.sp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(NamuColors.Fill, RoundedCornerShape(8.dp))
                        .padding(8.dp),
                )
            }
            Spacer(Modifier.height(10.dp))
            Text(
                "迁移只升级 .conf 格式并保留 .legacy.bak；启动恢复会清掉未完成的 .tmp，" +
                    "目标损坏且备份可用时自动回退。这里只记录计数，不读取节点密码或规则正文。",
                fontSize = 11.sp,
                color = NamuColors.TextSub,
                lineHeight = 16.sp,
            )
        }
    }
}

@Composable
fun PrivacyAndLimitsDialog(onDismiss: () -> Unit, onOpenMitm: (() -> Unit)? = null) {
    NamuDialog(
        title = "隐私与系统限制",
        confirmText = "关闭",
        showDismiss = false,
        onConfirm = onDismiss,
        onDismiss = onDismiss,
    ) {
        Column(
            Modifier.fillMaxWidth().heightIn(max = 380.dp).verticalScroll(rememberScrollState()),
        ) {
            Text("数据留在本机", fontSize = 13.sp, color = NamuColors.TextMain, fontWeight = FontWeight.Medium)
            Text(
                "诊断报告、运行日志、DNS 查询、备份都只写入本地文件或应用私有目录；没有遥测上报，" +
                    "没有账号系统。导出文件由你选择保存位置。",
                fontSize = 12.sp, color = NamuColors.TextSub, lineHeight = 17.sp,
            )
            Spacer(Modifier.height(10.dp))
            Text("证书与 MITM", fontSize = 13.sp, color = NamuColors.TextMain, fontWeight = FontWeight.Medium)
            Text(
                "只有启用 MITM 并安装本机 CA 后才会解密命中域名的 HTTPS。银行、支付、证券类应用请加入跳过列表，" +
                    "或直接关闭 MITM；卸载应用前先在系统证书/模块里移除 CA。",
                fontSize = 12.sp, color = NamuColors.TextSub, lineHeight = 17.sp,
            )
            Spacer(Modifier.height(10.dp))
            Text("Android 系统限制", fontSize = 13.sp, color = NamuColors.TextMain, fontWeight = FontWeight.Medium)
            Text(
                "VPN 同一时间只能有一个；部分 ROM 会在后台清理服务，需要允许自启动/后台运行。" +
                    "Private DNS 的 strict 模式可能绕过本地过滤，建议关闭或设为自动；Root 只用于可选证书区，" +
                    "未 Root 设备仍可用 VpnService + 用户 CA。",
                fontSize = 12.sp, color = NamuColors.TextSub, lineHeight = 17.sp,
            )
            Spacer(Modifier.height(10.dp))
            Text(
                "本机没有 Android 真机/模拟器，M7 的 VPN 授权、前后台、重启、网络切换和真实代理矩阵未实测；" +
                    "发布报告会明确列出未验证项，不编造性能数字。",
                fontSize = 11.sp, color = NamuColors.Orange, lineHeight = 16.sp,
            )
            if (onOpenMitm != null) {
                TextButton(onClick = { onDismiss(); onOpenMitm() }, modifier = Modifier.fillMaxWidth()) {
                    Text("打开 MITM 证书设置", fontSize = 14.sp, color = NamuColors.Blue)
                }
            }
        }
    }
}

@Composable
fun LiveConnectionsDialog(
    stats: StatsData,
    cfg: AppConfig,
    runtimeState: RuntimeState,
    logs: List<LogEntry>,
    onDismiss: () -> Unit,
) {
    val ctx = LocalContext.current
    val net = remember { NetworkStatus.current(ctx) }
    val store = remember { LiveConnStore() }
    var rows by remember { mutableStateOf<List<LiveConn>>(emptyList()) }
    var total by remember { mutableStateOf(0) }

    // 只在已连接时轮询；对话框关闭后 LaunchedEffect 随组合取消，不会留后台协程。
    LaunchedEffect(runtimeState.connected) {
        if (!runtimeState.connected) {
            store.clear()
            rows = emptyList()
            total = 0
            return@LaunchedEffect
        }
        while (true) {
            val next = withContext(Dispatchers.IO) { store.refresh() }
            rows = next
            total = store.total
            kotlinx.coroutines.delay(1000)
        }
    }

    NamuDialog(
        title = "实时连接",
        confirmText = "关闭",
        showDismiss = false,
        onConfirm = onDismiss,
        onDismiss = onDismiss,
    ) {
        Column(
            Modifier.fillMaxWidth().heightIn(max = 430.dp).verticalScroll(rememberScrollState()),
        ) {
            MiniInfo("状态", when {
                runtimeState.stopping -> "正在关闭"
                runtimeState.connected -> "已连接"
                runtimeState.starting -> "正在连接"
                else -> "未连接"
            })
            MiniInfo("当前节点", cfg.nodes.firstOrNull { it.name == cfg.selected }?.name ?: cfg.selected ?: "未选择")
            MiniInfo("活跃 / 累计连接", "${stats.activeConns} / ${stats.totalConns}")
            MiniInfo("运行时长", liveUptime(stats.uptime))
            MiniInfo("底层网络", "${net.label} · ${net.detail}")
            MiniInfo("MITM 解密 / 改写", "${stats.mitmConns} / ${stats.mitmRewritten}")
            Spacer(Modifier.height(8.dp))
            when {
                !runtimeState.connected -> Text(
                    "内核未运行，没有可展示的连接。连接建立后这里会显示每一条连接的应用、目标、动作和命中规则。",
                    fontSize = 11.sp, color = NamuColors.TextSub, lineHeight = 16.sp,
                )
                rows.isEmpty() -> Text(
                    "暂无活跃连接。新连接会在 1 秒内出现在这里。",
                    fontSize = 11.sp, color = NamuColors.TextSub, lineHeight = 16.sp,
                )
                else -> {
                    Text(
                        "按建立时间倒序，显示前 ${rows.take(60).size} 条（内核共 $total 条）。" +
                            "关闭的连接会随内核计数自动消失。",
                        fontSize = 11.sp, color = NamuColors.TextSub, lineHeight = 16.sp,
                    )
                    Spacer(Modifier.height(6.dp))
                    rows.take(60).forEach { c -> LiveConnRow(ctx, c) }
                }
            }
            if (logs.isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                Text(
                    "最近连接日志",
                    fontSize = 11.sp, color = NamuColors.TextSub, fontWeight = FontWeight.Medium,
                )
                logs.asReversed().filter {
                    it.tag.contains("conn", true) || it.msg.contains("连接", true)
                }.take(5).forEach { e ->
                    Text(
                        "${liveTime(e.ts)} [${e.level}] ${e.msg}",
                        fontSize = 10.sp, color = NamuColors.TextSub, lineHeight = 14.sp,
                        maxLines = 2, overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

@Composable
private fun LiveConnRow(ctx: android.content.Context, c: LiveConn) {
    val actionColor = when {
        c.action.contains("拦截") || c.action.contains("拒绝") -> NamuColors.Red
        c.action.contains("节点") || c.action.contains("代理") || c.action.contains("全局") -> NamuColors.Blue
        else -> NamuColors.TextSub
    }
    Column(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                c.appLabel(ctx),
                fontSize = 12.sp,
                color = NamuColors.TextMain,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Text(
                if (c.mitm) "${c.action} · MITM" else c.action,
                fontSize = 11.sp,
                color = actionColor,
                maxLines = 1,
            )
            Spacer(Modifier.width(8.dp))
            Text(liveUptime(c.ageMs), fontSize = 10.sp, color = NamuColors.TextSub)
        }
        Text(
            c.endpoint,
            fontSize = 12.sp,
            color = NamuColors.TextMain,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.fillMaxWidth().padding(top = 1.dp),
        )
        if (c.rule.isNotEmpty()) {
            Text(
                "命中：${c.rule}",
                fontSize = 10.sp,
                color = NamuColors.TextSub,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.fillMaxWidth().padding(top = 1.dp),
            )
        }
    }
}

@Composable
private fun MiniInfo(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, fontSize = 12.sp, color = NamuColors.TextSub)
        Spacer(Modifier.weight(1f))
        Text(value, fontSize = 12.sp, color = NamuColors.TextMain, maxLines = 1)
    }
}

private fun liveUptime(ms: Long): String {
    if (ms <= 0L) return "-"
    val sec = ms / 1000
    val h = sec / 3600
    val m = (sec % 3600) / 60
    val s = sec % 60
    return if (h > 0) "${h}h ${m}m" else if (m > 0) "${m}m ${s}s" else "${s}s"
}

private fun liveTime(ts: Long): String =
    java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date(ts))
