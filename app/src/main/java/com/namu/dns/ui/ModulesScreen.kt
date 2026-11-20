package com.namu.dns.ui

import com.namu.dns.core.LocalDockClearance

import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.namu.dns.Actions
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.ModuleSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun ModulesScreen(onRestart: () -> Unit) {
    var showAdd by remember { mutableStateOf(false) }
    var syncing by remember { mutableStateOf(false) }
    var deleteTarget by remember { mutableStateOf<ModuleSource?>(null) }
    val scope = rememberCoroutineScope()
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val runtime = container.runtime
    val messages = container.messages
    val modules = cfg.moduleSources
    val enabled = modules.count { it.enabled }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("模块")
        GroupCard {
            SettingsRow(
                title = "导入模块...",
                subtitle = "支持从本地文件或 URL 导入，可分别启用与同步",
                chevron = true,
                onClick = { showAdd = true },
            )
            SettingsRow(
                title = "同步全部",
                subtitle = if (modules.isEmpty()) "还没有导入模块" else "重新拉取 $enabled 个启用模块",
                value = if (syncing) "同步中…" else null,
                chevron = true,
                showDivider = false,
                onClick = {
                    if (!syncing && modules.isNotEmpty()) scope.launch {
                        syncing = true
                        try {
                            val result = Actions.syncModules()
                            messages.show(if (result.errors.isEmpty()) {
                                "已同步 ${result.updated} 个模块"
                            } else {
                                "同步 ${result.updated} 个，失败 ${result.errors.size} 个：${result.errors.first()}"
                            })
                        } catch (e: Exception) {
                            messages.show(e.message ?: "同步模块失败")
                        } finally {
                            syncing = false
                        }
                    }
                },
            )
        }

        SectionHeader("已安装")
        if (modules.isEmpty()) {
            GroupCard {
                Column(
                    Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 30.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text("暂无模块", fontSize = 15.sp, color = NamuColors.TextMain)
                    Spacer(Modifier.height(5.dp))
                    Text(
                        "模块主要用来按 App 维护规则，例如酷安、B站、闲鱼各自一份。",
                        fontSize = 12.sp,
                        color = NamuColors.TextSub,
                        lineHeight = 17.sp,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.height(12.dp))
                    Row(
                        Modifier
                            .heightIn(min = 48.dp)
                            .background(NamuColors.Blue, androidx.compose.foundation.shape.RoundedCornerShape(9.dp))
                            .clickable { showAdd = true }
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Rounded.Add, null, tint = androidx.compose.ui.graphics.Color.White, modifier = Modifier.height(16.dp))
                        Text(" 导入模块 URL", fontSize = 13.sp, color = androidx.compose.ui.graphics.Color.White)
                    }
                }
            }
        } else {
            GroupCard {
                modules.forEachIndexed { index, module ->
                    val subtitle = buildString {
                        append(module.app.ifBlank { "按 App 分组" })
                        append(" · ${module.blockRules} 条阻断")
                        if (module.routeRules > 0) append("，${module.routeRules} 条分流")
                        if (module.allowRules > 0) append("，${module.allowRules} 条例外")
                        if (module.mitmRules > 0) append("，${module.mitmRules} 条 MITM")
                        if (module.ignored > 0) append("，${module.ignored} 条不支持")
                        if (module.error.isNotBlank()) append("\n${module.error}")
                    }
                    SettingsRow(
                        title = module.name.ifBlank { "未命名模块" },
                        subtitle = subtitle,
                        showDivider = index != modules.lastIndex,
                        rightContent = {
                            IosSwitch(
                                checked = module.enabled,
                                onCheckedChange = { enabledNow ->
                                    scope.launch { Actions.setModuleEnabled(module.id, enabledNow) }
                                },
                            )
                            MiniTextAction("删除", color = NamuColors.Red) { deleteTarget = module }
                        },
                    )
                }
            }
        }

        FooterText(
            "模块按小火箭 .sgmodule 解析：[Rule] 支持 DOMAIN / DOMAIN-SUFFIX / DOMAIN-REGEX / " +
                "IP-CIDR / IP-CIDR6 / PORT；AdBlock 支持 ||domain^ 后缀、|domain| 精确和 @@ 例外。" +
                "带 $ 选项、通配路径与 PROCESS-NAME 的规则会跳过，并在导入预览按原因列出。" +
                "[MITM] 域名与 [URL Rewrite] / [Header Rewrite] / Loon [Rewrite] / [Script] 会在「设置 → MITM 去广告」启用并安装 CA 证书后生效；" +
                "脚本运行在 QuickJS 沙箱内，支持 \$request/\$response/\$done/\$httpClient/\$persistentStore/\$argument；\$notification 只记录日志，不弹系统通知；" +
                "setTimeout/setInterval 按 Loon 语义只执行一次，Promise/async 已驱动微任务，binary-body-mode/Uint8Array 已支持，require/本地文件读取不支持，导入预览会逐条标出；" +
                "当前 DNS 过滤按域名生效，模块按 App 分组管理，不是系统级按 UID 隔离。",
        )
        Spacer(Modifier.height(LocalDockClearance.current + 34.dp))
    }

    if (showAdd) {
        AddModuleDialog(
            onDismiss = { showAdd = false },
            onDone = {
                showAdd = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
    deleteTarget?.let { target ->
        NamuDialog(
            title = "删除模块",
            message = "删除「${target.name}」后，它带来的规则会立即从本地过滤中移除。",
            confirmText = "删除",
            confirmColor = NamuColors.Red,
            onDismiss = { deleteTarget = null },
            onConfirm = {
                val id = target.id
                deleteTarget = null
                scope.launch {
                    Actions.deleteModule(id)
                    messages.show("已删除模块")
                }
            },
        ) {}
    }
}

@Composable
private fun AddModuleDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var preview by remember { mutableStateOf<Actions.ModulePreview?>(null) }
    var acknowledged by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val messages = LocalAppContainer.current.messages
    val context = LocalContext.current
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            loading = true
            error = null
            try {
                val picked = withContext(Dispatchers.IO) {
                    val name = context.contentResolver.query(uri, null, null, null, null)?.use { c ->
                        val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                        if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
                    }
                    val text = context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                        ?: throw RuntimeException("无法读取该文件")
                    (name ?: "本地模块.plugin") to text
                }
                val (fileName, text) = picked
                url = "local://$fileName"
                if (name.isBlank()) name = fileName.substringBeforeLast('.')
                preview = Actions.previewModuleText(url, text, name)
                error = null
            } catch (e: Exception) {
                error = e.message ?: "读取本地模块失败"
            } finally {
                loading = false
            }
        }
    }

    NamuDialog(
        title = "导入模块",
        message = if (preview == null) {
            "填写模块 URL。支持小火箭 .sgmodule / 纯文本规则，也支持 {\"name\",\"rules\"} 形式的 JSON。"
        } else {
            "先预览再确认：确认后才会写入本地并合并规则。"
        },
        confirmText = if (preview == null) "预览" else "确认导入",
        loading = loading,
        confirmEnabled = url.isNotBlank() &&
            (preview == null || preview!!.parsed.lostRouteTargets.isEmpty() || acknowledged),
        onDismiss = onDismiss,
        onConfirm = {
            scope.launch {
                loading = true
                error = null
                try {
                    val p = preview
                    if (p == null) {
                        preview = Actions.previewModule(url, name)
                        acknowledged = false
                    } else {
                        val result = Actions.importPreview(p)
                        messages.show(buildString {
                            append("已导入「${result.name}」：${result.blockRules} 条阻断")
                            if (result.routeRules > 0) append("，${result.routeRules} 条分流")
                            if (result.allowRules > 0) append("，${result.allowRules} 条例外")
                            if (result.mitmRules > 0) append("，${result.mitmRules} 条 MITM/重写")
                            if (result.ignored > 0) append("，${result.ignored} 条暂不支持")
                        })
                        onDone()
                    }
                } catch (e: Exception) {
                    error = e.message ?: "导入失败"
                } finally {
                    loading = false
                }
            }
        },
    ) {
        NamuTextField(url, { url = it; error = null }, "https://example.com/app.sgmodule", singleLine = true)
        Spacer(Modifier.height(8.dp))
        NamuTextField(name, { name = it }, "模块名称（可留空，自动读取）", singleLine = true)
        Row(
            Modifier.fillMaxWidth().padding(top = 2.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "从本地文件导入",
                fontSize = 12.sp,
                color = NamuColors.Blue,
                modifier = Modifier
                    .clickable {
                        error = null
                        preview = null
                        filePicker.launch(arrayOf("*/*"))
                    }
                    .padding(vertical = 8.dp, horizontal = 4.dp),
            )
            Text(
                "从剪贴板粘贴 URL",
                fontSize = 12.sp,
                color = NamuColors.Blue,
                modifier = Modifier
                    .clickable { clipboard.getText()?.text?.let { url = it; error = null } }
                    .padding(vertical = 8.dp, horizontal = 4.dp),
            )
        }
        if (error != null) {
            Text(
                error!!,
                fontSize = 12.sp,
                color = NamuColors.Red,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        preview?.let { p ->
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp)
                    .background(NamuColors.Fill, RoundedCornerShape(10.dp))
                    .padding(12.dp),
            ) {
                Text("模块：${p.name}", fontSize = 14.sp, color = NamuColors.TextMain)
                Spacer(Modifier.height(4.dp))
                Text(
                    buildString {
                        val mitmCount = p.parsed.mitmHostnames.size +
                            p.parsed.urlRewrites.size + p.parsed.headerRewrites.size +
                            p.parsed.loonRewrites.size + p.parsed.scripts.size
                        val lost = p.parsed.lostRouteTargets.size
                        val supported = p.parsed.blockLines.size + p.parsed.routeRules.size + mitmCount
                        append("完整支持 $supported 条 · 部分支持 $lost 条 · 跳过 ${p.parsed.ignored} 条")
                        append("\n阻断 ${p.parsed.blockLines.size} · 分流 ${p.parsed.routeRules.size} · 例外 ${p.parsed.allowLines.size}")
                        if (mitmCount > 0) append(" · MITM/重写 $mitmCount")
                        if (p.parsed.ignoredReasons.isNotEmpty()) {
                            append("\n跳过明细：")
                            append(p.parsed.ignoredReasons.entries.sortedByDescending { it.value }
                                .take(4)
                                .joinToString("，") { "${moduleSkipLabel(it.key)} ${it.value}" })
                        }
                        if (p.duplicateBlock + p.duplicateRoute > 0) {
                            append("\n与现有模块重复 ${p.duplicateBlock + p.duplicateRoute} 条（导入后自动去重）")
                        }
                        if (p.parsed.blockLines.isEmpty() && p.parsed.routeRules.isEmpty() && mitmCount == 0) {
                            append("\n警告：没有任何可用规则")
                        }
                    },
                    fontSize = 12.sp,
                    color = NamuColors.TextSub,
                    lineHeight = 17.sp,
                )
                if (p.parsed.sectionStatus.isNotEmpty()) {
                    Spacer(Modifier.height(10.dp))
                    Text(
                        "分段能力：",
                        fontSize = 12.sp,
                        color = NamuColors.TextMain,
                    )
                    p.parsed.sectionStatus.forEach { st ->
                        Text(
                            "${st.section}：${st.lines} 行，${st.supported} 行可用 · ${sectionStatusLabel(st.status)}",
                            fontSize = 11.sp,
                            color = when (st.status) {
                                "executed", "stored" -> NamuColors.Green
                                "partial" -> NamuColors.Orange
                                "unsupported" -> NamuColors.Red
                                else -> NamuColors.TextSub
                            },
                            lineHeight = 16.sp,
                        )
                        Text(
                            "  ${st.detail}",
                            fontSize = 11.sp,
                            color = NamuColors.TextSub,
                            lineHeight = 16.sp,
                        )
                    }
                }
                if (p.parsed.scripts.isNotEmpty() || p.parsed.scriptLines.isNotEmpty()) {
                    Spacer(Modifier.height(10.dp))
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .background(NamuColors.Orange.copy(alpha = 0.12f), RoundedCornerShape(8.dp))
                            .padding(10.dp),
                    ) {
                        Text(
                            "脚本导入警示：脚本会进入 QuickJS 沙箱，仅在 MITM 启用并安装 CA 后执行；缺失正文或未实现 API 会逐条标注。",
                            fontSize = 11.sp,
                            color = NamuColors.Orange,
                            lineHeight = 16.sp,
                        )
                        val remote = p.parsed.scripts
                            .map { it.scriptPath.trim() }
                            .filter { it.startsWith("http://", true) || it.startsWith("https://", true) }
                            .distinct()
                        if (remote.isNotEmpty()) {
                            Spacer(Modifier.height(5.dp))
                            Text(
                                "远程 script-path（确认导入时将下载正文）：\n" +
                                    remote.take(4).joinToString("\n") { "· $it" } +
                                    if (remote.size > 4) "\n… 共 ${remote.size} 个远程脚本" else "",
                                fontSize = 11.sp,
                                color = NamuColors.TextSub,
                                lineHeight = 15.sp,
                            )
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                    Text("脚本能力：", fontSize = 12.sp, color = NamuColors.TextMain)
                    val req = p.parsed.scripts.count { it.phase == "request" }
                    val resp = p.parsed.scripts.count { it.phase == "response" }
                    val cached = p.parsed.scripts.count { it.source.isNotBlank() }
                    Text(
                        "已解析 ${p.parsed.scripts.size} 条（请求 $req / 响应 $resp），正文已缓存 $cached 条" +
                            if (p.parsed.scriptLines.size > p.parsed.scripts.size) {
                                "，${p.parsed.scriptLines.size - p.parsed.scripts.size} 条规则无法解析"
                            } else "",
                        fontSize = 11.sp,
                        color = NamuColors.TextSub,
                        lineHeight = 16.sp,
                    )
                    p.parsed.scripts.take(6).forEach { rule ->
                        val (status, gap) = scriptCapability(rule)
                        Text(
                            "· ${rule.name}（${rule.phase}）: $status" +
                                if (gap.isNotBlank()) " — $gap" else "",
                            fontSize = 11.sp,
                            color = when (status) {
                                "可用" -> NamuColors.Green
                                "部分可用" -> NamuColors.Orange
                                else -> NamuColors.Red
                            },
                            lineHeight = 16.sp,
                        )
                    }
                    if (p.parsed.scripts.size > 6) {
                        Text("… 其余 ${p.parsed.scripts.size - 6} 条见模块详情", fontSize = 11.sp, color = NamuColors.TextSub)
                    }
                    if (p.parsed.scriptIssues.isNotEmpty()) {
                        Text(
                            "脚本缺口：" + p.parsed.scriptIssues.take(4).joinToString("；"),
                            fontSize = 11.sp,
                            color = NamuColors.Orange,
                            lineHeight = 16.sp,
                        )
                    }
                }
                if (p.parsed.dependencies.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "能力边界：" + p.parsed.dependencies.joinToString("、") +
                            "。缺失或超限的脚本不会执行，也不会伪装修复。",
                        fontSize = 11.sp,
                        color = NamuColors.Orange,
                        lineHeight = 16.sp,
                    )
                }
                val lost = p.parsed.lostRouteTargets
                if (lost.isNotEmpty()) {
                    Spacer(Modifier.height(10.dp))
                    Text(
                        "重要分流目标丢失：" + lost.take(3).joinToString("、") +
                            (if (lost.size > 3) " 等 ${lost.size} 个" else "") +
                            "\n这些规则不会被导入；请确认后再继续。",
                        fontSize = 12.sp,
                        color = NamuColors.Red,
                        lineHeight = 17.sp,
                    )
                    Row(
                        Modifier.fillMaxWidth().padding(top = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            "我已确认丢失的分流目标",
                            fontSize = 12.sp,
                            color = NamuColors.TextMain,
                            modifier = Modifier.weight(1f),
                        )
                        IosSwitch(checked = acknowledged, onCheckedChange = { acknowledged = it })
                    }
                }
            }
        }
    }
}

/** 单条脚本的可用性判断：正文缺失=不可用；用了未提供的宿主 API=部分可用。 */
private fun scriptCapability(rule: com.namu.dns.core.config.ScriptConfig): Pair<String, String> {
    if (rule.source.isBlank()) return "不可用" to "脚本正文未缓存"
    val gaps = mutableListOf<String>()
    val low = rule.source
    if (Regex("\\brequire\\s*\\(").containsMatchIn(low)) gaps.add("require")
    if (Regex("\\bfetch\\s*\\(").containsMatchIn(low)) gaps.add("fetch")
    if (Regex("\\bXMLHttpRequest\\b").containsMatchIn(low)) gaps.add("XMLHttpRequest")
    if (Regex("\\bWebAssembly\\b").containsMatchIn(low)) gaps.add("WebAssembly")
    if ("\$utils" in low) gaps.add("\$utils")
    if (gaps.isNotEmpty()) return "部分可用" to "未提供 ${gaps.joinToString("/")}，其余 API 可用"
    if (rule.binaryBodyMode) return "可用" to "Uint8Array 二进制正文"
    if ("\$notification" in low) return "部分可用" to "\$notification 只记录到运行日志，不弹系统通知"
    val used = buildList {
        if ("\$httpClient" in low) add("\$httpClient")
        if ("\$persistentStore" in low) add("\$persistentStore")
        if ("\$argument" in low) add("\$argument")
        if ("\$notification" in low) add("\$notification")
        if ("\$done" in low) add("\$done")
    }
    return "可用" to if (used.isEmpty()) "仅使用 \$request/\$response" else used.joinToString("/")
}

private fun sectionStatusLabel(status: String): String = when (status) {
    "executed" -> "已执行"
    "stored" -> "已存储，内核执行"
    "partial" -> "部分支持"
    "unsupported" -> "不支持"
    else -> "未识别"
}

private fun moduleSkipLabel(key: String): String = when (key) {
    "unsupported_section" -> "未支持分区"
    "unsupported_rule_type" -> "规则类型不支持"
    "unsupported_rule_target" -> "分流目标不支持"
    "invalid_rule" -> "规则值无效"
    "unsupported_adblock_option" -> "AdBlock 选项不支持"
    "invalid_adblock" -> "AdBlock 语法无效"
    "invalid_domain" -> "域名无效"
    "invalid_mitm_host" -> "MITM 域名无效"
    "invalid_json_rule" -> "JSON 规则无效"
    else -> key
}
