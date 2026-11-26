package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.runtime.Composable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import org.json.JSONObject
import com.namu.dns.Actions
import com.namu.dns.AppConfig
import com.namu.dns.ConfigFileStore
import com.namu.dns.ConfigStore
import com.namu.dns.ruleLogicValueOk
import com.namu.dns.ruleLogicKinds
import com.namu.dns.core.config.ConfigIssueLevel
import com.namu.dns.core.config.ConfigSourceRegistry
import com.namu.dns.NativeCore
import com.namu.dns.App
import com.namu.dns.NodeInfo
import com.namu.dns.RuleItem
import com.namu.dns.RuleSource
import com.namu.dns.ProxyGroup
import com.namu.dns.StatsData
import com.namu.dns.core.config.ProxyGroupValidation
import com.namu.dns.normalizeAdsDomain
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val uiSettings get() = App.container.settings
private val uiRuntime get() = App.container.runtime
private val uiMessages get() = App.container.messages
private val uiContext get() = App.container.context

@Composable
fun NamuDialog(
    title: String,
    message: String? = null,
    confirmText: String = "确定",
    dismissText: String = "取消",
    confirmEnabled: Boolean = true,
    confirmColor: Color = NamuColors.Blue,
    loading: Boolean = false,
    showDismiss: Boolean = true,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    scrollContent: Boolean = false,
    content: @Composable ColumnScope.() -> Unit = {},
) {
    Dialog(onDismissRequest = { if (!loading) onDismiss() }) {
        var shown by remember { mutableStateOf(false) }
        LaunchedEffect(Unit) { shown = true }
        val scale by animateFloatAsState(
            if (shown) 1f else .96f,
            spring(dampingRatio = NamuTokens.PressDamping, stiffness = NamuTokens.PressStiffness),
            label = "dialog-scale",
        )
        val opacity by animateFloatAsState(if (shown) 1f else 0f, label = "dialog-opacity")
        val shape = RoundedCornerShape(NamuTokens.RadiusDialog)
        Column(
            Modifier
                .widthIn(max = if (scrollContent) 380.dp else 320.dp)
                .fillMaxWidth()
                .graphicsLayer { scaleX = scale; scaleY = scale; alpha = opacity }
                .shadow(14.dp, shape)
                .clip(shape)
                .background(NamuColors.Floating),
        ) {
            Column(
                Modifier.weight(1f, fill = false).fillMaxWidth().verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = if (scrollContent) 20.dp else 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    title,
                    style = NamuTokens.Type.Title,
                    color = NamuColors.TextMain,
                    textAlign = TextAlign.Center,
                )
                if (!message.isNullOrBlank()) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        message,
                        fontSize = 14.sp,
                        color = NamuColors.TextSub,
                        textAlign = TextAlign.Center,
                        lineHeight = 20.sp,
                    )
                }
                Spacer(Modifier.height(10.dp))
                content()
            }
            RowDivider(startInset = 0.dp)
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (showDismiss) {
                    TextButton(
                        onClick = onDismiss,
                        enabled = !loading,
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                        shape = CircleShape,
                        colors = ButtonDefaults.textButtonColors(
                            containerColor = NamuColors.Fill,
                            contentColor = NamuColors.TextMain,
                        ),
                    ) {
                        Text(dismissText, style = NamuTokens.Type.NavigationTitle, textAlign = TextAlign.Center)
                    }
                }
                TextButton(
                    onClick = onConfirm,
                    enabled = confirmEnabled && !loading,
                    modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                    shape = CircleShape,
                    colors = ButtonDefaults.textButtonColors(
                        containerColor = confirmColor.copy(alpha = .12f),
                        contentColor = confirmColor,
                        disabledContainerColor = NamuColors.Fill,
                        disabledContentColor = NamuColors.TextTertiary,
                    ),
                ) {
                    if (loading) {
                        CircularProgressIndicator(Modifier.size(17.dp), color = confirmColor, strokeWidth = 2.dp)
                    } else {
                        Text(confirmText, style = NamuTokens.Type.NavigationTitle, textAlign = TextAlign.Center)
                    }
                }
            }
        }
    }
}

@Composable
fun NamuTextField(
    value: String,
    onChange: (String) -> Unit,
    placeholder: String,
    modifier: Modifier = Modifier,
    singleLine: Boolean = false,
    maxLines: Int = 5,
) {
    BasicTextField(
        modifier = modifier,
        value = value,
        onValueChange = onChange,
        singleLine = singleLine,
        maxLines = if (singleLine) 1 else maxLines,
        textStyle = NamuTokens.Type.Body.copy(fontSize = 15.sp, lineHeight = 20.sp, color = NamuColors.TextMain),
        cursorBrush = SolidColor(NamuColors.Brand),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
        decorationBox = { inner ->
            Box(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 46.dp)
                    .clip(RoundedCornerShape(NamuTokens.RadiusControl))
                    .background(NamuColors.Fill)
                    .padding(horizontal = 14.dp, vertical = 11.dp),
                contentAlignment = Alignment.CenterStart,
            ) {
                if (value.isEmpty()) {
                    Text(placeholder, fontSize = 15.sp, color = NamuColors.TextSub)
                }
                inner()
            }
        },
    )
}

@Composable
fun ChoiceChip(text: String, selected: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Box(
        modifier
            .clip(RoundedCornerShape(NamuTokens.RadiusControl))
            .heightIn(min = 48.dp)
            .background(if (selected) NamuColors.Blue else NamuColors.Fill)
            .clickable { onClick() }
            .padding(horizontal = 10.dp, vertical = 7.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, fontSize = 12.sp, color = if (selected) Color.White else NamuColors.TextMain)
    }
}

@Composable
fun SubscriptionDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    var text by remember { mutableStateOf(uiSettings.current().subscription) }
    var append by remember { mutableStateOf(false) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var report by remember { mutableStateOf<Actions.ImportResult?>(null) }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current

    NamuDialog(
        title = "导入订阅",
        message = "粘贴 Clash 订阅链接，或直接粘贴 Base64 / 节点链接内容",
        confirmText = "导入",
        loading = loading,
        confirmEnabled = text.isNotBlank(),
        onDismiss = onDismiss,
        onConfirm = {
            scope.launch {
                loading = true
                error = null
                try {
                    val result = Actions.importSubscription(text, append = append)
                    uiSettings.update { current -> current.copy(
                        subscription = if (text.trim().startsWith("http")) text.trim() else current.subscription,
                    ) }
                    val skipped = if (result.skipped > 0) "，跳过 ${result.skipped} 个节点" else ""
                    uiMessages.show("已导入 ${result.nodes} 个节点、${result.rules} 条规则$skipped")
                    if (result.diagnostics.isEmpty() && result.warnings.isEmpty()) {
                        onDone()
                    } else {
                        report = result
                    }
                } catch (e: Exception) {
                    error = e.message ?: "导入失败"
                } finally {
                    loading = false
                }
            }
        },
    ) {
        NamuTextField(text, { text = it; error = null }, "https://… 或订阅内容", maxLines = 4)
        Row(
            Modifier.fillMaxWidth().padding(top = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("追加到现有节点", fontSize = 13.sp, color = NamuColors.TextMain)
                Text(
                    if (append) "保留已有分组，同名节点用新的覆盖" else "清空现有节点，只保留本次导入",
                    fontSize = 11.sp,
                    color = NamuColors.TextSub,
                )
            }
            IosSwitch(checked = append, onCheckedChange = { append = it })
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            MiniTextAction("从剪贴板粘贴") {
                clipboard.getText()?.text?.let { text = it }
            }
        }
        if (error != null) {
            Text(error!!, fontSize = 12.sp, color = NamuColors.Red, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        }
    }
    report?.let { result ->
        val counts = listOfNotNull(
            result.diagnosticCounts["unknown_scheme"]?.takeIf { it > 0 }?.let { "未知 scheme $it" },
            result.diagnosticCounts["unsupported_protocol"]?.takeIf { it > 0 }?.let { "已知不支持协议 $it" },
            result.diagnosticCounts["unsupported_param"]?.takeIf { it > 0 }?.let { "不支持参数 $it" },
            result.diagnosticCounts["invalid"]?.takeIf { it > 0 }?.let { "无效条目 $it" },
        ).joinToString("，")
        val shown = result.diagnostics.take(8).joinToString("\n") {
            "${it.line}. ${it.scheme} · ${diagnosticCategoryLabel(it.category)}：${it.reason}\n${it.raw}"
        }
        val more = if (result.diagnostics.size > 8) "\n…另有 ${result.diagnostics.size - 8} 条" else ""
        val warningText = result.warnings.take(3).joinToString("\n")
        val message = buildString {
            append("有效节点 ${result.nodes} / 输入 ${result.totalLines}；跳过 ${result.skipped} 个")
            if (counts.isNotBlank()) append("\n$counts")
            if (shown.isNotBlank()) append("\n\n$shown$more")
            if (warningText.isNotBlank()) append("\n\n$warningText")
        }
        NamuDialog(
            title = "订阅导入诊断",
            message = message,
            confirmText = "知道了",
            showDismiss = false,
            onConfirm = onDone,
            onDismiss = {},
        ) {}
    }
}

/** 手动规则的输入校验；与 ModuleParser 保持同一套边界。 */
internal fun ruleValueError(type: String, raw: String): String? {
    val v = raw.trim()
    if (v.isEmpty()) return "内容不能为空"
    return when (type) {
        "DOMAIN", "DOMAIN-SUFFIX" -> {
            val d = v.removePrefix("||").trimStart('|').trimEnd('^', '|').trim('.')
            if (com.namu.dns.isValidAdsDomain(d)) null else "请输入合法域名"
        }
        "DOMAIN-KEYWORD" -> if (v.any { it.isWhitespace() }) "关键词不能包含空格" else null
        "DOMAIN-REGEX", "URL-REGEX" -> runCatching { Regex(v) }.fold(
            onSuccess = { null },
            onFailure = { "正则无效：${it.message ?: "无法编译"}" },
        )
        "GEOIP" -> if (v.equals("CN", true)) null else "当前内置中国 IP 库，请填写 CN"
        "FINAL" -> if (v.equals("MATCH", true)) null else "FINAL 的值固定为 MATCH"
        "DST-PORT", "PORT" -> {
            val p = v.toIntOrNull()
            if (p == null || p !in 1..65535) "端口必须是 1–65535" else null
        }
        "IP-CIDR" -> if (validCidrValue(v, ipv6 = false)) null else "请输入合法 IPv4 CIDR（前缀 0–32）"
        "IP-CIDR6" -> if (validCidrValue(v, ipv6 = true)) null else "请输入合法 IPv6 CIDR（前缀 0–128）"
        "APP", "PROCESS-NAME", "APP-NAME" -> if (validPackageName(v)) null else "请输入应用包名，如 com.bilibili.app"
        "UID" -> if (v.toIntOrNull() != null) null else "UID 必须是数字"
        "AND", "OR", "NOT" -> if (ruleLogicValueOk(type, v)) null else "格式：((DOMAIN,a.com),(PORT,443))，子项可嵌套"
        "SCRIPT" -> if (v.none { it.isWhitespace() }) null else "脚本名不能含空格"
        else -> null
    }
}

/** 包名校验：允许子进程后缀（com.example.app:push）。 */
internal fun validPackageName(raw: String): Boolean {
    val v = raw.trim().substringBefore(':')
    if (v.isEmpty() || v.length > 255) return false
    // 每段至少一个字符，且只允许字母/数字/下划线；首段不能以数字开头（Android 包名规则）。
    val parts = v.split('.')
    if (parts.size < 2) return false
    if (parts.first()[0].isDigit()) return false
    return parts.all { p -> p.isNotEmpty() && p.all { it.isLetterOrDigit() || it == '_' } }
}

private fun validCidrValue(value: String, ipv6: Boolean): Boolean {
    val parts = value.split('/')
    if (parts.size != 2) return false
    val prefix = parts[1].toIntOrNull() ?: return false
    if (ipv6) {
        if (prefix !in 0..128 || !parts[0].contains(':')) return false
        return runCatching { java.net.InetAddress.getByName(parts[0]) is java.net.Inet6Address }.getOrDefault(false)
    }
    if (prefix !in 0..32) return false
    val octets = parts[0].split('.')
    if (octets.size != 4) return false
    return octets.all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
}

internal fun diagnosticCategoryLabel(category: String): String = when (category) {
    "unknown_scheme" -> "未知 scheme"
    "unsupported_protocol" -> "协议不支持"
    "unsupported_param" -> "参数不支持"
    "invalid" -> "无效"
    else -> category
}

@Composable
fun CustomAdsDialog(
    onDismiss: () -> Unit,
    onDone: () -> Unit,
    initial: List<String> = uiSettings.current().customAds,
    onSave: (List<String>) -> Unit = { domains -> uiSettings.update { it.copy(customAds = domains) } },
) {
    var items by remember { mutableStateOf(initial) }
    var input by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    fun add() {
        val domain = normalizeAdsDomain(input)
        when {
            domain == null -> error = "请输入有效域名，例如 ads.example.com"
            items.contains(domain) -> error = "该域名已在列表中"
            else -> {
                items = items + domain
                input = ""
                error = null
            }
        }
    }

    NamuDialog(
        title = "本地拦截域名",
        message = "只支持域名，不写 http://、路径或通配符；保存后会同时拦截该域名及其子域名。",
        confirmText = "保存",
        confirmEnabled = true,
        onDismiss = onDismiss,
        onConfirm = {
            onSave(items.distinct())
            onDone()
        },
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.weight(1f)) {
                NamuTextField(
                    value = input,
                    onChange = { input = it; error = null },
                    placeholder = "ads.example.com",
                    singleLine = true,
                )
            }
            Spacer(Modifier.width(6.dp))
            TextButton(onClick = { add() }, enabled = input.isNotBlank()) {
                Text("添加", fontSize = 14.sp, color = NamuColors.Blue)
            }
        }
        if (error != null) {
            Spacer(Modifier.height(6.dp))
            Text(
                error!!,
                fontSize = 12.sp,
                color = NamuColors.Red,
                textAlign = TextAlign.Start,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Spacer(Modifier.height(8.dp))
        if (items.isEmpty()) {
            Text("还没有本地拦截域名", fontSize = 12.sp, color = NamuColors.TextSub)
        } else {
            Column(
                Modifier
                    .fillMaxWidth()
                    .heightIn(max = 190.dp)
                    .verticalScroll(rememberScrollState()),
            ) {
                items.forEach { domain ->
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(domain, fontSize = 13.sp, color = NamuColors.TextMain, modifier = Modifier.weight(1f))
                        MiniTextAction("删除", color = NamuColors.Red) {
                            items = items - domain
                            error = null
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ScriptArgumentsDialog(
    scripts: List<com.namu.dns.core.config.ScriptConfig>,
    saved: Map<String, Map<String, String>>,
    onSave: (com.namu.dns.core.config.ScriptConfig, Map<String, String>) -> Unit,
    onDismiss: () -> Unit,
) {
    NamuDialog(
        title = "脚本参数",
        confirmText = "关闭",
        showDismiss = false,
        scrollContent = true,
        onDismiss = onDismiss,
        onConfirm = onDismiss,
    ) {
        Column(Modifier.fillMaxWidth()) {
            scripts.forEach { script ->
                val key = ConfigStore.scriptArgumentKey(script)
                var values by remember(script, saved) {
                    mutableStateOf(
                        script.arguments.mapValues { (k, v) -> saved[key]?.get(k) ?: v },
                    )
                }
                Text(
                    "${script.name.ifBlank { script.pattern }} · ${script.phase}",
                    fontSize = 13.sp, fontWeight = FontWeight.Medium, color = NamuColors.TextMain,
                    modifier = Modifier.padding(top = 12.dp, bottom = 4.dp),
                )
                if (script.arguments.isEmpty()) {
                    Text("无声明参数（[Argument] 为空）", fontSize = 11.sp, color = NamuColors.TextSub)
                } else {
                    script.arguments.keys.sorted().forEach { name ->
                        val type = script.argumentTypes[name] ?: "string"
                        Text("$name ($type)", fontSize = 11.sp, color = NamuColors.TextSub)
                        NamuTextField(values[name] ?: "", { v -> values = values + (name to v) }, "值")
                    }
                    TextButton(onClick = { onSave(script, values) }) {
                        Text("保存该脚本参数", fontSize = 12.sp, color = NamuColors.Accent)
                    }
                }
            }
        }
    }
}

@Composable
fun HostMapDialog(
    initial: Map<String, String>,
    onDismiss: () -> Unit,
    onDone: (Map<String, String>) -> Unit,
) {
    var text by remember {
        mutableStateOf(initial.entries.joinToString("\n") { "${it.key} = ${it.value}" })
    }
    var error by remember { mutableStateOf<String?>(null) }
    NamuDialog(
        title = "Host 映射",
        message = "每行一条：域名 = IP / 别名 / server:上游。支持 *.example.com；server:system 不支持。",
        confirmText = "保存",
        confirmEnabled = true,
        onDismiss = onDismiss,
        onConfirm = {
            val map = linkedMapOf<String, String>()
            var bad = false
            text.lineSequence().forEach { raw ->
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) return@forEach
                val i = line.indexOf('=')
                if (i <= 0) {
                    bad = true
                    return@forEach
                }
                val key = line.substring(0, i).trim().lowercase()
                val value = line.substring(i + 1).trim()
                if (key.isBlank() || value.isBlank()) {
                    bad = true
                } else {
                    map[key] = value
                }
            }
            if (bad) {
                error = "存在缺少域名或值的行，请按“域名 = 值”填写"
            } else {
                onDone(map)
            }
        },
    ) {
        NamuTextField(
            value = text,
            onChange = { text = it; error = null },
            placeholder = "example.com = 1.2.3.4\nold.example.com = new.example.com\napi.example.com = server:1.1.1.1",
            singleLine = false,
            maxLines = 8,
        )
        if (error != null) {
            Spacer(Modifier.height(6.dp))
            Text(error!!, fontSize = 12.sp, color = NamuColors.Red, modifier = Modifier.fillMaxWidth())
        }
    }
}


@Composable
fun RulesUpdateDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    var url by remember { mutableStateOf(uiSettings.current().rulesUrl) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    NamuDialog(
        title = "广告规则地址",
        message = "从该 URL 下载 AdBlock / hosts 格式规则，保存到本地并立即生效。更换地址后请重新下载。",
        confirmText = "下载",
        loading = loading,
        confirmEnabled = url.isNotBlank(),
        onDismiss = onDismiss,
        onConfirm = {
            scope.launch {
                loading = true
                error = null
                try {
                    val lines = Actions.updateAdsRules(url.trim())
                    uiSettings.update { it.copy(rulesUrl = url.trim()) }
                    uiMessages.show("广告规则已更新：$lines 行")
                    onDone()
                } catch (e: Exception) {
                    error = e.message ?: "下载失败"
                } finally {
                    loading = false
                }
            }
        },
    ) {
        NamuTextField(url, { url = it; error = null }, "https://你的服务器/ads.txt")
        if (error != null) {
            Spacer(Modifier.height(8.dp))
            Text(error!!, fontSize = 12.sp, color = NamuColors.Red, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
fun RemoteConfigDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    var url by remember { mutableStateOf(uiSettings.current().remoteConfigUrl) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    NamuDialog(
        title = "远端配置",
        message = "从你的服务器读取 JSON manifest：DNS 上游、bootstrap、fail-closed、模式、规则源 URL。大规则列表仍放在独立 URL。",
        confirmText = "保存并同步",
        loading = loading,
        confirmEnabled = url.isNotBlank(),
        onDismiss = onDismiss,
        onConfirm = {
            scope.launch {
                loading = true
                error = null
                try {
                    val result = Actions.importRemoteConfig(url.trim())
                    val suffix = if (result.errors.isEmpty()) "" else "；${result.errors.size} 个源失败：${result.errors.first()}"
                    uiMessages.show("已应用${result.name}：${result.sources} 个规则源、${result.lines} 行$suffix")
                    onDone()
                } catch (e: Exception) {
                    error = e.message ?: "导入失败"
                } finally {
                    loading = false
                }
            }
        },
    ) {
        NamuTextField(url, { url = it; error = null }, "https://你的服务器/namu/config.json", maxLines = 3)
        Spacer(Modifier.height(8.dp))
        Text(
            "示例字段：dns.upstream / dns.bootstrap / dns.fail_closed / rule_sources[] / routing.final_policy",
            fontSize = 11.sp,
            color = NamuColors.TextSub,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
        if (error != null) {
            Spacer(Modifier.height(8.dp))
            Text(error!!, fontSize = 12.sp, color = NamuColors.Red, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
fun RuleSourcesDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    var sources by remember { mutableStateOf(uiSettings.current().ruleSources) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    NamuDialog(
        title = "规则来源",
        message = if (sources.isEmpty()) {
            "当前没有 manifest 规则源。可在「远端配置」中定义 rule_sources，或继续使用手动规则 URL。"
        } else {
            "每个源独立下载、独立保留上一版；某个源失败不会清空其他规则。"
        },
        confirmText = "同步全部",
        loading = loading,
        confirmEnabled = sources.any { it.enabled },
        onDismiss = onDismiss,
        onConfirm = {
            scope.launch {
                loading = true
                error = null
                try {
                    val result = Actions.syncRuleSources()
                    sources = uiSettings.current().ruleSources
                    val msg = StringBuilder("已更新 ${result.updated} 个源，共 ${result.lines} 行")
                    if (result.errors.isNotEmpty()) {
                        msg.append("；失败：${result.errors.first()}")
                        error = msg.toString()
                    } else {
                        uiMessages.show(msg.toString())
                        onDone()
                    }
                } catch (e: Exception) {
                    error = e.message ?: "同步失败"
                } finally {
                    loading = false
                }
            }
        },
    ) {
        if (sources.isNotEmpty()) {
            Column(
                Modifier.fillMaxWidth().heightIn(max = 300.dp).verticalScroll(rememberScrollState()),
            ) {
                sources.forEach { src ->
                    SourceRow(src)
                }
            }
        }
        if (error != null) {
            Spacer(Modifier.height(8.dp))
            Text(error!!, fontSize = 12.sp, color = NamuColors.Red, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun SourceRow(src: RuleSource) {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 7.dp),
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(src.id, fontSize = 13.sp, color = NamuColors.TextMain, fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
            Text(
                when {
                    src.error.isNotBlank() && src.stale -> "失败·用旧缓存"
                    src.error.isNotBlank() -> "失败"
                    src.lines > 0 -> "${src.lines} 行"
                    else -> "待同步"
                },
                fontSize = 11.sp,
                color = if (src.error.isNotBlank()) NamuColors.Red else NamuColors.TextSub,
            )
        }
        Text(src.url, fontSize = 10.sp, color = NamuColors.TextTertiary, maxLines = 2)
        if (src.error.isNotBlank()) {
            Text(src.error, fontSize = 10.sp, color = NamuColors.Red, maxLines = 2)
            if (src.stale) {
                Text("失败后继续使用上一份缓存（${src.lines} 行）", fontSize = 10.sp, color = NamuColors.TextTertiary)
            }
        } else if (src.updatedAt > 0) {
            Text("上次同步 ${formatAgo(src.updatedAt)}", fontSize = 10.sp, color = NamuColors.TextTertiary)
        }
    }
}

@Composable
fun AddRuleDialog(
    groups: List<String> = emptyList(),
    initial: RuleItem? = null,
    onDismiss: () -> Unit,
    onAdd: (RuleItem) -> Unit,
) {
    var type by remember { mutableStateOf(initial?.type ?: "DOMAIN-SUFFIX") }
    var value by remember { mutableStateOf(initial?.value.orEmpty()) }
    var action by remember { mutableStateOf(initial?.action ?: "proxy") }
    var extendedMatch by remember { mutableStateOf(initial?.extendedMatch ?: false) }
    var preMatch by remember { mutableStateOf(initial?.preMatch ?: false) }
    val domainType = type.startsWith("DOMAIN") && type != "DOMAIN-SET"
    val httpType = type == "URL-REGEX" || type == "USER-AGENT"

    val types = listOf(
        "DOMAIN-SUFFIX" to "后缀",
        "DOMAIN" to "域名",
        "DOMAIN-KEYWORD" to "关键词",
        "DOMAIN-REGEX" to "正则",
        "DOMAIN-WILDCARD" to "通配符",
        "IP-CIDR" to "IPv4 段",
        "IP-CIDR6" to "IPv6 段",
        "USER-AGENT" to "User-Agent",
        "URL-REGEX" to "URL 正则",
        "RULE-SET" to "规则集",
        "DOMAIN-SET" to "域名集",
        "DST-PORT" to "目标端口",
        "PORT" to "端口",
        "GEOIP" to "GEOIP",
        "FINAL" to "FINAL",
        "APP" to "按应用",
        "AND" to "逻辑与",
        "OR" to "逻辑或",
        "NOT" to "逻辑非",
        "SCRIPT" to "脚本",
    )
    val actions = if (httpType) listOf(
        "reject" to "REJECT",
        "reject-dict" to "空 JSON 对象",
        "reject-array" to "空 JSON 数组",
        "reject-200" to "HTTP 200",
        "reject-img" to "1 像素 GIF",
        "reject-tinygif" to "TINYGIF",
        "reject-video" to "空白 MP4",
        "reject-drop" to "DROP",
    ) else listOf("proxy" to "PROXY", "direct" to "DIRECT", "block" to "REJECT")
    LaunchedEffect(type) {
        if (httpType && actions.none { it.first == action }) action = "reject"
        if (!httpType && action.startsWith("reject")) action = "block"
        if (type == "FINAL" && value.isBlank()) value = "MATCH"
    }
    val inputError = if (value.isBlank()) null else ruleValueError(type, value)

    NamuDialog(
        title = if (initial == null) "添加规则" else "编辑规则",
        confirmText = if (initial == null) "添加" else "保存",
        confirmEnabled = value.isNotBlank() && inputError == null && (!preMatch || action == "block"),
        scrollContent = true,
        onDismiss = onDismiss,
        onConfirm = {
            onAdd(initial?.copy(type = type, value = value.trim(), action = action, extendedMatch = extendedMatch && domainType, preMatch = preMatch && action == "block")
                ?: RuleItem(type = type, value = value.trim(), action = action, extendedMatch = extendedMatch && domainType, preMatch = preMatch && action == "block"))
        },
    ) {
        NamuTextField(
            value,
            { value = it },
            when (type) {
                "DOMAIN-REGEX" -> "^ad[0-9]+\\.example\\.com$"
                "URL-REGEX" -> "^https://example\\.com/ads/"
                "USER-AGENT" -> "AdBot*"
                "RULE-SET", "DOMAIN-SET" -> "https://example.com/rules.txt 或规则源 ID"
                "GEOIP" -> "CN"
                "FINAL" -> "MATCH"
                "DST-PORT", "PORT" -> "443、8443 或 1-65535"
                "IP-CIDR" -> "1.2.3.0/24"
                "IP-CIDR6" -> "2001:db8::/32"
                "APP", "PROCESS-NAME", "APP-NAME" -> "com.bilibili.app"
                "UID" -> "10100"
                "AND", "OR", "NOT" -> "((DOMAIN-SUFFIX,ads.com),(PORT,443))"
                "SCRIPT" -> "脚本名（脚本内定义 match(ctx) 返回布尔）"
                else -> "example.com 或 1.2.3.0/24"
            },
            singleLine = type !in ruleLogicKinds,
        )
        Spacer(Modifier.height(12.dp))
        Text("类型", fontSize = 12.sp, color = NamuColors.TextSub, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(6.dp))
        types.chunked(3).forEach { row ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                row.forEach { (key, label) ->
                    ChoiceChip(label, type == key, Modifier.weight(1f)) { type = key }
                }
                repeat(3 - row.size) { Spacer(Modifier.weight(1f)) }
            }
            Spacer(Modifier.height(6.dp))
        }
        Text(
            when (type) {
                "DOMAIN" -> "只匹配该域名本身，不会影响子域名"
                "DOMAIN-SUFFIX" -> "会同时匹配该域名和所有子域名"
                "DOMAIN-KEYWORD" -> "域名里包含该关键词就命中"
                "DOMAIN-REGEX" -> "按正则表达式匹配域名；非法正则不能添加"
                "URL-REGEX" -> "匹配完整 URL；需开启 HTTPS 解密，按所选 HTTP 响应拦截"
                "USER-AGENT" -> "支持 * 通配；需开启 HTTPS 解密，按请求头匹配"
                "RULE-SET", "DOMAIN-SET" -> "下载并缓存后展开；集合策略覆盖列表内策略"
                "GEOIP" -> "当前内置中国 IP 库，请填写 CN"
                "FINAL" -> "最终兜底规则，值固定为 MATCH"
                "DST-PORT", "PORT" -> "匹配目标端口，范围 1–65535"
                "IP-CIDR" -> "匹配 IPv4 CIDR；前缀范围 0–32"
                "IP-CIDR6" -> "匹配 IPv6 CIDR；前缀范围 0–128"
                "APP", "PROCESS-NAME", "APP-NAME" -> "只对填写的应用生效，其他应用不受影响；识别归属需要 Root"
                "UID" -> "按 Android UID 匹配；需要 Root 才能识别连接归属"
                else -> "按 IP 段匹配"
            },
            fontSize = 11.sp,
            color = NamuColors.TextSub,
            modifier = Modifier.fillMaxWidth(),
        )
        if (inputError != null) {
            Text(inputError, fontSize = 11.sp, color = NamuColors.Red, modifier = Modifier.fillMaxWidth().padding(top = 4.dp))
        }
        Spacer(Modifier.height(12.dp))
        Text("策略", fontSize = 12.sp, color = NamuColors.TextSub, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(6.dp))
        actions.chunked(3).forEach { row ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                row.forEach { (key, label) ->
                    ChoiceChip(label, action == key, Modifier.weight(1f)) { action = key }
                }
                repeat(3 - row.size) { Spacer(Modifier.weight(1f)) }
            }
            Spacer(Modifier.height(6.dp))
        }
        if (groups.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text("或选择策略组", fontSize = 12.sp, color = NamuColors.TextSub, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(6.dp))
            groups.chunked(2).forEach { row ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    row.forEach { name ->
                        ChoiceChip(name, action == name, Modifier.weight(1f)) { action = name }
                    }
                    if (row.size == 1) Spacer(Modifier.weight(1f))
                }
                Spacer(Modifier.height(5.dp))
            }
        }
        Spacer(Modifier.height(8.dp))
        SwitchRow(
            title = "扩展匹配",
            subtitle = if (domainType) "同时匹配 TLS SNI 与 HTTP Host" else "仅域名类规则可用",
            checked = extendedMatch && domainType,
        ) { if (domainType) extendedMatch = it }
        SwitchRow(
            title = "预匹配",
            subtitle = if (action == "block") "在普通规则前优先判定" else "仅拦截策略可用",
            checked = preMatch && action == "block",
            showDivider = false,
        ) { if (action == "block") preMatch = it }
    }
}

@Composable
fun DnsDialog(current: String, onDismiss: () -> Unit, onSelect: (String) -> Unit) {
    var system by remember { mutableStateOf(current.isBlank() || current == "system") }
    var address by remember { mutableStateOf(current.takeUnless { it == "system" }.orEmpty()) }
    val issue = if (system) null else com.namu.dns.core.config.ConfigDnsInput.error(address)
    NamuDialog(
        title = "DNS 地址",
        confirmText = "保存",
        confirmEnabled = issue == null,
        onDismiss = onDismiss,
        onConfirm = { onSelect(if (system) "system" else address.trim()) },
    ) {
        SettingsRow("系统 DNS", onClick = { system = true },
            value = if (system) "✓" else null)
        SettingsRow("自定义 DNS", onClick = { system = false }, value = if (!system) "✓" else null)
        if (!system) {
            NamuTextField(address, { address = it }, "DoH、DoT 或 UDP 地址", singleLine = true)
            if (address.isNotBlank() && issue != null) Text(issue, color = NamuColors.Red, fontSize = 12.sp)
        }
    }
}

@Composable
fun StringListDialog(
    title: String,
    message: String,
    initial: List<String>,
    onDismiss: () -> Unit,
    onConfirm: (List<String>) -> Unit,
) {
    var text by remember { mutableStateOf(initial.joinToString("\n")) }
    val values = text.lines().map { it.trim().trim('.').lowercase() }.filter { it.isNotBlank() }.distinct()
    val invalid = values.firstOrNull { !Regex("^[a-z0-9_*.-]+$").matches(it) }
    NamuDialog(
        title = title,
        message = message,
        confirmText = "保存",
        confirmEnabled = invalid == null,
        onDismiss = onDismiss,
        onConfirm = { onConfirm(values) },
    ) {
        NamuTextField(text, { text = it }, "example.com\n*.example.org", maxLines = 8)
        if (invalid != null) Text("无效域名：$invalid", color = NamuColors.Red, fontSize = 12.sp)
    }
}

@Composable
fun ChoiceDialog(
    title: String,
    message: String = "",
    options: List<Pair<String, String>>,
    selected: String,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    NamuDialog(
        title = title,
        message = message,
        confirmText = "关闭",
        showDismiss = false,
        onConfirm = onDismiss,
        onDismiss = onDismiss,
    ) {
        options.forEach { (key, label) ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(NamuTokens.RadiusControl))
                    .clickable { onSelect(key) }
                    .padding(horizontal = 10.dp, vertical = 11.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(label, fontSize = 14.sp, color = NamuColors.TextMain, modifier = Modifier.weight(1f))
                if (selected == key) CheckMark()
            }
        }
    }
}


@Composable
fun NodeInfoDialog(
    node: NodeInfo,
    selected: Boolean,
    onSelect: () -> Unit,
    onDelete: () -> Unit,
    onDismiss: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    NamuDialog(
        title = node.name,
        confirmText = "关闭",
        showDismiss = false,
        onConfirm = onDismiss,
        onDismiss = onDismiss,
    ) {
        Column(Modifier.fillMaxWidth()) {
            InfoLine("协议", node.typeLabel)
            InfoLine("地址", "${node.server}:${node.port}")
            if (node.type == "ss") InfoLine("加密", node.method ?: "-")
            if (!node.sni.isNullOrBlank()) InfoLine("SNI", node.sni!!)
            if (!node.wsPath.isNullOrBlank()) InfoLine("路径", node.wsPath!!)
            InfoLine("延迟", node.latency?.let { "$it ms" } ?: "未测试")
            if (selected) InfoLine("状态", "当前使用")
            Spacer(Modifier.height(6.dp))
            Box(Modifier.fillMaxWidth().height(0.5.dp).background(NamuColors.Separator))
            DialogAction("设为当前服务器", NamuColors.Blue) { onSelect() }
            Box(Modifier.fillMaxWidth().height(0.5.dp).background(NamuColors.Separator))
            DialogAction("复制分享链接", NamuColors.Blue) {
                clipboard.setText(AnnotatedString(node.shareLink()))
                uiMessages.show("链接已复制")
                onDismiss()
            }
            Box(Modifier.fillMaxWidth().height(0.5.dp).background(NamuColors.Separator))
            DialogAction("删除该服务器", NamuColors.Red) { onDelete() }
        }
    }
}

@Composable
private fun InfoLine(label: String, value: String) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, fontSize = 13.sp, color = NamuColors.TextSub)
        Spacer(Modifier.weight(1f))
        Text(value, fontSize = 13.sp, color = NamuColors.TextMain, maxLines = 1)
    }
}

@Composable
private fun DialogAction(text: String, color: Color, onClick: () -> Unit) {
    Box(
        Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(vertical = 11.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, fontSize = 15.sp, color = color)
    }
}

@Composable
fun ConfigNameDialog(
    title: String,
    initial: String = "",
    confirmText: String = "创建",
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf(initial) }
    NamuDialog(
        title = title,
        confirmText = confirmText,
        confirmEnabled = name.isNotBlank(),
        onConfirm = { onConfirm(name.trim()) },
        onDismiss = onDismiss,
    ) {
        NamuTextField(name, { name = it }, "例如 自用.conf", singleLine = true)
    }
}

/** 配置导入预览只保留结论：不可用项包含跳过/未知/部分支持段落与非 INFO 诊断。 */
private fun configUnusableCount(preview: com.namu.dns.core.config.ConfigSourcePreview): Int {
    val count = preview.skipped.size + preview.unknown.size + preview.partial.size +
        preview.issues.count { it.level != ConfigIssueLevel.INFO }
    return if (preview.canImport) count else maxOf(1, count)
}

@Composable
fun ConfigImportDialog(
    urlMode: Boolean = false,
    onDone: (ConfigFileStore.FileInfo) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf("导入.conf") }
    var url by remember { mutableStateOf("") }
    var text by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var reading by remember { mutableStateOf(false) }
    val context = uiContext
    val settings = uiSettings
    val composeContext = LocalContext.current
    val scope = rememberCoroutineScope()
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            reading = true
            error = null
            try {
                val picked = withContext(Dispatchers.IO) {
                    val display = composeContext.contentResolver.query(uri, null, null, null, null)?.use { c ->
                        val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                        if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
                    }
                    val bytes = composeContext.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw RuntimeException("无法读取该文件")
                    if (bytes.size > 2 * 1024 * 1024) throw RuntimeException("配置文件超过 2MB")
                    (display ?: "导入.conf") to bytes.toString(Charsets.UTF_8)
                }
                val (fileName, content) = picked
                name = fileName
                text = content.removePrefix("\uFEFF")
            } catch (e: Exception) {
                error = e.message ?: "读取配置文件失败"
            } finally {
                reading = false
            }
        }
    }
    val preview = remember(text, settings.current().toJson().toString()) {
        if (text.isBlank()) null else ConfigSourceRegistry.preview(text, settings.current())
    }

    NamuDialog(
        title = if (urlMode) "URL 导入" else "导入配置文件",
        message = "",
        confirmText = if (preview?.canImport == true) "导入" else "仅预览",
        loading = reading,
        confirmEnabled = name.isNotBlank() && text.isNotBlank() && preview?.canImport == true,
        onConfirm = {
            error = null
            val p = preview ?: return@NamuDialog
            if (!p.canImport) {
                error = p.reason.ifBlank { "当前格式仅支持识别和预览，暂不启用" }
                return@NamuDialog
            }
            val n = ConfigFileStore.sanitize(name)
            if (ConfigFileStore.exists(context, n)) {
                error = "已存在同名配置文件"
            } else if (App.container.config.import(n, text.trim(), url.trim().takeIf { urlMode && it.isNotBlank() })) {
                onDone(ConfigFileStore.FileInfo(n, 0L, 0L, false, false))
            } else {
                error = "内容不是有效的原生配置，或写入失败"
            }
        },
        onDismiss = onDismiss,
    ) {
        NamuTextField(name, { name = it }, "文件名", singleLine = true)
        Spacer(Modifier.height(8.dp))
        if (urlMode) {
            NamuTextField(url, { url = it; error = null }, "https://example.com/config.conf", maxLines = 3)
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Start) {
                MiniTextAction("下载") {
                    scope.launch {
                        reading = true
                        error = null
                        try {
                            val content = Actions.fetchText(url.trim(), maxBytes = 2 * 1024 * 1024)
                            text = content.removePrefix("\uFEFF")
                            name = url.substringAfterLast('/').substringBefore('?').ifBlank { "导入.conf" }
                        } catch (e: Exception) {
                            error = e.message ?: "下载失败"
                        } finally {
                            reading = false
                        }
                    }
                }
            }
        } else {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Start) {
                MiniTextAction("选择文件") {
                    error = null
                    filePicker.launch(arrayOf("*/*"))
                }
            }
        }
        preview?.let { p ->
            Spacer(Modifier.height(8.dp))
            val unusable = configUnusableCount(p)
            Text(
                if (unusable == 0) "全部可用" else "有 $unusable 个不可用",
                fontSize = 13.sp,
                color = if (unusable == 0) NamuColors.Green else NamuColors.Orange,
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            )
        }
        error?.let {
            Text(it, fontSize = 12.sp, color = NamuColors.Red, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
fun ProxyGroupsDialog(
    groups: List<ProxyGroup>,
    nodes: List<String>,
    selections: Map<String, String>,
    observeRuntime: Boolean = true,
    onChange: (List<ProxyGroup>, Map<String, String>) -> Boolean = { next, selection ->
        uiSettings.update { it.copy(proxyGroups = next, groupSelections = selection) }
        true
    },
    onDismiss: () -> Unit,
) {
    var editing by remember { mutableStateOf<ProxyGroup?>(null) }
    var creating by remember { mutableStateOf(false) }
    // 组页面可见时才轮询内核 stats；对话框销毁即停止，不建常驻通道。
    var liveStats by remember { mutableStateOf<StatsData?>(null) }
    LaunchedEffect(observeRuntime) {
        if (!observeRuntime) return@LaunchedEffect
        while (true) {
            if (NativeCore.available) {
                val raw = withContext(Dispatchers.IO) { NativeCore.nativeStats() }
                liveStats = StatsData.fromJson(raw)
            }
            delay(2_000)
        }
    }
    if (editing != null || creating) {
        ProxyGroupEditorDialog(
            initial = editing,
            isNew = creating,
            groups = groups,
            nodes = nodes,
            selections = selections,
            onChange = onChange,
            onDismiss = {
                editing = null
                creating = false
            },
        )
        return
    }
    NamuDialog(
        title = "策略组",
        message = "select 手动选择；url-test 按测速延迟选；fallback 按顺序故障切换。规则动作可直接写组名。",
        confirmText = "完成",
        showDismiss = false,
        onConfirm = onDismiss,
        onDismiss = onDismiss,
    ) {
        Column(
            Modifier.fillMaxWidth().heightIn(max = 360.dp).verticalScroll(rememberScrollState()),
        ) {
            if (groups.isEmpty()) {
                Text(
                    "还没有策略组。创建后可在规则动作或最终策略里直接引用组名。",
                    fontSize = 12.sp, color = NamuColors.TextSub,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp),
                )
            }
            groups.forEachIndexed { index, g ->
                val selected = selections[g.name]
                val health = liveStats?.groupHealth?.firstOrNull { it.name == g.name }
                val current = health?.current ?: selected
                val issues = ProxyGroupValidation.validate(groups, nodes, selections)
                    .count { it.level == ConfigIssueLevel.ERROR && it.path.contains(g.name) }
                SettingsRow(
                    title = g.name,
                    subtitle = buildString {
                        append(
                            when (g.type) {
                                "url-test" -> "url-test · ${g.testUrl}"
                                "fallback" -> "fallback · 故障切换"
                                "load-balance" -> "load-balance · ${if (g.lbMode == "round-robin") "轮询" else "一致性哈希"}"
                                else -> "select · 手动选择"
                            },
                        )
                        append(" · ${g.members.size} 个成员")
                        if (!current.isNullOrBlank()) append(" · 当前 $current")
                        if (issues > 0) append(" · $issues 个错误")
                    },
                    value = if (g.type == "select") "选择" else "自动",
                    valueColor = if (issues > 0) NamuColors.Red else NamuColors.TextSub,
                    chevron = true,
                    showDivider = index < groups.lastIndex,
                    onClick = { editing = g },
                )
                val leafHealth = health?.members?.filter { it.node } ?: emptyList()
                if (leafHealth.isNotEmpty()) {
                    Text(
                        leafHealth.joinToString("  ") { m ->
                            val latency = m.tcpLatencyMs?.let { "${it}ms" } ?: "—"
                            val mark = when (m.tcpStatus) {
                                "healthy" -> "✓"
                                "unhealthy" -> "✗"
                                "failing" -> "!"
                                else -> "?"
                            }
                            "${m.name} $latency$mark"
                        },
                        fontSize = 11.sp,
                        color = NamuColors.TextSub,
                        lineHeight = 15.sp,
                        modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 8.dp),
                    )
                }
            }
            TextButton(onClick = { creating = true }, modifier = Modifier.fillMaxWidth()) {
                Text("+ 新增策略组", fontSize = 14.sp, color = NamuColors.Blue)
            }
        }
    }
}

@Composable
private fun ProxyGroupEditorDialog(
    initial: ProxyGroup?,
    isNew: Boolean,
    groups: List<ProxyGroup>,
    nodes: List<String>,
    selections: Map<String, String>,
    onChange: (List<ProxyGroup>, Map<String, String>) -> Boolean,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf(initial?.name ?: "") }
    var type by remember { mutableStateOf(initial?.type ?: "select") }
    var members by remember { mutableStateOf(initial?.members ?: emptyList()) }
    var selection by remember { mutableStateOf(selections[initial?.name] ?: "") }
    var testUrl by remember { mutableStateOf(initial?.testUrl ?: "http://www.gstatic.com/generate_204") }
    var interval by remember { mutableStateOf((initial?.interval ?: 600).toString()) }
    var timeout by remember { mutableStateOf((initial?.timeout ?: 5000).toString()) }
    var tolerance by remember { mutableStateOf((initial?.tolerance ?: 50).toString()) }
    var failureThreshold by remember { mutableStateOf((initial?.failureThreshold ?: 3).toString()) }
    var recoveryThreshold by remember { mutableStateOf((initial?.recoveryThreshold ?: 2).toString()) }
    var noNodeAction by remember { mutableStateOf(initial?.noNodeAction ?: "global") }
    var lbMode by remember { mutableStateOf(initial?.lbMode ?: "consistent-hash") }
    var switchInterval by remember { mutableStateOf((initial?.switchInterval ?: 30).toString()) }

    val candidate = ProxyGroup(
        name = name.trim(),
        type = type,
        members = members,
        testUrl = testUrl.trim(),
        interval = interval.toIntOrNull() ?: 600,
        timeout = timeout.toIntOrNull() ?: 5000,
        tolerance = tolerance.toIntOrNull() ?: 50,
        failureThreshold = failureThreshold.toIntOrNull() ?: 3,
        recoveryThreshold = recoveryThreshold.toIntOrNull() ?: 2,
        noNodeAction = noNodeAction,
        lbMode = lbMode,
        switchInterval = switchInterval.toIntOrNull() ?: 30,
    )
    val baseOthers = groups.filter { it.name != (initial?.name ?: "") }
    val candidateGroups = if (isNew) groups + candidate else baseOthers + candidate
    val candidateSelections = selections.toMutableMap().apply {
        if (type == "select" && selection.isNotBlank() && selection in members) {
            put(candidate.name, selection)
        } else {
            remove(candidate.name)
        }
    }
    val validation = ProxyGroupValidation.validate(candidateGroups, nodes, candidateSelections)
    val cycle = !isNew && ProxyGroupValidation.wouldCreateCycle(groups, initial?.name ?: "", members)
    val duplicateName = candidate.name.isNotBlank() && groups.any { it.name == candidate.name && it.name != initial?.name }
    val errors = validation.count { it.level == ConfigIssueLevel.ERROR } +
        (if (cycle) 1 else 0) + (if (duplicateName) 1 else 0)
    val canSave = candidate.name.isNotBlank() && members.isNotEmpty() && errors == 0

    fun save() {
        val nextGroups = if (isNew) groups + candidate else groups.map { if (it.name == initial?.name) candidate else it }
        val nextSelections = selections.toMutableMap().apply {
            if (type == "select" && selection.isNotBlank() && selection in members) {
                put(candidate.name, selection)
            } else {
                remove(candidate.name)
            }
            if (!isNew && initial?.name != candidate.name) remove(initial?.name ?: "")
        }
        if (onChange(nextGroups, nextSelections)) onDismiss()
    }

    NamuDialog(
        title = if (isNew) "新增策略组" else "编辑策略组",
        message = "成员可选节点或其他策略组；循环、空组、缺失引用和重复名称会阻止保存。",
        confirmText = "保存",
        confirmEnabled = canSave,
        onConfirm = { save() },
        onDismiss = onDismiss,
    ) {
        Column(
            Modifier.fillMaxWidth().heightIn(max = 390.dp).verticalScroll(rememberScrollState()),
        ) {
            if (isNew) {
                NamuTextField(name, { name = it; selection = "" }, "组名，例如 自动选择", singleLine = true)
            } else {
                Text("组名：${initial?.name.orEmpty()}", fontSize = 13.sp, color = NamuColors.TextMain)
            }
            Spacer(Modifier.height(10.dp))
            Text("类型", fontSize = 12.sp, color = NamuColors.TextSub)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf(
                    "select" to "手动",
                    "url-test" to "测速",
                    "fallback" to "故障",
                    "load-balance" to "负载",
                ).forEach { (key, label) ->
                    ChoiceChip(label, type == key, Modifier.weight(1f)) { type = key }
                }
            }
            if (type == "load-balance") {
                Spacer(Modifier.height(8.dp))
                Text("选路方式", fontSize = 12.sp, color = NamuColors.TextSub)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ChoiceChip("一致性哈希", lbMode != "round-robin", Modifier.weight(1f)) {
                        lbMode = "consistent-hash"
                    }
                    ChoiceChip("轮询", lbMode == "round-robin", Modifier.weight(1f)) {
                        lbMode = "round-robin"
                    }
                }
            }
            if (type == "url-test" || type == "fallback" || type == "load-balance") {
                Spacer(Modifier.height(6.dp))
                NamuTextField(switchInterval, { switchInterval = it }, "切换间隔 秒（默认 30）", singleLine = true)
            }
            Spacer(Modifier.height(10.dp))
            Text("成员（节点 / 策略组）", fontSize = 12.sp, color = NamuColors.TextSub)
            val candidates = (nodes + groups.filter { it.name != (initial?.name ?: "") }.map { it.name })
                .filter { it.isNotBlank() }
                .distinct()
            candidates.chunked(2).forEach { row ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    row.forEach { member ->
                        val chosen = member in members
                        ChoiceChip(member, chosen, Modifier.weight(1f)) {
                            members = if (chosen) members - member else members + member
                            if (selection !in members) selection = ""
                        }
                    }
                    if (row.size == 1) Spacer(Modifier.weight(1f))
                }
                Spacer(Modifier.height(5.dp))
            }
            if (type == "select") {
                Spacer(Modifier.height(8.dp))
                Text("当前选择（留空则默认第一个成员）", fontSize = 12.sp, color = NamuColors.TextSub)
                members.chunked(2).forEach { row ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        row.forEach { member ->
                            ChoiceChip(member, selection == member, Modifier.weight(1f)) {
                                selection = if (selection == member) "" else member
                            }
                        }
                        if (row.size == 1) Spacer(Modifier.weight(1f))
                    }
                    Spacer(Modifier.height(5.dp))
                }
            }
            if (type != "select") {
                Spacer(Modifier.height(8.dp))
                NamuTextField(testUrl, { testUrl = it }, "测速 URL", singleLine = true)
                Spacer(Modifier.height(6.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    NamuTextField(timeout, { timeout = it }, "超时 ms", singleLine = true, modifier = Modifier.weight(1f))
                    NamuTextField(interval, { interval = it }, "间隔秒", singleLine = true, modifier = Modifier.weight(1f))
                }
                Spacer(Modifier.height(6.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    NamuTextField(failureThreshold, { failureThreshold = it }, "失败阈值", singleLine = true, modifier = Modifier.weight(1f))
                    NamuTextField(recoveryThreshold, { recoveryThreshold = it }, "恢复阈值", singleLine = true, modifier = Modifier.weight(1f))
                }
            }
            if (type == "url-test") {
                Spacer(Modifier.height(6.dp))
                NamuTextField(tolerance, { tolerance = it }, "切换容差 ms", singleLine = true)
            }
            Spacer(Modifier.height(8.dp))
            Text("无可用成员时", fontSize = 12.sp, color = NamuColors.TextSub)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("global" to "跟随全局", "block" to "拦截", "direct" to "直连").forEach { (key, label) ->
                    ChoiceChip(label, noNodeAction == key, Modifier.weight(1f)) { noNodeAction = key }
                }
            }
            val errorText = validation.filter { it.level == ConfigIssueLevel.ERROR }.joinToString("\n") { it.message }
            if (cycle || duplicateName || errorText.isNotBlank()) {
                Spacer(Modifier.height(8.dp))
                Text(
                    buildString {
                        if (duplicateName) append("组名已存在\n")
                        if (cycle) append("成员会形成嵌套循环\n")
                        append(errorText)
                    }.trim(),
                    fontSize = 11.sp, color = NamuColors.Red, lineHeight = 16.sp,
                )
            }
            if (!isNew) {
                Spacer(Modifier.height(8.dp))
                TextButton(
                    onClick = {
                        val next = groups.filterNot { it.name == initial?.name }
                        val nextSel = selections - (initial?.name ?: "")
                        if (onChange(next, nextSel)) onDismiss()
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("删除该策略组", fontSize = 13.sp, color = NamuColors.Red)
                }
            }
        }
    }
}

@Composable
fun RuleTestDialog(
    config: AppConfig = uiSettings.current(),
    useRuntimeAssets: Boolean = true,
    onDismiss: () -> Unit,
) {
    var input by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    NamuDialog(
        title = "测试规则",
        message = if (useRuntimeAssets) "输入域名或 IPv4，查看会命中哪条规则" else "测试此方案的自定义规则",
        confirmText = "测试",
        confirmEnabled = input.isNotBlank(),
        onConfirm = {
            val text = input.trim()
            scope.launch {
                // 优先用内核算：与运行时同一套判定（含模块规则、CN 直连、模式覆盖）。
                val native = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                    if (!useRuntimeAssets || !NativeCore.available) return@withContext null
                    runCatching {
                        val json = NativeCore.nativeTestRule(
                            ConfigStore.buildNative(uiContext, config),
                            text,
                        )
                        val o = org.json.JSONObject(json)
                        val detail = o.optString("detail").ifBlank { return@runCatching null }
                        buildString {
                            append(detail)
                            val chain = o.optJSONArray("chain")
                            if (chain != null && chain.length() > 0) {
                                append("\n解析链：")
                                for (i in 0 until chain.length()) {
                                    if (i > 0) append(" → ")
                                    append(chain.optString(i))
                                }
                            }
                            append("\n判定：").append(o.optString("action", "未知"))
                            val ruleAction = o.optString("ruleAction")
                            if (ruleAction.isNotBlank() && ruleAction != o.optString("action")) {
                                append("　规则动作：").append(ruleAction)
                            }
                            val node = o.optString("node")
                            if (node.isNotBlank()) append("　实际使用：").append(node)
                            val udpAction = o.optString("udpAction")
                            if (udpAction.isNotBlank()) {
                                append("\nUDP 判定：").append(udpAction)
                                val udpNode = o.optString("udpNode")
                                if (udpNode.isNotBlank()) append("　目标：").append(udpNode)
                                val udpChain = o.optJSONArray("udpChain")
                                if (udpChain != null && udpChain.length() > 0) {
                                    append("　解析链：")
                                    for (i in 0 until udpChain.length()) {
                                        if (i > 0) append(" → ")
                                        append(udpChain.optString(i))
                                    }
                                }
                            }
                            val issues = o.optJSONArray("issues")
                            if (issues != null && issues.length() > 0) {
                                append("\n诊断：")
                                for (i in 0 until issues.length()) append("\n· ").append(issues.optString(i))
                            }
                        }
                    }.getOrNull()
                }
                result = native ?: evaluateRule(config, text)
            }
        },
        onDismiss = onDismiss,
    ) {
        NamuTextField(input, { input = it; result = null }, "example.com 或 1.2.3.4", singleLine = true)
        Text(
            "分流规则按顺序匹配、命中即停，FINAL 永远最后；DNS 拦截白名单在过滤层单独生效，不在这张规则表里。",
            fontSize = 11.sp,
            color = NamuColors.TextSub,
            lineHeight = 16.sp,
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
        )
        result?.let {
            Spacer(Modifier.height(10.dp))
            Text(
                it,
                fontSize = 13.sp,
                color = if (it.startsWith("未命中")) NamuColors.TextSub else NamuColors.TextMain,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

private fun actionLabel(a: String): String = when (a.lowercase()) {
    "proxy" -> "代理"
    "direct" -> "直连"
    "block" -> "拦截"
    else -> a
}

private fun evaluateRule(cfg: AppConfig, input: String): String {
    val text = input.trim().lowercase()
    val ipv4 = text.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}"))
    cfg.rules.forEachIndexed { index, r ->
        if (!r.enabled) return@forEachIndexed
        val hit = when (r.type.uppercase()) {
            "DOMAIN" -> !ipv4 && text == r.value.lowercase()
            "DOMAIN-SUFFIX" -> {
                val s = r.value.lowercase().trimStart('.')
                !ipv4 && (text == s || text.endsWith(".$s"))
            }
            "DOMAIN-KEYWORD" -> !ipv4 && text.contains(r.value.lowercase())
            "DOMAIN-REGEX" -> !ipv4 && runCatching { Regex(r.value).containsMatchIn(text) }.getOrDefault(false)
            "IP-CIDR", "IP-CIDR6" -> ipv4 && cidrContains(r.value, text)
            "PORT" -> false
            else -> false
        }
        if (hit) return "命中 ${r.type} ${r.value} → ${actionLabel(r.action)}（第 ${index + 1} 条）"
    }
    return "未命中任何规则，走最终策略：${actionLabel(cfg.finalPolicy)}"
}

private fun cidrContains(cidr: String, ip: String): Boolean {
    return try {
        val parts = cidr.split("/")
        if (parts.size != 2) return false
        val net = parts[0].split(".").map { it.toInt() }
        val mask = parts[1].toInt()
        if (net.size != 4 || mask !in 0..32) return false
        val addr = ip.split(".").map { it.toInt() }
        if (addr.size != 4) return false
        val shift = 32 - mask
        val netPart = net.fold(0L) { acc, v -> (acc shl 8) or v.toLong() } ushr shift
        val ipPart = addr.fold(0L) { acc, v -> (acc shl 8) or v.toLong() } ushr shift
        netPart == ipPart
    } catch (_: Exception) {
        false
    }
}

/** 可启动应用项：按 App MITM 选择器的数据源。 */
data class AppEntry(val pkg: String, val label: String)

/**
 * 只查 launcher intent（Manifest 里声明了对应 `<queries>`），不申请 QUERY_ALL_PACKAGES。
 * 返回按名称排序、同包名去重的结果；单个应用取标签失败不影响整个列表。
 */
private fun loadLaunchableApps(ctx: android.content.Context): List<AppEntry> {
    val pm = ctx.packageManager
    val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    val resolved = pm.queryIntentActivities(intent, 0)
    return resolved.mapNotNull { info ->
        val pkg = info.activityInfo?.packageName ?: return@mapNotNull null
        val label = runCatching { info.loadLabel(pm).toString() }.getOrDefault(pkg)
        AppEntry(pkg, label)
    }.distinctBy { it.pkg }.sortedBy { it.label.lowercase() }
}

@Composable
fun AppScopeDialog(
    mode: String,
    apps: List<String>,
    onDismiss: () -> Unit,
    onApply: (String, List<String>) -> Unit,
) {
    val ctx = LocalContext.current
    var localMode by remember { mutableStateOf(if (mode == "allow" || mode == "deny") mode else "all") }
    val selected = remember { mutableStateListOf<String>().apply { addAll(apps) } }
    var query by remember { mutableStateOf("") }
    var loaded by remember { mutableStateOf<Result<List<AppEntry>>?>(null) }
    LaunchedEffect(Unit) {
        loaded = withContext(Dispatchers.IO) { runCatching { loadLaunchableApps(ctx) } }
    }
    val entries = loaded?.getOrNull().orEmpty()
    val visiblePackages = remember(entries) { entries.mapTo(HashSet()) { it.pkg } }
    val savedEntries = remember(apps, visiblePackages) {
        apps.filterNot { it in visiblePackages }.distinct().map { AppEntry(it, it) }
    }
    val filtered = remember(entries, savedEntries, query) {
        val q = query.trim()
        (savedEntries + entries).filter {
            it.label.contains(q, ignoreCase = true) || it.pkg.contains(q, ignoreCase = true)
        }
    }
    val selection = selected.toList()
    var unresolved by remember { mutableStateOf<List<String>>(emptyList()) }
    LaunchedEffect(selection) {
        unresolved = withContext(Dispatchers.IO) {
            com.namu.dns.AppUidResolver.resolveUids(ctx, selection).second
        }
    }
    NamuDialog(
        title = "按 App MITM",
        scrollContent = true,
        confirmText = "保存",
        onConfirm = {
            if (localMode == "all" || (localMode == "deny" && selected.isEmpty())) onApply("all", emptyList())
            else onApply(localMode, selected.toList())
            onDismiss()
        },
        onDismiss = onDismiss,
    ) {
        Column(Modifier.fillMaxWidth()) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ChoiceChip("全部应用", localMode == "all", Modifier.weight(1f)) { localMode = "all" }
                ChoiceChip("仅选中", localMode == "allow", Modifier.weight(1f)) { localMode = "allow" }
                ChoiceChip("跳过选中", localMode == "deny", Modifier.weight(1f)) { localMode = "deny" }
            }
            if (localMode != "all") {
                Spacer(Modifier.height(8.dp))
                NamuTextField(
                    value = query,
                    onChange = { query = it },
                    placeholder = "搜索应用名或包名",
                    singleLine = true,
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    "已选 ${selected.size} 个 · 桌面应用 ${entries.size} 个",
                    fontSize = 12.sp,
                    color = NamuColors.TextSub,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (unresolved.any { it in selected }) {
                    Text(
                        if (localMode == "deny") "有应用无法识别，MITM 将暂停"
                        else "有应用无法识别，将跳过这些应用",
                        fontSize = 12.sp,
                        color = NamuColors.TextSub,
                    )
                }
                LazyColumn(Modifier.fillMaxWidth().heightIn(max = 320.dp)) {
                    items(filtered, key = { it.pkg }) { e ->
                        val checked = selected.contains(e.pkg)
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable {
                                    if (checked) selected.remove(e.pkg) else selected.add(e.pkg)
                                }
                                .padding(vertical = 3.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(
                                checked = checked,
                                onCheckedChange = { on ->
                                    if (on) { if (!selected.contains(e.pkg)) selected.add(e.pkg) }
                                    else selected.remove(e.pkg)
                                },
                            )
                            Column(Modifier.weight(1f)) {
                                Text(e.label, fontSize = 13.sp, color = NamuColors.TextMain, maxLines = 1)
                                Text(
                                    e.pkg,
                                    fontSize = 10.sp,
                                    color = NamuColors.TextTertiary,
                                    maxLines = 1,
                                )
                            }
                        }
                    }
                    if (filtered.isEmpty()) item {
                        Text(
                            when {
                                loaded == null -> "正在读取应用列表"
                                loaded?.isFailure == true -> "读取应用失败"
                                entries.isEmpty() && query.isBlank() -> "没有可见的桌面应用"
                                else -> "没有匹配的应用"
                            },
                            fontSize = 12.sp,
                            color = NamuColors.TextSub,
                            modifier = Modifier.padding(vertical = 10.dp),
                        )
                    }
                }
            }
        }
    }
}
