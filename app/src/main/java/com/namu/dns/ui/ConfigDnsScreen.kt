package com.namu.dns.ui

import android.net.InetAddresses
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.outlined.Remove
import androidx.compose.material3.IconButton
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.AppConfig
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.config.ConfigDnsInput
import com.namu.dns.core.config.DnsPolicyRule

@Composable
internal fun ConfigDnsScreen(editor: ProfileEditor, onBack: () -> Unit) {
    val messages = LocalAppContainer.current.messages
    val original = remember(editor) {
        val saved = editor.current()
        saved.copy(dnsUpstream = saved.dnsUpstream.ifBlank { "system" })
    }
    var draft by remember(editor) { mutableStateOf(original) }
    var expanded by rememberSaveable { mutableStateOf(false) }
    var confirmExit by rememberSaveable { mutableStateOf(false) }
    var editAddress by remember { mutableStateOf<DnsAddressEdit?>(null) }
    var editPolicy by remember { mutableStateOf<Int?>(null) }
    var showBootstrap by remember { mutableStateOf(false) }
    var showHeader by remember { mutableStateOf(false) }
    var showRealIp by remember { mutableStateOf(false) }
    val dirty = draft != original
    val primaryIssue = ConfigDnsInput.error(draft.dnsUpstream)
    val fallbackIssue = draft.dnsFallback
        .takeIf { it.isNotBlank() && (draft.allowDnsFallback || it != original.dnsFallback) }
        ?.let(ConfigDnsInput::error)
    val canSave = dirty && editAddress == null && primaryIssue == null && fallbackIssue == null

    fun leave() {
        if (dirty || editAddress != null) confirmExit = true else onBack()
    }

    BackHandler(enabled = dirty || editAddress != null) { leave() }
    Column(Modifier.fillMaxSize().background(NamuColors.Bg)) {
        ShadowTopBar(
            title = "DNS",
            left = {
                IconButton(onClick = ::leave) {
                    NamuIcon(Icons.AutoMirrored.Rounded.ArrowBack, "返回")
                }
            },
            right = {
                IconButton(
                    enabled = canSave,
                    onClick = {
                        if (editor.update { it.applyDnsDraft(original, draft) }) {
                            messages.show("DNS 配置已保存")
                            onBack()
                        }
                    },
                ) {
                    NamuIcon(Icons.Filled.Check, "保存 DNS 配置", tint = if (canSave) {
                        NamuColors.Brand
                    } else {
                        NamuColors.TextTertiary
                    })
                }
            },
        )
        DetailList(Modifier.imePadding()) {
            SectionHeader("DNS 服务器")
            GroupCard {
                DnsAddressRows(
                    label = "主 DNS",
                    raw = draft.dnsUpstream,
                    editIndex = editAddress?.takeUnless { it.fallback }?.index,
                    onEdit = { editAddress = it?.let { index -> DnsAddressEdit(false, index) } },
                    onChange = { draft = draft.copy(dnsUpstream = it) },
                )
            }
            SectionHeader("回退")
            GroupCard {
                SwitchRow("启用回退", checked = draft.allowDnsFallback) {
                    draft = draft.copy(allowDnsFallback = it)
                }
                DnsAddressRows(
                    label = "备用 DNS",
                    raw = draft.dnsFallback,
                    editIndex = editAddress?.takeIf { it.fallback }?.index,
                    onEdit = { editAddress = it?.let { index -> DnsAddressEdit(true, index) } },
                    onChange = { draft = draft.copy(dnsFallback = it) },
                )
            }
            SectionHeader("解析策略")
            GroupCard {
                SwitchRow("劫持 DNS", checked = draft.dnsHijack ?: true) { draft = draft.copy(dnsHijack = it) }
                SwitchRow("关闭 AAAA", checked = draft.blockAaaa) { draft = draft.copy(blockAaaa = it) }
                SwitchRow("DNS 查询日志", checked = draft.dnsQueryLog, showDivider = false) {
                    draft = draft.copy(dnsQueryLog = it)
                }
            }
            SectionHeader("按域名 DNS")
            GroupCard {
                draft.dnsPolicies.forEachIndexed { index, policy ->
                    EditableDnsRow(
                        title = policy.pattern,
                        subtitle = policy.servers,
                        onEdit = { editPolicy = index },
                        onRemove = { draft = draft.copy(dnsPolicies = draft.dnsPolicies.without(index)) },
                    )
                }
                SettingsRow("添加域名策略", showDivider = false, onClick = { editPolicy = draft.dnsPolicies.size })
            }

            Spacer(Modifier.height(18.dp))
            GroupCard {
                SettingsRow(
                    "高级 DNS",
                    value = if (expanded) "收起" else "展开",
                    showDivider = expanded,
                    onClick = { expanded = !expanded },
                )
                if (expanded) {
                    SettingsRow(
                        "Bootstrap IP",
                        value = draft.dnsBootstrap.ifBlank { "未设置" },
                        chevron = true,
                        onClick = { showBootstrap = true },
                    )
                    SettingsRow(
                        "DoH 请求头",
                        value = draft.dnsHeaderName.ifBlank { "未设置" },
                        chevron = true,
                        onClick = { showHeader = true },
                    )
                    SwitchRow("异常应答复核", checked = draft.fallbackFilter) { draft = draft.copy(fallbackFilter = it) }
                    SwitchRow("非 CN IP 复核", checked = draft.fallbackGeoCheck) { draft = draft.copy(fallbackGeoCheck = it) }
                    SwitchRow("Fake-IP", checked = draft.fakeIp) { draft = draft.copy(fakeIp = it) }
                    SettingsRow(
                        "真实 IP 名单",
                        value = "${draft.alwaysRealIp.size} 项",
                        chevron = true,
                        showDivider = false,
                        onClick = { showRealIp = true },
                    )
                }
            }
            val issue = primaryIssue ?: fallbackIssue
            if (issue != null) {
                Text(issue, color = NamuColors.Red, fontSize = 13.sp, modifier = Modifier.padding(16.dp))
            }
            Spacer(Modifier.height(24.dp))
        }
    }
    if (confirmExit) {
        NamuDialog(
            title = "放弃未保存的更改？",
            confirmText = "放弃",
            dismissText = "继续编辑",
            confirmColor = NamuColors.Red,
            onConfirm = onBack,
            onDismiss = { confirmExit = false },
        )
    }
    editPolicy?.let { index ->
        val policy = draft.dnsPolicies.getOrNull(index)
        var pattern by remember(index) { mutableStateOf(policy?.pattern.orEmpty()) }
        var servers by remember(index) { mutableStateOf(policy?.servers.orEmpty()) }
        val normalized = pattern.trim().removePrefix("*.").trim('.').lowercase()
        val repeated = draft.dnsPolicies.withIndex().any { (i, rule) ->
            i != index && rule.pattern.trim().removePrefix("*.").trim('.').equals(normalized, ignoreCase = true)
        }
        val issue = when {
            pattern.isBlank() || servers.isBlank() -> null
            !normalized.matches(Regex("[a-z0-9_-]+(?:[.][a-z0-9_-]+)*")) -> "请输入域名或域名后缀"
            repeated -> "此域名策略已存在"
            else -> ConfigDnsInput.error(servers)
        }
        NamuDialog(
            title = "按域名 DNS",
            confirmText = "完成",
            confirmEnabled = pattern.isNotBlank() && servers.isNotBlank() && issue == null,
            onDismiss = { editPolicy = null },
            onConfirm = {
                val next = DnsPolicyRule(pattern.trim(), servers.trim())
                draft = draft.copy(dnsPolicies = draft.dnsPolicies.replacing(index, next))
                editPolicy = null
            },
        ) {
            NamuTextField(pattern, { pattern = it }, "域名或后缀", singleLine = true)
            Spacer(Modifier.height(8.dp))
            NamuTextField(servers, { servers = it }, "DNS 地址，多个用逗号隔开", singleLine = true)
            if (issue != null) Text(issue, color = NamuColors.Red, fontSize = 12.sp)
        }
    }
    if (showBootstrap) {
        var ip by remember { mutableStateOf(draft.dnsBootstrap) }
        val valid = ip.isBlank() || InetAddresses.isNumericAddress(ip.trim())
        NamuDialog(
            title = "Bootstrap IP",
            confirmText = "完成",
            confirmEnabled = valid,
            onDismiss = { showBootstrap = false },
            onConfirm = { draft = draft.copy(dnsBootstrap = ip.trim()); showBootstrap = false },
        ) {
            NamuTextField(ip, { ip = it }, "IPv4 或 IPv6 地址", singleLine = true)
            if (!valid) Text("请输入合法的 IP 地址", color = NamuColors.Red, fontSize = 12.sp)
        }
    }
    if (showHeader) {
        var name by remember { mutableStateOf(draft.dnsHeaderName) }
        var value by remember { mutableStateOf(draft.dnsHeaderValue) }
        val valid = (name.isBlank() && value.isBlank()) ||
            (name.trim().matches(Regex("[a-zA-Z0-9!#$%&'*+.^_`|~-]+")) &&
                value.isNotBlank() && value.none { it.code < 32 && it != '\t' || it.code == 127 })
        NamuDialog(
            title = "DoH 请求头",
            confirmText = "完成",
            confirmEnabled = valid,
            onDismiss = { showHeader = false },
            onConfirm = {
                draft = draft.copy(dnsHeaderName = name.trim(), dnsHeaderValue = value.trim())
                showHeader = false
            },
        ) {
            NamuTextField(name, { name = it }, "请求头名称", singleLine = true)
            Spacer(Modifier.height(8.dp))
            NamuTextField(value, { value = it }, "请求头值", singleLine = true)
            if (!valid) Text("请同时填写有效的名称和值", color = NamuColors.Red, fontSize = 12.sp)
        }
    }
    if (showRealIp) {
        StringListDialog(
            title = "真实 IP 名单",
            message = "每行一个域名后缀，支持 * 和 ?。",
            initial = draft.alwaysRealIp,
            onDismiss = { showRealIp = false },
            onConfirm = { draft = draft.copy(alwaysRealIp = it); showRealIp = false },
        )
    }
}

private data class DnsAddressEdit(val fallback: Boolean, val index: Int)

@Composable
private fun DnsAddressRows(
    label: String,
    raw: String,
    editIndex: Int?,
    onEdit: (Int?) -> Unit,
    onChange: (String) -> Unit,
) {
    val entries = raw.split(',', '\n').map(String::trim).filter(String::isNotEmpty)

    @Composable
    fun EditorAt(index: Int) {
        AnimatedVisibility(
            visible = editIndex == index,
            enter = expandVertically() + fadeIn(),
            exit = shrinkVertically() + fadeOut(),
        ) {
            InlineDnsAddressEditor(entries, index, onCancel = { onEdit(null) }) {
                onChange(it)
                onEdit(null)
            }
        }
    }

    Column(Modifier.fillMaxWidth().animateContentSize()) {
        entries.forEachIndexed { index, address ->
            EditableDnsRow(
                title = if (address.equals("system", ignoreCase = true)) "系统 DNS" else address,
                onEdit = { onEdit(index) },
                onRemove = {
                    onEdit(null)
                    onChange(entries.without(index).joinToString(","))
                },
            )
            EditorAt(index)
        }
        SettingsRow("添加$label", showDivider = editIndex == entries.size, onClick = { onEdit(entries.size) })
        EditorAt(entries.size)
    }
}

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun InlineDnsAddressEditor(
    entries: List<String>,
    index: Int,
    onCancel: () -> Unit,
    onApply: (String) -> Unit,
) {
    var value by rememberSaveable(index) { mutableStateOf(entries.getOrNull(index).orEmpty()) }
    val next = entries.replacing(index, value.trim()).joinToString(",")
    val error = when {
        value.isBlank() -> null
        value.any { it == ',' || it == '\n' || it == '\r' } -> "一次请输入一条 DNS 地址"
        else -> ConfigDnsInput.error(next)
    }
    val focus = remember { FocusRequester() }
    val bringIntoView = remember { BringIntoViewRequester() }
    val keyboard = LocalSoftwareKeyboardController.current
    val imeVisible = WindowInsets.ime.getBottom(LocalDensity.current) > 0
    LaunchedEffect(Unit) {
        focus.requestFocus()
        keyboard?.show()
    }
    LaunchedEffect(imeVisible) {
        if (imeVisible) bringIntoView.bringIntoView()
    }
    Column(Modifier.fillMaxWidth().bringIntoViewRequester(bringIntoView).padding(horizontal = 16.dp, vertical = 6.dp)) {
        NamuTextField(value, { value = it }, "输入 DNS 地址", modifier = Modifier.focusRequester(focus), singleLine = true)
        if (error != null) {
            Text(error, color = NamuColors.Red, fontSize = 12.sp, modifier = Modifier.padding(top = 5.dp))
        }
        Row(Modifier.align(Alignment.End)) {
            TextButton(onClick = { keyboard?.hide(); onCancel() }) { Text("取消") }
            TextButton(
                onClick = { keyboard?.hide(); onApply(next) },
                enabled = value.isNotBlank() && error == null,
            ) { Text("完成") }
        }
    }
    RowDivider()
}

@Composable
private fun EditableDnsRow(title: String, subtitle: String? = null, onEdit: () -> Unit, onRemove: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 52.dp).padding(start = 16.dp, end = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            Modifier.weight(1f).clickable(onClickLabel = "编辑 $title", onClick = onEdit).padding(vertical = 10.dp),
        ) {
            Text(title, style = NamuTokens.Type.Body, color = NamuColors.TextMain)
            if (subtitle != null) Text(subtitle, style = NamuTokens.Type.Caption, color = NamuColors.TextSub)
        }
        IconButton(onClick = onRemove) {
            androidx.compose.material3.Icon(
                Icons.Outlined.Remove,
                contentDescription = "移除 $title",
                tint = NamuColors.Red,
            )
        }
    }
    RowDivider()
}

private fun <T> List<T>.without(index: Int): List<T> = toMutableList().apply { removeAt(index) }
private fun <T> List<T>.replacing(index: Int, value: T): List<T> = toMutableList().apply {
    if (index == size) add(value) else set(index, value)
}

private fun AppConfig.applyDnsDraft(original: AppConfig, draft: AppConfig): AppConfig {
    fun <T> value(before: T, after: T, current: T) = if (before != after) after else current
    return copy(
        dnsUpstream = value(original.dnsUpstream, draft.dnsUpstream, dnsUpstream),
        dnsFallback = value(original.dnsFallback, draft.dnsFallback, dnsFallback),
        allowDnsFallback = value(original.allowDnsFallback, draft.allowDnsFallback, allowDnsFallback),
        dnsPolicies = value(original.dnsPolicies, draft.dnsPolicies, dnsPolicies),
        dnsHijack = value(original.dnsHijack, draft.dnsHijack, dnsHijack),
        blockAaaa = value(original.blockAaaa, draft.blockAaaa, blockAaaa),
        dnsQueryLog = value(original.dnsQueryLog, draft.dnsQueryLog, dnsQueryLog),
        dnsBootstrap = value(original.dnsBootstrap, draft.dnsBootstrap, dnsBootstrap),
        dnsHeaderName = value(original.dnsHeaderName, draft.dnsHeaderName, dnsHeaderName),
        dnsHeaderValue = value(original.dnsHeaderValue, draft.dnsHeaderValue, dnsHeaderValue),
        fallbackFilter = value(original.fallbackFilter, draft.fallbackFilter, fallbackFilter),
        fallbackGeoCheck = value(original.fallbackGeoCheck, draft.fallbackGeoCheck, fallbackGeoCheck),
        fakeIp = value(original.fakeIp, draft.fakeIp, fakeIp),
        alwaysRealIp = value(original.alwaysRealIp, draft.alwaysRealIp, alwaysRealIp),
    )
}
