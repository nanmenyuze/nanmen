package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.ui.viewmodel.MitmViewModel
import com.namu.dns.ConfigStore
import com.namu.dns.MitmManager
import com.namu.dns.RootCaManager
import com.namu.dns.core.LocalAppContainer
import org.json.JSONObject

/**
 * MITM 去广告设置页：总开关、CA 生成与系统信任模块、手动域名/跳过列表、模块规则与运行数据。
 *
 * 规则主要来自模块的 [MITM] / [URL Rewrite] / [Header Rewrite]；这里管理全局开关、
 * 证书与手动补充的域名。启用后内核按 URL 正则拒绝或改写响应体，握手失败自动放行。
 */
@Composable
fun MitmScreen() {
    val container = LocalAppContainer.current
    val cfg by container.settings.config.collectAsStateWithLifecycle()
    val statsState by container.stats.state.collectAsStateWithLifecycle()
    val stats = statsState.stats
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val vm: MitmViewModel = viewModel(factory = MitmViewModel.factory(container, ctx))
    val busy by vm.busy.collectAsStateWithLifecycle()
    val caExists by vm.caExists.collectAsStateWithLifecycle()
    val caFingerprint by vm.caFingerprint.collectAsStateWithLifecycle()
    val trust by vm.trust.collectAsStateWithLifecycle()
    val trustState = remember(caExists, trust) {
        RootCaManager.resolveTrustState(caExists, trust)
    }
    val trustValue = when (trustState) {
        RootCaManager.TrustState.NOT_GENERATED -> "未生成"
        RootCaManager.TrustState.GENERATED_NOT_INSTALLED -> "已生成未安装"
        RootCaManager.TrustState.INSTALLED_PENDING -> "已安装待生效"
        RootCaManager.TrustState.ACTIVE -> "已生效"
        RootCaManager.TrustState.CONFLICT -> "证书区冲突"
        RootCaManager.TrustState.INJECT_FAILED -> "安装未完成"
        RootCaManager.TrustState.REMOVED -> "已卸载"
        RootCaManager.TrustState.RESIDUAL -> "残留异常"
        RootCaManager.TrustState.UNVERIFIABLE -> "无法核验"
    }
    val trustSubtitle = when (trustState) {
        RootCaManager.TrustState.NOT_GENERATED -> "导出模块时会生成公开 CA"
        RootCaManager.TrustState.GENERATED_NOT_INSTALLED -> trust.detail.ifBlank { "导出模块后，在 Magisk 中安装并完整重启" }
        RootCaManager.TrustState.INSTALLED_PENDING -> "已发现模块，尚未核实系统信任状态。请确认已在 Magisk 启用并完整重启"
        RootCaManager.TrustState.ACTIVE -> "已在 Zygote 的系统证书区核对到同一张 CA"
        RootCaManager.TrustState.CONFLICT -> "系统证书区存在其他覆盖层，请在 Magisk 中检查模块"
        RootCaManager.TrustState.INJECT_FAILED -> "模块启动时未完成挂载，可导出安装日志查看原因"
        RootCaManager.TrustState.REMOVED -> "已移除"
        RootCaManager.TrustState.RESIDUAL -> "仍能读到这张 CA，请检查 Magisk 模块和系统凭据"
        RootCaManager.TrustState.UNVERIFIABLE -> trust.detail.ifBlank { "当前无法核对系统证书区" }
    }
    val mitm = cfg.mitm
    var showHosts by remember { mutableStateOf(false) }
    var showSkip by remember { mutableStateOf(false) }
    var showApps by remember { mutableStateOf(false) }
    var showScriptArgs by remember { mutableStateOf(false) }
    var showCaGuide by remember { mutableStateOf(false) }
    var hostsText by remember { mutableStateOf("") }
    var skipText by remember { mutableStateOf("") }

    // 从模块安装/文件管理器返回时重新核对，避免状态停在“未检测到”。
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        vm.refresh()
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) vm.refresh()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // 启用模块合并出的 MITM 域名 + 两类重写规则总数，每行算一条。
    val moduleMitmCount = remember(mitm, cfg.moduleSources) {
        runCatching {
            val o = JSONObject(ConfigStore.moduleMitmFile(ctx).readText())
            (o.optJSONArray("hostnames")?.length() ?: 0) +
                (o.optJSONArray("urlRewrites")?.length() ?: 0) +
                (o.optJSONArray("headerRewrites")?.length() ?: 0)
        }.getOrDefault(0)
    }
    // 参数编辑覆盖 active 脚本 + 启用模块脚本；键与内核 CompiledScriptRule.key 一致。
    val scriptsForArgs = remember(mitm, cfg.moduleSources) {
        val out = LinkedHashMap<String, com.namu.dns.core.config.ScriptConfig>()
        mitm.scripts.forEach { out[ConfigStore.scriptKey(it)] = it }
        runCatching {
            JSONObject(ConfigStore.moduleMitmFile(ctx).readText()).optJSONArray("scripts")?.let { a ->
                for (i in 0 until a.length()) {
                    a.optJSONObject(i)?.let {
                        val sc = com.namu.dns.core.config.ScriptConfig.fromJsonObject(it)
                        out.putIfAbsent(ConfigStore.scriptKey(sc), sc)
                    }
                }
            }
        }
        out.values.toList()
    }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("MITM 去广告")
        GroupCard {
            SettingsRow(
                title = "启用 MITM",
                subtitle = "解密命中域名列表的 HTTPS：按 URL 拒绝广告请求、正则改写响应体",
                icon = Icons.Rounded.Security,
                rightContent = {
                    IosSwitch(
                        checked = mitm.enabled,
                        onCheckedChange = { on -> vm.setEnabled(on) },
                    )
                },
            )
            SettingsRow(
                title = "CA 证书",
                value = if (caExists) "已生成" else "未生成",
                subtitle = "首次导出时自动生成并长期复用；卸载应用前请先移除已安装证书",
                showDivider = true,
            )
            FingerprintRow(
                fingerprint = caFingerprint,
                onCopy = {
                    caFingerprint?.let {
                        clipboard.setText(AnnotatedString(it))
                        container.messages.show("CA SHA-256 指纹已复制")
                    }
                },
            )
            SettingsRow(
                title = "系统证书区（模块）",
                value = trustValue,
                subtitle = trustSubtitle,
                showDivider = true,
            )
            SettingsRow(
                title = "Root / 模块管理器",
                value = when (trust.root.kind) {
                    com.namu.dns.RootCaManager.RootKind.MAGISK -> "Magisk"
                    com.namu.dns.RootCaManager.RootKind.KERNELSU -> "KernelSU"
                    com.namu.dns.RootCaManager.RootKind.APATCH -> "APatch"
                    com.namu.dns.RootCaManager.RootKind.NONE ->
                        if (trust.root.available) "未识别" else "未授权"
                },
                subtitle = "Root 用于核验。模块在 Magisk、KernelSU 或 APatch 中安装、停用或移除",
                showDivider = true,
            )
            SettingsRow(
                title = "重新核验",
                subtitle = "重新检查 CA 指纹、Root 模块与系统证书区；从模块管理器返回也会自动核验",
                icon = Icons.Rounded.Refresh,
                chevron = true,
                showDivider = false,
                onClick = {
                    if (!busy) {
                        vm.refresh()
                        container.messages.show("已发起证书与模块重新核验")
                    }
                },
            )
        }

        SectionHeader("证书安装")
        GroupCard {
            SettingsRow(
                title = "安装与更新指引",
                subtitle = "Magisk / KernelSU / APatch 的模块安装、更新、停用与重启步骤",
                icon = Icons.Rounded.Info,
                chevron = true,
                onClick = { showCaGuide = true },
            )
            if (trust.root.available) {
                SettingsRow(
                    title = "导出安装日志",
                    subtitle = "导出到「下载/NamuDNS」",
                    icon = Icons.Rounded.Download,
                    value = if (busy) "处理中…" else null,
                    chevron = true,
                    onClick = { vm.exportInjectionLog() },
                )
            }
            SettingsRow(
                title = "导出 CA 模块 ZIP",
                subtitle = "Magisk / KernelSU / APatch；导出到「下载/NamuDNS」，只包含公开 CA",
                icon = Icons.Rounded.Download,
                value = if (busy) "处理中…" else null,
                chevron = true,
                onClick = { vm.generateTrustModule() },
            )
            SettingsRow(
                title = "仅导出证书文件",
                subtitle = "PEM + DER 与模块 zip 使用同一出口：公共「下载/NamuDNS」；无存储权限也可在文件管理器打开",
                icon = Icons.Rounded.Download,
                chevron = true,
                showDivider = false,
                onClick = { vm.exportOnly() },
            )
        }

        SectionHeader("域名与规则")
        GroupCard {
            SettingsRow(
                title = "按 App MITM",
                value = when (mitm.appMode) {
                    "allow" -> "仅 ${mitm.apps.size} 个应用"
                    "deny" -> "跳过 ${mitm.apps.size} 个应用"
                    else -> "全部应用"
                },
                subtitle = "只解密选定应用，或把银行、支付、证书固定应用排除在外",
                chevron = true,
                onClick = { showApps = true },
            )
            SettingsRow(
                title = "手动 MITM 域名",
                value = "${mitm.hostnames.size} 个",
                subtitle = "逗号分隔，支持 *.example.com（含主域与全部子域）",
                chevron = true,
                onClick = {
                    hostsText = mitm.hostnames.joinToString(", ")
                    showHosts = true
                },
            )
            SettingsRow(
                title = "跳过域名（永不 MITM）",
                value = "${mitm.skipHostnames.size} 个",
                subtitle = "银行、支付等敏感应用建议加入跳过列表",
                chevron = true,
                onClick = {
                    skipText = mitm.skipHostnames.joinToString(", ")
                    showSkip = true
                },
            )
            SettingsRow(
                title = "脚本参数",
                value = if (scriptsForArgs.isEmpty()) "无脚本" else "${scriptsForArgs.size} 个",
                subtitle = "修改 \$argument 当前值，立即生效，不重编译脚本；number/boolean 按声明类型注入",
                chevron = true,
                onClick = { showScriptArgs = true },
            )
            SettingsRow(
                title = "上游连接复用（实验）",
                subtitle = "默认关闭；开启后 h1 独占复用、h2 按服务器 SETTINGS 共享。灰度失败可随时关闭，只影响新连接",
                rightContent = {
                    IosSwitch(
                        checked = mitm.poolEnabled,
                        onCheckedChange = { vm.setPoolEnabled(it) },
                    )
                },
            )
            SettingsRow(
                title = "手动触发 generic 脚本",
                subtitle = "仅手动执行 trigger=generic 的脚本，与 cron/network-changed 共用串行执行",
                chevron = true,
                onClick = { vm.triggerGeneric() },
            )
            SettingsRow(
                title = "模块 MITM 规则",
                value = "$moduleMitmCount 条",
                subtitle = "「策略 → 模块」导入含 [MITM]/[URL Rewrite]/[Header Rewrite] 的模块后自动合并去重",
                showDivider = false,
            )
        }

        SectionHeader("运行数据")
        GroupCard {
            SettingsRow("解密连接", value = stats.mitmConns.toString())
            SettingsRow("拒绝广告请求", value = stats.mitmRejected.toString())
            SettingsRow("改写响应体", value = stats.mitmRewritten.toString())
            SettingsRow(
                "握手失败自动放行",
                value = stats.mitmFailed.toString(),
                subtitle = "证书绑定等场景：域名临时放行 5 分钟，不会断网",
            )
            SettingsRow(
                "QUIC 拦截回落 TCP",
                value = stats.mitmQuicBlocked.toString(),
                subtitle = "UDP 443 的 QUIC 被丢弃后，应用会自动改用 HTTPS/TCP 走 MITM",
            )
            SettingsRow(
                "按 App 跳过",
                value = stats.mitmAppSkipped.toString(),
                subtitle = "域名命中但不在「按 App MITM」范围内、按原样直通的连接数",
                showDivider = true,
            )
            SettingsRow(
                "正文提前直通",
                value = stats.mitmBodyBypassed.toString(),
                subtitle = "命中正文规则但属于视频/音频/二进制，或超过 2 MiB，直接流式透传，避免大缓冲",
                showDivider = false,
            )
        }

        SectionHeader("MITM 域名观测")
        GroupCard {
            if (stats.mitmFailedTop.isEmpty() && stats.mitmNoRuleTop.isEmpty()) {
                SettingsRow(
                    title = "暂无数据",
                    subtitle = "按 host 统计连接、失败、取消、无规则与改写，最多保留 256 条；只在本机内存，不上报",
                    showDivider = false,
                )
            } else {
                Text(
                    "失败 Top10",
                    fontSize = 11.sp,
                    color = NamuColors.TextSub,
                    modifier = Modifier.padding(start = 16.dp, top = 10.dp, bottom = 2.dp),
                )
                HostTopRows(
                    rows = stats.mitmFailedTop,
                    skipHosts = mitm.skipHostnames,
                    onSkip = { host -> vm.saveSkip(MitmManager.toggleSkip(mitm.skipHostnames, host)) },
                    onCopy = { host -> clipboard.setText(AnnotatedString(host)) },
                )
                Text(
                    "无规则 Top10",
                    fontSize = 11.sp,
                    color = NamuColors.TextSub,
                    modifier = Modifier.padding(start = 16.dp, top = 10.dp, bottom = 2.dp),
                )
                HostTopRows(
                    rows = stats.mitmNoRuleTop,
                    skipHosts = mitm.skipHostnames,
                    onSkip = { host -> vm.saveSkip(MitmManager.toggleSkip(mitm.skipHostnames, host)) },
                    onCopy = { host -> clipboard.setText(AnnotatedString(host)) },
                )
            }
        }

        FooterText(
            "MITM 只处理 HTTP/1.1 over TLS；只支持 h2 且不回落的少数应用会自动放行。" +
                "请仅在自己的设备上使用；银行/支付类应用建议加入跳过列表，或直接关闭 MITM。",
        )
        Spacer(Modifier.height(30.dp))
    }

    if (showHosts) {
        NamuDialog(
            title = "手动 MITM 域名",
            message = "逗号/换行分隔。*.example.com 匹配主域与全部子域；裸域名只精确匹配。",
            confirmText = "保存",
            onDismiss = { showHosts = false },
            onConfirm = {
                val list = MitmManager.parseHostList(hostsText)
                showHosts = false
                vm.saveHostnames(list)
            },
        ) {
            NamuTextField(hostsText, { hostsText = it }, "*.example.com, api.foo.cn")
        }
    }
    if (showApps) {
        AppScopeDialog(
            mode = mitm.appMode,
            apps = mitm.apps,
            onDismiss = { showApps = false },
            onApply = { mode, apps -> vm.setApps(mode, apps) },
        )
    }
    if (showSkip) {
        NamuDialog(
            title = "跳过域名",
            message = "这些域名永不做 MITM，始终透明转发。",
            confirmText = "保存",
            onDismiss = { showSkip = false },
            onConfirm = {
                val list = MitmManager.parseHostList(skipText)
                showSkip = false
                vm.saveSkip(list)
            },
        ) {
            NamuTextField(skipText, { skipText = it }, "*.bank.example.com")
        }
    }
    if (showScriptArgs) {
        ScriptArgumentsDialog(
            scripts = scriptsForArgs,
            saved = mitm.scriptArguments,
            onSave = { script, values -> vm.setScriptArguments(script, values) },
            onDismiss = { showScriptArgs = false },
        )
    }
    if (showCaGuide) {
        NamuDialog(
            title = "CA 模块安装与更新",
            message = "1. 点「导出 CA 模块 ZIP」，文件会保存到「下载/NamuDNS」。\n" +
                "2. 在 Magisk、KernelSU 或 APatch 的模块页选择「从本地安装」，选中刚导出的 ZIP。\n" +
                "3. 安装或覆盖更新后完整重启手机，再回到本页点「重新核验」。\n\n" +
                "CA 不变时可继续复用同一模块；证书指纹变化后才需要覆盖更新。停用或移除模块也必须完整重启。",
            confirmText = "知道了",
            showDismiss = false,
            onDismiss = { showCaGuide = false },
            onConfirm = { showCaGuide = false },
        )
    }

}

/**
 * 指纹是逐段核对的字符串，必须等宽、可换行、可复制；不能塞进 13sp 辅助字号的
 * subtitle，也不能靠整行暗点。复制按钮独立 48dp 命中区。
 */
@Composable
private fun FingerprintRow(
    fingerprint: String?,
    onCopy: () -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .padding(horizontal = 16.dp, vertical = 9.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("CA SHA-256 指纹", fontSize = 16.sp, color = NamuColors.TextMain)
                Text(
                    if (fingerprint == null) "生成 CA 后显示" else "与系统证书详情逐段核对",
                    fontSize = 12.sp,
                    color = NamuColors.TextSub,
                )
            }
            MiniTextAction(
                text = "复制",
                enabled = fingerprint != null,
                onClick = onCopy,
            )
        }
        if (fingerprint != null) {
            Text(
                fingerprint,
                fontSize = 12.sp,
                lineHeight = 17.sp,
                fontFamily = FontFamily.Monospace,
                color = NamuColors.TextMain,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, bottom = 12.dp),
            )
        }
        RowDivider(16.dp)
    }
}

private fun noRulePercent(row: com.namu.dns.MitmHostRow): String =
    if (row.reqs <= 0) "—" else String.format(java.util.Locale.US, "%.0f%%", row.noRule * 100.0 / row.reqs)

@Composable
private fun HostTopRows(
    rows: List<com.namu.dns.MitmHostRow>,
    skipHosts: List<String>,
    onSkip: (String) -> Unit,
    onCopy: (String) -> Unit,
) {
    rows.forEachIndexed { index, row ->
        SettingsRow(
            title = row.host,
            value = "无规则 ${row.noRule}/${row.reqs}（${noRulePercent(row)}） · 失败 ${row.failed}",
            subtitle = "连接 ${row.conns} · 取消 ${row.canceled} · 改写 ${row.rewritten}",
            showDivider = index != rows.lastIndex,
            rightContent = {
                Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                    TextButton(onClick = { onSkip(row.host) }) {
                        Text(
                            if (skipHosts.contains(row.host)) "取消跳过" else "加入跳过",
                            fontSize = 11.sp,
                        )
                    }
                    TextButton(onClick = { onCopy(row.host) }) {
                        Text("复制", fontSize = 11.sp)
                    }
                }
            },
        )
    }
}
