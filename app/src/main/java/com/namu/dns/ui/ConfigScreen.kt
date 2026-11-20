package com.namu.dns.ui

import com.namu.dns.core.LocalDockClearance

import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.ViewModule
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.App
import com.namu.dns.Actions
import com.namu.dns.AppConfig
import com.namu.dns.ConfigFileStore
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.namu.dns.ConfigStore
import com.namu.dns.NamuVpnService
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.RuleItem
import com.namu.dns.core.config.ProxyGroupValidation
import kotlinx.coroutines.launch
import java.io.File

@Composable
fun ConfigScreen(onOpenDetail: () -> Unit, onRestart: () -> Unit) {
    var showReset by remember { mutableStateOf(false) }
    var showRemote by remember { mutableStateOf(false) }
    var showCreate by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
    var showTest by remember { mutableStateOf(false) }
    var infoFile by remember { mutableStateOf<ConfigFileStore.FileInfo?>(null) }
    var revision by remember { mutableStateOf(0) }
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val runtime = container.runtime
    val messages = container.messages
    val context = container.context
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        ConfigFileStore.ensureDefault(context, cfg)
        revision++
    }
    val files = remember(revision) { ConfigFileStore.list(context) }
    val activeName = container.config.activeName()

    fun activate(name: String, openDetail: Boolean = false) {
        if (!container.config.switchTo(name)) {
            messages.show("配置读取失败")
            return
        }
        revision++
        messages.show("已切换到 $name")
        // 配置文件里的 rulesUrl 需要立刻落地，不能等下次冷启动才同步。
        // 规则同步完成后再进详情，避免 ConfigScreen 被导航销毁时协程一起取消。
        val ruleUrl = settings.current().rulesUrl
        if (ruleUrl.isNotBlank()) {
            scope.launch {
                try {
                    val n = Actions.updateAdsRules(ruleUrl)
                    ConfigStore.rebuildModules(context, settings.current())
                    if (runtime.current().connected) NamuVpnService.reload(context)
                    messages.show("规则源已同步：$n 条")
                } catch (e: Exception) {
                    messages.show("规则同步失败：${e.message ?: "网络错误"}")
                } finally {
                    if (openDetail) onOpenDetail()
                }
            }
        } else if (openDetail) {
            onOpenDetail()
        }
    }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("规则与配置")
        GroupCard {
            SettingsRow(
                title = "当前配置",
                value = activeName,
                chevron = true,
                onClick = onOpenDetail,
            )
            SettingsRow(
                title = "新建配置文件",
                subtitle = "把当前设置另存为一份独立配置",
                chevron = true,
                onClick = { showCreate = true },
            )
            SettingsRow(
                title = "导入配置文件…",
                subtitle = "原生 JSON / Clash / Loon / 小火箭；Loon/小火箭仅预览",
                chevron = true,
                onClick = { showImport = true },
            )
            SettingsRow(
                title = "从 URL 导入配置",
                subtitle = "从你的服务器拉取 DNS、路由和规则清单",
                chevron = true,
                onClick = { showRemote = true },
            )
            SettingsRow(
                title = "测试规则",
                subtitle = "输入域名或 IP，查看会命中哪条规则",
                chevron = true,
                onClick = { showTest = true },
            )
            SettingsRow(
                title = "恢复默认配置",
                subtitle = "清空规则集和手动规则，恢复基础 DNS 与内网直连",
                chevron = true,
                showDivider = false,
                onClick = { showReset = true },
            )
        }

        SectionHeader("本地文件")
        GroupCard {
            if (files.isEmpty()) {
                SettingsRow(
                    title = "还没有配置文件",
                    subtitle = "点上方「新建配置文件」开始",
                    showDivider = false,
                )
            } else {
                files.forEachIndexed { index, f ->
                    ConfigFileRow(
                        info = f,
                        showDivider = index != files.lastIndex,
                        onActivate = {
                            if (f.active) onOpenDetail() else activate(f.name, openDetail = true)
                        },
                        onInfo = { infoFile = f },
                    )
                }
            }
        }

        FooterText("橙点代表默认配置，蓝色勾代表正在使用的配置。切换会整体替换 DNS、规则与模块，服务器节点保持不变。")
        Spacer(Modifier.height(LocalDockClearance.current + 34.dp))
    }

    if (showReset) {
        NamuDialog(
            title = "恢复默认配置",
            message = "将清空远端配置、规则集 URL、手动规则和本地拦截域名；服务器节点和模块会保留。",
            confirmText = "恢复",
            confirmColor = NamuColors.Red,
            onDismiss = { showReset = false },
            onConfirm = {
                val nodes = cfg.nodes
                val selected = cfg.selected
                val subscription = cfg.subscription
                val modules = cfg.moduleSources
                settings.update { current -> current.copy(
                    nodes = nodes,
                    selected = selected,
                    subscription = subscription,
                    moduleSources = modules,
                    mode = "dns_only",
                    finalPolicy = "direct",
                ) }
                ConfigStore.rebuildModules(context, settings.current())
                revision++
                showReset = false
                if (runtime.current().connected) onRestart()
            },
        ) {}
    }
    if (showRemote) {
        RemoteConfigDialog(
            onDismiss = { showRemote = false },
            onDone = {
                showRemote = false
                revision++
                if (runtime.current().connected) onRestart()
            },
        )
    }
    if (showCreate) {
        ConfigNameDialog(
            title = "新建配置文件",
            initial = "配置-${files.size + 1}.conf",
            onConfirm = { name ->
                showCreate = false
                if (container.config.create(name)) {
                    revision++
                    activate(ConfigFileStore.sanitize(name), openDetail = true)
                } else {
                    messages.show("已存在同名配置文件")
                }
            },
            onDismiss = { showCreate = false },
        )
    }
    if (showImport) {
        ConfigImportDialog(
            onDone = { info ->
                showImport = false
                activate(info.name, openDetail = true)
            },
            onDismiss = { showImport = false },
        )
    }
    if (showTest) {
        RuleTestDialog(onDismiss = { showTest = false })
    }
    infoFile?.let { f ->
        ConfigFileInfoDialog(
            info = f.copy(active = f.name == activeName),
            onActivate = {
                infoFile = null
                activate(f.name)
            },
            onDelete = {
                infoFile = null
                val ok = container.config.delete(f.name)
                if (!ok) {
                    messages.show("默认配置不能删除")
                } else {
                    revision++
                    messages.show("已删除 ${f.name}")
                }
            },
            onRestore = {
                infoFile = null
                if (ConfigFileStore.restore(context, f.name)) {
                    // 当前 active 配置回退后，要把回退内容重新套回内存，不能只改磁盘。
                    if (f.name == activeName) {
                        ConfigFileStore.loadInto(context, f.name, settings.current())?.let { settings.set(it) }
                    }
                    revision++
                    messages.show("已回退到上一版 ${f.name}")
                } else {
                    messages.show("没有可回退的备份")
                }
            },
            onDismiss = { infoFile = null },
        )
    }
}

@Composable
private fun ConfigFileRow(
    info: ConfigFileStore.FileInfo,
    showDivider: Boolean,
    onActivate: () -> Unit,
    onInfo: () -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable { onActivate() }
            .padding(start = 16.dp, end = 12.dp, top = 10.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(7.dp)
                .clip(RoundedCornerShape(50))
                .background(if (info.isDefault) NamuColors.Orange else Color.Transparent),
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(info.name, fontSize = 16.sp, color = NamuColors.TextMain)
            Spacer(Modifier.height(2.dp))
            Text(
                "${formatConfigTime(info.modified)} · ${formatBytes(info.size)}",
                fontSize = 11.sp,
                color = NamuColors.TextSub,
            )
        }
        if (info.active) {
            CheckMark()
            Spacer(Modifier.width(10.dp))
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
                    contentDescription = "配置详情",
                    tint = Color.White,
                    modifier = Modifier.size(14.dp),
                )
            }
        }
    }
    if (showDivider) RowDivider(33.dp)
}

private fun formatConfigTime(ts: Long): String {
    if (ts <= 0L) return "-"
    return try {
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.getDefault())
        fmt.format(java.util.Date(ts))
    } catch (_: Exception) {
        "-"
    }
}

@Composable
fun ConfigDetailScreen(onRestart: () -> Unit, onOpenModules: () -> Unit, onOpenMitm: () -> Unit) {
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val runtime = container.runtime
    val messages = container.messages
    val scope = rememberCoroutineScope()
    var showDns by remember { mutableStateOf(false) }
    var showBlockMode by remember { mutableStateOf(false) }
    var showFinalPolicy by remember { mutableStateOf(false) }
    var showAddRule by remember { mutableStateOf(false) }
    var ruleQuery by remember { mutableStateOf("") }
    var showCustomAds by remember { mutableStateOf(false) }
    var showRemote by remember { mutableStateOf(false) }
    var showRuleSources by remember { mutableStateOf(false) }
    var showRulesUpdate by remember { mutableStateOf(false) }
    var showGroups by remember { mutableStateOf(false) }
    var updatingIp by remember { mutableStateOf(false) }
    val groupIssues = remember(cfg.proxyGroups, cfg.nodes, cfg.groupSelections) {
        ProxyGroupValidation.validate(cfg.proxyGroups, cfg.nodes.map { it.name }, cfg.groupSelections)
    }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("当前配置")
        GroupCard {
            SettingsRow(
                title = container.config.activeName(),
                subtitle = "配置文件 · 切换后整体替换 DNS、规则与模块",
                value = "使用中",
                valueColor = NamuColors.Green,
                showDivider = false,
            )
        }

        SectionHeader("通用")
        GroupCard {
            SettingsRow(
                title = "DNS 上游",
                subtitle = "纯递归服务器请填写 DoH / DoT 入口",
                value = configDnsLabel(cfg.dnsUpstream),
                chevron = true,
                onClick = { showDns = true },
            )
            SettingsRow(
                title = "Bootstrap IP",
                subtitle = "首次解析 DoH 域名时直接使用该地址",
                value = cfg.dnsBootstrap.ifBlank { "未设置" },
            )
            SettingsRow(
                title = "自定义 Header",
                subtitle = "DoH 鉴权头，随上游请求发送",
                value = if (cfg.dnsHeaderName.isBlank()) "未设置" else "${cfg.dnsHeaderName} · 已配置",
            )
            SwitchRow(
                title = "备用 DNS",
                subtitle = "主 DNS 失败/熔断或触发复核时使用 ${cfg.dnsFallback.ifBlank { "未设置" }}；支持 udp://、tls://、https://，关闭即 fail-closed",
                checked = cfg.allowDnsFallback,
            ) {
                settings.update { current -> current.copy(allowDnsFallback = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "异常应答复核",
                subtitle = "只复核私网、保留、广播等明显异常；境外 IP 本身不当作污染",
                checked = cfg.fallbackFilter,
            ) {
                settings.update { current -> current.copy(fallbackFilter = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "非 CN IP 复核",
                subtitle = "额外把非中国大陆 IP 交给备用 DNS 复核；会增加查询与等待，默认关闭",
                checked = cfg.fallbackGeoCheck,
            ) {
                settings.update { current -> current.copy(fallbackGeoCheck = it) }
                if (runtime.current().connected) onRestart()
            }
            SettingsRow(
                title = "拦截 TTL",
                subtitle = "NXDOMAIN 携带的 SOA 与本地拦截缓存时长，减少广告 SDK 反复查询",
                value = "${cfg.blockTtl} 秒",
                chevron = true,
                onClick = {
                    val next = when (cfg.blockTtl) {
                        15 -> 30
                        30 -> 60
                        60 -> 120
                        120 -> 300
                        else -> 15
                    }
                    settings.update { current -> current.copy(blockTtl = next) }
                    if (runtime.current().connected) onRestart()
                },
            )
            SwitchRow(
                title = "自动更新",
                subtitle = if (cfg.remoteConfigUrl.isNotBlank()) "按远端配置的 update_interval 检查" else "超过 12 小时拉取手动规则 URL",
                checked = cfg.autoUpdateRules,
            ) {
                settings.update { current -> current.copy(autoUpdateRules = it) }
            }
            SwitchRow(
                title = "拦截广告域名",
                subtitle = "在 DNS 层返回 NXDOMAIN 或 0.0.0.0，不请求上游",
                checked = cfg.blockEnabled,
            ) {
                settings.update { current -> current.copy(blockEnabled = it) }
                if (runtime.current().connected) onRestart()
            }
            SettingsRow(
                title = "拦截响应",
                value = if (cfg.blockMode == "zero") "0.0.0.0" else "NXDOMAIN",
                chevron = true,
                onClick = { showBlockMode = true },
            )
            SwitchRow(
                title = "DNS 查询日志",
                subtitle = "记录域名、拦截/放行、缓存或上游、耗时",
                checked = cfg.dnsQueryLog,
            ) {
                settings.update { current -> current.copy(dnsQueryLog = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "Fake-IP",
                subtitle = "TUN 模式下用虚拟地址加速分流；仅 DNS 模式自动停用",
                checked = cfg.fakeIp,
            ) {
                settings.update { current -> current.copy(fakeIp = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "关闭 AAAA",
                subtitle = "节点只有 IPv4 出口时开启，避免 App 拿到 IPv6 地址后连不通",
                checked = cfg.blockAaaa,
            ) {
                settings.update { current -> current.copy(blockAaaa = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "TLS / HTTP 域名嗅探",
                subtitle = "没有 DNS 映射时，从首包读取 SNI / Host",
                checked = cfg.sniff,
                showDivider = false,
            ) {
                settings.update { current -> current.copy(sniff = it) }
                if (runtime.current().connected) onRestart()
            }
        }

        SectionHeader("规则", trailing = { TextAction("添加") { showAddRule = true } })
        if (cfg.rules.isNotEmpty()) {
            NamuTextField(
                value = ruleQuery,
                onChange = { ruleQuery = it },
                placeholder = "搜索规则（类型/值/动作）",
                singleLine = true,
                modifier = Modifier.padding(horizontal = 12.dp),
            )
            Spacer(Modifier.height(8.dp))
        }
        GroupCard {
            if (cfg.rules.isEmpty()) {
                SettingsRow(
                    title = "暂无自定义规则",
                    subtitle = "添加后按顺序匹配；未命中时按最终策略处理",
                    showDivider = false,
                )
            } else {
                val visibleRules = cfg.rules.filter {
                    ruleQuery.isBlank() ||
                        it.type.contains(ruleQuery, ignoreCase = true) ||
                        it.value.contains(ruleQuery, ignoreCase = true) ||
                        it.action.contains(ruleQuery, ignoreCase = true)
                }
                if (visibleRules.isEmpty()) {
                    SettingsRow(title = "没有匹配的规则", subtitle = "换个关键字试试", showDivider = false)
                }
                visibleRules.forEachIndexed { index, rule ->
                    RuleRow(
                        rule = rule,
                        showDivider = index != visibleRules.lastIndex,
                        onToggle = {
                            settings.update { current ->
                                current.copy(rules = current.rules.map {
                                    if (it.type == rule.type && it.value == rule.value && it.action == rule.action) {
                                        it.copy(enabled = !it.enabled)
                                    } else it
                                })
                            }
                            if (runtime.current().connected) onRestart()
                        },
                        onDelete = {
                            settings.update { current -> current.copy(
                                rules = current.rules.filterNot {
                                    it.type == rule.type && it.value == rule.value && it.action == rule.action
                                },
                            ) }
                            if (runtime.current().connected) onRestart()
                        },
                    )
                }
            }
        }
        SectionHeader("MITM", trailing = { TextAction("管理") { onOpenMitm() } })
        GroupCard {
            SettingsRow(
                title = "MITM 去广告",
                value = if (cfg.mitm.enabled) "已启用" else "未启用",
                subtitle = "解密命中域名的 HTTPS，拒绝广告请求并改写响应",
            )
            SettingsRow(
                title = "手动域名 / 跳过域名",
                value = "${cfg.mitm.hostnames.size} / ${cfg.mitm.skipHostnames.size}",
                subtitle = "模块 [MITM]/重写规则自动合并；证书与明细在 MITM 页管理",
            )
            SettingsRow(
                title = "证书与规则管理",
                chevron = true,
                showDivider = false,
                onClick = onOpenMitm,
            )
        }
        GroupCard {
            SettingsRow(
                title = "本地拦截域名",
                subtitle = "手动维护，不依赖规则集 URL",
                value = "${cfg.customAds.size} 条",
                chevron = true,
                onClick = { showCustomAds = true },
            )
            SwitchRow(
                title = "国内域名 / IP 直连",
                subtitle = "国内站点不经过代理节点",
                checked = cfg.cnDirect,
            ) {
                settings.update { current -> current.copy(cnDirect = it) }
                if (runtime.current().connected) onRestart()
            }
            SettingsRow(
                title = "最终策略",
                subtitle = "所有规则都未命中时的处理方式",
                value = when {
                    cfg.finalPolicy == "direct" -> "全部直连"
                    cfg.finalPolicy.startsWith("node:") -> "节点 ${cfg.finalPolicy.removePrefix("node:")}"
                    else -> "走代理节点"
                },
                chevron = true,
                onClick = { showFinalPolicy = true },
            )
            SettingsRow(
                title = "更新国内 IP 库",
                subtitle = "用于国内直连判断",
                showDivider = false,
                rightContent = {
                    if (updatingIp) {
                        androidx.compose.material3.CircularProgressIndicator(
                            Modifier.height(18.dp).width(18.dp),
                            color = NamuColors.TextSub,
                            strokeWidth = 2.dp,
                        )
                    } else {
                        Text("更新", fontSize = 14.sp, color = NamuColors.Blue)
                    }
                },
                onClick = {
                    if (!updatingIp) {
                        scope.launch {
                            updatingIp = true
                            try {
                                val n = com.namu.dns.Actions.updateCnIp("https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt")
                                messages.show("国内 IP 库已更新：$n 条")
                                if (runtime.current().connected) onRestart()
                            } catch (e: Exception) {
                                messages.show("更新失败：${e.message}")
                            } finally {
                                updatingIp = false
                            }
                        }
                    }
                },
            )
        }

        SectionHeader("规则集 URL")
        GroupCard {
            SettingsRow(
                title = "远端配置",
                subtitle = if (cfg.remoteConfigUrl.isBlank()) {
                    "配置 URL 下发 DNS、模式和规则集清单"
                } else {
                    "${cfg.remoteConfigName.ifBlank { "已配置" }} · ${formatAgo(cfg.remoteConfigUpdatedAt)}"
                },
                value = if (cfg.remoteConfigUrl.isBlank()) "未配置" else "已同步",
                valueColor = if (cfg.remoteConfigUrl.isBlank()) NamuColors.Orange else NamuColors.Green,
                chevron = true,
                onClick = { showRemote = true },
            )
            SettingsRow(
                title = "规则集 URL",
                subtitle = if (cfg.ruleSources.isEmpty()) {
                    "尚未导入 DNS 过滤规则集"
                } else {
                    "${cfg.ruleSources.size} 个来源 · ${cfg.ruleSources.sumOf { it.lines }} 行"
                },
                value = if (cfg.ruleSources.isEmpty()) "无" else "已配置",
                valueColor = if (cfg.ruleSources.isEmpty()) NamuColors.Orange else NamuColors.Green,
                chevron = true,
                onClick = { showRuleSources = true },
            )
            if (cfg.ruleSources.isEmpty()) {
                SettingsRow(
                    title = "手动规则 URL",
                    subtitle = if (cfg.rulesUrl.isBlank()) "未设置" else cfg.rulesUrl,
                    value = if (cfg.rulesUrl.isBlank()) "" else "已设置",
                    chevron = true,
                    showDivider = false,
                    onClick = { showRulesUpdate = true },
                )
            }
        }

        SectionHeader("策略组")
        GroupCard {
            val errors = groupIssues.count { it.level == com.namu.dns.core.config.ConfigIssueLevel.ERROR }
            SettingsRow(
                title = "策略组与选择",
                subtitle = when {
                    cfg.proxyGroups.isEmpty() -> "select / url-test / fallback；可嵌套引用"
                    errors > 0 -> "$errors 个错误：循环、空组或引用失效"
                    else -> "${cfg.proxyGroups.size} 个组；规则可直接引用组名"
                },
                value = if (cfg.proxyGroups.isEmpty()) "无" else "${cfg.proxyGroups.size} 个",
                valueColor = if (errors > 0) NamuColors.Red else if (cfg.proxyGroups.isEmpty()) NamuColors.TextSub else NamuColors.Green,
                chevron = true,
                showDivider = false,
                onClick = { showGroups = true },
            )
        }

        SectionHeader("模块")
        GroupCard {
            val enabled = cfg.moduleSources.count { it.enabled }
            SettingsRow(
                title = "模块规则",
                subtitle = if (cfg.moduleSources.isEmpty()) {
                    "导入 .sgmodule，按 App 生效"
                } else {
                    "${cfg.moduleSources.size} 个模块 · ${enabled} 个启用 · ${cfg.moduleSources.sumOf { it.blockRules }} 条拦截"
                },
                value = if (cfg.moduleSources.isEmpty()) "无" else "${cfg.moduleSources.size} 个",
                valueColor = if (cfg.moduleSources.isEmpty()) NamuColors.Orange else NamuColors.Green,
                chevron = true,
                showDivider = false,
                onClick = onOpenModules,
            )
        }

        FooterText("规则按顺序匹配：自定义规则 → 国内直连 → 最终策略。规则集 URL 由本地过滤，未命中的查询才发往 DNS 上游。")
        Spacer(Modifier.height(34.dp))
    }

    if (showDns) {
        DnsDialog(
            current = cfg.dnsUpstream,
            onDismiss = { showDns = false },
            onSelect = { url ->
                settings.update { current -> current.copy(dnsUpstream = url) }
                showDns = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
    if (showBlockMode) {
        ChoiceDialog(
            title = "拦截响应",
            message = "命中广告规则时返回哪种 DNS 结果",
            options = listOf("nxdomain" to "NXDOMAIN（域名不存在）", "zero" to "0.0.0.0（空地址）"),
            selected = cfg.blockMode,
            onSelect = { key ->
                settings.update { current -> current.copy(blockMode = key) }
                showBlockMode = false
                if (runtime.current().connected) onRestart()
            },
            onDismiss = { showBlockMode = false },
        )
    }
    if (showFinalPolicy) {
        ChoiceDialog(
            title = "最终策略",
            message = "所有规则都未命中时如何处理流量",
            options = listOf("proxy" to "走当前节点", "direct" to "全部直连") +
                cfg.proxyGroups.map { it.name to "策略组：${it.name}" },
            selected = cfg.finalPolicy,
            onSelect = { key ->
                settings.update { current -> current.copy(finalPolicy = key) }
                showFinalPolicy = false
                if (runtime.current().connected) onRestart()
            },
            onDismiss = { showFinalPolicy = false },
        )
    }
    if (showAddRule) {
        AddRuleDialog(
            groups = cfg.proxyGroups.map { it.name },
            onDismiss = { showAddRule = false },
            onAdd = { item ->
                settings.update { current -> current.copy(rules = current.rules + item) }
                showAddRule = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
    if (showGroups) {
        ProxyGroupsDialog(
            groups = cfg.proxyGroups,
            nodes = cfg.nodes.map { it.name },
            selections = cfg.groupSelections,
            onDismiss = { showGroups = false },
        )
    }
    if (showCustomAds) {
        CustomAdsDialog(
            onDismiss = { showCustomAds = false },
            onDone = {
                showCustomAds = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
    if (showRemote) {
        RemoteConfigDialog(
            onDismiss = { showRemote = false },
            onDone = {
                showRemote = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
    if (showRuleSources) {
        RuleSourcesDialog(
            onDismiss = { showRuleSources = false },
            onDone = {
                showRuleSources = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
    if (showRulesUpdate) {
        RulesUpdateDialog(
            onDismiss = { showRulesUpdate = false },
            onDone = {
                showRulesUpdate = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
}

@Composable
private fun RuleRow(rule: RuleItem, showDivider: Boolean, onToggle: () -> Unit, onDelete: () -> Unit) {
    SettingsRow(
        title = rule.value,
        subtitle = ruleTypeLabel(rule.type) + if (!rule.enabled) " · 已禁用（不下发内核）" else "",
        showDivider = showDivider,
        rightContent = {
            Text(
                actionLabel(rule.action),
                fontSize = 13.sp,
                color = if (rule.enabled) actionColor(rule.action) else NamuColors.TextTertiary,
            )
            Spacer(Modifier.width(8.dp))
            IosSwitch(checked = rule.enabled, onCheckedChange = { onToggle() })
            Spacer(Modifier.width(8.dp))
            MiniTextAction("删除", color = NamuColors.Red) { onDelete() }
        },
    )
}

private fun ruleTypeLabel(type: String): String = when (type) {
    "DOMAIN-SUFFIX" -> "域名后缀"
    "DOMAIN" -> "完整域名"
    "DOMAIN-KEYWORD" -> "关键词"
    "DOMAIN-REGEX" -> "正则"
    "IP-CIDR", "IP-CIDR6" -> "IP 段"
    "PORT" -> "端口"
    "FINAL", "MATCH" -> "最终规则"
    else -> type
}

private fun actionLabel(action: String): String = when (action) {
    "proxy" -> "代理"
    "direct" -> "直连"
    "block" -> "拦截"
    else -> if (action.startsWith("node:")) "节点" else action
}

private fun actionColor(action: String): Color = when (action) {
    "proxy" -> NamuColors.Blue
    "direct" -> NamuColors.Green
    "block" -> NamuColors.Red
    else -> NamuColors.Teal
}

private fun configDnsLabel(url: String): String = when {
    url.startsWith("https://") -> "DoH · ${hostOf(url)}"
    url.startsWith("tls://") -> "DoT · ${url.removePrefix("tls://")}"
    url.startsWith("udp://") -> "UDP · ${url.removePrefix("udp://")}"
    url.isBlank() -> "未设置"
    else -> url
}
