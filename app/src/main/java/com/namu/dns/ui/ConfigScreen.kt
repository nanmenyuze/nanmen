package com.namu.dns.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.material3.IconButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.MoreVert
import com.namu.dns.AppConfig
import com.namu.dns.MitmManager
import com.namu.dns.core.config.ConfigFile
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.namu.dns.Actions
import com.namu.dns.ConfigFileStore
import com.namu.dns.ConfigStore
import com.namu.dns.NamuVpnService
import com.namu.dns.RuleSource
import com.namu.dns.RuleItem
import com.namu.dns.RuleLineParser
import com.namu.dns.core.ConfigSection
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.config.DirectFilterScope
import com.namu.dns.core.config.ProxyGroupValidation
import com.namu.dns.core.config.RoutingMode
import com.namu.dns.core.repository.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun ConfigScreen(onOpenPanel: (String) -> Unit) {
    var copyFrom by remember { mutableStateOf<String?>(null) }
    var switching by remember { mutableStateOf(false) }
    var showCreate by remember { mutableStateOf(false) }
    var showImportLocal by remember { mutableStateOf(false) }
    var showImportUrl by remember { mutableStateOf(false) }
    var infoFile by remember { mutableStateOf<ConfigFileStore.FileInfo?>(null) }
    var deleteFile by remember { mutableStateOf<ConfigFileStore.FileInfo?>(null) }
    var revision by remember { mutableIntStateOf(0) }
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val messages = container.messages
    val context = container.context
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        ConfigFileStore.ensureDefault(context, cfg)
        revision++
    }
    val activeName by settings.activeProfile.collectAsStateWithLifecycle()
    val files = remember(revision, activeName) { ConfigFileStore.list(context, activeName) }

    fun activate(name: String) {
        if (switching || name == container.config.activeName()) return
        if (NamuVpnService.profileSwitchPending()) {
            messages.show("正在应用上一份配置")
            return
        }
        scope.launch {
            switching = true
            try {
                val problem = container.config.validateProfile(name)
                if (problem != null) {
                    messages.show(problem)
                    return@launch
                }
                val target = container.config.loadProfile(name) ?: return@launch
                if (!prepareProfileCa(target, context)) {
                    messages.show("CA 准备失败，已保留当前配置")
                    return@launch
                }
                if (!container.config.switchTo(name)) {
                    messages.show("配置校验失败，已保留当前配置")
                    return@launch
                }
                revision++
                if (!NamuVpnService.profileSwitchPending() && container.config.activeName() == name) messages.show("已切换到 $name")
            } finally {
                switching = false
            }
        }
    }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("配置文件")
        GroupCard {
            SettingsRow("新建配置", chevron = true, onClick = { showCreate = true })
            SettingsRow("本地导入", chevron = true, onClick = { showImportLocal = true })
            SettingsRow("URL 导入", chevron = true, showDivider = false, onClick = { showImportUrl = true })
        }
        Spacer(Modifier.height(16.dp))
        GroupCard {
            if (files.isEmpty()) {
                SettingsRow(title = "暂无配置文件", showDivider = false)
            } else {
                files.forEachIndexed { index, f ->
                    ConfigFileRow(
                        info = f,
                        showDivider = index != files.lastIndex,
                        issue = remember(f, cfg.nodes, revision) { container.config.validateProfile(f.name) },
                        onActivate = { activate(f.name) },
                        onInfo = { onOpenPanel(f.name) },
                    )
                }
            }
        }
        Spacer(Modifier.height(24.dp))
    }

    if (showCreate) {
        ConfigNameDialog(
            title = "新建配置文件",
            initial = "配置-${files.size + 1}.conf",
            onConfirm = { name ->
                showCreate = false
                if (container.config.create(name)) {
                    revision++
                    onOpenPanel(ConfigFileStore.sanitize(name))
                } else {
                    messages.show("已存在同名配置文件")
                }
            },
            onDismiss = { showCreate = false },
        )
    }
    if (showImportLocal || showImportUrl) {
        ConfigImportDialog(
            urlMode = showImportUrl,
            onDone = { info ->
                showImportLocal = false
                showImportUrl = false
                revision++
                messages.show("已导入 ${info.name}")
            },
            onDismiss = {
                showImportLocal = false
                showImportUrl = false
            },
        )
    }
    infoFile?.let { f ->
        ConfigFileInfoDialog(
            info = f.copy(active = f.name == activeName),
            onActivate = {
                infoFile = null
                activate(f.name)
            },
            onEdit = {
                infoFile = null
                onOpenPanel(f.name)
            },
            onCopy = { copyFrom = f.name; infoFile = null },
            onExport = {
                scope.launch { exportProfile(f.name) }
            },
            onDelete = {
                infoFile = null
                deleteFile = f
            },
            onRestore = {
                infoFile = null
                if (ConfigFileStore.restore(context, f.name)) {
                    // 当前 active 配置回退后，要把回退内容重新套回内存，不能只改磁盘。
                    if (f.name == activeName) {
                        ConfigFileStore.loadInto(context, f.name, settings.current())?.let { restored ->
                            container.config.saveProfile(f.name) { restored }
                        }
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
    copyFrom?.let { source ->
        ConfigNameDialog(
            title = "复制配置",
            initial = source.removeSuffix(".conf") + "-副本.conf",
            onConfirm = { target ->
                if (container.config.copyProfile(source, target)) {
                    copyFrom = null
                    revision++
                    messages.show("已复制配置")
                } else messages.show("复制失败：检查配置名和存储空间")
            },
            onDismiss = { copyFrom = null },
        )
    }
    deleteFile?.let { f ->
        NamuDialog(
            title = "删除配置？",
            message = f.name,
            confirmText = "删除",
            onDismiss = { deleteFile = null },
            onConfirm = {
                deleteFile = null
                if (container.config.delete(f.name)) {
                    revision++
                    messages.show("已删除 ${f.name}")
                } else {
                    messages.show("默认配置不能删除")
                }
            },
        )
    }
}

@Composable
private fun ConfigFileRow(
    info: ConfigFileStore.FileInfo,
    showDivider: Boolean,
    issue: String?,
    onActivate: () -> Unit,
    onInfo: () -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, end = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).clickable(onClick = onActivate).padding(vertical = 12.dp)) {
            Text(info.name, fontSize = 16.sp, color = NamuColors.TextMain)
            if (issue != null) {
                Text("! $issue", fontSize = 12.sp, color = NamuColors.Red)
            } else if (info.isDefault) {
                Text("默认配置", fontSize = 12.sp, color = NamuColors.TextSub)
            }
        }
        // 未激活的行保留蓝勾槽位，所有文件右侧只显示面板入口。
        Box(Modifier.width(28.dp), contentAlignment = Alignment.Center) {
            if (info.active) CheckMark()
        }
        IconButton(onClick = onInfo) { NamuIcon(Icons.Outlined.Info, "管理 ${info.name}") }
    }
    if (showDivider) RowDivider()
}

internal fun SettingsRepository.applyRouting(mode: String, fullRoute: Boolean): Boolean {
    val current = current()
    if (current.mode == mode && current.dnsOnlyFullRoute == fullRoute) return false
    update {
        it.copy(
            mode = mode,
            dnsOnlyFullRoute = fullRoute,
            finalPolicy = if (mode == DirectFilterScope.Connections.mode && it.mode != mode) "direct" else it.finalPolicy,
        )
    }
    return true
}

@Composable
fun ConfigDetailScreen(
    name: String,
    onOpenSection: (ConfigSection) -> Unit,
    onOpenRaw: () -> Unit,
    onDeleted: () -> Unit = {},
) {
    val editor = rememberProfileEditor(name) ?: return
    val cfg = editor.current()
    val scope = rememberCoroutineScope()
    val container = LocalAppContainer.current
    val context = LocalContext.current
    var showGroups by remember { mutableStateOf(false) }
    var showTest by remember { mutableStateOf(false) }
    var copyName by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var updating by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState())) {
        SectionHeader("配置")
        GroupCard {
            SettingsRow("通用", value = configDnsLabel(cfg.dnsUpstream), chevron = true, onClick = { onOpenSection(ConfigSection.General) })
            SettingsRow("规则", value = "${cfg.rules.size} 条", chevron = true, onClick = { onOpenSection(ConfigSection.Rules) })
            SettingsRow("Hosts", value = "${cfg.mitm.hostMappings.size} 条", chevron = true, onClick = { onOpenSection(ConfigSection.Hosts) })
            SettingsRow("URL 重写", value = "${cfg.mitm.urlRewrites.size} 条", chevron = true, onClick = { onOpenSection(ConfigSection.UrlRewrite) })
            SettingsRow("头部重写", value = "${cfg.mitm.headerRewrites.size} 条", chevron = true, onClick = { onOpenSection(ConfigSection.HeaderRewrite) })
            SettingsRow("正文重写", value = "${cfg.mitm.bodyRewrites.size} 条", chevron = true, onClick = { onOpenSection(ConfigSection.BodyRewrite) })
            SettingsRow("HTTPS 解密", value = if (cfg.mitm.enabled) "已开启" else "已关闭", chevron = true, onClick = { onOpenSection(ConfigSection.Https) })
            SettingsRow("代理分组", value = "${cfg.proxyGroups.size} 个", chevron = true, onClick = { showGroups = true })
            SettingsRow("高级设置", value = "6 项", chevron = true, showDivider = false, onClick = { onOpenSection(ConfigSection.Advanced) })
        }
        Spacer(Modifier.height(16.dp))
        GroupCard {
            SettingsRow("规则集 URL", value = "${cfg.ruleSources.size} 个", chevron = true, onClick = { onOpenSection(ConfigSection.Sources) })
            if (cfg.remoteConfigUrl.isNotBlank()) {
                SettingsRow(
                    "更新配置",
                    value = if (updating) "更新中…" else "来自 URL",
                    onClick = {
                        if (updating) return@SettingsRow
                        scope.launch(kotlinx.coroutines.Dispatchers.IO) {
                            updating = true
                            try {
                                val conn = java.net.URL(cfg.remoteConfigUrl).openConnection() as java.net.HttpURLConnection
                                conn.connectTimeout = 15000
                                conn.readTimeout = 30000
                                val text = conn.inputStream.bufferedReader().use { it.readText() }
                                conn.disconnect()
                                val result = com.namu.dns.core.config.ConfigSourceRegistry.parse(text, cfg)
                                val parsed = result.config
                                if (!result.preview.canImport || parsed == null) {
                                    container.messages.show(result.preview.reason.ifBlank { "远端配置无法导入" })
                                } else {
                                    val next = parsed.toAppConfig(cfg).copy(
                                        remoteConfigUrl = cfg.remoteConfigUrl,
                                        remoteConfigName = name,
                                        remoteConfigUpdatedAt = System.currentTimeMillis(),
                                    )
                                    if (editor.update { next }) container.messages.show("配置已更新")
                                    else container.messages.show("配置校验失败，未覆盖当前配置")
                                }
                            } catch (e: Exception) {
                                container.messages.show("更新失败：${e.message ?: "网络错误"}")
                            } finally { updating = false }
                        }
                    },
                )
            }
            SettingsRow("编辑纯文本", chevron = true, onClick = onOpenRaw)
            SettingsRow("校验配置", onClick = { container.messages.show(container.config.validateProfile(name) ?: "配置校验通过") })
            SettingsRow("导出配置", showDivider = false, onClick = { scope.launch { exportProfile(name) } })
        }
        Spacer(Modifier.height(16.dp))
        GroupCard {
            SettingsRow("复制配置", onClick = { copyName = true })
            SettingsRow("测试规则", showDivider = false, onClick = { showTest = true })
        }
        Spacer(Modifier.height(16.dp))
        GroupCard {
            SettingsRow("删除配置", valueColor = NamuColors.Red, showDivider = false, onClick = { confirmDelete = true })
        }
        Spacer(Modifier.height(24.dp))
    }
    if (showGroups) {
        ProxyGroupsDialog(
            groups = cfg.proxyGroups,
            nodes = cfg.nodes.map { it.name },
            selections = cfg.groupSelections,
            observeRuntime = editor.isActive,
            onChange = { groups, selections -> editor.update { it.copy(proxyGroups = groups, groupSelections = selections) } },
            onDismiss = { showGroups = false },
        )
    }
    if (showTest) RuleTestDialog(config = cfg, useRuntimeAssets = editor.isActive, onDismiss = { showTest = false })
    if (copyName) {
        ConfigNameDialog(
            title = "复制配置",
            initial = name.removeSuffix(".conf") + "-副本.conf",
            onConfirm = {
                if (container.config.copyProfile(name, it)) { copyName = false; container.messages.show("已复制配置") }
                else container.messages.show("复制失败：配置已存在或存储不可用")
            },
            onDismiss = { copyName = false },
        )
    }
    if (confirmDelete) {
        NamuDialog(
            title = "删除配置？", message = name, confirmText = "删除",
            onDismiss = { confirmDelete = false },
            onConfirm = {
                confirmDelete = false
                if (container.config.delete(name)) { container.messages.show("已删除配置"); onDeleted() }
                else container.messages.show("默认配置不能删除")
            },
        )
    }
}

@Composable
fun ConfigSectionScreen(section: ConfigSection, name: String, onOpenCertificate: () -> Unit) {
    val editor = rememberProfileEditor(name) ?: return
    when (section) {
        ConfigSection.General -> ConfigGeneralScreen(editor)
        ConfigSection.Rules -> ConfigRulesScreen(editor)
        ConfigSection.Sources -> ConfigSourcesScreen(editor)
        ConfigSection.Hosts -> ConfigHostsScreen(editor)
        ConfigSection.UrlRewrite -> ConfigRewriteScreen(editor, "URL 重写")
        ConfigSection.HeaderRewrite -> ConfigRewriteScreen(editor, "头部重写")
        ConfigSection.BodyRewrite -> ConfigRewriteScreen(editor, "正文重写")
        ConfigSection.Https -> ConfigHttpsScreen(editor, onOpenCertificate)
        ConfigSection.Advanced -> ConfigAdvancedScreen(editor)
    }
}

@Composable
private fun ConfigGeneralScreen(settings: ProfileEditor) {
    val container = LocalAppContainer.current
    val cfg = settings.current()
    var showDns by remember { mutableStateOf(false) }
    var showFallback by remember { mutableStateOf(false) }
    var showSkip by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("DNS")
        GroupCard {
            SettingsRow(
                title = "DNS 上游",
                value = configDnsLabel(cfg.dnsUpstream),
                chevron = true,
                onClick = { showDns = true },
            )
            if (cfg.dnsBootstrap.isNotBlank()) {
                SettingsRow(
                    title = "Bootstrap IP",
                    value = cfg.dnsBootstrap,
                )
            }
            if (cfg.dnsHeaderName.isNotBlank()) {
                SettingsRow(
                    title = "DoH 请求头",
                    value = cfg.dnsHeaderName,
                )
            }
            SettingsRow(title = "备用 DNS", value = configDnsLabel(cfg.dnsFallback), chevron = true, onClick = { showFallback = true })
            SwitchRow(
                title = "启用回退",
                subtitle = "${configDnsLabel(cfg.dnsFallback)} · 关闭后禁止回退",
                checked = cfg.allowDnsFallback,
            ) {
                settings.update { current -> current.copy(allowDnsFallback = it) }
            }
            SwitchRow(
                title = "DNS 查询日志",
                checked = cfg.dnsQueryLog,
                showDivider = false,
            ) {
                settings.update { current -> current.copy(dnsQueryLog = it) }
            }
        }

        SectionHeader("连接处理")
        GroupCard {
            SettingsRow(
                title = "跳过代理",
                subtitle = "匹配域名后缀的连接始终直连",
                value = "${cfg.skipProxyHosts.size} 项",
                chevron = true,
                showDivider = false,
                onClick = { showSkip = true },
            )
        }
        Spacer(Modifier.height(24.dp))
    }

    if (showDns) {
        DnsListDialog(
            title = "DNS 覆写",
            current = cfg.dnsUpstream,
            onDismiss = { showDns = false },
            onConfirm = { value ->
                settings.update { it.copy(dnsUpstream = value) }
                showDns = false
            },
        )
    }
    if (showFallback) {
        DnsListDialog(
            title = "备用 DNS",
            current = cfg.dnsFallback,
            onDismiss = { showFallback = false },
            onConfirm = { value ->
                settings.update { it.copy(dnsFallback = value) }
                showFallback = false
            },
        )
    }
    if (showSkip) {
        StringListDialog(
            title = "跳过代理",
            message = "每行一个域名后缀，匹配连接将直接放行。",
            initial = cfg.skipProxyHosts,
            onDismiss = { showSkip = false },
            onConfirm = { hosts ->
                settings.update { it.copy(skipProxyHosts = hosts) }
                showSkip = false
            },
        )
    }
}

@Composable
private fun ConfigAdvancedScreen(settings: ProfileEditor) {
    val cfg = settings.current()
    var showFilterScope by remember { mutableStateOf(false) }
    val filterScope = DirectFilterScope.fromConfig(cfg.mode, cfg.dnsOnlyFullRoute)
    Column(Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState())) {
        SectionHeader("高级设置")
        GroupCard {
            SwitchRow("关闭 AAAA", subtitle = "只返回 IPv4 地址", checked = cfg.blockAaaa) {
                settings.update { current -> current.copy(blockAaaa = it) }
            }
            SwitchRow("异常应答复核", subtitle = "使用备用 DNS 复核异常地址", checked = cfg.fallbackFilter) {
                settings.update { current -> current.copy(fallbackFilter = it) }
            }
            SwitchRow("非 CN IP 复核", subtitle = "非中国大陆 IP 也交给备用 DNS 复核", checked = cfg.fallbackGeoCheck) {
                settings.update { current -> current.copy(fallbackGeoCheck = it) }
            }
            SwitchRow("Fake-IP", subtitle = "仅在接管连接时生效", checked = cfg.fakeIp) {
                settings.update { current -> current.copy(fakeIp = it) }
            }
            SwitchRow("TLS / HTTP 域名嗅探", subtitle = "从连接中识别域名", checked = cfg.sniff, showDivider = false) {
                settings.update { current -> current.copy(sniff = it) }
            }
        }
        SectionHeader("过滤")
        GroupCard {
            SettingsRow("过滤范围", value = filterScope.title, chevron = true, showDivider = false, onClick = { showFilterScope = true })
        }
        Spacer(Modifier.height(24.dp))
    }
    if (showFilterScope) {
        ChoiceDialog(
            title = "过滤范围",
            message = "轻量模式只接管系统 DNS。全量接管会让其他连接也经过 VPN，自带 DoH 的应用仍可能绕过 DNS 过滤。",
            options = DirectFilterScope.entries.map { it.name to it.title },
            selected = filterScope.name,
            onSelect = { key ->
                showFilterScope = false
                val selected = DirectFilterScope.valueOf(key)
                val current = settings.current()
                val fullRoute = if (selected == DirectFilterScope.Connections) current.dnsOnlyFullRoute else selected.fullRoute
                settings.update {
                    it.copy(mode = selected.mode, dnsOnlyFullRoute = fullRoute, finalPolicy = if (selected.mode == DirectFilterScope.Connections.mode && it.mode != selected.mode) "direct" else it.finalPolicy)
                }
            },
            onDismiss = { showFilterScope = false },
        )
    }
}

@Composable
private fun ConfigRulesScreen(settings: ProfileEditor) {
    val container = LocalAppContainer.current
    val scope = rememberCoroutineScope()
    val cfg = settings.current()
    var showAddRule by remember { mutableStateOf(false) }
    var editRuleIndex by remember { mutableStateOf<Int?>(null) }
    var ruleQuery by remember { mutableStateOf("") }
    var manageMode by remember { mutableStateOf(false) }
    var manageMenu by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf(setOf<Int>()) }

    Column(Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState())) {
        SectionHeader(
            "规则",
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (manageMode) {
                        TextAction("完成") { manageMode = false; selected = emptySet() }
                    } else {
                        TextAction("＋") { showAddRule = true }
                        Box {
                            IconButton(onClick = { manageMenu = true }) { NamuIcon(Icons.Outlined.MoreVert, "管理规则") }
                            DropdownMenu(expanded = manageMenu, onDismissRequest = { manageMenu = false }) {
                                DropdownMenuItem(text = { Text("选择规则") }, onClick = {
                                    manageMenu = false; manageMode = true; selected = emptySet()
                                })
                                DropdownMenuItem(text = { Text("全选") }, onClick = {
                                    manageMenu = false; manageMode = true; selected = cfg.rules.indices.toSet()
                                })
                            }
                        }
                    }
                }
            },
        )
        NamuTextField(
            value = ruleQuery,
            onChange = { ruleQuery = it },
            placeholder = "搜索规则",
            singleLine = true,
            modifier = Modifier.padding(horizontal = 12.dp),
        )
        Spacer(Modifier.height(8.dp))
        GroupCard {
            val visibleRules = cfg.rules.withIndex().filter { (_, rule) ->
                ruleQuery.isBlank() || rule.type.contains(ruleQuery, true) ||
                    rule.value.contains(ruleQuery, true) || rule.action.contains(ruleQuery, true)
            }
            if (visibleRules.isEmpty()) {
                SettingsRow(title = if (cfg.rules.isEmpty()) "暂无规则" else "没有匹配的规则", showDivider = false)
            }
            visibleRules.forEachIndexed { index, (position, rule) ->
                ConfigRuleRow(
                    rule = rule,
                    selected = position in selected,
                    managing = manageMode,
                    showDivider = index != visibleRules.lastIndex,
                    onClick = {
                        if (manageMode) {
                            selected = if (position in selected) selected - position else selected + position
                        } else editRuleIndex = position
                    },
                )
            }
        }
        if (manageMode) {
            Spacer(Modifier.height(12.dp))
            GroupCard {
                SettingsRow(
                    "删除所选",
                    value = "${selected.size} 条",
                    valueColor = NamuColors.Red,
                    showDivider = false,
                    onClick = {
                        if (selected.isNotEmpty()) {
                            settings.update { current -> current.copy(rules = current.rules.filterIndexed { i, _ -> i !in selected }) }
                            selected = emptySet()
                            manageMode = false
                        }
                    },
                )
            }
        }
        Spacer(Modifier.height(24.dp))
    }

    if (showAddRule || editRuleIndex != null) {
        val targetIndex = editRuleIndex
        AddRuleDialog(
            groups = cfg.proxyGroups.map { it.name },
            initial = targetIndex?.let(cfg.rules::getOrNull),
            onDismiss = { showAddRule = false; editRuleIndex = null },
            onAdd = { item ->
                fun persist(): Boolean {
                    val saved = settings.update { current ->
                        val list = if (targetIndex == null) current.rules + item
                        else current.rules.mapIndexed { index, old -> if (index == targetIndex) item else old }
                        current.copy(rules = list)
                    }
                    if (saved) { showAddRule = false; editRuleIndex = null }
                    return saved
                }
                if ((item.type == "RULE-SET" || item.type == "DOMAIN-SET") && item.value.startsWith("http")) {
                    scope.launch {
                        try {
                            val content = Actions.fetchText(item.value, maxBytes = 8 * 1024 * 1024)
                            ConfigStore.ruleSetFile(container.context, item.value).writeText(content)
                            if (persist()) container.messages.show("规则集已下载并保存")
                        } catch (e: Exception) {
                            container.messages.show("规则集下载失败：${e.message ?: "网络错误"}")
                        }
                    }
                } else persist()
            },
        )
    }
}

@Composable
private fun ConfigRuleRow(
    rule: RuleItem,
    selected: Boolean,
    managing: Boolean,
    showDivider: Boolean,
    onClick: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(rule.value, color = if (rule.enabled) NamuColors.TextMain else NamuColors.TextSub, fontSize = 16.sp)
            Text(
                "${rule.type} · ${rule.action}" + (if (rule.extendedMatch) " · 扩展匹配" else "") + (if (rule.preMatch) " · 预匹配" else ""),
                color = NamuColors.TextSub,
                fontSize = 12.sp,
            )
        }
        if (managing) Text(if (selected) "✓" else "○", color = if (selected) NamuColors.Blue else NamuColors.TextSub, fontSize = 20.sp)
        else Text("›", color = NamuColors.TextSub, fontSize = 22.sp)
    }
    if (showDivider) RowDivider()
}

@Composable
private fun ConfigSourcesScreen(settings: ProfileEditor) {
    val cfg = settings.current()
    val messages = LocalAppContainer.current.messages
    val scope = rememberCoroutineScope()
    var field by remember { mutableStateOf<String?>(null) }
    var editingSource by remember { mutableStateOf<RuleSource?>(null) }
    var address by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var lastResult by remember { mutableStateOf<String?>(null) }

    fun edit(title: String, initial: String, source: RuleSource? = null) {
        field = title
        address = initial
        editingSource = source
    }

    fun runUpdate(task: suspend () -> String) {
        if (busy) return
        scope.launch {
            busy = true
            try {
                lastResult = task()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                lastResult = e.message ?: "同步失败"
            } finally {
                settings.refresh()
                busy = false
            }
        }
    }

    Column(Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState())) {
        SectionHeader("规则来源", trailing = { TextAction("＋") { edit("规则集 URL", "") } })
        GroupCard {
            cfg.ruleSources.forEach { source ->
                SettingsRow(
                    title = source.id,
                    subtitle = source.error.ifBlank { source.url },
                    value = if (!source.enabled) "已停用" else if (source.updatedAt > 0) formatAgo(source.updatedAt) else "待同步",
                    chevron = true,
                    onClick = { edit("规则集 URL", source.url, source) },
                )
            }
            SettingsRow("手动规则 URL", subtitle = cfg.rulesUrl.ifBlank { null },
                value = if (cfg.rulesUpdatedAt > 0) formatAgo(cfg.rulesUpdatedAt) else null, chevron = true,
                onClick = { edit("手动规则 URL", cfg.rulesUrl) })
            SettingsRow("同步规则源", value = if (busy) "处理中" else null, chevron = true, showDivider = false, onClick = {
                if (cfg.ruleSources.any { it.enabled }) {
                    runUpdate {
                        val result = Actions.syncRuleSources(profileName = settings.name)
                        "已更新 ${result.updated} 个来源" + result.errors.firstOrNull()?.let { " · $it" }.orEmpty()
                    }
                } else if (cfg.ruleSources.isNotEmpty()) messages.show("请先启用一个规则来源")
                else if (cfg.rulesUrl.isNotBlank()) runUpdate {
                    "已同步 ${Actions.updateAdsRules(cfg.rulesUrl, settings.name)} 条规则"
                } else messages.show("请先添加规则来源")
            })
        }
        lastResult?.let { result ->
            Text(result, modifier = Modifier.padding(18.dp), color = NamuColors.TextSub, fontSize = 13.sp)
        }
    }

    field?.let { title ->
        val source = editingSource
        val input = address.trim()
        val uri = runCatching { java.net.URI(input) }.getOrNull()
        val valid = (input.isEmpty() && title != "规则集 URL") ||
            (uri?.scheme in setOf("http", "https") && !uri?.host.isNullOrBlank())
        var enabled by remember(title, source?.id) { mutableStateOf(source?.enabled ?: true) }
        NamuDialog(
            title = title,
            confirmText = "保存",
            confirmEnabled = valid,
            onDismiss = { field = null },
            onConfirm = {
                val saved = settings.update { current -> when (title) {
                    "远端配置 URL" -> if (input == current.remoteConfigUrl) current else current.copy(remoteConfigUrl = input, remoteConfigName = "", remoteConfigUpdatedAt = 0)
                    "手动规则 URL" -> if (input == current.rulesUrl) current else current.copy(rulesUrl = input, rulesUpdatedAt = 0)
                    else -> {
                        val next = if (source != null && source.url == input) source.copy(enabled = enabled)
                        else RuleSource(id = source?.id ?: "source_${java.util.UUID.randomUUID().toString().take(12)}", url = input, enabled = enabled)
                        current.copy(ruleSources = if (source == null) current.ruleSources + next else current.ruleSources.map { if (it.id == source.id) next else it })
                    }
                } }
                if (saved) field = null
            },
        ) {
            NamuTextField(address, { address = it }, "https://…", singleLine = true)
            if (title == "规则集 URL") {
                SwitchRow("启用规则集", checked = enabled) { enabled = it }
                if (source != null) {
                    TextAction("删除来源") {
                        if (settings.update { it.copy(ruleSources = it.ruleSources.filterNot { entry -> entry.id == source.id }) }) field = null
                    }
                }
            }
        }
    }
}

@Composable
private fun RuleImportDialog(
    urlMode: Boolean,
    onImport: (List<RuleItem>) -> Unit,
    onDismiss: () -> Unit,
) {
    var url by remember { mutableStateOf("") }
    var text by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var reading by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            reading = true
            error = null
            try {
                text = withContext(Dispatchers.IO) {
                    val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw RuntimeException("无法读取该文件")
                    if (bytes.size > 2 * 1024 * 1024) throw RuntimeException("规则文件超过 2MB")
                    bytes.toString(Charsets.UTF_8).removePrefix("\uFEFF")
                }
            } catch (e: Exception) {
                error = e.message ?: "读取规则文件失败"
            } finally {
                reading = false
            }
        }
    }
    val parsed = remember(text) {
        val rules = mutableListOf<RuleItem>()
        var invalid = 0
        text.lineSequence().forEach { raw ->
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) {
                return@forEach
            }
            val item = RuleLineParser.split(line)?.let { parsedLine ->
                val action = when (val value = parsedLine.action.trim().uppercase()) {
                    "DIRECT" -> "direct"
                    "PROXY" -> "proxy"
                    "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "REJECT-NO-DROP", "BLOCK" -> "block"
                    else -> parsedLine.action.trim().takeIf { value.isNotEmpty() }
                }
                action?.let { RuleItem(parsedLine.type, parsedLine.value, it) }
            }
            if (item == null) invalid++ else rules += item
        }
        rules.distinctBy { Triple(it.type, it.value, it.action) } to invalid
    }

    NamuDialog(
        title = if (urlMode) "URL 导入规则" else "本地导入规则",
        confirmText = "导入",
        loading = reading,
        confirmEnabled = parsed.first.isNotEmpty() && parsed.second == 0,
        onConfirm = { onImport(parsed.first) },
        onDismiss = onDismiss,
    ) {
        if (urlMode) {
            NamuTextField(url, { url = it; error = null }, "https://example.com/rules.list", maxLines = 3)
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Start) {
                MiniTextAction("下载") {
                    scope.launch {
                        reading = true
                        error = null
                        try {
                            text = Actions.fetchText(url.trim(), maxBytes = 2 * 1024 * 1024).removePrefix("\uFEFF")
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
                MiniTextAction("选择规则文件") {
                    error = null
                    filePicker.launch(arrayOf("*/*"))
                }
            }
        }
        if (text.isNotBlank()) {
            Text(
                if (parsed.second == 0) "可导入 ${parsed.first.size} 条规则" else "${parsed.second} 行无法解析",
                fontSize = 13.sp,
                color = if (parsed.second == 0) NamuColors.Green else NamuColors.Red,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            )
        }
        error?.let {
            Text(it, fontSize = 12.sp, color = NamuColors.Red, modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
        }
    }
}

@Composable
private fun RuleRow(
    rule: RuleItem,
    showDivider: Boolean,
    onEdit: () -> Unit,
    onToggle: () -> Unit,
    onDelete: () -> Unit,
    onMove: (Int) -> Unit,
    canMoveUp: Boolean,
    canMoveDown: Boolean,
) {
    var menu by remember { mutableStateOf(false) }
    SettingsRow(
        title = rule.value,
        subtitle = ruleTypeLabel(rule.type) + if (!rule.enabled) " · 已禁用" else "",
        showDivider = showDivider,
        chevron = true,
        onClick = onEdit,
        rightContent = {
            Text(actionLabel(rule.action), fontSize = 13.sp, color = if (rule.enabled) actionColor(rule.action) else NamuColors.TextTertiary)
            Box {
                IconButton(onClick = { menu = true }) { NamuIcon(Icons.Outlined.MoreVert, "规则操作") }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text(if (rule.enabled) "停用" else "启用") }, onClick = { menu = false; onToggle() })
                    DropdownMenuItem(text = { Text("上移") }, enabled = canMoveUp, onClick = { menu = false; onMove(-1) })
                    DropdownMenuItem(text = { Text("下移") }, enabled = canMoveDown, onClick = { menu = false; onMove(1) })
                    DropdownMenuItem(text = { Text("删除") }, onClick = { menu = false; onDelete() })
                }
            }
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
    "APP", "PROCESS-NAME", "APP-NAME" -> "按应用"
    "UID" -> "UID"
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
    url == "system" -> "系统默认"
    url.startsWith("https://") -> "DoH · ${hostOf(url)}"
    url.startsWith("tls://") -> "DoT · ${url.removePrefix("tls://")}"
    url.startsWith("udp://") -> "UDP · ${url.removePrefix("udp://")}"
    url.isBlank() -> "未设置"
    else -> url
}
