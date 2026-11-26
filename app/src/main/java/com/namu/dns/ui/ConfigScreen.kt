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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.IconButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.MoreVert
import com.namu.dns.AppConfig
import com.namu.dns.MitmManager
import com.namu.dns.core.LocalDockClearance
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.namu.dns.Actions
import com.namu.dns.GlobalRuleStore
import com.namu.dns.normalizeAdsDomain
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
fun ConfigScreen(onOpenPanel: (String) -> Unit, onOpenModules: () -> Unit) {
    var switching by remember { mutableStateOf(false) }
    var showCreate by remember { mutableStateOf(false) }
    var showImportLocal by remember { mutableStateOf(false) }
    var showImportUrl by remember { mutableStateOf(false) }
    var addMenu by remember { mutableStateOf(false) }
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
        MainPageTopBar("配置") {
            Box {
                Box(
                    Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(NamuColors.Blue.copy(alpha = 0.12f))
                        .clickable(onClickLabel = "新建或导入配置") { addMenu = true },
                    contentAlignment = Alignment.Center,
                ) {
                    NamuIcon(Icons.Outlined.Add, tint = NamuColors.Blue, size = 20.dp)
                }
                FloatingMenu(
                    expanded = addMenu,
                    onDismissRequest = { addMenu = false },
                    modifier = Modifier.width(148.dp),
                ) {
                    DropdownMenuItem(
                        text = { Text("新建配置", fontSize = 14.sp) },
                        modifier = Modifier.height(44.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp),
                        onClick = { addMenu = false; showCreate = true },
                    )
                    DropdownMenuItem(
                        text = { Text("本地导入", fontSize = 14.sp) },
                        modifier = Modifier.height(44.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp),
                        onClick = { addMenu = false; showImportLocal = true },
                    )
                    DropdownMenuItem(
                        text = { Text("URL 导入", fontSize = 14.sp) },
                        modifier = Modifier.height(44.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp),
                        onClick = { addMenu = false; showImportUrl = true },
                    )
                }
            }
        }
        SectionHeader("配置方案")
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
        Spacer(Modifier.height(20.dp))
        GroupCard {
            SettingsRow(
                title = "模块",
                value = "${cfg.moduleSources.count { it.enabled }} 个已启用",
                chevron = true,
                showDivider = false,
                onClick = onOpenModules,
            )
        }
        Spacer(Modifier.height(LocalDockClearance.current + 24.dp))
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
        // 蓝勾槽位固定宽度并前置：未激活的行也保留占位，名称与铅笔在所有行保持同一位置。
        Box(Modifier.width(28.dp), contentAlignment = Alignment.Center) {
            if (info.active) {
                Box(
                    Modifier.size(20.dp).clip(CircleShape).background(NamuColors.Blue),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Filled.Check, contentDescription = "当前方案", tint = Color.White, modifier = Modifier.size(13.dp))
                }
            }
        }
        Column(Modifier.weight(1f).clickable(onClick = onActivate).padding(vertical = 12.dp)) {
            Text(info.name, fontSize = 16.sp, color = NamuColors.TextMain)
            if (issue != null) {
                Text("! $issue", fontSize = 12.sp, color = NamuColors.Red)
            } else if (info.isDefault) {
                Text("默认配置", fontSize = 12.sp, color = NamuColors.TextSub)
            }
        }
        IconButton(onClick = onInfo) { NamuIcon(Icons.Outlined.Edit, "编辑 ${info.name}") }
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
    var showResetDefault by remember { mutableStateOf(false) }
    var updating by remember { mutableStateOf(false) }
    DetailList {
        SectionHeader("配置")
        GroupCard {
            SettingsRow("DNS", value = configDnsLabel(cfg.dnsUpstream), chevron = true, onClick = { onOpenSection(ConfigSection.General) })
            SettingsRow("Hosts", value = "${cfg.mitm.hostMappings.size} 条", chevron = true, onClick = { onOpenSection(ConfigSection.Hosts) })
            SettingsRow("代理分组", value = "${cfg.proxyGroups.size} 个", chevron = true, onClick = { showGroups = true })
            SettingsRow("连接与路由", chevron = true, showDivider = false, onClick = { onOpenSection(ConfigSection.Advanced) })
        }
        Spacer(Modifier.height(16.dp))
        GroupCard {
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
            SettingsRow("恢复默认配置", valueColor = NamuColors.Orange, onClick = { showResetDefault = true })
            SettingsRow("删除配置", valueColor = NamuColors.Red, showDivider = false, onClick = { confirmDelete = true })
        }
        Spacer(Modifier.height(24.dp))
    }
    if (showResetDefault) {
        NamuDialog(
            title = "恢复默认配置",
            message = "将「$name」恢复为出厂默认：解析、路由、拦截与 MITM 参数重置，节点、策略组与订阅清空；模块与全局规则不受影响。上一版自动备份在磁盘。",
            confirmText = "恢复",
            confirmColor = NamuColors.Orange,
            onConfirm = {
                showResetDefault = false
                if (editor.update { AppConfig(dnsUpstream = "system", dnsFallback = "system") }) {
                    container.messages.show("已恢复默认配置")
                } else {
                    container.messages.show("恢复失败，已保留原配置")
                }
            },
            onDismiss = { showResetDefault = false },
        )
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
fun ConfigSectionScreen(
    section: ConfigSection,
    name: String,
    onOpenCertificate: () -> Unit,
    onBack: () -> Unit,
) {
    val editor = rememberProfileEditor(name) ?: return
    when (section) {
        ConfigSection.General -> ConfigDnsScreen(editor, onBack)
        ConfigSection.Rules -> LocalRulesDetailScreen()
        ConfigSection.Sources -> ConfigSourcesScreen(editor)
        ConfigSection.Hosts -> ConfigHostsScreen(editor)
        ConfigSection.UrlRewrite -> ConfigRewriteScreen(editor, "URL 重写")
        ConfigSection.HeaderRewrite -> ConfigRewriteScreen(editor, "头部重写")
        ConfigSection.BodyRewrite -> ConfigRewriteScreen(editor, "正文重写")
        ConfigSection.Https -> HttpsScopeSection(onOpenCertificate)
        ConfigSection.Advanced -> ConfigAdvancedScreen(editor)
    }
}

@Composable
private fun ConfigAdvancedScreen(settings: ProfileEditor) {
    val cfg = settings.current()
    var showFilterScope by remember { mutableStateOf(false) }
    var showSkip by remember { mutableStateOf(false) }
    val filterScope = DirectFilterScope.fromConfig(cfg.mode, cfg.dnsOnlyFullRoute)
    DetailList {
        SectionHeader("连接与路由")
        GroupCard {
            SwitchRow("IPv6", subtitle = "管理 VPN 的 IPv6 地址和路由", checked = cfg.ipv6 ?: true) { enabled ->
                settings.update { it.copy(ipv6 = enabled) }
            }
            SwitchRow("IPv6 优先", subtitle = "直连时优先尝试 IPv6", checked = cfg.preferIpv6 ?: false) { enabled ->
                settings.update { it.copy(preferIpv6 = enabled) }
            }
            SwitchRow("TLS / HTTP 域名嗅探", checked = cfg.sniff) { enabled ->
                settings.update { it.copy(sniff = enabled) }
            }
            SettingsRow(
                "跳过代理",
                value = "${cfg.skipProxyHosts.size} 项",
                chevron = true,
                showDivider = false,
                onClick = { showSkip = true },
            )
        }
        SectionHeader("过滤")
        GroupCard {
            SettingsRow("过滤范围", value = filterScope.title, chevron = true, showDivider = false, onClick = { showFilterScope = true })
        }
        Spacer(Modifier.height(24.dp))
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
internal fun LocalRulesDetailScreen() {
    val container = LocalAppContainer.current
    val scope = rememberCoroutineScope()
    val rules = GlobalRuleStore.state.localRules
    val groups = container.settings.current().proxyGroups.map { it.name }
    var showAddRule by remember { mutableStateOf(false) }
    var editRuleIndex by remember { mutableStateOf<Int?>(null) }
    var ruleQuery by remember { mutableStateOf("") }
    var manageMode by remember { mutableStateOf(false) }
    var manageMenu by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf(setOf<Int>()) }
    var showAds by remember { mutableStateOf(false) }

    DetailList {
        SectionHeader("本地规则")
        GroupCard {
            SwitchRow("启用本地规则", subtitle = "全局共享；置顶只影响显示，匹配顺序保持迁移前", checked = GlobalRuleStore.state.localRulesEnabled) { on ->
                scope.launch { Actions.setLocalRulesEnabled(on) }
            }
            SettingsRow(
                "本地拦截域名",
                subtitle = "每行一个域名，写入 DNS 过滤",
                value = "${GlobalRuleStore.state.localAds.size} 条",
                chevron = true,
                showDivider = false,
                onClick = { showAds = true },
            )
        }
        SectionHeader(
            "分流规则",
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (manageMode) {
                        TextAction("完成") { manageMode = false; selected = emptySet() }
                    } else {
                        TextAction("＋") { showAddRule = true }
                        Box {
                            IconButton(onClick = { manageMenu = true }) { NamuIcon(Icons.Outlined.MoreVert, "管理规则") }
                            FloatingMenu(expanded = manageMenu, onDismissRequest = { manageMenu = false }) {
                                DropdownMenuItem(text = { Text("选择规则") }, onClick = {
                                    manageMenu = false; manageMode = true; selected = emptySet()
                                })
                                DropdownMenuItem(text = { Text("全选") }, onClick = {
                                    manageMenu = false; manageMode = true; selected = rules.indices.toSet()
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
            val visibleRules = rules.withIndex().filter { (_, rule) ->
                ruleQuery.isBlank() || rule.type.contains(ruleQuery, true) ||
                    rule.value.contains(ruleQuery, true) || rule.action.contains(ruleQuery, true)
            }
            if (visibleRules.isEmpty()) {
                SettingsRow(title = if (rules.isEmpty()) "暂无规则" else "没有匹配的规则", showDivider = false)
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
                            val sel = selected
                            scope.launch { Actions.updateLocalRules { list -> list.filterIndexed { i, _ -> i !in sel } } }
                            selected = emptySet()
                            manageMode = false
                        }
                    },
                )
            }
        }
        Spacer(Modifier.height(24.dp))
    }

    if (showAds) {
        StringListDialog(
            title = "本地拦截域名",
            message = "每行一个域名；与远端规则集相互独立。",
            initial = GlobalRuleStore.state.localAds,
            onDismiss = { showAds = false },
            onConfirm = { list ->
                scope.launch { Actions.updateLocalAds { list.mapNotNull { normalizeAdsDomain(it) }.distinct() } }
                showAds = false
            },
        )
    }

    if (showAddRule || editRuleIndex != null) {
        val targetIndex = editRuleIndex
        AddRuleDialog(
            groups = groups,
            initial = targetIndex?.let(rules::getOrNull),
            onDismiss = { showAddRule = false; editRuleIndex = null },
            onAdd = { item ->
                scope.launch {
                    if ((item.type == "RULE-SET" || item.type == "DOMAIN-SET") && item.value.startsWith("http")) {
                        try {
                            val content = Actions.fetchText(item.value, maxBytes = 8 * 1024 * 1024)
                            ConfigStore.ruleSetFile(container.context, item.value).writeText(content)
                            container.messages.show("规则集已下载并保存")
                        } catch (e: Exception) {
                            container.messages.show("规则集下载失败：${e.message ?: "网络错误"}")
                            return@launch
                        }
                    }
                    Actions.updateLocalRules { list ->
                        if (targetIndex == null) list + item
                        else list.mapIndexed { index, old -> if (index == targetIndex) item else old }
                    }
                    showAddRule = false
                    editRuleIndex = null
                }
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
        Modifier.fillMaxWidth().heightIn(min = 54.dp).clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(
                rule.value,
                color = if (rule.enabled) NamuColors.TextMain else NamuColors.TextSub,
                style = NamuTokens.Type.Body.copy(lineHeight = 20.sp),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                rule.type + (if (rule.extendedMatch) " · 扩展匹配" else "") + (if (rule.preMatch) " · 预匹配" else ""),
                color = NamuColors.TextSub,
                fontSize = 12.sp,
            )
        }
        if (managing) Text(if (selected) "✓" else "○", color = if (selected) NamuColors.Blue else NamuColors.TextSub, fontSize = 20.sp)
        else {
            Text(
                rule.action.uppercase(),
                modifier = Modifier.widthIn(max = 100.dp).padding(end = 8.dp),
                style = NamuTokens.Type.Caption,
                color = NamuColors.TextSub,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Chevron()
        }
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

    DetailList {
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
        minHeight = 52.dp,
        showDivider = showDivider,
        chevron = true,
        onClick = onEdit,
        rightContent = {
            Text(actionLabel(rule.action), fontSize = 13.sp, color = if (rule.enabled) actionColor(rule.action) else NamuColors.TextTertiary)
            Box {
                IconButton(onClick = { menu = true }) { NamuIcon(Icons.Outlined.MoreVert, "规则操作") }
                FloatingMenu(expanded = menu, onDismissRequest = { menu = false }) {
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
    "AND" -> "逻辑与"
    "OR" -> "逻辑或"
    "NOT" -> "逻辑非"
    "SCRIPT" -> "脚本判定"
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
