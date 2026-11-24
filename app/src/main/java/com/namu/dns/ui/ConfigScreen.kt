package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.namu.dns.Actions
import com.namu.dns.ConfigFileStore
import com.namu.dns.ConfigStore
import com.namu.dns.NamuVpnService
import com.namu.dns.RuleItem
import com.namu.dns.core.ConfigSection
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.config.DirectFilterScope
import com.namu.dns.core.config.ProxyGroupValidation
import com.namu.dns.core.config.RoutingMode
import com.namu.dns.core.repository.SettingsRepository
import kotlinx.coroutines.launch

@Composable
fun ConfigScreen(onOpenDetail: () -> Unit) {
    var showCreate by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
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
        SectionHeader("当前配置")
        GroupCard {
            SettingsRow(
                title = "编辑当前配置",
                value = activeName,
                chevron = true,
                showDivider = false,
                onClick = onOpenDetail,
            )
        }

        SectionHeader(
            text = "本地配置",
            trailing = {
                Row {
                    TextAction("新建") { showCreate = true }
                    TextAction("导入文件") { showImport = true }
                }
            },
        )
        GroupCard {
            if (files.isEmpty()) {
                SettingsRow(title = "暂无配置文件", showDivider = false)
            } else {
                files.forEachIndexed { index, f ->
                    ConfigFileRow(
                        info = f,
                        showDivider = index != files.lastIndex,
                        onActivate = { activate(f.name) },
                        onInfo = { infoFile = f },
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
            .clickable(enabled = !info.active, onClick = onActivate)
            .padding(start = 16.dp, end = 12.dp, top = 10.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(info.name, fontSize = 16.sp, color = NamuColors.TextMain)
            if (info.isDefault) {
                Text("默认配置", fontSize = 12.sp, color = NamuColors.TextSub)
            }
        }
        if (info.active) {
            CheckMark()
            Spacer(Modifier.width(10.dp))
        }
        IconButton(onClick = onInfo, modifier = Modifier.size(48.dp)) {
            Icon(
                Icons.Rounded.Info,
                contentDescription = "管理 ${info.name}",
                tint = NamuColors.TextSub,
                modifier = Modifier.size(20.dp),
            )
        }
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
fun ConfigDetailScreen(onOpenSection: (ConfigSection) -> Unit) {
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    var showGroups by remember { mutableStateOf(false) }
    val groupIssues = remember(cfg.proxyGroups, cfg.nodes, cfg.groupSelections) {
        ProxyGroupValidation.validate(cfg.proxyGroups, cfg.nodes.map { it.name }, cfg.groupSelections)
    }
    val errors = groupIssues.count { it.level == com.namu.dns.core.config.ConfigIssueLevel.ERROR }
    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("当前配置")
        GroupCard {
            SettingsRow(
                title = container.config.activeName(),
                value = "使用中",
                valueColor = NamuColors.Green,
                showDivider = false,
            )
        }
        SectionHeader("配置内容")
        GroupCard {
            SettingsRow(
                title = ConfigSection.General.title,
                value = configDnsLabel(cfg.dnsUpstream),
                chevron = true,
                onClick = { onOpenSection(ConfigSection.General) },
            )
            SettingsRow(
                title = ConfigSection.Rules.title,
                value = "${cfg.rules.size} 条自定义规则",
                chevron = true,
                onClick = { onOpenSection(ConfigSection.Rules) },
            )
            SettingsRow(
                title = ConfigSection.Sources.title,
                value = if (cfg.remoteConfigUrl.isNotBlank()) "已配置远端" else null,
                chevron = true,
                onClick = { onOpenSection(ConfigSection.Sources) },
            )
            SettingsRow(
                title = "策略组",
                value = if (errors > 0) "$errors 个错误" else "${cfg.proxyGroups.size} 个",
                valueColor = if (errors > 0) NamuColors.Red else NamuColors.TextSub,
                chevron = true,
                showDivider = false,
                onClick = { showGroups = true },
            )
        }
        Spacer(Modifier.height(24.dp))
    }

    if (showGroups) {
        ProxyGroupsDialog(
            groups = cfg.proxyGroups,
            nodes = cfg.nodes.map { it.name },
            selections = cfg.groupSelections,
            onDismiss = { showGroups = false },
        )
    }
}

@Composable
fun ConfigSectionScreen(section: ConfigSection, onRestart: () -> Unit) {
    when (section) {
        ConfigSection.General -> ConfigGeneralScreen(onRestart)
        ConfigSection.Rules -> ConfigRulesScreen(onRestart)
        ConfigSection.Sources -> ConfigSourcesScreen(onRestart)
    }
}

@Composable
private fun ConfigGeneralScreen(onRestart: () -> Unit) {
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val runtime = container.runtime
    val routingMode = RoutingMode.fromConfig(cfg.mode)
    val filterScope = DirectFilterScope.fromConfig(cfg.mode, cfg.dnsOnlyFullRoute)
    var showFilterScope by remember { mutableStateOf(false) }
    var showDns by remember { mutableStateOf(false) }
    var showHostMap by remember { mutableStateOf(false) }

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
            SwitchRow(
                title = "备用 DNS",
                subtitle = "${configDnsLabel(cfg.dnsFallback)} · 关闭后禁止回退",
                checked = cfg.allowDnsFallback,
            ) {
                settings.update { current -> current.copy(allowDnsFallback = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "异常应答复核",
                subtitle = "使用备用 DNS 复核异常地址",
                checked = cfg.fallbackFilter,
            ) {
                settings.update { current -> current.copy(fallbackFilter = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "非 CN IP 复核",
                subtitle = "非中国大陆 IP 也交给备用 DNS 复核",
                checked = cfg.fallbackGeoCheck,
            ) {
                settings.update { current -> current.copy(fallbackGeoCheck = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "DNS 查询日志",
                checked = cfg.dnsQueryLog,
            ) {
                settings.update { current -> current.copy(dnsQueryLog = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "关闭 AAAA",
                subtitle = "适用于仅支持 IPv4 出口的节点",
                checked = cfg.blockAaaa,
            ) {
                settings.update { current -> current.copy(blockAaaa = it) }
                if (runtime.current().connected) onRestart()
            }
            SettingsRow(
                title = "Host 映射",
                value = "${cfg.mitm.hostMappings.size} 条",
                chevron = true,
                showDivider = false,
                onClick = { showHostMap = true },
            )
        }

        SectionHeader("连接处理")
        GroupCard {
            SwitchRow(
                title = "Fake-IP",
                subtitle = "仅在接管连接时生效",
                checked = cfg.fakeIp,
            ) {
                settings.update { current -> current.copy(fakeIp = it) }
                if (runtime.current().connected) onRestart()
            }
            SwitchRow(
                title = "TLS / HTTP 域名嗅探",
                subtitle = "从连接中识别域名",
                checked = cfg.sniff,
                showDivider = false,
            ) {
                settings.update { current -> current.copy(sniff = it) }
                if (runtime.current().connected) onRestart()
            }
        }
        if (routingMode == RoutingMode.Direct) {
            SectionHeader("过滤")
            GroupCard {
                SettingsRow(
                    title = "过滤范围",
                    value = filterScope.title,
                    chevron = true,
                    showDivider = false,
                    onClick = { showFilterScope = true },
                )
            }
        }
        Spacer(Modifier.height(24.dp))
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
                // 连接层过滤始终全量接管，保留原有 DNS-only 开关供切回时使用。
                val fullRoute = if (selected == DirectFilterScope.Connections) current.dnsOnlyFullRoute else selected.fullRoute
                if (settings.applyRouting(selected.mode, fullRoute) && runtime.current().connected) onRestart()
            },
            onDismiss = { showFilterScope = false },
        )
    }
    if (showHostMap) {
        HostMapDialog(
            initial = cfg.mitm.hostMappings,
            onDismiss = { showHostMap = false },
            onDone = { map ->
                // Host 是配置态：写回后走一次热重载，新 DNS 引擎不继承旧缓存。
                settings.update { current -> current.copy(mitm = current.mitm.copy(hostMappings = map)) }
                showHostMap = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
}

@Composable
private fun ConfigRulesScreen(onRestart: () -> Unit) {
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val runtime = container.runtime
    val messages = container.messages
    val scope = rememberCoroutineScope()
    var showBlockMode by remember { mutableStateOf(false) }
    var showFinalPolicy by remember { mutableStateOf(false) }
    var showAddRule by remember { mutableStateOf(false) }
    var ruleQuery by remember { mutableStateOf("") }
    var showCustomAds by remember { mutableStateOf(false) }
    var updatingIp by remember { mutableStateOf(false) }
    var showTest by remember { mutableStateOf(false) }
    var showReset by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        Spacer(Modifier.height(12.dp))
        GroupCard {
            SettingsRow(title = "测试规则", chevron = true, showDivider = false, onClick = { showTest = true })
        }

        SectionHeader("拦截")
        GroupCard {
            SwitchRow(
                title = "订阅广告规则",
                subtitle = "仅控制订阅规则文件，自定义规则的拦截不受影响",
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
            SettingsRow(
                title = "拦截 TTL",
                subtitle = "拦截结果的缓存时长",
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
            SettingsRow(
                title = "本地拦截域名",
                showDivider = false,
                value = "${cfg.customAds.size} 条",
                chevron = true,
                onClick = { showCustomAds = true },
            )
        }

        SectionHeader("分流")
        GroupCard {
            SwitchRow(
                title = "国内域名 / IP 直连",
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
                title = "国内 IP 库",
                showDivider = false,
                value = if (updatingIp) "更新中…" else "更新",
                onClick = {
                    if (!updatingIp) {
                        scope.launch {
                            updatingIp = true
                            try {
                                val n = Actions.updateCnIp("https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt")
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

        SectionHeader("自定义规则", trailing = { TextAction("添加") { showAddRule = true } })
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
                    SettingsRow(title = "没有匹配的规则", showDivider = false)
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

        SectionHeader("重置")
        GroupCard {
            SettingsRow(
                title = "重置路由设置",
                chevron = true,
                showDivider = false,
                onClick = { showReset = true },
            )
        }
        Spacer(Modifier.height(24.dp))
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
    if (showCustomAds) {
        CustomAdsDialog(
            onDismiss = { showCustomAds = false },
            onDone = {
                showCustomAds = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
    if (showTest) {
        RuleTestDialog(onDismiss = { showTest = false })
    }
    if (showReset) {
        NamuDialog(
            title = "重置路由设置",
            message = "当前配置将切到「仅过滤」，最终策略设为直连。",
            confirmText = "重置",
            confirmColor = NamuColors.Red,
            onDismiss = { showReset = false },
            onConfirm = {
                settings.update { it.copy(mode = "dns_only", finalPolicy = "direct") }
                ConfigStore.rebuildModules(container.context, settings.current())
                showReset = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
}

@Composable
private fun ConfigSourcesScreen(onRestart: () -> Unit) {
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val runtime = container.runtime
    var showRemote by remember { mutableStateOf(false) }
    var showRuleSources by remember { mutableStateOf(false) }
    var showRulesUpdate by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("远端配置")
        GroupCard {
            SettingsRow(
                title = "远端配置",
                subtitle = if (cfg.remoteConfigUrl.isBlank()) {
                    null
                } else {
                    "${cfg.remoteConfigName.ifBlank { "已配置" }} · ${formatAgo(cfg.remoteConfigUpdatedAt)}"
                },
                value = if (cfg.remoteConfigUrl.isBlank()) "未配置" else "已同步",
                valueColor = if (cfg.remoteConfigUrl.isBlank()) NamuColors.Orange else NamuColors.Green,
                chevron = true,
                onClick = { showRemote = true },
            )
            SwitchRow(
                title = "自动更新",
                subtitle = if (cfg.remoteConfigUrl.isNotBlank()) "按远端配置的间隔检查" else "手动规则 URL 每 12 小时更新",
                checked = cfg.autoUpdateRules,
                showDivider = false,
            ) {
                settings.update { current -> current.copy(autoUpdateRules = it) }
            }
        }

        SectionHeader("规则来源")
        GroupCard {
            SettingsRow(
                title = "规则集",
                showDivider = cfg.ruleSources.isEmpty(),
                subtitle = if (cfg.ruleSources.isEmpty()) {
                    null
                } else {
                    "${cfg.ruleSources.sumOf { it.lines }} 行"
                },
                value = if (cfg.ruleSources.isEmpty()) "无" else "${cfg.ruleSources.size} 个",
                chevron = true,
                onClick = { showRuleSources = true },
            )
            if (cfg.ruleSources.isEmpty()) {
                SettingsRow(
                    title = "手动规则 URL",
                    value = if (cfg.rulesUrl.isBlank()) "未设置" else "已设置",
                    chevron = true,
                    showDivider = false,
                    onClick = { showRulesUpdate = true },
                )
            }
        }

        Spacer(Modifier.height(24.dp))
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
        subtitle = ruleTypeLabel(rule.type) + if (!rule.enabled) " · 已禁用" else "",
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
