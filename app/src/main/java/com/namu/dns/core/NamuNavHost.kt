package com.namu.dns.core

import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavDestination
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.toRoute
import com.namu.dns.UiPrefs
import com.namu.dns.ui.OnboardingScreen
import com.namu.dns.ui.AdvancedSettingsScreen
import com.namu.dns.ui.ConfigDetailScreen
import com.namu.dns.ui.ConfigScreen
import com.namu.dns.ui.ConfigSectionScreen
import com.namu.dns.ui.DataAnalyticsScreen
import com.namu.dns.ui.DataScreen
import com.namu.dns.ui.DetailChrome
import com.namu.dns.ui.DiagnosticsScreen
import com.namu.dns.ui.DnsLogsScreen
import com.namu.dns.ui.FirstRunVpnGuide
import com.namu.dns.ui.HomeScreen
import com.namu.dns.ui.LogsScreen
import com.namu.dns.ui.MitmScreen
import com.namu.dns.ui.ModuleDetailScreen
import com.namu.dns.ui.ModulesScreen
import com.namu.dns.ui.NamuColors
import com.namu.dns.ui.NamuTokens
import com.namu.dns.ui.NodesScreen
import com.namu.dns.ui.ScanScreen
import com.namu.dns.ui.SettingsScreen
import com.namu.dns.ui.QuickEditScreen
import com.namu.dns.ui.ShadowTopBar

internal val LocalDockClearance = compositionLocalOf { 0.dp }

/** 外壳入口：Scaffold + NavHost；顶栏/底栏跟随当前类型安全路由联动。 */
@Composable
fun NamuAppShell(
    onToggle: () -> Unit,
    onRestart: () -> Unit,
    openNodes: Boolean = false,
    onNodesConsumed: () -> Unit = {},
) {
    val vm: AppViewModel = viewModel()
    CompositionLocalProvider(LocalAppContainer provides vm.container) {
        // B4 首启引导：未完成时先显示三页引导，完成/跳过后进入主界面。
        if (!UiPrefs.onboardingDone) {
            OnboardingScreen(onFinish = { UiPrefs.setOnboardingDone(true) })
            return@CompositionLocalProvider
        }
        val container = vm.container
        val runtimeState by container.runtime.state.collectAsStateWithLifecycle()
        // U4：首次 VPN 全屏引导只出现一次；授权/稍后都记为已读，之后用首页空态入口再次启动。
        if (!UiPrefs.vpnGuideDone && !runtimeState.connected) {
            FirstRunVpnGuide(
                onStart = {
                    UiPrefs.setVpnGuideDone(true)
                    onToggle()
                },
                onLater = { UiPrefs.setVpnGuideDone(true) },
            )
            return@CompositionLocalProvider
        }
        val navController = rememberNavController()
        // B1 通知「切换节点」入口：带 open_nodes extra 打开时直达节点页。
        LaunchedEffect(openNodes) {
            if (openNodes) {
                navController.navigate(NodesRoute)
                onNodesConsumed()
            }
        }
        val snackbar = remember { SnackbarHostState() }
        val entry by navController.currentBackStackEntryAsState()
        val destination = entry?.destination
        val tabs = MainTab.entries
        val currentTab = tabs.firstOrNull { destination.matches(it.route::class) }

        // 规则更新/自动测速已交给 WorkManager（RuleUpdateWorker / NodeTestWorker），
        // 不再绑在 Activity 的 LaunchedEffect 上，划掉界面也不会停。
        LaunchedEffect(Unit) {
            container.messages.messages.collect { snackbar.showSnackbar(it) }
        }

        Scaffold(
            containerColor = NamuColors.Bg,
            snackbarHost = {
                SnackbarHost(snackbar) { data ->
                    Box(
                        Modifier.fillMaxWidth().padding(horizontal = 28.dp, vertical = 8.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Surface(shape = RoundedCornerShape(NamuTokens.RadiusCard), color = Color(0xEE1C1C1E)) {
                            Text(
                                data.visuals.message,
                                color = Color.White,
                                fontSize = 13.sp,
                                lineHeight = 17.sp,
                                modifier = Modifier.padding(horizontal = 18.dp, vertical = 11.dp),
                            )
                        }
                    }
                }
            },
            bottomBar = {
                if (currentTab != null) {
                    GlassDock(
                        tabs = tabs,
                        selected = currentTab,
                        onSelect = navController::openMainTab,
                    )
                }
            },
        ) { padding ->
            val direction = LocalLayoutDirection.current
            val hasDock = currentTab != null
            Box(
                Modifier.fillMaxSize().padding(
                    start = padding.calculateStartPadding(direction),
                    end = padding.calculateEndPadding(direction),
                    top = padding.calculateTopPadding(),
                    bottom = if (hasDock) 0.dp else padding.calculateBottomPadding(),
                ).consumeWindowInsets(PaddingValues(top = padding.calculateTopPadding())),
                contentAlignment = Alignment.TopCenter,
            ) {
                CompositionLocalProvider(LocalDockClearance provides
                    (if (hasDock) padding.calculateBottomPadding() else 0.dp)) {
                    NamuNavHost(
                        navController = navController,
                        onToggle = onToggle,
                        onRestart = onRestart,
                        modifier = Modifier.fillMaxHeight().widthIn(max = 640.dp).fillMaxWidth(),
                    )
                }
            }
        }
    }
}

/** 所有页面只在这里注册；屏幕内部不感知 NavController，回调由外壳映射成路由跳转。 */
@Composable
fun NamuNavHost(
    navController: NavHostController,
    onToggle: () -> Unit,
    onRestart: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val direction = if (LocalLayoutDirection.current == androidx.compose.ui.unit.LayoutDirection.Ltr) 1 else -1
    NavHost(
        navController = navController,
        startDestination = HomeRoute,
        modifier = modifier.clipToBounds(),
        enterTransition = {
            if (targetState.destination.isMainTab()) fadeIn(tween(160))
            else slideInHorizontally(tween(300)) { direction * it }
        },
        exitTransition = {
            if (targetState.destination.isMainTab()) fadeOut(tween(140))
            else slideOutHorizontally(tween(300)) { -direction * it / 4 }
        },
        popEnterTransition = {
            if (initialState.destination.isMainTab()) fadeIn(tween(160))
            else slideInHorizontally(tween(280)) { -direction * it / 4 }
        },
        popExitTransition = {
            if (initialState.destination.isMainTab()) fadeOut(tween(140))
            else slideOutHorizontally(tween(280)) { direction * it }
        },
    ) {
        composable<HomeRoute> {
            HomeScreen(
                onToggle = onToggle,
                onOpenNodes = { navController.navigate(NodesRoute) },
                onRestart = onRestart,
            )
        }
        composable<ConfigRoute> {
            ConfigScreen(
                onOpenPanel = { navController.navigate(ConfigDetailRoute(it)) },
                onOpenModules = { navController.navigate(ModulesRoute) },
            )
        }
        composable<DataRoute> {
            DataScreen(
                onOpenAnalytics = { navController.navigate(DataAnalyticsRoute(it)) },
                onOpenDiagnostics = { navController.navigate(DiagnosticsRoute) },
                onOpenMitmDetails = { navController.navigate(MitmRuntimeRoute) },
            )
        }
        detail<DataAnalyticsRoute>(navController) { entry ->
            DataAnalyticsScreen(
                section = entry.toRoute<DataAnalyticsRoute>().section,
                onRestart = onRestart,
                onStartVpn = onToggle,
            )
        }
        composable<SettingsRoute> {
            SettingsScreen(
                onOpenMitm = { navController.navigate(MitmRoute) },
                onOpenAdvanced = { navController.navigate(AdvancedSettingsRoute) },
            )
        }
        detail<DiagnosticsRoute>(navController) {
            DiagnosticsScreen(
                onOpenRuntimeLogs = { navController.navigate(LogsRoute(LogKind.Runtime)) },
                onOpenDnsLogs = { navController.navigate(LogsRoute(LogKind.Dns)) },
            )
        }
        detail<AdvancedSettingsRoute>(navController) {
            AdvancedSettingsScreen(onRestart = onRestart)
        }
        detail<NodesRoute>(navController) {
            NodesScreen(
                onRestart = onRestart,
                onBack = { navController.popBackStack() },
            )
        }
        detail<LogsRoute>(navController) { logsEntry ->
            when (logsEntry.toRoute<LogsRoute>().kind) {
                LogKind.Runtime -> LogsScreen()
                LogKind.Dns -> DnsLogsScreen()
            }
        }
        detail<ConfigDetailRoute>(navController) { entry ->
            val name = entry.toRoute<ConfigDetailRoute>().name
            ConfigDetailScreen(
                name = name,
                onOpenSection = { navController.navigate(ConfigSectionRoute(it, name)) },
                onOpenRaw = { navController.navigate(QuickEditRoute(name)) },
                onDeleted = { navController.popBackStack() },
            )
        }
        composable<QuickEditRoute> { entry ->
            DetailChrome {
                QuickEditScreen(name = entry.toRoute<QuickEditRoute>().name, onBack = { navController.popBackStack() })
            }
        }
        composable<ConfigSectionRoute> { entry ->
            val route = entry.toRoute<ConfigSectionRoute>()
            val content: @Composable () -> Unit = {
                ConfigSectionScreen(
                    route.section,
                    route.name,
                    onOpenCertificate = { navController.navigate(MitmRoute) },
                    onBack = { navController.popBackStack() },
                )
            }
            if (route.section == ConfigSection.General) {
                DetailChrome(content)
            } else {
                DetailDestination(entry, navController, content)
            }
        }
        composable<ModulesRoute> {
            DetailChrome {
                ModulesScreen(
                    onRestart = onRestart,
                    onOpenDetail = { navController.navigate(ModuleDetailRoute(it)) },
                    onBack = { navController.popBackStack() },
                )
            }
        }
        detail<ModuleDetailRoute>(navController) { detailEntry ->
            ModuleDetailScreen(
                moduleId = detailEntry.toRoute<ModuleDetailRoute>().moduleId,
                onBack = { navController.popBackStack() },
            )
        }
        detail<MitmRoute>(navController) { MitmScreen(certificateOnly = true) }
        detail<MitmRuntimeRoute>(navController) { MitmScreen(certificateOnly = false) }
        detail<ScanRoute>(navController) {
            ScanScreen(onDone = { navController.popBackStack() })
        }
    }
}

private fun NavDestination.isMainTab(): Boolean = MainTab.entries.any { matches(it.route::class) }

private inline fun <reified T : Any> NavGraphBuilder.detail(
    navController: NavHostController,
    crossinline content: @Composable (NavBackStackEntry) -> Unit,
) {
    composable<T> { entry ->
        DetailDestination(entry, navController) { content(entry) }
    }
}

@Composable
private fun DetailDestination(
    entry: NavBackStackEntry,
    navController: NavHostController,
    content: @Composable () -> Unit,
) {
    DetailChrome {
        Column(Modifier.fillMaxSize()) {
            ShadowTopBar(
                title = titleFor(entry.destination, entry),
                left = {
                    NavIcon(Icons.AutoMirrored.Rounded.ArrowBack, "返回") {
                        navController.popBackStack()
                    }
                },
                right = {
                    if (entry.destination.matches(NodesRoute::class)) {
                        NavIcon(Icons.Rounded.QrCodeScanner, "扫码导入节点") {
                            navController.navigate(ScanRoute)
                        }
                    }
                },
            )
            Box(Modifier.weight(1f).fillMaxWidth()) { content() }
        }
    }
}

private fun NavHostController.openMainTab(tab: MainTab) {
    navigate(tab.route) {
        popUpTo(graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}

private fun titleFor(destination: NavDestination?, entry: androidx.navigation.NavBackStackEntry?): String = when {
    destination.matches(HomeRoute::class) -> "南门 DNS"
    destination.matches(ConfigRoute::class) -> "配置"
    destination.matches(DataRoute::class) -> "数据"
    destination.matches(DataAnalyticsRoute::class) -> entry?.toRoute<DataAnalyticsRoute>()?.section?.title ?: "数据详情"
    destination.matches(ModulesRoute::class) -> "模块"
    destination.matches(ModuleDetailRoute::class) -> "模块详情"
    destination.matches(SettingsRoute::class) -> "设置"
    destination.matches(AdvancedSettingsRoute::class) -> "高级设置"
    destination.matches(DiagnosticsRoute::class) -> "日志与诊断"
    destination.matches(NodesRoute::class) -> "节点与订阅"
    destination.matches(LogsRoute::class) ->
        if (entry?.toRoute<LogsRoute>()?.kind == LogKind.Dns) "DNS 查询" else "运行日志"
    destination.matches(ConfigDetailRoute::class) -> entry?.toRoute<ConfigDetailRoute>()?.name ?: "配置"
    destination.matches(QuickEditRoute::class) -> "快速编辑"
    destination.matches(ConfigSectionRoute::class) -> entry?.toRoute<ConfigSectionRoute>()
        ?.let { "${it.section.title} · ${it.name}" } ?: "配置"
    destination.matches(MitmRoute::class) -> "MITM 管理"
    destination.matches(MitmRuntimeRoute::class) -> "MITM 运行详情"
    destination.matches(ScanRoute::class) -> "扫码导入"
    else -> "南门 DNS"
}

@Composable
private fun NavIcon(
    icon: ImageVector,
    desc: String,
    onClick: () -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    Box(
        Modifier
            .size(44.dp)
            .clip(CircleShape)
            .clickable(interactionSource = interaction, indication = null) { onClick() },
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            icon,
            contentDescription = desc,
            tint = NamuColors.TextMain,
            modifier = Modifier.size(23.dp),
        )
    }
}
