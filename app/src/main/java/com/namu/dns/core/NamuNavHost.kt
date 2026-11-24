package com.namu.dns.core

import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
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
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.toRoute
import com.namu.dns.UiPrefs
import com.namu.dns.ui.OnboardingScreen
import com.namu.dns.ui.ConfigDetailScreen
import com.namu.dns.ui.ConfigScreen
import com.namu.dns.ui.DataScreen
import com.namu.dns.ui.DnsLogsScreen
import com.namu.dns.ui.FirstRunVpnGuide
import com.namu.dns.ui.HomeScreen
import com.namu.dns.ui.LogsScreen
import com.namu.dns.ui.MitmScreen
import com.namu.dns.ui.ModulesScreen
import com.namu.dns.ui.NamuColors
import com.namu.dns.ui.NodesScreen
import com.namu.dns.ui.ScanScreen
import com.namu.dns.ui.SettingsScreen
import com.namu.dns.ui.PrimaryTopBar
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
        val isDetail = destination != null && currentTab == null

        // 规则更新/自动测速已交给 WorkManager（RuleUpdateWorker / NodeTestWorker），
        // 不再绑在 Activity 的 LaunchedEffect 上，划掉界面也不会停。
        LaunchedEffect(Unit) {
            container.messages.messages.collect { snackbar.showSnackbar(it) }
        }

        val pageLayer = rememberGraphicsLayer()
        var pageOrigin by remember { mutableStateOf(Offset.Zero) }
        Scaffold(
            containerColor = NamuColors.Bg,
            topBar = {
                if (currentTab != null) {
                    PrimaryTopBar(titleFor(destination, entry))
                } else {
                    ShadowTopBar(
                        title = titleFor(destination, entry),
                        left = {
                            if (isDetail) {
                                NavIcon(Icons.AutoMirrored.Rounded.ArrowBack, "返回") {
                                    navController.popBackStack()
                                }
                            }
                        },
                        right = {
                            if (destination.matches(NodesRoute::class)) {
                                NavIcon(Icons.Rounded.QrCodeScanner, "扫码导入节点") {
                                    navController.navigate(ScanRoute)
                                }
                            }
                        },
                    )
                }
            },
            snackbarHost = {
                SnackbarHost(snackbar) { data ->
                    Box(
                        Modifier.fillMaxWidth().padding(horizontal = 28.dp, vertical = 8.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Surface(shape = RoundedCornerShape(18.dp), color = Color(0xEE1C1C1E)) {
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
                        pageLayer = pageLayer,
                        pageOrigin = { pageOrigin },
                        onSelect = { tab ->
                            navController.navigate(tab.route) {
                                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                    )
                }
            },
        ) { padding ->
            val direction = LocalLayoutDirection.current
            val hasDock = currentTab != null
            val capture = if (hasDock) Modifier
                .onGloballyPositioned { pageOrigin = it.positionInRoot() }
                .drawWithContent {
                    pageLayer.record { this@drawWithContent.drawContent() }
                    drawLayer(pageLayer)
                } else Modifier
            Box(
                Modifier.fillMaxSize().padding(
                    start = padding.calculateStartPadding(direction),
                    end = padding.calculateEndPadding(direction),
                    top = padding.calculateTopPadding(),
                    bottom = if (hasDock) 0.dp else padding.calculateBottomPadding(),
                ),
                contentAlignment = Alignment.TopCenter,
            ) {
                CompositionLocalProvider(LocalDockClearance provides
                    (if (hasDock) padding.calculateBottomPadding() else 0.dp)) {
                    NamuNavHost(
                        navController = navController,
                        onToggle = onToggle,
                        onRestart = onRestart,
                        modifier = Modifier.fillMaxHeight().widthIn(max = 640.dp).fillMaxWidth().then(capture),
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
    NavHost(
        navController = navController,
        startDestination = HomeRoute,
        modifier = modifier,
        enterTransition = {
            fadeIn(tween(180)) + slideInVertically(tween(220)) { it / 48 }
        },
        exitTransition = { fadeOut(tween(120)) },
        popEnterTransition = { fadeIn(tween(170)) },
        popExitTransition = {
            fadeOut(tween(140)) + slideOutVertically(tween(180)) { it / 60 }
        },
    ) {
        composable<HomeRoute> {
            HomeScreen(
                onToggle = onToggle,
                onOpenNodes = { navController.navigate(NodesRoute) },
                onRestart = onRestart,
                onOpenData = { navController.navigate(DataRoute) },
                onOpenConfig = { navController.navigate(ConfigDetailRoute) },
                onOpenModules = {
                    navController.navigate(ModulesRoute) {
                        popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                        launchSingleTop = true
                        restoreState = true
                    }
                },
                onOpenMitm = { navController.navigate(MitmRoute) },
            )
        }
        composable<ConfigRoute> {
            StrategyScreen(
                onOpenDetail = {
                    if (!navController.popBackStack<ConfigDetailRoute>(inclusive = false)) {
                        navController.navigate(ConfigDetailRoute)
                    }
                },
                onRestart = onRestart,
            )
        }
        composable<DataRoute> {
            DataScreen(
                onOpenLogs = { navController.navigate(LogsRoute(LogKind.Runtime)) },
                onOpenDnsLogs = { navController.navigate(LogsRoute(LogKind.Dns)) },
                onRestart = onRestart,
                onStartVpn = onToggle,
            )
        }
        composable<SettingsRoute> {
            SettingsScreen(
                onRestart = onRestart,
                onOpenLogs = { navController.navigate(LogsRoute(LogKind.Runtime)) },
                onOpenMitm = { navController.navigate(MitmRoute) },
            )
        }
        composable<NodesRoute> {
            NodesScreen(
                onRestart = onRestart,
                onBack = { navController.popBackStack() },
            )
        }
        composable<LogsRoute> { logsEntry ->
            when (logsEntry.toRoute<LogsRoute>().kind) {
                LogKind.Runtime -> LogsScreen()
                LogKind.Dns -> DnsLogsScreen()
            }
        }
        composable<ConfigDetailRoute> {
            ConfigDetailScreen(
                onRestart = onRestart,
                onOpenModules = { navController.navigate(ModulesRoute) },
                onManageProfiles = { navController.navigate(ConfigRoute) },
                onOpenMitm = { navController.navigate(MitmRoute) },
            )
        }
        composable<ModulesRoute> {
            ModulesScreen(
                onRestart = onRestart,
                onOpenMitm = { navController.navigate(MitmRoute) },
            )
        }
        composable<MitmRoute> { MitmScreen() }
        composable<ScanRoute> {
            ScanScreen(onDone = {
                navController.popBackStack()
            })
        }
    }
}

private fun titleFor(destination: NavDestination?, entry: androidx.navigation.NavBackStackEntry?): String = when {
    destination.matches(HomeRoute::class) -> "南门 DNS"
    destination.matches(ConfigRoute::class) -> "规则"
    destination.matches(DataRoute::class) -> "维护"
    destination.matches(ModulesRoute::class) -> "模块"
    destination.matches(SettingsRoute::class) -> "我的"
    destination.matches(NodesRoute::class) -> "代理节点"
    destination.matches(LogsRoute::class) ->
        if (entry?.toRoute<LogsRoute>()?.kind == LogKind.Dns) "DNS 查询" else "运行日志"
    destination.matches(ConfigDetailRoute::class) -> "当前配置"
    destination.matches(MitmRoute::class) -> "MITM 管理"
    destination.matches(ScanRoute::class) -> "扫码导入"
    else -> "南门 DNS"
}

@Composable
private fun StrategyScreen(onOpenDetail: () -> Unit, onRestart: () -> Unit) {
    var section by rememberSaveable { mutableStateOf(0) }
    val pages = rememberSaveableStateHolder()
    Column(Modifier.fillMaxSize()) {
        TabRow(
            selectedTabIndex = section,
            containerColor = NamuColors.Bg,
            contentColor = NamuColors.Accent,
        ) {
            listOf("规则", "模块").forEachIndexed { index, label ->
                Tab(
                    selected = index == section,
                    onClick = { section = index },
                    selectedContentColor = NamuColors.Accent,
                    unselectedContentColor = NamuColors.TextSub,
                    text = { Text(label) },
                )
            }
        }
        pages.SaveableStateProvider(section) {
            if (section == 0) ConfigScreen(onOpenDetail, onRestart)
            else ModulesScreen(onRestart)
        }
    }
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
            .size(48.dp)
            .clip(RoundedCornerShape(8.dp))
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
