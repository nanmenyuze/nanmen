package com.namu.dns.core

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.border
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.layout.heightIn
import androidx.compose.ui.semantics.Role
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
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
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.layer.GraphicsLayer
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.toRoute
import com.namu.dns.App
import com.namu.dns.UiPrefs
import com.namu.dns.ui.OnboardingScreen
import com.namu.dns.ui.ConfigDetailScreen
import com.namu.dns.ui.ConfigScreen
import com.namu.dns.ui.DataScreen
import com.namu.dns.ui.DnsLogsScreen
import com.namu.dns.ui.HomeScreen
import com.namu.dns.ui.LogsScreen
import com.namu.dns.ui.MitmScreen
import com.namu.dns.ui.ModulesScreen
import com.namu.dns.ui.NamuColors
import com.namu.dns.ui.NodesScreen
import com.namu.dns.ui.ScanScreen
import com.namu.dns.ui.SettingsScreen
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
        val currentTab = MainTab.entries.firstOrNull { destination.matches(it.route::class) }
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
                ShadowTopBar(
                    title = titleFor(destination, entry),
                    left = {
                        NavIcon(
                            icon = if (isDetail) Icons.AutoMirrored.Rounded.ArrowBack else Icons.Rounded.QrCodeScanner,
                            desc = if (isDetail) "返回" else "导入服务器",
                        ) {
                            if (isDetail) {
                                navController.popBackStack()
                            } else {
                                navController.navigate(ScanRoute)
                            }
                        }
                    },
                    right = {
                        if (destination.matches(HomeRoute::class)) {
                            NavIcon(Icons.Rounded.Add, "添加服务器") {
                                navController.navigate(NodesRoute)
                            }
                        }
                    },
                )
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
                    MainTabBar(
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
        enterTransition = { fadeIn(tween(170)) },
        exitTransition = { fadeOut(tween(120)) },
    ) {
        composable<HomeRoute> {
            HomeScreen(
                onToggle = onToggle,
                onOpenNodes = { navController.navigate(NodesRoute) },
                onRestart = onRestart,
            )
        }
        composable<ConfigRoute> {
            StrategyScreen(
                onOpenDetail = { navController.navigate(ConfigDetailRoute) },
                onRestart = onRestart,
            )
        }
        composable<DataRoute> {
            DataScreen(
                onOpenLogs = { navController.navigate(LogsRoute(LogKind.Runtime)) },
                onOpenDnsLogs = { navController.navigate(LogsRoute(LogKind.Dns)) },
                onOpenNodes = { navController.navigate(NodesRoute) },
                onRestart = onRestart,
            )
        }
        composable<SettingsRoute> {
            SettingsScreen(
                onRestart = onRestart,
                onOpenLogs = { navController.navigate(LogsRoute(LogKind.Runtime)) },
                onOpenMitm = { navController.navigate(MitmRoute) },
            )
        }
        composable<NodesRoute> { NodesScreen(onRestart = onRestart) }
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
                onOpenMitm = { navController.navigate(MitmRoute) },
            )
        }
        composable<ModulesRoute> { ModulesScreen(onRestart = onRestart) }
        composable<MitmRoute> { MitmScreen() }
        composable<ScanRoute> {
            ScanScreen(onDone = {
                navController.navigate(NodesRoute) {
                    popUpTo(ScanRoute) { inclusive = true }
                    launchSingleTop = true
                }
            })
        }
    }
}

private fun titleFor(destination: NavDestination?, entry: androidx.navigation.NavBackStackEntry?): String = when {
    destination.matches(HomeRoute::class) -> "南门DNS"
    destination.matches(ConfigRoute::class) -> MainTab.Config.label
    destination.matches(DataRoute::class) -> "数据"
    destination.matches(SettingsRoute::class) -> "设置"
    destination.matches(NodesRoute::class) -> "服务器"
    destination.matches(LogsRoute::class) ->
        if (entry?.toRoute<LogsRoute>()?.kind == LogKind.Dns) "DNS 查询" else "运行日志"
    destination.matches(ConfigDetailRoute::class) -> "基础配置"
    destination.matches(ModulesRoute::class) -> "模块"
    destination.matches(MitmRoute::class) -> "MITM 去广告"
    destination.matches(ScanRoute::class) -> "扫码导入"
    else -> "南门DNS"
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
private fun MainTabBar(
    selected: MainTab,
    pageLayer: GraphicsLayer,
    pageOrigin: () -> Offset,
    onSelect: (MainTab) -> Unit,
) {
    var dockOrigin by remember { mutableStateOf(Offset.Zero) }
    val shape = RoundedCornerShape(32.dp)
    Box(
        Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 20.dp, vertical = 10.dp),
        contentAlignment = Alignment.Center,
    ) {
        BoxWithConstraints(
            Modifier.widthIn(max = 360.dp).fillMaxWidth()
                .shadow(3.dp, shape).clip(shape)
                .onGloballyPositioned { dockOrigin = it.positionInRoot() }
                .border(0.5.dp, NamuColors.Separator, shape),
        ) {
            // 仅此背景层应用 RenderEffect，导航文字和指示器单独绘制。
            Spacer(Modifier.matchParentSize().blur(12.dp).drawBehind {
                val offset = pageOrigin() - dockOrigin
                translate(offset.x, offset.y) { drawLayer(pageLayer) }
            })
            Spacer(Modifier.matchParentSize().background(NamuColors.Card.copy(alpha = 0.64f)))
            val cellWidth = maxWidth / MainTab.entries.size
            val indicatorX by animateDpAsState(
                targetValue = cellWidth * selected.ordinal,
                animationSpec = tween(220),
                label = "dock-indicator",
            )
            Row(Modifier.fillMaxWidth().selectableGroup().padding(vertical = 4.dp)) {
                MainTab.entries.forEach { item ->
                    TabButton(
                        selected = item == selected,
                        iconRes = item.iconRes,
                        label = item.label,
                        modifier = Modifier.weight(1f),
                    ) { onSelect(item) }
                }
            }
            Box(
                Modifier.align(Alignment.BottomStart)
                    .offset(x = indicatorX + (cellWidth - 12.dp) / 2)
                    .padding(bottom = 3.dp)
                    .size(12.dp, 2.dp)
                    .background(NamuColors.Accent, shape),
            )
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

@Composable
private fun TabButton(
    selected: Boolean,
    iconRes: Int,
    label: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val haptic = LocalHapticFeedback.current
    Column(
        modifier
            .heightIn(min = 48.dp)
            .selectable(selected = selected, role = Role.Tab, interactionSource = interaction, indication = null) {
                if (!selected) {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onClick()
                }
            }
            .padding(vertical = 4.dp),
        verticalArrangement = androidx.compose.foundation.layout.Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        val tint by animateColorAsState(
            if (selected) NamuColors.Accent else NamuColors.TextSub,
            tween(180),
            label = "tab-tint",
        )
        Icon(
            painter = painterResource(iconRes),
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.height(3.dp))
        Text(
            label,
            fontSize = 12.sp,
            fontWeight = if (selected) FontWeight.Medium else FontWeight.Normal,
            color = tint,
        )
    }
}
