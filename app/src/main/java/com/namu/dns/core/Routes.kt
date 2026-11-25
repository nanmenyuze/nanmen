package com.namu.dns.core

import androidx.annotation.DrawableRes
import androidx.annotation.Keep
import androidx.navigation.NavDestination
import androidx.navigation.NavDestination.Companion.hasRoute
import com.namu.dns.R
import kotlinx.serialization.Serializable
import kotlin.reflect.KClass

/**
 * 类型安全路由：Navigation Compose 2.8+ 直接以这些 @Serializable 对象作为目的地，
 * 不再用字符串 dest / 布尔 showXxx 维护页面状态。
 */
@Serializable
data object HomeRoute

@Serializable
data object ConfigRoute

@Serializable
data object DataRoute

@Serializable
data object SettingsRoute

@Serializable
data object AdvancedSettingsRoute

/** 设置 → 运行数据与诊断：DNS 拦截、流量连接、MITM 统计与日志导出的总览二级页。 */
@Serializable
data object DiagnosticsRoute

@Serializable
data object NodesRoute

@Keep
@Serializable
enum class LogKind {
    Runtime,
    Dns,
}

/** 运行日志与 DNS 查询日志共用一条路由，用 kind 区分，避免两套几乎相同的页面。 */
@Serializable
data class LogsRoute(val kind: LogKind = LogKind.Runtime)

@Serializable
data class ConfigDetailRoute(val name: String)

@Serializable
data class QuickEditRoute(val name: String)

@Keep
@Serializable
enum class ConfigSection(val title: String) {
    General("通用"),
    Rules("规则"),
    Sources("规则来源"),
    Hosts("Hosts"),
    UrlRewrite("URL 重写"),
    HeaderRewrite("头部重写"),
    BodyRewrite("正文重写"),
    Https("HTTPS 解密"),
    Advanced("高级设置"),
}

@Serializable
data class ConfigSectionRoute(val section: ConfigSection, val name: String)

@Serializable
data object ModulesRoute

@Serializable
data class ModuleDetailRoute(val moduleId: String)

/** MITM 去广告：证书安装、域名/跳过列表、规则与运行数据。 */
@Serializable
data object MitmRoute

@Serializable
data object MitmRuntimeRoute

/** 扫码导入的占位路由；当前入口仍复用「节点」页的导入/订阅流程。 */
@Serializable
data object ScanRoute

enum class MainTab(
    val label: String,
    @DrawableRes val iconRes: Int,
    val route: Any,
) {
    Home("首页", R.drawable.ic_tab_home, HomeRoute),
    Modules("模块", R.drawable.ic_tab_rules, ModulesRoute),
    Settings("设置", R.drawable.ic_tab_settings, SettingsRoute),
}

/** Navigation 的类型安全匹配；destination 为 null 时视为不在任何已知路由。 */
fun NavDestination?.matches(route: KClass<*>): Boolean = this?.hasRoute(route) == true
