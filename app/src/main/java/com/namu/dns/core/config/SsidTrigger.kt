package com.namu.dns.core.config

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import com.namu.dns.AppConfig
import androidx.core.content.ContextCompat

data class SsidState(
    val enabled: Boolean = false,
    val optedIn: Boolean = false,
    val hasPermission: Boolean = false,
    val currentSsid: String = "",
    val matched: Boolean = false,
    /** 需要 UI 展示授权入口；G2 不开 UI，只把状态交给后续壳层。 */
    val needsPermission: Boolean = false,
)

/**
 * S6：SSID 触发默认关，且只有用户主动 opt-in 后才申请定位权限。
 * 只读取当前 Wi-Fi SSID；不采集位置、不做地理围栏、不上报。
 * 服务端配置只提供 SSID 名单，最终是否启用仍由本地 opt-in 决定。
 */
object SsidTrigger {
    // 用字面量而不是 Manifest.permission 字段，避免 lint 把 API 33 常量标为 InlinedApi；
    // 运行时按 SDK_INT 分支，31/32 不会请求该权限。
    private const val NEARBY_WIFI_DEVICES = "android.permission.NEARBY_WIFI_DEVICES"

    fun state(
        context: Context,
        cfg: AppConfig,
        names: List<String> = cfg.ssidTriggerNames,
    ): SsidState {
        if (!cfg.ssidTriggerEnabled) return SsidState(enabled = false)
        val missing = requiredPermissions().filter {
            ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
        }
        val hasPermission = missing.isEmpty()
        if (!cfg.ssidLocationOptIn) {
            return SsidState(enabled = true, optedIn = false, hasPermission = hasPermission, needsPermission = true)
        }
        if (!hasPermission) {
            return SsidState(enabled = true, optedIn = true, hasPermission = false, needsPermission = true)
        }
        @Suppress("DEPRECATION")
        val ssid = runCatching {
            (context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager)
                .connectionInfo
                ?.getSSID()
                ?.trim()
                ?.trim('"')
                .orEmpty()
        }.getOrDefault("")
        val matched = matches(ssid, names)
        return SsidState(
            enabled = true,
            optedIn = true,
            hasPermission = true,
            currentSsid = ssid,
            matched = matched,
        )
    }

    /**
     * 运行时判定入口，供 AutoConnect 消费。名单可传
     * `ConfigStore.effectiveSsidTriggers`（Profile + 模块 [General] 合并结果）。
     */
    fun active(
        context: Context,
        cfg: AppConfig,
        names: List<String> = cfg.ssidTriggerNames,
    ): Boolean {
        val s = state(context, cfg, names)
        return s.enabled && s.optedIn && s.hasPermission && s.matched
    }

    /** 纯函数：空 SSID、占位符 `<unknown ssid>`、空名单一律不命中。 */
    fun matches(currentSsid: String, names: List<String>): Boolean {
        val ssid = currentSsid.trim().trim('"')
        if (ssid.isBlank() || ssid.equals("<unknown ssid>", ignoreCase = true)) return false
        return names.any { it.trim().trim('"').equals(ssid, ignoreCase = true) }
    }

    /**
     * Android 13+ 的 Wi-Fi API 走 NEARBY_WIFI_DEVICES；但平台仍把当前 SSID 归为
     * location-sensitive（与 getScanResults 同权限），所以读取 SSID 时 FINE_LOCATION
     * 也要保留。这里只做“当前 SSID 是否等于本地名单”，不采集、不存、不上报位置。
     */
    fun permissionName(): String = permissionName(Build.VERSION.SDK_INT)

    fun permissionName(sdk: Int): String = if (sdk >= 33) {
        NEARBY_WIFI_DEVICES
    } else Manifest.permission.ACCESS_FINE_LOCATION

    fun requiredPermissions(sdk: Int = Build.VERSION.SDK_INT): List<String> =
        if (sdk >= 33) {
            listOf(NEARBY_WIFI_DEVICES, Manifest.permission.ACCESS_FINE_LOCATION)
        } else {
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
}
