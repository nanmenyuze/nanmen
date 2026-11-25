package com.namu.dns

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

/** M7 网络状态：只读取底层网络，不把 VPN 自身当成"网络"。 */
object NetworkStatus {
    data class Snapshot(
        val label: String,
        val detail: String,
        val metered: Boolean?,
        val vpnUp: Boolean,
    )

    @Suppress("DEPRECATION")
    fun current(context: Context): Snapshot {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val active = cm?.activeNetwork
        val activeCaps = active?.let { cm.getNetworkCapabilities(it) }
        val vpnUp = activeCaps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true ||
            App.container.runtime.current().connected
        val underlying = cm?.allNetworks?.mapNotNull { n ->
            val c = cm.getNetworkCapabilities(n) ?: return@mapNotNull null
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            if (!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            n to c
        }?.sortedWith(
            compareByDescending<Pair<android.net.Network, NetworkCapabilities>> {
                it.second.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            }.thenByDescending {
                when {
                    it.second.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 3
                    it.second.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
                    it.second.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 1
                    else -> 0
                }
            },
        )?.firstOrNull()
        if (underlying == null) {
            return Snapshot("无底层网络", if (vpnUp) "VPN 已启动，但底层网络不可用" else "请检查 Wi‑Fi / 移动数据", null, vpnUp)
        }
        val caps = underlying.second
        val label = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi‑Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "移动数据"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "以太网"
            else -> "其他网络"
        }
        val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        val metered = if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) false else true
        val detail = buildString {
            append(if (validated) "已验证" else "未验证")
            append(" · ")
            append(if (metered) "计费网络" else "不计费")
            if (caps.linkDownstreamBandwidthKbps > 0) {
                append(" · 下行约 ").append(caps.linkDownstreamBandwidthKbps / 1000).append(" Mbps")
            }
            if (vpnUp) append(" · VPN 隧道已建立")
        }
        return Snapshot(label, detail, metered, vpnUp)
    }
}
