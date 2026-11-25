package com.namu.dns

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.InetAddress

/**
 * 跟随手机底层网络的 DNS，不把阿里/腾讯/Cloudflare 等第三方解析器写死成默认值。
 *
 * 只从非 VPN 的底层网络读取 LinkProperties.dnsServers；如果系统没有下发 DNS，
 * 返回空值，由配置下发层留空（内核不会改回第三方默认）。
 */
object SystemDns {
    const val FOLLOW = "system"
    /** 拿不到系统 DNS 时下发不可达的本地地址：宁可 fail-closed，也不回落到第三方。 */
    const val FAIL_CLOSED = "udp://127.0.0.1:9"

    data class Selection(
        val primary: String?,
        val secondary: String?,
        val networkLabel: String,
    ) {
        val available: Boolean get() = primary != null
        val primaryUpstream: String? get() = primary?.let(::udp)
        val secondaryUpstream: String? get() = secondary?.let(::udp)
    }

    fun isFollow(value: String?): Boolean = value?.trim()?.equals(FOLLOW, true) == true

    @Suppress("DEPRECATION")
    fun selection(context: Context): Selection {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val active = cm?.activeNetwork
        val activeCaps = active?.let { cm?.getNetworkCapabilities(it) }
        // VPN 正在运行时 activeNetwork 是 VPN 本身；此时才回退到所有非 VPN 底层网络。
        val networks = if (active != null && activeCaps != null &&
            !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        ) {
            listOf(active)
        } else {
            cm?.allNetworks?.toList().orEmpty()
        }
        val candidates = networks.mapNotNull { network ->
            val caps = cm?.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            val lp = cm.getLinkProperties(network) ?: return@mapNotNull null
            val dns = lp.dnsServers
                .filterNot { it.isLoopbackAddress || it.isLinkLocalAddress || it.isAnyLocalAddress }
                .distinctBy { it.hostAddress }
            if (dns.isEmpty()) return@mapNotNull null
            network to (caps to dns)
        }.sortedWith(
            compareByDescending<Pair<android.net.Network, Pair<NetworkCapabilities, List<InetAddress>>>> {
                it.second.first.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            }.thenByDescending {
                when {
                    it.second.first.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 3
                    it.second.first.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
                    it.second.first.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 1
                    else -> 0
                }
            }
        )?.firstOrNull()

        if (candidates == null) return Selection(null, null, "未获取到系统 DNS")
        val caps = candidates.second.first
        val all = candidates.second.second
        val v4 = all.filterIsInstance<Inet4Address>()
        val ordered = v4 + all.filterNot { it is Inet4Address }
        val primary = ordered.getOrNull(0)?.hostAddress
        val secondary = ordered.getOrNull(1)?.hostAddress
        val label = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi‑Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "移动数据"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "以太网"
            else -> "底层网络"
        }
        return Selection(primary, secondary, "$label 系统 DNS")
    }

    fun display(value: String?, context: Context? = null): String {
        if (!isFollow(value)) return value?.ifBlank { "未设置" } ?: "未设置"
        val s = context?.let { selection(it) }
        return if (s == null) "系统默认" else if (s.available) "系统默认 · ${s.networkLabel}" else "系统默认（未获取到 DNS）"
    }

    private fun udp(host: String): String =
        if (host.contains(':')) "udp://[$host]:53" else "udp://$host:53"
}
