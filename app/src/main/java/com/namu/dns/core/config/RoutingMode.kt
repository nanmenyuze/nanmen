package com.namu.dns.core.config

enum class RoutingMode(val key: String, val title: String) {
    Direct("dns_only", "全局直连"),
    Rules("rule", "规则分流"),
    Proxy("global", "全局代理");

    fun modeFor(currentMode: String): String =
        if (this == Direct && currentMode == DirectFilterScope.Connections.mode) currentMode else key

    companion object {
        fun fromConfig(mode: String): RoutingMode = when (mode) {
            "dns_only", "filter_only" -> Direct
            "global" -> Proxy
            else -> Rules
        }
    }
}

enum class DirectFilterScope(val mode: String, val fullRoute: Boolean, val title: String) {
    SystemDns("dns_only", false, "仅系统 DNS（轻量）"),
    FullRouteDns("dns_only", true, "全量接管，仅过滤 DNS"),
    Connections("filter_only", true, "DNS 和连接规则");

    companion object {
        fun fromConfig(mode: String, fullRoute: Boolean): DirectFilterScope = when {
            mode == Connections.mode -> Connections
            fullRoute -> FullRouteDns
            else -> SystemDns
        }
    }
}
