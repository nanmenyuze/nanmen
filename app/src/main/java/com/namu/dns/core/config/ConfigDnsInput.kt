package com.namu.dns.core.config

import java.net.URI

object ConfigDnsInput {
    fun error(value: String): String? {
        val entries = value.split(',', '\n').map { it.trim() }.filter { it.isNotEmpty() }
        if (entries.isEmpty()) return "请填写 DNS 地址"
        if (entries.size > 8) return "最多添加 8 个 DNS 地址"
        if (entries.size > 1 && entries.any { it.equals("system", true) }) return "系统 DNS 不能与其他地址混用"
        entries.forEachIndexed { index, entry ->
            singleError(entry)?.let { return if (entries.size == 1) it else "第 ${index + 1} 项：$it" }
        }
        return null
    }

    private fun singleError(address: String): String? {
        if (address.equals("system", ignoreCase = true)) return null
        val candidate = if ("://" in address) address else {
            val authority = if (address.count { it == ':' } > 1 && !address.startsWith('[')) {
                "[$address]"
            } else address
            "udp://$authority"
        }
        val uri = runCatching { URI(candidate) }.getOrNull()
            ?: return "DNS 地址格式不正确"
        if (uri.host.isNullOrBlank() || uri.userInfo != null || uri.fragment != null ||
            (uri.port != -1 && uri.port !in 1..65535)
        ) return "DNS 主机或端口无效"
        return when (uri.scheme) {
            "https", "http" -> null
            "udp", "tls", "dot" -> if (uri.path.trim('/').isEmpty() && uri.query == null) null
                else "UDP 和 DoT 地址只填写主机和端口"
            else -> "支持系统 DNS、DoH、DoT 和 UDP"
        }
    }
}
