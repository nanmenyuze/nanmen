package com.namu.dns.core.config

/**
 * S6：模块 [General] 中会改变壳行为的键。
 *
 * 只做确定性映射，不把模块里的 TUN/内核参数偷偷覆盖用户设置：
 * - skip-proxy / bypass → 追加到 MITM 跳过域名；
 * - ssid-trigger → 交给 SSID 触发名单（仍需本地 opt-in）；
 * - proxy-test-url / internet-test-url / test-timeout → 壳层健康检查候选；
 * - force-close-connections → 模块变更时重建连接（由运行层消费）。
 */
data class ModuleGeneralEffects(
    val skipHosts: List<String> = emptyList(),
    val ssidTriggers: List<String> = emptyList(),
    val testUrl: String = "",
    val testTimeout: Int = 0,
    val forceCloseConnections: Boolean = false,
    val raw: Map<String, String> = emptyMap(),
)

object ModuleGeneral {
    fun parse(options: Map<String, String>): ModuleGeneralEffects {
        fun split(vararg keys: String): List<String> = keys
            .flatMap { options[it].orEmpty().split(',', ';', ' ') }
            .map { it.trim().trim('"') }
            .filter { it.isNotBlank() && it != "*" }
            .distinct()

        val timeout = options["test-timeout"]?.toIntOrNull()?.takeIf { it in 1..60 } ?: 0
        return ModuleGeneralEffects(
            skipHosts = split("skip-proxy", "bypass"),
            ssidTriggers = split("ssid-trigger", "ssid-trigger-names"),
            testUrl = options["proxy-test-url"].orEmpty().ifBlank { options["internet-test-url"].orEmpty() },
            testTimeout = timeout,
            forceCloseConnections = options["force-close-connections"]
                ?.let { it.equals("true", true) || it == "1" } ?: false,
            raw = options,
        )
    }
}
