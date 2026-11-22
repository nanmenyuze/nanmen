package com.namu.dns

import com.namu.dns.core.config.MitmConfig
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** UID 表只在存在真实消费者时轮询；纯 DNS 且无按 App 判断的默认配置必须为 false。 */
class UidDemandTest {

    @Test
    fun plainDnsOnlyConfigDoesNotPollUidTable() {
        // 默认 MITM 关闭，金融保护虽默认开但没有 MITM 消费者；纯 DNS 不该周期 su。
        assertFalse(needsUidMap(AppConfig(mode = "dns_only")))
    }

    @Test
    fun appRuleRequiresUidTable() {
        val cfg = AppConfig(
            rules = listOf(
                RuleItem(type = "PROCESS-NAME", value = "com.example.app", action = "直连"),
            ),
        )
        assertTrue(needsUidMap(cfg))
    }

    @Test
    fun perAppMitmRequiresUidTable() {
        val cfg = AppConfig(
            mitm = MitmConfig(
                enabled = true,
                appMode = "deny",
                apps = listOf("com.example.bank"),
            ),
        )
        assertTrue(needsUidMap(cfg))
    }

    @Test
    fun mitmWithAllAppsAndFinanceOnRequiresUidTable() {
        val cfg = AppConfig(
            mitm = MitmConfig(enabled = true, appMode = "all", apps = emptyList()),
            financeProtect = true,
        )
        assertTrue(needsUidMap(cfg))
    }

    @Test
    fun mitmAllAppsWithoutFinanceDoesNotRequireUidTable() {
        val cfg = AppConfig(
            mitm = MitmConfig(enabled = true, appMode = "all", apps = emptyList()),
            financeProtect = false,
        )
        assertFalse(needsUidMap(cfg))
    }

    @Test
    fun appRuleWinsEvenIfMitmDisabled() {
        val cfg = AppConfig(
            mitm = MitmConfig(enabled = false),
            rules = listOf(RuleItem(type = "UID", value = "10123", action = "代理")),
        )
        assertTrue(needsUidMap(cfg))
    }
}
