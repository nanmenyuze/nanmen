package com.namu.dns

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UidDemandTest {

    @Test
    fun plainDnsOnlyConfigDoesNotPollUidTable() {
        assertFalse(needsUidMap(AppConfig(mode = "dns_only"), GlobalRuleStore.State()))
    }

    @Test
    fun activeGlobalAppRuleRequiresUidTable() {
        val global = GlobalRuleStore.State(
            localRulesEnabled = true,
            localRules = listOf(RuleItem(type = "PROCESS-NAME", value = "com.example.app", action = "直连")),
        )
        assertTrue(needsUidMap(AppConfig(), global))
        assertFalse(needsUidMap(AppConfig(), global.copy(localRulesEnabled = false)))
    }

    @Test
    fun globalPerAppMitmRequiresUidTableWithFinanceOff() {
        val global = GlobalRuleStore.State(
            scope = GlobalRuleStore.MitmScope(enabled = true, appMode = "deny", apps = listOf("com.example.bank")),
        )
        assertTrue(needsUidMap(AppConfig(financeProtect = false), global))
    }

    @Test
    fun globalMitmAllAppsRequiresUidTableOnlyWithFinanceOn() {
        val global = GlobalRuleStore.State(scope = GlobalRuleStore.MitmScope(enabled = true))
        assertTrue(needsUidMap(AppConfig(financeProtect = true), global))
        assertFalse(needsUidMap(AppConfig(financeProtect = false), global))
    }
}
