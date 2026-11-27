package com.namu.dns

import com.namu.dns.core.config.ConfigFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class SubscriptionRoutingTest {
    private val source = subscriptionSourceId("https://example.com/subscribe?token=test")
    private val otherSource = subscriptionSourceId("https://other.example/subscribe")
    private val oldGroup = ProxyGroup("已下架", members = listOf("旧节点"), subscriptionSource = source)
    private val manual = ProxyGroup("Proxy", members = listOf("手动节点"))
    private val other = ProxyGroup("其他订阅", members = listOf("其他节点"), subscriptionSource = otherSource)
    private val oldRule = RuleItem("DOMAIN", "old.example", oldGroup.name, "订阅", subscriptionSource = source)

    @Test
    fun refreshReplacesOwnedItemsAndKeepsOtherSourcesEvenWhenGroupNamesCollide() {
        val incomingGroups = listOf(
            ProxyGroup(manual.name, members = listOf("新节点")),
            ProxyGroup("嵌套", members = listOf(manual.name)),
            ProxyGroup(other.name, members = listOf("新节点")),
        )
        val updated = Actions.mergeSubscriptionRouting(
            current = AppConfig(
                rules = listOf(oldRule, oldRule.copy(value = "other.example", subscriptionSource = otherSource)),
                proxyGroups = listOf(oldGroup, manual, other),
                finalPolicy = oldGroup.name,
                finalPolicySource = source,
                groupSelections = mapOf(oldGroup.name to "旧节点", manual.name to "手动节点"),
            ),
            source = source,
            nodeAliases = mapOf("新节点" to "新节点 (2)"),
            groups = incomingGroups,
            rules = listOf(
                oldRule.copy(value = "new.example", action = manual.name, subscriptionSource = ""),
                oldRule.copy(value = "node.example", action = "node:新节点", subscriptionSource = ""),
            ),
            finalPolicy = other.name,
            replaceRouting = true,
        )
        assertEquals(listOf(manual, other), updated.proxyGroups.take(2))
        val imported = updated.proxyGroups.drop(2)
        assertEquals(listOf("Proxy（策略组）", "嵌套", "其他订阅（策略组）"), imported.map { it.name })
        assertEquals(listOf("新节点 (2)"), imported.first().members)
        assertEquals(listOf(imported.first().name), imported[1].members)
        assertEquals(imported.last().name, updated.finalPolicy)
        assertEquals(source, updated.finalPolicySource)
        assertEquals(listOf("other.example", "new.example", "node.example"), updated.rules.map { it.value })
        assertEquals(listOf(imported.first().name, "node:新节点 (2)"), updated.rules.drop(1).map { it.action })
        assertEquals(mapOf(manual.name to "手动节点"), updated.groupSelections)
    }

    @Test
    fun nodeOnlyRefreshClearsOwnedRoutingAndLeavesIndependentFinalAlone() {
        val current = AppConfig(
            rules = listOf(oldRule),
            proxyGroups = listOf(oldGroup, manual),
            finalPolicy = oldGroup.name,
            finalPolicySource = source,
        )
        fun refresh(cfg: AppConfig) = Actions.mergeSubscriptionRouting(
            cfg, source, emptyMap(), emptyList(), emptyList(), null, replaceRouting = true,
        )
        val refreshed = refresh(current)
        assertEquals(listOf(manual), refreshed.proxyGroups)
        assertEquals(emptyList<RuleItem>(), refreshed.rules)
        assertEquals("proxy", refreshed.finalPolicy)
        assertEquals("", refreshed.finalPolicySource)
        val independent = refresh(current.copy(finalPolicy = other.name, finalPolicySource = otherSource))
        assertEquals(other.name, independent.finalPolicy)
        assertEquals(otherSource, independent.finalPolicySource)
    }

    @Test
    fun refreshKeepsOnlySelectionsForMembersStillInTheGroup() {
        val kept = ProxyGroup("可用", members = listOf("A", "B"), subscriptionSource = source)
        val lost = ProxyGroup("变化", members = listOf("A", "B"), subscriptionSource = source)
        val refreshed = Actions.mergeSubscriptionRouting(
            AppConfig(proxyGroups = listOf(kept, lost), groupSelections = mapOf(kept.name to "B", lost.name to "B")),
            source, emptyMap(), listOf(kept, lost.copy(members = listOf("A"))), emptyList(), null,
            replaceRouting = true,
        )
        assertEquals(mapOf(kept.name to "B"), refreshed.groupSelections)
    }

    @Test
    fun legacyItemsWithUncertainOwnershipSurviveRefresh() {
        val legacyGroup = oldGroup.copy(subscriptionSource = "")
        val legacyRule = oldRule.copy(subscriptionSource = "")
        val current = AppConfig(
            rules = listOf(legacyRule), proxyGroups = listOf(legacyGroup), finalPolicy = legacyGroup.name,
        )
        val refreshed = Actions.mergeSubscriptionRouting(
            current, source, emptyMap(), emptyList(), emptyList(), null, replaceRouting = true,
        )
        assertEquals(current, refreshed)
    }

    @Test
    fun ownershipSurvivesDeviceAndProfileStorageWithoutRawSubscriptionUrl() {
        val current = AppConfig(
            rules = listOf(oldRule),
            proxyGroups = listOf(oldGroup),
            finalPolicy = oldGroup.name,
            finalPolicySource = source,
        )
        val profileJson = ConfigFile.fromAppConfig(current).toJson()
        assertFalse(profileJson.contains("token=test"))
        val profile = ConfigFile.fromJson(profileJson).toAppConfig(AppConfig(finalPolicySource = otherSource))
        val snapshot = AppConfig.fromJson(current.toJson().toString())
        for (restored in listOf(profile, snapshot)) {
            assertEquals(source, restored.finalPolicySource)
            assertEquals(source, restored.proxyGroups.single().subscriptionSource)
            assertEquals(source, restored.rules.single().subscriptionSource)
        }
        assertEquals("", ConfigFile().toAppConfig(current).finalPolicySource)
    }

    @Test
    fun localAndConfigRulesPrecedeModulesAndSubscriptionRulesFollowModules() {
        val local = RuleItem("DOMAIN", "shared.example", "direct")
        val config = local.copy(value = "config.example", source = "[Rule]")
        val module = local.copy(action = "block", source = "模块")
        val tagged = oldRule.copy(value = local.value)
        val legacy = oldRule.copy(value = "legacy.example", subscriptionSource = "")
        val cfg = AppConfig(mode = "rule", rules = listOf(tagged, legacy, config))
        val global = GlobalRuleStore.State(localRulesEnabled = true, localRules = listOf(local))
        val compiled = ConfigStore.routingRules(cfg, global, listOf(module)) { it }
        assertEquals(listOf("本地规则", "[Rule]", "模块", "订阅", "订阅"), compiled.map { it.source })
        assertEquals(listOf("direct", "direct", "block", oldGroup.name, oldGroup.name), compiled.map { it.action })
        assertEquals(listOf("本地规则", "模块"), ConfigStore.routingRules(
            cfg.copy(mode = "dns_only"), global, listOf(module),
        ) { it }.map { it.source })
    }
}
