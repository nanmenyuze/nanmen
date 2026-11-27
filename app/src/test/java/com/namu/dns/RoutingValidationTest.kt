package com.namu.dns

import com.namu.dns.core.config.ConfigIssueLevel
import com.namu.dns.core.config.RoutingValidation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutingValidationTest {
    private fun group(name: String, members: List<String> = listOf("节点")) =
        ProxyGroup(name = name, members = members)

    @Test
    fun validRoutingPasses() {
        val issues = RoutingValidation.validate(
            groups = listOf(group("Proxy"), group("嵌套", listOf("Proxy"))),
            nodeNames = listOf("节点"),
            rules = listOf(RuleItem("DOMAIN", "a.example", "Proxy", "订阅", subscriptionSource = "s")),
            finalPolicy = "嵌套",
            finalPolicySource = "s",
            selections = mapOf("Proxy" to "节点"),
        )
        assertTrue(issues.none { it.level == ConfigIssueLevel.ERROR })
    }

    @Test
    fun emptyGroupAndCycleAreErrors() {
        val empty = RoutingValidation.validate(
            groups = listOf(group("空组", emptyList())),
            nodeNames = listOf("节点"),
            rules = emptyList(),
            finalPolicy = "direct",
        )
        assertTrue(empty.any { it.level == ConfigIssueLevel.ERROR && it.message.contains("没有成员") })

        val cycle = RoutingValidation.validate(
            groups = listOf(group("A", listOf("B")), group("B", listOf("A"))),
            nodeNames = listOf("节点"),
            rules = emptyList(),
            finalPolicy = "direct",
        )
        assertTrue(cycle.any { it.level == ConfigIssueLevel.ERROR && it.message.contains("循环") })
    }

    @Test
    fun ruleAndFinalPointingToDeletedGroupAreErrors() {
        val issues = RoutingValidation.validate(
            groups = listOf(group("保留")),
            nodeNames = listOf("节点"),
            rules = listOf(
                RuleItem("DOMAIN", "a.example", "已删除组", "订阅"),
                RuleItem("IP-CIDR", "1.2.3.0/24", "node:已删除节点", "订阅", noResolve = true),
            ),
            finalPolicy = "也删了",
            finalPolicySource = "s",
        )
        val errors = issues.filter { it.level == ConfigIssueLevel.ERROR }
        assertEquals(3, errors.size)
        assertTrue(errors.any { it.message.contains("已删除组") })
        assertTrue(errors.any { it.message.contains("已删除节点") })
        assertTrue(errors.any { it.message.contains("FINAL") })
    }

    @Test
    fun legacyUnknownSourceHintIsShown() {
        val issues = RoutingValidation.validate(
            groups = emptyList(),
            nodeNames = emptyList(),
            rules = listOf(RuleItem("DOMAIN", "a.example", "旧组", "订阅", subscriptionSource = "")),
            finalPolicy = "direct",
        )
        assertTrue(issues.any {
            it.level == ConfigIssueLevel.ERROR && it.message.contains("旧版来源不确定")
        })
    }

    @Test
    fun duplicateGroupNamesMakeRuleAmbiguous() {
        val issues = RoutingValidation.validate(
            groups = listOf(group("Proxy"), group("Proxy")),
            nodeNames = listOf("节点"),
            rules = listOf(RuleItem("DOMAIN", "a.example", "Proxy", "订阅")),
            finalPolicy = "direct",
        )
        assertTrue(issues.any { it.level == ConfigIssueLevel.ERROR && it.message.contains("重复") })
    }
}
