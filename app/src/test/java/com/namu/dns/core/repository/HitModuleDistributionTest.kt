package com.namu.dns.core.repository

import org.junit.Assert.assertEquals
import org.junit.Test

class HitModuleDistributionTest {
    @Test
    fun combinesRuleTypesAndResolvesOldIdsWithoutExposingThem() {
        val rows = listOf(
            HitSourceStat("dns", "mod_a", "旧名称", windowHits = 12),
            HitSourceStat("script", "mod_a", "script|mod_a", windowHits = 8),
            HitSourceStat("script", "mod_missing", "script|mod_missing", windowHits = 3),
            HitSourceStat("dns", "mod_other", windowHits = 1),
            HitSourceStat("url", "mod_removed", "旧模块", windowHits = 5),
        )
        assertEquals(
            listOf(HitModuleStat("新名称", 20), HitModuleStat("旧模块", 5), HitModuleStat("未归因", 4)),
            hitModuleDistribution(rows, mapOf("mod_a" to "新名称")),
        )
    }
}
