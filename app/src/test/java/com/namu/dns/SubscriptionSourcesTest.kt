package com.namu.dns

import com.namu.dns.core.config.ConfigFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SubscriptionSourcesTest {
    private val a = "https://a.example/sub?token=1"
    private val b = "https://b.example/sub?token=2"

    @Test
    fun multipleSourcesRoundTripWithoutLeakingUrlIntoProfile() {
        val cfg = AppConfig(
            subscription = a,
            subscriptionSources = listOf(
                SubscriptionSource(subscriptionSourceId(a), a, "A", nodeCount = 2, lastSuccessAt = 7L),
                SubscriptionSource(subscriptionSourceId(b), b, "B", enabled = false, lastError = "超时", stale = true),
            ),
        )
        val restored = AppConfig.fromJson(cfg.toJson().toString())
        assertEquals(2, restored.subscriptionSources.size)
        assertEquals(listOf("A", "B"), restored.subscriptionSources.map { it.name })
        assertFalse(restored.subscriptionSources.first { it.id == subscriptionSourceId(b) }.enabled)
        assertTrue(restored.subscriptionSources.first { it.id == subscriptionSourceId(b) }.stale)
        val profile = ConfigFile.fromAppConfig(restored).toJson()
        assertFalse(profile.contains("a.example"))
        assertFalse(profile.contains("token="))
    }

    @Test
    fun legacySingleSubscriptionMigratesToSourceList() {
        val legacy = AppConfig(
            subscription = a,
            nodes = listOf(NodeInfo(name = "N", type = "ss", server = "1.1.1.1", port = 8388)),
        )
        val restored = AppConfig.fromJson(legacy.toJson().toString())
        assertEquals(listOf(subscriptionSourceId(a)), restored.subscriptionSources.map { it.id })
        assertEquals(a, restored.subscriptionSources.single().url)
        assertTrue(restored.subscriptionSources.single().nodeCount == 0)

        val withSourceNodes = legacy.copy(
            nodes = legacy.nodes.map { it.copy(source = subscriptionSourceId(a)) },
        )
        assertEquals(
            1,
            AppConfig.fromJson(withSourceNodes.toJson().toString()).subscriptionSources.single().nodeCount,
        )
    }

    @Test
    fun legacyRowsAreAddedForOldConfigsWithoutSourceMetadata() {
        val cfg = AppConfig(subscription = a, subscriptionInfo = SubscriptionInfo(updatedAt = 9L))
        val rows = Actions.subscriptionSourceRows(cfg)
        assertEquals(1, rows.size)
        assertEquals(a, rows.single().url)
        assertEquals(9L, rows.single().lastSuccessAt)
    }
}
