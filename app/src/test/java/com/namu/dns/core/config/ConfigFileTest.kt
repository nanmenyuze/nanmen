package com.namu.dns.core.config

import com.namu.dns.AppConfig
import com.namu.dns.ModuleSource
import com.namu.dns.NodeInfo
import com.namu.dns.ProxyGroup
import com.namu.dns.RuleItem
import com.namu.dns.RuleSource
import com.namu.dns.SubscriptionInfo
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigFileTest {
    private fun sampleConfig() = AppConfig(
        mode = "global",
        dnsUpstream = "https://dns.example.com/dns-query",
        dnsFallback = "tls://1.1.1.1:853",
        dnsCacheTtl = 120,
        blockTtl = 30,
        fallbackFilter = false,
        fallbackGeoCheck = true,
        blockEnabled = false,
        finalPolicy = "direct",
        fakeIp = true,
        autoSelectNode = true,
        autoClearLogs = false,
        autoDisablePrivateDns = true,
        themeMode = "dark",
        autoConnect = true,
        pingMethod = "tls",
        subscriptionInfo = SubscriptionInfo(100, 600, 1000, 1_700_000_000_000L, 123L),
        rules = listOf(
            RuleItem("DOMAIN-SUFFIX", "example.com", "proxy", "manual"),
            RuleItem("IP-CIDR", "10.0.0.0/8", "direct"),
        ),
        ruleSources = listOf(
            RuleSource("ads", "https://example.com/ads.txt", "adblock", true, 123L, 456, ""),
        ),
        moduleSources = listOf(
            ModuleSource("mod", "示例模块", "https://example.com/mod.sgmodule", "com.example", true, 789L, 1, 2, 3),
        ),
        customAds = listOf("ads.example.com", "tracker.example.net"),
        proxyGroups = listOf(
            ProxyGroup("自动", "url-test", listOf("node", "备用"), tolerance = 100),
            ProxyGroup("手动", "select", listOf("自动")),
        ),
        groupSelections = mapOf("手动" to "自动"),
        nodes = listOf(NodeInfo("node", "ss", "1.2.3.4", 8388)),
        selected = "node",
        subscription = "https://example.com/sub",
    )

    @Test
    fun `nested config round trips`() {
        val cfg = sampleConfig()
        val file = ConfigFile.fromAppConfig(cfg)
        val decoded = ConfigFile.fromJson(file.toJson())
        assertEquals(file, decoded)
        assertEquals(2, decoded.rules.size)
        assertEquals(2, decoded.proxyGroups.size)
        assertEquals("url-test", decoded.proxyGroups.first().type)
        assertEquals(100, decoded.proxyGroups.first().tolerance)
        assertEquals("ads.example.com", decoded.customAds.first())
        assertEquals("示例模块", decoded.modules.single().name)
        assertEquals(30, decoded.general.blockTtl)
        assertTrue(decoded.general.fakeIp)
        assertEquals("dark", decoded.general.themeMode)
        assertEquals(true, decoded.general.autoConnect)
        assertEquals("tls", decoded.general.pingMethod)
        assertEquals(300L, decoded.general.subscriptionInfo?.remaining)
        assertEquals("dark", decoded.toAppConfig(decoded.toAppConfig(sampleConfig())).themeMode)
    }

    @Test
    fun `applying config keeps device nodes and selection`() {
        val base = sampleConfig()
        val file = ConfigFile.fromAppConfig(
            base.copy(
                mode = "dns_only",
                rules = listOf(RuleItem("DOMAIN", "only.example", "direct")),
                customAds = listOf("only.example.com"),
            ),
        )
        val applied = file.toAppConfig(base)
        assertEquals("dns_only", applied.mode)
        assertEquals(base.nodes, applied.nodes)
        assertEquals(base.selected, applied.selected)
        assertEquals(base.subscription, applied.subscription)
        // 组选择是设备侧状态，切换/套用配置时必须保留。
        assertEquals(base.groupSelections, applied.groupSelections)
        assertEquals(listOf(RuleItem("DOMAIN", "only.example", "direct")), applied.rules)
        assertEquals(listOf("only.example.com"), applied.customAds)
    }


    @Test
    fun `unknown root fields survive import and re-save`() {
        val root = JSONObject(ConfigFile.fromAppConfig(AppConfig()).toJson())
        root.put("futureSection", JSONObject().put("enabled", true))
        root.put("futureFlag", "keep")
        val imported = ConfigFile.fromExternal(root.toString(), AppConfig())!!
        assertEquals(3, imported.modelVersion)
        assertTrue(imported.unknownRoot.containsKey("futureSection"))
        assertTrue(imported.unknownRoot.containsKey("futureFlag"))

        val app = imported.toAppConfig()
        assertTrue(app.configUnknown.contains("futureSection"))
        val saved = JSONObject(ConfigFile.fromAppConfig(app).toJson())
        assertEquals(true, saved.getJSONObject("futureSection").getBoolean("enabled"))
        assertEquals("keep", saved.optString("futureFlag"))
    }

    @Test
    fun `unknown fields also survive AppConfig json round trip`() {
        val app = AppConfig(
            configUnknown = JSONObject().put("futureFlag", "keep").toString(),
        )
        val decoded = AppConfig.fromJson(app.toJson().toString())
        assertEquals("keep", JSONObject(decoded.configUnknown).optString("futureFlag"))
        assertEquals("keep", decoded.toJson().optString("futureFlag"))
    }


    @Test
    fun `proxy groups survive config round trip but selections stay device side`() {
        val cfg = sampleConfig()
        val file = ConfigFile.fromAppConfig(cfg)
        val text = file.toJson()
        val decoded = ConfigFile.fromJson(text)
        assertEquals(cfg.proxyGroups, decoded.proxyGroups)
        // .conf 不写设备侧选择，避免把 A 设备的选择带到 B 设备。
        assertTrue(!JSONObject(text).has("groupSelections"))
        val applied = decoded.toAppConfig(cfg)
        assertEquals(cfg.groupSelections, applied.groupSelections)
    }

    @Test
    fun `legacy import preserves rules mitm and device nodes`() {
        val app = sampleConfig().copy(
            mitm = MitmConfig(
                enabled = true,
                hostnames = listOf("api.example.com"),
                urlRewrites = listOf("^http://api.example.com https://api.example.com"),
            ),
        )
        val file = ConfigFile.fromLegacyJson(app.toJson().toString(), app)
        val applied = file.toAppConfig(app)
        assertEquals(app.rules, applied.rules)
        assertEquals(app.mitm, applied.mitm)
        assertEquals(app.nodes, applied.nodes)
        assertEquals(app.selected, applied.selected)
    }

    @Test
    fun `legacy flat json is migrated into model`() {
        val cfg = sampleConfig()
        val legacy = cfg.toJson().toString()
        val file = ConfigFile.fromJson(legacy)
        assertEquals("global", file.general.mode)
        assertEquals(30, file.general.blockTtl)
        assertEquals(2, file.rules.size)
        assertEquals("ads.example.com", file.customAds.first())
        assertEquals("node", file.toAppConfig(cfg).selected)
    }
}
