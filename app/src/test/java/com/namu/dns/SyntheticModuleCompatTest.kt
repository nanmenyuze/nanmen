package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 南门DNS 自写合成模块回归：
 * %APPEND% 前缀、中段通配 MITM 主机、URL-REGEX REJECT 转 MITM 重写、
 * DNS 过滤 2603 域全量解析、除脚本外零意外丢弃。
 */
class SyntheticModuleCompatTest {
    private fun fixture(name: String): String {
        val candidates = listOf(
            File("../compat/fixtures/modules/synthetic/synthetic-$name.sgmodule"),
            File("compat/fixtures/modules/synthetic/synthetic-$name.sgmodule"),
        )
        return candidates.firstOrNull { it.isFile }?.readText()
            ?: error("fixture not found: $name")
    }

    @Test
    fun appendPrefixKeepsFirstMitmHost() {
        val p = ModuleParser.parse(fixture("video"))
        assertEquals(6, p.mitmHostnames.size)
        assertTrue(p.mitmHostnames.contains("app.video.example.com"))
        assertFalse(p.ignoredReasons.containsKey("invalid_mitm_host"))
    }

    @Test
    fun videoFiveScriptsAreAllParsedIncludingBinaryPlayPage() {
        val p = ModuleParser.parse(fixture("video"))
        assertEquals(5, p.scripts.size)
        val names = p.scripts.map { it.name }.toSet()
        assertEquals(setOf("合成开屏", "合成推荐流", "合成标签", "合成我的页", "合成播放页"), names)
        val play = p.scripts.first { it.name == "合成播放页" }
        assertTrue(play.binaryBodyMode)
        assertTrue(play.requiresBody)
        assertEquals("response", play.phase)
    }

    @Test
    fun midWildcardMitmHostsArePreserved() {
        val maps = ModuleParser.parse(fixture("maps"))
        assertEquals(3, maps.mitmHostnames.size)
        assertTrue(maps.mitmHostnames.contains("m*.maps.example.com"))
        val store = ModuleParser.parse(fixture("store"))
        assertTrue(store.mitmHostnames.contains("img*.shop.example.com"))
        val local = ModuleParser.parse(fixture("local"))
        assertTrue(local.mitmHostnames.contains("p*.local.example.com"))
    }

    @Test
    fun urlRegexRejectBecomesMitmRewrite() {
        val store = ModuleParser.parse(fixture("store"))
        assertTrue(store.urlRewrites.any { it.contains("debug") && it.trim().endsWith("reject") })
        assertFalse(store.ignoredReasons.containsKey("unsupported_rule_type"))
        val market = ModuleParser.parse(fixture("market"))
        assertTrue(market.urlRewrites.any { it.contains("sponsor") })
        assertTrue(market.urlRewrites.any { it.contains("assets") })
        assertFalse(market.ignoredReasons.containsKey("unsupported_rule_type"))
    }

    @Test
    fun dnsFilterParsesAllDomains() {
        val p = ModuleParser.parse(fixture("dns-filter"))
        assertEquals(2603, p.blockLines.size)
        assertEquals(0, p.ignored)
    }

    @Test
    fun allModulesOnlyDropScriptLines() {
        val names = listOf(
            "video", "shortvideo", "locker", "shop", "market", "store", "local",
            "novel", "music", "maps", "community", "audio", "mail", "reading",
            "groupbuy", "browser", "dns-filter",
        )
        val badKeys = setOf("invalid_mitm_host", "unsupported_rule_type", "invalid_rule")
        for (n in names) {
            val p = ModuleParser.parse(fixture(n))
            val bad = p.ignoredReasons.keys.filter { it in badKeys }
            assertTrue("$n 意外丢弃: $bad", bad.isEmpty())
        }
    }
}
