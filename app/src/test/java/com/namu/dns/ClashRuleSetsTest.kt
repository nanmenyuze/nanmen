package com.namu.dns

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ClashRuleSetsTest {
    @Test
    fun nativeParserRuleFlagsAndFinalDefaultsSurviveAndroidRoundTrip() {
        val ipRule = RuleItem.fromJson(org.json.JSONObject(
            """{"type":"IP-CIDR","value":"192.0.2.0/24","action":"direct","no_resolve":true}""",
        ))
        assertTrue(ipRule.toJson().getBoolean("noResolve"))
        val final = RuleItem.fromJson(org.json.JSONObject("""{"type":"FINAL","action":null}"""))
        assertEquals("proxy", final.action)
    }

    private class MemoryCache : ClashRuleSets.Cache {
        val entries = HashMap<String, ClashRuleSets.CachedProvider>()
        override fun read(url: String) = entries[url]
        override fun write(url: String, text: String, etag: String, lastModified: String) {
            entries[url] = ClashRuleSets.CachedProvider(text, etag, lastModified)
        }
    }

    private fun def(
        name: String,
        behavior: String,
        url: String = "https://example.com/$name.txt",
        type: String = "http",
    ) = ClashRuleSets.ProviderDef(name, type, url, behavior, "", 86_400)

    private fun ref(name: String, action: String = "proxy", noResolve: Boolean = false) =
        RuleItem("RULE-SET", name, action, "订阅", noResolve = noResolve)

    @Test
    fun domainProviderExpandsSuffixAndWildcardAndOverridesAction() = runBlocking {
        val exp = ClashRuleSets.expand(
            rules = listOf(ref("ads", "block")),
            defs = listOf(def("ads", "domain")),
            cache = MemoryCache(),
        ) { _, _ ->
            Actions.FetchResult("example.com\n+.foo.com\n*.bar.com\n# comment", emptyMap())
        }
        assertEquals(listOf("DOMAIN-SUFFIX", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"),
            exp.rules.map { it.type })
        assertTrue(exp.rules.all { it.action == "block" })
        assertEquals("fresh", exp.statuses.single().state)
        assertEquals(3, exp.statuses.single().rules)
    }

    @Test
    fun ipProviderHonoursNoResolveAndBareIpBecomesHostPrefix() = runBlocking {
        val exp = ClashRuleSets.expand(
            rules = listOf(ref("cnip", "direct", noResolve = true)),
            defs = listOf(def("cnip", "ipcidr")),
            cache = MemoryCache(),
        ) { _, _ ->
            Actions.FetchResult("1.2.3.0/24\n2001:db8::/32\n9.9.9.9", emptyMap())
        }
        assertEquals(listOf("IP-CIDR", "IP-CIDR6", "IP-CIDR"), exp.rules.map { it.type })
        assertEquals("9.9.9.9/32", exp.rules[2].value)
        assertTrue("引用行的 no-resolve 必须覆盖整份 provider", exp.rules.all { it.noResolve })
    }

    @Test
    fun fetchFailureFallsBackToCacheWhenAvailable() = runBlocking {
        val cache = MemoryCache()
        cache.entries["https://example.com/ads.txt"] =
            ClashRuleSets.CachedProvider("cached.example", etag = "\"v1\"")
        val exp = ClashRuleSets.expand(
            rules = listOf(ref("ads")),
            defs = listOf(def("ads", "domain")),
            cache = cache,
        ) { _, _ -> throw RuntimeException("offline") }
        assertEquals(1, exp.rules.size)
        assertEquals("cached.example", exp.rules.single().value)
        assertEquals("cached", exp.statuses.single().state)
        assertTrue(exp.warnings.any { it.contains("继续使用上一份缓存") })
    }

    @Test
    fun firstLoadFailureWithoutCacheIsPendingAndExplicit() = runBlocking {
        val exp = ClashRuleSets.expand(
            rules = listOf(ref("ads")),
            defs = listOf(def("ads", "domain")),
            cache = MemoryCache(),
        ) { _, _ -> throw RuntimeException("offline") }
        assertTrue(exp.rules.isEmpty())
        assertEquals("pending", exp.statuses.single().state)
        assertTrue(exp.statuses.single().message.contains("无缓存"))
        assertTrue(exp.warnings.any { it.contains("首次加载失败且无缓存") })
    }

    @Test
    fun notModifiedReusesCacheAndReportsCachedState() = runBlocking {
        val cache = MemoryCache()
        cache.entries["https://example.com/ads.txt"] =
            ClashRuleSets.CachedProvider("cached.example", etag = "\"v1\"")
        val exp = ClashRuleSets.expand(
            rules = listOf(ref("ads")),
            defs = listOf(def("ads", "domain")),
            cache = cache,
        ) { _, headers ->
            assertEquals("\"v1\"", headers["If-None-Match"])
            Actions.FetchResult("", emptyMap(), status = 304)
        }
        assertEquals("cached", exp.statuses.single().state)
        assertEquals(1, exp.rules.size)
    }

    @Test
    fun missingAndUnsupportedProvidersAreReportedWithoutCrashing() = runBlocking {
        val exp = ClashRuleSets.expand(
            rules = listOf(ref("missing"), ref("bad")),
            defs = listOf(def("bad", "binary")),
            cache = MemoryCache(),
        ) { _, _ -> Actions.FetchResult("x", emptyMap()) }
        assertTrue(exp.rules.isEmpty())
        assertEquals(setOf("missing", "unsupported"), exp.statuses.map { it.state }.toSet())
    }

    @Test
    fun yamlPayloadStyleProviderIsSupported() = runBlocking {
        val exp = ClashRuleSets.expand(
            rules = listOf(ref("ads", "block")),
            defs = listOf(def("ads", "domain")),
            cache = MemoryCache(),
        ) { _, _ ->
            Actions.FetchResult(
                "payload:\n  - '+.ads.example'\n  - '.tracker.example'\n  - '*.cdn-ad.example'\n",
                emptyMap(),
            )
        }
        assertEquals(3, exp.rules.size)
        assertEquals(listOf("ads.example", "tracker.example"), exp.rules.take(2).map { it.value })
        assertEquals("DOMAIN-WILDCARD", exp.rules[2].type)
    }

    @Test
    fun classicalPayloadKeepsLineNoResolveAndSkipsUnsupportedLines() = runBlocking {
        val exp = ClashRuleSets.expand(
            rules = listOf(ref("classic")),
            defs = listOf(def("classic", "classical")),
            cache = MemoryCache(),
        ) { _, _ ->
            Actions.FetchResult(
                "DOMAIN-SUFFIX,ads.example\nIP-CIDR,1.2.3.0/24,no-resolve\nPROCESS-NAME, chrome\n",
                emptyMap(),
            )
        }
        assertEquals(2, exp.rules.size)
        assertTrue(exp.rules.any { it.type == "IP-CIDR" && it.noResolve })
    }
}
