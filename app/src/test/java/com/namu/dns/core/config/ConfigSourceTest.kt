package com.namu.dns

import com.namu.dns.core.config.ConfigFormat
import com.namu.dns.core.config.ConfigSourceRegistry
import com.namu.dns.core.config.ConfigIssueLevel
import com.namu.dns.core.config.ConfigFile
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigSourceTest {
    @Test
    fun `native json keeps unknown root and locates duplicate ids`() {
        val root = JSONObject(ConfigFile.fromAppConfig(AppConfig()).toJson())
        root.put("futureSection", JSONObject().put("enabled", true))
        root.put(
            "ruleSources",
            JSONArray()
                .put(JSONObject().put("id", "same").put("url", "https://a.example/ads.txt"))
                .put(JSONObject().put("id", "same").put("url", "https://b.example/ads.txt")),
        )
        val preview = ConfigSourceRegistry.preview(root.toString())
        assertEquals(ConfigFormat.NATIVE, preview.format)
        assertFalse(preview.canImport)
        assertTrue(preview.unknown.contains("futureSection"))
        assertTrue(preview.issues.any { it.level == ConfigIssueLevel.ERROR && it.path.contains("ruleSources") })
    }

    @Test
    fun `clash preview locates duplicate names and missing group member`() {
        val text = """
            mixed-port: 7890
            proxies:
              - name: n1
                type: ss
              - name: n1
                type: ss
            proxy-groups:
              - name: g1
                type: select
                proxies:
                  - n1
                  - missing
            rules:
              - DOMAIN,ad.example.com,REJECT
            script:
              - foo.js
        """.trimIndent()
        val preview = ConfigSourceRegistry.preview(text)
        assertEquals(ConfigFormat.CLASH, preview.format)
        assertFalse(preview.canImport)
        assertTrue(preview.issues.any { it.level == ConfigIssueLevel.ERROR && it.message.contains("重复节点名") })
        assertTrue(preview.issues.any { it.level == ConfigIssueLevel.ERROR && it.path.contains("proxy-groups") })
        assertTrue(preview.unknown.contains("script"))
    }


    @Test
    fun `valid clash rules can import but keep nodes out of config file`() {
        val text = """
            mode: rule
            mixed-port: 7890
            proxies:
              - name: n1
                type: ss
            proxy-groups:
              - name: g1
                type: select
                proxies:
                  - n1
            rules:
              - DOMAIN-SUFFIX,ad.example.com,REJECT
              - DOMAIN,ads.example.com,g1
              - MATCH,DIRECT
        """.trimIndent()
        val result = ConfigSourceRegistry.parse(text)
        assertEquals(ConfigFormat.CLASH, result.preview.format)
        assertTrue(result.preview.canImport)
        assertEquals(2, result.preview.rules)
        assertEquals(2, result.config?.rules?.size)
        assertEquals("g1", result.config?.rules?.get(1)?.action)
        assertEquals("g1", result.config?.proxyGroups?.single()?.name)
        assertEquals("direct", result.config?.general?.finalPolicy)
        assertEquals(ConfigFile.SOURCE_CLASH, result.config?.sourceFormat)
    }

    @Test
    fun `loon imports nodes groups rules and dns`() {
        val text = """
            [General]
            dns-server = https://dns.alidns.com/dns-query
            dns-fallback = 223.5.5.5
            ipv6 = false
            [Proxy]
            node = ss, 1.2.3.4, 8388, aes-128-gcm, pass
            [Proxy Group]
            Proxy = select, node
            [Rule]
            DOMAIN,ad.example.com,REJECT
            DOMAIN,unknown.example.com,missing-policy
            DOMAIN-SUFFIX,bad.example.com,Proxy
            DOMAIN-WILDCARD,*.track.example.com,REJECT
            FINAL,Proxy
            [Script]
            script.js
        """.trimIndent()
        val result = ConfigSourceRegistry.parse(text)
        val preview = result.preview
        assertEquals(ConfigFormat.LOON, preview.format)
        assertTrue(preview.canImport)
        assertEquals(1, preview.nodes)
        assertEquals(1, preview.groups)
        assertEquals(4, preview.rules)
        assertEquals(1, result.nodes.size)
        assertEquals("ss", result.nodes.single().type)
        assertEquals("Proxy", result.config?.proxyGroups?.single()?.name)
        assertEquals("Proxy", result.config?.general?.finalPolicy)
        assertEquals("https://dns.alidns.com/dns-query", result.config?.general?.dnsUpstream)
        assertEquals(true, result.config?.general?.blockAaaa)
        assertTrue(preview.issues.any { it.level == ConfigIssueLevel.WARNING && it.path.startsWith("[Rule] line") })
        assertTrue(preview.unknown.contains("Script"))
        assertTrue(result.config?.rules?.any { it.type == "DOMAIN-WILDCARD" } == true)
    }

    @Test
    fun `loon imports process and uid rules as app rules`() {
        val text = """
            [Proxy]
            node = ss, 1.2.3.4, 8388, aes-128-gcm, pass
            [Rule]
            PROCESS-NAME,com.example.app,REJECT
            UID,10001,REJECT
            DOMAIN,ad.example.com,REJECT
        """.trimIndent()
        val result = ConfigSourceRegistry.parse(text)
        // 按 App 分流已支持：包名类规则保留包名，下发内核前由壳层解析成 UID。
        val types = result.config?.rules?.map { it.type } ?: emptyList()
        assertTrue(types.contains("PROCESS-NAME"))
        assertTrue(types.contains("UID"))
        assertEquals(
            "com.example.app",
            result.config?.rules?.first { it.type == "PROCESS-NAME" }?.value,
        )
    }

    @Test
    fun `non numeric uid value is rejected instead of silently kept`() {
        val text = """
            [Rule]
            UID,com.example.app,REJECT
        """.trimIndent()
        val result = ConfigSourceRegistry.parse(text)
        // 包名写进 UID 字段是用户常见笔误，必须报错而不是下发一条永不命中的规则。
        assertTrue(result.preview.issues.any { it.level == ConfigIssueLevel.ERROR && it.message.contains("必须是数字") })
    }

    @Test
    fun `shadowrocket imports its supported subset`() {
        val text = """
            [General]
            dns-server = https://doh.pub/dns-query
            [Proxy]
            node = ss, 1.2.3.4, 8388, aes-128-gcm, pass
            [Rule]
            DOMAIN,ad.example.com,REJECT
            [URL Rewrite]
            ^http://example.com https://example.com
        """.trimIndent()
        val result = ConfigSourceRegistry.parse(text)
        assertEquals(ConfigFormat.SHADOWROCKET, result.preview.format)
        assertTrue(result.preview.canImport)
        assertEquals(1, result.preview.nodes)
        assertEquals(1, result.nodes.size)
        assertEquals("https://doh.pub/dns-query", result.config?.general?.dnsUpstream)
        assertTrue(result.preview.partial.any { it.contains("URL Rewrite") })
        assertEquals(ConfigFile.SOURCE_SHADOWROCKET, result.config?.sourceFormat)
    }

    @Test
    fun `native json can import when no errors`() {
        val preview = ConfigSourceRegistry.preview(ConfigFile.fromAppConfig(AppConfig()).toJson())
        assertEquals(ConfigFormat.NATIVE, preview.format)
        assertTrue(preview.canImport)
    }
}
