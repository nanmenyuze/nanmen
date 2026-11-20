package com.namu.dns

import com.namu.dns.core.config.ConfigFile
import com.namu.dns.core.config.MitmConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * M1（MITM-Ready 数据模型 + 模块解析）TDD 测试。
 * 目标：外壳先把 MITM 的数据形状定死，内核 1.11 接入后零结构调整。
 * 这些用例先于实现编写（RED），实现后应全部通过（GREEN）。
 */
class MitmConfigTest {

    @Test
    fun `mitm defaults are disabled and empty`() {
        val m = MitmConfig()
        assertFalse(m.enabled)
        assertTrue(m.hostnames.isEmpty())
        assertTrue(m.skipHostnames.isEmpty())
        assertTrue(m.urlRewrites.isEmpty())
        assertTrue(m.headerRewrites.isEmpty())
    }

    @Test
    fun `config file mitm section round trips`() {
        val cfg = ConfigFile(
            mitm = MitmConfig(
                enabled = true,
                hostnames = listOf("*.example.com", "api.test.com"),
                skipHostnames = listOf("*.bank.com"),
                urlRewrites = listOf("^https?://ad\\.test/ reject"),
                headerRewrites = listOf("api.test.com request-header-del X-Ad"),
            ),
        )
        val decoded = ConfigFile.fromJson(cfg.toJson())
        assertEquals(cfg.mitm, decoded.mitm)
    }

    @Test
    fun `legacy flat json without mitm gets defaults`() {
        val legacy = AppConfig().toJson().toString()
        val cfg = ConfigFile.fromJson(legacy)
        assertEquals(MitmConfig(), cfg.mitm)
    }

    @Test
    fun `new format json without mitm key gets defaults`() {
        val text = """{"general":{"mode":"rule"},"rules":[]}"""
        val cfg = ConfigFile.fromJson(text)
        assertEquals(MitmConfig(), cfg.mitm)
    }

    @Test
    fun `config file copy preserves mitm from app config`() {
        val app = AppConfig().copy(
            mitm = MitmConfig(enabled = true, hostnames = listOf("*.example.com")),
        )
        val file = ConfigFile.fromAppConfig(app)
        val applied = file.toAppConfig(AppConfig())
        assertEquals(app.mitm, applied.mitm)
    }

    @Test
    fun `app config mitm round trips through json`() {
        val cfg = AppConfig().copy(
            mitm = MitmConfig(enabled = true, hostnames = listOf("*.a.com")),
        )
        val decoded = AppConfig.fromJson(cfg.toJson().toString())
        assertEquals(cfg.mitm, decoded.mitm)
    }

    @Test
    fun `module parser reads mitm hostname assignment`() {
        val module = """
            #!name=去广告
            [MITM]
            hostname = *.example.com, api.test.com
            [URL Rewrite]
            ^https?://ad\.test/ reject
        """.trimIndent()
        val parsed = ModuleParser.parse(module)
        assertEquals(listOf("*.example.com", "api.test.com"), parsed.mitmHostnames)
        assertEquals(listOf("^https?://ad\\.test/ reject"), parsed.urlRewrites)
    }

    @Test
    fun `module parser reads bare mitm hostname lines`() {
        val module = """
            [MITM]
            *.example.com
            api.test.com
        """.trimIndent()
        val parsed = ModuleParser.parse(module)
        assertEquals(listOf("*.example.com", "api.test.com"), parsed.mitmHostnames)
    }

    @Test
    fun `module parser captures header rewrite and ignores script`() {
        val module = """
            [MITM]
            hostname = *.example.com
            [Header Rewrite]
            example.com request-header-del X-Ad
            [Script]
            hostname = *.example.com
            script-path = https://x/y.js
        """.trimIndent()
        val parsed = ModuleParser.parse(module)
        assertEquals(listOf("example.com request-header-del X-Ad"), parsed.headerRewrites)
        // 脚本仍不支持，计入 ignored；MITM/重写不算 ignored
        assertTrue(parsed.ignored >= 1)
    }

    @Test
    fun `module parser structures loon request and response scripts`() {
        val module = """
            #!name=脚本模块
            [Argument]
            region=cn
            [Script]
            http-request ^https://api\.example\.com/v1 script-path=https://cdn.example.com/a.js requires-body=1 max-size=65536 timeout=8 tag=请求脚本
            http-response ^https://api\.example\.com/v1 script-path=https://cdn.example.com/b.js timeout=5000 tag=响应脚本
        """.trimIndent()
        val parsed = ModuleParser.parse(module)
        assertEquals(2, parsed.scripts.size)
        val req = parsed.scripts.first { it.phase == "request" }
        assertEquals("^https://api\\.example\\.com/v1", req.pattern)
        assertEquals("https://cdn.example.com/a.js", req.scriptPath)
        assertTrue(req.requiresBody)
        assertEquals(65536, req.maxSize)
        assertEquals(8000, req.timeoutMs)
        assertEquals("cn", req.arguments["region"])
        val resp = parsed.scripts.first { it.phase == "response" }
        assertFalse(resp.requiresBody)
        assertEquals(5000, resp.timeoutMs)
    }

    @Test
    fun `module parser supports key value script form`() {
        val module = """
            [Script]
            type=response, pattern=^https://api\.test\.com/, script-path=https://cdn.example.com/c.js, max-size=0, timeout=3
        """.trimIndent()
        val parsed = ModuleParser.parse(module)
        assertEquals(1, parsed.scripts.size)
        val script = parsed.scripts.single()
        assertEquals("response", script.phase)
        assertEquals("^https://api\\.test\\.com/", script.pattern)
        assertEquals(2 * 1024 * 1024, script.maxSize)
        assertEquals(3000, script.timeoutMs)
    }

    @Test
    fun `script without script path is rejected with a gap`() {
        val module = """
            [Script]
            http-request ^https://api\.example\.com/
        """.trimIndent()
        val parsed = ModuleParser.parse(module)
        assertTrue(parsed.scripts.isEmpty())
        assertTrue(parsed.scriptIssues.any { it.contains("script-path") })
        assertTrue(parsed.sectionStatus.any { it.section == "Script" && it.status == "unsupported" })
    }

    @Test
    fun `script config json uses camel case for the rust kernel`() {
        val cfg = com.namu.dns.core.config.ScriptConfig(
            name = "demo",
            phase = "request",
            pattern = "^https://api\\.test/",
            source = "\$done({});",
            arguments = mapOf("region" to "cn"),
            timeoutMs = 4000,
            maxSize = 131072,
            requiresBody = true,
            scriptPath = "https://cdn.example.com/d.js",
        )
        val o = cfg.toJsonObject()
        assertEquals(4000, o.getInt("timeoutMs"))
        assertEquals(131072, o.getInt("maxSize"))
        assertTrue(o.getBoolean("requiresBody"))
        assertEquals("cn", o.getJSONObject("arguments").getString("region"))
    }

    @Test
    fun `pure mitm module has no dns rules but carries mitm`() {
        val module = """
            #!name=纯MITM
            [MITM]
            hostname = *.example.com
            [URL Rewrite]
            ^https?://ad\.test/ reject
        """.trimIndent()
        val parsed = ModuleParser.parse(module)
        assertTrue(parsed.blockLines.isEmpty())
        assertTrue(parsed.routeRules.isEmpty())
        assertEquals(listOf("*.example.com"), parsed.mitmHostnames)
        assertEquals(1, parsed.urlRewrites.size)
    }
}
