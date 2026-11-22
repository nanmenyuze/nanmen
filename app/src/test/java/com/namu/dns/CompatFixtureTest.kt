package com.namu.dns

import com.namu.dns.core.config.ConfigFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 兼容性基线：只验证当前解析器对固定样本的“现状”，不声称已经实现 Loon 全量能力。
 * 样本路径为仓库根目录 compat/fixtures；单元测试工作目录是 app 模块。
 */
class CompatFixtureTest {
    private fun fixture(path: String): String {
        val candidates = listOf(
            File("../compat/fixtures/$path"),
            File("compat/fixtures/$path"),
        )
        val file = candidates.firstOrNull { it.isFile }
            ?: error("fixture not found: $path (cwd=${File(".").absolutePath})")
        return file.readText()
    }

    @Test
    fun `surge module parses only supported subset`() {
        val parsed = ModuleParser.parse(fixture("modules/surge-demo.sgmodule"))
        println(
            "surge: name=${parsed.name} blocks=${parsed.blockLines.size} routes=${parsed.routeRules.size} " +
                "mitm=${parsed.mitmHostnames.size} url=${parsed.urlRewrites.size} header=${parsed.headerRewrites.size} ignored=${parsed.ignored}",
        )
        assertEquals("Compat Surge Demo", parsed.name)
        assertEquals(1, parsed.blockLines.size)
        // M5 补齐 DOMAIN-WILDCARD/GEOIP 后，样本中这两条不再被跳过。
        assertEquals(6, parsed.routeRules.size)
        assertEquals(2, parsed.mitmHostnames.size)
        assertEquals(4, parsed.urlRewrites.size)
        assertEquals(3, parsed.headerRewrites.size)
        // 规则集增量后：RULE-SET 行解析为规则集引用，不再计入 ignored（5→4）。
        assertEquals(1, parsed.ruleSets.size)
        assertEquals("https://example.com/rules.txt", parsed.ruleSets[0].url)
        assertEquals(3, parsed.ignored)
    }

    @Test
    fun `loon plugin is parsed as partial module`() {
        val parsed = ModuleParser.parse(fixture("modules/loon-demo.plugin"))
        println(
            "loon: name=${parsed.name} blocks=${parsed.blockLines.size} routes=${parsed.routeRules.size} " +
                "mitm=${parsed.mitmHostnames.size} ignored=${parsed.ignored}",
        )
        assertEquals("Compat Loon Plugin", parsed.name)
        assertEquals(1, parsed.blockLines.size)
        assertEquals(3, parsed.routeRules.size)
        assertEquals(1, parsed.mitmHostnames.size)
        // General/Argument 已接入；只有无法解析成 script-path 的 Script 行仍计为未执行。
        assertEquals(1, parsed.ignored)
        assertEquals(1, parsed.loonRewrites.size)
        assertTrue(parsed.sectionStatus.any { it.section == "Rewrite" && it.status == "stored" })
        assertTrue(parsed.sectionStatus.any { it.section == "Script" && it.status == "unsupported" })
        // fixture 里的 Script 是旧式 `script(...)` 动作，没有 script-path，仍应明确报缺口。
        assertTrue(parsed.dependencies.any { it.contains("脚本") })
    }

    @Test
    fun `loon rewrite separates supported actions from gaps`() {
        val parsed = ModuleParser.parse(
            """
            [Rewrite]
            ^https://api\.example\.com/feed response-body-replace-regex "ad" ""
            request if ${'$'}{url} ~= /^https:\/\/api\.example\.com\/ad/ then redirect(302, "https://example.com/")
            ^https://api\.example\.com/x response-body-json-jq 'del(.data.ad)'
            ^https://api\.example\.com/y mock-response-body data-type=json data-path=response.json
            """.trimIndent(),
        )
        assertEquals(4, parsed.loonRewrites.size)
        assertEquals(0, parsed.ignored)
        val rewrite = parsed.sectionStatus.first { it.section == "Rewrite" }
        assertEquals(4, rewrite.lines)
        assertEquals(4, rewrite.supported)
        assertEquals("stored", rewrite.status)
    }

    @Test
    fun `adblock fixture parses supported line forms`() {
        val parsed = ModuleParser.parse(fixture("rulesets/ads.txt"))
        println("adblock: blocks=${parsed.blockLines} ignored=${parsed.ignored}")
        assertEquals(3, parsed.blockLines.size)
        assertEquals(0, parsed.ignored)
        assertTrue(parsed.blockLines.contains("|exact.example.net|"))
    }


    @Test
    fun `adblock allow and exact forms are preserved`() {
        val parsed = ModuleParser.parse(
            """
            ||suffix.example.com^
            |exact.example.net|
            @@||allowed.example.org^
            @@|allowed.example.net|
            0.0.0.0 hosts.example.io
            """.trimIndent(),
        )
        assertEquals(3, parsed.blockLines.size)
        assertEquals(2, parsed.allowLines.size)
        assertEquals(0, parsed.ignored)
        assertTrue(parsed.blockLines.contains("||suffix.example.com^"))
        assertTrue(parsed.blockLines.contains("|exact.example.net|"))
        assertTrue(parsed.allowLines.contains("@@||allowed.example.org^"))
        assertTrue(parsed.allowLines.contains("@@|allowed.example.net|"))
    }

    @Test
    fun `invalid adblock syntax and conditional options are counted`() {
        val parsed = ModuleParser.parse(
            """
            ||ok.example.com^
            ||bad..com^
            ||cond.example.com^${'$'}third-party
            """.trimIndent(),
        )
        assertEquals(1, parsed.blockLines.size)
        assertEquals(2, parsed.ignored)
        assertEquals(1, parsed.ignoredReasons["invalid_adblock"])
        assertEquals(1, parsed.ignoredReasons["unsupported_adblock_option"])
    }

    @Test
    fun `domain regex and port are validated and route targets surfaced`() {
        val parsed = ModuleParser.parse(
            """
            [Rule]
            DOMAIN-REGEX,^ad[0-9]+\.example\.com$,REJECT
            PORT,8443,PROXY
            PORT,0,PROXY
            DOMAIN-SUFFIX,ads.example.com,MissingGroup
            """.trimIndent(),
        )
        assertEquals(2, parsed.routeRules.size)
        assertTrue(parsed.routeRules.any { it.type == "DOMAIN-REGEX" })
        assertTrue(parsed.routeRules.any { it.type == "PORT" && it.value == "8443" })
        assertEquals(2, parsed.ignored)
        assertTrue(parsed.lostRouteTargets.contains("MissingGroup"))
    }

    @Test
    fun `subscription userinfo fixture is parsed`() {
        val raw = fixture("headers/subscription-userinfo.txt").substringAfter(':').trim()
        val info = Actions.parseSubscriptionUserInfo(raw, now = 123L)!!
        assertEquals(100L, info.upload)
        assertEquals(600L, info.download)
        assertEquals(1000L, info.total)
        assertEquals(1700000000000L, info.expireAt)
        assertEquals(300L, info.remaining)
        assertEquals(123L, info.updatedAt)
    }

    @Test
    fun `app config fixtures parse as expected`() {
        val nested = ConfigFile.fromExternal(fixture("configs/app-config.json"), AppConfig())!!
        assertEquals(3, nested.rules.size)
        assertEquals("DOMAIN-REGEX", nested.rules[0].type)
        assertEquals("""^ad[0-9]+\.example\.com$""", nested.rules[0].value)
        assertEquals("block", nested.rules[0].action)

        val legacy = ConfigFile.fromExternal(fixture("configs/legacy-flat.json"), AppConfig())!!
        assertEquals(1, legacy.rules.size)
        assertEquals("DOMAIN-SUFFIX", legacy.rules[0].type)
        assertEquals("ads.example.com", legacy.rules[0].value)
        assertEquals("block", legacy.rules[0].action)
    }


    @Test
    fun `loon argument declarations carry types into scripts and rewrite expansion`() {
        val parsed = ModuleParser.parse(
            """
            [Argument]
            enabled = switch,true
            ratio = input,9.99,type=number
            region = select,"CN","US",type=string
            broken = input,abc,type=number
            [Rewrite]
            request if ${'$'}{url} ~= /^https:\/\/api\.example\.com\/x/ && ${'$'}{enabled} == true then request.header.add("X-Test","1")
            [Script]
            request if ${'$'}{url} ~= /^https:\/\/api\.example\.com\/feed/ then script("https://cdn.example.com/feed.js", {${'$'}{enabled}}) with requires_body=true, timeout=5, tag="feed"
            """.trimIndent(),
        )
        assertEquals("true", parsed.arguments["enabled"])
        assertEquals("9.99", parsed.arguments["ratio"])
        assertEquals("CN", parsed.arguments["region"])
        assertEquals("abc", parsed.arguments["broken"])
        assertEquals("boolean", parsed.argumentTypes["enabled"])
        assertEquals("number", parsed.argumentTypes["ratio"])
        assertEquals("string", parsed.argumentTypes["region"])
        // number 默认值非法时降为 string，避免内核注入 NaN。
        assertEquals("string", parsed.argumentTypes["broken"])
        // Rewrite 里的参数引用不再编译期展开，避免拼进正则/URL。
        assertTrue(parsed.loonRewrites.single().contains("${'$'}{enabled}"))
        val script = parsed.scripts.single()
        assertEquals("request", script.phase)
        assertEquals("""^https:\/\/api\.example\.com\/feed""", script.pattern)
        assertEquals("feed", script.name)
        assertTrue(script.requiresBody)
        assertEquals(5000, script.timeoutMs)
        assertEquals("boolean", script.argumentTypes["enabled"])
    }

    @Test
    fun `loon script v2 cron is scheduled and compound condition is passed to kernel`() {
        val parsed = ModuleParser.parse(
            """
            [Script]
            cron "0 8 * * *" script("https://cdn.example.com/daily.js")
            request if ${'$'}{url} ~= /^https:\/\/api\.example\.com\/x/ && ${'$'}{request.header['X']} == "1" then script("https://cdn.example.com/x.js")
            """.trimIndent(),
        )
        assertEquals(2, parsed.scripts.size)
        assertEquals(0, parsed.scriptIssues.size)
        val cron = parsed.scripts.first { it.cron == "0 8 * * *" }
        assertEquals("cron", cron.phase)
        assertEquals(".*", cron.pattern)
        val script = parsed.scripts.first { it.phase == "request" }
        assertTrue(script.pattern.startsWith("^https"))
        assertTrue(script.condition.contains("request.header['X']"))
    }

    @Test
    fun `websocket rewrite section keeps own syntax and rejects unknown actions`() {
        val parsed = ModuleParser.parse(
            """
            [WebSocket Rewrite]
            ws-block ^https://api.example.com/blocked
            ws-text-replace ^https://api.example.com/ws "foo" "bar"
            ws-redirect ^https://api.example.com/ws
            """.trimIndent(),
        )
        assertEquals(2, parsed.wsRewrites.size)
        assertTrue(parsed.wsRewrites.any { it.startsWith("ws-block") })
        assertTrue(parsed.wsRewrites.any { it.startsWith("ws-text-replace") })
        assertTrue(parsed.ignoredReasons.containsKey("unsupported_websocket_action"))
        assertTrue(parsed.sectionStatus.any { it.section == "WebSocket Rewrite" && it.status == "stored" })
    }

    @Test
    fun `map local inline data becomes mock and file path is reported`() {
        val parsed = ModuleParser.parse(
            """
            [Map Local]
            ^https://api.example.com/ad data-type=json data={"code":0,"msg":"ok"} status-code=200 header=Content-Type:application/json
            ^https://api.example.com/file data-path=/tmp/mock.json
            [Map Remote]
            ^https://old.example.com/ https://new.example.com/
            """.trimIndent(),
        )
        assertEquals(3, parsed.loonRewrites.size)
        assertTrue(parsed.loonRewrites.any { it.contains("mock-response-body") && it.contains("status-code=200") && it.contains("header=") })
        assertTrue(parsed.loonRewrites.any { it.contains("data-path=") })
        assertTrue(parsed.loonRewrites.any { it.contains("https://new.example.com/") })
        assertTrue(!parsed.ignoredReasons.containsKey("unsupported_map_local_data_path"))
        assertTrue(!parsed.ignoredReasons.containsKey("unsupported_map_remote"))
        assertTrue(parsed.sectionStatus.any { it.section == "Map Local" && it.status == "executed" })
        assertTrue(parsed.sectionStatus.any { it.section == "Map Remote" && it.status == "executed" })
    }

    @Test
    fun `general mitm skip and arguments are parsed`() {
        val parsed = ModuleParser.parse(
            """
            [General]
            skip-proxy = 192.168.0.0/16, localhost
            dns-server = 223.5.5.5
            [Argument]
            region = select,"CN","US",tag=Region
            [Mitm]
            hostname = %APPEND% api.example.com, *.example.net
            skip = bank.example.com
            tcp-connection = true
            [Script]
            response if ${'$'}{url} ~= /^https:\/\/api\.example\.com\// && ${'$'}{request.method} == GET then script("https://example.com/a.js")
            """.trimIndent(),
        )
        assertEquals(2, parsed.generalOptions.size)
        assertEquals("223.5.5.5", parsed.generalOptions["dns-server"])
        assertEquals(setOf("api.example.com", "*.example.net"), parsed.mitmHostnames.toSet())
        assertEquals(listOf("bank.example.com"), parsed.mitmSkipHostnames)
        assertEquals("true", parsed.mitmOptions["tcp-connection"])
        assertEquals("CN", parsed.arguments["region"])
        assertEquals("string", parsed.argumentTypes["region"])
        assertEquals(0, parsed.ignored)
        assertTrue(parsed.sectionStatus.any { it.section == "General" && it.status == "stored" })
        assertTrue(parsed.sectionStatus.any { it.section == "Argument" && it.status == "executed" })
        assertTrue(parsed.sectionStatus.any { it.section == "MITM" && it.status == "executed" })
    }
}
