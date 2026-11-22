package com.namu.dns

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class M7BackupTest {
    private fun sampleConfig() = AppConfig(
        mode = "rule",
        selected = "hk",
        nodes = listOf(NodeInfo("hk", "ss", "1.2.3.4", 8388)),
        rules = listOf(RuleItem("DOMAIN", "ads.example", "reject")),
    )

    private fun backup(
        schema: Int = M7Backup.SCHEMA,
        app: JSONObject = sampleConfig().toJson(),
        files: Map<String, String> = mapOf(
            "default.conf" to com.namu.dns.core.config.ConfigFile.fromAppConfig(sampleConfig()).toJson(),
        ),
        moduleFiles: Map<String, String> = emptyMap(),
        scriptFiles: Map<String, String> = emptyMap(),
        ruleSetFiles: Map<String, String> = emptyMap(),
    ): String = JSONObject().apply {
        put("schema", schema)
        put("appVersion", "2.3.7")
        put("app", app)
        put("activeConfig", "default.conf")
        put("configVersion", 3)
        put("configFiles", JSONObject().apply { files.forEach { (k, v) -> put(k, v) } })
        put("moduleFiles", JSONObject().apply { moduleFiles.forEach { (k, v) -> put(k, v) } })
        put("scriptFiles", JSONObject().apply { scriptFiles.forEach { (k, v) -> put(k, v) } })
        put("ruleSetFiles", JSONObject().apply { ruleSetFiles.forEach { (k, v) -> put(k, v) } })
    }.toString()

    @Test
    fun `inspect parses app and config files without writing`() {
        val info = M7Backup.inspect(backup())
        assertEquals("2.3.7", info.appVersion)
        assertEquals("default.conf", info.activeConfig)
        assertEquals(1, info.files.size)
        assertEquals(1, info.config.nodes.size)
        assertEquals("hk", info.config.nodes.first().name)
    }

    @Test
    fun `inspect keeps local module bodies and dependencies`() {
        val info = M7Backup.inspect(
            backup(
                moduleFiles = mapOf("module_abc123.sgmodule" to "[Rule]\nDOMAIN,ads.example,REJECT"),
                scriptFiles = mapOf("script_0123456789abcdef0123456789abcdef.js" to "console.log(1)"),
                ruleSetFiles = mapOf("ruleset_0123456789abcdef.txt" to "DOMAIN,ads.example"),
            ),
        )
        assertEquals(1, info.moduleFiles.size)
        assertEquals(1, info.scriptFiles.size)
        assertEquals(1, info.ruleSetFiles.size)
        assertTrue(info.moduleFiles["module_abc123.sgmodule"]!!.contains("ads.example"))
    }

    @Test
    fun `inspect rejects unsafe asset file names`() {
        try {
            M7Backup.inspect(backup(moduleFiles = mapOf("module_../evil.sgmodule" to "x")))
            fail("路径穿越文件名应被拒绝")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("非法文件名"))
        }
        try {
            M7Backup.inspect(backup(scriptFiles = mapOf("script_ABCDEF.js" to "x")))
            fail("非法脚本文件名应被拒绝")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("非法文件名"))
        }
    }

    @Test
    fun `inspect rejects wrong schema`() {
        try {
            M7Backup.inspect(backup(schema = 2))
            fail("schema 2 应被拒绝")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("schema=2"))
        }
    }

    @Test
    fun `inspect rejects broken config json before any write`() {
        try {
            M7Backup.inspect(backup(files = mapOf("broken.conf" to "{not json")))
            fail("坏 JSON 应被拒绝")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("broken.conf"))
        }
    }
}
