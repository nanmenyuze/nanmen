package com.namu.dns

import com.namu.dns.core.config.ConfigFile
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ConfigFileMigrationTest {
    @get:Rule
    val tmp = TemporaryFolder()


    @Test
    fun `version one config is upgraded and backup is retained`() {
        val dir = tmp.newFolder("v1")
        val current = AppConfig()
        val v1 = JSONObject(ConfigFile.fromAppConfig(current).toJson()).put("version", 1)
        dir.resolve("v1.conf").writeText(v1.toString())
        dir.resolve(ConfigFileStore.DEFAULT_NAME).writeText(v1.toString())

        val result = ConfigFileMigration.migrate(dir, current)
        assertEquals(2, result.migrated)
        assertEquals(2, result.scanned)
        val upgraded = JSONObject(dir.resolve("v1.conf").readText())
        assertEquals(ConfigFile.CURRENT_VERSION, upgraded.optInt("version"))
        assertTrue(dir.resolve("v1.conf.legacy.bak").exists())
    }

    @Test
    fun `recover removes stale tmp and restores missing target from backup`() {
        val dir = tmp.newFolder("recover")
        val target = dir.resolve("active.conf")
        val backup = dir.resolve("active.conf.legacy.bak")
        val tmp = dir.resolve("active.conf.tmp")
        val valid = ConfigFile.fromAppConfig(AppConfig()).toJson()
        target.writeText(valid)
        backup.writeText(valid)
        tmp.writeText("{broken")
        val first = ConfigFileMigration.recover(dir)
        assertEquals(1, first.recovered)
        assertTrue(!tmp.exists())

        assertTrue(target.delete())
        assertTrue(backup.exists())
        val second = ConfigFileMigration.recover(dir)
        assertEquals(1, second.restored)
        assertTrue(target.exists())
        assertEquals(ConfigFile.CURRENT_VERSION, JSONObject(target.readText()).optInt("version"))
    }

    @Test
    fun `recover restores truncated target`() {
        val dir = tmp.newFolder("truncated")
        val target = dir.resolve("truncated.conf")
        val backup = dir.resolve("truncated.conf.legacy.bak")
        val valid = ConfigFile.fromAppConfig(AppConfig()).toJson()
        target.writeText("{broken")
        backup.writeText(valid)
        val result = ConfigFileMigration.recover(dir)
        assertEquals(1, result.restored)
        assertTrue(target.readText().contains("general"))
    }

    @Test
    fun `legacy conf gets general and migration is idempotent`() {
        val dir = tmp.newFolder("configs")
        val current = AppConfig(
            mode = "global",
            dnsUpstream = "https://current.example/dns-query",
            blockTtl = 30,
            nodes = listOf(NodeInfo("node", "ss", "1.2.3.4", 8388)),
            selected = "node",
        )
        val legacy = JSONObject().apply {
            put("mode", "dns_only")
            put("rules", JSONArray().apply {
                put(RuleItem("DOMAIN-SUFFIX", "legacy.example", "proxy").toJson())
            })
            put("customAds", JSONArray().apply { put("ads.legacy.example") })
        }
        dir.resolve("old.conf").writeText(legacy.toString())

        val first = ConfigFileMigration.migrate(dir, current)
        assertEquals(2, first.scanned) // 新建 default + old
        assertEquals(2, first.migrated)
        assertTrue(first.createdDefault)

        val migrated = ConfigFile.fromJson(dir.resolve("old.conf").readText())
        assertEquals("dns_only", migrated.general.mode) // 旧文件已有键优先
        assertEquals("https://current.example/dns-query", migrated.general.dnsUpstream) // 缺失字段用全局补齐
        assertEquals(1, migrated.rules.size)
        assertEquals("legacy.example", migrated.rules.single().value)
        assertEquals(listOf("ads.legacy.example"), migrated.customAds)

        val default = ConfigFile.fromJson(dir.resolve(ConfigFileStore.DEFAULT_NAME).readText())
        assertEquals("global", default.general.mode)
        assertEquals(30, default.general.blockTtl)

        val second = ConfigFileMigration.migrate(dir, current)
        assertEquals(2, second.scanned)
        assertEquals(0, second.migrated)
        assertEquals(2, second.skipped)
        assertTrue(dir.resolve("old.conf.legacy.bak").exists())
    }
}
