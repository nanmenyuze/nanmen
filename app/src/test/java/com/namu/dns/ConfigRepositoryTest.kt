package com.namu.dns

import com.namu.dns.core.config.ConfigFile
import com.namu.dns.core.repository.ConfigEntry
import com.namu.dns.core.repository.ConfigFileGateway
import com.namu.dns.core.repository.DefaultConfigRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigRepositoryTest {
    private class FakeGateway : ConfigFileGateway {
        val files = linkedMapOf<String, String>()

        override fun ensureDefault(cfg: AppConfig) {
            files.putIfAbsent(ConfigFileStore.DEFAULT_NAME, ConfigFile.fromAppConfig(cfg).toJson())
        }

        override fun list(active: String): List<ConfigEntry> = files.keys.map {
            ConfigEntry(it, 1L, 1L, it == active, it == ConfigFileStore.DEFAULT_NAME)
        }

        override fun load(name: String, current: AppConfig): AppConfig? =
            files[name]?.let { ConfigFile.fromJson(it).toAppConfig(current) }

        override fun save(name: String, cfg: AppConfig): Boolean {
            files[name] = ConfigFile.fromAppConfig(cfg).toJson()
            return true
        }

        override fun exists(name: String): Boolean = files.containsKey(name)

        override fun delete(name: String): Boolean {
            if (name == ConfigFileStore.DEFAULT_NAME) return false
            return files.remove(name) != null
        }
    }

    @Test
    fun `switch replaces config and keeps nodes, then fires applied`() {
        val settings = FakeSettingsRepository(
            AppConfig(mode = "dns_only", nodes = listOf(NodeInfo("n", "ss", "1.2.3.4", 8388)), selected = "n"),
        )
        val gateway = FakeGateway().apply { ensureDefault(settings.current()) }
        gateway.files["work.conf"] = ConfigFile.fromAppConfig(
            AppConfig(mode = "global", rules = listOf(RuleItem("DOMAIN", "work.example", "proxy"))),
        ).toJson()
        var applied: AppConfig? = null
        val repo = DefaultConfigRepository(settings, gateway, onApplied = { applied = it })

        assertTrue(repo.switchTo("work.conf"))
        assertEquals("work.conf", settings.activeConfigName())
        assertEquals("global", settings.current().mode)
        assertEquals(listOf(RuleItem("DOMAIN", "work.example", "proxy")), settings.current().rules)
        assertEquals(listOf(NodeInfo("n", "ss", "1.2.3.4", 8388)), settings.current().nodes)
        assertEquals("n", settings.current().selected)
        assertEquals("global", applied?.mode)
    }

    @Test
    fun `default cannot be deleted and active delete falls back`() {
        val settings = FakeSettingsRepository(AppConfig(mode = "dns_only"))
        val gateway = FakeGateway().apply { ensureDefault(settings.current()) }
        var applied = 0
        val repo = DefaultConfigRepository(settings, gateway, onApplied = { applied++ })

        assertFalse(repo.delete(ConfigFileStore.DEFAULT_NAME))

        gateway.files["tmp.conf"] = ConfigFile.fromAppConfig(AppConfig(mode = "global")).toJson()
        assertTrue(repo.switchTo("tmp.conf"))
        applied = 0

        assertTrue(repo.delete("tmp.conf"))
        assertEquals(ConfigFileStore.DEFAULT_NAME, settings.activeConfigName())
        assertEquals("dns_only", settings.current().mode)
        assertEquals(1, applied)
        assertFalse(gateway.exists("tmp.conf"))
    }

    @Test
    fun `create and import reject duplicates`() {
        val settings = FakeSettingsRepository(AppConfig(mode = "global", dnsUpstream = "https://a.example/dns-query"))
        val gateway = FakeGateway().apply { ensureDefault(settings.current()) }
        val repo = DefaultConfigRepository(settings, gateway)

        assertTrue(repo.create("new.conf"))
        assertTrue(gateway.exists("new.conf"))
        assertFalse(repo.create("new.conf"))

        val nested = ConfigFile.fromAppConfig(AppConfig(mode = "rule", customAds = listOf("x.example.com"))).toJson()
        assertTrue(repo.import("imported.conf", nested))
        assertFalse(repo.import("imported.conf", nested))
        val loaded = gateway.load("imported.conf", settings.current())
        assertEquals("rule", loaded?.mode)
        assertEquals(listOf("x.example.com"), loaded?.customAds)
    }
    @Test
    fun `editing or importing backup profile leaves current profile untouched`() {
        val original = AppConfig(themeMode = "dark", autoConnect = true, pingMethod = "http")
        val settings = FakeSettingsRepository(original)
        val files = FakeGateway().apply { ensureDefault(original) }
        val originalText = files.files.getValue(ConfigFileStore.DEFAULT_NAME)
        var applied = 0
        val repository = DefaultConfigRepository(settings, files, onApplied = { applied++ })
        val imported = """
            {"general":{"dnsUpstream":"system","themeMode":"light","autoConnect":false,"pingMethod":"tcp"}}
        """.trimIndent()
        assertTrue(repository.import("backup.conf", imported))
        repository.saveProfile("backup.conf") {
            it.copy(
                dnsUpstream = "https://dns.example/query",
                mitm = it.mitm.copy(enabled = true, hostMappings = mapOf("nas.home" to "192.168.1.2")),
            )
        }
        assertEquals(ConfigFileStore.DEFAULT_NAME, repository.activeName())
        assertEquals(originalText, files.files[ConfigFileStore.DEFAULT_NAME])
        assertEquals(original, settings.current())
        assertEquals(0, applied)

        assertTrue(repository.switchTo("backup.conf"))
        assertEquals("https://dns.example/query", settings.current().dnsUpstream)
        assertTrue(settings.current().mitm.enabled)
        assertEquals("192.168.1.2", settings.current().mitm.hostMappings["nas.home"])
        assertEquals("dark", settings.current().themeMode)
        assertEquals("http", settings.current().pingMethod)
        assertTrue(settings.current().autoConnect)
        assertEquals(1, applied)
    }

}
