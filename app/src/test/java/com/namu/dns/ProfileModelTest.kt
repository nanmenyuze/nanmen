package com.namu.dns

import com.namu.dns.core.config.ConfigFile
import com.namu.dns.core.config.GroupValidator
import com.namu.dns.core.config.ModuleGeneral
import com.namu.dns.core.config.ModuleOrder
import com.namu.dns.core.config.SsidTrigger
import com.namu.dns.core.repository.ProfileMigration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class ProfileModelTest {
    private fun node(name: String) = NodeInfo(name, "ss", "1.1.1.1", 443, method = "aes-128-gcm", password = "x")

    @Test
    fun `group selections stay in their own profile`() {
        val cfg = AppConfig(
            nodes = listOf(node("n1"), node("n2")),
            proxyGroups = listOf(ProxyGroup("G", members = listOf("n1", "n2"))),
            groupSelections = mapOf("G" to "n2"),
        )
        val text = ConfigFile.fromAppConfig(cfg).toJson()
        val loaded = ConfigFile.fromJson(text).toAppConfig(AppConfig(nodes = cfg.nodes))
        assertEquals("n2", loaded.groupSelections["G"])
    }

    @Test
    fun `legacy file without group selections falls back to device value`() {
        val cfg = AppConfig(
            nodes = listOf(node("n1")),
            groupSelections = mapOf("G" to "n1"),
        )
        val legacy = cfg.toJson().apply { remove("groupSelections") }.toString()
        val parsed = ConfigFile.fromExternal(legacy, cfg)!!
        assertEquals(cfg.groupSelections, parsed.groupSelections)
        val applied = parsed.toAppConfig(cfg)
        assertEquals("n1", applied.groupSelections["G"])
    }

    @Test
    fun `group validator rejects orphan and cycle`() {
        val cfg = AppConfig(
            nodes = listOf(node("n1")),
            proxyGroups = listOf(
                ProxyGroup("A", members = listOf("B")),
                ProxyGroup("B", members = listOf("A")),
                ProxyGroup("C", members = listOf("missing")),
            ),
            groupSelections = mapOf("A" to "n1", "ghost" to "n1"),
        )
        val r = GroupValidator.validate("p.conf", cfg)
        assertFalse(r.ok)
        assertTrue(r.errors.any { it.code == "group_cycle" })
        assertTrue(r.errors.any { it.code == "missing_group_member" })
        assertTrue(r.warnings.any { it.code == "stale_group_selection" })
        assertEquals(3, r.groupMap.size)
    }

    @Test
    fun `module reorder only changes order and keeps enabled state`() {
        val modules = listOf(
            ModuleSource("a", "A", "", enabled = true),
            ModuleSource("b", "B", "", enabled = false),
            ModuleSource("c", "C", "", enabled = true),
        )
        val moved = ModuleOrder.move(modules, 2, 0)
        assertEquals(listOf("c", "a", "b"), moved.map { it.id })
        assertEquals(listOf(0, 1, 2), moved.map { it.order })
        assertFalse(moved.first { it.id == "b" }.enabled)
    }

    @Test
    fun `module drag target follows dragged center in both directions`() {
        val centers = listOf(60f, 160f, 260f, 360f)
        assertEquals(2, ModuleOrder.dragTarget(centers, from = 0, draggedCenter = 285f))
        assertEquals(2, ModuleOrder.dragTarget(centers, from = 3, draggedCenter = 175f))
        assertEquals(0, ModuleOrder.dragTarget(centers, from = 2, draggedCenter = 20f))
        assertEquals(3, ModuleOrder.dragTarget(centers, from = 1, draggedCenter = 500f))
    }

    @Test
    fun `module drag target waits for center crossing and rejects invalid origin`() {
        val centers = listOf(60f, 160f, 260f)
        assertEquals(0, ModuleOrder.dragTarget(centers, from = 0, draggedCenter = 159f))
        assertEquals(1, ModuleOrder.dragTarget(centers, from = 0, draggedCenter = 161f))
        assertEquals(2, ModuleOrder.dragTarget(centers, from = 2, draggedCenter = 161f))
        assertEquals(1, ModuleOrder.dragTarget(centers, from = 2, draggedCenter = 159f))
        assertEquals(-1, ModuleOrder.dragTarget(centers, from = -1, draggedCenter = 160f))
        assertEquals(-1, ModuleOrder.dragTarget(centers, from = 3, draggedCenter = 160f))
    }

    @Test
    fun `module general maps shell keys without touching kernel`() {
        val effects = ModuleGeneral.parse(
            mapOf(
                "skip-proxy" to "a.com, b.com",
                "ssid-trigger" to "\"Home\",Office",
                "proxy-test-url" to "http://test.example/",
                "test-timeout" to "5",
                "force-close-connections" to "true",
            ),
        )
        assertEquals(listOf("a.com", "b.com"), effects.skipHosts)
        assertEquals(listOf("Home", "Office"), effects.ssidTriggers)
        assertEquals(5, effects.testTimeout)
        assertTrue(effects.forceCloseConnections)
    }

    @Test
    fun `uid route parses and invalid uid is ignored`() {
        val m = ModuleParser.parse("[Rule]\nUID,10086,DIRECT\nUID,-1,PROXY")
        assertEquals(listOf(RuleItem("UID", "10086", "direct")), m.routeRules)
        assertTrue(m.ignored >= 1)
    }

    @Test
    fun `ssid matching rejects blank unknown and empty list`() {
        assertTrue(SsidTrigger.matches("Home", listOf("home")))
        assertFalse(SsidTrigger.matches("", listOf("Home")))
        assertFalse(SsidTrigger.matches("<unknown ssid>", listOf("Home")))
        assertFalse(SsidTrigger.matches("Home", emptyList()))
    }

    @Test
    fun `ssid permission follows sdk and keeps location for ssid`() {
        assertEquals("android.permission.NEARBY_WIFI_DEVICES", SsidTrigger.permissionName(33))
        assertEquals("android.permission.ACCESS_FINE_LOCATION", SsidTrigger.permissionName(32))
        assertEquals(2, SsidTrigger.requiredPermissions(33).size)
        assertTrue(SsidTrigger.requiredPermissions(33).contains("android.permission.NEARBY_WIFI_DEVICES"))
        assertTrue(SsidTrigger.requiredPermissions(33).contains("android.permission.ACCESS_FINE_LOCATION"))
        assertEquals(listOf("android.permission.ACCESS_FINE_LOCATION"), SsidTrigger.requiredPermissions(32))
    }

    @Test
    fun `profile migration dry-run applies backup and rolls back`() {
        val root = Files.createTempDirectory("profile-migration").toFile()
        val configs = File(root, "configs").apply { mkdirs() }
        val old = """{"version":3,"general":{},"rules":[{"type":"DOMAIN","value":"a.com","action":"direct"}]}"""
        File(configs, "work.conf").writeText(old)
        val fallback = AppConfig(groupSelections = mapOf("G" to "n1"))
        val dry = ProfileMigration.dryRun(root, fallback)
        assertTrue(dry.ok)
        assertEquals(1, dry.changedCount)
        assertTrue(!File(configs, "profile-migration-backup/work.conf").exists())

        val applied = ProfileMigration.apply(root, fallback)
        assertTrue(applied.ok)
        val migrated = File(configs, "work.conf").readText()
        assertTrue(migrated.contains("groupSelections"))
        assertEquals("n1", ConfigFile.fromJson(migrated).groupSelections?.get("G"))
        assertTrue(File(configs, "profile-migration-backup/work.conf").exists())

        val rolled = ProfileMigration.rollback(root)
        assertTrue(rolled.rolledBack)
        assertEquals(old, File(configs, "work.conf").readText())
    }

    @Test
    fun `migration semantic comparison ignores only migration fields`() {
        val before = """{"version":3,"general":{},"rules":[{"type":"DOMAIN","value":"a.com","action":"direct"}]}"""
        val after = """{"version":4,"groupSelections":{"G":"n1"},"general":{},"rules":[{"type":"DOMAIN","value":"a.com","action":"direct"}]}"""
        assertTrue(ProfileMigration.semanticEqual(before, after))
        val changed = """{"version":4,"groupSelections":{},"general":{},"rules":[{"type":"DOMAIN","value":"b.com","action":"direct"}]}"""
        assertFalse(ProfileMigration.semanticEqual(before, changed))
    }
}
