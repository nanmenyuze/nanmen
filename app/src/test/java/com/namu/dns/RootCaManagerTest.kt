package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Root CA 管理里的纯函数：挂载栈判定、状态原子写格式、路径安全。 */
class RootCaManagerTest {
    @Test
    fun `bind ownership uses matching directory identities`() {
        val target = "/apex/com.android.conscrypt/cacerts"
        val output = """
            __TARGET__=$target
            __NS_BEGIN__=zygote:10
            __NS_KIND__=zygote
            __NS_MOUNTS_BEGIN__
            42 12 0:1 /adb/namu_mitm_ca/cacerts_staging $target ro - tmpfs tmpfs ro
            __NS_MOUNTS_END__
            __NS_IDS_BEGIN__
            90:42
            90:42
            __NS_IDS_END__
            __NS_END__
            __NS_BEGIN__=zygote:11
            __NS_KIND__=zygote
            __NS_IDS_BEGIN__
            90:42
            __NS_IDS_END__
            __NS_END__
        """.trimIndent()
        val blocks = RootCaManager.parseNamespaceBlocks(output)
        assertTrue(blocks[0].ownsTarget)
        assertFalse(blocks[1].ownsTarget)
        assertEquals(
            listOf("/adb/namu_mitm_ca/cacerts_staging"),
            RootCaManager.explicitMountRoots(blocks[0].mounts, target),
        )
    }


    @Test
    fun `root kind is parsed from su output`() {
        assertEquals(RootCaManager.RootKind.MAGISK, RootCaManager.parseRootKind("uid=0\n__KIND__=magisk"))
        assertEquals(RootCaManager.RootKind.KERNELSU, RootCaManager.parseRootKind("__KIND__=kernelsu"))
        assertEquals(RootCaManager.RootKind.APATCH, RootCaManager.parseRootKind("__KIND__=apatch"))
        assertEquals(RootCaManager.RootKind.NONE, RootCaManager.parseRootKind("uid=0\nPermission denied"))
    }

    @Test
    fun `status is only done with explicit marker`() {
        val ok = RootCaManager.parseStatus(
            "state=ok\ncert=d756baa7.0\ntarget=/apex/com.android.conscrypt/cacerts\nbound=3\nconflict=0\ndone=1",
        )
        assertTrue(ok.done)
        assertEquals("ok", ok.state)
        assertEquals("d756baa7.0", ok.cert)
        assertEquals(3, ok.bound)
        assertFalse(ok.conflict)

        assertFalse(RootCaManager.parseStatus("state=ok\ncert=d756baa7.0").done)
        assertFalse(RootCaManager.parseStatus("").done)
    }

    @Test
    fun `top mount source is the last matching layer`() {
        val mounts = """
            /dev/block/dm-0 /apex/com.android.conscrypt/cacerts ext4 ro 0 0
            /data/adb/namu_mitm_ca/cacerts_staging /apex/com.android.conscrypt/cacerts tmpfs rw 0 0
            /data/adb/namu_mitm_ca/cacerts_staging /apex/com.android.conscrypt/cacerts tmpfs rw 0 0
            tmpfs /data/local/tmp tmpfs rw 0 0
        """.trimIndent()
        assertEquals(
            RootCaManager.STAGING_DIR,
            RootCaManager.parseMountTopSource(mounts, "/apex/com.android.conscrypt/cacerts"),
        )
        assertNull(RootCaManager.parseMountTopSource(mounts, "/system/etc/security/cacerts"))
    }

    @Test
    fun `only staging source mounts are selected for unmount`() {
        val mounts = """
            /dev/block/dm-0 /apex/com.android.conscrypt/cacerts ext4 ro 0 0
            /data/adb/namu_mitm_ca/cacerts_staging /apex/com.android.conscrypt/cacerts tmpfs rw 0 0
            /data/adb/namu_mitm_ca/cacerts_staging /apex/com.android.conscrypt/cacerts tmpfs rw 0 0
            /data/adb/other_module /system/etc/security/cacerts tmpfs rw 0 0
        """.trimIndent()
        assertEquals(
            listOf("/apex/com.android.conscrypt/cacerts"),
            RootCaManager.mountPointsBySource(mounts, RootCaManager.STAGING_DIR),
        )
    }

    @Test
    fun `mounts are grouped by namespace`() {
        val out = """
            __NS__=1
            rootfs / rootfs rw 0 0
            __NS__=4242
            /data/adb/namu_mitm_ca/cacerts_staging /apex/com.android.conscrypt/cacerts tmpfs rw 0 0
        """.trimIndent()
        val map = RootCaManager.parseMountsByNamespace(out)
        assertEquals(setOf("1", "4242"), map.keys)
        assertTrue(map.getValue("4242").contains(RootCaManager.STAGING_DIR))
        assertEquals(2, map.size)
    }

    @Test
    fun `shell path rejects user controlled metacharacters`() {
        assertTrue(RootCaManager.isShellSafePath("/data/user/0/com.namu.dns/files/ca_module_stage"))
        assertFalse(RootCaManager.isShellSafePath("/data/a;rm -rf /"))
        assertFalse(RootCaManager.isShellSafePath("/data/$(reboot)"))
        assertFalse(RootCaManager.isShellSafePath("relative/path"))
    }

    @Test
    fun `ca refresh only when regenerated or no matching trust`() {
        assertFalse(
            RootCaManager.caNeedsRefresh(
                regenerated = false,
                snap = RootCaManager.TrustSnapshot(visibleInSelf = true),
            ),
        )
        assertTrue(
            RootCaManager.caNeedsRefresh(
                regenerated = true,
                snap = RootCaManager.TrustSnapshot(visibleInSelf = true),
            ),
        )
        assertTrue(
            RootCaManager.caNeedsRefresh(
                regenerated = false,
                snap = RootCaManager.TrustSnapshot(visibleInSelf = false),
            ),
        )
        assertFalse(
            RootCaManager.caNeedsRefresh(
                regenerated = false,
                snap = RootCaManager.TrustSnapshot(
                    moduleInstalled = true,
                    moduleCertMatches = true,
                ),
            ),
        )
        assertTrue(
            RootCaManager.caNeedsRefresh(
                regenerated = false,
                snap = RootCaManager.TrustSnapshot(
                    moduleInstalled = true,
                    moduleCertMatches = false,
                ),
            ),
        )
    }

    @Test
    fun `three facts resolve to one exclusive state`() {
        val root = RootCaManager.RootInfo(true, RootCaManager.RootKind.MAGISK)
        val noCa = RootCaManager.TrustSnapshot(root = root)
        assertEquals(
            RootCaManager.TrustState.NOT_GENERATED,
            RootCaManager.resolveTrustState(caExists = false, snap = noCa),
        )
        assertEquals(
            RootCaManager.TrustState.UNVERIFIABLE,
            RootCaManager.resolveTrustState(
                caExists = true,
                snap = RootCaManager.TrustSnapshot(root = RootCaManager.RootInfo(false)),
            ),
        )
        assertEquals(
            RootCaManager.TrustState.CONFLICT,
            RootCaManager.resolveTrustState(
                caExists = true,
                snap = RootCaManager.TrustSnapshot(root = root, conflict = true),
            ),
        )
        assertEquals(
            RootCaManager.TrustState.INJECT_FAILED,
            RootCaManager.resolveTrustState(
                caExists = true,
                snap = RootCaManager.TrustSnapshot(
                    root = root,
                    status = RootCaManager.StatusInfo(done = true, state = "error"),
                ),
            ),
        )
        assertEquals(
            RootCaManager.TrustState.ACTIVE,
            RootCaManager.resolveTrustState(
                caExists = true,
                snap = RootCaManager.TrustSnapshot(
                    root = root,
                    moduleInstalled = true,
                    moduleCertMatches = true,
                    mountedInZygote = true,
                ),
            ),
        )
        assertEquals(
            RootCaManager.TrustState.INSTALLED_PENDING,
            RootCaManager.resolveTrustState(
                caExists = true,
                snap = RootCaManager.TrustSnapshot(
                    root = root,
                    moduleInstalled = true,
                    moduleCertMatches = true,
                ),
            ),
        )
        assertEquals(
            RootCaManager.TrustState.RESIDUAL,
            RootCaManager.resolveTrustState(
                caExists = true,
                snap = RootCaManager.TrustSnapshot(root = root, visibleInSelf = true),
            ),
        )
        val report = RootCaManager.RemovalReport(at = 1L, cleared = 2)
        assertEquals(
            RootCaManager.TrustState.REMOVED,
            RootCaManager.resolveTrustState(caExists = true, snap = noCa, removal = report),
        )
        // 新定位：App 不再执行卸载，安装/启停全部交给面具，历史卸载记录只作展示。
        assertEquals(
            RootCaManager.TrustState.GENERATED_NOT_INSTALLED,
            RootCaManager.resolveTrustState(caExists = true, snap = noCa),
        )
    }

    @Test
    fun `namespace blocks keep mounts and per namespace cert`() {
        val out = """
            __TARGET__=/apex/com.android.conscrypt/cacerts
            __NS_BEGIN__=self
            __NS_KIND__=self
            __NS_MOUNTS_BEGIN__
            /dev/block/dm-0 /apex/com.android.conscrypt/cacerts ext4 ro 0 0
            __NS_MOUNTS_END__
            __NS_CERT_BEGIN__
            -----BEGIN CERTIFICATE-----
            AAA
            -----END CERTIFICATE-----
            __NS_CERT_END__
            __NS_END__
            __NS_BEGIN__=zygote:42
            __NS_KIND__=zygote
            __NS_MOUNTS_BEGIN__
            /data/adb/namu_mitm_ca/cacerts_staging /apex/com.android.conscrypt/cacerts tmpfs rw 0 0
            __NS_MOUNTS_END__
            __NS_CERT_BEGIN__
            -----BEGIN CERTIFICATE-----
            BBB
            -----END CERTIFICATE-----
            __NS_CERT_END__
            __NS_END__
        """.trimIndent()
        val blocks = RootCaManager.parseNamespaceBlocks(out)
        assertEquals(2, blocks.size)
        assertEquals("self", blocks[0].kind)
        assertTrue(blocks[0].mounts.contains("/dev/block/dm-0"))
        assertTrue(blocks[0].cert.contains("AAA"))
        assertEquals("zygote", blocks[1].kind)
        assertEquals(
            RootCaManager.STAGING_DIR,
            RootCaManager.parseMountTopSource(blocks[1].mounts, blocks[1].target),
        )
        assertTrue(blocks[1].cert.contains("BBB"))
    }

    @Test
    fun `removal report parses deduped namespaces and failure list`() {
        val report = RootCaManager.parseRemovalReport(
            """
            __REMOVAL_CLEARED__=3
            __REMOVAL_FAILED__=2
            __REMOVAL_FAILED_NS__=zygote:41,pid:999,
            """.trimIndent(),
            at = 123L,
        )
        assertEquals(3, report.cleared)
        assertEquals(2, report.failed)
        assertEquals(listOf("zygote:41", "pid:999"), report.failedNamespaces)
        assertEquals(123L, report.at)
        assertNull(RootCaManager.removalReport(0L, 0, 0, ""))
    }

    @Test
    fun `system base mount is not a foreign overlay`() {
        assertFalse(RootCaManager.isForeignCertOverlay("/dev/block/dm-0"))
        assertFalse(RootCaManager.isForeignCertOverlay(RootCaManager.STAGING_DIR))
        assertTrue(RootCaManager.isForeignCertOverlay("/data/adb/modules/other/system/etc/security/cacerts"))
        assertTrue(RootCaManager.isForeignCertOverlay("tmpfs"))
    }

    @Test
    fun `pem compare ignores line endings`() {
        val expected = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
        val actual = "-----BEGIN CERTIFICATE-----\r\nQUJD\r\n-----END CERTIFICATE-----"
        assertTrue(RootCaManager.pemCertificateMatches(actual, expected))
    }
}
