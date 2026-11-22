package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Root CA 管理里的纯函数：挂载栈判定、状态原子写格式、路径安全。 */
class RootCaManagerTest {

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
                snap = RootCaManager.TrustSnapshot(systemCertInstalled = true),
            ),
        )
        assertTrue(
            RootCaManager.caNeedsRefresh(
                regenerated = true,
                snap = RootCaManager.TrustSnapshot(systemCertInstalled = true),
            ),
        )
        assertTrue(
            RootCaManager.caNeedsRefresh(
                regenerated = false,
                snap = RootCaManager.TrustSnapshot(systemCertInstalled = false),
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
}
