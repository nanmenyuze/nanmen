package com.namu.dns

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipInputStream

/** 系统信任模块（KernelSU/Magisk）zip 构建：结构、烤入的证书、脚本参数化。 */
class TrustModuleGeneratorTest {

    private val fakePem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

    private fun build(
        name: String = "d756baa7.0",
        pem: ByteArray = fakePem.toByteArray(),
    ): Map<String, ByteArray> {
        val out = ByteArrayOutputStream()
        TrustModuleGenerator.buildModuleZip(pem, name, out)
        val entries = mutableMapOf<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(out.toByteArray())).use { z ->
            var e = z.nextEntry
            while (e != null) {
                entries[e.name] = z.readBytes()
                e = z.nextEntry
            }
        }
        return entries
    }

    @Test
    fun `module contains required files`() {
        val m = build()
        assertTrue(m.containsKey("module.prop"))
        assertTrue(m.containsKey("customize.sh"))
        assertTrue(m.containsKey("service.sh"))
        assertTrue(m.containsKey("inject.sh"))
        assertTrue(m.containsKey("bind.sh"))
        listOf("post-fs-data.sh", "uninstall.sh", "cleanup-all.sh", "unmount.sh", "remove.sh").forEach {
            assertFalse("unexpected hook: $it", m.containsKey(it))
        }
        assertTrue(m.containsKey("certs/d756baa7.0"))
        assertTrue(m.containsKey("README.md"))
    }

    @Test
    fun `baked cert is certificate only`() {
        val pem = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
        val cert = String(build(pem = pem.toByteArray())["certs/d756baa7.0"]!!)
        assertTrue(cert.startsWith("-----BEGIN CERTIFICATE-----"))
        assertTrue(cert.contains("ABC"))
        assertTrue(cert.endsWith("-----END CERTIFICATE-----\n"))
        assertFalse(cert.contains("PRIVATE KEY"))
    }

    @Test
    fun `private key is stripped from module cert`() {
        val pem = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n" +
            "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n"
        val cert = String(build(pem = pem.toByteArray())["certs/d756baa7.0"]!!)
        assertFalse(cert.contains("PRIVATE KEY"))
        assertFalse(cert.contains("SECRET"))
    }

    @Test
    fun `scripts use certificate name and staging bind`() {
        val m = build(name = "abcdef01.0")
        val service = String(m["service.sh"]!!)
        assertTrue(service.contains("inject.sh"))
        assertTrue(service.contains("--late"))
        val inject = String(m["inject.sh"]!!)
        assertTrue(inject.contains("NAME=abcdef01.0"))
        assertTrue(inject.contains("/apex/com.android.conscrypt/cacerts"))
        assertTrue(inject.contains("cacerts_staging"))
        assertTrue(String(m["bind.sh"]!!).contains("mount --bind"))
        assertTrue(inject.contains("cmp -s"))
        assertTrue(inject.contains("nsenter"))
        assertTrue(inject.contains("STATUS.tmp"))
        assertFalse(inject.contains("mount -t tmpfs"))

        assertTrue(inject.contains("/proc/sys/kernel/random/boot_id"))
        assertFalse(inject.contains("umount"))
        assertFalse(inject.contains("rm -rf \"\$STAGING\""))
        assertFalse(String(m["bind.sh"]!!).contains("umount"))
        assertTrue(String(m["module.prop"]!!).contains("id=namu_mitm_ca"))
    }

    @Test
    fun `read only preflight refuses a missing changed or extra system certificate`() {
        val dir = kotlin.io.path.createTempDirectory("namu-ca-preflight").toFile()
        try {
            val source = dir.resolve("system").apply { mkdir() }
            val stage = dir.resolve("stage").apply { mkdir() }
            val script = dir.resolve("bind.sh").apply { writeBytes(build().getValue("bind.sh")) }
            val original = source.resolve("01234567.0").apply { writeText("stock CA") }
            val copy = stage.resolve(original.name).apply { writeText(original.readText()) }
            stage.resolve("d756baa7.0").writeText(fakePem)
            fun verify(mode: String = "--verify"): Int = ProcessBuilder(
                "sh", script.absolutePath, stage.absolutePath, source.absolutePath, "d756baa7.0", mode,
            ).start().waitFor()

            assertEquals(0, verify())
            assertEquals(2, verify("--unmount"))
            copy.writeText("different CA")
            assertEquals(9, verify())
            copy.delete()
            assertEquals(9, verify())
            copy.writeText(original.readText())
            stage.resolve("12345678.0").writeText("unrelated CA")
            assertEquals(9, verify())
            assertEquals("stock CA", original.readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `all shell scripts pass sh syntax check`() {
        val m = build()
        val tmp = kotlin.io.path.createTempDirectory("namu-sh").toFile()
        try {
            for ((name, bytes) in m) {
                if (!name.endsWith(".sh")) continue
                val f = java.io.File(tmp, name)
                f.writeBytes(bytes)
                val p = ProcessBuilder("sh", "-n", f.absolutePath)
                    .redirectErrorStream(true)
                    .start()
                val out = p.inputStream.bufferedReader().readText()
                assertTrue("$name syntax: $out", p.waitFor() == 0)
            }
        } finally {
            tmp.deleteRecursively()
        }
    }

    @Test
    fun `pruning leaves current mounted and unrecognized state alone`() {
        val dir = kotlin.io.path.createTempDirectory("namu-ca-prune").toFile()
        try {
            val state = dir.resolve("state").apply { mkdir() }
            val proc = dir.resolve("proc").apply { mkdir() }
            val current = "aaaaaaaa-1234-1234-1234-000000000001"
            val mounted = "aaaaaaaa-1234-1234-1234-000000000002"
            val old = "aaaaaaaa-1234-1234-1234-000000000003"
            val script = dir.resolve("prune.sh").apply { writeBytes(build().getValue("prune.sh")) }
            proc.resolve("1").apply { mkdir() }.resolve("mountinfo").writeText(
                "1 0 0:1 /adb/namu_mitm_ca/cacerts_staging.$mounted /apex/conscrypt/cacerts rw - ext4 /dev/block/vda rw\n",
            )
            for (id in listOf(current, mounted, old, "test")) {
                state.resolve("cacerts_staging.$id").apply { mkdir() }
                    .resolve("d756baa7.0").writeText(fakePem)
                state.resolve("inject_lock.$id").mkdir()
            }
            assertEquals(0, ProcessBuilder("sh", script.path, state.path, current, proc.path).start().waitFor())
            assertTrue(state.resolve("cacerts_staging.$current/d756baa7.0").isFile)
            assertTrue(state.resolve("cacerts_staging.$mounted/d756baa7.0").isFile)
            assertTrue(state.resolve("cacerts_staging.test/d756baa7.0").isFile)
            assertTrue(state.resolve("inject_lock.$current").isDirectory)
            assertFalse(state.resolve("cacerts_staging.$old").exists())
            assertFalse(state.resolve("inject_lock.$old").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `module zip name carries first eight of fingerprint`() {
        assertTrue(
            TrustModuleGenerator.moduleZipFileName("ABCDEF01.0") == "namu_mitm_ca_abcdef01.zip",
        )
        assertTrue(
            TrustModuleGenerator.moduleZipFileName("12345678.0") == "namu_mitm_ca_12345678.zip",
        )
    }

    @Test
    fun `cert entry name follows system name`() {
        assertTrue(build(name = "12345678.0").containsKey("certs/12345678.0"))
    }

    @Test
    fun `certificate extractor rejects missing certificate`() {
        assertTrue(TrustModuleGenerator.certificateOnlyPem("no cert here") == null)
    }
}
