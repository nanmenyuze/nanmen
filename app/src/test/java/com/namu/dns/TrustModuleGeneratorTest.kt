package com.namu.dns

import org.junit.Assert.assertFalse
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
        assertTrue(m.containsKey("post-fs-data.sh"))
        assertTrue(m.containsKey("service.sh"))
        assertTrue(m.containsKey("uninstall.sh"))
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
    fun `scripts use certificate name and apex path`() {
        val m = build(name = "abcdef01.0")
        val post = String(m["post-fs-data.sh"]!!)
        assertTrue(post.contains("NAME=abcdef01.0"))
        assertTrue(post.contains("/apex/com.android.conscrypt/cacerts"))
        assertTrue(post.contains("mount -t tmpfs"))
        assertFalse(post.contains("umount"))
        assertTrue(String(m["service.sh"]!!).contains("nsenter"))
        assertTrue(String(m["module.prop"]!!).contains("id=namu_mitm_ca"))
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
