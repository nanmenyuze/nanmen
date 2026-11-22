package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** P3.1 远程模块拉取：显式列出支持子集与拒绝清单，不把「能下载」当成通过。 */
class ModuleFetchPolicyTest {
    private fun fixture(): String {
        val candidates = listOf(
            File("../compat/fixtures/remote/synthetic-remote.sgmodule"),
            File("compat/fixtures/remote/synthetic-remote.sgmodule"),
        )
        return candidates.firstOrNull { it.isFile }?.readText()
            ?: error("fixture not found: remote")
    }

    @Test
    fun remoteUrlSupportSubset() {
        assertNull(ModuleFetchPolicy.urlError("https://modules.example.com/a.sgmodule"))
        assertNull(ModuleFetchPolicy.urlError("https://modules.example.com:8443/a.sgmodule?x=1"))
        assertNull(ModuleFetchPolicy.urlError("local://module.sgmodule", allowLocal = true))
    }

    @Test
    fun remoteUrlRejectList() {
        assertEquals("模块来源为空", ModuleFetchPolicy.urlError("  "))
        assertEquals("远程模块只允许 HTTPS", ModuleFetchPolicy.urlError("http://modules.example.com/a.sgmodule"))
        assertEquals("远程模块只允许 HTTPS", ModuleFetchPolicy.urlError("ftp://modules.example.com/a.sgmodule"))
        assertEquals("远程模块只允许 HTTPS", ModuleFetchPolicy.urlError("file:///sdcard/a.sgmodule"))
        assertEquals("远程模块只允许 HTTPS", ModuleFetchPolicy.urlError("local://module.sgmodule"))
    }

    @Test
    fun contentTypeSupportSubset() {
        assertNull(ModuleFetchPolicy.contentTypeError(null))
        assertNull(ModuleFetchPolicy.contentTypeError(""))
        assertNull(ModuleFetchPolicy.contentTypeError("text/plain; charset=utf-8"))
        assertNull(ModuleFetchPolicy.contentTypeError("text/html"))
        assertNull(ModuleFetchPolicy.contentTypeError("application/octet-stream"))
        assertNull(ModuleFetchPolicy.contentTypeError("application/json; charset=utf-8"))
        assertNull(ModuleFetchPolicy.contentTypeError("application/yaml"))
        assertNull(ModuleFetchPolicy.contentTypeError("application/x-yaml"))
    }

    @Test
    fun contentTypeRejectList() {
        assertNotNull(ModuleFetchPolicy.contentTypeError("image/png"))
        assertNotNull(ModuleFetchPolicy.contentTypeError("application/zip"))
        assertNotNull(ModuleFetchPolicy.contentTypeError("application/pdf"))
        assertNotNull(ModuleFetchPolicy.contentTypeError("application/vnd.android.package-archive"))
    }

    @Test
    fun sizeLimitAcceptsExactlyFourMiBAndRejectsOneByteMore() {
        assertNull(ModuleFetchPolicy.sizeError(ModuleFetchPolicy.MAX_BYTES.toLong()))
        assertNotNull(ModuleFetchPolicy.sizeError(ModuleFetchPolicy.MAX_BYTES + 1L))
        assertNotNull(ModuleFetchPolicy.sizeError(Long.MAX_VALUE))
    }

    @Test
    fun controlCharacterRejectList() {
        assertNull(ModuleFetchPolicy.controlCharError("a\tb\r\nc"))
        assertNotNull(ModuleFetchPolicy.controlCharError("a\u0001b"))
        assertNotNull(ModuleFetchPolicy.controlCharError("a\u000Eb"))
        assertNotNull(ModuleFetchPolicy.controlCharError("a\u001Fb"))
    }

    @Test
    fun remoteFixtureIsParsableAndPassesFetchPolicy() {
        val text = fixture()
        val parsed = ModuleParser.parse(text)
        assertTrue(parsed.blockLines.isNotEmpty())
        assertTrue(parsed.mitmHostnames.isNotEmpty())
        assertNull(ModuleFetchPolicy.urlError("https://modules.example.com/synthetic-remote.sgmodule"))
        assertNull(ModuleFetchPolicy.contentTypeError("text/plain; charset=utf-8"))
        assertNull(ModuleFetchPolicy.sizeError(text.toByteArray().size.toLong()))
        assertNull(ModuleFetchPolicy.controlCharError(text))
    }

    @Test
    fun remoteFixtureWithControlCharacterIsRejectedBeforeParsing() {
        val text = fixture() + "\u0001"
        assertNotNull(ModuleFetchPolicy.controlCharError(text))
    }
}
