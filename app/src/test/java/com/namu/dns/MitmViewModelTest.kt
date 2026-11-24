package com.namu.dns

import com.namu.dns.core.runtime.DefaultMessageRepository
import com.namu.dns.ui.viewmodel.MitmViewModel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** M2：MitmViewModel 行为测试。操作全部注入 fake，不触 Android。 */
@OptIn(ExperimentalCoroutinesApi::class)
class MitmViewModelTest {

    @Before fun setup() { Dispatchers.setMain(UnconfinedTestDispatcher()) }
    @After fun teardown() { Dispatchers.resetMain() }

    private class Harness(
        caExists: Boolean = true,
        private val exportResult: MitmManager.ExportResult =
            MitmManager.ExportResult(ok = true, pemPath = "/data/ca.pem", derPath = "/data/ca.der", systemName = "d756baa7.0"),
        private val moduleResult: TrustModuleGenerator.Result =
            TrustModuleGenerator.Result(ok = true, path = "下载/NamuDNS/namu_mitm_ca_module.zip"),
        private val systemCertResult: Boolean = false,
        private val snapshot: RootCaManager.TrustSnapshot = RootCaManager.TrustSnapshot(),
        publishLog: suspend (String) -> String = { "" },
    ) {
        var ca = caExists
        var exports = 0
        val enabledCalls = mutableListOf<Boolean>()
        val hostCalls = mutableListOf<List<String>>()
        val skipCalls = mutableListOf<List<String>>()
        var modulePem = ""
        val messages = DefaultMessageRepository()
        val vm = MitmViewModel(
            messages = messages,
            caExistsCheck = { ca },
            export = { exports++; ca = exportResult.ok; exportResult },
            generateModule = { pem, _ -> modulePem = pem; moduleResult },
            systemCertCheck = { systemCertResult },
            applyEnabled = { enabledCalls.add(it) },
            applyHostnames = { hostCalls.add(it) },
            applySkip = { skipCalls.add(it) },
            applyApps = { _, _ -> },
            exportDirFallback = { "/data/export" },
            trustSnapshotCheck = { snapshot },
            publishLog = publishLog,
        )
        fun lastMessage(): String = messages.messages.replayCache.lastOrNull() ?: ""

    }

    @Test
    fun `enable without ca exports first then applies`() {
        val h = Harness(caExists = false)
        h.vm.setEnabled(true)
        assertEquals(1, h.exports)
        assertEquals(listOf(true), h.enabledCalls)
        assertTrue(h.vm.caExists.value)
        assertFalse(h.vm.busy.value)
    }

    @Test
    fun `enable export failure does not apply and reports`() {
        val h = Harness(caExists = false, exportResult = MitmManager.ExportResult(ok = false, error = "boom"))
        h.vm.setEnabled(true)
        assertTrue(h.enabledCalls.isEmpty())
        assertFalse(h.vm.caExists.value)
        assertTrue(h.lastMessage().contains("CA 生成失败"))
        assertFalse(h.vm.busy.value)
    }

    @Test
    fun `enable with existing ca skips export`() {
        val h = Harness(caExists = true)
        h.vm.setEnabled(true)
        assertEquals(0, h.exports)
        assertEquals(listOf(true), h.enabledCalls)
    }

    @Test
    fun `disable never exports`() {
        val h = Harness(caExists = false)
        h.vm.setEnabled(false)
        assertEquals(0, h.exports)
        assertEquals(listOf(false), h.enabledCalls)
    }

    @Test
    fun `generate module success shows path and guidance`() {
        val h = Harness()
        h.vm.generateTrustModule()
        assertTrue(h.lastMessage().contains("模块已导出"))
        assertTrue(h.lastMessage().contains("模块管理器"))
        assertTrue(h.lastMessage().contains("重启后重新核验"))
        assertEquals("/data/ca.pem", h.modulePem)
        assertFalse(h.vm.busy.value)
    }

    @Test
    fun `generate module failure reports`() {
        val h = Harness(moduleResult = TrustModuleGenerator.Result(ok = false, error = "磁盘满"))
        h.vm.generateTrustModule()
        assertTrue(h.lastMessage().contains("模块生成失败"))
        assertTrue(h.lastMessage().contains("磁盘满"))
        assertFalse(h.vm.busy.value)
    }

    @Test
    fun `generate module marks detected when system cert present`() {
        val h = Harness(systemCertResult = true)
        h.vm.generateTrustModule()
        assertTrue(h.vm.systemCertInstalled.value)
    }

    @Test
    fun `generate module without system cert not detected`() {
        val h = Harness(systemCertResult = false)
        h.vm.generateTrustModule()
        assertFalse(h.vm.systemCertInstalled.value)
    }

    @Test
    fun `export failure during generate reports and resets busy`() {
        val h = Harness(exportResult = MitmManager.ExportResult(ok = false, error = "x"))
        h.vm.generateTrustModule()
        assertTrue(h.lastMessage().contains("证书导出失败"))
        assertFalse(h.vm.busy.value)
    }

    @Test
    fun `export only reports directory`() {
        val h = Harness()
        h.vm.exportOnly()
        assertTrue(h.lastMessage().contains("/data"))
    }

    @Test
    fun `export logs includes current Zygote results when boot log is missing`() = runBlocking<Unit> {
        val published = CompletableDeferred<String>()
        val foreignRoot = "/adb/modules/example/system/etc/security/cacerts"
        val mount = "42 12 0:1 $foreignRoot /apex/com.android.conscrypt/cacerts ro - tmpfs tmpfs ro"
        val h = Harness(
            snapshot = RootCaManager.TrustSnapshot(
                root = RootCaManager.RootInfo(true, RootCaManager.RootKind.KERNELSU),
                moduleInstalled = true,
                moduleCertMatches = true,
                bootId = "current-boot",
                conflict = true,
                topSources = listOf(foreignRoot),
                conflictSources = listOf(foreignRoot),
                zygoteChecks = listOf(RootCaManager.ZygoteCheck(
                    process = "zygote:123",
                    directoryIds = listOf("1:2", "1:3"),
                    ownsTarget = false,
                    certificateReadable = false,
                    certificateMatches = false,
                    targetMounts = listOf(mount),
                )),
            ),
            publishLog = { published.complete(it); "Downloads/log.txt" },
        )
        h.vm.exportOnly()
        h.vm.exportInjectionLog()
        val report = withTimeout(5_000) { published.await() }
        assertTrue(report.contains("未读到开机注入日志"))
        assertTrue(report.contains("cert=d756baa7.0"))
        assertTrue(report.contains("current_boot=current-boot"))
        assertTrue(report.contains("resolved_state=CONFLICT"))
        assertTrue(report.contains("mount_roots=$foreignRoot"))
        assertTrue(report.contains("conflict_sources=$foreignRoot"))
        assertTrue(report.contains("zygote:123: ids=1:2,1:3, mount_matches=false"))
        assertTrue(report.contains("zygote:123: mountinfo=$mount"))
    }

    @Test
    fun `save hostnames and skip delegate`() {
        val h = Harness()
        h.vm.saveHostnames(listOf("*.a.com"))
        h.vm.saveSkip(listOf("*.bank.com"))
        assertEquals(listOf(listOf("*.a.com")), h.hostCalls)
        assertEquals(listOf(listOf("*.bank.com")), h.skipCalls)
    }
}
