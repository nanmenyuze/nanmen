package com.namu.dns

import com.namu.dns.core.repository.DefaultNodeRepository
import com.namu.dns.core.repository.HitRepository
import com.namu.dns.core.repository.HitsUiState
import com.namu.dns.core.repository.LogRepository
import com.namu.dns.core.repository.LogsUiState
import com.namu.dns.core.repository.StatsRepository
import com.namu.dns.core.repository.StatsUiState
import com.namu.dns.core.runtime.DefaultMessageRepository
import com.namu.dns.core.runtime.DefaultRuntimeRepository
import com.namu.dns.ui.viewmodel.DataViewModel
import com.namu.dns.ui.viewmodel.HomeViewModel
import com.namu.dns.ui.viewmodel.SettingsViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestWatcher
import org.junit.runner.Description
import app.cash.turbine.test

@OptIn(ExperimentalCoroutinesApi::class)
class ViewModelStateTest {
    class MainDispatcherRule(
        private val dispatcher: TestDispatcher = UnconfinedTestDispatcher(),
    ) : TestWatcher() {
        override fun starting(description: Description) = Dispatchers.setMain(dispatcher)
        override fun finished(description: Description) = Dispatchers.resetMain()
    }

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeStats : StatsRepository {
        private val _state = MutableStateFlow(StatsUiState())
        override val state: StateFlow<StatsUiState> = _state.asStateFlow()
        override fun current() = _state.value
        override fun poll() = Unit
        override fun resetSession() = Unit
    }

    private class FakeHits : HitRepository {
        private val _state = MutableStateFlow(HitsUiState())
        override val state: StateFlow<HitsUiState> = _state.asStateFlow()
        override fun current() = _state.value
        override fun poll() = Unit
        override fun setWindow(hours: Int) = Unit
        override fun repair() = Unit
        override fun clear() = Unit
        override fun setEnabled(enabled: Boolean) = Unit
    }

    private class FakeLogs : LogRepository {
        private val _state = MutableStateFlow(LogsUiState())
        override val state: StateFlow<LogsUiState> = _state.asStateFlow()
        override fun current() = _state.value
        override fun poll() = Unit
        override fun clearRuntime() = Unit
        override fun clearDns() = Unit
    }

    @Test
    fun `home state follows config runtime and stats`() = runTest {
        val settings = FakeSettingsRepository()
        val runtime = DefaultRuntimeRepository()
        val stats = FakeStats()
        val vm = HomeViewModel(
            settings, runtime, stats, DefaultNodeRepository(settings), DefaultMessageRepository(),
            ping = { _ -> 42L },
        )
        vm.state.test {
            assertEquals(AppConfig(), awaitItem().config)
            settings.update { it.copy(mode = "proxy") }
            assertEquals("proxy", awaitItem().config.mode)
            runtime.markStarting()
            assertEquals(true, awaitItem().runtime.starting)
            runtime.markConnected(123)
            assertEquals(123L, awaitItem().runtime.lastStartupMs)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `filter only mode forces final policy to direct`() = runTest {
        val settings = FakeSettingsRepository(AppConfig(mode = "rule", finalPolicy = "proxy"))
        val vm = HomeViewModel(
            settings, DefaultRuntimeRepository(), FakeStats(),
            DefaultNodeRepository(settings), DefaultMessageRepository(),
            ping = { _ -> 42L },
        )
        vm.setMode("filter_only")
        val cfg = settings.current()
        assertEquals("filter_only", cfg.mode)
        // 纯过滤不代理：final 必须直接落到 direct，否则无节点时会先判代理再被兜底拦截。
        assertEquals("direct", cfg.finalPolicy)
    }

    @Test
    fun `switching to rule mode does not rewrite final policy`() = runTest {
        val settings = FakeSettingsRepository(AppConfig(mode = "filter_only", finalPolicy = "direct"))
        val vm = HomeViewModel(
            settings, DefaultRuntimeRepository(), FakeStats(),
            DefaultNodeRepository(settings), DefaultMessageRepository(),
            ping = { _ -> 42L },
        )
        vm.setMode("rule")
        assertEquals("rule", settings.current().mode)
        // 从纯过滤切回规则模式时不能在背后改用户的 final 选择。
        assertEquals("direct", settings.current().finalPolicy)
        vm.setMode("global")
        assertEquals("global", settings.current().mode)
    }

    @Test
    fun `home test state is kept in view model and probes selected node`() = runTest {
        val settings = FakeSettingsRepository(
            AppConfig(
                nodes = listOf(NodeInfo("n1", "ss", "1.1.1.1", 443)),
                selected = "n1",
                pingMethod = "tls",
            ),
        )
        var nodeUsed: String? = null
        val vm = HomeViewModel(
            settings, DefaultRuntimeRepository(), FakeStats(), DefaultNodeRepository(settings), DefaultMessageRepository(),
            ping = { node ->
                nodeUsed = node.name
                42L
            },
        )
        vm.testSelectedNode()
        advanceUntilIdle()
        assertEquals("42 ms", vm.testState.value.result)
        assertEquals(false, vm.testState.value.testing)
        assertEquals("n1", nodeUsed)
        assertEquals(42L, settings.current().nodes.single().latency)
    }

    @Test
    fun `data state follows logs and nodes`() = runTest {
        val settings = FakeSettingsRepository(
            AppConfig(autoClearLogs = false, nodes = listOf(NodeInfo("n1", "ss", "1.1.1.1", 443))),
        )
        val runtime = DefaultRuntimeRepository()
        val vm = DataViewModel(settings, runtime, FakeStats(), FakeHits(), FakeLogs(), DefaultNodeRepository(settings), DefaultMessageRepository())
        vm.state.test {
            assertEquals(0, awaitItem().logs.runtime.size)
            settings.update { it.copy(autoClearLogs = true) }
            assertEquals(true, awaitItem().config.autoClearLogs)
            vm.clearAllNodes()
            assertEquals(emptyList<NodeInfo>(), awaitItem().config.nodes)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `settings state exposes config changes`() = runTest {
        val settings = FakeSettingsRepository()
        val vm = SettingsViewModel(settings, DefaultMessageRepository())
        vm.state.test {
            assertEquals(false, awaitItem().config.autoDisablePrivateDns)
            vm.setAutoDisablePrivateDns(true)
            assertEquals(true, awaitItem().config.autoDisablePrivateDns)
            cancelAndIgnoreRemainingEvents()
        }
    }
}
