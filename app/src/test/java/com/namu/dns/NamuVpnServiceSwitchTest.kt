package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * 切网滞回纯决策测试：
 * - 当前网络真正丢失 → 立即重建（真切换不能慢）；
 * - 当前仍可用但出现更优网络 → 先确认（验证位抖动不能触发整隧道重建）；
 * - 无变化 / 无可用网络 → 不动。
 */
class NamuVpnServiceSwitchTest {

    @Test
    fun noChangeKeepsCurrent() {
        assertEquals(
            NamuVpnService.NetSwitchDecision.NONE,
            NamuVpnService.decideNetworkSwitch(
                pickedIsNull = false,
                pickedIsCurrent = true,
                currentUsable = true,
            ),
        )
    }

    @Test
    fun allNetworksLostWaitsForRecovery() {
        assertEquals(
            NamuVpnService.NetSwitchDecision.NONE,
            NamuVpnService.decideNetworkSwitch(
                pickedIsNull = true,
                pickedIsCurrent = false,
                currentUsable = false,
            ),
        )
    }

    @Test
    fun currentLostRebuildsImmediately() {
        // onLost / 失去 INTERNET：真断网，必须立即切，不等确认窗口。
        assertEquals(
            NamuVpnService.NetSwitchDecision.REBUILD_NOW,
            NamuVpnService.decideNetworkSwitch(
                pickedIsNull = false,
                pickedIsCurrent = false,
                currentUsable = false,
            ),
        )
    }

    @Test
    fun currentUsableButBetterAppearedConfirmsLater() {
        // Wi-Fi 验证位抖动场景：当前网络还能用，"更优"网络要先稳定一个窗口。
        assertEquals(
            NamuVpnService.NetSwitchDecision.CONFIRM_LATER,
            NamuVpnService.decideNetworkSwitch(
                pickedIsNull = false,
                pickedIsCurrent = false,
                currentUsable = true,
            ),
        )
    }

    @Test
    fun confirmWindowIsSecondsNotMilliseconds() {
        // 窗口必须足够长以覆盖常见验证抖动（秒级），又不能长到真断网恢复不可感。
        assertEquals(5000L, NamuVpnService.NETWORK_SWITCH_CONFIRM_MS)
        assertEquals(3000L, NamuVpnService.REBUILD_RETRY_DELAY_MS)
    }

    @Test
    fun tunnelSpecTracksMtuRouteAndMode() {
        val base = AppConfig(mode = "dns_only", dnsOnlyFullRoute = false, mtu = 1500)
        assertEquals(TunnelSpec("dns_only", 1500, fullRoute = false), tunnelSpec(base))
        // 连接中只改 MTU 也必须重建：setMtu 只在 establish 时生效。
        assertNotEquals(tunnelSpec(base), tunnelSpec(base.copy(mtu = 9000)))
        // DNS-only 全量接管会加默认路由，同样不是热重载能改的。
        assertNotEquals(tunnelSpec(base), tunnelSpec(base.copy(dnsOnlyFullRoute = true)))
        assertNotEquals(tunnelSpec(base), tunnelSpec(base.copy(mode = "global")))
        // establish 回退 1500 时，已应用状态必须记录实际值，不能记配置里的 9000。
        assertEquals(1500, tunnelSpec(base.copy(mtu = 9000), appliedMtu = 1500).mtu)
    }
    @Test
    fun mitmTemporarilyEnablesConnectionRoutingWithoutChangingDirectMode() {
        val light = AppConfig(mode = "dns_only", dnsOnlyFullRoute = false, mtu = 1500)
        val enabled = light.copy(mitm = light.mitm.copy(enabled = true))
        assertEquals(TunnelSpec("dns_only", 1500, fullRoute = true), tunnelSpec(enabled))
        assertEquals(false, enabled.dnsOnlyFullRoute)
        val disabled = enabled.copy(mitm = enabled.mitm.copy(enabled = false))
        assertEquals(tunnelSpec(light), tunnelSpec(disabled))
        assertEquals(true, tunnelSpec(disabled.copy(dnsOnlyFullRoute = true)).fullRoute)
    }
}
