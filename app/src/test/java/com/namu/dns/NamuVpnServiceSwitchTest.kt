package com.namu.dns

import org.junit.Assert.assertEquals
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
}