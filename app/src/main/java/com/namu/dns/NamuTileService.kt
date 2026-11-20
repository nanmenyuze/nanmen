package com.namu.dns

import android.content.Intent
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/**
 * 快捷设置磁贴：下拉通知栏一键连接/断开 VPN（A1）。
 * 未授权 VPN 时打开 App 引导授权，不在磁贴里弹权限框。
 */
class NamuTileService : TileService() {

    override fun onCreate() {
        super.onCreate()
        App.init(applicationContext)
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        App.init(applicationContext)
        val runtime = App.container.runtime.current()
        if (runtime.stopping) return
        if (runtime.connected || NamuVpnService.isRunning() || runtime.starting) {
            NamuVpnService.stop(this)
        } else {
            val prepare = VpnService.prepare(this)
            if (prepare != null) {
                // 需要 VPN 授权：打开 App，由用户在首页开关处授权。
                startActivity(
                    Intent(this, MainActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            } else {
                NamuVpnService.start(this)
            }
        }
        updateTile()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        // 点击启动后服务尚未 connected，用 runtime.starting 让磁贴立即变为激活态。
        val runtime = App.container.runtime.current()
        val running = !runtime.stopping &&
            (runtime.connected || runtime.starting || NamuVpnService.isRunning())
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "南门DNS"
        tile.contentDescription = if (running) "南门DNS 已连接，点击断开" else "南门DNS 未连接，点击连接"
        tile.updateTile()
    }
}
