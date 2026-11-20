package com.namu.dns

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.namu.dns.core.NamuAppShell
import com.namu.dns.ui.NamuTheme

class MainActivity : ComponentActivity() {

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            App.container.messages.show("未获得 VPN 授权，无法启动过滤")
        }
    }

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    // B1 通知「切换节点」：带 extra 启动/新意图时直达节点页。
    private var openNodes by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        App.init(applicationContext)
        openNodes = intent.getBooleanExtra("open_nodes", false)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.light(android.graphics.Color.WHITE, android.graphics.Color.WHITE),
        )
        askNotificationPermission()
        setContent {
            val config by App.container.settings.config.collectAsStateWithLifecycle()
            val dark = when (config.themeMode) {
                "light" -> false
                "dark" -> true
                else -> isSystemInDarkTheme()
            }
            SideEffect {
                WindowCompat.getInsetsController(window, window.decorView).apply {
                    isAppearanceLightNavigationBars = !dark
                    isAppearanceLightStatusBars = !dark
                }
            }
            NamuTheme(darkTheme = dark) {
                NamuAppShell(
                    onToggle = { toggleVpn() },
                    onRestart = { restartVpn() },
                    openNodes = openNodes,
                    onNodesConsumed = { openNodes = false },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        openNodes = intent.getBooleanExtra("open_nodes", false)
    }

    private fun askNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun toggleVpn() {
        // 正在关闭时忽略点击，避免旧关闭线程和新启动线程互相踩踏。
        val runtime = App.container.runtime.current()
        if (runtime.stopping) return
        // 不能只信内存状态：Activity 重建后该状态可能是 false，
        // 但 VPN 服务其实还在运行。服务自身也有 alive 状态兜底。
        if (runtime.connected || NamuVpnService.isRunning() || runtime.starting) {
            NamuVpnService.stop(this)
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            vpnPermission.launch(prepare)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        NamuVpnService.start(this)
    }

    private fun restartVpn() {
        if (!App.container.runtime.current().connected) return
        // 不停止 VPN：服务内部热重启内核；模式变化时才重建 TUN。
        NamuVpnService.reload(this)
    }
}
