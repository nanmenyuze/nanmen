package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CloudDownload
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * B4 首启引导：三页（VPN 授权 / 导入服务器 / 私人 DNS 与 Root）。
 * 首启显示，可跳过；完成/跳过后写 UiPrefs.onboardingDone，不再出现。
 * 设置页「重新查看引导」可重置。
 */
@Composable
fun OnboardingScreen(onFinish: () -> Unit) {
    var step by remember { mutableStateOf(0) }
    data class Page(val title: String, val body: String, val icon: ImageVector)
    val pages = listOf(
        Page(
            "VPN 权限",
            "南门DNS 通过 Android 系统 VPN 接口接管 DNS 与流量，全部在本机处理，不上传任何数据。\n\n首次连接会弹出系统 VPN 授权框，点「确定」即可；之后可在首页开关或通知栏磁贴一键启停。",
            Icons.Rounded.Shield,
        ),
        Page(
            "导入服务器",
            "支持 Clash 订阅、Base64 节点链接与扫码导入：首页右上角 + 或「服务器」页均可导入。\n\n不导入节点也能使用 DNS 广告过滤；导入后按规则分流，连接中切换节点会自动重连。",
            Icons.Rounded.CloudDownload,
        ),
        Page(
            "私人 DNS 与 Root",
            "系统「私人 DNS」会绕过本 App 的 DNS 过滤，建议关闭；Root 设备可在设置开启「自动接管私人 DNS」。\n\nDNS 广告过滤无需 Root，开箱即用。MITM 去广告面向 Root 设备：在 MITM 页生成 KernelSU/Magisk 系统信任模块，安装并重启后所有 App 信任 CA、重启不丢（证书绑定应用会自动放行）。银行/支付类应用请加入跳过列表。",
            Icons.Rounded.Lock,
        ),
    )
    val page = pages[step]
    Column(
        Modifier
            .fillMaxSize()
            .background(NamuColors.Bg)
            .padding(horizontal = 28.dp, vertical = 40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(48.dp))
        Icon(page.icon, contentDescription = null, tint = NamuColors.Blue, modifier = Modifier.size(64.dp))
        Spacer(Modifier.height(24.dp))
        Text(page.title, fontSize = 24.sp, fontWeight = FontWeight.Bold, color = NamuColors.TextMain)
        Spacer(Modifier.height(14.dp))
        Text(
            page.body,
            fontSize = 14.sp,
            color = NamuColors.TextSub,
            lineHeight = 22.sp,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.weight(1f))
        Row(verticalAlignment = Alignment.CenterVertically) {
            pages.indices.forEach { i ->
                Box(
                    Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(if (i == step) NamuColors.Blue else NamuColors.TextTertiary),
                )
                if (i != pages.lastIndex) Spacer(Modifier.width(8.dp))
            }
        }
        Spacer(Modifier.height(24.dp))
        IosButton(
            text = if (step < pages.lastIndex) "下一步" else "开始使用",
            onClick = { if (step < pages.lastIndex) step++ else onFinish() },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        MiniTextAction("跳过引导") { onFinish() }
        Spacer(Modifier.height(12.dp))
    }
}
