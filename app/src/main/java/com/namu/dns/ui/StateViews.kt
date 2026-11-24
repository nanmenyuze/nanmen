package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Inbox
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.WifiTethering
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.core.repository.ShellPhase

/** U4 四态：loading 用静态骨架，避免额外循环动效。 */
@Composable
fun NamuLoadingPanel(
    label: String = "正在读取…",
    modifier: Modifier = Modifier,
) {
    Column(
        modifier.fillMaxWidth().padding(NamuTokens.Space20),
        verticalArrangement = Arrangement.spacedBy(NamuTokens.Space12),
    ) {
        Text(label, style = NamuTokens.Type.Caption, color = NamuColors.TextSub)
        repeat(3) { index ->
            Box(
                Modifier
                    .fillMaxWidth(if (index == 2) 0.62f else 1f)
                    .height(if (index == 0) 18.dp else 12.dp)
                    .clip(RoundedCornerShape(6.dp))
                    .background(NamuColors.Fill),
            )
        }
    }
}

@Composable
fun NamuEmptyPanel(
    title: String,
    body: String,
    action: String? = null,
    onAction: (() -> Unit)? = null,
    icon: ImageVector = Icons.Outlined.Inbox,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier.fillMaxWidth().padding(horizontal = NamuTokens.Space24, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            Modifier.size(52.dp).clip(CircleShape).background(NamuColors.Fill),
            contentAlignment = Alignment.Center,
        ) { NamuIcon(icon, tint = NamuColors.Brand, size = 24.dp) }
        Spacer(Modifier.height(NamuTokens.Space12))
        Text(title, style = NamuTokens.Type.Title, color = NamuColors.TextMain, textAlign = TextAlign.Center)
        Spacer(Modifier.height(NamuTokens.Space4))
        Text(body, style = NamuTokens.Type.Caption, color = NamuColors.TextSub, textAlign = TextAlign.Center)
        if (action != null && onAction != null) {
            Spacer(Modifier.height(NamuTokens.Space16))
            IosButton(action, onAction, modifier = Modifier.width(220.dp))
        }
    }
}

@Composable
fun NamuErrorPanel(
    message: String,
    onRetry: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier.fillMaxWidth().padding(horizontal = NamuTokens.Space24, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            Modifier.size(52.dp).clip(CircleShape).background(NamuColors.RedFill.copy(alpha = 0.10f)),
            contentAlignment = Alignment.Center,
        ) { NamuIcon(Icons.Outlined.ErrorOutline, tint = NamuColors.RedFill, size = 24.dp) }
        Spacer(Modifier.height(NamuTokens.Space12))
        Text("读取失败", style = NamuTokens.Type.Title, color = NamuColors.TextMain)
        Spacer(Modifier.height(NamuTokens.Space4))
        Text(
            message.ifBlank { "数据暂时不可用，请重试" },
            style = NamuTokens.Type.Caption,
            color = NamuColors.TextSub,
            textAlign = TextAlign.Center,
        )
        if (onRetry != null) {
            Spacer(Modifier.height(NamuTokens.Space16))
            IosButton("重试", onRetry, modifier = Modifier.width(180.dp))
        }
    }
}

@Composable
fun NamuSuccessHeader(
    title: String,
    subtitle: String,
    modifier: Modifier = Modifier,
) {
    Row(modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(28.dp).clip(CircleShape).background(NamuColors.GreenFill.copy(alpha = 0.12f)),
            contentAlignment = Alignment.Center,
        ) { NamuIcon(Icons.Outlined.CheckCircle, tint = NamuColors.GreenFill, size = 18.dp) }
        Spacer(Modifier.width(NamuTokens.Space8))
        Column(Modifier.weight(1f)) {
            Text(title, style = NamuTokens.Type.Body, fontWeight = FontWeight.SemiBold, color = NamuColors.TextMain)
            Text(subtitle, style = NamuTokens.Type.Caption, color = NamuColors.TextSub)
        }
    }
}

/** U4 四态统一入口；首页/数据页都按同一顺序判断，避免各页各写一套。 */
@Composable
fun NamuStatePanel(
    phase: ShellPhase,
    message: String,
    needsVpnGuide: Boolean,
    onStartVpn: () -> Unit,
    onRetry: (() -> Unit)? = null,
) {
    when (phase) {
        ShellPhase.LOADING -> NamuLoadingPanel()
        ShellPhase.EMPTY -> NamuEmptyPanel(
            title = if (needsVpnGuide) "先启动 VPN" else "还没有命中",
            body = if (needsVpnGuide) {
                "启动后只在本机记录域名、模块与时间，不保存 path / query / body / headers。"
            } else {
                message.ifBlank { "本窗口暂无查询" }
            },
            action = if (needsVpnGuide) "启动 VPN" else null,
            onAction = if (needsVpnGuide) onStartVpn else null,
            icon = if (needsVpnGuide) Icons.Outlined.WifiTethering else Icons.Outlined.Inbox,
        )
        ShellPhase.ERROR -> NamuErrorPanel(message, onRetry)
        ShellPhase.SUCCESS -> Unit
    }
}

/** 首次 VPN 全屏引导：只出现一次，讲清权限边界，不夹带位置/请求内容。 */
@Composable
fun FirstRunVpnGuide(onStart: () -> Unit, onLater: () -> Unit) {
    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).padding(horizontal = NamuTokens.Space24),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(72.dp))
        Box(
            Modifier.size(72.dp).clip(CircleShape).background(NamuColors.Brand.copy(alpha = 0.10f)),
            contentAlignment = Alignment.Center,
        ) { NamuIcon(Icons.Outlined.Shield, tint = NamuColors.Brand, size = 32.dp) }
        Spacer(Modifier.height(NamuTokens.Space20))
        Text("让南门DNS 接管 DNS", style = NamuTokens.Type.Display, color = NamuColors.TextMain, textAlign = TextAlign.Center)
        Spacer(Modifier.height(NamuTokens.Space8))
        Text(
            "首次启动会弹出系统 VPN 授权。南门DNS 只在本机处理 DNS 与分流，不读取请求内容，不上传浏览记录。",
            style = NamuTokens.Type.Body,
            color = NamuColors.TextSub,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(NamuTokens.Space24))
        listOf(
            "只记录域名、模块与时间；默认不保存路径、查询串和正文",
            "请求记录默认关，可随时清空",
            "VPN 授权由系统弹窗确认，可随时断开",
        ).forEach { line ->
            Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.Top) {
                Box(
                    Modifier.padding(top = 4.dp).size(6.dp).clip(CircleShape).background(NamuColors.Brand),
                )
                Spacer(Modifier.width(NamuTokens.Space8))
                Text(line, style = NamuTokens.Type.Caption, color = NamuColors.TextSub)
            }
        }
        Spacer(Modifier.weight(1f))
        IosButton("启动 VPN", onStart)
        Spacer(Modifier.height(NamuTokens.Space8))
        MiniTextAction("稍后再说", color = NamuColors.TextSub, onClick = onLater)
        Spacer(Modifier.height(NamuTokens.Space32))
    }
}
