package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.R

/**
 * 自愿打赏弹窗（低调、无对价、不解锁功能）。
 *
 * 设计原则（务必保持，勿改成付费解锁/会员）：
 * - 完全自愿，不构成对软件/服务/功能的购买；
 * - 不解锁任何功能、不换取优先支持或其他对价；
 * - 本项目仅供学习研究，不提供任何代理服务，打赏不产生服务义务；
 * - 入口仅在「关于」页一个普通行，无弹窗骚扰、无红点、无强制。
 *
 * 接入：在 SettingsScreen「关于」GroupCard 加一行 onClick 弹出本弹窗，见 集成说明.md。
 */
object DonateInfo {
    /** 替换为你自己的爱发电主页；留空则隐藏爱发电入口。 */
    const val AFDIAN_URL = ""

    /** 收款码图片资源名（放 app/src/main/res/drawable/）。为 0 时显示占位框，编译不依赖图片。 */
    val WECHAT_QR = 0   // 例如 R.drawable.donate_wechat
    val ALIPAY_QR = R.drawable.donate_alipay
}

@Composable
fun DonateDialog(onDismiss: () -> Unit) {
    val uriHandler = LocalUriHandler.current
    NamuDialog(
        title = "自愿打赏",
        confirmText = "关闭",
        showDismiss = false,
        onConfirm = onDismiss,
        onDismiss = onDismiss,
    ) {
        Text(
            "南门DNS 免费开源，全部功能完整开放，无任何付费内容。" +
                "如果它对你有帮助，可以自愿请作者喝杯咖啡。",
            fontSize = 13.sp,
            color = NamuColors.TextMain,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "打赏完全自愿，不构成对任何软件、服务或功能的购买，不解锁任何功能，" +
                "也不换取优先支持或其他对价。本项目仅供学习与研究，不提供任何代理服务、" +
                "节点订阅或跨境网络服务，打赏不产生任何服务义务。请量力而行。",
            fontSize = 11.sp,
            color = NamuColors.TextSub,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(14.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            QrPlaceholder("微信", DonateInfo.WECHAT_QR, Modifier.weight(1f))
            QrPlaceholder("支付宝", DonateInfo.ALIPAY_QR, Modifier.weight(1f))
        }
        if (DonateInfo.AFDIAN_URL.isNotBlank()) {
            Spacer(Modifier.height(12.dp))
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(NamuColors.Fill)
                    .clickable { runCatching { uriHandler.openUri(DonateInfo.AFDIAN_URL) } }
                    .padding(vertical = 12.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text("爱发电打赏 →", fontSize = 13.sp, color = NamuColors.Blue, fontWeight = FontWeight.Medium)
            }
        }
    }
}

@Composable
private fun QrPlaceholder(label: String, drawableRes: Int, modifier: Modifier = Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier
                .fillMaxWidth()
                .height(120.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(NamuColors.Fill),
            contentAlignment = Alignment.Center,
        ) {
            if (drawableRes != 0) {
                // 放入收款码图片后，把下面占位 Text 换成：
                // Image(painter = painterResource(drawableRes), contentDescription = label,
                //       modifier = Modifier.size(108.dp))
                androidx.compose.foundation.Image(
                    painter = androidx.compose.ui.res.painterResource(drawableRes),
                    contentDescription = label,
                    modifier = Modifier.size(108.dp),
                )
            } else {
                Text(
                    "$label 收款码\n（占位）",
                    fontSize = 11.sp,
                    color = NamuColors.TextTertiary,
                    textAlign = TextAlign.Center,
                )
            }
        }
        Spacer(Modifier.height(4.dp))
        Text(label, fontSize = 11.sp, color = NamuColors.TextSub)
    }
}
