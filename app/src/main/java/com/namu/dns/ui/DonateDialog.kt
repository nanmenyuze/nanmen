package com.namu.dns.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.Image
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
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
 * 支付宝走个人收款码深链，点一下直接进「向你付款」页，由付款人自己填金额，
 * 不需要商户号，也不需要先扫码。
 */
object DonateInfo {
    /** 替换为你自己的爱发电主页；留空则隐藏爱发电入口。 */
    const val AFDIAN_URL = ""

    /** 支付宝个人收款码解码后的链接（从收款码图片解出）。 */
    const val ALIPAY_QR_URL = "https://qr.alipay.com/fkx18400ml32jqliznjhpbc"

    /** 支付宝「向我付款」深链；qrcode 参数必须是 URL 编码后的收款码链接。 */
    fun alipayDeepLink(): String =
        "alipayqr://platformapi/startapp?saId=10000007&qrcode=" + Uri.encode(ALIPAY_QR_URL)

    /** 未安装支付宝时的网页回退地址。 */
    fun alipayWebFallback(): String = ALIPAY_QR_URL

    /** 仅在深链和网页都打不开时展示的兜底收款码。 */
    val ALIPAY_QR = R.drawable.donate_alipay
}

@Composable
fun DonateDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    var showFallbackQr by remember { mutableStateOf(false) }

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

        Box(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(NamuTokens.RadiusControl))
                .background(NamuColors.Fill)
                .clickable {
                    if (!openAlipay(context)) showFallbackQr = true
                }
                .padding(vertical = 14.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    "支付宝 · 向我付款",
                    fontSize = 14.sp,
                    color = NamuColors.Blue,
                    fontWeight = FontWeight.Medium,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    "点一下直接进入付款页，金额自己填",
                    fontSize = 11.sp,
                    color = NamuColors.TextSub,
                )
            }
        }

        if (showFallbackQr) {
            Spacer(Modifier.height(10.dp))
            Text(
                "没有找到支付宝，已尝试打开网页。也可以直接扫下面的收款码：",
                fontSize = 11.sp,
                color = NamuColors.TextSub,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(
                        Modifier
                            .size(150.dp)
                            .clip(RoundedCornerShape(NamuTokens.RadiusControl))
                            .background(NamuColors.Fill),
                        contentAlignment = Alignment.Center,
                    ) {
                        Image(
                            painter = painterResource(DonateInfo.ALIPAY_QR),
                            contentDescription = "支付宝收款码",
                            modifier = Modifier.size(138.dp),
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "支付宝收款码",
                        fontSize = 11.sp,
                        color = NamuColors.TextSub,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }

        if (DonateInfo.AFDIAN_URL.isNotBlank()) {
            Spacer(Modifier.height(12.dp))
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(NamuTokens.RadiusControl))
                    .background(NamuColors.Fill)
                    .clickable {
                        runCatching {
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse(DonateInfo.AFDIAN_URL))
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                            )
                        }
                    }
                    .padding(vertical = 12.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    "爱发电打赏 →",
                    fontSize = 13.sp,
                    color = NamuColors.Blue,
                    fontWeight = FontWeight.Medium,
                )
            }
        }
    }
}

/**
 * 依次尝试支付宝深链、网页回退。返回 true 表示已有 Activity 接手。
 * 部分 ROM 会限制包可见性，所以不做 resolveActivity 预判，直接 startActivity
 * 并捕获异常，避免「明明装了支付宝却打不开」。
 */
private fun openAlipay(context: Context): Boolean {
    val candidates = listOf(
        Intent(Intent.ACTION_VIEW, Uri.parse(DonateInfo.alipayDeepLink()))
            .setPackage("com.eg.android.AlipayGphone"),
        Intent(Intent.ACTION_VIEW, Uri.parse(DonateInfo.alipayDeepLink())),
        Intent(Intent.ACTION_VIEW, Uri.parse(DonateInfo.alipayWebFallback())),
    )
    for (intent in candidates) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            context.startActivity(intent)
            return true
        } catch (_: ActivityNotFoundException) {
            // 尝试下一个候选
        } catch (_: SecurityException) {
            // 个别 ROM 的包可见性限制会抛 SecurityException，继续回退
        }
    }
    return false
}
