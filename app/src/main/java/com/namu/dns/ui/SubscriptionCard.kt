package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.SubscriptionInfo
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 首页/服务器页的订阅流量与到期概览。 */
@Composable
fun SubscriptionCard(info: SubscriptionInfo) {
    val expired = info.expireAt in 1..System.currentTimeMillis()
    GroupCard {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("订阅流量", fontSize = 15.sp, color = NamuColors.TextMain)
                Spacer(Modifier.weight(1f))
                Text(
                    if (info.total > 0) "剩余 ${formatBytes(info.remaining)}" else "流量未知",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = NamuColors.Blue,
                )
            }

            if (info.total > 0) {
                Spacer(Modifier.height(8.dp))
                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(RoundedCornerShape(3.dp))
                        .background(NamuColors.TrackOff),
                ) {
                    Box(
                        Modifier
                            .fillMaxWidth((100 - info.usedPercent).toFloat() / 100f)
                            .fillMaxHeight()
                            .background(
                                if (info.usedPercent >= 90) NamuColors.Orange else NamuColors.Blue,
                                RoundedCornerShape(3.dp),
                            ),
                    )
                }
            }
            Spacer(Modifier.height(7.dp))
            Row {
                Text(
                    if (info.total > 0) {
                        "已用 ${formatBytes(info.used)} / ${formatBytes(info.total)} · ${info.usedPercent}%"
                    } else {
                        "已用 ${formatBytes(info.used)}"
                    },
                    fontSize = 11.sp,
                    color = NamuColors.TextSub,
                )
                Spacer(Modifier.weight(1f))
                Text(
                    if (info.expireAt > 0) "到期 ${subscriptionExpiry(info)}" else "到期未知",
                    fontSize = 11.sp,
                    color = if (expired) NamuColors.Red else NamuColors.TextSub,
                )
            }
            if (info.updatedAt > 0) {
                Text(
                    "更新 ${formatAgo(info.updatedAt)}",
                    fontSize = 10.sp,
                    color = NamuColors.TextTertiary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
    }
}

internal fun subscriptionExpiry(info: SubscriptionInfo): String {
    if (info.expireAt <= 0) return "未知"
    return SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date(info.expireAt))
}
