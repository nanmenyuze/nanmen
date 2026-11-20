package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.StatsData

/** DNS 延迟六档柱状图；高度按最大值归一，计数用 Long。 */
@Composable
fun DnsLatencyBars(stats: StatsData, modifier: Modifier = Modifier) {
    val buckets = listOf(
        "<10" to stats.dnsLatLt10,
        "<50" to stats.dnsLatLt50,
        "<100" to stats.dnsLatLt100,
        "<300" to stats.dnsLatLt300,
        "<1000" to stats.dnsLatLt1000,
        "≥1000" to stats.dnsLatGe1000,
    )
    val max = buckets.maxOfOrNull { it.second }?.coerceAtLeast(1L) ?: 1L
    Row(
        modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        buckets.forEach { (label, count) ->
            Column(
                Modifier.weight(1f),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(((count.toDouble() / max) * 38.0).toFloat().coerceIn(2f, 38f).dp)
                        .background(NamuColors.Blue, RoundedCornerShape(topStart = 3.dp, topEnd = 3.dp)),
                )
                Text(
                    label,
                    fontSize = 9.sp,
                    color = NamuColors.TextSub,
                    modifier = Modifier.padding(top = 3.dp),
                )
                Text(
                    count.toString(),
                    fontSize = 9.sp,
                    color = NamuColors.TextTertiary,
                )
            }
        }
    }
}
