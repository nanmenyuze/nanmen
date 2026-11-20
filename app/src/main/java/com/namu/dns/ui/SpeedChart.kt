package com.namu.dns.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.core.stats.SpeedSample

/**
 * 最近 60 个 1 秒采样的双色 sparkline。
 * 纵轴按上下行最大值自适应，所有计算保持 Long/Double，不引入 Float 动画。
 */
@Composable
fun SpeedSparkline(
    samples: List<SpeedSample>,
    modifier: Modifier = Modifier,
) {
    Canvas(modifier) {
        val maxValue = maxOf(
            samples.maxOfOrNull { it.up } ?: 0L,
            samples.maxOfOrNull { it.down } ?: 0L,
            1024L,
        ).toDouble()
        val topPadding = 3.dp.toPx()
        val bottom = size.height - 2.dp.toPx()
        val drawHeight = (bottom - topPadding).coerceAtLeast(1f)

        fun path(values: List<Long>): Path {
            val p = Path()
            if (values.isEmpty()) return p
            val lastIndex = (values.size - 1).coerceAtLeast(1)
            values.forEachIndexed { i, value ->
                val x = if (values.size == 1) 0f else size.width * i / lastIndex
                val y = bottom - (value.toDouble() / maxValue).coerceIn(0.0, 1.0).toFloat() * drawHeight
                if (i == 0) p.moveTo(x, y) else p.lineTo(x, y)
            }
            return p
        }

        drawLine(
            color = NamuColors.Separator.copy(alpha = 0.65f),
            start = Offset(0f, bottom),
            end = Offset(size.width, bottom),
            strokeWidth = 1f,
        )

        val stroke = Stroke(width = 1.8.dp.toPx(), cap = StrokeCap.Round)
        drawPath(path(samples.map { it.up }), color = NamuColors.Orange, style = stroke)
        drawPath(path(samples.map { it.down }), color = NamuColors.Blue, style = stroke)
    }
}

@Composable
fun SpeedLegend(modifier: Modifier = Modifier) {
    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(6.dp)
                .background(NamuColors.Orange, RoundedCornerShape(50)),
        )
        Spacer(Modifier.width(5.dp))
        Text("↑ 上行", fontSize = 11.sp, color = NamuColors.Orange)
        Spacer(Modifier.width(14.dp))
        Box(
            Modifier
                .size(6.dp)
                .background(NamuColors.Blue, RoundedCornerShape(50)),
        )
        Spacer(Modifier.width(5.dp))
        Text("↓ 下行", fontSize = 11.sp, color = NamuColors.Blue)
    }
}
