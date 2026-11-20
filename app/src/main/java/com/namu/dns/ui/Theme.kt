package com.namu.dns.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

object NamuColors {
    // UI 主题状态放在这里，所有颜色 getter 读取同一个 state；
    // 页面里已有 200+ 处 NamuColors.Bg/TextMain 等引用，这样切主题会自动重组，不用逐页替换。
    private val darkState = mutableStateOf(false)
    val isDark: Boolean get() = darkState.value

    internal fun setDark(dark: Boolean) {
        if (darkState.value != dark) darkState.value = dark
    }

    val Bg: Color get() = if (isDark) Color(0xFF141D1A) else Color(0xFFF4F7F5)
    val Card: Color get() = if (isDark) Color(0xFF1C1C1E) else Color(0xFFFFFFFF)
    val CardPressed: Color get() = if (isDark) Color(0xFF2C2C2E) else Color(0xFFE5E5EA)
    val Separator: Color get() = if (isDark) Color(0xFF38383A) else Color(0xFFE3E3E8)
    val Fill: Color get() = if (isDark) Color(0xFF1C1C1E) else Color(0xFFF2F2F7)
    val FillPressed: Color get() = if (isDark) Color(0xFF2C2C2E) else Color(0xFFE8E8ED)
    val Blue: Color get() = if (isDark) Color(0xFF0A84FF) else Color(0xFF007AFF)
    val Accent: Color get() = if (isDark) Color(0xFF9EDAC0) else Color(0xFF165C47)
    val Green: Color get() = if (isDark) Color(0xFF30D158) else Color(0xFF34C759)
    val Red: Color get() = if (isDark) Color(0xFFFF453A) else Color(0xFFFF3B30)
    val Orange: Color get() = if (isDark) Color(0xFFFF9F0A) else Color(0xFFFF9500)
    val Teal: Color get() = if (isDark) Color(0xFF64D2FF) else Color(0xFF30B0C7)
    val TextMain: Color get() = if (isDark) Color(0xFFF2F2F7) else Color(0xFF1C1C1E)
    val TextSub: Color get() = if (isDark) Color(0xFFAEAEB2) else Color(0xFF596760)
    val TextTertiary: Color get() = if (isDark) Color(0xFF636366) else Color(0xFFC7C7CC)
    val TrackOff: Color get() = if (isDark) Color(0xFF3A3A3C) else Color(0xFFE9E9EA)
}

@Composable
fun NamuTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    NamuColors.setDark(darkTheme)
    MaterialTheme(
        colorScheme = if (darkTheme) {
            darkColorScheme(
                primary = NamuColors.Blue,
                onPrimary = Color.White,
                secondary = NamuColors.Teal,
                background = NamuColors.Bg,
                surface = NamuColors.Card,
                surfaceVariant = NamuColors.Fill,
                onBackground = NamuColors.TextMain,
                onSurface = NamuColors.TextMain,
                onSurfaceVariant = NamuColors.TextSub,
                error = NamuColors.Red,
            )
        } else {
            lightColorScheme(
                primary = NamuColors.Blue,
                onPrimary = Color.White,
                secondary = NamuColors.Teal,
                background = NamuColors.Bg,
                surface = NamuColors.Card,
                surfaceVariant = NamuColors.Fill,
                onBackground = NamuColors.TextMain,
                onSurface = NamuColors.TextMain,
                onSurfaceVariant = NamuColors.TextSub,
                error = NamuColors.Red,
            )
        },
        content = content,
    )
}

@Composable
fun LargeTitle(title: String, subtitle: String? = null, trailing: @Composable (() -> Unit)? = null) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(start = 20.dp, end = 16.dp, top = 10.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 32.sp, fontWeight = FontWeight.Bold, color = NamuColors.TextMain, letterSpacing = (-0.5).sp)
            if (subtitle != null) {
                Spacer(Modifier.height(2.dp))
                Text(subtitle, fontSize = 13.sp, color = NamuColors.TextSub)
            }
        }
        trailing?.invoke()
    }
}

@Composable
fun SectionHeader(text: String, trailing: @Composable (() -> Unit)? = null) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(start = 20.dp, end = 16.dp, top = 20.dp, bottom = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text.uppercase(),
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            color = NamuColors.TextSub,
            letterSpacing = 0.5.sp,
            modifier = Modifier.weight(1f),
        )
        trailing?.invoke()
    }
}

/** iOS / Shadowrocket 风格的蓝色顶部导航栏。 */
@Composable
fun ShadowTopBar(
    title: String,
    left: @Composable () -> Unit,
    right: @Composable () -> Unit = {},
) {
    Column(Modifier.fillMaxWidth().background(NamuColors.Bg)) {
        Row(
            Modifier
                .fillMaxWidth()
                .statusBarsPadding()
                .height(46.dp)
                .padding(horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(44.dp), contentAlignment = Alignment.Center) { left() }
            Text(
                title,
                fontSize = 17.sp,
                fontWeight = FontWeight.SemiBold,
                color = NamuColors.TextMain,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.weight(1f),
            )
            Box(Modifier.size(44.dp), contentAlignment = Alignment.Center) { right() }
        }
        Box(Modifier.fillMaxWidth().height(0.5.dp).background(Color(0x22000000)))
    }
}

@Composable
fun GroupCard(glow: Boolean = false, content: @Composable ColumnScope.() -> Unit) {
    // 每张卡片进屏时轻微上浮 + 淡入，和 iOS 分组列表的节奏一致。
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { visible = true }
    val a by animateFloatAsState(if (visible) 1f else 0f, tween(200), label = "card-alpha")
    val dy by animateDpAsState(if (visible) 0.dp else 10.dp, tween(260), label = "card-offset")
    // 已连接时卡片边缘做很轻的呼吸描边；glow=false 的卡片绝不创建无限动画，
    // 否则每个列表页每张卡都会 1.6 秒循环请求帧，亮屏白耗电。
    val pulse = if (glow) {
        rememberInfiniteTransition(label = "glow").animateFloat(
            initialValue = 0.18f,
            targetValue = 0.5f,
            animationSpec = infiniteRepeatable(tween(1600), RepeatMode.Reverse),
            label = "glow-alpha",
        ).value
    } else {
        0f
    }
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp)
            .offset(y = dy)
            .alpha(a)
            .shadow(0.5.dp, RoundedCornerShape(14.dp))
            .clip(RoundedCornerShape(14.dp))
            .background(NamuColors.Card)
            .then(
                if (glow) Modifier.border(1.dp, NamuColors.Blue.copy(alpha = pulse), RoundedCornerShape(14.dp))
                else Modifier,
            ),
        content = content,
    )
}

@Composable
fun RowDivider(startInset: Dp = 16.dp) {
    Box(
        Modifier
            .padding(start = startInset)
            .fillMaxWidth()
            .height(0.5.dp)
            .background(NamuColors.Separator),
    )
}

@Composable
fun SettingsRow(
    title: String,
    subtitle: String? = null,
    value: String? = null,
    valueColor: Color = NamuColors.TextSub,
    chevron: Boolean = false,
    showDivider: Boolean = true,
    icon: ImageVector? = null,
    iconTint: Color = NamuColors.Blue,
    rightContent: (@Composable RowScope.() -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    // iOS 列表点按反馈：轻微内缩 + 淡灰底，不用水波纹。
    val scale by animateFloatAsState(if (pressed) 0.985f else 1f, spring(stiffness = 420f), label = "row-scale")
    val pressBg by animateColorAsState(
        if (pressed) NamuColors.FillPressed else Color.Transparent,
        tween(120),
        label = "row-press",
    )
    Column(
        Modifier
            .fillMaxWidth()
            .graphicsLayer { scaleX = scale; scaleY = scale }
            .background(pressBg)
            .then(
                if (onClick != null) {
                    Modifier.clickable(interactionSource = interaction, indication = null) { onClick() }
                } else {
                    Modifier
                },
            ),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .padding(horizontal = 16.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (icon != null) {
                Icon(icon, contentDescription = null, tint = iconTint, modifier = Modifier.size(21.dp))
                Spacer(Modifier.width(13.dp))
            }
            Column(Modifier.weight(1f)) {
                Text(title, fontSize = 16.sp, color = NamuColors.TextMain)
                if (subtitle != null) {
                    Spacer(Modifier.height(1.dp))
                    AnimatedContent(
                        targetState = subtitle,
                        transitionSpec = {
                            (fadeIn(tween(180)) + slideInVertically(tween(200)) { it / 3 }) togetherWith
                                (fadeOut(tween(110)) + slideOutVertically(tween(160)) { -it / 4 })
                        },
                        label = "row-subtitle",
                    ) { text ->
                        Text(text, fontSize = 12.sp, color = NamuColors.TextSub, lineHeight = 16.sp)
                    }
                }
            }
            if (rightContent != null) {
                rightContent()
            } else {
                if (value != null) {
                    Text(
                        value,
                        fontSize = 15.sp,
                        color = valueColor,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.widthIn(max = 190.dp),
                    )
                }
                if (chevron) {
                    Spacer(Modifier.width(6.dp))
                    Chevron()
                }
            }
        }
        if (showDivider) RowDivider(if (icon != null) 56.dp else 16.dp)
    }
}

@Composable
fun Chevron(color: Color = NamuColors.TextTertiary) {
    Canvas(Modifier.size(9.dp, 15.dp)) {
        val w = size.width
        val h = size.height
        drawLine(color, Offset(0.5f, h * 0.10f), Offset(w, h * 0.5f), strokeWidth = 2.dp.toPx())
        drawLine(color, Offset(w, h * 0.5f), Offset(0.5f, h * 0.90f), strokeWidth = 2.dp.toPx())
    }
}

@Composable
fun IosSwitch(checked: Boolean, onCheckedChange: (Boolean) -> Unit, enabled: Boolean = true) {
    val progress by animateFloatAsState(
        targetValue = if (checked) 1f else 0f,
        animationSpec = spring(dampingRatio = 0.82f, stiffness = 380f),
        label = "ios-switch",
    )
    val track = lerp(NamuColors.TrackOff, NamuColors.Blue, progress)
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val pressScale by animateFloatAsState(if (pressed) 0.95f else 1f, spring(stiffness = 500f), label = "switch-press")
    val haptic = LocalHapticFeedback.current
    // 外层 51x48 是实际触控区；内层 51x31 才是视觉开关，保证 TalkBack/手指都够得着。
    Box(
        Modifier
            .size(51.dp, 48.dp)
            .semantics {
                role = Role.Switch
                stateDescription = when {
                    !enabled -> "不可用"
                    checked -> "已开启"
                    else -> "已关闭"
                }
                if (!enabled) disabled()
            }
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onCheckedChange(!checked)
            },
        contentAlignment = Alignment.Center,
    ) {
        Box(
            Modifier
                .size(51.dp, 31.dp)
                .graphicsLayer { scaleX = pressScale; scaleY = pressScale }
                .clip(RoundedCornerShape(16.dp))
                .background(track)
                .padding(2.dp),
            contentAlignment = Alignment.CenterStart,
        ) {
            Box(
                Modifier
                    .offset(x = 20.dp * progress)
                    .size(27.dp)
                    .shadow(1.5.dp, CircleShape)
                    .clip(CircleShape)
                    .background(Color.White)
                    .graphicsLayer {
                        // 按下时拇指轻微横向拉伸，松开回弹，接近 iOS 的手感。
                        scaleX = if (pressed) 0.92f else 1f
                        scaleY = if (pressed) 1.06f else 1f
                    },
            )
        }
    }
}

@Composable
fun SwitchRow(
    title: String,
    subtitle: String? = null,
    checked: Boolean,
    showDivider: Boolean = true,
    onCheckedChange: (Boolean) -> Unit,
) {
    SettingsRow(
        title = title,
        subtitle = subtitle,
        showDivider = showDivider,
        rightContent = {
            IosSwitch(checked = checked, onCheckedChange = onCheckedChange)
        },
    )
}

@Composable
fun IosButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    loading: Boolean = false,
) {
    Button(
        onClick = onClick,
        enabled = enabled && !loading,
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = NamuColors.Blue,
            disabledContainerColor = NamuColors.Blue.copy(alpha = 0.4f),
            contentColor = Color.White,
        ),
        modifier = modifier.fillMaxWidth().height(50.dp),
    ) {
        if (loading) {
            CircularProgressIndicator(Modifier.size(18.dp), color = Color.White, strokeWidth = 2.dp)
        } else {
            Text(text, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
fun FooterText(text: String) {
    Text(
        text,
        fontSize = 12.sp,
        color = NamuColors.TextSub,
        lineHeight = 17.sp,
        modifier = Modifier.padding(start = 20.dp, end = 20.dp, top = 10.dp),
    )
}

@Composable
fun CheckMark(color: Color = NamuColors.Blue) {
    Canvas(Modifier.size(19.dp, 15.dp)) {
        val w = size.width
        val h = size.height
        drawLine(color, Offset(w * 0.05f, h * 0.52f), Offset(w * 0.40f, h * 0.88f), strokeWidth = 2.dp.toPx())
        drawLine(color, Offset(w * 0.40f, h * 0.88f), Offset(w * 0.95f, h * 0.10f), strokeWidth = 2.dp.toPx())
    }
}

@Composable
fun PillBadge(text: String, color: Color) {
    Box(
        Modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.12f))
            .padding(horizontal = 8.dp, vertical = 3.dp),
    ) {
        Text(text, color = color, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun EmptyState(
    title: String,
    subtitle: String,
    icon: ImageVector? = null,
    buttonText: String? = null,
    onButton: (() -> Unit)? = null,
) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 32.dp, vertical = 60.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        icon?.let {
            Box(
                Modifier
                    .size(62.dp)
                    .clip(CircleShape)
                    .background(NamuColors.Fill),
                contentAlignment = Alignment.Center,
            ) {
                Icon(it, contentDescription = null, tint = NamuColors.TextTertiary, modifier = Modifier.size(30.dp))
            }
            Spacer(Modifier.height(16.dp))
        }
        Text(title, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, color = NamuColors.TextMain)
        Spacer(Modifier.height(6.dp))
        Text(subtitle, fontSize = 13.sp, color = NamuColors.TextSub, lineHeight = 18.sp)
        if (buttonText != null && onButton != null) {
            Spacer(Modifier.height(18.dp))
            IosButton(buttonText, onButton, modifier = Modifier.widthIn(max = 240.dp))
        }
    }
}

@Composable
fun TextAction(text: String, color: Color = NamuColors.Blue, modifier: Modifier = Modifier, onClick: () -> Unit) {
    TextButton(
        onClick = onClick,
        modifier = modifier.heightIn(min = 48.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 8.dp),
    ) {
        Text(text, color = color, fontSize = 16.sp)
    }
}

/** 12–13sp 的文字操作按钮也保留 48dp 触控高度，避免“字小且点不中”。 */
@Composable
fun MiniTextAction(
    text: String,
    color: Color = NamuColors.Blue,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Box(
        modifier
            .heightIn(min = 48.dp)
            .clickable(enabled = enabled) { onClick() }
            .padding(horizontal = 4.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text,
            fontSize = 12.sp,
            color = if (enabled) color else NamuColors.TextTertiary,
        )
    }
}

fun formatBytes(v: Long): String {
    if (v < 1024) return "$v B"
    val units = listOf("KB", "MB", "GB", "TB")
    var value = v.toDouble() / 1024.0
    var i = 0
    while (value >= 1024 && i < units.size - 1) {
        value /= 1024.0
        i++
    }
    return if (value >= 100) "${value.toInt()} ${units[i]}" else String.format(java.util.Locale.US, "%.1f %s", value, units[i])
}

fun formatAgo(ts: Long): String {
    if (ts <= 0) return "尚未更新"
    val diff = System.currentTimeMillis() - ts
    return when {
        diff < 60_000 -> "刚刚"
        diff < 3_600_000 -> "${diff / 60_000} 分钟前"
        diff < 86_400_000 -> "${diff / 3_600_000} 小时前"
        diff < 30L * 86_400_000 -> "${diff / 86_400_000} 天前"
        else -> {
            val cal = java.util.Calendar.getInstance()
            cal.timeInMillis = ts
            String.format(java.util.Locale.US, "%02d-%02d", cal.get(java.util.Calendar.MONTH) + 1, cal.get(java.util.Calendar.DAY_OF_MONTH))
        }
    }
}

fun hostOf(url: String): String {
    if (url.isBlank()) return "未设置"
    return try {
        java.net.URI(url).host ?: url
    } catch (_: Exception) {
        url
    }
}
