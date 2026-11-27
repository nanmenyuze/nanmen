package com.namu.dns.ui

import androidx.compose.ui.unit.IntOffset
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.Icon
import androidx.compose.material3.Typography
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.DpOffset
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** U0：3.0 壳的设计令牌；页面不再各自散落 13/14/16/28sp 与随手圆角。 */
object NamuTokens {
    /** 操作蓝：操作与选中统一取色；品牌橙只用于品牌字。 */
    val Brand = Color(0xFF007AFF)
    val BrandOrange = Color(0xFFC54F00)
    val Ink = Color(0xFF151B25)
    val Sub = Color(0xFF606773)
    val Tertiary = Color(0xFF6B7280)
    val Bg = Color(0xFFF2F2F7)
    val Card = Color(0xFFFFFFFF)
    val Border = Color(0xFFE9E9F0)
    /** 首页运行卡的极浅灰层级；深色模式不用，沿用现有卡色。 */
    val CardSoft = Color.White
    val Success = Color(0xFF187A42)
    val Warning = Color(0xFFC77700)
    val Danger = Color(0xFFD92D20)

    const val PressDamping = 0.86f
    const val PressStiffness = 500f

    val Space2 = 2.dp
    val Space4 = 4.dp
    val Space8 = 8.dp
    val Space12 = 12.dp
    val Space16 = 16.dp
    val Space20 = 20.dp
    val Space24 = 24.dp
    val Space32 = 32.dp

    val RadiusCard = 24.dp
    val RadiusRunCard = 30.dp
    val RadiusDataCard = 26.dp
    val RadiusRow = 16.dp
    val RadiusControl = 14.dp
    val RadiusMenu = 22.dp
    val RadiusDialog = 30.dp

    /** 20dp / 2px 线性图标；新页面统一走 NamuIcon。 */
    val IconSize = 20.dp
    val IconStroke = 2.dp

    object Type {
        val PageTitle = TextStyle(fontSize = 32.sp, lineHeight = 40.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp)
        val NavigationTitle = TextStyle(fontSize = 17.sp, lineHeight = 22.sp, fontWeight = FontWeight.SemiBold)
        val Display = TextStyle(fontSize = 28.sp, lineHeight = 34.sp, fontWeight = FontWeight.SemiBold)
        val Title = TextStyle(fontSize = 20.sp, lineHeight = 26.sp, fontWeight = FontWeight.SemiBold)
        val Body = TextStyle(fontSize = 16.sp, lineHeight = 24.sp)
        val Caption = TextStyle(fontSize = 12.sp, lineHeight = 17.sp)
    }
}

object NamuColors {
    // UI 主题状态放在这里，所有颜色 getter 读取同一个 state；
    // 页面里已有 200+ 处 NamuColors.Bg/TextMain 等引用，这样切主题会自动重组，不用逐页替换。
    private val darkState = mutableStateOf(false)
    val isDark: Boolean get() = darkState.value

    internal fun setDark(dark: Boolean) {
        if (darkState.value != dark) darkState.value = dark
    }

    val Bg: Color get() = if (isDark) Color.Black else NamuTokens.Bg
    val Card: Color get() = if (isDark) Color(0xFF1C1C1E) else NamuTokens.Card
    val Floating: Color get() = if (isDark) Color(0xD928282D) else Color(0xD9FFFFFF)
    val GlassSurface: Color get() = if (isDark) Color(0x5228282D) else Color(0x61FFFFFF)
    val GlassRim: Color get() = if (isDark) Color(0xFF707079) else Color.White
    val CardSoft: Color get() = if (isDark) Color(0xFF1C1C1E) else NamuTokens.CardSoft
    val CardPressed: Color get() = if (isDark) Color(0xFF2C2C2E) else Color(0xFFF1F2F7)
    val Separator: Color get() = if (isDark) Color(0xFF38383A) else NamuTokens.Border
    val Fill: Color get() = if (isDark) Color(0xFF303036) else Color(0xFFF0F0F6)
    val FillPressed: Color get() = if (isDark) Color(0xFF2C2C2E) else Color(0xFFE8E8ED)
    val Blue: Color get() = Brand
    /** 浅色采用系统蓝，深色提高亮度；绿色只表达运行状态。 */
    val Brand: Color get() = if (isDark) Color(0xFF0A84FF) else NamuTokens.Brand
    /** 选中态统一走品牌色，绿色不再承担导航/品牌装饰。 */
    val Accent: Color get() = Brand
    /** 品牌橙：仅品牌字使用；深色沿用暖橙。 */
    val BrandOrange: Color get() = if (isDark) Color(0xFFFFA45E) else NamuTokens.BrandOrange
    val Green: Color get() = if (isDark) Color(0xFF30D158) else NamuTokens.Success
    val Red: Color get() = if (isDark) Color(0xFFFF453A) else NamuTokens.Danger
    /** 图形/文字同色：第四五轮统一色板后不再分场景取值，保留别名供图形调用点使用。 */
    val GreenFill: Color get() = Green
    val RedFill: Color get() = Red
    val Orange: Color get() = if (isDark) Color(0xFFFF9F0A) else NamuTokens.Warning
    val Teal: Color get() = if (isDark) Color(0xFF64D2FF) else Color(0xFF30B0C7)
    val TextMain: Color get() = if (isDark) Color(0xFFEDF1F6) else NamuTokens.Ink
    val TextSub: Color get() = if (isDark) Color(0xFFAEAEB2) else NamuTokens.Sub
    val TextTertiary: Color get() = if (isDark) Color(0xFF8E8E93) else NamuTokens.Tertiary
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
                primary = NamuColors.Brand,
                onPrimary = Color.White,
                secondary = NamuColors.Brand,
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
                primary = NamuColors.Brand,
                onPrimary = Color.White,
                secondary = NamuColors.Brand,
                background = NamuColors.Bg,
                surface = NamuColors.Card,
                surfaceVariant = NamuColors.Fill,
                onBackground = NamuColors.TextMain,
                onSurface = NamuColors.TextMain,
                onSurfaceVariant = NamuColors.TextSub,
                error = NamuColors.Red,
            )
        },
        typography = Typography(
            titleLarge = NamuTokens.Type.Title,
            titleMedium = NamuTokens.Type.NavigationTitle,
            bodyLarge = NamuTokens.Type.Body,
            bodySmall = NamuTokens.Type.Caption,
        ),
        shapes = Shapes(
            extraSmall = RoundedCornerShape(12.dp),
            small = RoundedCornerShape(NamuTokens.RadiusControl),
            medium = RoundedCornerShape(NamuTokens.RadiusMenu),
            large = RoundedCornerShape(NamuTokens.RadiusCard),
            extraLarge = RoundedCornerShape(NamuTokens.RadiusDialog),
        ),
        content = content,
    )
}

/** U0：新页面统一入口，20dp / 2px 线性图标。 */
@Composable
fun NamuIcon(
    icon: ImageVector,
    desc: String? = null,
    tint: Color = NamuColors.TextMain,
    size: Dp = NamuTokens.IconSize,
) {
    Icon(icon, contentDescription = desc, tint = tint, modifier = Modifier.size(size))
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
            Text(title, style = NamuTokens.Type.PageTitle, fontFamily = FontFamily.SansSerif, color = NamuColors.TextMain)
            if (subtitle != null) {
                Spacer(Modifier.height(2.dp))
                Text(subtitle, fontSize = 12.sp, color = NamuColors.TextSub)
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
            .padding(start = 20.dp, end = 16.dp, top = 24.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text,
            fontSize = 17.sp,
            fontWeight = FontWeight.SemiBold,
            color = NamuColors.TextMain,
            modifier = Modifier.weight(1f).semantics { heading() },
        )
        trailing?.invoke()
    }
}

@Composable
fun PrimaryTopBar(title: String, subtitle: String = "") {
    Column(
        Modifier.fillMaxWidth()
            .background(NamuColors.Bg)
            .statusBarsPadding()
            .padding(start = 22.dp, end = 22.dp, top = 16.dp, bottom = 10.dp)
    ) {
        Text(
            title,
            modifier = Modifier.semantics { heading() },
            style = NamuTokens.Type.PageTitle,
            fontFamily = FontFamily.SansSerif,
            color = NamuColors.TextMain,
        )
        if (subtitle.isNotEmpty()) {
            Text(
                subtitle,
                modifier = Modifier.padding(top = 3.dp),
                fontSize = 12.sp,
                color = NamuColors.TextSub,
            )
        }
    }
}

/** 首页、模块、设置共用的大标题顶栏：状态栏留白、标题基线和操作区高度完全一致。 */
@Composable
fun MainPageTopBar(
    title: String,
    titleColor: Color = NamuColors.TextMain,
    leading: @Composable (() -> Unit)? = null,
    titleContent: @Composable (() -> Unit)? = null,
    trailing: @Composable (() -> Unit)? = null,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(NamuColors.Bg)
            .statusBarsPadding()
            .padding(start = 22.dp, end = 16.dp, top = 16.dp, bottom = 18.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (leading != null) {
            Box(Modifier.height(44.dp), contentAlignment = Alignment.Center) { leading() }
            Spacer(Modifier.width(6.dp))
        }
        Box(Modifier.weight(1f).height(44.dp), contentAlignment = Alignment.CenterStart) {
            if (titleContent != null) {
                titleContent()
            } else {
                Text(
                    title,
                    style = NamuTokens.Type.PageTitle,
                    fontFamily = FontFamily.SansSerif,
                    color = titleColor,
                    maxLines = 1,
                )
            }
        }
        Box(Modifier.height(44.dp), contentAlignment = Alignment.Center) {
            trailing?.invoke()
        }
    }
}

/**
 * 主页面统一外壳：正文与顶栏分层捕获，支持大标题折叠和真实背景模糊。
 * 顶栏不会捕获自身，避免递归采样造成文字重影。
 */
@Composable
fun MainPageChrome(
    title: String,
    titleColor: Color = NamuColors.TextMain,
    trailing: @Composable (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val scrollState = rememberScrollState()
    val collapseRange = with(LocalDensity.current) { 56.dp.toPx() }
    val collapse = (scrollState.value / collapseRange).coerceIn(0f, 1f)
    val contentLayer = rememberGraphicsLayer()
    var contentOrigin by remember { mutableStateOf(Offset.Zero) }
    var topBarOrigin by remember { mutableStateOf(Offset.Zero) }

    Box(Modifier.fillMaxSize().background(NamuColors.Bg)) {
        Column(
            Modifier.fillMaxSize()
                .onGloballyPositioned { contentOrigin = it.positionInRoot() }
                .drawWithContent {
                    contentLayer.record { this@drawWithContent.drawContent() }
                    drawLayer(contentLayer)
                }
                .verticalScroll(scrollState)
                .statusBarsPadding()
                .padding(top = 78.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(Modifier.widthIn(max = 560.dp).fillMaxWidth(), content = content)
        }

        Box(Modifier.fillMaxWidth().onGloballyPositioned { topBarOrigin = it.positionInRoot() }) {
            Spacer(
                Modifier.matchParentSize().clipToBounds().blur(18.dp).drawBehind {
                    val offset = contentOrigin - topBarOrigin
                    translate(offset.x, offset.y) { drawLayer(contentLayer) }
                },
            )
            Spacer(
                Modifier.matchParentSize().drawBehind {
                    drawRect(NamuColors.Bg.copy(alpha = .26f + .40f * collapse))
                    drawRect(
                        Brush.verticalGradient(
                            listOf(NamuColors.GlassRim.copy(alpha = .10f), Color.Transparent),
                        ),
                    )
                },
            )
            Column(Modifier.fillMaxWidth().statusBarsPadding()) {
                Box(
                    Modifier.fillMaxWidth().height(72.dp).padding(start = 22.dp, end = 16.dp),
                ) {
                    Text(
                        title,
                        style = NamuTokens.Type.PageTitle,
                        fontFamily = FontFamily.SansSerif,
                        color = titleColor,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.align(Alignment.CenterStart)
                            .padding(end = 112.dp)
                            .alpha(1f - collapse)
                            .graphicsLayer {
                                val scale = 1f - .06f * collapse
                                scaleX = scale
                                scaleY = scale
                            }
                            .semantics { heading() },
                    )
                    Text(
                        title,
                        style = NamuTokens.Type.NavigationTitle,
                        fontFamily = FontFamily.SansSerif,
                        color = titleColor,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.align(Alignment.Center).alpha(collapse),
                    )
                    if (trailing != null) {
                        Box(
                            Modifier.align(Alignment.CenterEnd)
                                .clip(CircleShape)
                                .background(NamuColors.GlassSurface),
                        ) { trailing() }
                    }
                }
                Box(
                    Modifier.fillMaxWidth().height(.5.dp)
                        .background(NamuColors.Separator.copy(alpha = collapse * .65f)),
                )
            }
        }
    }
}

private val LocalDetailScroll = compositionLocalOf { 0f }

@Composable
internal fun DetailChrome(content: @Composable () -> Unit) {
    var scroll by rememberSaveable { mutableStateOf(0f) }
    val range = with(LocalDensity.current) { 36.dp.toPx() }
    val connection = remember {
        object : NestedScrollConnection {
            override fun onPostScroll(consumed: Offset, available: Offset, source: NestedScrollSource): Offset {
                if (consumed.y != 0f) scroll = (scroll - consumed.y).coerceAtLeast(0f)
                return Offset.Zero
            }

            override suspend fun onPostFling(consumed: Velocity, available: Velocity): Velocity {
                if (available.y > 0f) scroll = 0f
                return Velocity.Zero
            }
        }
    }
    CompositionLocalProvider(LocalDetailScroll provides (scroll / range).coerceIn(0f, 1f)) {
        Box(Modifier.fillMaxSize().background(NamuColors.Bg).nestedScroll(connection)) { content() }
    }
}

/** 主要内容可以独立滚动，标题栏保持固定。 */
@Composable
fun DetailList(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier.fillMaxSize().background(NamuColors.Bg)
            .verticalScroll(rememberScrollState())
            .padding(top = 4.dp),
        content = content,
    )
}

@Composable
internal fun Modifier.menuPressMotion(interaction: MutableInteractionSource): Modifier {
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (pressed) .94f else 1f,
        animationSpec = spring(dampingRatio = NamuTokens.PressDamping, stiffness = NamuTokens.PressStiffness),
        label = "menu-button-press",
    )
    return graphicsLayer { scaleX = scale; scaleY = scale }
}

@Composable
internal fun FloatingMenu(
    expanded: Boolean,
    onDismissRequest: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    val menuShape = RoundedCornerShape(NamuTokens.RadiusMenu)
    DropdownMenu(
        expanded = expanded,
        onDismissRequest = onDismissRequest,
        modifier = modifier.border(.5.dp, NamuColors.GlassRim.copy(alpha = .38f), menuShape),
        offset = DpOffset(0.dp, 6.dp),
        shape = menuShape,
        containerColor = NamuColors.Floating,
        shadowElevation = 4.dp,
    ) {
        var shown by remember { mutableStateOf(false) }
        LaunchedEffect(Unit) { shown = true }
        val scale by animateFloatAsState(
            if (shown) 1f else .92f,
            spring(dampingRatio = .80f, stiffness = 460f),
            label = "glass-menu-scale",
        )
        val opacity by animateFloatAsState(if (shown) 1f else 0f, tween(140), label = "glass-menu-alpha")
        Column(
            Modifier.graphicsLayer {
                scaleX = scale
                scaleY = scale
                alpha = opacity
                transformOrigin = TransformOrigin(.5f, 0f)
            },
            content = content,
        )
    }
}

/** 二级页共用返回栏。 */
@Composable
fun ShadowTopBar(
    title: String,
    left: @Composable () -> Unit,
    right: @Composable () -> Unit = {},
) {
    val scroll = LocalDetailScroll.current
    val surface = lerp(NamuColors.GlassSurface, NamuColors.Floating, scroll * 0.70f)
    Column(
        Modifier.fillMaxWidth().background(
            Brush.verticalGradient(listOf(NamuColors.Bg, surface)),
        ),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .statusBarsPadding()
                .height(52.dp)
                .padding(horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier.size(44.dp).background(NamuColors.GlassSurface, CircleShape),
                contentAlignment = Alignment.Center,
            ) { left() }
            Text(
                title,
                style = NamuTokens.Type.NavigationTitle,
                color = NamuColors.TextMain,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Box(Modifier.size(44.dp), contentAlignment = Alignment.Center) { right() }
        }
        Box(Modifier.fillMaxWidth().height(0.5.dp).background(NamuColors.Separator.copy(alpha = scroll)))
    }
}

@Composable
fun GroupCard(radius: Dp = NamuTokens.RadiusCard, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(radius)
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .clip(shape)
            .background(NamuColors.Card),
        content = content,
    )
}

/** 首页运行卡使用白色实底，和页面背景区分。 */
@Composable
fun SoftCard(content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(NamuTokens.RadiusRunCard)
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .clip(shape)
            .background(NamuColors.CardSoft),
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
    rightContent: (@Composable RowScope.() -> Unit)? = null,
    onClick: (() -> Unit)? = null,
    minHeight: Dp = 56.dp,
) {
    // U5：带 chevron 的整行只负责导航；switch / 右侧按钮独占命中区；
    // 无 chevron 且右侧有控件/数字的状态行不可点。
    val compact = minHeight <= 52.dp
    val rowClickable = onClick != null && (chevron || rightContent == null)
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(if (pressed) 0.985f else 1f, spring(dampingRatio = NamuTokens.PressDamping, stiffness = NamuTokens.PressStiffness), label = "row-scale")
    val pressBg by animateColorAsState(
        if (pressed) NamuColors.FillPressed else Color.Transparent,
        tween(120),
        label = "row-press",
    )
    Column(
        Modifier
            .fillMaxWidth()
            .graphicsLayer { if (rowClickable) { scaleX = scale; scaleY = scale } }
            .background(pressBg)
            .then(
                if (rowClickable) {
                    Modifier.clickable(interactionSource = interaction, indication = null) { onClick?.invoke() }
                } else {
                    Modifier
                },
            ),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = minHeight)
                .padding(horizontal = 16.dp, vertical = if (compact) 6.dp else 9.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f).padding(end = 8.dp)) {
                Text(
                    title,
                    style = if (compact) NamuTokens.Type.Body.copy(lineHeight = 20.sp) else NamuTokens.Type.Body.copy(
                        fontWeight = if (rowClickable) FontWeight.Medium else FontWeight.Normal,
                    ),
                    color = NamuColors.TextMain,
                )
                if (subtitle != null) {
                    Spacer(Modifier.height(1.dp))
                    Text(subtitle, fontSize = 12.sp, color = NamuColors.TextSub, lineHeight = 16.sp)
                }
            }
            if (rightContent != null) {
                rightContent()
            } else {
                if (value != null) {
                    Text(
                        value,
                        fontSize = 13.sp,
                        color = valueColor,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.widthIn(max = 144.dp),
                    )
                }
                if (chevron) {
                    Spacer(Modifier.width(6.dp))
                    Chevron()
                }
            }
        }
        if (showDivider) RowDivider()
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
fun IosSwitch(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean = true,
    pendingLabel: String? = null,
) {
    val progress by animateFloatAsState(
        targetValue = if (checked) 1f else 0f,
        animationSpec = spring(dampingRatio = 0.82f, stiffness = 380f),
        label = "ios-switch",
    )
    val sheen = remember { Animatable(1f) }
    var wasChecked by remember { mutableStateOf(checked) }
    LaunchedEffect(checked) {
        val justEnabled = checked && !wasChecked
        wasChecked = checked
        if (justEnabled) {
            sheen.snapTo(0f)
            sheen.animateTo(1f, tween(430, easing = FastOutSlowInEasing))
        } else {
            sheen.snapTo(1f)
        }
    }
    val track = lerp(NamuColors.TrackOff, NamuColors.Blue, progress)
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val press by animateFloatAsState(
        if (pressed) 1f else 0f,
        spring(dampingRatio = NamuTokens.PressDamping, stiffness = NamuTokens.PressStiffness),
        label = "switch-press",
    )
    val haptic = LocalHapticFeedback.current
    // 外层 51x48 是实际触控区；内层 51x31 才是视觉开关，保证 TalkBack/手指都够得着。
    Box(
        Modifier
            .size(51.dp, 48.dp)
            .semantics {
                role = Role.Switch
                stateDescription = when {
                    pendingLabel != null -> pendingLabel
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
                .graphicsLayer { val scale = 1f - .03f * press; scaleX = scale; scaleY = scale }
                .clip(RoundedCornerShape(16.dp))
                .background(track)
                .padding(2.dp),
            contentAlignment = Alignment.CenterStart,
        ) {
            Canvas(Modifier.matchParentSize()) {
                val phase = sheen.value
                if (checked && phase > 0f && phase < 1f) {
                    val glowWidth = size.width * .55f
                    val edge = (size.width + glowWidth * 2f) * phase - glowWidth
                    drawRect(
                        brush = Brush.linearGradient(
                            colors = listOf(Color.Transparent, Color.White.copy(alpha = .39f), Color.Transparent),
                            start = Offset(edge - glowWidth, size.height),
                            end = Offset(edge + glowWidth, 0f),
                        ),
                    )
                }
            }
            Box(
                Modifier
                    .offset { IntOffset((20.dp * progress).roundToPx(), 0) }
                    .size(27.dp)
                    .shadow(1.5.dp, CircleShape)
                    .clip(CircleShape)
                    .background(Color.White)
                    .graphicsLayer {
                        scaleX = 1f + .07f * press
                        scaleY = 1f - .04f * press
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
        shape = CircleShape,
        colors = ButtonDefaults.buttonColors(
            containerColor = NamuColors.Brand,
            disabledContainerColor = NamuColors.Brand.copy(alpha = 0.4f),
            contentColor = Color.White,
        ),
        modifier = modifier.fillMaxWidth().height(52.dp),
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
        if (subtitle.isNotBlank()) {
            Spacer(Modifier.height(6.dp))
            Text(subtitle, fontSize = 13.sp, color = NamuColors.TextSub, lineHeight = 18.sp)
        }
        if (buttonText != null && onButton != null) {
            Spacer(Modifier.height(18.dp))
            IosButton(buttonText, onButton, modifier = Modifier.widthIn(max = 240.dp))
        }
    }
}

@Composable
fun TextAction(
    text: String,
    color: Color = NamuColors.Blue,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    TextButton(
        onClick = onClick,
        enabled = enabled,
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

/** 二级页顶栏：左侧返回，标题与主页面统一使用系统无衬线字。 */
@Composable
fun SecondaryTopBar(
    title: String,
    subtitle: String = "",
    onBack: (() -> Unit)? = null,
    actions: (@Composable () -> Unit)? = null,
) {
    Column(
        Modifier.fillMaxWidth()
            .background(NamuColors.Bg)
            .statusBarsPadding()
            .padding(start = 10.dp, end = 22.dp, top = 6.dp, bottom = 8.dp)
    ) {
        if (onBack != null) {
            TextAction("‹ 返回", color = NamuColors.TextSub) { onBack() }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f).padding(start = 12.dp, top = 2.dp)) {
                Text(
                    title,
                    modifier = Modifier.semantics { heading() },
                    style = NamuTokens.Type.PageTitle,
                    fontFamily = FontFamily.SansSerif,
                    color = NamuColors.TextMain,
                )
                if (subtitle.isNotEmpty()) {
                    Text(subtitle, fontSize = 12.sp, color = NamuColors.TextSub, modifier = Modifier.padding(top = 2.dp))
                }
            }
            actions?.invoke()
        }
    }
}

