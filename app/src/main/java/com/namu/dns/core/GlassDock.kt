package com.namu.dns.core

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.waitForUpOrCancellation
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.BarChart
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Layers
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.ClipOp
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.ui.NamuColors
import com.namu.dns.ui.NamuTokens
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
internal fun GlassDock(
    tabs: List<MainTab>,
    selected: MainTab,
    onSelect: (MainTab) -> Unit,
) {
    val shape = RoundedCornerShape(32.dp)
    val labelsLayer = rememberGraphicsLayer()
    val currentSelect by rememberUpdatedState(onSelect)
    val currentTab by rememberUpdatedState(selected)
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    val haptic = LocalHapticFeedback.current

    var pressed by remember(tabs) { mutableStateOf(false) }
    var pressPeak by remember(tabs) { mutableStateOf(false) }
    var dragging by remember(tabs) { mutableStateOf(false) }
    var fingerSlot by remember(tabs) { mutableFloatStateOf(0f) }
    val selectedSlot = tabs.indexOf(selected).coerceAtLeast(0)
    val targetSlot = selectedSlot.toFloat()
    val slotMotion = remember(tabs) { Animatable(targetSlot) }
    val liquid = remember(tabs) { Animatable(1f) }
    var liquidFrom by remember(tabs) { mutableFloatStateOf(targetSlot) }
    var liquidTo by remember(tabs) { mutableFloatStateOf(targetSlot) }
    var pendingDragSlot by remember(tabs) { mutableStateOf<Float?>(null) }

    LaunchedEffect(tabs, selectedSlot, dragging) {
        if (dragging) return@LaunchedEffect
        val target = selectedSlot.toFloat()
        val from = pendingDragSlot ?: slotMotion.value
        pendingDragSlot = null
        if (abs(from - target) < .001f) {
            slotMotion.snapTo(target)
            liquid.snapTo(1f)
            return@LaunchedEffect
        }
        slotMotion.snapTo(from)
        liquidFrom = from
        liquidTo = target
        liquid.snapTo(0f)
        launch {
            slotMotion.animateTo(
                target,
                spring(dampingRatio = .74f, stiffness = 420f),
            )
        }
        liquid.animateTo(1f, tween(durationMillis = 520, easing = FastOutSlowInEasing))
    }
    LaunchedEffect(pressed) {
        pressPeak = pressed
        if (pressed) {
            delay(115)
            pressPeak = false
        }
    }
    val lift by animateFloatAsState(
        when {
            pressed && pressPeak -> 1f
            pressed || dragging -> .74f
            else -> 0f
        },
        spring(dampingRatio = NamuTokens.PressDamping, stiffness = NamuTokens.PressStiffness),
        label = "glass lift",
    )
    val surface = NamuColors.Card
    val accent = NamuColors.Accent
    val rim = NamuColors.Separator

    Box(
        Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 20.dp, vertical = 12.dp),
        contentAlignment = Alignment.Center,
    ) {
        Box(
            Modifier.widthIn(max = 340.dp).fillMaxWidth()
                .shadow(8.dp, shape)
                .pointerInput(tabs, rtl) {
                    awaitEachGesture {
                        awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
                        pressed = true
                        try {
                            waitForUpOrCancellation(pass = PointerEventPass.Initial)
                        } finally {
                            pressed = false
                        }
                    }
                }
                .pointerInput(tabs, rtl) {
                    var x = 0f
                    fun slot(): Float {
                        val position = x / size.width.coerceAtLeast(1) * tabs.size
                        return ((if (rtl) tabs.size - position else position) - .5f)
                            .coerceIn(0f, tabs.lastIndex.toFloat())
                    }
                    detectHorizontalDragGestures(
                        onDragStart = { start ->
                            x = start.x
                            fingerSlot = slot()
                            pendingDragSlot = null
                            dragging = true
                        },
                        onHorizontalDrag = { change, _ ->
                            x = change.position.x
                            fingerSlot = slot()
                        },
                        onDragEnd = {
                            val target = tabs[fingerSlot.roundToInt()]
                            pendingDragSlot = fingerSlot
                            dragging = false
                            if (target != currentTab) {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                currentSelect(target)
                            }
                        },
                        onDragCancel = {
                            pendingDragSlot = fingerSlot
                            dragging = false
                        },
                    )
                },
        ) {
            // 实色表面：不再采样页面层，避免内容透过 Dock 形成穿影。
            Spacer(
                Modifier.matchParentSize()
                    .background(surface, shape)
                    .border(.5.dp, rim.copy(alpha = if (NamuColors.isDark) .35f else .72f), shape),
            )

            Row(
                Modifier.fillMaxWidth().height(64.dp).selectableGroup().drawWithContent {
                    labelsLayer.record { this@drawWithContent.drawContent() }
                    val cell = size.width / tabs.size
                    val slot = if (dragging) fingerSlot else slotMotion.value
                    val visualSlot = if (rtl) tabs.lastIndex - slot else slot
                    val center = Offset((visualSlot + .5f) * cell, size.height / 2)
                    val raised = lift.coerceIn(0f, 1f)
                    val progress = liquid.value.coerceIn(0f, 1f)
                    val travel = min(1f, abs(liquidTo - liquidFrom))
                    val wave = sin(progress * PI.toFloat())
                    val dragTravel = min(1f, abs(fingerSlot - selectedSlot.toFloat()))
                    val stretch = if (dragging) {
                        1.10f + .28f * dragTravel
                    } else {
                        1f + .40f * wave * travel
                    }
                    val squash = if (dragging) {
                        .96f - .02f * dragTravel
                    } else {
                        1f - .10f * wave * travel
                    }
                    val baseWidth = cell - 6.dp.toPx() + 6.dp.toPx() * raised
                    val baseHeight = size.height - 8.dp.toPx() + 11.dp.toPx() * raised
                    val lensSize = Size(baseWidth * stretch, baseHeight * squash)
                    val topLeft = center - Offset(lensSize.width / 2, lensSize.height / 2)
                    val radius = CornerRadius(lensSize.height / 2)
                    val lens = Path().apply { addRoundRect(RoundRect(Rect(topLeft, lensSize), radius)) }

                    // 选中 lens 改实色主色浅底，保留拉伸/squash 动效但不再放大页面内容。
                    clipPath(lens) {
                        drawRoundRect(
                            color = accent.copy(alpha = if (NamuColors.isDark) .16f else .10f),
                            topLeft = topLeft, size = lensSize, cornerRadius = radius,
                        )
                    }
                    drawRoundRect(
                        color = if (NamuColors.isDark) rim.copy(alpha = .45f) else Color.White.copy(alpha = .62f),
                        topLeft = topLeft, size = lensSize, cornerRadius = radius,
                        style = Stroke(.6.dp.toPx()),
                    )
                    val dispersion = if (dragging) .16f else .34f * wave * travel
                    if (dispersion > .01f) {
                        val shift = .65.dp.toPx()
                        drawRoundRect(
                            color = accent.copy(alpha = dispersion * .85f),
                            topLeft = topLeft - Offset(shift, shift * .35f),
                            size = lensSize, cornerRadius = radius,
                            style = Stroke(1.dp.toPx()),
                        )
                        drawRoundRect(
                            color = NamuColors.GlassRim.copy(alpha = dispersion * .58f),
                            topLeft = topLeft + Offset(shift, shift * .35f),
                            size = lensSize, cornerRadius = radius,
                            style = Stroke(.9.dp.toPx()),
                        )
                    }
                    drawLine(
                        color = accent.copy(alpha = .14f + .10f * raised),
                        start = Offset(topLeft.x + radius.x, topLeft.y + lensSize.height - 1.dp.toPx()),
                        end = Offset(topLeft.x + lensSize.width - radius.x, topLeft.y + lensSize.height - 1.dp.toPx()),
                        strokeWidth = 1.5.dp.toPx(),
                    )
                    if (raised > .01f || wave > .06f) {
                        clipPath(lens, ClipOp.Difference) { drawLayer(labelsLayer) }
                        clipPath(lens) {
                            val zoom = 1f + .18f * raised + .06f * wave
                            scale(zoom, zoom, pivot = center) { drawLayer(labelsLayer) }
                        }
                    } else {
                        drawLayer(labelsLayer)
                    }
                }.padding(vertical = 4.dp),
            ) {
                tabs.forEachIndexed { index, item ->
                    TabButton(
                        selected = item == selected,
                        highlighted = if (dragging) index == fingerSlot.roundToInt() else item == selected,
                        icon = when (item) {
                            MainTab.Home -> Icons.Outlined.Home
                            MainTab.Config -> Icons.Outlined.Layers
                            MainTab.Data -> Icons.Outlined.BarChart
                            MainTab.Settings -> Icons.Outlined.Settings
                        },
                        label = item.label,
                        modifier = Modifier.weight(1f),
                    ) { currentSelect(item) }
                }
            }
        }
    }
}

@Composable
private fun TabButton(
    selected: Boolean,
    highlighted: Boolean,
    icon: ImageVector,
    label: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val haptic = LocalHapticFeedback.current
    Column(
        modifier
            .heightIn(min = 48.dp)
            .selectable(selected = selected, role = Role.Tab, interactionSource = interaction, indication = null) {
                if (!selected) {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onClick()
                }
            }
            .padding(vertical = 4.dp),
        verticalArrangement = androidx.compose.foundation.layout.Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        val tint by animateColorAsState(
            if (highlighted) NamuColors.Accent else NamuColors.TextSub,
            tween(180),
            label = "tab-tint",
        )
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.height(3.dp))
        Text(
            label,
            fontSize = 12.sp,
            fontWeight = if (highlighted) FontWeight.Medium else FontWeight.Normal,
            color = tint,
        )
    }
}
