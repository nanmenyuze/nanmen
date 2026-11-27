package com.namu.dns.ui

import androidx.compose.runtime.mutableIntStateOf
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.gestures.scrollBy
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.outlined.MoreHoriz
import androidx.compose.material.icons.outlined.Widgets
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.LayoutCoordinates
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInParent
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.zIndex
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.namu.dns.GlobalRuleStore
import com.namu.dns.Actions
import com.namu.dns.ConfigStore
import com.namu.dns.ModuleParser
import com.namu.dns.ModuleSource
import com.namu.dns.ParsedModule
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.LocalDockClearance
import com.namu.dns.core.config.ModuleOrder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

@Composable
fun ModulesScreen(
    onRestart: () -> Unit,
    onOpenDetail: (String) -> Unit,
    onBack: (() -> Unit)? = null,
) {
    var importSource by remember { mutableStateOf<ModuleImportSource?>(null) }
    var syncing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val runtime = container.runtime
    val messages = container.messages
    // 3.0.18：模块列表全局共享；本地规则/本地重写置顶（仅显示）。
    val g = GlobalRuleStore.state
    val entries = GlobalRuleStore.displayEntries()
    val head = entries.filter { it.id == GlobalRuleStore.ID_LOCAL_RULES || it.id == GlobalRuleStore.ID_LOCAL_MITM }
    val ordered = entries.filter { it.id != GlobalRuleStore.ID_LOCAL_RULES && it.id != GlobalRuleStore.ID_LOCAL_MITM }
    val enabled = entries.count { it.enabled }
    val ctx = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val scrollState = rememberScrollState()
    val density = LocalDensity.current
    val autoScrollEdge = with(density) { 88.dp.toPx() }
    val centers = remember { mutableStateMapOf<String, Float>() }
    val rootCenters = remember { mutableStateMapOf<String, Float>() }
    var viewportTop by remember { mutableFloatStateOf(0f) }
    var viewportBottom by remember { mutableFloatStateOf(0f) }
    var draggingId by remember { mutableStateOf<String?>(null) }
    var dragOffsetY by remember { mutableFloatStateOf(0f) }
    var dragTargetIndex by remember { mutableIntStateOf(-1) }
    var autoScrollDirection by remember { mutableIntStateOf(0) }

    fun updateDragTarget() {
        val id = draggingId ?: return
        val from = ordered.indexOfFirst { it.id == id }
        val center = centers[id] ?: return
        if (from < 0 || ordered.any { centers[it.id] == null }) return
        dragTargetIndex = ModuleOrder.dragTarget(
            centers = ordered.map { centers.getValue(it.id) },
            from = from,
            draggedCenter = center + dragOffsetY,
        )
    }

    fun updateAutoScroll() {
        val id = draggingId ?: return
        val center = (rootCenters[id] ?: return) + dragOffsetY
        autoScrollDirection = when {
            center < viewportTop + autoScrollEdge -> -1
            center > viewportBottom - autoScrollEdge -> 1
            else -> 0
        }
    }

    fun finishDrag(save: Boolean) {
        val id = draggingId ?: return
        val from = ordered.indexOfFirst { it.id == id }
        val to = dragTargetIndex
        draggingId = null
        autoScrollDirection = 0
        dragOffsetY = 0f
        dragTargetIndex = -1
        if (save && from >= 0 && to >= 0 && from != to) {
            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
            scope.launch { Actions.reorderEntry(id, to) }
        }
    }

    LaunchedEffect(draggingId, autoScrollDirection) {
        if (draggingId == null || autoScrollDirection == 0) return@LaunchedEffect
        while (true) {
            val consumed = scrollState.scrollBy(autoScrollDirection * 16f)
            if (consumed == 0f) {
                autoScrollDirection = 0
                break
            }
            dragOffsetY += consumed
            updateDragTarget()
            delay(16)
        }
    }

    // 规则集展开结果：缓存未命中、格式不识别、整集被跳过时都在这里提示，避免静默失效。
    val ruleSetIssues = remember(g) {
        runCatching {
            val o = JSONObject(ConfigStore.moduleMitmFile(ctx).readText())
            val arr = o.optJSONArray("ruleSetIssues") ?: return@runCatching emptyList<String>()
            (0 until arr.length()).map { arr.optString(it) }.filter { it.isNotBlank() }
        }.getOrDefault(emptyList())
    }
    val ignoredRules = remember(g) {
        runCatching {
            JSONObject(ConfigStore.moduleMitmFile(ctx).readText()).optInt("ignoredRules", 0)
        }.getOrDefault(0)
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(NamuColors.Bg),
    ) {
        ModuleTopBar(
            syncing = syncing,
            syncEnabled = !syncing && enabled > 0,
            onBack = onBack,
            onImport = { importSource = it },
            onOpenLocalRules = { onOpenDetail(GlobalRuleStore.ID_LOCAL_RULES) },
            onSync = {
                syncing = true
                scope.launch {
                    try {
                        // 3.0.18：只保留「同步全部已启用模块」；规则集记录一并批量同步。
                        val result = Actions.syncModules()
                        val sets = Actions.syncRuleSources()
                        val errors = result.errors + sets.errors
                        messages.show(if (errors.isEmpty()) {
                            "已同步 ${result.updated} 个模块、${sets.updated} 个规则集"
                        } else {
                            "同步 ${result.updated + sets.updated} 个，失败 ${errors.size} 个：${errors.first()}"
                        })
                    } catch (e: Exception) {
                        messages.show(e.message ?: "同步模块失败")
                    } finally {
                        syncing = false
                    }
                }
            },
        )
        Column(
            Modifier
                .fillMaxSize()
                .onGloballyPositioned {
                    viewportTop = it.positionInRoot().y
                    viewportBottom = viewportTop + it.size.height
                }
                .verticalScroll(scrollState),
        ) {
            ModuleSectionHeader(
                title = "已安装",
                summary = "${entries.size} 个模块 · $enabled 个启用",
            )
        if (ruleSetIssues.isNotEmpty() || ignoredRules > 0) {
            GroupCard {
                Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
                    Text("规则异常", fontSize = 13.sp, color = NamuColors.Orange)
                    Spacer(Modifier.height(4.dp))
                    ruleSetIssues.take(5).forEach { issue ->
                        Text("· $issue", fontSize = 11.sp, color = NamuColors.TextSub, lineHeight = 16.sp)
                    }
                    if (ruleSetIssues.size > 5) {
                        Text("… 其余 ${ruleSetIssues.size - 5} 条在模块详情", fontSize = 11.sp, color = NamuColors.TextSub)
                    }
                    if (ignoredRules > 0) {
                        Text(
                            "已跳过 $ignoredRules 条规则",
                            fontSize = 11.sp,
                            color = NamuColors.TextSub,
                            lineHeight = 16.sp,
                        )
                    }
                }
            }
        }
        if (entries.isEmpty()) {
            GroupCard {
                Column(
                    Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 30.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text("暂无模块", fontSize = 15.sp, color = NamuColors.TextMain)
                }
            }
        } else {
            head.forEach { entry ->
                GlobalHeadRow(
                    entry = entry,
                    onClick = { if (draggingId == null) onOpenDetail(entry.id) },
                    onCheckedChange = { on ->
                        scope.launch {
                            if (entry.id == GlobalRuleStore.ID_LOCAL_RULES) Actions.setLocalRulesEnabled(on)
                            else Actions.setLocalMitmEnabled(on)
                        }
                    },
                )
                Spacer(Modifier.height(12.dp))
            }
            ordered.forEachIndexed { index, entry ->
                // 排序后按模块身份移动组合，避免相邻行继承图片、按压和动画状态。
                key(entry.id) {
                val module = (entry as? GlobalRuleStore.Entry.Remote)?.module
                val warning = when (entry) {
                    is GlobalRuleStore.Entry.Remote -> buildList {
                        if (entry.module.ignored > 0) add("${entry.module.ignored} 条不支持")
                        if (entry.module.stale) add("更新失败，使用旧缓存")
                        if (entry.module.error.isNotBlank()) add(entry.module.error)
                    }.joinToString("\n")
                    is GlobalRuleStore.Entry.RuleSet -> buildList {
                        if (entry.source.lines > 0) add("${entry.source.lines} 条规则")
                        if (entry.source.stale) add("更新失败，使用旧缓存")
                        else if (entry.source.error.isNotBlank()) add(entry.source.error)
                        else if (entry.source.notModified) add("已是最新")
                        else if (entry.source.updatedAt > 0) add(relativeUpdatedAt(entry.source.updatedAt))
                        if (entry.source.origin.isNotBlank()) add("来源方案 ${entry.source.origin}")
                    }.joinToString(" · ")
                    is GlobalRuleStore.Entry.Extra -> "来源方案 ${entry.item.origin}"
                    else -> ""
                }
                val isDragging = draggingId == entry.id
                val from = ordered.indexOfFirst { it.id == draggingId }
                val target = dragTargetIndex
                val currentCenter = centers[entry.id]
                val displacement = if (
                    draggingId == null || isDragging || from < 0 || target < 0 || currentCenter == null
                ) {
                    0f
                } else when {
                    target > from && index in (from + 1)..target -> {
                        val previousCenter = centers[ordered[index - 1].id]
                        if (previousCenter == null) 0f else previousCenter - currentCenter
                    }
                    target < from && index in target until from -> {
                        val nextCenter = centers[ordered[index + 1].id]
                        if (nextCenter == null) 0f else nextCenter - currentCenter
                    }
                    else -> 0f
                }
                val onMeasure: (LayoutCoordinates) -> Unit = { coordinates ->
                    centers[entry.id] = coordinates.positionInParent().y + coordinates.size.height / 2f
                    rootCenters[entry.id] = coordinates.positionInRoot().y + coordinates.size.height / 2f
                }
                val onClick = { if (draggingId == null) onOpenDetail(entry.id) }
                val onToggle: (Boolean) -> Unit = { on ->
                    scope.launch {
                        when (entry) {
                            is GlobalRuleStore.Entry.Remote -> Actions.setModuleEnabled(entry.module.id, on)
                            is GlobalRuleStore.Entry.RuleSet -> Actions.setRuleSetEnabled(entry.source.id, on)
                            is GlobalRuleStore.Entry.Extra -> Actions.setExtraMitmEnabled(entry.item.id, on)
                            else -> {}
                        }
                    }
                }
                val onDragStart = {
                    if (draggingId == null) {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        draggingId = entry.id
                        dragOffsetY = 0f
                        dragTargetIndex = index
                        autoScrollDirection = 0
                    }
                }
                val onDrag: (Float) -> Unit = { amountY ->
                    if (draggingId == entry.id) {
                        dragOffsetY += amountY
                        updateDragTarget()
                        updateAutoScroll()
                    }
                }
                val onDragEnd = { finishDrag(save = true) }
                val onDragCancel = { finishDrag(save = false) }
                if (module != null) {
                    ModuleRow(
                        module = module,
                        warning = warning,
                        isDragging = isDragging,
                        dragOffsetY = if (isDragging) dragOffsetY else 0f,
                        displacementY = displacement,
                        onMeasure = onMeasure,
                        onClick = onClick,
                        onCheckedChange = onToggle,
                        onDragStart = onDragStart,
                        onDrag = onDrag,
                        onDragEnd = onDragEnd,
                        onDragCancel = onDragCancel,
                    )
                } else {
                    GlobalEntryRow(
                        entry = entry,
                        warning = warning,
                        isDragging = isDragging,
                        dragOffsetY = if (isDragging) dragOffsetY else 0f,
                        displacementY = displacement,
                        onMeasure = onMeasure,
                        onClick = onClick,
                        onCheckedChange = onToggle,
                        onDragStart = onDragStart,
                        onDrag = onDrag,
                        onDragEnd = onDragEnd,
                        onDragCancel = onDragCancel,
                    )
                }
                if (index != ordered.lastIndex) Spacer(Modifier.height(12.dp))
                }
            }
        }

        Spacer(Modifier.height(LocalDockClearance.current + 34.dp))
        }
    }

    importSource?.let { source ->
        AddModuleDialog(
            source = source,
            onDismiss = { importSource = null },
            onDone = {
                importSource = null
                if (runtime.current().connected) onRestart()
            },
        )
    }
}

@Composable
private fun ModuleTopBar(
    syncing: Boolean,
    syncEnabled: Boolean,
    onBack: (() -> Unit)?,
    onImport: (ModuleImportSource) -> Unit,
    onOpenLocalRules: () -> Unit,
    onSync: () -> Unit,
) {
    var menuExpanded by remember { mutableStateOf(false) }
    val open = menuExpanded && !syncing
    val interaction = remember { MutableInteractionSource() }
    val iconRotation by animateFloatAsState(
        targetValue = if (open) 90f else 0f,
        animationSpec = spring(dampingRatio = NamuTokens.PressDamping, stiffness = NamuTokens.PressStiffness),
        label = "module-menu-icon",
    )
    ShadowTopBar(
        title = "模块",
        left = {
            if (onBack != null) {
                androidx.compose.material3.IconButton(onClick = onBack) {
                    NamuIcon(Icons.AutoMirrored.Rounded.ArrowBack, "返回")
                }
            }
        },
    ) {
        Box {
            Box(
                Modifier
                    .size(44.dp)
                    .menuPressMotion(interaction)
                    .clip(CircleShape)
                    .background(if (open) NamuColors.FillPressed else NamuColors.Card)
                    .semantics { stateDescription = if (open) "已展开" else "已收起" }
                    .clickable(
                        interactionSource = interaction,
                        indication = null,
                        enabled = !syncing,
                        onClickLabel = "模块操作",
                        role = Role.Button,
                    ) { menuExpanded = !menuExpanded },
                contentAlignment = Alignment.Center,
            ) {
                if (syncing) {
                    CircularProgressIndicator(
                        Modifier.size(19.dp),
                        strokeWidth = 2.dp,
                        color = NamuColors.Blue,
                    )
                } else {
                    Icon(
                        Icons.Outlined.MoreHoriz,
                        contentDescription = null,
                        tint = if (open) NamuColors.Blue else NamuColors.TextMain,
                        modifier = Modifier.size(22.dp).graphicsLayer { rotationZ = iconRotation },
                    )
                }
            }
            FloatingMenu(
                expanded = open,
                onDismissRequest = { menuExpanded = false },
                modifier = Modifier.width(220.dp),
            ) {
                ModuleImportSource.entries.forEach { source ->
                    DropdownMenuItem(
                        text = { Text(source.title, fontSize = 15.sp) },
                        onClick = {
                            menuExpanded = false
                            onImport(source)
                        },
                    )
                }
                DropdownMenuItem(
                    text = { Text("自定义规则", fontSize = 15.sp) },
                    onClick = {
                        menuExpanded = false
                        onOpenLocalRules()
                    },
                )
                RowDivider()
                DropdownMenuItem(
                    text = {
                        Text(
                            "同步全部已启用模块",
                            fontSize = 15.sp,
                            color = if (syncEnabled) NamuColors.TextMain else NamuColors.TextTertiary,
                        )
                    },
                    enabled = syncEnabled,
                    onClick = {
                        menuExpanded = false
                        onSync()
                    },
                )
            }
        }
    }
}

@Composable
private fun ModuleSectionHeader(title: String, summary: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(start = 20.dp, end = 20.dp, top = 10.dp, bottom = 9.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            title,
            modifier = Modifier.weight(1f),
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
            color = NamuColors.TextMain,
        )
        Text(summary, fontSize = 13.sp, color = NamuColors.Blue)
    }
}

@Composable
private fun ModuleRow(
    module: ModuleSource,
    warning: String,
    isDragging: Boolean,
    dragOffsetY: Float,
    displacementY: Float,
    onMeasure: (LayoutCoordinates) -> Unit,
    onClick: () -> Unit,
    onCheckedChange: (Boolean) -> Unit,
    onDragStart: () -> Unit,
    onDrag: (Float) -> Unit,
    onDragEnd: () -> Unit,
    onDragCancel: () -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val displaced by animateFloatAsState(
        targetValue = if (isDragging) 0f else displacementY,
        animationSpec = spring(dampingRatio = 0.78f, stiffness = 430f),
        label = "module-make-room",
    )
    val scale by animateFloatAsState(
        targetValue = if (isDragging) 1.025f else 1f,
        animationSpec = spring(dampingRatio = 0.72f, stiffness = 520f),
        label = "module-lift",
    )
    val shape = RoundedCornerShape(NamuTokens.RadiusCard)
    val status = moduleStatusLine(module, warning)
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .onGloballyPositioned(onMeasure)
            .zIndex(if (isDragging) 3f else 0f)
            .graphicsLayer {
                translationY = if (isDragging) dragOffsetY else displaced
                scaleX = scale
                scaleY = scale
            }
            .shadow(if (isDragging) 20.dp else 2.dp, shape)
            .clip(shape)
            .background(if (pressed && !isDragging) NamuColors.CardPressed else NamuColors.Card),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 76.dp)
                .padding(start = 16.dp, end = 8.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                Modifier
                    .weight(1f)
                    .pointerInput(module.id) {
                        detectDragGesturesAfterLongPress(
                            onDragStart = { onDragStart() },
                            onDrag = { change, dragAmount ->
                                change.consume()
                                onDrag(dragAmount.y)
                            },
                            onDragEnd = onDragEnd,
                            onDragCancel = onDragCancel,
                        )
                    }
                    .clickable(
                        interactionSource = interaction,
                        indication = null,
                        onClickLabel = "查看模块详情",
                        onClick = onClick,
                    ),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                ModuleLeadingIcon(module, size = 44.dp)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        module.name.ifBlank { "未命名模块" },
                        fontSize = 16.sp,
                        lineHeight = 21.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = NamuColors.TextMain,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Spacer(Modifier.height(3.dp))
                    Text(
                        status.first,
                        fontSize = 12.sp,
                        color = status.second,
                        lineHeight = 16.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            Spacer(Modifier.width(6.dp))
            // 开关独占触摸区域；其余卡片区域单击进入详情，长按开始拖动。
            IosSwitch(checked = module.enabled, onCheckedChange = onCheckedChange)
        }
    }
}

/** 3.0.18：本地规则/本地重写置顶行——仅名称、开关、一行状态，不参与拖拽。 */
@Composable
private fun GlobalHeadRow(
    entry: GlobalRuleStore.Entry,
    onClick: () -> Unit,
    onCheckedChange: (Boolean) -> Unit,
) {
    val status = when (entry) {
        is GlobalRuleStore.Entry.LocalRules ->
            "${entry.ruleCount} 条规则 · ${entry.adsCount} 条拦截域名" to NamuColors.TextSub
        is GlobalRuleStore.Entry.LocalMitm ->
            "${entry.count} 条重写与脚本" to NamuColors.TextSub
        else -> "" to NamuColors.TextSub
    }
    val shape = RoundedCornerShape(NamuTokens.RadiusCard)
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .shadow(2.dp, shape)
            .clip(shape)
            .background(NamuColors.Card)
            .clickable(onClick = onClick)
            .heightIn(min = 76.dp)
            .padding(start = 16.dp, end = 8.dp, top = 10.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(44.dp)
                .background(NamuColors.Blue.copy(alpha = 0.10f), RoundedCornerShape(NamuTokens.RadiusControl)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Outlined.Widgets, null, tint = NamuColors.Blue, modifier = Modifier.size(22.dp))
        }
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(
                entry.name,
                fontSize = 16.sp,
                lineHeight = 21.sp,
                fontWeight = FontWeight.SemiBold,
                color = NamuColors.TextMain,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(3.dp))
            Text(status.first, fontSize = 12.sp, color = status.second, lineHeight = 16.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Spacer(Modifier.width(6.dp))
        IosSwitch(checked = entry.enabled, onCheckedChange = onCheckedChange)
    }
}

/** 3.0.18：规则集/来源方案重写的全局行；与模块行同一拖拽手感。 */
@Composable
private fun GlobalEntryRow(
    entry: GlobalRuleStore.Entry,
    warning: String,
    isDragging: Boolean,
    dragOffsetY: Float,
    displacementY: Float,
    onMeasure: (LayoutCoordinates) -> Unit,
    onClick: () -> Unit,
    onCheckedChange: (Boolean) -> Unit,
    onDragStart: () -> Unit,
    onDrag: (Float) -> Unit,
    onDragEnd: () -> Unit,
    onDragCancel: () -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val displaced by animateFloatAsState(
        targetValue = if (isDragging) 0f else displacementY,
        animationSpec = spring(dampingRatio = 0.78f, stiffness = 430f),
        label = "global-make-room",
    )
    val scale by animateFloatAsState(
        targetValue = if (isDragging) 1.025f else 1f,
        animationSpec = spring(dampingRatio = 0.72f, stiffness = 520f),
        label = "global-lift",
    )
    val shape = RoundedCornerShape(NamuTokens.RadiusCard)
    val status = when (entry) {
        is GlobalRuleStore.Entry.RuleSet -> {
            val parts = mutableListOf<String>()
            if (!entry.enabled) parts += "已停用"
            parts += "${entry.source.lines} 条过滤"
            if (entry.source.stale) parts += "使用旧缓存"
            else if (entry.source.error.isNotBlank()) parts += "更新失败"
            else if (entry.source.updatedAt > 0) parts += relativeUpdatedAt(entry.source.updatedAt)
            parts.joinToString(" · ") to (if (entry.source.stale || entry.source.error.isNotBlank()) NamuColors.Orange else NamuColors.TextSub)
        }
        is GlobalRuleStore.Entry.Extra -> {
            val parts = mutableListOf<String>()
            if (!entry.enabled) parts += "已停用"
            parts += "${GlobalRuleStore.mitmCount(entry.item.content)} 条重写与脚本"
            parts += "来源方案 ${entry.item.origin}"
            parts.joinToString(" · ") to NamuColors.TextSub
        }
        else -> "" to NamuColors.TextSub
    }
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .onGloballyPositioned(onMeasure)
            .zIndex(if (isDragging) 3f else 0f)
            .graphicsLayer {
                translationY = if (isDragging) dragOffsetY else displaced
                scaleX = scale
                scaleY = scale
            }
            .shadow(if (isDragging) 20.dp else 2.dp, shape)
            .clip(shape)
            .background(if (pressed && !isDragging) NamuColors.CardPressed else NamuColors.Card),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 76.dp)
                .padding(start = 16.dp, end = 8.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                Modifier
                    .weight(1f)
                    .pointerInput(entry.id) {
                        detectDragGesturesAfterLongPress(
                            onDragStart = { onDragStart() },
                            onDrag = { change, dragAmount ->
                                change.consume()
                                onDrag(dragAmount.y)
                            },
                            onDragEnd = onDragEnd,
                            onDragCancel = onDragCancel,
                        )
                    }
                    .clickable(
                        interactionSource = interaction,
                        indication = null,
                        onClickLabel = "查看详情",
                        onClick = onClick,
                    ),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    Modifier
                        .size(44.dp)
                        .background(NamuColors.Blue.copy(alpha = 0.10f), RoundedCornerShape(NamuTokens.RadiusControl)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Outlined.Widgets, null, tint = NamuColors.Blue, modifier = Modifier.size(22.dp))
                }
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        entry.name,
                        fontSize = 16.sp,
                        lineHeight = 21.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = NamuColors.TextMain,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Spacer(Modifier.height(3.dp))
                    Text(status.first, fontSize = 12.sp, color = status.second, lineHeight = 16.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            Spacer(Modifier.width(6.dp))
            IosSwitch(checked = entry.enabled, onCheckedChange = onCheckedChange)
        }
    }
}

/** 列表只留一行状态：规则规模 + 更新时间 + 异常，避免把详情搬回列表。 */
private fun moduleStatusLine(module: ModuleSource, warning: String): Pair<String, Color> {
    val total = module.blockRules + module.routeRules + module.mitmRules + module.allowRules
    val parts = mutableListOf<String>()
    if (module.stale) parts += "使用旧缓存"
    else if (module.error.isNotBlank()) parts += "更新失败"
    if (!module.enabled) parts += "已停用"
    parts += if (total > 0) "$total 条规则" else "无规则"
    if (module.ignored > 0) parts += "${module.ignored} 条不支持"
    if (!module.stale && module.error.isBlank()) {
        if (module.notModified) parts += "已是最新"
        else if (module.updatedAt > 0) parts += relativeUpdatedAt(module.updatedAt)
    }
    val abnormal = module.ignored > 0 || module.stale || module.error.isNotBlank() || warning.isNotBlank()
    val color = when {
        abnormal -> NamuColors.Orange
        !module.enabled -> NamuColors.TextTertiary
        else -> NamuColors.TextSub
    }
    return parts.joinToString(" · ") to color
}

private fun relativeUpdatedAt(timestamp: Long): String {
    val elapsed = (System.currentTimeMillis() - timestamp).coerceAtLeast(0L)
    val minute = 60_000L
    val hour = 60 * minute
    val day = 24 * hour
    return when {
        elapsed < minute -> "刚刚更新"
        elapsed < hour -> "${elapsed / minute} 分钟前"
        elapsed < day -> "${elapsed / hour} 小时前"
        elapsed < 30 * day -> "${elapsed / day} 天前"
        else -> "较早更新"
    }
}

@Suppress("ProduceStateDoesNotAssignValue")
@Composable
private fun rememberModuleMetadata(module: ModuleSource): State<String?> {
    val context = LocalContext.current
    return produceState(
        initialValue = null,
        module.id,
        module.updatedAt,
        module.cacheBytes,
    ) {
        value = withContext(Dispatchers.IO) {
            loadDeclaredModuleMetadata(context, module.id)
        }
    }
}

/** 模块列表摘要只读取本地缓存正文中的声明；不联网、不写配置。 */
private fun loadDeclaredModuleMetadata(context: Context, moduleId: String): String? {
    val text = runCatching {
        ConfigStore.moduleFile(context, moduleId)
            .takeIf { it.exists() && it.length() > 0L }
            ?.readText()
    }.getOrNull() ?: return null
    return declaredModuleMetadata(text)
}

private fun declaredModuleMetadata(text: String): String? {
    val trimmed = text.removePrefix("\uFEFF").trimStart()
    val author: String?
    val category: String?
    val description: String?
    if (trimmed.startsWith("{")) {
        val json = runCatching { JSONObject(trimmed) }.getOrNull()
        author = jsonMetadataValue(json, "author")
        category = jsonMetadataValue(json, "category")
        description = jsonMetadataValue(json, "desc") ?: jsonMetadataValue(json, "description")
    } else {
        author = moduleMetadataLine(text, "author")
        category = moduleMetadataLine(text, "category")
        description = moduleMetadataLine(text, "desc") ?: moduleMetadataLine(text, "description")
    }
    return listOfNotNull(author, category)
        .filter { it.isNotBlank() }
        .joinToString(" · ")
        .ifBlank { description.orEmpty() }
        .takeIf { it.isNotBlank() }
}

private fun moduleMetadataLine(text: String, key: String): String? = Regex(
    "^#!${Regex.escape(key)}\\s*=\\s*(.+?)\\s*$",
    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
).find(text)?.groupValues?.get(1)?.trim()?.takeIf { it.isNotBlank() }

private fun jsonMetadataValue(json: JSONObject?, key: String): String? {
    if (json == null) return null
    return sequenceOf(
        json.optString(key),
        json.optJSONObject("meta")?.optString(key),
        json.optJSONObject("metadata")?.optString(key),
    ).map { it?.trim().orEmpty() }
        .firstOrNull { it.isNotBlank() }
}

@Suppress("ProduceStateDoesNotAssignValue")
@Composable
private fun ModuleLeadingIcon(module: ModuleSource, size: Dp = 40.dp) {
    val context = LocalContext.current
    val icon by produceState<ImageBitmap?>(
        initialValue = null,
        module.id,
        module.updatedAt,
        module.cacheBytes,
    ) {
        // 排序或复用组合位置时先清掉上一个模块的图片，避免短暂错配。
        value = null
        value = withContext(Dispatchers.IO) {
            loadDeclaredModuleIcon(context, module.id)
        }
    }
    val hasIcon = icon != null
    Box(
        Modifier
            .size(size)
            .clip(RoundedCornerShape(size * 0.275f))
            .background(if (hasIcon) NamuColors.Fill else NamuColors.Brand.copy(alpha = .11f)),
        contentAlignment = Alignment.Center,
    ) {
        val bitmap = icon
        if (bitmap != null) {
            Image(
                bitmap = bitmap,
                contentDescription = null,
                modifier = Modifier.fillMaxSize(),
                contentScale = ContentScale.Crop,
            )
        } else {
            NamuIcon(
                Icons.Outlined.Widgets,
                tint = if (NamuColors.isDark) NamuColors.TextMain else NamuColors.Brand,
                size = size * 0.55f,
            )
        }
    }
}

/** 图标只从已有模块缓存读取；不写回配置，也不为了图标重新同步模块。 */
private fun loadDeclaredModuleIcon(context: Context, moduleId: String): ImageBitmap? {
    val text = runCatching {
        ConfigStore.moduleFile(context, moduleId)
            .takeIf { it.exists() && it.length() > 0L }
            ?.readText()
    }.getOrNull() ?: return null
    val address = declaredModuleIconUrl(text) ?: return null
    return runCatching { downloadModuleIcon(address)?.asImageBitmap() }.getOrNull()
}

private fun declaredModuleIconUrl(text: String): String? {
    val trimmed = text.removePrefix("\uFEFF").trimStart()
    val declared = if (trimmed.startsWith("{")) {
        runCatching {
            val json = JSONObject(trimmed)
            sequenceOf(json.optString("icon"), json.optString("iconUrl"), json.optString("icon-url"))
                .firstOrNull { it.isNotBlank() }
        }.getOrNull()
    } else {
        Regex(
            "^#!icon\\s*=\\s*(.+?)\\s*$",
            setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
        ).find(text)?.groupValues?.get(1)
    }
    val candidate = declared?.trim()?.trim('"', '\'')?.takeIf { it.length <= 2048 } ?: return null
    return runCatching {
        URL(candidate).takeIf {
            it.protocol.equals("https", ignoreCase = true) && !it.host.isNullOrBlank()
        }?.toExternalForm()
    }.getOrNull()
}

private const val MaxModuleIconBytes = 1024 * 1024
private const val MaxModuleIconDimension = 4096

/** 小图标下载设置严格上限；重定向、非 HTTPS 与异常图片统一交给线性图标兜底。 */
private fun downloadModuleIcon(address: String): Bitmap? {
    val connection = (URL(address).openConnection() as? HttpURLConnection) ?: return null
    return try {
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.instanceFollowRedirects = false
        connection.useCaches = true
        connection.setRequestProperty("Accept", "image/*")
        connection.setRequestProperty("User-Agent", "NamuDNS/3.0.1")
        if (connection.responseCode != HttpURLConnection.HTTP_OK) return null
        if (connection.contentLength > MaxModuleIconBytes) return null
        val bytes = connection.inputStream.buffered().use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                if (output.size() + count > MaxModuleIconBytes) return null
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        if (bytes.isEmpty()) null else decodeModuleIcon(bytes)
    } catch (_: Exception) {
        null
    } finally {
        connection.disconnect()
    }
}

private fun decodeModuleIcon(bytes: ByteArray): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    if (bounds.outWidth > MaxModuleIconDimension || bounds.outHeight > MaxModuleIconDimension) return null
    var sampleSize = 1
    while (bounds.outWidth / sampleSize > 256 || bounds.outHeight / sampleSize > 256) {
        sampleSize *= 2
    }
    val options = BitmapFactory.Options().apply { inSampleSize = sampleSize }
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
}

@Suppress("ProduceStateDoesNotAssignValue")
@Composable
fun ModuleDetailScreen(moduleId: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val container = LocalAppContainer.current
    val cfg by container.settings.config.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    // 3.0.18：伪模块/规则集/来源重写分流到各自详情。
    if (moduleId == GlobalRuleStore.ID_LOCAL_RULES) {
        LocalRulesDetailScreen()
        return
    }
    if (moduleId == GlobalRuleStore.ID_LOCAL_MITM) {
        LocalMitmDetailScreen()
        return
    }
    if (moduleId.startsWith(GlobalRuleStore.ID_RULESET_PREFIX)) {
        RuleSetDetailScreen(moduleId.removePrefix(GlobalRuleStore.ID_RULESET_PREFIX))
        return
    }
    if (GlobalRuleStore.state.extraMitm.any { it.id == moduleId }) {
        ExtraMitmDetailScreen(moduleId)
        return
    }
    val ordered = GlobalRuleStore.orderedModules()
    val module = ordered.firstOrNull { it.id == moduleId }
    if (module == null) {
        Column(
            Modifier.fillMaxSize().background(NamuColors.Bg).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text("模块不存在或已删除", fontSize = 16.sp, color = NamuColors.TextSub)
            Spacer(Modifier.height(16.dp))
            Text(
                "返回模块列表",
                color = NamuColors.Blue,
                fontSize = 15.sp,
                modifier = Modifier.clip(RoundedCornerShape(NamuTokens.RadiusControl)).clickable(onClick = onBack).padding(12.dp),
            )
        }
        return
    }

    val index = ordered.indexOfFirst { it.id == module.id }
    val metadata by rememberModuleMetadata(module)
    var syncing by remember(module.id) { mutableStateOf(false) }
    var confirmDelete by remember(module.id) { mutableStateOf(false) }
    var showRaw by remember(module.id) { mutableStateOf(false) }
    val cached by produceState<ModuleDetailCache?>(
        initialValue = null,
        module.id,
        module.updatedAt,
        module.cacheBytes,
    ) {
        value = withContext(Dispatchers.IO) { loadModuleDetailCache(context, module.id) }
    }

    DetailList {
        Spacer(Modifier.height(12.dp))
        GroupCard {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                ModuleLeadingIcon(module, size = 64.dp)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        module.name.ifBlank { "未命名模块" },
                        fontSize = 21.sp,
                        fontWeight = FontWeight.Bold,
                        color = NamuColors.TextMain,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        (metadata ?: module.app).ifBlank {
                            if (module.url.startsWith("https://", ignoreCase = true)) "URL 模块" else "本地模块"
                        },
                        fontSize = 12.sp,
                        color = NamuColors.TextSub,
                        lineHeight = 16.sp,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                IosSwitch(
                    checked = module.enabled,
                    onCheckedChange = { enabled ->
                        scope.launch { Actions.setModuleEnabled(module.id, enabled) }
                    },
                )
            }
            val detail = cached
            if (!detail?.description.isNullOrBlank()) {
                Text(
                    detail!!.description!!,
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 10.dp),
                    fontSize = 13.sp,
                    lineHeight = 19.sp,
                    color = NamuColors.TextSub,
                )
            }
            Text(
                "来源：${module.url.ifBlank { "本地模块" }}",
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp),
                fontSize = 11.sp,
                lineHeight = 16.sp,
                color = NamuColors.TextTertiary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            val warning = buildList {
                if (module.ignored > 0) add("${module.ignored} 条不支持")
                if (module.stale) add("更新失败，使用旧缓存")
                if (module.error.isNotBlank()) add(module.error)
            }.joinToString(" · ")
            if (warning.isNotBlank()) {
                Text(
                    warning,
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp),
                    fontSize = 12.sp,
                    lineHeight = 17.sp,
                    color = NamuColors.Orange,
                )
            }
            // 3.0.18：命中/脚本异常只展示能可靠归属到本模块的数据（按来源名前缀过滤）。
            val moduleIssues = remember(module.id, module.updatedAt) {
                runCatching {
                    val o = JSONObject(ConfigStore.moduleMitmFile(context).readText())
                    val out = mutableListOf<String>()
                    listOf("scriptIssues", "ruleSetIssues").forEach { k ->
                        val a = o.optJSONArray(k) ?: return@forEach
                        for (i in 0 until a.length()) {
                            val t = a.optString(i)
                            if (t.startsWith("${module.name}｜")) out.add(t.removePrefix("${module.name}｜"))
                        }
                    }
                    out
                }.getOrDefault(emptyList())
            }
            if (moduleIssues.isNotEmpty()) {
                Text(
                    moduleIssues.joinToString("\n"),
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp),
                    fontSize = 12.sp,
                    lineHeight = 17.sp,
                    color = NamuColors.Orange,
                )
            }
            RowDivider()
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                ModuleDetailStat(module.blockRules, "阻断", Modifier.weight(1f))
                ModuleDetailStatDivider()
                ModuleDetailStat(module.routeRules, "分流", Modifier.weight(1f))
                ModuleDetailStatDivider()
                ModuleDetailStat(module.mitmRules, "复写/MITM", Modifier.weight(1f))
                ModuleDetailStatDivider()
                ModuleDetailStat(module.allowRules, "例外", Modifier.weight(1f))
            }
        }

        SectionHeader(
            "脚本参数",
            trailing = {
                val detail = cached
                if (detail?.error == null) {
                    val count = (detail?.declared?.arguments?.size ?: 0) + (detail?.declared?.scripts?.size ?: 0)
                    Text(if (count > 0) "$count 项" else "未声明", fontSize = 12.sp, color = NamuColors.Blue)
                }
            },
        )
        GroupCard {
            when {
                cached == null -> ModuleDetailLoading()
                cached?.error != null -> ModuleDetailError(cached!!.error!!)
                cached?.declared == null -> ModuleDetailEmpty("无法解析模块声明")
                cached!!.declared!!.arguments.isEmpty() && cached!!.declared!!.scripts.isEmpty() ->
                    ModuleDetailEmpty("该模块未声明 [Argument] 或 [Script]")
                else -> {
                    val declared = cached!!.declared!!
                    declared.arguments.entries.forEachIndexed { i, (key, value) ->
                        if (i > 0) RowDivider()
                        ModuleKeyValueRow(
                            key = key,
                            value = value,
                            note = "默认值 · ${declared.argumentTypes[key] ?: "string"} 类型",
                            monospaceValue = true,
                        )
                    }
                    if (declared.scripts.isNotEmpty()) {
                        if (declared.arguments.isNotEmpty()) RowDivider()
                        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 11.dp)) {
                            Text(
                                "脚本条目 ${declared.scripts.size}",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = NamuColors.TextMain,
                            )
                        }
                        declared.scripts.forEachIndexed { i, script ->
                            if (i > 0) RowDivider()
                            ModuleScriptRow(script)
                        }
                    }
                }
            }
        }

        SectionHeader(
            "[General]",
            trailing = {
                val count = cached?.declared?.generalOptions?.size ?: 0
                Text(if (count > 0) "$count 个键" else "未声明", fontSize = 12.sp, color = NamuColors.Blue)
            },
        )
        GroupCard {
            when {
                cached == null -> ModuleDetailLoading()
                cached?.error != null -> ModuleDetailError(cached!!.error!!)
                cached?.declared?.generalOptions.isNullOrEmpty() -> ModuleDetailEmpty("该模块未声明 [General]")
                else -> {
                    val options = cached!!.declared!!.generalOptions
                    options.entries.forEachIndexed { i, (key, value) ->
                        if (i > 0) RowDivider()
                        ModuleKeyValueRow(
                            key = key,
                            value = value.ifBlank { "（空）" },
                            note = generalKeyNote(key),
                        )
                    }
                }
            }
        }

        SectionHeader(
            "MITM 规则",
            trailing = {
                val count = cached?.declared?.mitmHostnames?.size ?: 0
                Text(if (count > 0) "$count 个域名" else "未声明", fontSize = 12.sp, color = NamuColors.Blue)
            },
        )
        GroupCard {
            when {
                cached == null -> ModuleDetailLoading()
                cached?.error != null -> ModuleDetailError(cached!!.error!!)
                cached?.declared == null -> ModuleDetailEmpty("无法解析模块声明")
                else -> {
                    val declared = cached!!.declared!!
                    val rewriteCount = declared.urlRewrites.size + declared.headerRewrites.size +
                        declared.loonRewrites.size + declared.bodyRewrites.size + declared.wsRewrites.size
                    val declaredMitm = declared.mitmHostnames.isNotEmpty() ||
                        declared.mitmSkipHostnames.isNotEmpty() || rewriteCount > 0 || declared.mitmOptions.isNotEmpty()
                    if (!declaredMitm) {
                        ModuleDetailEmpty("该模块未声明 [MITM] / 改写规则")
                    } else {
                        Text(
                            "解密 ${declared.mitmHostnames.size} · 跳过 ${declared.mitmSkipHostnames.size} · 改写 $rewriteCount",
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                            fontSize = 12.sp,
                            color = NamuColors.TextSub,
                        )
                        if (declared.mitmHostnames.isNotEmpty()) {
                            RowDivider()
                            ModuleRuleListBlock("解密域名", declared.mitmHostnames)
                        }
                        if (declared.mitmSkipHostnames.isNotEmpty()) {
                            RowDivider()
                            ModuleRuleListBlock("跳过域名", declared.mitmSkipHostnames)
                        }
                        val rewrites = buildList {
                            if (declared.urlRewrites.isNotEmpty()) add("URL Rewrite" to declared.urlRewrites.size)
                            if (declared.headerRewrites.isNotEmpty()) add("Header Rewrite" to declared.headerRewrites.size)
                            if (declared.loonRewrites.isNotEmpty()) add("Rewrite" to declared.loonRewrites.size)
                            if (declared.bodyRewrites.isNotEmpty()) add("Body Rewrite" to declared.bodyRewrites.size)
                            if (declared.wsRewrites.isNotEmpty()) add("WebSocket Rewrite" to declared.wsRewrites.size)
                        }
                        if (rewrites.isNotEmpty()) {
                            RowDivider()
                            rewrites.forEachIndexed { i, (name, count) ->
                                if (i > 0) RowDivider()
                                ModuleKeyValueRow(name, "$count 条", note = "由内核逐条解析执行")
                            }
                        }
                        if (declared.mitmOptions.isNotEmpty()) {
                            RowDivider()
                            declared.mitmOptions.entries.forEachIndexed { i, (key, value) ->
                                if (i > 0) RowDivider()
                                ModuleKeyValueRow(key, value.ifBlank { "（空）" }, note = "[MITM] 细项")
                            }
                        }
                    }
                }
            }
        }

        SectionHeader(
            "规则与详情",
            trailing = { Text("本地缓存解析结果", fontSize = 12.sp, color = NamuColors.Blue) },
        )
        GroupCard {
            Text(
                "阻断 ${module.blockRules} · 分流 ${module.routeRules} · 例外 ${module.allowRules} · MITM ${module.mitmRules}",
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                fontSize = 12.sp,
                color = NamuColors.TextSub,
            )
            RowDivider()
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable { showRaw = !showRaw }
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("查看原文", fontSize = 15.sp, color = NamuColors.TextMain)
                    Text(
                        "按 [分区] 原样展示本地缓存，不联网、不执行",
                        fontSize = 12.sp,
                        color = NamuColors.TextSub,
                    )
                }
                Text(
                    if (showRaw) "收起" else "展开",
                    fontSize = 13.sp,
                    color = NamuColors.Blue,
                )
                Spacer(Modifier.width(6.dp))
                Chevron(color = if (showRaw) NamuColors.Blue else NamuColors.TextTertiary)
            }
            if (showRaw) {
                RowDivider()
                when {
                    cached == null -> ModuleDetailLoading()
                    cached?.error != null -> ModuleDetailError(cached!!.error!!)
                    cached?.sections.isNullOrEmpty() -> ModuleDetailEmpty("暂无本地缓存正文")
                    else -> {
                        SelectionContainer {
                            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
                                cached!!.sections.forEachIndexed { sectionIndex, section ->
                                    if (sectionIndex > 0) Spacer(Modifier.height(14.dp))
                                    Text(
                                        section.title,
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = NamuColors.Blue,
                                    )
                                    Spacer(Modifier.height(6.dp))
                                    Text(
                                        section.body,
                                        fontSize = 11.sp,
                                        lineHeight = 17.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = NamuColors.TextMain,
                                    )
                                }
                            }
                        }
                        if (cached?.truncated == true) {
                            Text(
                                "正文过长，仅显示前 50,000 个字符",
                                modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 14.dp),
                                fontSize = 11.sp,
                                color = NamuColors.Orange,
                            )
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))
        GroupCard {
            Text(
                "删除模块",
                modifier = Modifier.fillMaxWidth().clickable { confirmDelete = true }.padding(vertical = 16.dp),
                color = NamuColors.Red,
                fontSize = 15.sp,
                fontWeight = FontWeight.Medium,
                textAlign = TextAlign.Center,
            )
        }
    }

    if (confirmDelete) {
        NamuDialog(
            title = "删除模块",
            message = "确定删除「${module.name.ifBlank { "未命名模块" }}」？",
            confirmText = "删除",
            confirmColor = NamuColors.Red,
            onDismiss = { confirmDelete = false },
            onConfirm = {
                confirmDelete = false
                scope.launch {
                    Actions.deleteModule(module.id)
                    container.messages.show("已删除模块")
                    onBack()
                }
            },
        ) {}
    }
}

@Composable
private fun ModuleDetailLoading() {
    Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = NamuColors.Brand)
    }
}

@Composable
private fun ModuleDetailError(message: String) {
    Text(
        message,
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        fontSize = 12.sp,
        color = NamuColors.Red,
    )
}

@Composable
private fun ModuleDetailEmpty(message: String) {
    Text(
        message,
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        fontSize = 12.sp,
        color = NamuColors.TextSub,
    )
}

@Composable
private fun ModuleKeyValueRow(
    key: String,
    value: String,
    note: String?,
    monospaceValue: Boolean = false,
) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                key,
                modifier = Modifier.weight(1f),
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium,
                color = NamuColors.TextMain,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (!note.isNullOrBlank()) {
                Text(note, fontSize = 11.sp, color = NamuColors.TextTertiary)
            }
        }
        Spacer(Modifier.height(3.dp))
        Text(
            value,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            fontFamily = if (monospaceValue) FontFamily.Monospace else FontFamily.Default,
            color = NamuColors.TextSub,
        )
    }
}

@Composable
private fun ModuleRuleListBlock(title: String, values: List<String>) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp)) {
        Text(title, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = NamuColors.TextMain)
        Spacer(Modifier.height(4.dp))
        Text(
            values.joinToString(", "),
            fontSize = 11.sp,
            lineHeight = 17.sp,
            fontFamily = FontFamily.Monospace,
            color = NamuColors.TextSub,
        )
    }
}

@Composable
private fun ModuleScriptRow(script: com.namu.dns.core.config.ScriptConfig) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 11.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                script.name.ifBlank { "未命名脚本" },
                modifier = Modifier.weight(1f),
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium,
                color = NamuColors.TextMain,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                when {
                    !script.enabled -> "已禁用"
                    script.enableParam.isNotBlank() -> "跟随开关"
                    else -> "已启用"
                },
                fontSize = 11.sp,
                color = if (script.enabled) NamuColors.TextTertiary else NamuColors.Orange,
            )
        }
        Spacer(Modifier.height(3.dp))
        Text(
            listOf(script.phase, script.pattern).filter { it.isNotBlank() }.joinToString(" · "),
            fontSize = 11.sp,
            lineHeight = 16.sp,
            fontFamily = FontFamily.Monospace,
            color = NamuColors.TextSub,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        if (script.scriptPath.isNotBlank()) {
            Spacer(Modifier.height(2.dp))
            Text(
                script.scriptPath,
                fontSize = 11.sp,
                color = NamuColors.TextTertiary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (script.arguments.isNotEmpty()) {
            Spacer(Modifier.height(2.dp))
            Text(
                "参数 ${script.arguments.keys.joinToString(", ")}",
                fontSize = 11.sp,
                color = NamuColors.TextTertiary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/** [General] 只标注壳层实际消费的键，其余保持在详情里可查但不假装生效。 */
private fun generalKeyNote(key: String): String? = when (key.lowercase()) {
    "skip-proxy", "bypass" -> "追加 MITM 跳过域名"
    "ssid-trigger", "ssid-trigger-names" -> "SSID 触发名单（需本地开启）"
    "proxy-test-url", "internet-test-url" -> "健康检查地址"
    "test-timeout" -> "健康检查超时（秒）"
    "force-close-connections" -> "模块变更时重建连接"
    "legacy-chain" -> "旧模块多脚本链式执行"
    else -> null
}

@Composable
private fun ModuleDetailStat(value: Int, label: String, modifier: Modifier = Modifier) {
    Row(modifier, horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
        Text("$value", fontSize = 21.sp, fontWeight = FontWeight.SemiBold, color = NamuColors.TextMain)
        Spacer(Modifier.width(5.dp))
        Text(label, fontSize = 11.sp, color = NamuColors.TextSub, maxLines = 1)
    }
}

@Composable
private fun ModuleDetailStatDivider() {
    Box(Modifier.width(0.5.dp).height(30.dp).background(NamuColors.Separator))
}

private data class ModuleDetailCache(
    val description: String?,
    val sections: List<ModuleRuleSection>,
    val truncated: Boolean,
    /** 只用于详情展示的声明解析；不写配置、不执行脚本。 */
    val declared: ParsedModule? = null,
    val error: String? = null,
)

private data class ModuleRuleSection(
    val title: String,
    val body: String,
)

/** 详情只读取既有缓存并按原文分区，不联网、不执行脚本、不写回模块配置。 */
private fun loadModuleDetailCache(context: Context, moduleId: String): ModuleDetailCache {
    return runCatching {
        val file = ConfigStore.moduleFile(context, moduleId)
        if (!file.exists() || file.length() == 0L) {
            ModuleDetailCache(description = null, sections = emptyList(), truncated = false)
        } else {
            val raw = file.readText()
            val truncated = raw.length > 50_000
            ModuleDetailCache(
                description = declaredModuleDescription(raw),
                sections = parseModuleSections(raw.take(50_000)),
                truncated = truncated,
                declared = runCatching { ModuleParser.parse(raw) }.getOrNull(),
            )
        }
    }.getOrElse {
        ModuleDetailCache(
            description = null,
            sections = emptyList(),
            truncated = false,
            error = "读取模块缓存失败：${it.message ?: "未知错误"}",
        )
    }
}

private fun declaredModuleDescription(text: String): String? {
    val trimmed = text.removePrefix("\uFEFF").trimStart()
    return if (trimmed.startsWith("{")) {
        val json = runCatching { JSONObject(trimmed) }.getOrNull()
        jsonMetadataValue(json, "desc") ?: jsonMetadataValue(json, "description")
    } else {
        moduleMetadataLine(text, "desc") ?: moduleMetadataLine(text, "description")
    }
}

private fun parseModuleSections(text: String): List<ModuleRuleSection> {
    val trimmed = text.removePrefix("\uFEFF").trim()
    if (trimmed.isEmpty()) return emptyList()
    if (trimmed.startsWith("{")) return listOf(ModuleRuleSection("JSON 配置", trimmed))

    val sections = mutableListOf<ModuleRuleSection>()
    val body = StringBuilder()
    var title = "模块信息"
    fun flush() {
        val content = body.toString().trim()
        if (content.isNotBlank()) sections += ModuleRuleSection(title, content)
        body.clear()
    }

    trimmed.lines().forEach { line ->
        val header = Regex("^\\s*\\[([^]]+)]\\s*$").find(line)
        if (header != null) {
            flush()
            title = "[${header.groupValues[1].trim()}]"
        } else if (title == "模块信息" && line.trimStart().startsWith("#!")) {
            // 名称、作者和图标声明已经用于详情头部，不在规则区重复展示。
        } else {
            body.appendLine(line.trimEnd())
        }
    }
    flush()
    if (sections.isEmpty()) return listOf(ModuleRuleSection("模块正文", trimmed))
    return sections
}

private enum class ModuleImportSource(val title: String) {
    Local("导入本地模块"),
    Url("URL 导入模块"),
    RuleSet("导入规则集"),
}

@Composable
private fun AddModuleDialog(source: ModuleImportSource, onDismiss: () -> Unit, onDone: () -> Unit) {
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var preview by remember { mutableStateOf<Actions.ModulePreview?>(null) }
    var approveDns by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val messages = LocalAppContainer.current.messages
    val context = LocalContext.current
    val focus = LocalFocusManager.current
    val keyboard = LocalSoftwareKeyboardController.current
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null || loading || preview != null) return@rememberLauncherForActivityResult
        loading = true
        error = null
        scope.launch {
            try {
                val picked = withContext(Dispatchers.IO) {
                    val name = context.contentResolver.query(uri, null, null, null, null)?.use { c ->
                        val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                        if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
                    }
                    val text = context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                        ?: throw RuntimeException("无法读取该文件")
                    (name ?: "本地模块.plugin") to text
                }
                val (fileName, text) = picked
                val displayName = name.ifBlank { fileName.substringBeforeLast('.') }
                preview = Actions.previewModuleText("local://$fileName", text, displayName)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                error = e.message ?: "读取本地模块失败"
            } finally {
                loading = false
            }
        }
    }

    LaunchedEffect(source) {
        if (source == ModuleImportSource.Local) filePicker.launch(arrayOf("*/*"))
    }

    NamuDialog(
        title = if (preview == null) source.title else "模块预览",
        confirmText = when {
            preview != null -> "确认导入"
            source == ModuleImportSource.Local -> "选择文件"
            source == ModuleImportSource.RuleSet -> "导入"
            else -> "预览"
        },
        dismissText = if (preview == null) "取消" else "返回编辑",
        loading = loading,
        scrollContent = true,
        confirmEnabled = preview != null || source == ModuleImportSource.Local || url.isNotBlank(),
        onDismiss = {
            if (preview == null) {
                onDismiss()
            } else {
                preview = null
                error = null
            }
        },
        onConfirm = confirm@{
            if (loading) return@confirm
            focus.clearFocus()
            keyboard?.hide()
            if (preview == null && source == ModuleImportSource.Local) {
                filePicker.launch(arrayOf("*/*"))
                return@confirm
            }
            loading = true
            error = null
            scope.launch {
                try {
                    val p = preview
                    if (p == null) {
                        if (source == ModuleImportSource.RuleSet) {
                            val lines = Actions.importRuleSet(url, name)
                            messages.show("已导入规则集：$lines 条过滤")
                            onDone()
                        } else {
                            preview = Actions.previewModule(url, name)
                        }
                    } else {
                        val result = Actions.importPreview(p, approveDns)
                        messages.show(buildString {
                            append("已导入「${result.name}」：${result.blockRules} 条阻断")
                            if (result.routeRules > 0) append("，${result.routeRules} 条分流")
                            if (result.allowRules > 0) append("，${result.allowRules} 条例外")
                            if (result.mitmRules > 0) append("，${result.mitmRules} 条 MITM/重写")
                            if (result.ignored > 0) append("，${result.ignored} 条暂不支持")
                        })
                        onDone()
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    error = e.message ?: "导入失败"
                } finally {
                    loading = false
                }
            }
        },
    ) {
        if (preview == null && source != ModuleImportSource.Local) {
            NamuTextField(
                url,
                { if (!loading) { url = it; error = null } },
                "HTTPS 链接",
                singleLine = true,
            )
            Spacer(Modifier.height(8.dp))
            NamuTextField(name, { if (!loading) name = it }, "名称（可留空）", singleLine = true)
            Text(
                "粘贴 URL",
                fontSize = 13.sp,
                color = NamuColors.Blue,
                modifier = Modifier
                    .clickable(enabled = !loading) { clipboard.getText()?.text?.let { url = it.trim(); error = null } }
                    .padding(vertical = 12.dp, horizontal = 4.dp),
            )
        }
        if (error != null) {
            Text(
                error!!,
                fontSize = 12.sp,
                color = NamuColors.Red,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        preview?.let { p ->
            val unusable = moduleUnusableCount(p.parsed)
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(NamuColors.Fill, RoundedCornerShape(NamuTokens.RadiusControl))
                    .padding(12.dp),
            ) {
                Text(
                    if (unusable == 0) "全部可用" else "有 $unusable 个不可用",
                    fontSize = 13.sp,
                    color = if (unusable == 0) NamuColors.Green else NamuColors.Orange,
                )
            }
            if (p.dnsNotes.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                Column(
                    Modifier
                        .fillMaxWidth()
                        .background(NamuColors.Fill, RoundedCornerShape(NamuTokens.RadiusControl))
                        .padding(12.dp),
                ) {
                    Text("附带 DNS 参数（经确认才合并进 DNS 配置）", fontSize = 13.sp, color = NamuColors.Orange)
                    Spacer(Modifier.height(4.dp))
                    p.dnsNotes.forEach { note ->
                        Text("· $note", fontSize = 11.sp, lineHeight = 16.sp, color = NamuColors.TextSub)
                    }
                }
                Spacer(Modifier.height(4.dp))
                SwitchRow("允许合并附带 DNS 参数", checked = approveDns, showDivider = false) { approveDns = it }
            }
        }
    }
}

/** 导入预览只保留结论：不可用条目数；空模块按 1 个不可用处理。 */
private fun moduleUnusableCount(parsed: com.namu.dns.ParsedModule): Int {
    val supported = parsed.blockLines.size + parsed.routeRules.size + parsed.allowLines.size +
        parsed.mitmHostnames.size + parsed.urlRewrites.size + parsed.headerRewrites.size +
        parsed.loonRewrites.size + parsed.bodyRewrites.size + parsed.hostMappings.size + parsed.scripts.size
    val unavailable = parsed.ignored + parsed.lostRouteTargets.size + parsed.scriptIssues.size
    return if (supported == 0 && unavailable == 0) 1 else unavailable
}

/** 单条脚本的可用性判断：正文缺失=不可用；用了未提供的宿主 API=部分可用。 */
private fun scriptCapability(rule: com.namu.dns.core.config.ScriptConfig): Pair<String, String> {
    // 禁用优先于可用性判断：它本来就不执行，不该显示成"不可用"让人去修正文。
    if (!rule.enabled) return "已禁用" to "Loon enable=false，条目不执行"
    if (rule.enableParam.isNotBlank()) return "跟随开关" to "启用状态由参数 ${rule.enableParam} 决定"
    if (rule.source.isBlank()) return "不可用" to "脚本正文未缓存"
    val gaps = mutableListOf<String>()
    val low = rule.source
    if (Regex("\\bfetch\\s*\\(").containsMatchIn(low)) gaps.add("fetch")
    if (Regex("\\bXMLHttpRequest\\b").containsMatchIn(low)) gaps.add("XMLHttpRequest")
    if (Regex("\\bWebAssembly\\b").containsMatchIn(low)) gaps.add("WebAssembly")
    if (gaps.isNotEmpty()) return "部分可用" to "未提供 ${gaps.joinToString("/")}，其余 API 可用"
    if (rule.binaryBodyMode) return "可用" to "Uint8Array 二进制正文"
    val used = buildList {
        if ("\$httpClient" in low) add("\$httpClient")
        if ("\$persistentStore" in low) add("\$persistentStore")
        if ("\$argument" in low) add("\$argument")
        if ("\$environment" in low) add("\$environment")
        if ("\$utils" in low) add("\$utils")
        if (Regex("\\brequire\\s*\\(").containsMatchIn(low)) add("require")
        if ("\$notification" in low) add("\$notification")
        if ("\$done" in low) add("\$done")
    }
    return "可用" to if (used.isEmpty()) "仅使用 \$request/\$response" else used.joinToString("/")
}

private fun sectionStatusLabel(status: String): String = when (status) {
    "executed" -> "已执行"
    "stored" -> "已存储，内核执行"
    "partial" -> "部分支持"
    "unsupported" -> "不支持"
    else -> "未识别"
}

private fun moduleSkipLabel(key: String): String = when (key) {
    "unsupported_section" -> "未支持分区"
    "unsupported_rule_type" -> "规则类型不支持"
    "unsupported_rule_target" -> "分流目标不支持"
    "invalid_rule" -> "规则值无效"
    "unsupported_adblock_option" -> "AdBlock 选项不支持"
    "invalid_adblock" -> "AdBlock 语法无效"
    "invalid_domain" -> "域名无效"
    "invalid_mitm_host" -> "MITM 域名无效"
    "host_mapping_invalid" -> "Host 映射无效"
    "host_server_system_unsupported" -> "Host server:system 不支持"
    "host_server_http_unsupported" -> "Host DoH 仅支持 HTTPS"
    "host_server_scheme_unsupported" -> "Host 上游协议不支持"
    "body_rewrite_invalid" -> "Body Rewrite 规则无效"
    "invalid_json_rule" -> "JSON 规则无效"
    else -> key
}
