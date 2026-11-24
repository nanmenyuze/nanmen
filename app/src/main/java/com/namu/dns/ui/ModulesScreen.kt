package com.namu.dns.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.ArrowDownward
import androidx.compose.material.icons.outlined.ArrowUpward
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.zIndex
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.namu.dns.Actions
import com.namu.dns.ConfigStore
import com.namu.dns.ModuleSource
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.LocalDockClearance
import com.namu.dns.core.config.ModuleOrder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ModulesScreen(onRestart: () -> Unit) {
    var showAdd by remember { mutableStateOf(false) }
    var showLibrary by remember { mutableStateOf(false) }
    var syncing by remember { mutableStateOf(false) }
    var syncingId by remember { mutableStateOf<String?>(null) }
    var actionTarget by remember { mutableStateOf<ModuleSource?>(null) }
    var detailTarget by remember { mutableStateOf<ModuleSource?>(null) }
    var appTarget by remember { mutableStateOf<ModuleSource?>(null) }
    var deleteTarget by remember { mutableStateOf<ModuleSource?>(null) }
    val scope = rememberCoroutineScope()
    val container = LocalAppContainer.current
    val settings = container.settings
    val cfg by settings.config.collectAsStateWithLifecycle()
    val runtime = container.runtime
    val messages = container.messages
    val modules = cfg.moduleSources
    val enabled = modules.count { it.enabled }
    val hitState by container.hits.state.collectAsStateWithLifecycle()
    val todayBySource = remember(hitState.snapshot.sources) {
        hitState.snapshot.sources.associate { it.sourceId to it.hitsToday }
    }
    val ordered = remember(modules) {
        modules.sortedWith(
            compareBy<ModuleSource> { if (it.order >= 0) it.order else Int.MAX_VALUE }
                .thenBy { modules.indexOf(it) },
        )
    }
    val ctx = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val scrollState = rememberScrollState()
    val density = LocalDensity.current
    val autoScrollEdge = with(density) { 88.dp.toPx() }
    val centers = remember { mutableStateMapOf<String, Float>() }
    val rootCenters = remember { mutableStateMapOf<String, Float>() }
    val heights = remember { mutableStateMapOf<String, Float>() }
    var viewportTop by remember { mutableFloatStateOf(0f) }
    var viewportBottom by remember { mutableFloatStateOf(0f) }
    var draggingId by remember { mutableStateOf<String?>(null) }
    var dragOffsetY by remember { mutableFloatStateOf(0f) }
    var dragTargetIndex by remember { mutableStateOf(-1) }
    var autoScrollDirection by remember { mutableStateOf(0) }

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
            scope.launch { Actions.reorderModule(id, to) }
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
    val ruleSetIssues = remember(modules) {
        runCatching {
            val o = JSONObject(ConfigStore.moduleMitmFile(ctx).readText())
            val arr = o.optJSONArray("ruleSetIssues") ?: return@runCatching emptyList<String>()
            (0 until arr.length()).map { arr.optString(it) }.filter { it.isNotBlank() }
        }.getOrDefault(emptyList())
    }
    val ignoredRules = remember(modules) {
        runCatching {
            JSONObject(ConfigStore.moduleMitmFile(ctx).readText()).optInt("ignoredRules", 0)
        }.getOrDefault(0)
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(NamuColors.Bg)
            .onGloballyPositioned {
                viewportTop = it.positionInRoot().y
                viewportBottom = viewportTop + it.size.height
            }
            .verticalScroll(scrollState),
    ) {
        SectionHeader(
            container.config.activeName(),
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box {
                        TextAction("模块库") { showLibrary = true }
                        DropdownMenu(
                            expanded = showLibrary,
                            onDismissRequest = { showLibrary = false },
                        ) {
                            DropdownMenuItem(
                                text = { Text("导入本地文件或 URL") },
                                onClick = {
                                    showLibrary = false
                                    showAdd = true
                                },
                            )
                            DropdownMenuItem(
                                text = { Text(if (syncing) "同步中…" else "同步全部") },
                                enabled = !syncing && enabled > 0,
                                onClick = {
                                    showLibrary = false
                                    syncing = true
                                    scope.launch {
                                        try {
                                            val result = Actions.syncModules()
                                            messages.show(if (result.errors.isEmpty()) {
                                                "已同步 ${result.updated} 个模块"
                                            } else {
                                                "同步 ${result.updated} 个，失败 ${result.errors.size} 个：${result.errors.first()}"
                                            })
                                        } catch (e: Exception) {
                                            messages.show(e.message ?: "同步模块失败")
                                        } finally {
                                            syncing = false
                                        }
                                    }
                                },
                            )
                        }
                    }
                }
            },
        )
        val appBound = modules.count { it.app.isNotBlank() }
        GroupCard {
            SettingsRow(
                title = "应用归属",
                value = "$appBound 个模块",
                showDivider = true,
            )
            SettingsRow(
                title = "自定义规则",
                value = "${cfg.rules.size} 条",
                showDivider = false,
            )
        }
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
        if (modules.isEmpty()) {
            GroupCard {
                Column(
                    Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 30.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text("暂无模块", fontSize = 15.sp, color = NamuColors.TextMain)
                    Spacer(Modifier.height(12.dp))
                    Row(
                        Modifier
                            .heightIn(min = 48.dp)
                            .background(NamuColors.Blue, androidx.compose.foundation.shape.RoundedCornerShape(9.dp))
                            .clickable { showAdd = true }
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Outlined.Add, null, tint = androidx.compose.ui.graphics.Color.White, modifier = Modifier.height(16.dp))
                        Text(" 导入模块", fontSize = 13.sp, color = androidx.compose.ui.graphics.Color.White)
                    }
                }
            }
        } else {
            GroupCard {
                ordered.forEachIndexed { index, module ->
                    val totalRules = module.blockRules + module.routeRules + module.allowRules + module.mitmRules
                    val todayHits = todayBySource[module.id] ?: 0L
                    val subtitle = buildString {
                        append(if (module.url.isNotBlank()) "URL" else "本地")
                        append(" · $totalRules 条规则")
                        append(" · ")
                        append(if (module.updatedAt > 0) "更新 ${formatAgo(module.updatedAt)}" else "尚未更新")
                        append(" · 今日命中 $todayHits")
                        if (module.app.isNotBlank()) append(" · ${module.app}")
                        if (module.ignored > 0) append(" · ${module.ignored} 条不支持")
                        if (module.stale) append(" · 上次更新失败，继续使用旧缓存")
                        if (module.error.isNotBlank()) append("\n${module.error}")
                    }
                    val isDragging = draggingId == module.id
                    val from = ordered.indexOfFirst { it.id == draggingId }
                    val target = dragTargetIndex
                    val draggedHeight = draggingId?.let { heights[it] } ?: 0f
                    val displacement = if (draggingId == null || isDragging || from < 0 || target < 0) {
                        0f
                    } else when {
                        target > from && index in (from + 1)..target -> -draggedHeight
                        target < from && index in target until from -> draggedHeight
                        else -> 0f
                    }
                    ModuleRow(
                        module = module,
                        subtitle = subtitle,
                        showDivider = index != ordered.lastIndex,
                        isDragging = isDragging,
                        dragOffsetY = if (isDragging) dragOffsetY else 0f,
                        displacementY = displacement,
                        onMeasure = { coordinates ->
                            centers[module.id] = coordinates.positionInParent().y + coordinates.size.height / 2f
                            rootCenters[module.id] = coordinates.positionInRoot().y + coordinates.size.height / 2f
                            heights[module.id] = coordinates.size.height.toFloat()
                        },
                        onClick = { if (draggingId == null) actionTarget = module },
                        onCheckedChange = { enabledNow ->
                            scope.launch { Actions.setModuleEnabled(module.id, enabledNow) }
                        },
                        onDragStart = {
                            if (draggingId == null) {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                draggingId = module.id
                                dragOffsetY = 0f
                                dragTargetIndex = index
                                autoScrollDirection = 0
                            }
                        },
                        onDrag = { amountY ->
                            if (draggingId == module.id) {
                                dragOffsetY += amountY
                                updateDragTarget()
                                updateAutoScroll()
                            }
                        },
                        onDragEnd = { finishDrag(save = true) },
                        onDragCancel = { finishDrag(save = false) },
                    )
                }
            }
        }

        Spacer(Modifier.height(LocalDockClearance.current + 34.dp))
    }

    if (showAdd) {
        AddModuleDialog(
            onDismiss = { showAdd = false },
            onDone = {
                showAdd = false
                if (runtime.current().connected) onRestart()
            },
        )
    }
    actionTarget?.let { target ->
        val current = ordered.firstOrNull { it.id == target.id } ?: target
        val index = ordered.indexOfFirst { it.id == current.id }
        ModuleActionSheet(
            module = current,
            index = index,
            lastIndex = ordered.lastIndex,
            syncing = syncingId == current.id,
            onDismiss = { actionTarget = null },
            onDetail = {
                actionTarget = null
                detailTarget = current
            },
            onEditApp = {
                actionTarget = null
                appTarget = current
            },
            onSync = {
                actionTarget = null
                if (syncingId == null) {
                    syncingId = current.id
                    scope.launch {
                        try {
                            val result = Actions.syncModules(current.id)
                            messages.show(if (result.errors.isEmpty()) {
                                "已同步「${current.name.ifBlank { "未命名模块" }}」"
                            } else {
                                result.errors.first()
                            })
                        } catch (e: Exception) {
                            messages.show(e.message ?: "同步模块失败")
                        } finally {
                            syncingId = null
                        }
                    }
                }
            },
            onMove = { destination ->
                actionTarget = null
                scope.launch { Actions.reorderModule(current.id, destination) }
            },
            onDelete = {
                actionTarget = null
                deleteTarget = current
            },
        )
    }
    detailTarget?.let { target ->
        ModuleDetailSheet(target, onDismiss = { detailTarget = null })
    }
    appTarget?.let { target ->
        ModuleAppSheet(
            module = target,
            onDismiss = { appTarget = null },
            onSave = { app ->
                scope.launch {
                    Actions.setModuleApp(target.id, app)
                    appTarget = null
                    messages.show(if (app.isBlank()) "已清除应用归属" else "已保存应用归属")
                }
            },
        )
    }
    deleteTarget?.let { target ->
        NamuDialog(
            title = "删除模块",
            message = "删除「${target.name}」后，它带来的规则会立即从本地过滤中移除。",
            confirmText = "删除",
            confirmColor = NamuColors.Red,
            onDismiss = { deleteTarget = null },
            onConfirm = {
                val id = target.id
                deleteTarget = null
                scope.launch {
                    Actions.deleteModule(id)
                    messages.show("已删除模块")
                }
            },
        ) {}
    }
}

@Composable
private fun ModuleRow(
    module: ModuleSource,
    subtitle: String,
    showDivider: Boolean,
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
    Column(
        Modifier
            .fillMaxWidth()
            .onGloballyPositioned(onMeasure)
            .zIndex(if (isDragging) 2f else 0f)
            .graphicsLayer {
                translationY = if (isDragging) dragOffsetY else displaced
                scaleX = scale
                scaleY = scale
            }
            .then(
                if (isDragging) {
                    Modifier
                        .shadow(16.dp, RoundedCornerShape(14.dp))
                        .clip(RoundedCornerShape(14.dp))
                        .background(NamuColors.Card)
                } else {
                    Modifier.background(if (pressed) NamuColors.FillPressed else Color.Transparent)
                },
            ),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 64.dp)
                .padding(start = 16.dp, end = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(
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
                        onClick = onClick,
                    )
                    .padding(vertical = 12.dp),
            ) {
                Text(
                    module.name.ifBlank { "未命名模块" },
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium,
                    color = NamuColors.TextMain,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    subtitle,
                    fontSize = 12.sp,
                    color = if (module.error.isNotBlank()) NamuColors.Orange else NamuColors.TextSub,
                    lineHeight = 16.sp,
                )
            }
            Spacer(Modifier.width(8.dp))
            // 手势只挂在左侧内容区，开关的点击和长按都不会触发卡片功能面板或拖拽。
            IosSwitch(checked = module.enabled, onCheckedChange = onCheckedChange)
        }
        if (showDivider) RowDivider()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModuleActionSheet(
    module: ModuleSource,
    index: Int,
    lastIndex: Int,
    syncing: Boolean,
    onDismiss: () -> Unit,
    onDetail: () -> Unit,
    onEditApp: () -> Unit,
    onSync: () -> Unit,
    onMove: (Int) -> Unit,
    onDelete: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = NamuColors.Bg) {
        Column(Modifier.fillMaxWidth().padding(bottom = 26.dp)) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp)) {
                Text(
                    module.name.ifBlank { "未命名模块" },
                    fontSize = 22.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = NamuColors.TextMain,
                )
                Spacer(Modifier.height(8.dp))
            }
            GroupCard {
                ModuleActionRow(
                    icon = Icons.Outlined.Description,
                    title = "查看规则与详情",
                    chevron = true,
                    onClick = onDetail,
                )
                ModuleActionRow(
                    icon = Icons.Outlined.Apps,
                    title = "应用归属管理",
                    value = module.app.ifBlank { "未设置" },
                    chevron = true,
                    onClick = onEditApp,
                )
                ModuleActionRow(
                    icon = Icons.Outlined.Sync,
                    title = if (syncing) "正在同步当前模块" else "立即同步当前模块",
                    loading = syncing,
                    enabled = !syncing && module.url.startsWith("https://"),
                    onClick = onSync,
                )
                ModuleActionRow(
                    icon = Icons.Outlined.ArrowUpward,
                    title = "上移",
                    enabled = index > 0,
                    onClick = { onMove(index - 1) },
                )
                ModuleActionRow(
                    icon = Icons.Outlined.ArrowDownward,
                    title = "下移",
                    enabled = index in 0 until lastIndex,
                    showDivider = false,
                    onClick = { onMove(index + 1) },
                )
            }
            Spacer(Modifier.height(12.dp))
            GroupCard {
                ModuleActionRow(
                    icon = Icons.Outlined.Delete,
                    title = "删除模块",
                    destructive = true,
                    showDivider = false,
                    onClick = onDelete,
                )
            }
        }
    }
}

@Composable
private fun ModuleActionRow(
    icon: ImageVector,
    title: String,
    value: String? = null,
    enabled: Boolean = true,
    loading: Boolean = false,
    chevron: Boolean = false,
    destructive: Boolean = false,
    showDivider: Boolean = true,
    onClick: () -> Unit,
) {
    val contentColor = if (destructive) NamuColors.Red else NamuColors.TextMain
    Column(
        Modifier
            .fillMaxWidth()
            .alpha(if (enabled) 1f else 0.42f)
            .clickable(enabled = enabled && !loading, onClick = onClick),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 58.dp)
                .padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            NamuIcon(icon, null, tint = if (destructive) NamuColors.Red else NamuColors.Brand)
            Spacer(Modifier.width(13.dp))
            Text(title, fontSize = 16.sp, color = contentColor, modifier = Modifier.weight(1f))
            if (loading) {
                CircularProgressIndicator(Modifier.size(19.dp), strokeWidth = 2.dp, color = NamuColors.Brand)
            } else if (value != null) {
                Text(value, fontSize = 12.sp, color = NamuColors.TextSub, maxLines = 1)
            }
            if (chevron) {
                Spacer(Modifier.width(8.dp))
                Chevron()
            }
        }
        if (showDivider) RowDivider(startInset = 49.dp)
    }
}

@Suppress("ProduceStateDoesNotAssignValue")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModuleDetailSheet(module: ModuleSource, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val cached by produceState<String?>(initialValue = null, module.id, module.updatedAt) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                val file = ConfigStore.moduleFile(context, module.id)
                if (!file.exists() || file.length() == 0L) {
                    "暂无本地缓存正文。远程模块可先执行“立即同步当前模块”。"
                } else {
                    val text = file.readText()
                    if (text.length > 20_000) text.take(20_000) + "\n\n… 正文过长，仅显示前 20,000 个字符" else text
                }
            }.getOrElse { "读取模块缓存失败：${it.message ?: "未知错误"}" }
        }
    }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = NamuColors.Bg) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp).padding(bottom = 26.dp)) {
            Text(
                module.name.ifBlank { "未命名模块" },
                fontSize = 22.sp,
                fontWeight = FontWeight.SemiBold,
                color = NamuColors.TextMain,
            )
            Text(
                "阻断 ${module.blockRules} · 分流 ${module.routeRules} · 例外 ${module.allowRules} · MITM ${module.mitmRules}" +
                    "\n来源：${module.url.ifBlank { "本地模块" }}" +
                    "\n更新：${if (module.updatedAt > 0) formatAgo(module.updatedAt) else "尚未更新"}",
                fontSize = 12.sp,
                color = NamuColors.TextSub,
                lineHeight = 17.sp,
                modifier = Modifier.padding(top = 5.dp, bottom = 12.dp),
            )
            Column(
                Modifier
                    .fillMaxWidth()
                    .heightIn(max = 480.dp)
                    .clip(RoundedCornerShape(14.dp))
                    .background(NamuColors.Fill)
                    .verticalScroll(rememberScrollState())
                    .padding(14.dp),
            ) {
                val text = cached
                if (text == null) {
                    CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = NamuColors.Brand)
                } else {
                    SelectionContainer {
                        Text(
                            text,
                            fontSize = 11.sp,
                            lineHeight = 16.sp,
                            fontFamily = FontFamily.Monospace,
                            color = NamuColors.TextMain,
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModuleAppSheet(
    module: ModuleSource,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit,
) {
    var app by remember(module.id) { mutableStateOf(module.app) }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = NamuColors.Bg) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp).padding(bottom = 26.dp)) {
            Text(
                "应用归属",
                fontSize = 22.sp,
                fontWeight = FontWeight.SemiBold,
                color = NamuColors.TextMain,
            )
            Text(
                module.name.ifBlank { "未命名模块" },
                fontSize = 13.sp,
                color = NamuColors.TextSub,
                modifier = Modifier.padding(top = 3.dp, bottom = 14.dp),
            )
            NamuTextField(app, { app = it }, "例如：酷安、B站或 com.example.app", singleLine = true)
            Text(
                "这里编辑的是模块的 #!app 分组元数据，用于整理和识别规则归属；不会把模块变成系统级按 UID 隔离。远程模块若自带 #!app，下次同步可能以远程值为准。留空保存可清除归属。",
                fontSize = 12.sp,
                color = NamuColors.TextSub,
                lineHeight = 17.sp,
                modifier = Modifier.padding(vertical = 12.dp),
            )
            IosButton("保存归属", onClick = { onSave(app) })
        }
    }
}

@Composable
private fun AddModuleDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var preview by remember { mutableStateOf<Actions.ModulePreview?>(null) }
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

    NamuDialog(
        title = if (preview == null) "导入模块" else "模块预览",
        message = if (preview == null) "选择本地文件或填写 HTTPS 链接。" else null,
        confirmText = if (preview == null) "预览" else "确认导入",
        dismissText = if (preview == null) "取消" else "返回编辑",
        loading = loading,
        scrollContent = true,
        confirmEnabled = preview != null || url.isNotBlank(),
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
            loading = true
            error = null
            scope.launch {
                try {
                    val p = preview
                    if (p == null) {
                        preview = Actions.previewModule(url, name)
                            } else {
                        val result = Actions.importPreview(p)
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
        if (preview == null) {
            NamuTextField(url, { if (!loading) { url = it; error = null } }, "https://example.com/app.sgmodule", singleLine = true)
            Spacer(Modifier.height(8.dp))
            NamuTextField(name, { if (!loading) name = it }, "模块名称（可留空，自动读取）", singleLine = true)
            Row(
                Modifier.fillMaxWidth().padding(top = 2.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "从本地文件导入",
                    fontSize = 12.sp,
                    color = NamuColors.Blue,
                    modifier = Modifier
                        .clickable(enabled = !loading) {
                            focus.clearFocus()
                            keyboard?.hide()
                            filePicker.launch(arrayOf("*/*"))
                        }
                        .padding(vertical = 8.dp, horizontal = 4.dp),
                )
                Text(
                    "从剪贴板粘贴 URL",
                    fontSize = 12.sp,
                    color = NamuColors.Blue,
                    modifier = Modifier
                        .clickable(enabled = !loading) { clipboard.getText()?.text?.let { url = it; error = null } }
                        .padding(vertical = 8.dp, horizontal = 4.dp),
                )
            }
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
                    .background(NamuColors.Fill, RoundedCornerShape(10.dp))
                    .padding(12.dp),
            ) {
                Text(
                    if (unusable == 0) "全部可用" else "有 $unusable 个不可用",
                    fontSize = 13.sp,
                    color = if (unusable == 0) NamuColors.Green else NamuColors.Orange,
                )
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
