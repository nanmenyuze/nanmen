package com.namu.dns.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.launch
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.OffsetMapping
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.TransformedText
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.ConfigFileStore
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.config.ConfigFile

@Composable
fun QuickEditScreen(
    name: String,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val container = LocalAppContainer.current
    val profile = rememberProfileEditor(name) ?: return
    val scope = rememberCoroutineScope()
    val fileName = name
    val initial = remember(fileName) { ConfigFile.fromAppConfig(profile.current()).toJson() }
    var editor by remember(fileName) { mutableStateOf(TextFieldValue(initial)) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirmExit by remember { mutableStateOf(false) }
    var saving by remember { mutableStateOf(false) }
    var textLayout by remember { mutableStateOf<TextLayoutResult?>(null) }

    fun save() {
        if (saving) return
        val current = profile.current()
        val parsed = ConfigFile.fromExternal(editor.text, current)
        if (parsed == null) {
            error = "JSON 格式或配置字段不正确"
            return
        }
        scope.launch {
            saving = true
            try {
                val candidate = parsed.toAppConfig(current)
                if (profile.isActive && !prepareProfileCa(candidate, context)) {
                    error = "CA 准备失败"
                    return@launch
                }
                if (profile.update { parsed.toAppConfig(it) }) {
                    container.messages.show("已保存 $fileName")
                    onBack()
                }
            } finally {
                saving = false
            }
        }
    }

    fun requestBack() {
        if (editor.text == initial) onBack() else confirmExit = true
    }
    BackHandler { requestBack() }
    if (confirmExit) {
        NamuDialog(
            title = "保存修改？",
            confirmText = "保存",
            dismissText = "继续编辑",
            onConfirm = { confirmExit = false; save() },
            onDismiss = { confirmExit = false },
        ) {
            TextButton(onClick = { confirmExit = false; onBack() }) { Text("放弃修改") }
        }
    }
    val editorScroll = rememberScrollState()
    val lineCount = editor.text.lineSequence().count().coerceAtLeast(1)
    val currentLine = remember(editor.text, editor.selection) {
        editor.text.take(editor.selection.start.coerceIn(0, editor.text.length)).count { it == '\n' }
    }
    val jsonTransformation = rememberJsonVisualTransformation()
    val currentLineColor = NamuColors.Orange.copy(alpha = if (NamuColors.isDark) 0.13f else 0.08f)

    Column(Modifier.fillMaxSize().background(NamuColors.Bg)) {
        Row(
            Modifier.fillMaxWidth().statusBarsPadding().height(52.dp).padding(horizontal = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = { requestBack() }) { Text("取消", color = NamuColors.Blue) }
            Text(
                "快速编辑",
                modifier = Modifier.weight(1f),
                textAlign = TextAlign.Center,
                fontSize = 17.sp,
                fontWeight = FontWeight.SemiBold,
                color = NamuColors.TextMain,
            )
            TextButton(onClick = { save() }, enabled = !saving) {
                Text("保存", color = NamuColors.Brand, fontWeight = FontWeight.SemiBold)
            }
        }

        Spacer(Modifier.height(8.dp))
        GroupCard {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 15.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    Modifier.size(42.dp).clip(RoundedCornerShape(NamuTokens.RadiusControl))
                        .background(NamuColors.Blue.copy(alpha = 0.10f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        Icons.Outlined.Description,
                        contentDescription = null,
                        tint = NamuColors.Blue,
                        modifier = Modifier.size(27.dp),
                    )
                }
                Spacer(Modifier.width(13.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        fileName,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = NamuColors.TextMain,
                        maxLines = 1,
                    )
                    Spacer(Modifier.height(3.dp))
                    Text(
                        "当前配置文件 · 原生 JSON",
                        fontSize = 12.sp,
                        color = NamuColors.TextSub,
                    )
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    "编辑中",
                    modifier = Modifier.clip(RoundedCornerShape(7.dp))
                        .background(NamuColors.Orange.copy(alpha = 0.10f))
                        .padding(horizontal = 9.dp, vertical = 5.dp),
                    fontSize = 11.sp,
                    color = NamuColors.Orange,
                )
            }
        }

        Row(
            Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(NamuColors.Green))
            Spacer(Modifier.width(7.dp))
            Text(
                "保存前自动校验 JSON 与配置格式",
                modifier = Modifier.weight(1f),
                fontSize = 12.sp,
                color = NamuColors.TextSub,
            )
            Text("UTF-8", fontSize = 11.sp, color = NamuColors.TextTertiary)
        }
        if (error != null) {
            Text(
                error!!,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp).padding(bottom = 10.dp),
                fontSize = 12.sp,
                color = NamuColors.Red,
            )
        }

        Box(
            Modifier.fillMaxWidth().weight(1f)
                .padding(horizontal = 16.dp)
                .padding(bottom = 16.dp)
                .clip(RoundedCornerShape(NamuTokens.RadiusCard))
                .background(NamuColors.Card),
        ) {
            Row(
                Modifier.fillMaxSize().verticalScroll(editorScroll).padding(vertical = 13.dp),
            ) {
                Column(
                    Modifier.width(42.dp),
                    horizontalAlignment = Alignment.End,
                ) {
                    repeat(lineCount) { index ->
                        Text(
                            "${index + 1}",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 13.sp,
                            lineHeight = 21.sp,
                            color = if (index == currentLine) NamuColors.Orange else NamuColors.TextTertiary,
                        )
                    }
                }
                Spacer(Modifier.width(11.dp))
                BasicTextField(
                    value = editor,
                    onValueChange = {
                        editor = it
                        error = null
                    },
                    modifier = Modifier.weight(1f).padding(end = 14.dp).drawBehind {
                        val layout = textLayout ?: return@drawBehind
                        if (layout.lineCount == 0 || editor.text.isEmpty()) return@drawBehind
                        val offset = editor.selection.start.coerceIn(0, editor.text.length)
                        val line = layout.getLineForOffset(offset).coerceIn(0, layout.lineCount - 1)
                        val top = layout.getLineTop(line)
                        val bottom = layout.getLineBottom(line)
                        drawRect(
                            color = currentLineColor,
                            topLeft = Offset(0f, top),
                            size = Size(size.width, bottom - top),
                        )
                    },
                    textStyle = TextStyle(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        lineHeight = 21.sp,
                        color = NamuColors.TextMain,
                    ),
                    cursorBrush = SolidColor(NamuColors.Brand),
                    visualTransformation = jsonTransformation,
                    onTextLayout = { textLayout = it },
                )
            }
        }
    }
}

private val jsonTokenRegex = Regex(
    """("(?:\\.|[^"\\])*")(?=\s*:)|("(?:\\.|[^"\\])*")|\b(true|false|null)\b|(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)""",
)

private class JsonVisualTransformation(
    private val keyColor: Color,
    private val stringColor: Color,
    private val literalColor: Color,
    private val numberColor: Color,
) : VisualTransformation {
    override fun filter(text: AnnotatedString): TransformedText {
        val source = text.text
        val highlighted = buildAnnotatedString {
            append(source)
            jsonTokenRegex.findAll(source).forEach { match ->
                val color = when {
                    match.groups[1] != null -> keyColor
                    match.groups[2] != null -> stringColor
                    match.groups[3] != null -> literalColor
                    else -> numberColor
                }
                addStyle(SpanStyle(color = color), match.range.first, match.range.last + 1)
            }
        }
        return TransformedText(highlighted, OffsetMapping.Identity)
    }
}

@Composable
private fun rememberJsonVisualTransformation(): VisualTransformation {
    val dark = NamuColors.isDark
    return remember(dark) {
        JsonVisualTransformation(
            keyColor = if (dark) Color(0xFF7DAFFF) else Color(0xFF2563EB),
            stringColor = if (dark) Color(0xFF7DDCB0) else Color(0xFF16845B),
            literalColor = if (dark) Color(0xFFFFB86B) else Color(0xFFC26700),
            numberColor = if (dark) Color(0xFFD4A5FF) else Color(0xFF8B45B8),
        )
    }
}
