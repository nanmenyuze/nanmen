package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.ConfigFileStore
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.config.ConfigFile

@Composable
fun QuickEditScreen(
    onBack: () -> Unit,
    onRestart: () -> Unit,
) {
    val context = LocalContext.current
    val container = LocalAppContainer.current
    val fileName = container.settings.activeConfigName()
    val initial = remember(fileName) {
        ConfigFileStore.exportText(context, fileName).orEmpty()
    }
    var editor by remember(fileName) { mutableStateOf(TextFieldValue(initial)) }
    var error by remember { mutableStateOf<String?>(null) }
    val lineCount = editor.text.lineSequence().count().coerceAtLeast(1)

    Column(Modifier.fillMaxSize().background(NamuColors.Bg)) {
        Row(
            Modifier.fillMaxWidth().statusBarsPadding().height(52.dp).padding(horizontal = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) { Text("取消", color = NamuColors.TextMain) }
            Text(
                "快速编辑",
                modifier = Modifier.weight(1f),
                textAlign = TextAlign.Center,
                fontSize = 17.sp,
                fontWeight = FontWeight.SemiBold,
                color = NamuColors.TextMain,
            )
            TextButton(
                onClick = {
                    val current = container.settings.current()
                    val parsed = ConfigFile.fromExternal(editor.text, current)
                    if (parsed == null) {
                        error = "JSON 格式或配置字段不正确"
                    } else {
                        container.settings.set(parsed.toAppConfig(current))
                        if (container.runtime.current().connected) onRestart()
                        container.messages.show("已保存 $fileName")
                        onBack()
                    }
                },
            ) {
                Text("保存", color = NamuColors.Brand, fontWeight = FontWeight.SemiBold)
            }
        }
        Text(
            fileName,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 6.dp),
            fontSize = 12.sp,
            color = NamuColors.TextSub,
        )
        if (error != null) {
            Text(
                error!!,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 4.dp),
                fontSize = 12.sp,
                color = NamuColors.Red,
            )
        }
        Row(
            Modifier.fillMaxWidth().weight(1f)
                .background(NamuColors.Card)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 12.dp, vertical = 14.dp),
        ) {
            Column(Modifier.width(34.dp), horizontalAlignment = Alignment.End) {
                repeat(lineCount) { index ->
                    Text(
                        "${index + 1}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        lineHeight = 21.sp,
                        color = NamuColors.TextTertiary,
                    )
                }
            }
            Spacer(Modifier.width(12.dp))
            BasicTextField(
                value = editor,
                onValueChange = {
                    editor = it
                    error = null
                },
                modifier = Modifier.fillMaxWidth(),
                textStyle = TextStyle(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    lineHeight = 21.sp,
                    color = NamuColors.TextMain,
                ),
                cursorBrush = SolidColor(NamuColors.Brand),
            )
        }
    }
}
