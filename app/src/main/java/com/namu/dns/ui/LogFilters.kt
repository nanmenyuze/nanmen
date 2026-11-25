package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.namu.dns.DnsLogEntry
import com.namu.dns.LogEntry

internal fun runtimeLevelKey(level: String): String = when (level.uppercase().firstOrNull()) {
    'E' -> "E"
    'W' -> "W"
    else -> "I"
}

internal fun filterRuntimeLogs(logs: List<LogEntry>, level: String, query: String): List<LogEntry> {
    val q = query.trim()
    return logs.filter { entry ->
        (level == "all" || level == runtimeLevelKey(entry.level)) &&
            (q.isEmpty() || (entry.msg + " " + entry.tag).contains(q, ignoreCase = true))
    }
}

internal fun filterDnsLogs(logs: List<DnsLogEntry>, action: String, query: String): List<DnsLogEntry> {
    val q = query.trim()
    return logs.filter { entry ->
        (action == "all" || entry.action == action) &&
            (q.isEmpty() || entry.domain.contains(q, ignoreCase = true))
    }
}

/** 日志页通用筛选条：动作/级别 chips + 关键字输入。 */
@Composable
fun LogFilterBar(
    chips: List<Pair<String, String>>,
    selected: String,
    onSelect: (String) -> Unit,
    query: String,
    onQueryChange: (String) -> Unit,
    placeholder: String,
) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 2.dp)
            .clip(RoundedCornerShape(NamuTokens.RadiusControl))
            .background(NamuColors.Card)
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            chips.forEach { (key, label) ->
                ChoiceChip(label, selected == key) { onSelect(key) }
            }
        }
        Spacer(Modifier.height(8.dp))
        NamuTextField(
            value = query,
            onChange = onQueryChange,
            placeholder = placeholder,
            singleLine = true,
        )
    }
}
