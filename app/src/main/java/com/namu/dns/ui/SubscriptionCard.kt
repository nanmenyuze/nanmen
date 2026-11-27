package com.namu.dns.ui

import com.namu.dns.SubscriptionInfo
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

internal fun subscriptionSummary(info: SubscriptionInfo): String? = buildList {
    if (info.total > 0) add("剩余 ${formatBytes(info.remaining)}")
    if (info.expireAt > 0) {
        val date = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date(info.expireAt))
        add(if (info.expireAt <= System.currentTimeMillis()) "已到期" else "${date} 到期")
    }
}.joinToString(" · ").ifBlank { null }
