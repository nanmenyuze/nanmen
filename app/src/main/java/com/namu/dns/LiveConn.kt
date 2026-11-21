package com.namu.dns

import android.content.Context
import org.json.JSONObject

/** 一条活跃 TCP 连接的内核快照。`uid == null` 表示归属未解析（无 root 或表还没同步）。 */
data class LiveConn(
    val id: Long,
    val uid: Int?,
    val domain: String?,
    val ip: String,
    val port: Int,
    val action: String,
    val rule: String,
    val mitm: Boolean,
    val ageMs: Long,
    val upBytes: Long,
    val downBytes: Long,
) {
    /** 瞬时速率（B/s），由 LiveConnStore 每次刷新时按两次采样差分算好写入。 */
    var upBps: Long = 0L
    var downBps: Long = 0L
    /** 列表主标题：有域名用域名，否则用 IP。 */
    val target: String get() = domain?.takeIf { it.isNotEmpty() } ?: ip

    /** 目标串：域名带端口，裸 IP 只在非 443 时补端口，避免每行都拖一串 `:443`。 */
    val endpoint: String
        get() = when {
            !domain.isNullOrEmpty() -> "$domain:$port"
            port == 443 -> ip
            else -> "$ip:$port"
        }

    /** 按 App 分流下最该看的一列：这条连接算谁的。 */
    fun appLabel(context: Context): String = AppLabel.of(context, uid)
}

/**
 * 活跃连接快照的增量缓存。
 *
 * 内核每次只回 id 大于游标的记录，壳层按内核给的 total 裁掉最旧的条目：
 * 连接关闭时内核不会推删除事件，`total` 就是唯一可信的「现在还有几条」。
 * 这样每秒只传新增部分，不会因为 1024 条上限把整表重传一遍。
 */
internal class LiveConnStore {
    private val items = LinkedHashMap<Long, LiveConn>()
    private var cursor = 0L
    // 速率差分：保留上次采样的累计字节与时刻（内核给的是累计值，不是速率）。
    private val prevBytes = HashMap<Long, Pair<Long, Long>>()
    private var lastSampleMs = 0L

    var total: Int = 0
        private set

    fun rows(): List<LiveConn> = items.values.sortedByDescending { it.id }

    fun clear() {
        items.clear()
        cursor = 0
        total = 0
    }

    fun refresh(): List<LiveConn> {
        if (!NativeCore.available) return rows()
        val text = runCatching { NativeCore.nativeConnections(cursor) }.getOrNull() ?: return rows()
        val o = runCatching { JSONObject(text) }.getOrNull() ?: return rows()
        total = o.optInt("total", items.size)
        cursor = o.optLong("last", cursor)
        val arr = o.optJSONArray("items")
        if (arr != null) {
            for (i in 0 until arr.length()) {
                val c = arr.optJSONObject(i) ?: continue
                val id = c.optLong("id")
                if (id <= 0) continue
                items[id] = LiveConn(
                    id = id,
                    uid = if (c.isNull("uid")) null else c.optInt("uid"),
                    domain = if (c.isNull("domain")) null else c.optString("domain"),
                    ip = c.optString("ip"),
                    port = c.optInt("port"),
                    action = c.optString("action"),
                    rule = c.optString("rule"),
                    mitm = c.optBoolean("mitm"),
                    ageMs = c.optLong("ageMs"),
                    upBytes = c.optLong("up"),
                    downBytes = c.optLong("down"),
                )
            }
        }
        // id 单调递增，keys 的插入顺序就是建立顺序；超出总数就从头删最旧的。
        while (items.size > total) {
            val oldest = items.keys.firstOrNull() ?: break
            items.remove(oldest)
            prevBytes.remove(oldest)
        }
        // 速率差分：间隔太短会放大抖动，0.2s 以下直接沿用上次结果。
        val nowMs = System.currentTimeMillis()
        if (lastSampleMs > 0L) {
            val dt = (nowMs - lastSampleMs) / 1000.0
            if (dt >= 0.2) {
                for (c in items.values) {
                    val p = prevBytes[c.id]
                    if (p != null) {
                        c.upBps = ((c.upBytes - p.first).coerceAtLeast(0L) / dt).toLong()
                        c.downBps = ((c.downBytes - p.second).coerceAtLeast(0L) / dt).toLong()
                    }
                }
                prevBytes.clear()
                for (c in items.values) prevBytes[c.id] = c.upBytes to c.downBytes
                lastSampleMs = nowMs
            }
        } else {
            for (c in items.values) prevBytes[c.id] = c.upBytes to c.downBytes
            lastSampleMs = nowMs
        }
        return rows()
    }
}

/**
 * UID → 应用名的展示缓存。
 * 包可见性受限时 `getNameForUid` 可能拿不到，宁可直接显示 `UID 10086`，
 * 也不要空着让用户以为没解析。
 */
internal object AppLabel {
    private val cache = HashMap<Int, String>()

    fun of(context: Context, uid: Int?): String {
        if (uid == null) return "归属未知"
        if (uid == 0) return "root"
        cache[uid]?.let { return it }
        val label = runCatching {
            val pm = context.packageManager
            val pkg = pm.getNameForUid(uid) ?: return@runCatching null
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        }.getOrNull() ?: "UID $uid"
        cache[uid] = label
        return label
    }
}
