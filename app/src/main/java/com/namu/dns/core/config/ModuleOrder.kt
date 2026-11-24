package com.namu.dns.core.config

import com.namu.dns.ModuleSource

/**
 * S3：拖拽只改 order，不改 identity。调用方在 Profile 内传 enabled/disabled 全表，
 * 返回的新列表按 0..n-1 重新编号，后续 rebuildModules 直接按 order 执行。
 */
object ModuleOrder {
    fun move(modules: List<ModuleSource>, from: Int, to: Int): List<ModuleSource> {
        if (modules.isEmpty()) return modules
        val a = from.coerceIn(0, modules.lastIndex)
        val b = to.coerceIn(0, modules.lastIndex)
        if (a == b) return modules.withIndex().map { (i, m) -> m.copy(order = i) }
        val list = modules.toMutableList()
        val item = list.removeAt(a)
        list.add(b, item)
        return list.mapIndexed { i, m -> m.copy(order = i) }
    }

    /**
     * 按拖拽后的卡片中心计算插入位置。只比较其他模块的原始中心，
     * 因此卡片高度不同也不会因为视觉位移反复跳动。
     */
    fun dragTarget(centers: List<Float>, from: Int, draggedCenter: Float): Int {
        if (from !in centers.indices) return -1
        var target = 0
        centers.forEachIndexed { index, center ->
            if (index != from && center < draggedCenter) target++
        }
        return target
    }

    /** 关闭模块只动 enabled，不重排、不改 id，避免同步任务用旧快照把它复活。 */
    fun setEnabled(modules: List<ModuleSource>, id: String, enabled: Boolean): List<ModuleSource> =
        modules.map { if (it.id == id) it.copy(enabled = enabled) else it }

    /** 同步结果只允许写 url/缓存/统计字段，enabled/order 由 Profile 决定。 */
    fun mergeSync(
        local: List<ModuleSource>,
        remote: List<ModuleSource>,
    ): List<ModuleSource> {
        val byId = local.associateBy { it.id }
        return local.map { old ->
            val fresh = remote.firstOrNull { it.id == old.id } ?: return@map old
            old.copy(
                updatedAt = fresh.updatedAt,
                blockRules = fresh.blockRules,
                routeRules = fresh.routeRules,
                mitmRules = fresh.mitmRules,
                allowRules = fresh.allowRules,
                ignored = fresh.ignored,
                error = fresh.error,
                etag = fresh.etag,
                lastModified = fresh.lastModified,
                stale = fresh.stale,
                cacheBytes = fresh.cacheBytes,
            )
        } + remote.filter { it.id !in byId }
    }
}
