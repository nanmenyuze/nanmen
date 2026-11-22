package com.namu.dns

/**
 * 远程模块拉取的纯策略层，便于单测覆盖「支持子集 + 显式拒绝清单」。
 * 真正的网络、缓存和原子替换仍在 Actions.syncModules 中完成。
 */
object ModuleFetchPolicy {
    const val MAX_BYTES = 4 * 1024 * 1024

    private val allowedContentTypes = setOf(
        "application/octet-stream",
        "application/json",
        "application/yaml",
        "application/x-yaml",
    )

    /** 远程来源只允许 HTTPS；local:// 仅供本地文件导入/预览。 */
    fun urlError(url: String, allowLocal: Boolean = false): String? {
        val target = url.trim()
        if (target.isBlank()) return "模块来源为空"
        if (target.startsWith("https://")) return null
        if (allowLocal && target.startsWith("local://")) return null
        return "远程模块只允许 HTTPS"
    }

    /** 空 Content-Type 允许（部分静态站点不返回），其余必须是 text 斜杠星号、或以白名单类型开头。 */
    fun contentTypeError(raw: String?): String? {
        val ct = raw.orEmpty().substringBefore(';').trim().lowercase()
        if (ct.isEmpty()) return null
        if (ct.startsWith("text/") || ct in allowedContentTypes) return null
        return "Content-Type 不允许: $ct"
    }

    fun sizeError(bytes: Long): String? =
        if (bytes > MAX_BYTES) "模块超过 4MB" else null

    /** 模块是文本格式；除 TAB/LF/CR 外的 C0 控制字符明确拒绝。 */
    fun controlCharError(text: String): String? =
        if (text.any { it.code < 0x09 || (it.code in 0x0E..0x1F) }) {
            "模块包含异常控制字符"
        } else null
}
