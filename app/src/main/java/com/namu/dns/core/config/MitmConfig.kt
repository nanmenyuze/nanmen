package com.namu.dns.core.config

import kotlinx.serialization.Serializable
import org.json.JSONArray
import org.json.JSONObject

/**
 * 配置文件里的 MITM 分区（对齐小火箭：[MITM] hostname 归属 .conf）。
 *
 * 外壳先把数据形状定死：内核 1.10 会忽略未知字段，1.11 接入后直接消费，
 * UI 与模型零结构调整。enabled 是「该配置是否启用 MITM」，全局开关另在设置页。
 *
 * - hostnames：需要解密的域名（支持 *.example.com 通配）
 * - skipHostnames：银行/支付等跳过域名（证书绑定应用自动放行之外的显式跳过）
 * - urlRewrites / headerRewrites：来自模块 [URL Rewrite]/[Header Rewrite] 的原始规则行，
 *   由内核解析执行；外壳只负责存储/合并/展示。
 */

/**
 * 一条脚本规则。source 是下载后的 JavaScript 正文；scriptPath 只在外壳使用，
 * 不下发内核。phase=request/response，pattern 匹配完整 URL。
 */
@Serializable
data class ScriptConfig(
    val name: String = "",
    val phase: String = "request",
    val pattern: String = "",
    val source: String = "",
    val arguments: Map<String, String> = emptyMap(),
    val timeoutMs: Int = 5000,
    val maxSize: Int = 2 * 1024 * 1024,
    val requiresBody: Boolean = false,
    /** `binary-body-mode=true`：body 以 Uint8Array 暴露，可处理 gRPC/protobuf 原始帧。 */
    val binaryBodyMode: Boolean = false,
    val scriptPath: String = "",
    /** Loon 单条 argument 的原始字符串（区别于 [Argument] 的对象形式）。 */
    val argumentText: String = "",
) {
    fun toJsonObject(): JSONObject = JSONObject().apply {
        put("name", name)
        put("phase", phase)
        put("pattern", pattern)
        put("source", source)
        put("arguments", JSONObject(arguments as Map<*, *>))
        put("timeoutMs", timeoutMs)
        put("maxSize", maxSize)
        put("requiresBody", requiresBody)
        put("binaryBodyMode", binaryBodyMode)
        if (argumentText.isNotBlank()) put("argumentText", argumentText)
    }

    companion object {
        fun fromJsonObject(o: JSONObject): ScriptConfig = ScriptConfig(
            name = o.optString("name", ""),
            phase = o.optString("phase", "request"),
            pattern = o.optString("pattern", ""),
            source = o.optString("source", ""),
            arguments = buildMap {
                o.optJSONObject("arguments")?.let { a ->
                    a.keys().forEach { k -> put(k, a.optString(k, "")) }
                }
            },
            timeoutMs = o.optInt("timeoutMs", 5000),
            maxSize = o.optInt("maxSize", 2 * 1024 * 1024),
            requiresBody = o.optBoolean("requiresBody", false),
            binaryBodyMode = o.optBoolean("binaryBodyMode", false),
            scriptPath = o.optString("scriptPath", ""),
            argumentText = o.optString("argumentText", ""),
        )
    }
}

@Serializable
data class MitmConfig(
    val enabled: Boolean = false,
    val hostnames: List<String> = emptyList(),
    val skipHostnames: List<String> = emptyList(),
    val urlRewrites: List<String> = emptyList(),
    val headerRewrites: List<String> = emptyList(),
    /** Loon [Rewrite] 原始行（旧版/新版），与 Surge [URL Rewrite] 分开保存。 */
    val loonRewrites: List<String> = emptyList(),
    /** 请求/响应脚本；模块导入时下载正文并缓存。 */
    val scripts: List<ScriptConfig> = emptyList(),
) {
    val isEmpty: Boolean
        get() = !enabled && hostnames.isEmpty() && skipHostnames.isEmpty() &&
            urlRewrites.isEmpty() && headerRewrites.isEmpty() && loonRewrites.isEmpty() &&
            scripts.isEmpty()

    fun toJsonObject(): JSONObject = JSONObject().apply {
        put("enabled", enabled)
        put("hostnames", JSONArray(hostnames))
        put("skipHostnames", JSONArray(skipHostnames))
        put("urlRewrites", JSONArray(urlRewrites))
        put("headerRewrites", JSONArray(headerRewrites))
        put("loonRewrites", JSONArray(loonRewrites))
        put("scripts", JSONArray(scripts.map { it.toJsonObject() }))
    }

    companion object {
        fun fromJsonObject(o: JSONObject?): MitmConfig {
            if (o == null) return MitmConfig()
            fun arr(key: String): List<String> {
                val a = o.optJSONArray(key) ?: return emptyList()
                return (0 until a.length()).map { a.optString(it, "") }.filter { it.isNotBlank() }
            }
            return MitmConfig(
                enabled = o.optBoolean("enabled", false),
                hostnames = arr("hostnames"),
                skipHostnames = arr("skipHostnames"),
                urlRewrites = arr("urlRewrites"),
                headerRewrites = arr("headerRewrites"),
                loonRewrites = arr("loonRewrites"),
                scripts = o.optJSONArray("scripts")?.let { a ->
                    (0 until a.length()).mapNotNull { i ->
                        a.optJSONObject(i)?.let { ScriptConfig.fromJsonObject(it) }
                    }
                } ?: emptyList(),
            )
        }
    }
}
