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
    /** 预筛 URL 正则；有 condition 时由内核按条件树重算。 */
    val pattern: String = "",
    /** Loon Script v2 条件表达式；空 = 旧版仅按 pattern 匹配。 */
    val condition: String = "",
    val source: String = "",
    val arguments: Map<String, String> = emptyMap(),
    /** [Argument] 声明类型：string / number / boolean。内核据此把 $argument 注入成对应 JS 类型。 */
    val argumentTypes: Map<String, String> = emptyMap(),
    /** 运行期当前值；只覆盖 $argument，不参与源码字符串展开。 */
    val argumentValues: Map<String, String> = emptyMap(),
    /** 5 段 cron；非空时内核按本地时区调度。 */
    val cron: String = "",
    /** cron / network-changed / generic；空值由 cron 推导。 */
    val trigger: String = "",
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
        if (condition.isNotBlank()) put("condition", condition)
        put("source", source)
        put("arguments", JSONObject(arguments as Map<*, *>))
        if (argumentTypes.isNotEmpty()) put("argumentTypes", JSONObject(argumentTypes as Map<*, *>))
        if (argumentValues.isNotEmpty()) put("argumentValues", JSONObject(argumentValues as Map<*, *>))
        if (cron.isNotBlank()) put("cron", cron)
        if (trigger.isNotBlank()) put("trigger", trigger)
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
            condition = o.optString("condition", ""),
            source = o.optString("source", ""),
            arguments = buildMap {
                o.optJSONObject("arguments")?.let { a ->
                    a.keys().forEach { k -> put(k, a.optString(k, "")) }
                }
            },
            argumentTypes = buildMap {
                o.optJSONObject("argumentTypes")?.let { a ->
                    a.keys().forEach { k -> put(k, a.optString(k, "string")) }
                }
            },
            argumentValues = buildMap {
                o.optJSONObject("argumentValues")?.let { a ->
                    a.keys().forEach { k -> put(k, a.optString(k, "")) }
                }
            },
            cron = o.optString("cron", ""),
            trigger = o.optString("trigger", ""),
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
    /** Surge [Body Rewrite] 原始行：http-request/http-response <url> <regex> <replacement>。 */
    val bodyRewrites: List<String> = emptyList(),
    /** [WebSocket Rewrite] 原始行；南门自有语法，仅 h1 Upgrade 生效。 */
    val wsRewrites: List<String> = emptyList(),
    /** Surge/Loon [Host] 域名映射：值可为 IP、CNAME 别名或 server:上游。 */
    val hostMappings: Map<String, String> = emptyMap(),
    /** 请求/响应脚本；模块导入时下载正文并缓存。 */
    val scripts: List<ScriptConfig> = emptyList(),
    /** 脚本参数运行期覆盖：key = phase|pattern|name，value = 当前参数值。 */
    val scriptArguments: Map<String, Map<String, String>> = emptyMap(),
    /**
     * 按 App MITM：`all` 全部应用 / `allow` 仅 [apps] 内 / `deny` [apps] 内跳过。
     * 银行、支付、证书固定应用放进 deny 即可避免被解密后握手失败。
     */
    val appMode: String = "all",
    /** [appMode] 使用的包名列表；下发内核前解析成 UID。 */
    val apps: List<String> = emptyList(),
    /** 灰度：MITM 上游连接池；默认关闭。 */
    val poolEnabled: Boolean = false,
    /** 池化连接空闲上限（秒）。 */
    val poolIdleSecs: Long = 30,
) {
    val isEmpty: Boolean
        get() = !enabled && hostnames.isEmpty() && skipHostnames.isEmpty() &&
            urlRewrites.isEmpty() && headerRewrites.isEmpty() && loonRewrites.isEmpty() &&
            bodyRewrites.isEmpty() && wsRewrites.isEmpty() && hostMappings.isEmpty() && scripts.isEmpty() &&
            scriptArguments.isEmpty() && apps.isEmpty() && !poolEnabled

    fun toJsonObject(): JSONObject = JSONObject().apply {
        put("enabled", enabled)
        put("hostnames", JSONArray(hostnames))
        put("skipHostnames", JSONArray(skipHostnames))
        put("urlRewrites", JSONArray(urlRewrites))
        put("headerRewrites", JSONArray(headerRewrites))
        put("loonRewrites", JSONArray(loonRewrites))
        put("bodyRewrites", JSONArray(bodyRewrites))
        put("wsRewrites", JSONArray(wsRewrites))
        put("hostMappings", JSONObject(hostMappings as Map<*, *>))
        put("scripts", JSONArray(scripts.map { it.toJsonObject() }))
        put("scriptArguments", JSONObject().apply {
            scriptArguments.forEach { (k, v) -> put(k, JSONObject(v as Map<*, *>)) }
        })
        put("appMode", appMode)
        put("apps", JSONArray(apps))
        put("poolEnabled", poolEnabled)
        put("poolIdleSecs", poolIdleSecs)
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
                bodyRewrites = arr("bodyRewrites"),
                wsRewrites = arr("wsRewrites"),
                hostMappings = buildMap {
                    o.optJSONObject("hostMappings")?.let { h ->
                        h.keys().forEach { k ->
                            val v = h.optString(k, "").trim()
                            if (k.isNotBlank() && v.isNotBlank()) put(k.trim().lowercase(), v)
                        }
                    }
                },
                scripts = o.optJSONArray("scripts")?.let { a ->
                    (0 until a.length()).mapNotNull { i ->
                        a.optJSONObject(i)?.let { ScriptConfig.fromJsonObject(it) }
                    }
                } ?: emptyList(),
                scriptArguments = buildMap {
                    o.optJSONObject("scriptArguments")?.let { all ->
                        all.keys().forEach { k ->
                            val one = all.optJSONObject(k) ?: return@forEach
                            put(k, buildMap {
                                one.keys().forEach { pk -> put(pk, one.optString(pk, "")) }
                            })
                        }
                    }
                },
                appMode = o.optString("appMode", "all").ifBlank { "all" },
                apps = arr("apps"),
                poolEnabled = o.optBoolean("poolEnabled", false),
                poolIdleSecs = o.optLong("poolIdleSecs", 30),
            )
        }
    }
}
