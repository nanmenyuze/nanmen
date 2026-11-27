package com.namu.dns

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Clash `rule-providers` / `RULE-SET` 的壳层实现。
 *
 * 内核只负责识别声明和规则引用（`rule_providers` + 类型为 RULE-SET 的 RuleConf），
 * 真正的下载、条件缓存与展开放在壳层：网络请求、重定向和鉴权头处理已经在
 * [Actions.fetchTextResult] 里统一做过，避免内核 JNI 同步调用里再做一套。
 *
 * 语义约定：
 * - `behavior: domain` 的每条按后缀匹配（Clash 的 domain provider 是后缀集合）；
 * - `behavior: ipcidr` 展开为 IP-CIDR / IP-CIDR6；
 * - `behavior: classical` 按普通规则行解析，支持行内策略与 no-resolve；
 * - 引用行的 `no-resolve` 会覆盖整份 provider 展开出的 IP 规则。
 */
object ClashRuleSets {
    data class ProviderDef(
        val name: String,
        val type: String,
        val url: String,
        val behavior: String,
        val path: String,
        val interval: Long,
    )

    data class ProviderStatus(
        val name: String,
        /** fresh / cached / pending / missing / unsupported */
        val state: String,
        val rules: Int,
        val message: String,
    )

    data class Expansion(
        val rules: List<RuleItem>,
        val statuses: List<ProviderStatus>,
        val warnings: List<String>,
    ) {
        val pending: List<ProviderStatus> get() = statuses.filter { it.state == "pending" || it.state == "missing" || it.state == "unsupported" }
    }

    data class CachedProvider(
        val text: String,
        val etag: String = "",
        val lastModified: String = "",
        val updatedAt: Long = 0L,
    )

    interface Cache {
        fun read(url: String): CachedProvider?
        fun write(url: String, text: String, etag: String, lastModified: String)
        fun touch(url: String) {}
    }

    class FileCache(private val context: Context) : Cache {
        private fun file(url: String): File {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(url.toByteArray()).joinToString("") { "%02x".format(it) }.take(24)
            return File(File(context.filesDir, "rule_providers"), "provider_$digest.txt")
        }

        private fun meta(url: String): File = File(file(url).path + ".json")

        override fun read(url: String): CachedProvider? {
            val f = file(url)
            if (!f.exists() || f.length() == 0L) return null
            val o = runCatching { JSONObject(meta(url).readText()) }.getOrNull()
            return CachedProvider(
                text = runCatching { f.readText() }.getOrNull() ?: return null,
                etag = o?.optString("etag", "").orEmpty(),
                lastModified = o?.optString("lastModified", "").orEmpty(),
                updatedAt = o?.optLong("updatedAt", 0L) ?: 0L,
            )
        }

        override fun write(url: String, text: String, etag: String, lastModified: String) {
            val f = file(url)
            f.parentFile?.mkdirs()
            ConfigStore.writeAtomicPublic(f, text)
            ConfigStore.writeAtomicPublic(
                meta(url),
                JSONObject().apply {
                    put("url", url)
                    put("etag", etag)
                    put("lastModified", lastModified)
                    put("updatedAt", System.currentTimeMillis())
                }.toString(),
            )
        }
    }

    fun parseProviderDefs(arr: JSONArray?): List<ProviderDef> {
        if (arr == null) return emptyList()
        val out = mutableListOf<ProviderDef>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val name = o.optString("name").trim()
            if (name.isBlank()) continue
            out += ProviderDef(
                name = name,
                type = o.optString("kind", o.optString("type", "http")).trim().lowercase(),
                url = o.optString("url").trim(),
                behavior = o.optString("behavior", "classical").trim().lowercase(),
                path = o.optString("path").trim(),
                interval = o.optLong("interval", 86_400L),
            )
        }
        return out
    }

    /** 纯展开：测试直接喂内存缓存和固定正文，不依赖 Android。 */
    suspend fun expand(
        rules: List<RuleItem>,
        defs: List<ProviderDef>,
        cache: Cache,
        fetcher: suspend (url: String, headers: Map<String, String>) -> Actions.FetchResult,
    ): Expansion {
        val out = mutableListOf<RuleItem>()
        val statuses = mutableListOf<ProviderStatus>()
        val warnings = mutableListOf<String>()
        val byName = defs.associateBy { it.name }
        val resolved = HashMap<String, Pair<List<RuleItem>, ProviderStatus>>()

        suspend fun load(name: String): Pair<List<RuleItem>, ProviderStatus> {
            resolved[name]?.let { return it }
            val def = byName[name]
            if (def == null) {
                warnings += "规则集 $name 未在 rule-providers 中声明，相关 RULE-SET 规则已跳过"
                return (emptyList<RuleItem>() to ProviderStatus(name, "missing", 0, "未声明 rule-providers"))
                    .also { resolved[name] = it }
            }
            if (def.behavior !in setOf("domain", "ipcidr", "classical")) {
                warnings += "规则集 $name 的 behavior=${def.behavior} 不支持，相关规则已跳过"
                return (emptyList<RuleItem>() to ProviderStatus(name, "unsupported", 0, "behavior=${def.behavior} 不支持"))
                    .also { resolved[name] = it }
            }
            if (def.url.isBlank()) {
                val why = if (def.type == "file") {
                    "file 类型规则集需要设备本地文件，当前只支持 http(s) 远程地址"
                } else {
                    "缺少 url"
                }
                warnings += "规则集 $name 无法加载：$why"
                return (emptyList<RuleItem>() to ProviderStatus(name, "pending", 0, why))
                    .also { resolved[name] = it }
            }
            val cached = cache.read(def.url)
            val headers = buildMap {
                if (cached != null && cached.etag.isNotBlank()) put("If-None-Match", cached.etag)
                if (cached != null && cached.lastModified.isNotBlank()) put("If-Modified-Since", cached.lastModified)
            }
            val fetched = runCatching { fetcher(def.url, headers) }
            val status: ProviderStatus
            val text: String?
            if (fetched.isSuccess) {
                val result = fetched.getOrThrow()
                if (result.status == 304 && cached != null) {
                    text = cached.text
                    cache.touch(def.url)
                    status = ProviderStatus(name, "cached", 0, "304，继续使用本地缓存")
                } else {
                    text = result.text
                    runCatching {
                        cache.write(
                            def.url,
                            result.text,
                            result.headers["etag"].orEmpty(),
                            result.headers["last-modified"].orEmpty(),
                        )
                    }.onFailure {
                        warnings += "规则集 $name 已下载但缓存写入失败：${it.message}"
                    }
                    status = ProviderStatus(name, "fresh", 0, "已下载 ${result.text.length} 字节")
                }
            } else {
                val error = fetched.exceptionOrNull()?.message ?: "下载失败"
                text = cached?.text
                status = if (text != null) {
                    warnings += "规则集 $name 更新失败，继续使用上一份缓存：$error"
                    ProviderStatus(name, "cached", 0, "更新失败，使用上一份缓存：$error")
                } else {
                    warnings += "规则集 $name 首次加载失败且无缓存：$error"
                    ProviderStatus(name, "pending", 0, "无缓存，等待下载：$error")
                }
            }
            val expanded = if (text == null) emptyList() else {
                expandPayload(def, text, "规则集 ${def.name}")
            }
            return (expanded to status.copy(rules = expanded.size)).also { resolved[name] = it }
        }


        for (rule in rules) {
            if (rule.type == "RULE-SET" || rule.type == "DOMAIN-SET") {
                val (items, status) = load(rule.value)
                statuses += status
                out += items.map {
                    it.copy(
                        action = rule.action,
                        noResolve = rule.noResolve || it.noResolve,
                        extendedMatch = rule.extendedMatch,
                        preMatch = rule.preMatch && rule.action == "block",
                    )
                }
            } else {
                out += rule
            }
        }
        return Expansion(out, statuses.distinctBy { it.name }, warnings)
    }

    fun expandPayload(def: ProviderDef, content: String, source: String): List<RuleItem> {
        if (content.isBlank()) return emptyList()
        return when (def.behavior) {
            "domain" -> parseDomainProvider(content, source)
            "ipcidr" -> parseIpProvider(content, source)
            else -> RuleSetExpander.expandDetailed("RULE-SET", content, "proxy", source).items
        }
    }

    private fun parseDomainProvider(content: String, source: String): List<RuleItem> {
        val out = mutableListOf<RuleItem>()
        for (line in payloadEntries(content)) {
            if (line.any { it.isWhitespace() }) continue
            when {
                line.startsWith("*.") -> out += RuleItem("DOMAIN-WILDCARD", line, "proxy", source)
                line.startsWith("+.") -> out += RuleItem("DOMAIN-SUFFIX", line.removePrefix("+."), "proxy", source)
                line.startsWith(".") -> out += RuleItem("DOMAIN-SUFFIX", line.removePrefix("."), "proxy", source)
                else -> out += RuleItem("DOMAIN-SUFFIX", line, "proxy", source)
            }
        }
        return out
    }

    private fun parseIpProvider(content: String, source: String): List<RuleItem> {
        val out = mutableListOf<RuleItem>()
        for (line in payloadEntries(content)) {
            val cidr = if (line.contains('/')) line else {
                if (line.contains(':')) "$line/128" else "$line/32"
            }
            val type = if (cidr.contains(':')) "IP-CIDR6" else "IP-CIDR"
            val prefix = cidr.substringAfterLast('/').toIntOrNull() ?: continue
            if (prefix < 0 || prefix > if (type == "IP-CIDR6") 128 else 32) continue
            out += RuleItem(type, cidr, "proxy", source)
        }
        return out
    }

    /**
     * Clash provider 正文有两种载体：纯行列表，或 `payload:` + `- 'x'` 的 YAML 列表。
     * 这里不引入 YAML 依赖，只按行剥掉列表标记和引号；真正的规则行交给
     * [RuleSetExpander] 的 Clash-YAML 分支处理。
     */
    internal fun payloadEntries(content: String): List<String> {
        val yamlList = content.lineSequence().any { it.trim().startsWith("payload:") }
        return content.lineSequence().mapNotNull { raw ->
            val t = raw.trim()
            if (t.isEmpty() || t.startsWith("#") || t.startsWith("//") || t.startsWith(";")) return@mapNotNull null
            val value = if (yamlList) {
                if (!t.startsWith("- ")) return@mapNotNull null
                t.removePrefix("- ").trim()
            } else t
            value.trim('"').trim('\'').trim().takeIf { it.isNotEmpty() }
        }.toList()
    }
}
