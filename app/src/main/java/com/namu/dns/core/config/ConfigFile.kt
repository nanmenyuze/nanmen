package com.namu.dns.core.config

import com.namu.dns.SubscriptionInfo
import com.namu.dns.AppConfig
import com.namu.dns.ModuleSource
import com.namu.dns.RuleItem
import com.namu.dns.ProxyGroup
import com.namu.dns.RuleSource
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import org.json.JSONObject

/**
 * 一份可独立切换的配置文件（.conf）。
 *
 * 模型从 v2 起带 `version`；旧 2.x 文件没有 `version` 时按 v1 读取，迁移时升到 v2。
 * 未知根字段保存在 [unknownRoot]，保存时按原 key/JSON 值写回；不因为解析成功就静默丢掉。
 *
 * - general：DNS、隧道、路由、规则更新等标量设置
 * - rules / ruleSources / modules / customAds：该配置自己的规则资产
 * - nodes / selected / subscription 不进入配置文件，始终属于设备侧节点列表
 */
@Serializable
data class ConfigFile(
    @SerialName("version") val modelVersion: Int = 1,
    val general: GeneralConfig = GeneralConfig(),
    val rules: List<RuleItem> = AppConfig.defaultRules(),
    @SerialName("proxyGroups") val proxyGroups: List<ProxyGroup> = emptyList(),
    val ruleSources: List<RuleSource> = emptyList(),
    val modules: List<ModuleSource> = emptyList(),
    val customAds: List<String> = emptyList(),
    val mitm: MitmConfig = MitmConfig(),
    @Transient val unknownRoot: JsonObject = JsonObject(emptyMap()),
    @Transient val sourceFormat: String = SOURCE_NATIVE,
) {
    fun toJson(pretty: Boolean = true): String {
        val base = configJson(pretty = false).encodeToString(this)
        val root = Json.parseToJsonElement(base).jsonObject
        val merged = buildJsonObject {
            root.forEach { (key, value) -> put(key, value) }
            // unknownRoot 只补原生模型没有的 key，绝不能覆盖已知字段。
            unknownRoot.forEach { (key, value) ->
                if (!root.containsKey(key) && key !in KNOWN_ROOT_KEYS) put(key, value)
            }
            put("version", JsonPrimitive(CURRENT_VERSION))
        }
        return if (pretty) configJson(pretty = true).encodeToString(JsonObject.serializer(), merged)
        else merged.toString()
    }

    /**
     * 套到当前设备配置上：只替换配置相关字段，保留 nodes/selected/subscription。
     * unknownRoot 同时转给 AppConfig.configUnknown，供应用内再次保存时保留。
     */
    fun toAppConfig(base: AppConfig = AppConfig()): AppConfig = general.applyTo(base).copy(
        rules = rules,
        proxyGroups = proxyGroups,
        ruleSources = ruleSources,
        moduleSources = modules,
        customAds = customAds,
        mitm = mitm,
        configUnknown = if (unknownRoot.isEmpty()) "" else unknownRoot.toString(),
    )

    companion object {
        const val CURRENT_VERSION = 3
        const val SOURCE_NATIVE = "native-json"
        const val SOURCE_CLASH = "clash-yaml"
        const val SOURCE_LOON = "loon-conf"
        const val SOURCE_SHADOWROCKET = "shadowrocket-conf"

        private val KNOWN_ROOT_KEYS = setOf(
            "version", "general", "rules", "proxyGroups", "ruleSources", "modules", "customAds", "mitm",
            // 设备侧字段不属于配置文件；即使外部文件带进来，也不能写回 .conf。
            "nodes", "selected", "groupSelections", "subscription", "configUnknown",
        )

        /** 判断磁盘文件是否已经是带 general 分区的新格式（不要求 version 已是最新）。 */
        fun isNewFormat(text: String): Boolean = try {
            JSONObject(text).has("general")
        } catch (_: Exception) {
            false
        }

        fun fromAppConfig(cfg: AppConfig): ConfigFile = ConfigFile(
            modelVersion = CURRENT_VERSION,
            general = GeneralConfig.from(cfg),
            rules = cfg.rules,
            proxyGroups = cfg.proxyGroups,
            ruleSources = cfg.ruleSources,
            modules = cfg.moduleSources,
            customAds = cfg.customAds,
            mitm = cfg.mitm,
            unknownRoot = parseUnknown(cfg.configUnknown),
        )

        /**
         * 新格式：{"version":2,"general":{...},"rules":[...],...}
         * 旧格式：AppConfig.toJson() 的扁平 JSON，直接补成 ConfigFile。
         */
        fun fromJson(text: String): ConfigFile = fromExternal(text, AppConfig()) ?: ConfigFile()

        /** 导入外部文件：新格式直接解，旧扁平格式用 fallback 补齐 general；非法返回 null。 */
        fun fromExternal(text: String, fallback: AppConfig): ConfigFile? = try {
            val root = JSONObject(text)
            if (root.has("general")) {
                val decoded = configJson(pretty = false).decodeFromString<ConfigFile>(text)
                // 即使旧 2.x 文件没有 version，decoded 也会落为 1；未知根字段在这里捕获。
                decoded.copy(unknownRoot = extractUnknown(root), sourceFormat = SOURCE_NATIVE)
            } else {
                fromLegacyJson(text, fallback)
            }
        } catch (_: Exception) {
            null
        }

        /**
         * 旧版扁平 JSON → ConfigFile。fallback 提供旧文件缺失的 general 字段，
         * 旧文件已有键覆盖 fallback，避免升级后把用户填过的 DNS/路由重置成默认。
         */
        fun fromLegacyJson(text: String, fallback: AppConfig): ConfigFile {
            val merged = fallback.toJson()
            val old = JSONObject(text)
            val deviceOnly = setOf("nodes", "selected", "groupSelections", "subscription")
            old.keys().forEach { key ->
                if (key !in deviceOnly) merged.put(key, old.get(key))
            }
            val app = AppConfig.fromJson(merged.toString())
            return fromAppConfig(app).copy(
                modelVersion = CURRENT_VERSION,
                unknownRoot = extractUnknown(merged),
                sourceFormat = SOURCE_NATIVE,
            )
        }

        private fun parseUnknown(raw: String): JsonObject = try {
            if (raw.isBlank()) JsonObject(emptyMap()) else Json.parseToJsonElement(raw).jsonObject
        } catch (_: Exception) {
            JsonObject(emptyMap())
        }

        private fun extractUnknown(root: JSONObject): JsonObject = buildJsonObject {
            root.keys().forEach { key ->
                if (key !in KNOWN_ROOT_KEYS) {
                    runCatching { put(key, Json.parseToJsonElement(root.get(key).toString())) }
                        .onFailure { put(key, JsonPrimitive(root.optString(key, ""))) }
                }
            }
        }
    }
}

@Serializable
data class GeneralConfig(
    val mode: String = "dns_only",
    val dnsUpstream: String = "system",
    val dnsFallback: String = "system",
    val dnsBootstrap: String = "",
    val dnsHeaderName: String = "",
    val dnsHeaderValue: String = "",
    val dnsCacheTtl: Int = 600,
    val blockTtl: Int = 60,
    val fallbackFilter: Boolean = true,
    val fallbackGeoCheck: Boolean = false,
    val dnsQueryLog: Boolean = true,
    val remoteConfigUrl: String = "",
    val remoteConfigName: String = "",
    val remoteConfigUpdatedAt: Long = 0L,
    val remoteConfigInterval: Long = 21600_000L,
    val blockEnabled: Boolean = true,
    val blockMode: String = "nxdomain",
    val cnDirect: Boolean = true,
    val finalPolicy: String = "proxy",
    val rulesUrl: String = "",
    val autoUpdateRules: Boolean = true,
    val rulesUpdatedAt: Long = 0L,
    val allowDnsFallback: Boolean = true,
    val blockWhenNoNode: Boolean = true,
    val fakeIp: Boolean = false,
    val blockAaaa: Boolean = false,
    val sniff: Boolean = true,
    val autoSelectNode: Boolean = false,
    val autoClearLogs: Boolean = true,
    val autoDisablePrivateDns: Boolean = false,
    val themeMode: String = "system",
    val autoConnect: Boolean = false,
    val pingMethod: String = "tcp",
    val subscriptionInfo: SubscriptionInfo? = null,
) {
    fun applyTo(base: AppConfig): AppConfig = base.copy(
        mode = mode,
        dnsUpstream = dnsUpstream,
        dnsFallback = dnsFallback,
        dnsBootstrap = dnsBootstrap,
        dnsHeaderName = dnsHeaderName,
        dnsHeaderValue = dnsHeaderValue,
        dnsCacheTtl = dnsCacheTtl,
        blockTtl = blockTtl,
        fallbackFilter = fallbackFilter,
        fallbackGeoCheck = fallbackGeoCheck,
        dnsQueryLog = dnsQueryLog,
        remoteConfigUrl = remoteConfigUrl,
        remoteConfigName = remoteConfigName,
        remoteConfigUpdatedAt = remoteConfigUpdatedAt,
        remoteConfigInterval = remoteConfigInterval,
        blockEnabled = blockEnabled,
        blockMode = blockMode,
        cnDirect = cnDirect,
        finalPolicy = finalPolicy,
        rulesUrl = rulesUrl,
        autoUpdateRules = autoUpdateRules,
        rulesUpdatedAt = rulesUpdatedAt,
        allowDnsFallback = allowDnsFallback,
        blockWhenNoNode = blockWhenNoNode,
        fakeIp = fakeIp,
        blockAaaa = blockAaaa,
        sniff = sniff,
        autoSelectNode = autoSelectNode,
        autoClearLogs = autoClearLogs,
        autoDisablePrivateDns = autoDisablePrivateDns,
        themeMode = themeMode,
        autoConnect = autoConnect,
        pingMethod = pingMethod,
        subscriptionInfo = subscriptionInfo,
    )

    companion object {
        fun from(cfg: AppConfig): GeneralConfig = GeneralConfig(
            mode = cfg.mode,
            dnsUpstream = cfg.dnsUpstream,
            dnsFallback = cfg.dnsFallback,
            dnsBootstrap = cfg.dnsBootstrap,
            dnsHeaderName = cfg.dnsHeaderName,
            dnsHeaderValue = cfg.dnsHeaderValue,
            dnsCacheTtl = cfg.dnsCacheTtl,
            blockTtl = cfg.blockTtl,
            fallbackFilter = cfg.fallbackFilter,
            fallbackGeoCheck = cfg.fallbackGeoCheck,
            dnsQueryLog = cfg.dnsQueryLog,
            remoteConfigUrl = cfg.remoteConfigUrl,
            remoteConfigName = cfg.remoteConfigName,
            remoteConfigUpdatedAt = cfg.remoteConfigUpdatedAt,
            remoteConfigInterval = cfg.remoteConfigInterval,
            blockEnabled = cfg.blockEnabled,
            blockMode = cfg.blockMode,
            cnDirect = cfg.cnDirect,
            finalPolicy = cfg.finalPolicy,
            rulesUrl = cfg.rulesUrl,
            autoUpdateRules = cfg.autoUpdateRules,
            rulesUpdatedAt = cfg.rulesUpdatedAt,
            allowDnsFallback = cfg.allowDnsFallback,
            blockWhenNoNode = cfg.blockWhenNoNode,
            fakeIp = cfg.fakeIp,
            blockAaaa = cfg.blockAaaa,
            sniff = cfg.sniff,
            autoSelectNode = cfg.autoSelectNode,
            autoClearLogs = cfg.autoClearLogs,
            autoDisablePrivateDns = cfg.autoDisablePrivateDns,
            themeMode = cfg.themeMode,
            autoConnect = cfg.autoConnect,
            pingMethod = cfg.pingMethod,
            subscriptionInfo = cfg.subscriptionInfo,
        )
    }
}

private fun configJson(pretty: Boolean): Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    this.prettyPrint = pretty
}
