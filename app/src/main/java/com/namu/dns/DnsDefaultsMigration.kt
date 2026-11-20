package com.namu.dns

import android.content.Context
import com.namu.dns.core.repository.SettingsRepository

/**
 * 一次性把「基础配置」里旧的第三方 DNS 默认值换成跟随手机系统。
 *
 * 只处理旧内置默认：阿里 DoH + 223.5.5.5，且没有远端配置/DoH Header/Bootstrap。
 * 用户手动改过 DNS 的配置不会被覆盖。默认配置不是当前 active 时，只改 default.conf。
 */
object DnsDefaultsMigration {
    private const val PREFS = "namu_maintenance"
    private const val KEY = "dns_defaults_migrated_v1"
    private const val LEGACY_UPSTREAM = "https://dns.alidns.com/dns-query"
    private const val LEGACY_FALLBACK = "223.5.5.5"

    fun apply(context: Context, settings: SettingsRepository) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getBoolean(KEY, false)) return

        val active = settings.activeConfigName()
        val current = settings.current()
        if (active == ConfigFileStore.DEFAULT_NAME && isLegacyDefault(current)) {
            settings.update {
                it.copy(dnsUpstream = SystemDns.FOLLOW, dnsFallback = SystemDns.FOLLOW)
            }
        } else if (active != ConfigFileStore.DEFAULT_NAME) {
            val defaultCfg = ConfigFileStore.loadInto(context, ConfigFileStore.DEFAULT_NAME, current)
            if (defaultCfg != null && isLegacyDefault(defaultCfg)) {
                ConfigFileStore.save(
                    context,
                    ConfigFileStore.DEFAULT_NAME,
                    defaultCfg.copy(dnsUpstream = SystemDns.FOLLOW, dnsFallback = SystemDns.FOLLOW),
                )
            }
        }

        // DataStore 被清空时仍会回落到 files/default.json；这里只在它还是旧默认时更新。
        val base = ConfigStore.baseConfigFile(context)
        if (base.exists()) {
            val baseCfg = runCatching { AppConfig.fromJson(base.readText()) }.getOrNull()
            if (baseCfg != null && isLegacyDefault(baseCfg)) {
                ConfigStore.writeAtomicPublic(
                    base,
                    baseCfg.copy(
                        dnsUpstream = SystemDns.FOLLOW,
                        dnsFallback = SystemDns.FOLLOW,
                    ).toJson().toString(2),
                )
            }
        }
        prefs.edit().putBoolean(KEY, true).apply()
    }

    internal fun isLegacyDefault(cfg: AppConfig): Boolean =
        cfg.dnsUpstream.trim() == LEGACY_UPSTREAM &&
            cfg.dnsFallback.trim() == LEGACY_FALLBACK &&
            cfg.dnsBootstrap.isBlank() &&
            cfg.dnsHeaderName.isBlank() &&
            cfg.dnsHeaderValue.isBlank() &&
            cfg.remoteConfigUrl.isBlank() &&
            cfg.remoteConfigName.isBlank()
}
