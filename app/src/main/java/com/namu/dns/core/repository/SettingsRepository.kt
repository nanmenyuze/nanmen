package com.namu.dns.core.repository

import com.namu.dns.AppConfig
import kotlinx.coroutines.flow.StateFlow

/**
 * 设置仓库：DataStore 是唯一持久化来源，内存 StateFlow 供 UI/Service 同步读取。
 * 旧的 SharedPreferences 只在首次启动迁移时读取一次。
 */
interface SettingsRepository {
    val config: StateFlow<AppConfig>

    fun current(): AppConfig
    fun set(config: AppConfig)
    fun update(transform: (AppConfig) -> AppConfig): AppConfig
    fun save()

    fun assetStamp(): Int
    fun setAssetStamp(stamp: Int)
    fun defaultRulesMigrated(): Boolean
    fun markDefaultRulesMigrated()
    fun legacyAdsMigrated(): Boolean
    fun markLegacyAdsMigrated()

    fun activeConfigName(): String
    fun setActiveConfigName(name: String)

    fun privateDnsPending(): Boolean
    fun privateDnsMode(): String
    fun privateDnsHost(): String
    fun setPrivateDnsSnapshot(mode: String, host: String, pending: Boolean)
    fun setPrivateDnsPending(pending: Boolean)
}
