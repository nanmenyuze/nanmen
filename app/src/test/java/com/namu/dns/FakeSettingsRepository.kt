package com.namu.dns

import com.namu.dns.core.repository.SettingsRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** JVM 测试用的内存设置仓库，行为与 DataStore 版保持一致。 */
class FakeSettingsRepository(initial: AppConfig = AppConfig()) : SettingsRepository {
    private val _config = MutableStateFlow(initial)
    override val config: StateFlow<AppConfig> = _config.asStateFlow()

    private var stamp = -1
    private var defaultMigrated = false
    private var adsMigrated = false
    private val _activeProfile = MutableStateFlow("default.conf")
    override val activeProfile = _activeProfile
    private var active: String
        get() = _activeProfile.value
        set(value) { _activeProfile.value = value }
    private var pending = false
    private var mode = "opportunistic"
    private var host = ""

    override fun current(): AppConfig = _config.value

    override fun set(config: AppConfig) {
        _config.value = config
    }

    override fun update(transform: (AppConfig) -> AppConfig): AppConfig {
        val next = transform(_config.value)
        _config.value = next
        return next
    }

    override fun save() = Unit

    override fun assetStamp(): Int = stamp

    override fun setAssetStamp(stamp: Int) {
        this.stamp = stamp
    }

    override fun defaultRulesMigrated(): Boolean = defaultMigrated

    override fun markDefaultRulesMigrated() {
        defaultMigrated = true
    }

    override fun legacyAdsMigrated(): Boolean = adsMigrated

    override fun markLegacyAdsMigrated() {
        adsMigrated = true
    }

    override fun activeConfigName(): String = active

    override fun setActiveConfigName(name: String) {
        active = name
    }

    override fun privateDnsPending(): Boolean = pending

    override fun privateDnsMode(): String = mode

    override fun privateDnsHost(): String = host

    override fun setPrivateDnsSnapshot(mode: String, host: String, pending: Boolean) {
        this.mode = mode
        this.host = host
        this.pending = pending
    }

    override fun setPrivateDnsPending(pending: Boolean) {
        this.pending = pending
    }
}
