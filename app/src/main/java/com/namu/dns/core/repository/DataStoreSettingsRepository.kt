package com.namu.dns.core.repository

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.namu.dns.Actions
import com.namu.dns.AppConfig
import com.namu.dns.ConfigFileStore
import com.namu.dns.ConfigStore
import com.namu.dns.core.config.ConfigFile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

private val Context.namuSettingsDataStore: DataStore<Preferences> by preferencesDataStore(name = "namu_settings")

private object Keys {
    val CONFIG = stringPreferencesKey("config_json")
    val ASSET_STAMP = intPreferencesKey("assets_stamp")
    val DEFAULT_RULES_V2 = booleanPreferencesKey("default_rules_v2")
    val LEGACY_ADS_MIGRATED = booleanPreferencesKey("legacy_ads_migrated")
    val ACTIVE_CONFIG = stringPreferencesKey("active_config_file")
    val PRIVATE_DNS_PENDING = booleanPreferencesKey("private_dns_pending")
    val PRIVATE_DNS_MODE = stringPreferencesKey("private_dns_mode")
    val PRIVATE_DNS_HOST = stringPreferencesKey("private_dns_host")
    val PROFILE_DEVICE_PREFS = booleanPreferencesKey("profile_device_prefs_migrated")
    val LEGACY_MIGRATED = booleanPreferencesKey("legacy_migrated")
}

class DataStoreSettingsRepository(private val context: Context) : SettingsRepository {
    private val dataStore = context.namuSettingsDataStore
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val writeLock = Mutex()
    private val stateLock = Any()

    private val _config = MutableStateFlow(AppConfig())
    override val config: StateFlow<AppConfig> = _config.asStateFlow()

    private var assetStampCache = -1
    private var defaultRulesMigratedCache = false
    private var legacyAdsMigratedCache = false
    private val _activeProfile = MutableStateFlow(ConfigFileStore.DEFAULT_NAME)
    override val activeProfile = _activeProfile.asStateFlow()
    private var activeConfigCache: String
        get() = _activeProfile.value
        set(value) { _activeProfile.value = value }
    private var privateDnsPendingCache = false
    private var privateDnsModeCache = "opportunistic"
    private var privateDnsHostCache = ""

    init {
        // 只在首次启动读一次磁盘；之后全部走内存 StateFlow + DataStore 异步落盘。
        runBlocking(Dispatchers.IO) {
            migrateLegacyOnce()
            val p = dataStore.data.first()
            assetStampCache = p[Keys.ASSET_STAMP] ?: -1
            defaultRulesMigratedCache = p[Keys.DEFAULT_RULES_V2] ?: false
            legacyAdsMigratedCache = p[Keys.LEGACY_ADS_MIGRATED] ?: false
            activeConfigCache = p[Keys.ACTIVE_CONFIG] ?: ConfigFileStore.DEFAULT_NAME
            privateDnsPendingCache = p[Keys.PRIVATE_DNS_PENDING] ?: false
            privateDnsModeCache = p[Keys.PRIVATE_DNS_MODE] ?: "opportunistic"
            privateDnsHostCache = p[Keys.PRIVATE_DNS_HOST] ?: ""
            val text = p[Keys.CONFIG]
                ?: ConfigStore.baseConfigFile(context).takeIf { it.exists() && it.length() > 0 }?.readText()
                // 首次安装：ensureAssets 还没跑，baseConfigFile 可能不存在。
                // 直接读内置 default.json，避免把资产里的默认策略丢掉。
                ?: runCatching {
                    context.assets.open("default.json").bufferedReader().use { it.readText() }
                }.getOrNull()
            val stored = if (text.isNullOrBlank()) {
                AppConfig.freshDefaults()
            } else {
                runCatching { AppConfig.fromJson(text) }.getOrElse { AppConfig() }
            }
            // 2.x 起 active .conf 才是配置源；旧扁平文件先不用，等 2.2 迁移完成后再切过来。
            val activeText = ConfigFileStore.exportText(context, activeConfigCache)
            val activeProfile = activeText?.takeIf(ConfigFile::isNewFormat)
                ?.let { ConfigFile.fromExternal(it, stored) }
            val base = if (p[Keys.PROFILE_DEVICE_PREFS] == true) stored else {
                activeProfile?.general?.restoreLegacyDevicePreferences(stored) ?: stored
            }
            val loaded = activeProfile?.toAppConfig(base) ?: base
            _config.value = loaded.copy(nodes = Actions.nameSubscriptionNodes(loaded.nodes))
            if (p[Keys.PROFILE_DEVICE_PREFS] != true) {
                dataStore.edit {
                    it[Keys.CONFIG] = base.toJson().toString()
                    it[Keys.PROFILE_DEVICE_PREFS] = true
                }
            }
        }
    }

    override fun applySavedProfile(name: String, config: AppConfig) {
        synchronized(stateLock) {
            activeConfigCache = name
            _config.value = config
            val json = config.toJson().toString()
            scope.launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
                writeLock.withLock {
                    dataStore.edit {
                        it[Keys.ACTIVE_CONFIG] = name
                        it[Keys.CONFIG] = json
                    }
                }
            }
        }
    }

    override fun current(): AppConfig = _config.value

    override fun set(config: AppConfig) {
        synchronized(stateLock) {
            _config.value = config
            persist(config)
        }
    }

    override fun update(transform: (AppConfig) -> AppConfig): AppConfig = synchronized(stateLock) {
        val next = transform(_config.value)
        if (next == _config.value) return@synchronized next
        _config.value = next
        persist(next)
        next
    }

    override fun save() = synchronized(stateLock) { persist(_config.value) }

    override fun restoreSilent(cfg: AppConfig) = synchronized(stateLock) {
        _config.value = cfg
        persist(cfg)
    }

    private fun persist(cfg: AppConfig) {
        val json = cfg.toJson().toString()
        scope.launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
            writeLock.withLock {
                dataStore.edit { it[Keys.CONFIG] = json }
            }
        }
        // 2.5：配置改动只写当前 active .conf，不再刷新全局 default.json。
        // DataStore 里的 CONFIG 仍保存含 nodes 的设备快照，用于启动时兜底合并。
        //
        // 入队时必须同时冻结文件名和配置快照：用户改完 A 立刻切到 B 时，
        // activeConfigCache 已经变成 B；若任务执行时才读 active，会把 A 的内容
        // 写进 B，A 反而保留旧版本。ConfigStore 是单线程队列，冻结后顺序仍可靠。
        val activeSnapshot = activeConfigCache
        ConfigStore.submitFileIo {
            runCatching { ConfigFileStore.save(context, activeSnapshot, cfg) }
        }
    }

    override fun assetStamp(): Int = assetStampCache

    override fun setAssetStamp(stamp: Int) {
        assetStampCache = stamp
        scope.launch { dataStore.edit { it[Keys.ASSET_STAMP] = stamp } }
    }

    override fun defaultRulesMigrated(): Boolean = defaultRulesMigratedCache

    override fun markDefaultRulesMigrated() {
        defaultRulesMigratedCache = true
        scope.launch { dataStore.edit { it[Keys.DEFAULT_RULES_V2] = true } }
    }

    override fun legacyAdsMigrated(): Boolean = legacyAdsMigratedCache

    override fun markLegacyAdsMigrated() {
        legacyAdsMigratedCache = true
        scope.launch { dataStore.edit { it[Keys.LEGACY_ADS_MIGRATED] = true } }
    }

    override fun activeConfigName(): String = activeConfigCache

    override fun setActiveConfigName(name: String) {
        activeConfigCache = name
        scope.launch { dataStore.edit { it[Keys.ACTIVE_CONFIG] = name } }
    }

    override fun privateDnsPending(): Boolean = privateDnsPendingCache
    override fun privateDnsMode(): String = privateDnsModeCache
    override fun privateDnsHost(): String = privateDnsHostCache

    override fun setPrivateDnsSnapshot(mode: String, host: String, pending: Boolean) {
        privateDnsModeCache = mode
        privateDnsHostCache = host
        privateDnsPendingCache = pending
        scope.launch {
            dataStore.edit {
                it[Keys.PRIVATE_DNS_MODE] = mode
                it[Keys.PRIVATE_DNS_HOST] = host
                it[Keys.PRIVATE_DNS_PENDING] = pending
            }
        }
    }

    override fun setPrivateDnsPending(pending: Boolean) {
        privateDnsPendingCache = pending
        scope.launch { dataStore.edit { it[Keys.PRIVATE_DNS_PENDING] = pending } }
    }

    /** 旧 SharedPreferences 一次性迁移；有 marker，重复启动不会覆盖新值。 */
    private suspend fun migrateLegacyOnce() {
        val existing = dataStore.data.first()
        if (existing[Keys.LEGACY_MIGRATED] == true) return

        val legacy = context.getSharedPreferences("namu_prefs", Context.MODE_PRIVATE)
        val legacyPrivate = context.getSharedPreferences("namu_private_dns", Context.MODE_PRIVATE)
        val fallbackConfig = legacy.getString("config_json", null)
            ?: ConfigStore.baseConfigFile(context).takeIf { it.exists() && it.length() > 0 }?.readText()

        dataStore.edit { p ->
            if (p[Keys.CONFIG].isNullOrBlank() && !fallbackConfig.isNullOrBlank()) {
                p[Keys.CONFIG] = fallbackConfig
            }
            if (p[Keys.ASSET_STAMP] == null) {
                p[Keys.ASSET_STAMP] = legacy.getInt("assets_stamp", -1)
            }
            if (p[Keys.DEFAULT_RULES_V2] == null) {
                p[Keys.DEFAULT_RULES_V2] = legacy.getBoolean("default_rules_v2", false)
            }
            if (p[Keys.LEGACY_ADS_MIGRATED] == null) {
                p[Keys.LEGACY_ADS_MIGRATED] = legacy.getBoolean("legacy_ads_migrated", false)
            }
            if (p[Keys.ACTIVE_CONFIG] == null) {
                p[Keys.ACTIVE_CONFIG] = legacy.getString("active_config_file", ConfigFileStore.DEFAULT_NAME)
                    ?: ConfigFileStore.DEFAULT_NAME
            }
            if (p[Keys.PRIVATE_DNS_PENDING] == null) {
                p[Keys.PRIVATE_DNS_PENDING] = legacyPrivate.getBoolean("pending", false)
            }
            if (p[Keys.PRIVATE_DNS_MODE] == null) {
                p[Keys.PRIVATE_DNS_MODE] = legacyPrivate.getString("mode", "opportunistic") ?: "opportunistic"
            }
            if (p[Keys.PRIVATE_DNS_HOST] == null) {
                p[Keys.PRIVATE_DNS_HOST] = legacyPrivate.getString("host", "") ?: ""
            }
            p[Keys.LEGACY_MIGRATED] = true
        }
    }
}
