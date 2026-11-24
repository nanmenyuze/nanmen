package com.namu.dns.core

import android.content.Context
import androidx.compose.runtime.staticCompositionLocalOf
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import com.namu.dns.ConfigFileStore
import com.namu.dns.ConfigStore
import com.namu.dns.DnsDefaultsMigration
import com.namu.dns.MigrationReportStore
import com.namu.dns.NamuVpnService
import com.namu.dns.core.repository.AndroidConfigFileGateway
import com.namu.dns.core.repository.ConfigRepository
import com.namu.dns.core.repository.DataStoreSettingsRepository
import com.namu.dns.core.repository.DefaultConfigRepository
import com.namu.dns.core.repository.DefaultLogRepository
import com.namu.dns.core.repository.DefaultNodeRepository
import com.namu.dns.core.repository.DefaultRuleRepository
import com.namu.dns.core.repository.DefaultHitRepository
import com.namu.dns.core.repository.ProfileMigration
import com.namu.dns.core.repository.DefaultStatsRepository
import com.namu.dns.core.repository.HitRepository
import com.namu.dns.core.repository.LogRepository
import com.namu.dns.core.repository.NodeRepository
import com.namu.dns.core.repository.RuleRepository
import com.namu.dns.core.repository.SettingsRepository
import com.namu.dns.core.repository.StatsRepository
import com.namu.dns.core.runtime.DefaultMessageRepository
import com.namu.dns.core.runtime.DefaultRuntimeRepository
import com.namu.dns.core.runtime.MessageRepository
import com.namu.dns.core.runtime.RuntimeRepository

/**
 * 手动 DI 容器：App 只保留 context + 这个入口。
 * config/settings 来自 DataStore；runtime/stats/logs 全部是 StateFlow。
 */
class AppContainer(val context: Context) {
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val settings: SettingsRepository = DataStoreSettingsRepository(context)
    val config: ConfigRepository = DefaultConfigRepository(
        settings = settings,
        files = AndroidConfigFileGateway(context),
        onApplied = { cfg ->
            ConfigStore.rebuildModules(context, cfg)
            if (NamuVpnService.isRunning()) NamuVpnService.reload(context)
        },
    )
    val nodes: NodeRepository = DefaultNodeRepository(settings)
    val rules: RuleRepository = DefaultRuleRepository(settings)
    val runtime: RuntimeRepository = DefaultRuntimeRepository()
    val messages: MessageRepository = DefaultMessageRepository()
    val stats: StatsRepository = DefaultStatsRepository(runtime)
    val hits: HitRepository = DefaultHitRepository(runtime)
    val logs: LogRepository = DefaultLogRepository(runtime)

    init {
        // 2.2：先迁移旧 .conf，再跑 ensureAssets。ensureAssets 里的 settings.update 会
        // 异步把当前配置写回 active .conf；若顺序反了，旧扁平文件可能先被整体覆盖。
        val migration = ConfigFileStore.migrateLegacy(context, settings.current())
        MigrationReportStore.record(context, migration)
        // S2：把 2.9 的设备全局组选择无损复制进每份 Profile；失败不阻断启动。
        val profileMigration = runCatching { ProfileMigration.apply(context, settings.current()) }.getOrNull()
        // 迁移/恢复完成后，重新把 active .conf 套回内存，避免继续使用迁移前的 DataStore 快照。
        val profileChanged = profileMigration?.changedCount?.let { it > 0 } == true
        if (migration.migrated > 0 || migration.restored > 0 || migration.recovered > 0 || profileChanged) {
            val active = settings.activeConfigName()
            ConfigFileStore.loadInto(context, active, settings.current())?.let { settings.set(it) }
        }
        DnsDefaultsMigration.apply(context, settings)
        ConfigStore.ensureAssets(context, settings)
    }

    /** 服务状态切换后立即补一帧；JNI/JSON 解析始终在 IO，调用方可以在主线程安全触发。 */
    fun refreshRuntime() {
        ioScope.launch {
            stats.poll()
            hits.poll()
            logs.poll()
        }
    }

    fun nodeLabel(): String {
        val cfg = settings.current()
        return cfg.nodes.firstOrNull { it.name == cfg.selected }?.name
            ?: cfg.nodes.firstOrNull()?.name
            ?: "未选择节点"
    }
}

val LocalAppContainer = staticCompositionLocalOf<AppContainer> {
    error("AppContainer 未初始化：应在 NamuApp 中通过 CompositionLocalProvider 提供")
}
