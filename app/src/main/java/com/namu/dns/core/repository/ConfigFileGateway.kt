package com.namu.dns.core.repository

import android.content.Context
import com.namu.dns.AppConfig
import com.namu.dns.ConfigFileStore

/** 配置文件磁盘访问抽象：仓库只关心“读/写/删/列”，单测可用内存实现。 */
interface ConfigFileGateway {
    fun ensureDefault(cfg: AppConfig)
    fun list(active: String): List<ConfigEntry>
    fun load(name: String, current: AppConfig): AppConfig?
    fun save(name: String, cfg: AppConfig): Boolean
    fun exists(name: String): Boolean
    fun delete(name: String): Boolean
}

class AndroidConfigFileGateway(private val context: Context) : ConfigFileGateway {
    override fun ensureDefault(cfg: AppConfig) = ConfigFileStore.ensureDefault(context, cfg)

    override fun list(active: String): List<ConfigEntry> =
        ConfigFileStore.list(context, active).map {
            ConfigEntry(it.name, it.size, it.modified, it.active, it.isDefault)
        }

    override fun load(name: String, current: AppConfig): AppConfig? =
        ConfigFileStore.loadInto(context, name, current)

    override fun save(name: String, cfg: AppConfig): Boolean =
        ConfigFileStore.save(context, name, cfg)

    override fun exists(name: String): Boolean = ConfigFileStore.exists(context, name)

    override fun delete(name: String): Boolean = ConfigFileStore.delete(context, name)
}
