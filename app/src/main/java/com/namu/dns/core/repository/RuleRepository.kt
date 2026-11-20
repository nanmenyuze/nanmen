package com.namu.dns.core.repository

import com.namu.dns.Actions
import com.namu.dns.AppConfig
import com.namu.dns.RuleItem

interface RuleRepository {
    fun rules(): List<RuleItem>
    fun add(rule: RuleItem)
    fun remove(rule: RuleItem)
    fun update(config: (AppConfig) -> AppConfig): AppConfig
    suspend fun updateAdsRules(url: String): Int
    suspend fun autoUpdateIfDue(): Boolean
}

class DefaultRuleRepository(
    private val settings: SettingsRepository,
) : RuleRepository {
    override fun rules(): List<RuleItem> = settings.current().rules

    override fun add(rule: RuleItem) {
        settings.update { it.copy(rules = it.rules + rule) }
    }

    override fun remove(rule: RuleItem) {
        settings.update { it.copy(rules = it.rules.filterNot { existing -> existing == rule }) }
    }

    override fun update(config: (AppConfig) -> AppConfig): AppConfig = settings.update(config)

    override suspend fun updateAdsRules(url: String): Int = Actions.updateAdsRules(url)

    override suspend fun autoUpdateIfDue(): Boolean = Actions.autoUpdateRulesIfDue()
}
