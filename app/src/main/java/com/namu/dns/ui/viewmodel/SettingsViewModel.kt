package com.namu.dns.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.namu.dns.AppConfig
import com.namu.dns.core.AppContainer
import com.namu.dns.core.repository.SettingsRepository
import com.namu.dns.core.runtime.MessageRepository
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

data class SettingsUiState(
    val config: AppConfig = AppConfig(),
)

class SettingsViewModel(
    private val settings: SettingsRepository,
    private val messages: MessageRepository,
) : ViewModel() {
    val state: StateFlow<SettingsUiState> = settings.config
        .map { SettingsUiState(it) }
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5_000),
            SettingsUiState(settings.current()),
        )

    fun setAutoDisablePrivateDns(enabled: Boolean) {
        settings.update { it.copy(autoDisablePrivateDns = enabled) }
    }

    fun setFinanceProtect(enabled: Boolean) {
        settings.update { it.copy(financeProtect = enabled) }
    }

    fun setThemeMode(mode: String) {
        if (mode != "system" && mode != "light" && mode != "dark") return
        settings.update { it.copy(themeMode = mode) }
    }

    fun setAutoConnect(enabled: Boolean) {
        settings.update { it.copy(autoConnect = enabled) }
    }

    /** U6：SSID 默认关；启用只改本地标志，位置权限由独立入口申请。 */
    fun setSsidEnabled(enabled: Boolean) {
        settings.update { it.copy(ssidTriggerEnabled = enabled) }
    }

    fun setSsidLocationOptIn(optedIn: Boolean) {
        settings.update { it.copy(ssidLocationOptIn = optedIn) }
    }

    fun setSsidNames(text: String) {
        val names = text.split(',', ';', '\n')
            .map { it.trim().trim('"') }
            .filter { it.isNotBlank() && it != "*" }
            .distinct()
        settings.update { it.copy(ssidTriggerNames = names) }
    }

    fun setPingMethod(method: String) {
        if (method != "tcp" && method != "tls") return
        settings.update { it.copy(pingMethod = method) }
    }

    fun showMessage(message: String) = messages.show(message)

    companion object {
        fun factory(container: AppContainer) = viewModelFactory {
            initializer { SettingsViewModel(container.settings, container.messages) }
        }
    }
}
