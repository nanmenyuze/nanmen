package com.namu.dns

import android.annotation.SuppressLint
import android.content.Context
import com.namu.dns.core.AppContainer

/**
 * 只保留应用 context 与 DI 容器入口；所有可变状态已迁移到
 * SettingsRepository / RuntimeRepository / StatsRepository / LogRepository。
 */
@SuppressLint("StaticFieldLeak")
object App {
    lateinit var context: Context
        private set

    lateinit var container: AppContainer
        private set

    fun init(context: Context) {
        if (::container.isInitialized) return
        this.context = context.applicationContext
        this.container = AppContainer(this.context)
        UiPrefs.init(this.context)
    }
}
