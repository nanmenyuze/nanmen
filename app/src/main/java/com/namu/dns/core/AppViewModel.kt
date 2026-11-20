package com.namu.dns.core

import android.app.Application
import androidx.lifecycle.AndroidViewModel

/**
 * 外壳级 ViewModel：只做容器入口，不创建第二个容器。
 * 容器由 Application 的 App.init() 建立，Activity 重建时仍复用同一份
 * Settings/Runtime/Stats/Log StateFlow，避免 UI 与服务各看一份状态。
 */
class AppViewModel(application: Application) : AndroidViewModel(application) {
    val container: AppContainer get() = com.namu.dns.App.container
}
