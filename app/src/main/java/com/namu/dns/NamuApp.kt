package com.namu.dns

import android.app.Application
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class NamuApp : Application() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        CrashGuard.install(this)
        App.init(this)
        AutoConnect.install(this)
        SubscriptionUpdateWorker.schedule(this)
        RuleUpdateWorker.schedule(this)
        NodeTestWorker.schedule(this)
        scope.launch { PrivateDnsController.restore(this@NamuApp) }
    }
}
