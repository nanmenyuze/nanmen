package com.namu.dns

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/** 规则/远端配置更新从 Activity 生命周期解耦，界面销毁后仍按周期执行。 */
class RuleUpdateWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result = try {
        Actions.autoUpdateRulesIfDue()
        Result.success()
    } catch (_: Exception) {
        Result.retry()
    }

    companion object {
        private const val NAME = "namu_rule_update"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<RuleUpdateWorker>(6, TimeUnit.HOURS)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build(),
                )
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request,
            )
        }
    }
}

/** 自动选择节点：WorkManager 最小周期 15 分钟；只在开关打开时真正测速。 */
class NodeTestWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result = try {
        if (runCatching { App.container.settings.current().autoSelectNode }.getOrDefault(false)) {
            Actions.autoTestNodes()
        }
        Result.success()
    } catch (_: Exception) {
        Result.retry()
    }

    companion object {
        private const val NAME = "namu_node_test"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<NodeTestWorker>(15, TimeUnit.MINUTES)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build(),
                )
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request,
            )
        }
    }
}
