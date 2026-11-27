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

/** 远端模块/插件拉取：只更新用户已添加且启用的源；失败保留 good 缓存。 */
class ModuleUpdateWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result = try {
        Actions.syncModules()
        Result.success()
    } catch (_: Exception) {
        Result.retry()
    }

    companion object {
        private const val NAME = "namu_module_update"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<ModuleUpdateWorker>(6, TimeUnit.HOURS)
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
