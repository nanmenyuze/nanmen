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

class SubscriptionUpdateWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val cfg = runCatching { App.container.settings.current() }.getOrNull() ?: return Result.success()
        if (Actions.subscriptionSourceRows(cfg).none { it.enabled && it.url.isNotBlank() }) {
            return Result.success()
        }
        return try {
            val outcomes = Actions.refreshAllSubscriptions()
            for (o in outcomes) {
                if (!o.ok || o.nodes == 0) {
                    android.util.Log.w("NamuSubscription", "${o.name}: ${o.message}")
                }
            }
            // 全部来源都没有成功且存在网络类失败时交给 WorkManager 重试；
            // 单个来源失败不影响其他来源的结果。
            if (outcomes.isNotEmpty() && outcomes.none { it.ok }) Result.retry() else Result.success()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            Result.retry()
        }
    }

    companion object {
        private const val NAME = "namu_subscription_update"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<SubscriptionUpdateWorker>(6, TimeUnit.HOURS)
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
