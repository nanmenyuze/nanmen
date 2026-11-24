package com.namu.dns

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.runtime.mutableStateOf

/**
 * UI 级偏好（B2 节点排序 / B4 首启引导）：
 * 用 snapshot state 暴露，变更自动触发重组；持久化到独立 SharedPreferences，
 * 不进配置文件（与小火箭一致：排序/引导属于界面偏好，不属于 .conf）。
 */
object UiPrefs {
    private lateinit var sp: SharedPreferences
    private val nodeSortState = mutableStateOf("default")
    private val onboardingDoneState = mutableStateOf(false)
    private val vpnGuideDoneState = mutableStateOf(false)

    val nodeSort: String get() = nodeSortState.value
    val onboardingDone: Boolean get() = onboardingDoneState.value
    val vpnGuideDone: Boolean get() = vpnGuideDoneState.value

    fun init(context: Context) {
        if (::sp.isInitialized) return
        sp = context.getSharedPreferences("namu_ui", Context.MODE_PRIVATE)
        nodeSortState.value = sp.getString("node_sort", "default") ?: "default"
        onboardingDoneState.value = sp.getBoolean("onboarding_done", false)
        vpnGuideDoneState.value = sp.getBoolean("vpn_guide_done", false)
    }

    fun setNodeSort(mode: String) {
        nodeSortState.value = mode
        sp.edit().putString("node_sort", mode).apply()
    }

    fun setVpnGuideDone(done: Boolean) {
        vpnGuideDoneState.value = done
        sp.edit().putBoolean("vpn_guide_done", done).apply()
    }

    fun setOnboardingDone(done: Boolean) {
        onboardingDoneState.value = done
        sp.edit().putBoolean("onboarding_done", done).apply()
    }
}
