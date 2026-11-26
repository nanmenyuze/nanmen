package com.namu.dns.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.ApplyCoordinator
import com.namu.dns.Diagnostics
import com.namu.dns.core.LocalAppContainer
import com.namu.dns.core.LocalDockClearance
import com.namu.dns.ui.viewmodel.DataViewModel
import com.namu.dns.ui.viewmodel.MitmViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Composable
fun DiagnosticsScreen(
    onOpenRuntimeLogs: () -> Unit,
) {
    val container = LocalAppContainer.current
    val vm: DataViewModel = viewModel(factory = DataViewModel.factory(container))
    val state by vm.state.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val mitmVm: MitmViewModel = viewModel(factory = MitmViewModel.factory(container, ctx))
    val mitmBusy by mitmVm.busy.collectAsStateWithLifecycle()
    var showClearLogs by remember { mutableStateOf(false) }

    val cfg = state.config
    LaunchedEffect(Unit) { mitmVm.refresh() }

    DetailList {
        SectionHeader("内核实际状态")
        GroupCard {
            val kernelLines = ApplyCoordinator.kernelStateSummary(LocalContext.current)
            kernelLines.forEachIndexed { i, line ->
                SettingsRow(line, showDivider = i != kernelLines.lastIndex)
            }
        }
        SectionHeader("日志与导出")
        GroupCard {
            SettingsRow(
                title = "运行日志",
                subtitle = "内核、规则匹配与连接记录",
                value = "${state.logs.runtime.size} 条",
                chevron = true,
                onClick = onOpenRuntimeLogs,
            )
            SettingsRow(
                title = "连接前清空日志",
                subtitle = "每次连接前清空上一次的运行日志与 DNS 记录",
                rightContent = {
                    IosSwitch(
                        checked = cfg.autoClearLogs,
                        onCheckedChange = { vm.setAutoClearLogs(it) },
                    )
                },
            )
            SettingsRow(
                title = "清空当前日志",
                subtitle = "清空当前运行日志与 DNS 记录，不影响命中历史",
                chevron = true,
                onClick = { showClearLogs = true },
            )
            SettingsRow(
                title = "导出诊断报告",
                subtitle = "日志、内核版本、运行时长、请求数、缓存命中率、DNS 延迟分布和内存统计",
                chevron = true,
                onClick = {
                    scope.launch {
                        try {
                            val where = Diagnostics.export(ctx)
                            vm.showMessage("诊断报告已导出：$where")
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            vm.showMessage(e.message ?: "导出诊断报告失败")
                        }
                    }
                },
            )
            SettingsRow(
                title = "导出证书安装日志",
                subtitle = "开机安装与证书核验记录",
                value = if (mitmBusy) "处理中…" else null,
                chevron = true,
                showDivider = false,
                onClick = { mitmVm.exportInjectionLog() },
            )
        }

        Spacer(Modifier.height(LocalDockClearance.current + 30.dp))
    }

    if (showClearLogs) {
        NamuDialog(
            title = "清空日志？",
            message = "将清空当前运行日志与 DNS 记录；命中历史与统计不受影响。",
            confirmText = "清空",
            confirmColor = NamuColors.Red,
            onConfirm = {
                vm.clearLogsNow()
                showClearLogs = false
            },
            onDismiss = { showClearLogs = false },
        ) {}
    }
}
