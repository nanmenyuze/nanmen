package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.namu.dns.ui.viewmodel.MitmViewModel
import com.namu.dns.ConfigStore
import com.namu.dns.MitmManager
import com.namu.dns.core.LocalAppContainer
import org.json.JSONObject

/**
 * MITM 去广告设置页：总开关、CA 生成与系统信任模块、手动域名/跳过列表、模块规则与运行数据。
 *
 * 规则主要来自模块的 [MITM] / [URL Rewrite] / [Header Rewrite]；这里管理全局开关、
 * 证书与手动补充的域名。启用后内核按 URL 正则拒绝或改写响应体，握手失败自动放行。
 */
@Composable
fun MitmScreen() {
    val container = LocalAppContainer.current
    val cfg by container.settings.config.collectAsStateWithLifecycle()
    val statsState by container.stats.state.collectAsStateWithLifecycle()
    val stats = statsState.stats
    val ctx = LocalContext.current
    val vm: MitmViewModel = viewModel(factory = MitmViewModel.factory(container, ctx))
    val busy by vm.busy.collectAsStateWithLifecycle()
    val caExists by vm.caExists.collectAsStateWithLifecycle()
    val caFingerprint by vm.caFingerprint.collectAsStateWithLifecycle()
    val systemCertInstalled by vm.systemCertInstalled.collectAsStateWithLifecycle()
    val mitm = cfg.mitm
    var showHosts by remember { mutableStateOf(false) }
    var showSkip by remember { mutableStateOf(false) }
    var hostsText by remember { mutableStateOf("") }
    var skipText by remember { mutableStateOf("") }

    // 从模块安装/文件管理器返回时重新核对，避免状态停在“未检测到”。
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        vm.refresh()
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) vm.refresh()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // 启用模块合并出的 MITM 域名 + 两类重写规则总数，每行算一条。
    val moduleMitmCount = remember(mitm, cfg.moduleSources) {
        runCatching {
            val o = JSONObject(ConfigStore.moduleMitmFile(ctx).readText())
            (o.optJSONArray("hostnames")?.length() ?: 0) +
                (o.optJSONArray("urlRewrites")?.length() ?: 0) +
                (o.optJSONArray("headerRewrites")?.length() ?: 0)
        }.getOrDefault(0)
    }

    Column(
        Modifier.fillMaxSize().background(NamuColors.Bg).verticalScroll(rememberScrollState()),
    ) {
        SectionHeader("MITM 去广告")
        GroupCard {
            SettingsRow(
                title = "启用 MITM",
                subtitle = "解密命中域名列表的 HTTPS：按 URL 拒绝广告请求、正则改写响应体",
                icon = Icons.Rounded.Security,
                rightContent = {
                    IosSwitch(
                        checked = mitm.enabled,
                        onCheckedChange = { on -> vm.setEnabled(on) },
                    )
                },
            )
            SettingsRow(
                title = "CA 证书",
                value = if (caExists) "已生成" else "未生成",
                subtitle = "首次导出时自动生成并长期复用；卸载应用前请先移除已安装证书",
                showDivider = true,
            )
            SettingsRow(
                title = "CA SHA-256 指纹",
                subtitle = caFingerprint ?: "生成 CA 后显示；安装时请与系统证书详情的指纹核对",
                showDivider = true,
            )
            SettingsRow(
                title = "系统证书区（模块）",
                value = when {
                    !caExists -> "未生成"
                    systemCertInstalled -> "已检测到"
                    else -> "未检测到"
                },
                subtitle = "装好系统信任模块并重启后，按 DER 比对 APEX 证书目录；模块方式重启不丢",
                showDivider = false,
            )
        }

        SectionHeader("证书安装")
        GroupCard {
            SettingsRow(
                title = "生成系统信任模块（KernelSU/Magisk）",
                subtitle = "生成含本机 CA 的模块 zip 到「下载/NamuDNS」，用 KernelSU/Magisk 安装后重启，全 App 信任、重启不丢",
                icon = Icons.Rounded.Shield,
                value = if (busy) "处理中…" else null,
                chevron = true,
                onClick = { vm.generateTrustModule() },
            )
            SettingsRow(
                title = "仅导出证书文件",
                subtitle = "PEM + DER 存到应用私有目录 mitm/export，可自行处理",
                icon = Icons.Rounded.Download,
                chevron = true,
                showDivider = false,
                onClick = { vm.exportOnly() },
            )
        }

        SectionHeader("域名与规则")
        GroupCard {
            SettingsRow(
                title = "手动 MITM 域名",
                value = "${mitm.hostnames.size} 个",
                subtitle = "逗号分隔，支持 *.example.com（含主域与全部子域）",
                chevron = true,
                onClick = {
                    hostsText = mitm.hostnames.joinToString(", ")
                    showHosts = true
                },
            )
            SettingsRow(
                title = "跳过域名（永不 MITM）",
                value = "${mitm.skipHostnames.size} 个",
                subtitle = "银行、支付等敏感应用建议加入跳过列表",
                chevron = true,
                onClick = {
                    skipText = mitm.skipHostnames.joinToString(", ")
                    showSkip = true
                },
            )
            SettingsRow(
                title = "模块 MITM 规则",
                value = "$moduleMitmCount 条",
                subtitle = "「策略 → 模块」导入含 [MITM]/[URL Rewrite]/[Header Rewrite] 的模块后自动合并去重",
                showDivider = false,
            )
        }

        SectionHeader("运行数据")
        GroupCard {
            SettingsRow("解密连接", value = stats.mitmConns.toString())
            SettingsRow("拒绝广告请求", value = stats.mitmRejected.toString())
            SettingsRow("改写响应体", value = stats.mitmRewritten.toString())
            SettingsRow(
                "握手失败自动放行",
                value = stats.mitmFailed.toString(),
                subtitle = "证书绑定等场景：域名临时放行 5 分钟，不会断网",
            )
            SettingsRow(
                "QUIC 拦截回落 TCP",
                value = stats.mitmQuicBlocked.toString(),
                subtitle = "UDP 443 的 QUIC 被丢弃后，应用会自动改用 HTTPS/TCP 走 MITM",
                showDivider = false,
            )
        }

        FooterText(
            "MITM 只处理 HTTP/1.1 over TLS；只支持 h2 且不回落的少数应用会自动放行。" +
                "请仅在自己的设备上使用；银行/支付类应用建议加入跳过列表，或直接关闭 MITM。",
        )
        Spacer(Modifier.height(30.dp))
    }

    if (showHosts) {
        NamuDialog(
            title = "手动 MITM 域名",
            message = "逗号/换行分隔。*.example.com 匹配主域与全部子域；裸域名只精确匹配。",
            confirmText = "保存",
            onDismiss = { showHosts = false },
            onConfirm = {
                val list = MitmManager.parseHostList(hostsText)
                showHosts = false
                vm.saveHostnames(list)
            },
        ) {
            NamuTextField(hostsText, { hostsText = it }, "*.example.com, api.foo.cn")
        }
    }
    if (showSkip) {
        NamuDialog(
            title = "跳过域名",
            message = "这些域名永不做 MITM，始终透明转发。",
            confirmText = "保存",
            onDismiss = { showSkip = false },
            onConfirm = {
                val list = MitmManager.parseHostList(skipText)
                showSkip = false
                vm.saveSkip(list)
            },
        ) {
            NamuTextField(skipText, { skipText = it }, "*.bank.example.com")
        }
    }
}
