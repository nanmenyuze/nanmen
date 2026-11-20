package com.namu.dns

import android.content.Context
import android.provider.Settings

/**
 * Root 设备上的私人 DNS 临时接管。
 *
 * Android 的 Private DNS（DoT）会绕过 VpnService 的 53 端口，DNS 规则就永远命中不了。
 * 这里只在用户显式开启时，把全局 private_dns_mode 临时设为 off，断开 VPN 后恢复原值。
 * 所有命令都是固定字符串，不拼接用户输入。
 */
object PrivateDnsController {

    fun hasRoot(): Boolean = Regex("""\buid=0\b""").containsMatchIn(suResult("id").output)

    fun currentMode(context: Context): String =
        Settings.Global.getString(context.contentResolver, "private_dns_mode") ?: "off"

    fun specifier(context: Context): String =
        Settings.Global.getString(context.contentResolver, "private_dns_specifier") ?: ""

    fun bypassing(context: Context): Boolean = currentMode(context) != "off"

    /** 返回 true 表示已成功关闭；失败时不会留下 pending 状态。 */
    fun disable(context: Context): Boolean {
        val cr = context.contentResolver
        val mode = Settings.Global.getString(cr, "private_dns_mode") ?: "opportunistic"
        val host = Settings.Global.getString(cr, "private_dns_specifier") ?: ""
        val settings = App.container.settings
        settings.setPrivateDnsSnapshot(mode, host, pending = true)
        val ok = su("settings put global private_dns_mode off") == 0
        if (!ok) settings.setPrivateDnsPending(false)
        return ok
    }

    /**
     * 恢复全局 Private DNS。只有恢复命令真正成功才清 pending；
     * 失败时保留 pending，下次启动/覆盖安装继续重试，避免全局设置永久停在 off。
     */
    fun restore(context: Context) {
        val settings = App.container.settings
        if (!settings.privateDnsPending()) return
        val mode = settings.privateDnsMode()
            .takeIf { it == "off" || it == "opportunistic" || it == "hostname" }
            ?: "opportunistic"
        var ok = su("settings put global private_dns_mode $mode") == 0
        if (mode == "hostname") {
            val host = settings.privateDnsHost()
            if (host.isNotBlank() && host.all { it.isLetterOrDigit() || it == '.' || it == '-' }) {
                ok = su("settings put global private_dns_specifier $host") == 0 && ok
            }
        }
        if (ok) settings.setPrivateDnsPending(false)
    }

    private data class SuResult(val exitCode: Int, val output: String)

    private fun suResult(command: String): SuResult = try {
        val result = ProcessRunner.run(listOf("su", "-c", command), timeoutMs = 5_000)
        SuResult(result.exitCode, result.output)
    } catch (_: Exception) {
        SuResult(-1, "")
    }

    private fun su(command: String): Int = suResult(command).exitCode
}
