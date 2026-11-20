package com.namu.dns

import android.content.Context
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.Locale

/**
 * MITM 证书管理：导出、系统信任模块生成（KernelSU/Magisk，需 Root）。
 *
 * 定位 Root 增强工具：MITM 系统级信任只走开机早期运行的 KernelSU/Magisk 信任模块；
 * 模块把证书合并进 Android 14+ 的 Conscrypt APEX 证书目录或旧版系统目录，
 * 重启后仍生效，所有 App 继承同一份信任库。
 */
object MitmManager {

    fun caFile(context: Context): File = File(File(context.filesDir, "mitm"), "ca.pem")

    fun exportDir(context: Context): File = File(File(context.filesDir, "mitm"), "export")

    /** 读取当前 CA 的 DER；用于指纹核对和系统证书区比对。 */
    fun caDer(context: Context): ByteArray? {
        val pem = runCatching { caFile(context).readText() }.getOrNull() ?: return null
        val body = pem.substringAfter("-----BEGIN CERTIFICATE-----", "")
            .substringBefore("-----END CERTIFICATE-----")
        if (body.isBlank()) return null
        return runCatching {
            Base64.decode(body.filterNot { it.isWhitespace() }, Base64.DEFAULT)
        }.getOrNull()
    }

    /** 当前 CA 的 SHA-256 指纹，格式 AA:BB:...，用于和系统证书详情逐段核对。 */
    fun caFingerprint(context: Context): String? {
        val der = caDer(context) ?: return null
        val digest = MessageDigest.getInstance("SHA-256").digest(der)
        return digest.joinToString(":") { String.format(Locale.US, "%02X", it.toInt() and 0xff) }
    }

    data class ExportResult(
        val ok: Boolean,
        val pemPath: String = "",
        val derPath: String = "",
        val systemName: String = "",
        val error: String = "",
    )

    /** 生成/加载 CA 并导出 PEM + DER；未连接 VPN 也可用。 */
    suspend fun export(context: Context): ExportResult = withContext(Dispatchers.IO) {
        if (!NativeCore.available) {
            return@withContext ExportResult(false, error = "内核加载失败（native 库缺失）")
        }
        try {
            val json = JSONObject(
                NativeCore.nativeMitmExportCa(caFile(context).absolutePath, exportDir(context).absolutePath),
            )
            if (json.optBoolean("ok")) {
                ExportResult(
                    true,
                    json.optString("pem"),
                    json.optString("der"),
                    json.optString("system_name"),
                )
            } else {
                ExportResult(false, error = json.optString("error", "导出失败"))
            }
        } catch (e: Exception) {
            ExportResult(false, error = e.message ?: "导出失败")
        }
    }

    /** 系统证书区是否已装好当前这张 CA；按 DER 比对，避免文件名存在但仍是旧证书。 */
    fun systemCertInstalled(context: Context, systemName: String): Boolean {
        if (systemName.isBlank()) return false
        val expected = caDer(context) ?: return false
        val apex = File("/apex/com.android.conscrypt/cacerts")
        // Android 14+ Conscrypt 实际读 APEX 目录；APEX 存在时不能拿旧版目录的结果冒充成功。
        val dir = if (apex.isDirectory) apex else File("/system/etc/security/cacerts")
        val file = File(dir, systemName)
        return file.isFile && systemCertDerMatches(file, expected)
    }

    private fun systemCertDerMatches(file: File, expected: ByteArray): Boolean {
        val raw = runCatching { file.readBytes() }.getOrNull() ?: return false
        val text = String(raw, Charsets.UTF_8)
        if (!text.trimStart().startsWith("-----BEGIN CERTIFICATE-----")) {
            return raw.contentEquals(expected)
        }
        val body = text.substringAfter("-----BEGIN CERTIFICATE-----", "")
            .substringBefore("-----END CERTIFICATE-----")
            .trim()
        val der = runCatching {
            Base64.decode(body.filterNot { it.isWhitespace() }, Base64.DEFAULT)
        }.getOrNull() ?: return false
        return der.contentEquals(expected)
    }

    /** 解析用户输入的域名列表：逗号/换行/空格分隔，去重、小写、校验。 */
    fun parseHostList(text: String): List<String> {
        return text.split(',', '\n', ' ', ';')
            .map { it.trim().trimEnd('.').lowercase() }
            .filter { it.isNotEmpty() }
            .filter { p ->
                val body = p.removePrefix("*.")
                body.isNotEmpty() && body.length <= 253 && body.contains('.') &&
                    !body.contains('*') &&
                    body.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' || it == '.' }
            }
            .distinct()
    }
}
