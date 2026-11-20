package com.namu.dns

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * 生成 KernelSU/Magisk「系统信任模块」：开机早期（Zygote 启动前）把本 App 的 MITM CA
 * 合并进系统证书库（Android 14+ 为 Conscrypt APEX），重启后仍生效。
 *
 * 模块是自包含的：证书烤进 certs/<subject_hash_old>.0，不依赖 App 私有目录。
 * 模块由 KernelSU/Magisk 在开机早期挂载，所有 App 直接继承，且重启不丢。
 */
object TrustModuleGenerator {

    const val MODULE_ID = "namu_mitm_ca"
    const val MODULE_FILE = "namu_mitm_ca_module.zip"

    private const val CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
    private const val CERT_END = "-----END CERTIFICATE-----"

    data class Result(val ok: Boolean, val path: String = "", val error: String = "")

    /** 纯逻辑：把模块文件写入 zip 流（无 Android 依赖，可 JVM 单测）。 */
    fun buildModuleZip(caPem: ByteArray, systemName: String, out: OutputStream) {
        val certificate = certificateOnlyPem(String(caPem, Charsets.UTF_8))
            ?: throw IllegalArgumentException("PEM 证书缺少 CERTIFICATE 段")
        ZipOutputStream(out).use { z ->
            fun entry(name: String, bytes: ByteArray) {
                z.putNextEntry(ZipEntry(name))
                z.write(bytes)
                z.closeEntry()
            }
            entry("module.prop", MODULE_PROP.toByteArray())
            entry("customize.sh", customizeScript().toByteArray())
            entry("post-fs-data.sh", postFsData(systemName).toByteArray())
            entry("service.sh", serviceScript(systemName).toByteArray())
            entry("uninstall.sh", uninstallScript().toByteArray())
            // 只放证书段：ca.pem 同时含私钥，不能把私钥带进系统信任库/模块目录。
            entry("certs/$systemName", certificate.toByteArray())
            entry("README.md", readme(systemName).toByteArray())
        }
    }

    /** 生成模块 zip 到公共下载目录（29+ 用 MediaStore，无需存储权限）。 */
    suspend fun generate(context: Context, pemPath: String, systemName: String): Result =
        withContext(Dispatchers.IO) {
            try {
                if (!systemName.matches(Regex("[0-9a-f]{8}\\.0"))) {
                    return@withContext Result(false, error = "证书文件名非法: $systemName")
                }
                val pem = File(pemPath).readText()
                if (certificateOnlyPem(pem) == null) {
                    return@withContext Result(false, error = "PEM 证书无效，请重新导出")
                }
                val bytes = buildModuleBytes(pem.toByteArray(), systemName)
                val fileName = MODULE_FILE
                if (Build.VERSION.SDK_INT >= 29) {
                    val values = ContentValues().apply {
                        put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                        put(MediaStore.MediaColumns.MIME_TYPE, "application/zip")
                        put(MediaStore.MediaColumns.RELATIVE_PATH, "Download/NamuDNS")
                    }
                    val uri = context.contentResolver.insert(
                        MediaStore.Downloads.EXTERNAL_CONTENT_URI, values,
                    ) ?: return@withContext Result(false, error = "无法在下载目录创建文件")
                    context.contentResolver.openOutputStream(uri)?.use { out ->
                        out.write(bytes)
                    } ?: return@withContext Result(false, error = "写入下载目录失败")
                    Result(true, path = "下载/NamuDNS/$fileName")
                } else {
                    val dir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                        ?: return@withContext Result(false, error = "无外部存储目录")
                    val file = File(dir, fileName)
                    file.writeBytes(bytes)
                    Result(true, path = file.absolutePath)
                }
            } catch (e: Exception) {
                Result(false, error = e.message ?: "生成失败")
            }
        }

    /** 单元测试用：在内存里构建完整模块 zip。 */
    internal fun buildModuleBytes(pem: ByteArray, systemName: String): ByteArray {
        val out = ByteArrayOutputStream()
        buildModuleZip(pem, systemName, out)
        return out.toByteArray()
    }

    /**
     * 从 ca.pem 中抽出证书段。系统信任库只需要证书；私钥不能进入模块目录。
     * 返回带标准 PEM 头尾的证书文本，找不到则返回 null。
     */
    internal fun certificateOnlyPem(pem: String): String? {
        val start = pem.indexOf(CERT_BEGIN)
        if (start < 0) return null
        val end = pem.indexOf(CERT_END, start)
        if (end < 0) return null
        return pem.substring(start, end + CERT_END.length).trimEnd() + "\n"
    }

    private fun customizeScript() = """#!/system/bin/sh
# KernelSU 使用 MODPATH，Magisk 使用 MODPATH；兼容旧变量 MODDIR。
MODDIR="${'$'}{MODPATH:-${'$'}{MODDIR:-.}}"
SKIPUNZIP=0
set_perm_recursive "${'$'}MODDIR" 0 0 0755 0644
set_perm "${'$'}MODDIR/post-fs-data.sh" 0 0 0755
set_perm "${'$'}MODDIR/service.sh" 0 0 0755
set_perm "${'$'}MODDIR/uninstall.sh" 0 0 0755
"""

    private const val MODULE_PROP = """id=namu_mitm_ca
name=Namu MITM CA (System Trust)
version=v1.0
versionCode=1
author=NamuDNS
description=开机早期将 Namu MITM CA 合并进系统证书库（Android 14+ Conscrypt APEX），所有 App 信任，重启不丢。由 NamuDNS 生成。
"""

    private fun postFsData(name: String) = """#!/system/bin/sh
# Namu MITM CA — 开机早期合并系统证书库（Zygote 启动前）。
# 采用 tmpfs 叠加，不修改只读分区；模块卸载/重启后自动消失，无系统残留。
MODDIR=${'$'}{0%/*}
LOG=/data/adb/namu_mitm_ca.log
STATUS=/data/adb/namu_mitm_ca.status
exec >>"${'$'}LOG" 2>&1
echo "=== ${'$'}(date) post-fs-data start ==="
NAME=$name
APEX=/apex/com.android.conscrypt/cacerts
LEGACY=/system/etc/security/cacerts
SRC="${'$'}MODDIR/certs/${'$'}NAME"
: > "${'$'}STATUS"
if [ ! -f "${'$'}SRC" ]; then
  echo "ERROR: 模块内无证书 ${'$'}SRC"
  echo "ERROR: module cert missing" >> "${'$'}STATUS"
  exit 0
fi
inject() {
  TARGET="${'$'}1"
  [ -d "${'$'}TARGET" ] || { echo "skip: ${'$'}TARGET 不存在"; return 1; }
  TMP=/data/adb/namu_cacerts_tmp
  rm -rf "${'$'}TMP"
  mkdir -p -m 700 "${'$'}TMP" || return 1
  cp "${'$'}TARGET"/* "${'$'}TMP"/ 2>/dev/null
  cp "${'$'}SRC" "${'$'}TMP/${'$'}NAME" || { rm -rf "${'$'}TMP"; return 1; }
  # 直接叠加 tmpfs；不要卸载已有的系统/APEX 挂载，避免破坏其他模块和系统。
  if ! /system/bin/mount -t tmpfs tmpfs "${'$'}TARGET"; then
    echo "ERROR mount ${'$'}TARGET"
    echo "ERROR: mount ${'$'}TARGET" >> "${'$'}STATUS"
    rm -rf "${'$'}TMP"
    return 1
  fi
  cp "${'$'}TMP"/* "${'$'}TARGET"/ || { echo "ERROR copy ${'$'}TARGET"; return 1; }
  chown root:root "${'$'}TARGET"/* 2>/dev/null
  chmod 644 "${'$'}TARGET"/* 2>/dev/null
  chcon u:object_r:system_file:s0 "${'$'}TARGET"/* 2>/dev/null
  rm -rf "${'$'}TMP"
  echo "OK: 注入 ${'$'}TARGET （${'$'}(ls "${'$'}TARGET" | wc -l) 证书，含 ${'$'}NAME）"
  echo "OK: ${'$'}TARGET" >> "${'$'}STATUS"
  return 0
}
# APEX 在 Android 14+ 通常已挂载；最多等 2 秒，避免阻塞 post-fs-data 超时。
i=0
while [ ! -d "${'$'}APEX" ] && [ "${'$'}i" -lt 4 ]; do sleep 0.5; i=${'$'}((i+1)); done
if [ -d "${'$'}APEX" ]; then
  inject "${'$'}APEX"
else
  inject "${'$'}LEGACY"
fi
echo "=== post-fs-data done ==="
"""

    private fun serviceScript(name: String) = """#!/system/bin/sh
# late_start：校验；若 post-fs-data 因 APEX 时序没挂上，兜底重挂并绑定到 Zygote 命名空间。
MODDIR=${'$'}{0%/*}
LOG=/data/adb/namu_mitm_ca.log
STATUS=/data/adb/namu_mitm_ca.status
exec >>"${'$'}LOG" 2>&1
echo "=== ${'$'}(date) service check ==="
NAME=$name
APEX=/apex/com.android.conscrypt/cacerts
LEGACY=/system/etc/security/cacerts
SRC="${'$'}MODDIR/certs/${'$'}NAME"
check() { [ -f "${'$'}1/${'$'}NAME" ] && echo "present: ${'$'}1/${'$'}NAME" || echo "MISSING: ${'$'}1/${'$'}NAME"; }
check "${'$'}APEX"
check "${'$'}LEGACY"
if [ -f "${'$'}SRC" ] && [ ! -f "${'$'}APEX/${'$'}NAME" ] && [ -d "${'$'}APEX" ]; then
  echo "fallback: 重新合并 APEX"
  TMP=/data/adb/namu_cacerts_tmp2
  rm -rf "${'$'}TMP"
  mkdir -p -m 700 "${'$'}TMP" || exit 1
  cp "${'$'}APEX"/* "${'$'}TMP"/ 2>/dev/null
  cp "${'$'}SRC" "${'$'}TMP/${'$'}NAME" || exit 1
  if /system/bin/mount -t tmpfs tmpfs "${'$'}APEX"; then
    cp "${'$'}TMP"/* "${'$'}APEX"/
    chown root:root "${'$'}APEX"/* 2>/dev/null
    chmod 644 "${'$'}APEX"/* 2>/dev/null
    chcon u:object_r:system_file:s0 "${'$'}APEX"/* 2>/dev/null
    for Z in ${'$'}(pidof zygote) ${'$'}(pidof zygote64); do
      [ -n "${'$'}Z" ] || continue
      nsenter --mount=/proc/${'$'}Z/ns/mnt -- /system/bin/mount --bind "${'$'}TMP" "${'$'}APEX" 2>/dev/null \
        && echo "nsenter ok: ${'$'}Z" || echo "nsenter fail: ${'$'}Z"
    done
    echo "OK: fallback APEX" >> "${'$'}STATUS"
  else
    echo "ERROR: fallback mount APEX" >> "${'$'}STATUS"
  fi
fi
check "${'$'}APEX"
echo "=== service done ==="
"""

    private fun uninstallScript() = """#!/system/bin/sh
rm -rf /data/adb/namu_cacerts_tmp /data/adb/namu_cacerts_tmp2
rm -f /data/adb/namu_mitm_ca.status /data/adb/namu_mitm_ca.log
"""

    private fun readme(name: String) = """# Namu MITM CA 系统信任模块

由 NamuDNS 生成，内含本机 MITM CA 的证书段（certs/$name，不含私钥）。

## 安装
KernelSU → 模块 → 从存储安装 → 选本 zip → 重启。
Magisk → 模块 → 从本地安装 → 重启。

## 验证
- 重启后打开 NamuDNS → MITM 去广告，系统证书区应显示「已检测到」。
- 或执行：su -c cat /data/adb/namu_mitm_ca.log
  应看到 "OK: 注入 /apex/com.android.conscrypt/cacerts ... 含 $name"。
- 若浏览器仍提示证书不受信任：强制停止浏览器再打开；仍不行则说明该浏览器未使用系统信任库或有证书固定。

## 卸载
在 KernelSU/Magisk 中移除本模块并重启；tmpfs 注入会随重启消失，无系统残留。
"""
}
