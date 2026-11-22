package com.namu.dns

import android.content.ContentUris
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
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * 生成 KernelSU/Magisk/APatch「系统信任模块」：开机早期把本 App 的 MITM CA
 * 合并进系统证书库（Android 14+ 为 Conscrypt APEX），重启后仍生效。
 *
 * 模块是自包含的：证书烤进 certs/<subject_hash_old>.0，不依赖 App 私有目录。
 * 注入采用「常驻 staging 目录 + bind 整目录」，可幂等重复执行；卸载只移除
 * source 等于我们 staging 的挂载层，不碰 APEX 自身或别人的模块。
 */
object TrustModuleGenerator {

    const val MODULE_ID = "namu_mitm_ca"
    const val MODULE_FILE = "namu_mitm_ca_module.zip"

    private const val CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
    private const val CERT_END = "-----END CERTIFICATE-----"
    private val SYSTEM_NAME = Regex("[0-9a-f]{8}\\.0")

    data class Result(
        val ok: Boolean,
        val path: String = "",
        val error: String = "",
        val fileName: String = "",
        val fingerprint: String = "",
    )

    /** 纯逻辑：把模块文件写入 zip 流（无 Android 依赖，可 JVM 单测）。 */
    fun buildModuleZip(caPem: ByteArray, systemName: String, out: OutputStream) {
        require(SYSTEM_NAME.matches(systemName)) { "证书文件名非法: $systemName" }
        val certificate = certificateOnlyPem(String(caPem, Charsets.UTF_8))
            ?: throw IllegalArgumentException("PEM 证书缺少 CERTIFICATE 段")
        ZipOutputStream(out).use { z ->
            moduleEntries(certificate, systemName).forEach { (name, bytes) ->
                z.putNextEntry(ZipEntry(name))
                z.write(bytes)
                z.closeEntry()
            }
        }
    }

    /** 模块 zip 名带 CA 指纹前 8 位，避免不同 CA 的模块互相覆盖。 */
    internal fun moduleZipFileName(systemName: String): String {
        val prefix = systemName.substringBefore('.').lowercase(Locale.US)
            .filter { it in '0'..'9' || it in 'a'..'f' }
        return "namu_mitm_ca_${prefix.ifBlank { "unknown" }}.zip"
    }

    /** 生成模块 zip 到公共下载目录（29+ 用 MediaStore，无需存储权限）。 */
    suspend fun generate(context: Context, pemPath: String, systemName: String): Result =
        withContext(Dispatchers.IO) {
            try {
                if (!SYSTEM_NAME.matches(systemName)) {
                    return@withContext Result(false, error = "证书文件名非法: $systemName")
                }
                val pem = File(pemPath).readText()
                if (certificateOnlyPem(pem) == null) {
                    return@withContext Result(false, error = "PEM 证书无效，请重新导出")
                }
                val bytes = buildModuleBytes(pem.toByteArray(), systemName)
                val fileName = moduleZipFileName(systemName)
                if (Build.VERSION.SDK_INT >= 29) {
                    deleteExistingDownload(context, fileName)
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
                    Result(
                        true,
                        path = "下载/NamuDNS/$fileName",
                        fileName = fileName,
                        fingerprint = systemName.substring(0, 8),
                    )
                } else {
                    val dir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                        ?: return@withContext Result(false, error = "无外部存储目录")
                    val file = File(dir, fileName)
                    if (file.exists()) file.delete()
                    file.writeBytes(bytes)
                    Result(
                        true,
                        path = file.absolutePath,
                        fileName = fileName,
                        fingerprint = systemName.substring(0, 8),
                    )
                }
            } catch (e: Exception) {
                Result(false, error = e.message ?: "生成失败")
            }
        }

    /** 把模块文件写到 App 私有暂存目录，供 Root 侧整目录复制。 */
    internal fun writeModuleFiles(dir: File, caPem: String, systemName: String) {
        require(SYSTEM_NAME.matches(systemName)) { "证书文件名非法: $systemName" }
        val certificate = certificateOnlyPem(caPem)
            ?: throw IllegalArgumentException("PEM 证书缺少 CERTIFICATE 段")
        dir.deleteRecursively()
        dir.mkdirs()
        moduleEntries(certificate, systemName).forEach { (name, bytes) ->
            val f = File(dir, name)
            f.parentFile?.mkdirs()
            f.writeBytes(bytes)
            if (name.endsWith(".sh")) f.setExecutable(true, false)
        }
    }

    /** 仅写出卸载脚本，供「移除系统 CA」使用；不依赖 CA 是否存在。 */
    internal fun writeRemovalHelpers(dir: File) {
        dir.mkdirs()
        listOf("remove.sh", "unmount.sh").forEach { name ->
            val f = File(dir, name)
            f.writeText(renderScript(if (name == "remove.sh") removeScript() else unmountScript()))
            f.setExecutable(true, false)
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

    private fun deleteExistingDownload(context: Context, fileName: String) {
        runCatching {
            val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
            val projection = arrayOf(MediaStore.MediaColumns._ID)
            context.contentResolver.query(
                collection,
                projection,
                "${MediaStore.MediaColumns.DISPLAY_NAME}=?",
                arrayOf(fileName),
                null,
            )?.use { c ->
                val idCol = c.getColumnIndexOrThrow(MediaStore.MediaColumns._ID)
                while (c.moveToNext()) {
                    context.contentResolver.delete(
                        ContentUris.withAppendedId(collection, c.getLong(idCol)),
                        null,
                        null,
                    )
                }
            }
        }
    }

    private fun renderScript(script: String): String =
        script.trimStart().trimEnd() + "\n"

    private fun moduleEntries(certificate: String, systemName: String): List<Pair<String, ByteArray>> =
        listOf(
            "module.prop" to moduleProp().toByteArray(),
            "customize.sh" to renderScript(customizeScript()).toByteArray(),
            "post-fs-data.sh" to renderScript(postFsDataScript()).toByteArray(),
            "service.sh" to renderScript(serviceScript()).toByteArray(),
            "uninstall.sh" to renderScript(uninstallScript()).toByteArray(),
            "inject.sh" to renderScript(injectScript(systemName)).toByteArray(),
            "bind.sh" to renderScript(bindScript()).toByteArray(),
            "unmount.sh" to renderScript(unmountScript()).toByteArray(),
            "remove.sh" to renderScript(removeScript()).toByteArray(),
            // 只放证书段：ca.pem 同时含私钥，不能把私钥带进系统信任库/模块目录。
            "certs/$systemName" to certificate.toByteArray(),
            "README.md" to readme(systemName).toByteArray(),
        )

    private fun moduleProp() = """id=namu_mitm_ca
name=Namu MITM CA (System Trust)
version=v2.8
versionCode=208
author=NamuDNS
description=开机早期把 Namu MITM CA 合并进系统证书库（Android 14+ Conscrypt APEX），所有 App 信任；支持一键注入与无残留卸载。由 NamuDNS 生成。
"""

    private fun customizeScript() = """
        #!/system/bin/sh
        # KernelSU 与 Magisk 都提供 MODPATH；旧实现兼容 MODDIR。
        MODDIR=${'$'}{MODPATH:-${'$'}{MODDIR:-.}}
        SKIPUNZIP=0
        chown -R 0:0 "${'$'}MODDIR" 2>/dev/null
        find "${'$'}MODDIR" -type d -exec chmod 0755 {} \;
        find "${'$'}MODDIR" -type f -exec chmod 0644 {} \;
        for F in "${'$'}MODDIR"/*.sh; do
          [ -f "${'$'}F" ] && chmod 0755 "${'$'}F"
        done
    """.trimIndent()

    private fun postFsDataScript() = """
        #!/system/bin/sh
        # Zygote 启动前执行：先建常驻 staging，再 bind 到 APEX/legacy 证书库。
        MODDIR=${'$'}{0%/*}
        [ -x "${'$'}MODDIR/inject.sh" ] || chmod 0755 "${'$'}MODDIR/inject.sh"
        sh "${'$'}MODDIR/inject.sh" --boot
    """.trimIndent()

    private fun serviceScript() = """
        #!/system/bin/sh
        # late_start 兜底：APEX 时序未就绪时重试，并给已启动的 Zygote 命名空间补 bind。
        MODDIR=${'$'}{0%/*}
        i=0
        while [ "${'$'}i" -lt 3 ]; do
          if sh "${'$'}MODDIR/inject.sh" --late; then exit 0; fi
          i=${'$'}((i+1))
          sleep 1
        done
        exit 1
    """.trimIndent()

    private fun uninstallScript() = """
        #!/system/bin/sh
        MODDIR=${'$'}{0%/*}
        sh "${'$'}MODDIR/remove.sh"
    """.trimIndent()

    /**
     * 注入主脚本。所有路径都是常量；证书名由生成器写入并已通过 [0-9a-f]{8}\.0 校验。
     * bind 前先 cmp：目标里已有同一张证书就跳过，因此 post-fs-data/service/手动
     * 一键安装可以反复执行而不会叠加挂载层。
     */
    private fun injectScript(name: String): String {
        val template = """
            #!/system/bin/sh
            MODDIR=§{0%/*}
            STATE=__STATE__
            STAGING=§STATE/cacerts_staging
            STATUS=§STATE/status
            LOG=§STATE/inject.log
            NAME=__CERT_NAME__
            SRC="§MODDIR/certs/§NAME"
            APEX=__APEX__
            LEGACY=__LEGACY__
            mkdir -p "§STATE" 2>/dev/null
            if [ -f "§LOG" ] && [ "§(wc -c < "§LOG")" -gt 65536 ]; then
              tail -c 32768 "§LOG" > "§LOG.tmp" 2>/dev/null && mv -f "§LOG.tmp" "§LOG"
            fi
            exec >>"§LOG" 2>&1
            echo "=== §(date) inject start (§1) ==="
            write_status() {
              ST="§1"; shift
              {
                echo "state=§ST"
                for L in "§@"; do echo "§L"; done
                echo "done=1"
              } > "§STATUS.tmp.§§"
              mv -f "§STATUS.tmp.§§" "§STATUS"
            }
            fail() {
              echo "ERROR: §1"
              write_status error "cert=§NAME" "error=§1"
              exit 1
            }
            [ -f "§SRC" ] || fail "模块内证书缺失: §SRC"
            cp -f "§MODDIR/unmount.sh" "§STATE/unmount.sh" 2>/dev/null
            cp -f "§MODDIR/bind.sh" "§STATE/bind.sh" 2>/dev/null
            chmod 0755 "§STATE/unmount.sh" "§STATE/bind.sh" 2>/dev/null
            if [ -d "§APEX" ] && [ -n "§(ls -A "§APEX" 2>/dev/null)" ]; then
              TARGET="§APEX"
            else
              TARGET="§LEGACY"
            fi
            [ -d "§TARGET" ] || fail "系统证书目录不存在: §TARGET"
            command -v nsenter >/dev/null 2>&1 || fail "nsenter 不可用，无法注入 Zygote"

            unmount_all() {
              sh "§STATE/unmount.sh" || return 1
              SEEN=" "
              for P in 1 §(pidof zygote) §(pidof zygote64); do
                [ -n "§P" ] || continue
                case " §SEEN " in *" §P "*) continue ;; esac
                SEEN="§SEEN§P "
                nsenter -t "§P" -m -- /system/bin/sh "§STATE/unmount.sh" || return 1
              done
            }

            # CA 更新/首次安装：先卸掉自家旧层，再重建整库 staging。
            if [ -f "§STAGING/§NAME" ] && cmp -s "§STAGING/§NAME" "§SRC"; then
              echo "staging 已就绪，复用"
            else
              echo "重建 staging"
              unmount_all || fail "旧挂载层卸载失败，未重建 staging"
              rm -rf "§STAGING"
              mkdir -p "§STAGING" || fail "无法创建 staging"
              cp -R "§TARGET"/. "§STAGING"/ 2>/dev/null
              cp -f "§SRC" "§STAGING/§NAME" || fail "复制证书到 staging 失败"
              chown -R 0:0 "§STAGING" 2>/dev/null
              find "§STAGING" -type d -exec chmod 0755 {} \; 2>/dev/null
              find "§STAGING" -type f -exec chmod 0644 {} \; 2>/dev/null
              if command -v chcon >/dev/null 2>&1; then
                chcon -R u:object_r:system_file:s0 "§STAGING" 2>/dev/null
              fi
            fi

            BOUND=0
            bind_here() {
              if sh "§STATE/bind.sh" "§STAGING" "§TARGET" "§NAME"; then
                BOUND=§((BOUND+1))
              else
                echo "WARN: bind 失败: §1"
              fi
            }
            bind_here self
            SEEN=" "
            for P in 1 §(pidof zygote) §(pidof zygote64); do
              [ -n "§P" ] || continue
              case " §SEEN " in *" §P "*) continue ;; esac
              SEEN="§SEEN§P "
              if nsenter -t "§P" -m -- /system/bin/sh "§STATE/bind.sh" "§STAGING" "§TARGET" "§NAME"; then
                BOUND=§((BOUND+1))
                echo "bind ok: pid §P"
              else
                echo "WARN: bind fail pid §P"
              fi
            done

            CONFLICT=0
            top_source() {
              awk -v T="§TARGET" '§2==T { S=§1 } END { if (S!="") print S }' /proc/self/mounts
            }
            TOP="§(top_source)"
            if [ -n "§TOP" ] && [ "§TOP" != "§STAGING" ]; then
              CONFLICT=1
              echo "WARN: 目标最上层不是我们的 staging: §TOP"
            fi

            if [ "§BOUND" -le 0 ]; then
              fail "没有成功 bind 任何命名空间"
            fi
            write_status ok "cert=§NAME" "target=§TARGET" "bound=§BOUND" "conflict=§CONFLICT"
            echo "=== inject done: §TARGET, bound=§BOUND, conflict=§CONFLICT ==="
            exit 0
        """.trimIndent()
        return template
            .replace("__STATE__", RootCaManager.STATE_DIR)
            .replace("__APEX__", "/apex/com.android.conscrypt/cacerts")
            .replace("__LEGACY__", "/system/etc/security/cacerts")
            .replace("__CERT_NAME__", name)
            .replace('§', '$')
    }

    private fun bindScript() = """
        #!/system/bin/sh
        STAGING="§1"
        TARGET="§2"
        NAME="§3"
        [ -d "§TARGET" ] || exit 3
        [ -f "§STAGING/§NAME" ] || exit 4
        # 幂等：目标里已有同一张证书，说明本命名空间已 bind 过，直接跳过。
        if [ -f "§TARGET/§NAME" ] && cmp -s "§STAGING/§NAME" "§TARGET/§NAME"; then
          exit 0
        fi
        /system/bin/mount --bind "§STAGING" "§TARGET" || exit 5
        cmp -s "§STAGING/§NAME" "§TARGET/§NAME" || exit 6
        exit 0
    """.trimIndent().replace('§', '$')

    /**
     * 只卸载 source == 我们 staging 的层；逐层卸到无残留为止。
     * 完全不碰 source 不符的挂载（APEX 自身、其他模块、系统分区）。
     */
    private fun unmountScript() = """
        #!/system/bin/sh
        STAGING="__STAGING__"
        i=0
        while [ "§i" -lt 8 ]; do
          FOUND=0
          while read -r SRC MNT REST; do
            [ "§SRC" = "§STAGING" ] || continue
            FOUND=1
            /system/bin/umount "§MNT" 2>/dev/null || /system/bin/umount -l "§MNT" 2>/dev/null
          done < /proc/self/mounts
          [ "§FOUND" -eq 0 ] && exit 0
          i=§((i+1))
        done
        exit 1
    """.trimIndent()
        .replace("__STAGING__", RootCaManager.STAGING_DIR)
        .replace('§', '$')

    private fun removeScript() = """
        #!/system/bin/sh
        MODDIR=__MODULE__
        STATE=__STATE__
        STAGING=__STAGING__
        HELPER="§MODDIR/unmount.sh"
        [ -f "§HELPER" ] || HELPER="§STATE/unmount.sh"
        [ -f "§HELPER" ] || HELPER=/data/local/tmp/namu_ca_unmount.sh
        [ -f "§HELPER" ] || { echo "ERROR: 找不到 unmount 脚本，未删除模块"; exit 31; }
        echo "=== remove mounts ==="
        sh "§HELPER" || { echo "ERROR: 当前命名空间卸载失败"; exit 32; }
        SEEN=" "
        for P in 1 §(pidof zygote) §(pidof zygote64); do
          [ -n "§P" ] || continue
          case " §SEEN " in *" §P "*) continue ;; esac
          SEEN="§SEEN§P "
          nsenter -t "§P" -m -- /system/bin/sh "§HELPER" || { echo "ERROR: pid §P 卸载失败"; exit 33; }
        done
        echo "=== cleanup files ==="
        rm -rf "§MODDIR" "§STATE"
        rm -f /data/adb/namu_mitm_ca.status /data/adb/namu_mitm_ca.log
        rm -f /data/local/tmp/namu_ca_remove.sh /data/local/tmp/namu_ca_unmount.sh
        echo "=== remove done ==="
        exit 0
    """.trimIndent()
        .replace("__MODULE__", RootCaManager.MODULE_DIR)
        .replace("__STATE__", RootCaManager.STATE_DIR)
        .replace("__STAGING__", RootCaManager.STAGING_DIR)
        .replace('§', '$')

    private fun readme(name: String) = """# Namu MITM CA 系统信任模块

由 NamuDNS 生成，内含本机 MITM CA 的证书段（certs/$name，不含私钥）。

## 安装
优先在 App「MITM 去广告 → 证书安装」点「一键安装/更新系统 CA」，
App 会在检测到 Magisk / KernelSU / APatch 后直接写模块并立即注入 Zygote。
也可以手动安装：KernelSU/Magisk → 模块 → 从存储安装 → 选本 zip → 重启。

## 注入方式
- 模块内证书先复制到常驻目录 /data/adb/namu_mitm_ca/cacerts_staging，
  再把整个 staging 目录 bind 到 APEX（Android 14+）或 legacy 系统证书库。
- bind 前用 cmp 比较，已有同一张证书就跳过；post-fs-data、service 和
  手动一键安装可反复执行，不会叠加挂载层。
- 新 fork 的 App 继承 Zygote 命名空间的挂载；已运行 App 需要强杀重开。

## 验证
- App 内「系统证书区」显示「已安装」。
- 或执行：su -c cat /data/adb/namu_mitm_ca/inject.log
  应看到 "inject done" 与目标目录。

## 卸载
App 内点「移除系统 CA」会按 source 精确 umount 我们自己的 staging 层，
再删除模块目录、日志和状态，不碰 APEX 自身或其他模块。
也可在 Root 管理器中移除本模块并重启。
"""
}
