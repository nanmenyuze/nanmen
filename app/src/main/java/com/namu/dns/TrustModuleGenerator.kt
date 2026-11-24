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

/** 生成由 Magisk 安装并在开机时运行的系统 CA 模块。ZIP 仅含公开证书。 */
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
            "inject.sh" to renderScript(injectScript(systemName)).toByteArray(),
            "bind.sh" to renderScript(bindScript()).toByteArray(),
            "prune.sh" to renderScript(pruneScript()).toByteArray(),
            // 只放证书段：ca.pem 同时含私钥，不能把私钥带进系统信任库/模块目录。
            "certs/$systemName" to certificate.toByteArray(),
            "README.md" to readme(systemName).toByteArray(),
        )

    private fun moduleProp() = """id=namu_mitm_ca
name=Namu MITM CA (System Trust)
version=v2.14
versionCode=214
author=NamuDNS
description=由模块管理器管理的南门 DNS 系统 CA。安装或更新后重启系统界面并核验。
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
        MODDIR=§{0%/*}
        [ ! -e "§MODDIR/disable" ] && [ ! -e "§MODDIR/remove" ] || exit 0
        sh "§MODDIR/inject.sh" --early
        exit 0
    """.trimIndent().replace('§', '$')

    private fun serviceScript() = """
        #!/system/bin/sh
        # 由 Magisk 开机调用，等待证书库和 Zygote 就绪。
        MODDIR=${'$'}{0%/*}
        i=0
        while [ "${'$'}i" -lt 30 ]; do
          [ ! -e "${'$'}MODDIR/disable" ] && [ ! -e "${'$'}MODDIR/remove" ] || exit 0
          if sh "${'$'}MODDIR/inject.sh" --late; then exit 0; fi
          i=${'$'}((i+1))
          sleep 1
        done
        exit 1
    """.trimIndent()

    private fun injectScript(name: String): String {
        val template = """
            #!/system/bin/sh
            MODDIR=§{0%/*}
            STATE=__STATE__
            MODE=§1
            case "§MODE" in --early|--late) ;; *) exit 2 ;; esac
            BOOT_ID=§(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || exit 1
            case "§BOOT_ID" in ""|*[!0-9a-f-]*) exit 1 ;; esac
            STAGING=§STATE/cacerts_staging.§BOOT_ID
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
            LOCK=§STATE/inject_lock.§BOOT_ID
            mkdir "§LOCK" 2>/dev/null || exit 1
            trap 'rmdir "§LOCK"' EXIT
            echo "=== §(date) inject start (§1) ==="
            write_status() {
              ST="§1"; shift
              {
                echo "state=§ST"
                echo "boot_id=§BOOT_ID"
                echo "phase=§MODE"
                echo "staging=§{STAGING##*/}"
                for L in "§@"; do echo "§L"; done
                echo "done=1"
              } > "§STATUS.tmp.§§"
              mv -f "§STATUS.tmp.§§" "§STATUS"
            }
            fail() {
              echo "ERROR: §1"
              write_status error "cert=§NAME" "target=§TARGET" "error=§1"
              exit 1
            }
            [ -f "§SRC" ] || fail "模块内证书缺失: §SRC"
            SDK=§(getprop ro.build.version.sdk)
            case "§SDK" in ""|*[!0-9]*) fail "无法识别 Android 版本" ;; esac
            ZYGOTES="§(pidof zygote 2>/dev/null) §(pidof zygote64 2>/dev/null)"
            set -- §ZYGOTES
            if [ "§MODE" = "--early" ]; then
              if [ "§#" -gt 0 ]; then
                echo "SKIP: Zygote 已启动，交由后期服务核验"
                exit 0
              fi
              # 使用模块管理器提供的开机挂载视图，不切换或重启 init。
              PROC_IDS=§§
              SOURCE_PID=§§
            else
              command -v nsenter >/dev/null 2>&1 || fail "nsenter 不可用，无法注入 Zygote"
              [ "§#" -gt 0 ] || fail "Zygote 尚未就绪"
              PROC_IDS="§ZYGOTES"
              SOURCE_PID=§1
            fi
            HELPER="§MODDIR/bind.sh"
            check_or_bind() {
              PID="§1"; shift
              if [ "§PID" = "§§" ]; then
                sh "§HELPER" "§@"
              else
                nsenter -t "§PID" -m -- /system/bin/sh "§HELPER" "§@"
              fi
            }
            inject_target() (
              TARGET="§1"
              STAGING="§2"
              STATUS="§3"
              NEW=""
              trap '[ -z "§NEW" ] || rm -rf "§NEW"' EXIT
              [ -d "§TARGET" ] && [ ! -L "§TARGET" ] &&
                [ -n "§(ls -A "§TARGET" 2>/dev/null)" ] ||
                fail "证书目录不可用: §TARGET"
              # 已发布目录可能仍由旧进程使用。同一 boot_id 下为不同证书选独立目录。
              if [ -e "§STAGING" ] || [ -L "§STAGING" ]; then
                if [ -L "§STAGING" ] || [ ! -d "§STAGING" ] || ! cmp -s "§STAGING/§NAME" "§SRC"; then
                  SHA=§(sha256sum "§SRC") || fail "无法读取模块证书摘要"
                  SHA=§{SHA%% *}
                  printf '%s\n' "§SHA" | grep -Eq '^[0-9a-f]{64}§' || fail "模块证书摘要无效"
                  STAGING="§STAGING.§SHA"
                fi
              fi
              for P in §PROC_IDS; do
                check_or_bind "§P" "§STAGING" "§TARGET" "§NAME" --check ||
                  fail "证书区被其他挂载覆盖或无法核验: PID §P"
              done

              # 预检通过后才可复用已发布副本或创建独立副本。
              if [ -e "§STAGING" ] || [ -L "§STAGING" ]; then
                [ -d "§STAGING" ] && [ ! -L "§STAGING" ] &&
                  cmp -s "§STAGING/§NAME" "§SRC" ||
                  fail "当前证书副本不可用，已保留现有证书区"
              else
                STOCK="/proc/§SOURCE_PID/root§TARGET"
                [ ! -e "§STOCK/§NAME" ] && [ ! -L "§STOCK/§NAME" ] ||
                  fail "系统已有同名证书，已保留原证书库"
                NEW=§(mktemp -d "§STATE/cacerts.new.XXXXXX") || fail "无法创建临时证书目录"
                cp -R "§STOCK"/. "§NEW"/ || fail "复制系统证书库失败，未挂载"
                [ ! -e "§NEW/§NAME" ] && [ ! -L "§NEW/§NAME" ] || fail "副本内已有同名证书"
                cp -f "§SRC" "§NEW/§NAME" || fail "复制证书到 staging 失败"
                chown -R 0:0 "§NEW" || fail "无法设置证书所有者"
                chmod 0755 "§NEW" || fail "无法设置证书目录权限"
                find "§NEW" -type d -exec chmod 0755 {} \; || fail "无法设置子目录权限"
                find "§NEW" -type f -exec chmod 0644 {} \; || fail "无法设置证书权限"
                if command -v chcon >/dev/null 2>&1; then
                  chcon -R u:object_r:system_file:s0 "§NEW" || fail "无法设置证书 SELinux 标签"
                fi
                check_or_bind "§SOURCE_PID" "§NEW" "§TARGET" "§NAME" --verify ||
                  fail "系统证书库副本校验失败，未挂载"
                [ ! -e "§STAGING" ] && [ ! -L "§STAGING" ] || fail "已有证书目录，未替换"
                mv -T "§NEW" "§STAGING" || fail "无法发布证书目录"
                NEW=""
              fi

              # 所有目标先验证。尚未挂载的 namespace 必须逐个比对系统证书原件。
              for P in §PROC_IDS; do
                check_or_bind "§P" "§STAGING" "§TARGET" "§NAME" --verify ||
                  fail "系统证书库与副本不一致或不可读: PID §P；保持现状，请完整重启"
              done

              BOUND=0
              for P in §PROC_IDS; do
                if check_or_bind "§P" "§STAGING" "§TARGET" "§NAME"; then
                  BOUND=§((BOUND+1))
                else
                  fail "Zygote 证书挂载或核验失败: PID §P，已核验 §BOUND 个；保留现有挂载，请完整重启"
                fi
              done
              write_status ok "cert=§NAME" "target=§TARGET" "bound=§BOUND" "conflict=0"
              echo "=== inject done: §TARGET, bound=§BOUND, conflict=0 ==="
            )

            if [ "§SDK" -ge 34 ]; then
              if ! inject_target "§APEX" "§STAGING" "§STATUS" && [ "§MODE" = "--late" ]; then
                exit 1
              fi
              # 旧系统目录需要使用自己的原件。两个目录分别校验。
              inject_target "§LEGACY" "§STATE/cacerts_legacy.§BOOT_ID" "§STATE/status.legacy" ||
                echo "WARN: 旧系统证书区未挂载"
            else
              inject_target "§LEGACY" "§STAGING" "§STATUS" || exit 1
            fi
            [ "§MODE" = "--late" ] || exit 0
            sh "§MODDIR/prune.sh" "§STATE" "§BOOT_ID" ||
              echo "WARN: 保留无法安全清理的历史证书目录"
            exit 0
        """.trimIndent()
        return template
            .replace("__STATE__", RootCaManager.STATE_DIR)
            .replace("__APEX__", "/apex/com.android.conscrypt/cacerts")
            .replace("__LEGACY__", "/system/etc/security/cacerts")
            .replace("__CERT_NAME__", name)
            .replace('§', '$')
    }

    private fun pruneScript() = """
        #!/system/bin/sh
        STATE="§1"
        BOOT_ID="§2"
        PROC="§{3:-/proc}"
        is_boot_id() {
          printf '%s\n' "§1" | grep -Eq '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}§'
        }
        is_boot_id "§BOOT_ID" || exit 1
        [ -d "§STATE" ] && [ ! -L "§STATE" ] || exit 1
        [ -r "§PROC/1/mountinfo" ] || exit 1

        for DIR in "§STATE"/cacerts_staging.* "§STATE"/cacerts_legacy.* "§STATE"/inject_lock.*; do
          [ -d "§DIR" ] && [ ! -L "§DIR" ] || continue
          BASE="§{DIR##*/}"
          KEY="§{BASE#*.}"
          OLD="§{KEY%%.*}"
          [ "§OLD" != "§BOOT_ID" ] && is_boot_id "§OLD" || continue
          if [ "§KEY" != "§OLD" ]; then
            case "§BASE" in cacerts_staging.*|cacerts_legacy.*) ;; *) continue ;; esac
            printf '%s\n' "§{KEY#*.}" | grep -Eq '^[0-9a-f]{64}§' || continue
          fi
          case "§DIR" in
            "§STATE"/inject_lock.*) rmdir "§DIR" 2>/dev/null || :; continue ;;
          esac
          # A bind mount can report the staging path in the filesystem root field
          # with a shortened prefix. Check the exact boot-scoped basename.
          SAFE=1
          for PROCESS in "§PROC"/[0-9]*; do
            [ -d "§PROCESS" ] || continue
            grep -Fq "§BASE" "§PROCESS/mountinfo" 2>/dev/null
            case "§?" in
              0) SAFE=0; break ;;
              1) ;;
              *) [ ! -d "§PROCESS" ] || { SAFE=0; break; } ;;
            esac
          done
          [ "§SAFE" = 1 ] || continue
          # The generated certificate store is flat; refuse nested directories and
          # symlinks so pruning cannot descend into any mount or unrelated path.
          for ENTRY in "§DIR"/* "§DIR"/.[!.]* "§DIR"/..?*; do
            [ -e "§ENTRY" ] || [ -L "§ENTRY" ] || continue
            [ -f "§ENTRY" ] && [ ! -L "§ENTRY" ] || { SAFE=0; break; }
          done
          [ "§SAFE" = 1 ] || continue
          rm -f "§DIR"/* "§DIR"/.[!.]* "§DIR"/..?* && rmdir "§DIR" || exit 1
        done
    """.trimIndent().replace('§', '$')

    private fun bindScript() = """
        #!/system/bin/sh
        STAGING="§1"
        TARGET="§2"
        NAME="§3"
        case "§4" in ""|--check|--verify) ;; *) exit 2 ;; esac
        [ -d "§TARGET" ] || exit 3
        TARGET_ID=§(stat -Lc '%d:%i' "§TARGET") || exit 3
        STAGE_ID=§(stat -Lc '%d:%i' "§STAGING" 2>/dev/null)
        if [ "§TARGET_ID" = "§STAGE_ID" ]; then
          [ "§4" = "--check" ] && exit 0
          cmp -s "§STAGING/§NAME" "§TARGET/§NAME"
          exit §?
        fi
        # Own bind is proven by device+inode. For a different mount, inspect the
        # actual mount root instead of interpreting the filesystem's source name.
        awk -v t="§TARGET" '
          §5 == t {
            for (i=7; i <= NF && §i != "-"; i++) {}
            if (§4 !~ /^\/(system|apex)(\/|§)/ && (§4 != "/" || §(i+1) ~ /^(tmpfs|overlay)§/)) conflict=1
          }
          END {exit (NR==0 || conflict)}
        ' /proc/self/mountinfo || exit 7
        [ "§4" = "--check" ] && exit 0
        [ -n "§STAGE_ID" ] && [ -s "§STAGING/§NAME" ] || exit 4
        [ ! -e "§TARGET/§NAME" ] && [ ! -L "§TARGET/§NAME" ] || exit 9
        COUNT=0
        for F in "§TARGET"/*; do
          [ -f "§F" ] || continue
          [ -s "§F" ] && cmp -s "§F" "§STAGING/§{F##*/}" || exit 9
          COUNT=§((COUNT+1))
        done
        [ "§COUNT" -gt 0 ] || exit 9
        for F in "§STAGING"/*; do
          [ -f "§F" ] || continue
          [ "§{F##*/}" = "§NAME" ] || [ -f "§TARGET/§{F##*/}" ] || exit 9
        done
        [ "§4" = "--verify" ] && exit 0
        /system/bin/mount --bind "§STAGING" "§TARGET" || exit 5
        [ "§(stat -Lc '%d:%i' "§TARGET")" = "§STAGE_ID" ] || exit 6
        cmp -s "§STAGING/§NAME" "§TARGET/§NAME" || exit 6
        exit 0
    """.trimIndent().replace('§', '$')

    private fun readme(name: String) = """# 南门 DNS 系统 CA

模块只包含公开 CA（certs/$name）。在模块管理器的「从存储安装」选择本 ZIP，使用该管理器支持的重启方式。临时 Root 环境优先使用软重启。
停用或移除也从 Magisk 操作，随后完整重启。
启动早期尝试挂载，后期服务在 Zygote 中复核并补挂。Android 14 及以上对 APEX 和旧系统证书区分别校验。
重启后在 App 的证书页核对状态。
"""
}
