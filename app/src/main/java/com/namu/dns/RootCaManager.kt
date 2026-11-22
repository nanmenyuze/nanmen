package com.namu.dns

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Root 侧 CA 模块管理：写入 /data/adb/modules/namu_mitm_ca、立即注入 zygote、
 * 读取挂载栈做冲突检测、按 source 精确卸载。
 *
 * 安全边界：
 * - 所有进入 shell 的路径/文件名都是常量，证书名还必须匹配 [0-9a-f]{8}\.0；
 * - 用户输入（备注、域名等）绝不拼进 su 命令；
 * - 模块目录只写证书段，私钥留在 App 私有目录。
 */
object RootCaManager {

    const val MODULE_DIR = "/data/adb/modules/namu_mitm_ca"
    const val STATE_DIR = "/data/adb/namu_mitm_ca"
    const val STAGING_DIR = "$STATE_DIR/cacerts_staging"
    const val STATUS_FILE = "$STATE_DIR/status"
    const val LOG_FILE = "$STATE_DIR/inject.log"

    private const val APEX_DIR = "/apex/com.android.conscrypt/cacerts"
    private const val LEGACY_DIR = "/system/etc/security/cacerts"
    private val CERT_NAME = Regex("[0-9a-f]{8}\\.0")

    enum class RootKind { MAGISK, KERNELSU, APATCH, NONE }

    data class RootInfo(
        val available: Boolean,
        val kind: RootKind = RootKind.NONE,
        val detail: String = "",
    )

    data class StatusInfo(
        val done: Boolean = false,
        val state: String = "",
        val cert: String = "",
        val target: String = "",
        val bound: Int = 0,
        val conflict: Boolean = false,
        val lines: Map<String, String> = emptyMap(),
    )

    data class Result(
        val ok: Boolean,
        val message: String = "",
        val exportedPath: String = "",
        val needsRestart: Boolean = true,
    )

    data class TrustSnapshot(
        val root: RootInfo = RootInfo(false),
        val moduleInstalled: Boolean = false,
        val moduleCertMatches: Boolean = false,
        val systemCertInstalled: Boolean = false,
        val conflict: Boolean = false,
        val topSources: List<String> = emptyList(),
        val status: StatusInfo = StatusInfo(),
        val detail: String = "",
    )

    /**
     * A1：恢复备份后是否需要重装/更新系统 CA。
     * 同机恢复、CA 未重生且系统库或模块里已有同一张证书时不打扰；
     * 只有指纹变了、系统库没有且模块也没匹配，或模块证书冲突时才刷新。
     */
    fun caNeedsRefresh(regenerated: Boolean, snap: TrustSnapshot): Boolean =
        regenerated ||
            snap.conflict ||
            (snap.moduleInstalled && !snap.moduleCertMatches) ||
            (!snap.systemCertInstalled && !(snap.moduleInstalled && snap.moduleCertMatches))

    /** 一次 su 同时判断 Root 与模块管理器，减少等待授权/超时。 */
    suspend fun detect(context: Context): RootInfo = withContext(Dispatchers.IO) {
        val r = su(
            "id; " +
                "if [ -d /data/adb/magisk ]; then echo __KIND__=magisk; " +
                "elif [ -d /data/adb/ksu ]; then echo __KIND__=kernelsu; " +
                "elif [ -d /data/adb/ap ]; then echo __KIND__=apatch; " +
                "else echo __KIND__=none; fi",
            8_000,
        )
        if (r.timedOut) return@withContext RootInfo(false, detail = "Root 授权超时")
        val output = r.output
        if (!output.contains("uid=0")) {
            return@withContext RootInfo(false, detail = output.lineSequence().firstOrNull().orEmpty())
        }
        RootInfo(true, parseRootKind(output), output.trim())
    }

    /**
     * 一键安装/更新：有 Root 且能识别 Magisk/KSU/APatch 时写模块并立即注入；
     * 否则只导出 zip，交给用户手动安装，绝不写半吊子模块。
     */
    suspend fun install(context: Context, pemPath: String, systemName: String): Result =
        withContext(Dispatchers.IO) {
            if (!CERT_NAME.matches(systemName)) {
                return@withContext Result(false, "证书文件名非法：$systemName")
            }
            val pem = runCatching { File(pemPath).readText() }.getOrNull()
                ?: return@withContext Result(false, "CA 证书不存在，请先生成")
            if (TrustModuleGenerator.certificateOnlyPem(pem) == null) {
                return@withContext Result(false, "CA 证书格式无效，请重新生成")
            }
            val root = detect(context)
            if (!root.available || root.kind == RootKind.NONE) {
                val exported = TrustModuleGenerator.generate(context, pemPath, systemName)
                val why = if (!root.available) "未授予 Root" else "未识别到 Magisk/KernelSU/APatch"
                return@withContext Result(
                    false,
                    "$why，未写入模块。已导出 ${exported.path.ifBlank { "模块 zip" }}，请在 Root 管理器里手动安装。",
                    exported.path,
                )
            }

            val stage = File(context.filesDir, "ca_module_stage")
            runCatching {
                TrustModuleGenerator.writeModuleFiles(stage, pem, systemName)
            }.getOrElse { e ->
                return@withContext Result(false, "准备模块文件失败：${e.message}")
            }
            val stagePath = stage.absolutePath
            if (!isShellSafePath(stagePath)) {
                return@withContext Result(false, "模块暂存路径包含不安全字符")
            }

            val script = """
                DEST=$MODULE_DIR
                NEW=${'$'}DEST.new
                OLD=${'$'}DEST.old
                rm -rf "${'$'}NEW" "${'$'}OLD"
                mkdir -p "${'$'}NEW" || exit 11
                cp -R "$stagePath"/. "${'$'}NEW"/ || exit 12
                chown -R 0:0 "${'$'}NEW" || exit 13
                find "${'$'}NEW" -type d -exec chmod 0755 {} \;
                find "${'$'}NEW" -type f -exec chmod 0644 {} \;
                chmod 0755 "${'$'}NEW"/*.sh
                if command -v chcon >/dev/null 2>&1; then
                  chcon -R u:object_r:system_file:s0 "${'$'}NEW" 2>/dev/null
                fi
                if [ -d "${'$'}DEST" ]; then mv "${'$'}DEST" "${'$'}OLD" || exit 14; fi
                if ! mv "${'$'}NEW" "${'$'}DEST"; then
                  [ -d "${'$'}OLD" ] && mv "${'$'}OLD" "${'$'}DEST"
                  exit 15
                fi
                rm -rf "${'$'}OLD"
                sh "${'$'}DEST/inject.sh"
                RC=${'$'}?
                echo __STATUS_BEGIN__
                cat $STATUS_FILE 2>/dev/null
                echo __STATUS_END__
                exit ${'$'}RC
            """.trimIndent()
            val run = su(script, 70_000)
            val status = parseStatus(section(run.output, "__STATUS_BEGIN__", "__STATUS_END__"))
            if (run.timedOut) {
                return@withContext Result(false, "写入模块超时；请到 Root 管理器确认模块状态")
            }
            if (run.exitCode != 0 || !status.done || status.state != "ok") {
                val err = status.lines["error"] ?: status.lines["detail"]
                return@withContext Result(
                    false,
                    "模块写入/注入失败${if (err.isNullOrBlank()) "" else "：$err"}。日志：$LOG_FILE",
                )
            }
            Result(
                true,
                "系统 CA 已安装并注入：${status.target.ifBlank { "系统证书库" }}，" +
                    "证书 ${status.cert.ifBlank { systemName }}。新启动的 App 直接信任；" +
                    "已运行 App 请强杀重开。",
                needsRestart = true,
            )
        }

    /** 只卸载 source == 我们 staging 的挂载层，再删模块/状态/日志。 */
    suspend fun remove(context: Context): Result = withContext(Dispatchers.IO) {
        val helperDir = File(context.filesDir, "ca_module_stage")
        runCatching { TrustModuleGenerator.writeRemovalHelpers(helperDir) }.getOrElse { e ->
            return@withContext Result(false, "准备卸载脚本失败：${e.message}")
        }
        val stagePath = helperDir.absolutePath
        if (!isShellSafePath(stagePath)) {
            return@withContext Result(false, "卸载脚本暂存路径不安全")
        }
        val script = """
            cp "$stagePath/remove.sh" /data/local/tmp/namu_ca_remove.sh || exit 21
            cp "$stagePath/unmount.sh" /data/local/tmp/namu_ca_unmount.sh || exit 22
            chmod 0755 /data/local/tmp/namu_ca_remove.sh /data/local/tmp/namu_ca_unmount.sh
            sh /data/local/tmp/namu_ca_remove.sh
            RC=${'$'}?
            rm -f /data/local/tmp/namu_ca_remove.sh /data/local/tmp/namu_ca_unmount.sh
            exit ${'$'}RC
        """.trimIndent()
        val run = su(script, 45_000)
        if (run.timedOut) return@withContext Result(false, "移除系统 CA 超时")
        if (run.exitCode != 0) {
            return@withContext Result(
                false,
                "移除未尽：${run.output.trim().take(300).ifBlank { "退出码 ${run.exitCode}" }}",
            )
        }
        Result(
            true,
            "已移除系统 CA 并恢复原证书库。若当前 App 仍显示已信任，请强杀重开；" +
                "系统可能仍缓存旧证书直到下次重启。",
            needsRestart = true,
        )
    }

    /** 读取模块/挂载/系统证书区状态；无 Root 时仍可判断系统证书区。 */
    suspend fun inspect(context: Context, systemName: String): TrustSnapshot =
        withContext(Dispatchers.IO) {
            val systemInstalled = MitmManager.systemCertInstalled(context, systemName)
            val root = detect(context)
            if (!root.available) {
                return@withContext TrustSnapshot(
                    root = root,
                    systemCertInstalled = systemInstalled,
                    detail = "无 Root：只能按 DER 判断系统证书区是否一致",
                )
            }
            val expectedPem = runCatching {
                TrustModuleGenerator.certificateOnlyPem(MitmManager.caFile(context).readText())
            }.getOrNull()
            val script = """
                echo __MODULE__=${'$'}([ -d $MODULE_DIR ] && echo 1 || echo 0)
                echo __CERT__=
                if [ -f "$MODULE_DIR/certs/$systemName" ]; then
                  echo __CERT_BEGIN__
                  cat "$MODULE_DIR/certs/$systemName" 2>/dev/null
                  echo __CERT_END__
                fi
                echo __STATUS_BEGIN__
                cat $STATUS_FILE 2>/dev/null
                echo __STATUS_END__
                for P in 1 ${'$'}(pidof zygote) ${'$'}(pidof zygote64); do
                  [ -n "${'$'}P" ] || continue
                  echo "__NS__=${'$'}P"
                  cat /proc/${'$'}P/mounts 2>/dev/null
                done
                echo "__NS__=self"
                cat /proc/self/mounts
            """.trimIndent()
            val run = su(script, 12_000)
            if (run.timedOut) {
                return@withContext TrustSnapshot(root = root, systemCertInstalled = systemInstalled, detail = "读取状态超时")
            }
            val moduleInstalled = run.output.lineSequence()
                .firstOrNull { it.startsWith("__MODULE__=") }?.substringAfter("=") == "1"
            val certText = section(run.output, "__CERT_BEGIN__", "__CERT_END__")
            val moduleCertMatches = expectedPem != null && certText.isNotBlank() &&
                certText.trim() == expectedPem.trim()
            val status = parseStatus(section(run.output, "__STATUS_BEGIN__", "__STATUS_END__"))
            val mountsByNs = parseMountsByNamespace(run.output)
            val topSources = mountsByNs.flatMap { (_, mounts) ->
                listOfNotNull(
                    parseMountTopSource(mounts, APEX_DIR),
                    parseMountTopSource(mounts, LEGACY_DIR),
                )
            }.distinct()
            // 任一目标库的最上层不是我们，就算冲突；否则 APEX 正常、legacy 被别的模块盖住会漏报。
            val conflict = status.conflict || (moduleInstalled && topSources.any { it != STAGING_DIR })
            TrustSnapshot(
                root = root,
                moduleInstalled = moduleInstalled,
                moduleCertMatches = moduleCertMatches,
                systemCertInstalled = systemInstalled,
                conflict = conflict,
                topSources = topSources,
                status = status,
                detail = if (moduleInstalled && !moduleCertMatches) "模块内证书与当前 CA 不一致，请一键更新" else "",
            )
        }

    private fun su(script: String, timeoutMs: Long): ProcessRunner.Result =
        ProcessRunner.run(listOf("su", "-c", script), timeoutMs)

    internal fun parseRootKind(output: String): RootKind = when {
        output.contains("__KIND__=magisk") -> RootKind.MAGISK
        output.contains("__KIND__=kernelsu") -> RootKind.KERNELSU
        output.contains("__KIND__=apatch") -> RootKind.APATCH
        else -> RootKind.NONE
    }

    internal fun parseStatus(text: String): StatusInfo {
        if (text.isBlank()) return StatusInfo()
        val map = text.lineSequence()
            .mapNotNull { line ->
                val i = line.indexOf('=')
                if (i <= 0) null else line.substring(0, i) to line.substring(i + 1)
            }
            .toMap()
        return StatusInfo(
            done = map["done"] == "1",
            state = map["state"].orEmpty(),
            cert = map["cert"].orEmpty(),
            target = map["target"].orEmpty(),
            bound = map["bound"]?.toIntOrNull() ?: 0,
            conflict = map["conflict"] == "1",
            lines = map,
        )
    }

    /** /proc/mounts 里同一个挂载点可能叠多层；最后一行是最上层。 */
    internal fun parseMountTopSource(mountsText: String, target: String): String? {
        var source: String? = null
        for (line in mountsText.lineSequence()) {
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size >= 2 && parts[1] == target) source = parts[0]
        }
        return source
    }

    /** 按 source 精确挑出要卸载的挂载点；source 不符的一律不碰。 */
    internal fun mountPointsBySource(mountsText: String, source: String): List<String> {
        val points = mutableListOf<String>()
        for (line in mountsText.lineSequence()) {
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size >= 2 && parts[0] == source && parts[1] !in points) points += parts[1]
        }
        return points
    }

    internal fun parseMountsByNamespace(output: String): Map<String, String> {
        val result = LinkedHashMap<String, StringBuilder>()
        var current = "self"
        for (line in output.lineSequence()) {
            if (line.startsWith("__NS__=")) {
                current = line.substringAfter("=").ifBlank { "self" }
                result.getOrPut(current) { StringBuilder() }
            } else if (result.containsKey(current)) {
                result.getValue(current).appendLine(line)
            }
        }
        return result.mapValues { it.value.toString() }
    }

    private fun section(text: String, begin: String, end: String): String {
        val start = text.indexOf(begin) + begin.length
        if (start < begin.length) return ""
        val stop = text.indexOf(end, start)
        return if (stop < 0) "" else text.substring(start, stop).trim()
    }

    /** 路径只允许常规字符；命令里始终用双引号包住。 */
    internal fun isShellSafePath(path: String): Boolean =
        path.startsWith("/") && path.matches(Regex("[A-Za-z0-9_./-]+"))
}
