package com.namu.dns

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** 只读核验系统 CA；模块安装和移除由 Magisk 管理。 */
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

    /**
     * 第 13 节冻结的互斥状态机。判定只来自三个独立事实，不再把「本进程读得到」
     * 当成「系统信任已生效」。
     */
    enum class TrustState {
        NOT_GENERATED,
        GENERATED_NOT_INSTALLED,
        INSTALLED_PENDING,
        ACTIVE,
        CONFLICT,
        INJECT_FAILED,
        REMOVED,
        RESIDUAL,
        UNVERIFIABLE,
    }

    data class RemovalReport(
        val at: Long,
        /** 已清理的 namespace 数（不是挂载点层数）。 */
        val cleared: Int = 0,
        val failed: Int = 0,
        val failedNamespaces: List<String> = emptyList(),
    )

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
        val removal: RemovalReport? = null,
    )

    data class ZygoteCheck(
        val process: String,
        val directoryIds: List<String>,
        val ownsTarget: Boolean,
        val certificateReadable: Boolean,
        val certificateMatches: Boolean,
    )

    data class TrustSnapshot(
        val root: RootInfo = RootInfo(false),
        /** 模块目录是否存在（不要求证书匹配）。 */
        val moduleInstalled: Boolean = false,
        /** 模块目录内的证书与当前本地 CA 的 DER/PEM 是否一致。 */
        val moduleCertMatches: Boolean = false,
        /** zygote/zygote64 namespace 内顶层 source 为本项目 staging 且证书匹配。 */
        val mountedInZygote: Boolean = false,
        /** 本进程（南门DNS）当前是否还能读到同指纹证书；只作残留信号。 */
        val visibleInSelf: Boolean = false,
        val conflict: Boolean = false,
        val topSources: List<String> = emptyList(),
        /** 顶层 source 中明确属于其他模块/手工注入的来源。 */
        val conflictSources: List<String> = emptyList(),
        val status: StatusInfo = StatusInfo(),
        val detail: String = "",
        val bootId: String = "",
        val target: String = "",
        val zygoteChecks: List<ZygoteCheck> = emptyList(),
    ) {
        /** 模块目录存在且证书匹配，才算“已安装到磁盘”。 */
        val moduleOnDisk: Boolean get() = moduleInstalled && moduleCertMatches
    }

    /** 三事实合成互斥状态；纯函数，便于全枚举单测。 */
    fun resolveTrustState(
        caExists: Boolean,
        snap: TrustSnapshot,
        removal: RemovalReport? = null,
    ): TrustState {
        if (!caExists) return TrustState.NOT_GENERATED
        if (!snap.root.available) return TrustState.UNVERIFIABLE
        if (snap.conflict) return TrustState.CONFLICT
        if (snap.status.done && snap.status.state != "ok" && !snap.mountedInZygote) {
            return TrustState.INJECT_FAILED
        }
        // mountedInZygote 已在 namespace 内比对 DER，不能再叠加 moduleCertMatches，
        // 否则模块目录被删但 zygote 仍挂载时会被误报成“未生效”。
        if (snap.mountedInZygote) return TrustState.ACTIVE
        if (snap.moduleOnDisk) return TrustState.INSTALLED_PENDING
        if (snap.visibleInSelf) return TrustState.RESIDUAL
        if (removal != null) return TrustState.REMOVED
        return TrustState.GENERATED_NOT_INSTALLED
    }

    /** AppConfig 落盘的 lastRemovalReport 转回领域对象；0 表示从未移除过。 */
    fun removalReport(
        at: Long,
        cleared: Int,
        failed: Int,
        failedNamespaces: String,
    ): RemovalReport? = if (at <= 0L) {
        null
    } else {
        RemovalReport(
            at = at,
            cleared = cleared.coerceAtLeast(0),
            failed = failed.coerceAtLeast(0),
            failedNamespaces = failedNamespaces.split(',')
                .map { it.trim() }
                .filter { it.isNotBlank() },
        )
    }

    /**
     * A1：恢复备份后是否需要重装/更新系统 CA。
     * 同机恢复、CA 未重生且系统库或模块里已有同一张证书时不打扰；
     * 只有指纹变了、系统库没有且模块也没匹配，或模块证书冲突时才刷新。
     */
    fun caNeedsRefresh(regenerated: Boolean, snap: TrustSnapshot): Boolean =
        regenerated ||
            snap.conflict ||
            (snap.moduleInstalled && !snap.moduleCertMatches) ||
            (!snap.visibleInSelf && !snap.moduleOnDisk && !snap.mountedInZygote)

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

    /** 失败态给用户一个可打开/分享的日志；只读固定路径，不拼用户输入。 */
    suspend fun diagnosticLog(): String = withContext(Dispatchers.IO) {
        val script = """
            echo "=== inject.log ==="
            tail -c 32768 $LOG_FILE 2>/dev/null
            echo
            echo "=== status ==="
            cat $STATUS_FILE 2>/dev/null
        """.trimIndent()
        su(script, 8_000).output.trim()
    }

    /**
     * 读取模块、namespace 内挂载与本进程可见性，产出三个独立事实：
     * moduleOnDisk（目录+证书匹配）、mountedInZygote（zygote 视图顶层 staging 且 DER 匹配）、
     * visibleInSelf（本进程可见，只作残留信号）。无 Root 时明确降级为「无法核验」。
     */
    suspend fun inspect(context: Context, systemName: String): TrustSnapshot =
        withContext(Dispatchers.IO) {
            if (!CERT_NAME.matches(systemName)) {
                return@withContext TrustSnapshot(detail = "证书文件名非法，无法核验")
            }
            val visibleInSelf = MitmManager.systemCertInstalled(context, systemName)
            val root = detect(context)
            if (!root.available) {
                return@withContext TrustSnapshot(
                    root = root,
                    visibleInSelf = visibleInSelf,
                    detail = "无 Root：无法核验 zygote 命名空间，系统区状态未知",
                )
            }
            val expectedPem = runCatching {
                TrustModuleGenerator.certificateOnlyPem(MitmManager.caFile(context).readText())
            }.getOrNull()
            val script = """
                NAME="$systemName"
                BOOT_ID=${'$'}(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
                echo "__BOOT_ID__=${'$'}BOOT_ID"
                STAGE="$STAGING_DIR.${'$'}BOOT_ID"
                [ -d "${'$'}STAGE" ] || STAGE="$STAGING_DIR"
                echo __MODULE__=${'$'}([ -d "$MODULE_DIR" ] && echo 1 || echo 0)
                if [ -f "$MODULE_DIR/certs/$systemName" ]; then
                  echo __CERT_BEGIN__
                  cat "$MODULE_DIR/certs/$systemName" 2>/dev/null
                  echo __CERT_END__
                fi
                if [ -d "$APEX_DIR" ] && [ -n "${'$'}(ls -A "$APEX_DIR" 2>/dev/null)" ]; then
                  TARGET="$APEX_DIR"
                else
                  TARGET="$LEGACY_DIR"
                fi
                echo "__TARGET__=${'$'}TARGET"
                dump_ns() {
                  KEY="${'$'}1"; PID="${'$'}2"; KIND="${'$'}3"
                  echo "__NS_BEGIN__=${'$'}KEY"
                  echo "__NS_KIND__=${'$'}KIND"
                  echo "__NS_MOUNTS_BEGIN__"
                  cat "/proc/${'$'}PID/mountinfo" 2>/dev/null
                  echo "__NS_MOUNTS_END__"
                  echo "__NS_IDS_BEGIN__"
                  if [ "${'$'}PID" = "${'$'}${'$'}" ]; then
                    stat -Lc '%d:%i' "${'$'}STAGE" "${'$'}TARGET" 2>/dev/null
                  else
                    nsenter -t "${'$'}PID" -m -- stat -Lc '%d:%i' "${'$'}STAGE" "${'$'}TARGET" 2>/dev/null
                  fi
                  echo "__NS_IDS_END__"
                  echo "__NS_CERT_BEGIN__"
                  if [ "${'$'}PID" = "${'$'}${'$'}" ]; then
                    cat "${'$'}TARGET/${'$'}NAME" 2>/dev/null
                  else
                    nsenter -t "${'$'}PID" -m -- cat "${'$'}TARGET/${'$'}NAME" 2>/dev/null
                  fi
                  echo "__NS_CERT_END__"
                  echo "__NS_END__"
                }
                dump_ns self "${'$'}${'$'}" self
                [ -d /proc/1 ] && dump_ns init:1 1 init
                SEEN=" "
                for P in ${'$'}(pidof zygote) ${'$'}(pidof zygote64); do
                  [ -n "${'$'}P" ] || continue
                  case " ${'$'}SEEN " in *" ${'$'}P "*) continue ;; esac
                  SEEN="${'$'}SEEN${'$'}P "
                  dump_ns "zygote:${'$'}P" "${'$'}P" zygote
                done
                echo __STATUS_BEGIN__
                if [ -n "${'$'}BOOT_ID" ] && [ -f "$MODULE_DIR/module.prop" ] &&
                   [ ! -e "$MODULE_DIR/disable" ] && [ ! -e "$MODULE_DIR/remove" ] &&
                   grep -qx "boot_id=${'$'}BOOT_ID" "$STATUS_FILE" 2>/dev/null; then
                  cat "$STATUS_FILE"
                fi
                echo __STATUS_END__
            """.trimIndent()
            val run = su(script, 12_000)
            if (run.timedOut || run.exitCode != 0) {
                return@withContext TrustSnapshot(
                    root = root,
                    visibleInSelf = visibleInSelf,
                    detail = "读取状态超时；未采到 zygote 事实，不能判定已生效",
                )
            }
            val moduleInstalled = run.output.lineSequence()
                .firstOrNull { it.startsWith("__MODULE__=") }?.substringAfter("=") == "1"
            val certText = section(run.output, "__CERT_BEGIN__", "__CERT_END__")
            val moduleCertMatches = expectedPem != null && certText.isNotBlank() &&
                pemCertificateMatches(certText, expectedPem)
            val status = parseStatus(section(run.output, "__STATUS_BEGIN__", "__STATUS_END__"))
            val blocks = parseNamespaceBlocks(run.output)
            val zygoteChecks = blocks.filter { it.kind == "zygote" }.map { block ->
                ZygoteCheck(
                    process = block.key,
                    directoryIds = block.directoryIds,
                    ownsTarget = block.ownsTarget,
                    certificateReadable = block.cert.isNotBlank(),
                    certificateMatches = expectedPem != null && pemCertificateMatches(block.cert, expectedPem),
                )
            }
            val mountedInZygote = zygoteChecks.isNotEmpty() &&
                zygoteChecks.all { it.ownsTarget && it.certificateMatches }
            val topSources = blocks.flatMap { block -> explicitMountRoots(block.mounts, block.target) }.distinct()
            val conflictSources = blocks.filter { !it.ownsTarget }.flatMap { block ->
                explicitMountRoots(block.mounts, block.target).filter { isForeignCertOverlay(it) }
            }.distinct()
            val conflict = conflictSources.isNotEmpty()
            TrustSnapshot(
                root = root,
                moduleInstalled = moduleInstalled,
                moduleCertMatches = moduleCertMatches,
                mountedInZygote = mountedInZygote,
                visibleInSelf = visibleInSelf,
                conflict = conflict,
                topSources = topSources,
                conflictSources = conflictSources,
                status = status,
                bootId = run.output.lineSequence()
                    .firstOrNull { it.startsWith("__BOOT_ID__=") }?.substringAfter("=").orEmpty(),
                target = blocks.firstOrNull()?.target.orEmpty(),
                zygoteChecks = zygoteChecks,
                detail = if (moduleInstalled && !moduleCertMatches) {
                    "模块内证书与当前 CA 不一致，请一键更新模块"
                } else {
                    ""
                },
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

    data class NamespaceBlock(
        val key: String,
        val kind: String,
        val target: String,
        val mounts: String,
        val cert: String,
        val ownsTarget: Boolean = false,
        val directoryIds: List<String> = emptyList(),
    )

    /**
     * 解 inspect 脚本的 namespace 块。每块带 mounts 与在该 namespace 内读到的证书，
     * 不能用全局 __CERT__ 段代替——那只是模块目录里的证书。
     */
    internal fun parseNamespaceBlocks(output: String): List<NamespaceBlock> {
        val target = output.lineSequence()
            .firstOrNull { it.startsWith("__TARGET__=") }
            ?.substringAfter("=")
            .orEmpty()
        val blocks = mutableListOf<NamespaceBlock>()
        var key = ""
        var kind = ""
        var mounts = StringBuilder()
        var cert = StringBuilder()
        var inMounts = false
        var inCert = false
        var inIds = false
        val ids = mutableListOf<String>()

        fun flush() {
            if (key.isBlank()) return
            blocks += NamespaceBlock(
                key = key,
                kind = kind,
                target = target,
                mounts = mounts.toString(),
                cert = cert.toString().trim(),
                ownsTarget = ids.size == 2 && ids[0] == ids[1],
                directoryIds = ids.toList(),
            )
            key = ""
            kind = ""
            mounts = StringBuilder()
            cert = StringBuilder()
            ids.clear()
            inIds = false
        }

        for (line in output.lineSequence()) {
            when {
                line.startsWith("__NS_BEGIN__=") -> {
                    flush()
                    key = line.substringAfter("=")
                    inMounts = false
                    inCert = false
                }
                line.startsWith("__NS_KIND__=") -> kind = line.substringAfter("=")
                line == "__NS_MOUNTS_BEGIN__" -> inMounts = true
                line == "__NS_MOUNTS_END__" -> inMounts = false
                line == "__NS_IDS_BEGIN__" -> inIds = true
                line == "__NS_IDS_END__" -> inIds = false
                inIds && line.matches(Regex("[0-9]+:[0-9]+")) -> ids.add(line)
                line == "__NS_CERT_BEGIN__" -> inCert = true
                line == "__NS_CERT_END__" -> inCert = false
                line == "__NS_END__" -> flush()
                inMounts -> mounts.appendLine(line)
                inCert -> cert.appendLine(line)
            }
        }
        flush()
        return blocks
    }

    internal fun parseRemovalReport(output: String, at: Long): RemovalReport {
        var cleared = 0
        var failed = 0
        var failedNs = ""
        for (line in output.lineSequence()) {
            when {
                line.startsWith("__REMOVAL_CLEARED__=") ->
                    cleared = line.substringAfter("=").toIntOrNull() ?: 0
                line.startsWith("__REMOVAL_FAILED__=") ->
                    failed = line.substringAfter("=").toIntOrNull() ?: 0
                line.startsWith("__REMOVAL_FAILED_NS__=") ->
                    failedNs = line.substringAfter("=").trim()
            }
        }
        return RemovalReport(
            at = at,
            cleared = cleared.coerceAtLeast(0),
            failed = failed.coerceAtLeast(0),
            failedNamespaces = failedNs.split(',')
                .map { it.trim() }
                .filter { it.isNotBlank() },
        )
    }

    /** 比较证书正文的 base64，忽略换行/CRLF/首尾空白。 */
    internal fun pemCertificateMatches(actual: String, expected: String): Boolean {
        val a = pemBody(actual) ?: return false
        val e = pemBody(expected) ?: return false
        return a == e
    }

    private fun pemBody(pem: String): String? {
        val begin = "-----BEGIN CERTIFICATE-----"
        val end = "-----END CERTIFICATE-----"
        val start = pem.indexOf(begin)
        if (start < 0) return null
        val stop = pem.indexOf(end, start + begin.length)
        if (stop < 0) return null
        return pem.substring(start + begin.length, stop).filterNot { it.isWhitespace() }
    }

    /**
     * 目标证书库顶层 source 是否明确是别人的覆盖层。系统底层分区（/dev/block、/system、
     * /apex）不是冲突；/data/adb/modules/...、tmpfs、overlay 等才是。
     */
    internal fun isForeignCertOverlay(source: String): Boolean {
        if (source.isBlank() || source == STAGING_DIR) return false
        if (source.startsWith("/dev/")) return false
        if (source == "rootfs") return false
        if (source.startsWith("/system/") || source == "/system") return false
        if (source.startsWith("/apex/") || source == "/apex") return false
        return true
    }

    internal fun explicitMountRoots(text: String, target: String): List<String> =
        text.lineSequence().mapNotNull { line ->
            val fields = line.split(' ')
            if (fields.getOrNull(4) != target) return@mapNotNull null
            val separator = fields.indexOf("-")
            if (separator < 6) return@mapNotNull null
            val root = fields[3]
            if (root == "/") fields.getOrNull(separator + 1)?.takeIf { it == "tmpfs" || it == "overlay" }
            else root
        }.toList()

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
