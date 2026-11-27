package com.namu.dns

object NativeCore {
    val available: Boolean = try {
        System.loadLibrary("nanmen_core")
        true
    } catch (_: Throwable) {
        false
    }

    @JvmStatic external fun nativeStart(tunFd: Int, configJson: String): Boolean
    const val RELOAD_OK = 1
    const val RELOAD_CA_UNAVAILABLE = -1
    const val RELOAD_INVALID_CONFIG = -2
    @JvmStatic external fun nativeProbeNodes(payloadJson: String): String
    @JvmStatic external fun nativeValidateConfig(configJson: String): Boolean
    @JvmStatic external fun nativeReloadRules(configJson: String): Int
    /** 运行期修改脚本参数（只换 $argument 注入值，不重编译脚本）。 */
    @JvmStatic external fun nativeSetScriptArguments(payloadJson: String): Boolean
    /** 手动/网络事件触发：network-changed / generic；返回启动的脚本条数。 */
    @JvmStatic external fun nativeTriggerScripts(kind: String): Int
    /** 下发「五元组 → 归属 UID」整表，返回接受的条数；-1 表示参数错误。 */
    @JvmStatic external fun nativeSetUidMap(tableJson: String): Int
    @JvmStatic external fun nativeStop()
    @JvmStatic external fun nativeStats(): String
    /** D1-D3 命中摘要快照；`since` 为 ring 增量游标，首次传 0。 */
    @JvmStatic external fun nativeHits(since: Long): String
    /** 历史文件损坏后重建（保留可读部分，失败时返回 false）。 */
    @JvmStatic external fun nativeSetHitHistoryEnabled(enabled: Boolean): Boolean
    @JvmStatic external fun nativeHitsRepair(): Boolean
    /** 清空内存与持久化命中摘要。 */
    @JvmStatic external fun nativeClearHits()

    /** 活跃连接增量快照；`since` 是上次的游标，首次传 0。 */
    @JvmStatic external fun nativeConnections(since: Long): String
    /** 切网后调用：作废旧网络上的 QUIC 假活判定。 */
    @JvmStatic external fun nativeClearQuicBlackhole()
    @JvmStatic external fun nativeLogs(sinceId: Long): String
    @JvmStatic external fun nativeClearLogs()
    @JvmStatic external fun nativeDnsLogs(sinceId: Long): String
    @JvmStatic external fun nativeClearDnsLogs()
    @JvmStatic external fun nativeParseSubscription(text: String): String
    @JvmStatic external fun nativeTestRule(configJson: String, input: String): String
    /** 生成/加载 MITM CA 并导出 PEM+DER，返回 JSON（ok/pem/der/system_name/error）。 */
    @JvmStatic external fun nativeMitmExportCa(caFilePath: String, outDir: String): String
    @JvmStatic external fun nativeVersion(): String
}
