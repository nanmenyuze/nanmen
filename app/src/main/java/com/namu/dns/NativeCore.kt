package com.namu.dns

object NativeCore {
    val available: Boolean = try {
        System.loadLibrary("nanmen_core")
        true
    } catch (_: Throwable) {
        false
    }

    @JvmStatic external fun nativeStart(tunFd: Int, configJson: String): Boolean
    @JvmStatic external fun nativeReloadRules(configJson: String): Boolean
    /** 下发「五元组 → 归属 UID」整表，返回接受的条数；-1 表示参数错误。 */
    @JvmStatic external fun nativeSetUidMap(tableJson: String): Int
    @JvmStatic external fun nativeStop()
    @JvmStatic external fun nativeStats(): String

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
