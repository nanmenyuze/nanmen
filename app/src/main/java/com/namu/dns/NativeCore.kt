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
    @JvmStatic external fun nativeStop()
    @JvmStatic external fun nativeStats(): String
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
