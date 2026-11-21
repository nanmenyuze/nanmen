package com.namu.dns

/**
 * Android 没有给 VpnService 暴露「这个包属于哪个 App」的接口：
 * TUN 里只能看到五元组，看不到 UID。要按 App 分流，只能拿五元组去
 * 系统 socket 表反查归属者。
 *
 * 数据来源是 `/proc/net/tcp` 与 `/proc/net/tcp6` 的 `uid` 列。
 * 普通应用进程读这两个文件只能看到自己名下的 socket（SELinux 限制），
 * 拿不到别的 App，所以必须借 root 读全表；没有 root 时本模块返回空表，
 * 内核侧会把 UID 视为「未知」，规则不生效而不是猜。
 *
 * 解析格式（列以空白分隔）：
 *   sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
 *    0: 0100007F:1F90 00000000:0000 0A ...                                      1000      0 12345
 * 索引 1 是本地地址、2 是远端地址、7 是 uid。
 * 地址是「4 字节十六进制小端」；IPv6 是 4 个 32 位小端字。
 */
internal object UidResolver {

    /** 一条 socket 归属记录。IP 已还原成标准文本形式。 */
    data class Entry(
        val localIp: String,
        val localPort: Int,
        val remoteIp: String,
        val remotePort: Int,
        val uid: Int,
    )

    /**
     * 解析 `/proc/net/tcp`（[ipv6] = false）或 `/proc/net/tcp6`（true）的文本。
     * 纯函数，便于单元测试；不负责读取。
     */
    fun parseProcNet(text: String, ipv6: Boolean): List<Entry> {
        val out = ArrayList<Entry>()
        for (line in text.lineSequence()) {
            val t = line.trim()
            // 跳过表头（以 "sl" 开头）与空行。
            if (t.isEmpty() || t.startsWith("sl")) continue
            val f = t.split(WHITESPACE)
            if (f.size < 10) continue
            val local = splitAddrPort(f[1]) ?: continue
            val remote = splitAddrPort(f[2]) ?: continue
            // 无对端的 socket（LISTEN / 未连接）没有归属意义，跳过。
            if (remote.second == 0) continue
            val uid = f[7].toIntOrNull() ?: continue
            val lip = decodeIp(local.first, ipv6) ?: continue
            val rip = decodeIp(remote.first, ipv6) ?: continue
            out.add(Entry(lip, local.second, rip, remote.second, uid))
        }
        return out
    }

    private val WHITESPACE = Regex("\\s+")

    private fun splitAddrPort(s: String): Pair<String, Int>? {
        val i = s.lastIndexOf(':')
        if (i <= 0 || i == s.length - 1) return null
        val port = s.substring(i + 1).toIntOrNull(16) ?: return null
        return s.substring(0, i) to port
    }

    /**
     * proc 表里的地址字段是主机字节序的十六进制：
     * IPv4 为 1 个小端 32 位字（"0100007F" = 127.0.0.1），
     * IPv6 为 4 个连续的小端 32 位字，拼成 16 字节。
     */
    fun decodeIp(hex: String, ipv6: Boolean): String? {
        if (!ipv6) {
            if (hex.length != 8) return null
            val v = hex.toLongOrNull(16) ?: return null
            val b = ByteArray(4)
            for (k in 0..3) b[k] = ((v shr (8 * k)) and 0xFF).toByte()
            return b.joinToString(".") { (it.toInt() and 0xFF).toString() }
        }
        if (hex.length != 32) return null
        val bytes = ByteArray(16)
        for (word in 0..3) {
            val chunk = hex.substring(word * 8, word * 8 + 8)
            val v = chunk.toLongOrNull(16) ?: return null
            for (k in 0..3) bytes[word * 4 + k] = ((v shr (8 * k)) and 0xFF).toByte()
        }
        // 压缩成标准 IPv6 文本（省略全零段，:: 只出现一次）。
        return formatIpv6(bytes)
    }

    private fun formatIpv6(bytes: ByteArray): String {
        val groups = (0 until 8).map { i ->
            ((bytes[i * 2].toInt() and 0xFF) shl 8) or (bytes[i * 2 + 1].toInt() and 0xFF)
        }
        // 找最长全零段做 :: 压缩。
        var bestStart = -1
        var bestLen = 0
        var curStart = -1
        var curLen = 0
        for ((i, g) in groups.withIndex()) {
            if (g == 0) {
                if (curStart < 0) { curStart = i; curLen = 0 }
                curLen++
                if (curLen > bestLen) { bestLen = curLen; bestStart = curStart }
            } else {
                curStart = -1; curLen = 0
            }
        }
        if (bestLen < 2) return groups.joinToString(":") { it.toString(16) }
        val head = groups.take(bestStart).joinToString(":") { it.toString(16) }
        val tail = groups.drop(bestStart + bestLen).joinToString(":") { it.toString(16) }
        return "$head::$tail"
    }

    /**
     * 读一次全表。返回 null 表示没有 root / 读取失败，
     * 调用方应把 UID 当作未知而不是当成 0（root 的 UID 是 0，混淆会误杀）。
     *
     * 顺序很关键：**必须先试 root**。普通进程读 `/proc/net/tcp` 虽然能成功，
     * 但 SELinux 只放行自己名下的 socket，拿到的是残缺表——如果先走普通读取，
     * 就会永远「读成功」而永远缺其他 App 的条目，UID 规则在大半场景静默失效。
     * 因此普通读取只作为无 root 时的兜底（至少能覆盖本 App 自己的连接）。
     */
    fun readAll(): List<Entry>? {
        val root = readAsRoot()
        if (root != null) return root
        val v4 = readAsSelf("/proc/net/tcp") ?: return null
        val v6 = readAsSelf("/proc/net/tcp6") ?: ""
        return parseProcNet(v4, ipv6 = false) + parseProcNet(v6, ipv6 = true)
    }

    /** 一次 su 调用读两份表，省掉一次 fork/exec——这张表是秒级轮询的。 */
    private fun readAsRoot(): List<Entry>? {
        val cmd = "cat /proc/net/tcp; echo $SPLIT; cat /proc/net/tcp6"
        val r = ProcessRunner.run(listOf("su", "-c", cmd), 3000)
        if (r.timedOut || r.exitCode != 0 || r.output.isBlank()) return null
        val parts = r.output.split(SPLIT)
        if (parts.size < 2) return null
        return parseProcNet(parts[0], ipv6 = false) + parseProcNet(parts[1], ipv6 = true)
    }

    private fun readAsSelf(path: String): String? = runCatching {
        val f = java.io.File(path)
        if (f.canRead()) f.readText() else null
    }.getOrNull()

    private const val SPLIT = "__NAMU_UID_SPLIT__"

    /**
     * 序列化成内核认识的紧凑数组：
     * `[["10.10.10.1",54321,"1.2.3.4",443,10200], ...]`
     *
     * 不用 org.json：这份表每秒都在生成，手写拼接省掉一次完整对象树分配。
     * 地址都是本模块自己格式化出来的标准文本，不含需要转义的字符。
     */
    fun toJson(entries: List<Entry>): String {
        val sb = StringBuilder(entries.size * 48 + 4)
        sb.append('[')
        for ((i, e) in entries.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append('[')
            sb.append('"').append(e.localIp).append("\",")
            sb.append(e.localPort).append(',')
            sb.append('"').append(e.remoteIp).append("\",")
            sb.append(e.remotePort).append(',')
            sb.append(e.uid)
            sb.append(']')
        }
        sb.append(']')
        return sb.toString()
    }

}
