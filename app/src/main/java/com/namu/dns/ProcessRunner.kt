package com.namu.dns

import java.io.IOException

/**
 * minSdk 24 兼容的外部进程执行器。
 *
 * 不能先 readBytes/readText 再判断超时：输出流未 EOF 时会永久阻塞。
 * 这里后台读取 stdout/stderr，同时轮询 exitValue；超时后 destroy，
 * 不调用 API 26 才有的 waitFor(timeout) / destroyForcibly。
 */
internal object ProcessRunner {
    data class Result(
        val exitCode: Int,
        val output: String,
        val timedOut: Boolean,
    )

    fun run(command: List<String>, timeoutMs: Long): Result {
        val process = ProcessBuilder(command)
            .redirectErrorStream(true)
            .start()
        process.outputStream.close()

        val output = StringBuffer()
        val reader = Thread {
            try {
                process.inputStream.bufferedReader().use { stream ->
                    val buf = CharArray(4096)
                    while (true) {
                        val n = stream.read(buf)
                        if (n < 0) break
                        output.append(String(buf, 0, n))
                    }
                }
            } catch (_: IOException) {
                // 进程被销毁或输出流提前关闭，保留已经读到的部分。
            }
        }.apply {
            isDaemon = true
            start()
        }

        val deadline = System.currentTimeMillis() + timeoutMs.coerceAtLeast(1L)
        var exited = false
        var exitCode = -1
        try {
            while (true) {
                try {
                    exitCode = process.exitValue()
                    exited = true
                    break
                } catch (_: IllegalThreadStateException) {
                    if (System.currentTimeMillis() >= deadline) break
                    Thread.sleep(50)
                }
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }

        if (!exited) {
            // destroy() 在 API 24 即可用；su 的子进程若仍不退场，读线程为 daemon，不阻塞调用方。
            process.destroy()
        }
        try {
            reader.join(300)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        return Result(if (exited) exitCode else -1, output.toString(), !exited)
    }
}
