package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 社区模块最常见的 Loon 旧版写法是 `^url - reject-dict`（动作前有一个 `-`）。
 * 解析器如果把 `-` 当动作名，整行会被判为不支持，导入时直接丢掉——这比规则本身失效更隐蔽。
 */
class LoonDashSyntaxTest {

    private fun parse(rewriteLines: List<String>): ParsedModule =
        ModuleParser.parse(
            buildString {
                appendLine("#!name=语法测试")
                appendLine("[MITM]")
                appendLine("hostname = app.example.com")
                appendLine("[Rewrite]")
                rewriteLines.forEach { appendLine(it) }
            }.trimIndent(),
        )

    @Test
    fun `dash separated actions are kept for the kernel`() {
        val parsed = parse(
            listOf(
                """^https?://app\.example\.com/x/v2/splash/list - reject-dict""",
                """^https?://acs\.example\.com/gw/mtop\.a\.getadv - reject-dict""",
                """^https?://api\.example\.com/ad - reject""",
            ),
        )
        assertEquals(3, parsed.loonRewrites.size)
        // 原行必须原样下发：内核按同一套语法再解析一次，壳层不能自行改写正则。
        assertTrue(parsed.loonRewrites.all { it.contains(" - ") })
    }

    @Test
    fun `both dash and non dash styles coexist`() {
        val parsed = parse(
            listOf(
                """^https?://a\.example\.com/a - reject-dict""",
                """^https?://b\.example\.com/b reject""",
            ),
        )
        assertEquals(2, parsed.loonRewrites.size)
    }

    @Test
    fun `unknown action after dash is still rejected`() {
        val parsed = parse(
            listOf(
                """^https?://a\.example\.com/a - map-local 1.2.3.4""",
                """^https?://b\.example\.com/b - reject-dict""",
            ),
        )
        // 不能因为放宽了 `-` 就把不支持的动作也收下。
        assertEquals(1, parsed.loonRewrites.size)
        assertTrue(parsed.loonRewrites.single().endsWith("- reject-dict"))
    }
}
