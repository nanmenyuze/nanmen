package com.namu.dns

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/** 实时连接增量：关闭项按 id 删除；仍在传输的长连接按变化项更新。 */
class LiveConnStoreTest {

    private fun row(id: Long, domain: String, up: Long, down: Long) = """
        {"id":$id,"uid":10086,"domain":"$domain","ip":"1.1.1.1","port":443,
         "action":"直连","rule":"规则","mitm":false,"ageMs":1,"up":$up,"down":$down,
         "upBps":0,"downBps":0}
    """.trimIndent().replace("\n", "").replace(" ", "")

    @Test
    fun closedIdsRemoveExactConnectionAndLongFlowStillUpdates() {
        val store = LiveConnStore()
        store.applySnapshot(
            JSONObject(
                """{"items":[${row(1, "long.example.com", 0, 0)},${row(2, "short.example.com", 0, 0)}],""" +
                    """"closed":[],"last":2,"total":2}""",
            ),
        )
        assertEquals(listOf(2L, 1L), store.rows().map { it.id })

        // B 先关闭，A 仍在下载：必须删 B、留 A，并刷新 A 的字节与速率。
        store.applySnapshot(
            JSONObject(
                """{"items":[${row(1, "long.example.com", 4096, 8192)}],""" +
                    """"closed":[2],"last":2,"total":1}""",
            ),
        )
        val rows = store.rows()
        assertEquals(1, rows.size)
        assertEquals(1L, rows[0].id)
        assertEquals(4096L, rows[0].upBytes)
        assertEquals(8192L, rows[0].downBytes)
        assertEquals(1, store.total)
    }

    @Test
    fun oldSnapshotWithoutClosedFallsBackToTotalTrim() {
        val store = LiveConnStore()
        store.applySnapshot(
            JSONObject(
                """{"items":[${row(1, "a.example.com", 0, 0)},${row(2, "b.example.com", 0, 0)}],""" +
                    """"last":2,"total":1}""",
            ),
        )
        assertEquals(listOf(2L), store.rows().map { it.id })
    }

    @Test
    fun clearResetsCursorAndRows() {
        val store = LiveConnStore()
        store.applySnapshot(
            JSONObject(
                """{"items":[${row(1, "a.example.com", 0, 0)}],"closed":[],"last":1,"total":1}""",
            ),
        )
        store.clear()
        assertEquals(0, store.rows().size)
        assertEquals(0, store.total)
    }
}
