package com.namu.dns.core

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Test

class RoutesTest {
    @Test
    fun logsRouteKeepsKind() {
        val json = Json.encodeToString(LogsRoute(LogKind.Dns))
        val decoded = Json.decodeFromString<LogsRoute>(json)
        assertEquals(LogKind.Dns, decoded.kind)
    }

    @Test
    fun defaultLogsRouteIsRuntime() {
        assertEquals(LogKind.Runtime, LogsRoute().kind)
    }

    @Test
    fun tabRoutesAreDistinct() {
        val routes = MainTab.entries.map { it.route }
        assertEquals(routes.size, routes.distinct().size)
    }
}
