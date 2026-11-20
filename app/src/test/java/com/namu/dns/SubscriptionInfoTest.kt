package com.namu.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SubscriptionInfoTest {
    @Test
    fun `parses standard subscription userinfo`() {
        val info = Actions.parseSubscriptionUserInfo(
            "upload=100; download=600; total=1000; expire=1700000000",
            now = 123L,
        )!!
        assertEquals(100L, info.upload)
        assertEquals(600L, info.download)
        assertEquals(1000L, info.total)
        assertEquals(1700000000000L, info.expireAt)
        assertEquals(300L, info.remaining)
        assertEquals(70, info.usedPercent)
        assertEquals(123L, info.updatedAt)
    }

    @Test
    fun `accepts millisecond expiry and unknown fields`() {
        val info = Actions.parseSubscriptionUserInfo(
            "download=1024; expire=1700000000000",
        )!!
        assertEquals(1700000000000L, info.expireAt)
        assertEquals(1024L, info.used)
        assertEquals(0, info.usedPercent)
    }

    @Test
    fun `empty or zero header is ignored`() {
        assertNull(Actions.parseSubscriptionUserInfo(null))
        assertNull(Actions.parseSubscriptionUserInfo("upload=0; download=0; total=0; expire=0"))
    }
}
