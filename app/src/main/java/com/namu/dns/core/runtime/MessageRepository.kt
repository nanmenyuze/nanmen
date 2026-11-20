package com.namu.dns.core.runtime

import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/** 一次性 UI 事件（Snackbar）。 */
interface MessageRepository {
    val messages: SharedFlow<String>
    fun show(message: String)
}

class DefaultMessageRepository : MessageRepository {
    private val _messages = MutableSharedFlow<String>(
        // 启动权限/服务错误可能在 UI 组合前产生；保留最后一条，避免 Snackbar 丢失。
        replay = 1,
        extraBufferCapacity = 16,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    override val messages: SharedFlow<String> = _messages.asSharedFlow()

    override fun show(message: String) {
        _messages.tryEmit(message)
    }
}
