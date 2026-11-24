package com.namu.dns.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.namu.dns.NodeInfo

/**
 * U6 新协议编辑表单：先落现有内核真正支持的 5 类协议；
 * 未实现的 Reality-only / Hysteria2 / TUIC 不在这里伪装成可保存。
 */
@Composable
fun AddNodeDialog(onDismiss: () -> Unit, onDone: (NodeInfo) -> Unit) {
    var type by remember { mutableStateOf("ss") }
    var name by remember { mutableStateOf("新节点") }
    var server by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("443") }
    var method by remember { mutableStateOf("aes-128-gcm") }
    var password by remember { mutableStateOf("") }
    var uuid by remember { mutableStateOf("") }
    var sni by remember { mutableStateOf("") }
    var flow by remember { mutableStateOf("") }
    var wsPath by remember { mutableStateOf("") }
    var wsHost by remember { mutableStateOf("") }
    var tls by remember { mutableStateOf(true) }
    var insecure by remember { mutableStateOf(false) }
    var group by remember { mutableStateOf("手动") }
    var error by remember { mutableStateOf<String?>(null) }

    val protocols = listOf(
        "ss" to "SS",
        "trojan" to "Trojan",
        "vless" to "VLESS",
        "vmess" to "VMess",
        "socks5" to "SOCKS5",
    )
    val valid = server.isNotBlank() && (port.toIntOrNull() ?: 0) in 1..65535 &&
        when (type) {
            "ss" -> password.isNotBlank()
            "trojan" -> password.isNotBlank()
            "vless", "vmess" -> uuid.isNotBlank()
            else -> true
        }

    NamuDialog(
        title = "添加节点",
        message = "手动填写一条节点；保存后立即进入节点池，连接中会热重载。",
        confirmText = "添加",
        confirmEnabled = valid,
        onDismiss = onDismiss,
        onConfirm = {
            if (!valid) {
                error = "请补全必填项"
                return@NamuDialog
            }
            onDone(
                NodeInfo(
                    name = name.trim().ifBlank { server.trim() },
                    type = type,
                    server = server.trim(),
                    port = port.toInt(),
                    method = if (type == "ss") method.trim().ifBlank { "aes-128-gcm" }
                    else if (type == "vmess") method.trim().ifBlank { "auto" } else null,
                    password = if (type == "ss" || type == "trojan" || type == "socks5") password.trim() else null,
                    uuid = if (type == "vless" || type == "vmess" || type == "socks5") uuid.trim().ifBlank { null } else null,
                    sni = sni.trim().ifBlank { null },
                    insecure = insecure,
                    tls = tls,
                    wsPath = wsPath.trim().ifBlank { null },
                    wsHost = wsHost.trim().ifBlank { null },
                    flow = if (type == "vless") flow.trim().ifBlank { null } else null,
                    group = group.trim().ifBlank { "手动" },
                ),
            )
        },
    ) {
        Text("协议", fontSize = 12.sp, color = NamuColors.TextSub)
        Row(
            Modifier.fillMaxWidth().padding(vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            protocols.forEach { (key, label) ->
                Column(
                    Modifier.weight(1f)
                        .background(
                            if (type == key) NamuColors.Brand.copy(alpha = 0.10f) else NamuColors.Fill,
                            RoundedCornerShape(9.dp),
                        )
                        .clickable { type = key; error = null }
                        .padding(vertical = 11.dp),
                    horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally,
                ) {
                    Text(
                        label,
                        fontSize = 12.sp,
                        fontWeight = if (type == key) FontWeight.SemiBold else FontWeight.Normal,
                        color = if (type == key) NamuColors.Brand else NamuColors.TextSub,
                    )
                }
            }
        }
        Spacer(Modifier.height(6.dp))
        NamuTextField(name, { name = it }, "节点名称", singleLine = true)
        NamuTextField(server, { server = it; error = null }, "服务器地址 / IP", singleLine = true)
        NamuTextField(port, { port = it; error = null }, "端口", singleLine = true)
        when (type) {
            "ss" -> {
                NamuTextField(method, { method = it }, "加密方法，如 aes-128-gcm", singleLine = true)
                NamuTextField(password, { password = it; error = null }, "密码", singleLine = true)
            }
            "trojan" -> {
                NamuTextField(password, { password = it; error = null }, "密码", singleLine = true)
                NamuTextField(sni, { sni = it }, "SNI（可空）", singleLine = true)
                NamuTextField(wsPath, { wsPath = it }, "WS path（可空，留空为 TCP）", singleLine = true)
                ToggleLine("TLS", tls) { tls = it }
                ToggleLine("允许不安全证书", insecure) { insecure = it }
            }
            "vless" -> {
                NamuTextField(uuid, { uuid = it; error = null }, "UUID", singleLine = true)
                NamuTextField(flow, { flow = it }, "Flow（可空，如 xtls-rprx-vision）", singleLine = true)
                NamuTextField(sni, { sni = it }, "SNI（可空）", singleLine = true)
                NamuTextField(wsPath, { wsPath = it }, "WS path（可空）", singleLine = true)
                NamuTextField(wsHost, { wsHost = it }, "WS Host（可空）", singleLine = true)
                ToggleLine("TLS", tls) { tls = it }
                ToggleLine("允许不安全证书", insecure) { insecure = it }
            }
            "vmess" -> {
                NamuTextField(uuid, { uuid = it; error = null }, "UUID", singleLine = true)
                NamuTextField(method, { method = it }, "加密方法（auto）", singleLine = true)
                NamuTextField(wsPath, { wsPath = it }, "WS path（可空）", singleLine = true)
                NamuTextField(wsHost, { wsHost = it }, "WS Host（可空）", singleLine = true)
                ToggleLine("TLS", tls) { tls = it }
                ToggleLine("允许不安全证书", insecure) { insecure = it }
            }
            "socks5" -> {
                NamuTextField(uuid, { uuid = it }, "用户名（可空）", singleLine = true)
                NamuTextField(password, { password = it }, "密码（可空）", singleLine = true)
            }
        }
        NamuTextField(group, { group = it }, "分组", singleLine = true)
        if (error != null) {
            Text(error!!, fontSize = 12.sp, color = NamuColors.Red, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun ToggleLine(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().height(48.dp),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Text(label, fontSize = 13.sp, color = NamuColors.TextMain, modifier = Modifier.weight(1f))
        IosSwitch(checked = checked, onCheckedChange = onChange)
    }
}
