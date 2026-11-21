# M4 协议能力矩阵（南门DNS 2.1 / 内核 1.11.5）

> 目标版本：Loon 3.5.3、Shadowrocket 2.2.66（版本来源见 `compat/targets.json`）。
> 原则：只声明经过解析或本地受控服务端验证的组合；未实现组合必须明确拒绝，不能“导入成功但连不上”。

## 1. 已实现协议与传输组合

| 协议 | 传输 | TLS | UDP | 当前状态 | 验收证据 |
|---|---|---|---|---|---|
| Shadowsocks AEAD（aes-128/256-gcm、chacha20-ietf-poly1305） | TCP | 否 | 支持 | 支持 | `core_test::ss_udp_roundtrip`、`ss_udp_replay_rejected`；TCP 由加密/分块单测覆盖 |
| SOCKS5（无认证/用户名密码） | TCP | 否 | 支持（UDP ASSOCIATE） | 支持 | `protocol_e2e::socks5_connects_roundtrip_and_reconnects`、`socks5_udp_associate_is_separate_and_roundtrips` |
| Trojan | TCP / WebSocket | TLS（默认开） | 支持（UDP ASSOCIATE） | 支持 | `protocol_e2e::trojan_plain_connects_roundtrip_and_reconnects`；`udp::udp_proto_tests::trojan_udp_roundtrip_with_local_server` |
| VLESS | TCP / WebSocket | TLS 可选 | 支持（长度分帧） | 支持 | `protocol_e2e::vless_plain_connects_roundtrip_and_reconnects`；`udp::udp_proto_tests::vless_udp_roundtrip_with_local_server` |
| HTTP / HTTPS CONNECT | TCP | HTTPS 时 TLS | 不支持 | 支持 | `core_test::http_connect_keeps_early_data`、`https_proxy_connects_with_tls_before_connect` |

说明：
- VLESS/Trojan 的 WebSocket 只支持标准 HTTP/1.1 Upgrade；gRPC、h2、HTTP/2 传输明确拒绝。
- SSH、WireGuard、AnyTLS、Snell、ShadowTLS、SSR、Juicity、Mieru 等均未实现，按 `unsupported_protocol` 诊断跳过。
- UDP 对 SS、SOCKS5、Trojan、VLESS 声明可用；HTTP 仍不声明。所有节点都受节点级 `udp: false` 约束，策略组按 UDP 解析时只认节点真实能力，不做“TCP 探测成功即 UDP 可用”的推断。

## 2. 未实现协议评估

| 协议 | 订阅出现频率判断 | 技术依赖 | 候选库/许可证评估 | M4 结论 |
|---|---|---|---|---|
| VMess | 中高（老订阅常见） | VMess AEAD、alterId、传输层 | `v2ray-core`（MIT）体积大、Go 运行时；`sing-box`（GPL-3.0）与当前闭源分发不兼容 | 不引入；准确拒绝并给出诊断 |
| VLESS Reality | 高（近两年常见） | uTLS 指纹、Reality 服务端公钥/ShortId | `sing-box`（GPL-3.0）、`rustls` 无 Reality 支持；需自研 uTLS 兼容层 | 不引入；Reality / 非空 flow / gRPC 明确拒绝 |
| Hysteria2 | 中（QUIC 订阅增长） | QUIC、BBR、带宽协商、UDP | `quinn`（MIT/Apache-2.0）可复用 QUIC；还需 Hysteria2 协议层与 UDP 转发 | 排期在现有 TCP 协议稳定后；M4 准确拒绝 |
| TUIC | 中低 | QUIC、UUID/密码、UDP relay | 同 Hysteria2，`quinn` 可复用；协议层需单独实现 | 不引入；准确拒绝 |

复用门槛（未满足则不合并）：
1. 许可证允许当前分发方式；GPL/AGPL 依赖不进入闭源 APK。
2. 提供 `arm64-v8a` / `armeabi-v7a` 预编译或可用 NDK 28 交叉编译。
3. 不引入与现有 Rust `tokio` 运行时冲突的全局运行时/事件循环。
4. 依赖可锁定、可审计，升级不破坏 `kernel_version.txt` 哈希校验。
5. 有本地或受控服务端的建立、双向、失败、重连测试，不能只做 URI 解析。

## 3. 明确拒绝的组合

| 输入 | 诊断分类 | 行为 |
|---|---|---|
| `vmess://`、`hysteria2://`、`tuic://`、`ssr://`、`anytls://`、`wireguard://` | `unsupported_protocol` | 跳过并显示原因，不生成节点 |
| VLESS `security=reality`、非空 `flow`、`type=grpc/h2` | `unsupported_param` | 跳过并显示原因 |
| Trojan `security=reality`、非空 `flow`、非 tcp/ws | `unsupported_param` | 跳过并显示原因 |
| SS `plugin=`（SIP003） | `unsupported_param` | 跳过并显示原因 |
| `PROCESS-NAME` / `PROCESS-PATH` / `UID` / `APP` 规则 | 配置导入错误 / 内核告警 | 配置导入直接拒绝并提示“没有可靠 UID/进程名数据源”；内核不静默当成不匹配 |

## 4. 验收边界

- 本轮完成：本地受控服务端的协议握手、双向传输、失败与重连；SS/SOCKS5 UDP 单独验证；未实现组合诊断。
- 未完成/受阻：无 Android 真机、无真实订阅节点、无公网测速端点；TLS 证书链和真实网络抖动仍需设备侧复核。
- 版本基线：应用 `2.1 (versionCode 71)`，内核 `1.11.5`，`minSdk 31`。
