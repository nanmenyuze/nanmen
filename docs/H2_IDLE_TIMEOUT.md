# h2 空闲连接握手超时修复（2.3.8 增量）

版本：南门DNS 2.3.8 / versionCode 82 / 内核 1.12.5
范围：`core/src/mitm/h2.rs`，纯内核修复，壳层与版本号不变。

## 问题

真机日志出现成片：

```text
h2 连接处理失败: h2 服务端握手超时
```

目标为 `app/api/api.live.bilibili.com`，每条从建连到报错约 10 秒。

## 根因

`h2::serve` 把上游连接用的 `H2_CONNECT_TIMEOUT=10s` 误用于「等待客户端 h2 preface」。
App（cronet）连接池会预热多条 TLS（ALPN h2），但备用连接可能延迟启用；10 秒内没发 preface 就被当成错误杀掉并写 warn。
真实 h2 服务端对空闲连接通常更宽容（60 秒以上）；这不是致命错误，但会产生日志噪声并让 App 被迫重连。

## 修复

- 新增 `H2_CLIENT_PREFACE_TIMEOUT=60s`，与上游 `H2_CONNECT_TIMEOUT=10s` 分离。
- 客户端 preface 等待超时按空闲连接安静回收：写 info 日志并返回 `Ok`，不再 warn 误报。
- 抽出 `serve_with_preface_timeout` 供测试使用短超时；生产 `serve` 委托 60 秒。
- 上游连接超时仍保持 10 秒，不变。

## 回归

- 新增 `h2_idle_client_preface_is_reclaimed_quietly`：客户端完成 TLS、ALPN 为 h2、但永不发 preface，200 ms 测试超时后应返回 `Ok`。
- Rust 全量 185/185（184 + 1），Kotlin 118/118，Lint 0 error / 38 warning / 3 information。
- APK 内 `.so` 与 `kernel_version.txt` 清单一致；无 Android 真机，真机 h2 日志噪声未复测。
