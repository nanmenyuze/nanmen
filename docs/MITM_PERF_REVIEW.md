# MITM 与数据面性能清单复核（2.3.8 / 内核 1.12.5）

本文只做静态复核，**未改动代码、未重新打包**。所有结论对应工作树 `work/v134` 当前状态。
目的：把「看起来该优化」的项，和「代码里其实已经这么做」的项分开，避免按清单盲改。

## 1. 结论摘要

| 清单项 | 结论 | 依据 |
|---|---|---|
| 1. 批量收发 + 每轮预算上限 | 已满足 | `netstack.rs` `MAX_RX_BURST=64` 限制每轮读取包数；写侧 drain 至 `WouldBlock`；`pending_out` 高水位 1024 形成背压 |
| 2. 包缓冲池（slab / token 借用） | 已满足 | `rx_pool`/`tx_pool` 复用 2048 字节缓冲，`MAX_POOL=128`，`TunRxToken` 用 `Drop` 兜底回收，写成功 `recycle_tx` 回池 |
| 3. h2 流控（initial window / WINDOW_UPDATE） | 不是 bug | 所有 `RecvStream` 路径都调用 `release_capacity(len)`；发送侧 `send_chunked` 按 `capacity` 分片 + `reserve_capacity`。h2 crate 由 `release_capacity` 自动发 WINDOW_UPDATE |
| 4. 出站段（nodelay / 批量缓冲 / TLS 复用） | 部分满足 | `set_nodelay(true)` 已在 `outbound.rs:216`；TLS 配置为静态共享，rustls 0.23 默认启用 session resumption；但中继读缓冲仅 16KB、非向量 IO；HTTP/1.1 无上游连接池 |
| 5. 规则匹配负缓存 | 低收益，不建议现在做 | 当前 MITM 规则总量只有 4 条（Surge 4 + Loon 0），每请求跑 4 条正则的开销可忽略 |

## 2. 逐条说明

### 2.1 批量收发：预算上限本来就在

- 读侧：每个 TUN 可读事件最多连续读 `MAX_RX_BURST = 64` 包，避免饿死其他 `select` 分支。
- 写侧：一次循环把 `pending_out` 一直 drain 到 `WouldBlock`，然后置 `write_blocked`，改由 `AsyncFd::writable()` 唤醒。
- 端到端背压：`pending_out` 达到 `MAX_PENDING_OUT = 1024` 时暂停读 TUN，不再 `truncate(512)`。
- 结论：清单里「唯一要加的是每轮预算上限」这条，Phase 1 已落地。

### 2.2 包缓冲池：生命周期已按 token 管住

- `TunDevice` 持有 `rx_pool` / `tx_pool`，单缓冲上限 `MAX_TUN_PACKET = 2048`。
- 读 TUN 时从池取缓冲、`set_len` 后交给 smoltcp，`RxToken::consume` 结束回池；`Drop` 兜底防止早退泄漏。
- 写 TUN 成功调用 `recycle_tx` 回池；队列满才计数 `tunTxDrop`，正常路径不丢。
- 与清单建议的差异：不是 slab，但达到「不再每包 alloc/free」的目的；smoltcp 0.11 要求的「读缓冲活得和 token 一样长」由 `Drop` 保证。

### 2.3 h2 流控：release_capacity 已全覆盖

复核到的释放点：

| 位置 | 场景 |
|---|---|
| `h2.rs:706` | 转发请求体 |
| `h2.rs:824` | 改写响应体 |
| `h2.rs:1052` | 透传响应体 |
| `h2.rs:1066` | 拒绝后排空请求体 |
| `h2.rs:1169` | 另一条响应路径 |

发送侧 `send_chunked`（`h2.rs:80-98`）按当前 `capacity` 分片，窗口不足时 `reserve_capacity` + `poll_capacity` 等待，不会等攒够整块。

结论：清单说「整个文件没有显式 WINDOW_UPDATE 设置」是把「手写帧」和「库代发」混淆了。`h2` crate 收到 `release_capacity` 才会补窗口；本实现每条读取路径都释放，**不是 bug**。

真正有意义的可调项是**初始窗口大小**（默认每流 65535、每连接 65535），见第 3 节。

### 2.4 出站段

已满足：

- `set_nodelay(true)` 在 `outbound.rs:216`，仅对 `connect_any` 成功分支生效。
- TLS 配置是 `Lazy` 静态（`TLS_SECURE` / `TLS_INSECURE` / `MITM_TLS_*`），同一进程内共享同一个 `ClientConfig`，因此 rustls 的内存 session store 也是共享的，**TLS 1.3 / 1.2 会话复用默认已开**。
- h2 上游按「每条下游 h2 连接一个 `UpstreamSlot`」共享 `SendRequest`，同连接多 stream 复用一条上游。

未满足：

- `relay_stream` 读缓冲固定 16KB（`netstack.rs:593`），按 588 Mbps 估算，单连接约需 **4486 轮/秒** syscall；改成 64KB 可降到约 **1122 轮/秒**。
- 读写都是单块 `read` / `write_all`，没有 `readv` / `writev` 向量 IO。
- HTTP/1.1 上游是「一条客户端连接对一条上游连接」，没有跨连接池化；改造面较大，不建议在本轮做。

### 2.5 规则匹配负缓存：收益与规则数成正比，当前接近 0

- `mod.rs:683` `rules_for(&url)`、`mod.rs:722` `loon_rules_for(&url)` 确实每个请求都跑一次匹配。
- 但当前加载量是 `4 条 Surge 改写规则、0 条 Loon 重写`（诊断报告 `mitm:` 行可查）。4 条正则的匹配成本在微秒级，相对 TLS/h2 处理的量级可以忽略。
- 负缓存的代价是正确性：按 host 缓存「无命中」必须带配置版本失效，否则改规则不生效；按完整 URL 缓存则 h2 多 path 场景命中率低。
- 结论：收益远小于复杂度，**现在不做**。如果将来规则量到几十上百条再考虑，届时按 host 前缀做粗筛 + 配置 generation 失效。

## 3. 收益排序（按当前实测条件估算）

| 措施 | 估算收益 | 代价 | 建议 |
|---|---|---|---|
| h2 上游 initial window 65535 → 256KB | 单流上限从约 **26.2 Mbps**（20ms RTT）抬到约 **104.9 Mbps**；1MB 约 419.4 Mbps | 每条 h2 连接额外占用窗口内存 | 中档（流 256KB / 连接 1MB）可做 |
| relay 读缓冲 16KB → 64KB | 单连接 syscall 轮次从约 4486/秒 降到约 1122/秒 | 每活跃连接 +48KB | 内存敏感，缓做 |
| 规则负缓存 | 当前约等于 0（规则仅 4 条） | 正确性风险 + 失效逻辑 | 不做 |
| HTTP/1.1 上游连接池 | 省一次握手 RTT | 改造面大、keep-alive 语义复杂 | 本轮不做 |

参考数字：588 Mbps 在 20ms RTT 下的 BDP 约 **1.402 MB**，所以默认 64KB 窗口必然成为天花板。

## 4. 与当前主线的关系

- 22:42 诊断里 `mitmConns = 0`，测速走 `dlcv2.cnspeedtest.cn:8443 [DIRECT]`，**没有一条流量经过 MITM**。因此上面第 3 节的 h2 窗口优化，对这次 243 vs 588 的差异**没有直接作用**。
- h2 窗口只在「MITM 命中的域名跑大流量」时才成为瓶颈；把它作为 MITM 侧的独立优化项保留，不要和测速结论混在一起。
- 要让 MITM 真正参与对照，需要先解决命中问题：当前只在 TCP 443 判断命中，8443 不进 MITM。可选做法是临时把 8443 纳入命中端口，或改用 443 大文件域名测速。这条需要单独拍板。

## 5. 未验证项

- 以上吞吐估算基于 20ms RTT 与无损链路，未做真机复测（当前无 ADB 设备）。
- h2 初始窗口调整后的实际内存占用、以及是否触发 LMK，需要在 `mitmConns > 0` 的真机测速里观察。
- 出站 TLS 会话复用是否真的命中（可用 `mitm` 日志的握手耗时分布间接判断），当前未加显式计数。
