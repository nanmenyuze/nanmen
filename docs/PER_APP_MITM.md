# 按 App MITM

全局 MITM 最大的副作用是：银行、支付、证书固定（pinning）的应用一旦被换证书，
握手直接失败，表现为「App 打不开、转账转不了」。这一版把 MITM 的解密范围从
「命中域名的全部流量」收窄到「命中域名 + 命中应用」。

## 三种范围

| appMode | 含义 | 与域名列表的关系 |
| --- | --- | --- |
| `all` | 默认，旧行为 | 域名命中即解密，不看应用 |
| `allow` | 仅 `apps` 内的应用 | 必须同时命中域名列表 |
| `deny` | `apps` 内的应用跳过 | 域名命中但应用在列表内 → 直接透传 |

列表在配置里存包名（`com.bank.app`，可读、换机后重新解析），下发内核前由
`AppUidResolver.resolveUids` 展开成 UID 数组，写入 `mitm.app_uids` + `mitm.app_mode`。

## 归属未知时怎么判

内核拿到的 `uid` 可能为空（例如 UDP/QUIC 没有 socket 表、无 root 读不到
`/proc/net/tcp`）。两种模式的处理相反，这是有意的：

- `allow`：**不解密**。宁可漏抓一个广告，也不能把列表外的银行 App 误伤。
- `deny`：**照常解密**。未知归属等同于「不在跳过列表」，保持全局行为，
  否则一次读表失败就会把整个 MITM 悄悄关掉。

## 实现位置

- 内核 `core/src/mitm/rewrite.rs`：`AppScope{All,Allow,Deny}`，
  `MitmEngine::should_mitm_uid(host, uid)` 先过 App 范围再过域名规则。
- 内核 `core/src/netstack.rs`：TCP accept 已经用 `(客户端端口, 目标地址, 目标端口)`
  查 `UidMap` 得到 `client_uid`（见 `docs/APP_ISOLATION.md`），MITM 判定直接复用它；
  UDP/QUIC 分支传 `None`，落上面的保守分支。
- 壳层 `MitmConfig`：`appMode` + `apps`，`ConfigStore.buildNative` 注入
  `app_mode` / `app_uids`。
- UI：MITM 页「按 App MITM」→ 全部 / 仅选中 / 跳过选中 + 应用多选（launcher
  intent 可见性，不申请 `QUERY_ALL_PACKAGES`）。

## 限制

- **无 root 时不可用**：UID 表来自 `su -c cat /proc/net/tcp`，普通进程只能看到
  自己名下的 socket。没有 root 时所有连接归属都是未知，`allow` 模式等于不解密，
  `deny` 模式等于全局解密。界面在数据页「按 App 分流」区块会给出无 root 提示。
- **UDP 443（QUIC）无法按 App 精确判断**：QUIC 走 UDP，没有可靠的应用归属，
  按上面的保守规则处理。
- 子进程（`com.app:push`）与服务进程的 socket 归属同一个 UID，按包名选择即可覆盖。
- 同一 UID 装多个包（共享 UID / 多用户）时按 UID 生效，无法再细分。
- 按 App 只决定「解不解密」，不影响分流动作；REJECT 类规则仍然按域名/IP 独立生效。
