# M3：策略组与规则分流

> 版本：`2.0` / `versionCode 70` / 内核 `1.11.5` / `minSdk 31`
> 状态：**IMPLEMENTED_WITH_BLOCKERS**（代码、JVM/内核单测、清洁构建通过；无 Android 真机、无真实节点与测速端点）

## 1. 本次交付范围

M3 把“规则命中一个组名”从静态字符串升级为可执行的分流模型：

- `select`：手动选择、缺省首成员、选择持久化。
- `fallback`：按成员顺序选择首个健康叶子，失败阈值后切换，恢复阈值后回到高优先级成员。
- `url-test`：选择最低延迟叶子；当前选择在 `best + tolerance` 内保持，避免抖动。
- 组嵌套：组可以引用组，解析结果为“顶层组 → 中间组 → 叶子节点”的链。
- 规则/最终策略可直接引用组名；`node:` 强制按节点解析。
- 组选择保存在设备侧 `AppConfig.groupSelections`，随 DataStore 快照持久化，不写入 `.conf`。
- 内核与壳层双重校验：空组、重复组名、重复成员、自引用、循环、缺失引用、重复节点、节点/组同名、失效选择。
- 运行时 TCP/UDP 分别解析；UDP 只允许 `ss` / `socks5`，TCP 探测结果绝不写入 UDP 健康。
- 规则测试返回命中来源、规则动作、策略组解析链、TCP 与 UDP 最终动作、组诊断。

## 2. 数据模型

### 2.1 配置字段

内核 JSON（写入 `config_json`）：

```json
{
  "proxy_groups": [
    {
      "name": "自动",
      "type": "url-test",
      "members": ["香港", "新加坡"],
      "test_url": "http://www.gstatic.com/generate_204",
      "interval": 600,
      "timeout": 5000,
      "tolerance": 50,
      "failure_threshold": 3,
      "recovery_threshold": 2,
      "no_node_action": "global"
    }
  ],
  "group_selections": { "手动": "香港" }
}
```

Kotlin `AppConfig` / `.conf` 使用 camelCase：

```json
{
  "proxyGroups": [
    {
      "name": "自动",
      "type": "url-test",
      "members": ["香港", "新加坡"],
      "testUrl": "http://www.gstatic.com/generate_204",
      "interval": 600,
      "timeout": 5000,
      "tolerance": 50,
      "failureThreshold": 3,
      "recoveryThreshold": 2,
      "noNodeAction": "global"
    }
  ]
}
```

`groupSelections` 是设备侧字段，`ConfigFile.KNOWN_ROOT_KEYS` 将它排除；切换/重新加载 `.conf` 时从当前设备 `AppConfig` 保留，而不是从文件覆盖。

### 2.2 默认值

| 字段 | 默认 | 约束 |
|---|---:|---|
| `type` | `select` | `select` / `url-test` / `fallback` |
| `test_url` | `http://www.gstatic.com/generate_204` | 仅 url-test / fallback 主动使用 |
| `interval` | 600 秒 | 壳层提示 5–86400 秒 |
| `timeout` | 5000 ms | 壳层提示 500–30000 ms |
| `tolerance` | 50 ms | url-test 保持容差 |
| `failure_threshold` | 3 | 连续失败达到后标记不健康 |
| `recovery_threshold` | 2 | 连续成功达到后恢复健康 |
| `no_node_action` | `global` | `global` / `block` / `direct` |

`global` 在运行时按 `block_when_no_node` 决定拦截或直连；`block` / `direct` 直接覆盖。

## 3. 解析语义

### 3.1 select

1. 如果 `groupSelections[group]` 存在且仍在 `members` 中，使用该成员。
2. 否则使用第一个成员。
3. 选择指向已删除成员时，组在校验阶段进入 `stale_selection` 禁用状态；运行时返回 `disabled_group`，不静默回落到首成员。
4. `select` 不参与后台健康检查的自动切换；手动选择的节点即使健康状态为失败，仍按选择使用。这样“手动固定节点”与“自动故障切换”不会互相干扰。

### 3.2 fallback

按 `members` 顺序逐个解析：

- 叶子健康状态不是 `Unhealthy` 即选用；`Unknown` 视为可尝试。
- 失败达到 `failure_threshold` 的叶子跳过。
- 全部成员不可用时，返回顶层组的 `no_node_action`。
- 恢复：成功达到 `recovery_threshold` 后重新变为健康，下一次解析会优先回到顺序更靠前的成员。

### 3.3 url-test

1. 解析所有健康叶子，收集延迟。
2. 计算最低延迟 `best`。
3. 如果当前 `groupSelections` 指向的叶子仍在候选中，且延迟 `<= best + tolerance`，保留当前选择。
4. 否则选最低延迟；延迟未知的候选排在已知延迟之后（`None` 视为最大值）。
5. 全部不可用时按 `no_node_action`。

`url-test` 的自动结果不写回 `groupSelections`；持久化的是手动选择。重启后首次解析先按持久化选择/首成员，再由后台探测更新健康与延迟。

### 3.4 嵌套组

`resolve_group` 递归展开，`chain` 为顶层到叶子：

```text
规则动作 GROUP:外层
  → 外层 (fallback)
  → 内层 (select)
  → 节点 A
```

- DFS 三色检测环；环上的组写入 `cycle` 诊断并禁用。
- 依赖已禁用组的组通过 `disabled_reference` 传播禁用。
- 空组、缺失引用、重复成员/节点/组名都会禁用相关组，并保留可定位的 issue path。
- UI 保存前用 `ProxyGroupValidation.wouldCreateCycle` 再检查一次，阻断“编辑后形成环”。

## 4. TCP / UDP 分离

### 4.1 运行时

`netstack::decide_action` 对规则返回的 `Action::Group` 按 `ConnKind` 选择 transport：

- TCP → `Transport::Tcp`
- UDP → `Transport::Udp`

成功时把组解析为 `Action::Node(leaf)`；失败时按组的 `no_node_action` 转 `Direct` / `Block`。

`Action::Missing`、显式节点不存在、组未解析都不会回落到“当前选中节点”，而是明确拦截/报错。

### 4.2 UDP 能力

UDP 策略只允许：

- `ss`
- `socks5`

`trojan` / `vless` / `http` 在 UDP 解析阶段返回 `udp_unsupported`，不会被当作可用成员。即使同一节点的 TCP 探测成功，也不会把结果写入 `udp.healthy` 或 `udp.latency`。

当前没有主动 UDP 探测：UDP 健康只按协议能力和已有 UDP 记录判断。`udp.healthy` 默认为 `None`（未知），不会因为 TCP 健康而变成 `true`。

### 4.3 健康检查

`run_health_loop` 只对 `url-test` / `fallback` 的叶子节点主动探测，`select` 不自动切换。

`probe_node`：

- 解析 `test_url` 的 scheme/host/port/path。
- 经真实节点建立连接；HTTPS 再包一层 TLS（校验系统根证书）。
- 发送 HTTP/1.1 `GET`，接受 `2xx` / `3xx`。
- 结果只写 `Transport::Tcp`。
- 超时来自组 `timeout`，失败/恢复计数来自组阈值。

### 4.4 规则测试

`nativeTestRule` 现在同时返回 TCP 与 UDP 结果：

| 字段 | 含义 |
|---|---|
| `ruleAction` | 规则命中的原始动作，如 `GROUP:自动` |
| `action` / `node` / `chain` | TCP 最终动作、节点、解析链 |
| `udpAction` / `udpNode` / `udpChain` | UDP 最终动作、节点、解析链 |
| `detail` | 命中来源、规则/组解析说明、TCP/UDP 差异 |
| `issues` | 本链相关的组诊断 |

UDP 不支持的显式节点显示 `UDP_UNSUPPORTED`；组因 UDP 不可用而失败时显示组策略决定的 `DIRECT` / `BLOCK`。因此规则测试不会用 TCP 结果宣称 UDP 可用。

## 5. 持久化与热更新

### 5.1 选择持久化

- 写入 `AppConfig.groupSelections`，随 `DataStoreSettingsRepository` 的 `config_json` 保存。
- `.conf` 的 `fromAppConfig` 不序列化 `groupSelections`；`toAppConfig(base)` 保留 `base` 中的组选择。
- 组编辑/删除时 UI 同步清理 `groupSelections`，避免留下指向已删除组的脏条目。
- 组选择指向已删除成员时，壳层 `ProxyGroupValidation` 与内核 `StrategySet` 都会报错，组被禁用，等待用户重新选择。

### 5.2 热更新

`nativeReloadRules` 构建新的 `RuleEngine` / `StrategySet` / DNS 后整体替换快照。M3 新增 `Ctx.decision` 读写锁：

- 新连接在 `decide_action` 期间持有读锁，看到“规则 + 策略组 + 节点 + 选中项”的同一代快照。
- 热更新持有写锁完成上述替换；释放后新连接才进入。
- 已有连接不持有该锁，继续使用已经解析出的节点/旧 `UdpMode`；不会被热更新中断。
- 如果节点在决策后、建连前被删除，`outbound::connect(Action::Node)` 返回“节点不存在（引用已失效）”，不静默回落。

## 6. 验收对照

| 验收项 | 结果 | 证据 |
|---|---|---|
| 两个规则分别命中两个独立组 | 通过 | `strategy::tests::two_rules_can_hit_two_independent_groups` |
| 选择与重启保持一致 | JVM 往返通过；真机重启未验收 | `ProxyGroupTest`、`ConfigFileTest`；`groupSelections` 走 DataStore，不写 `.conf` |
| 故障切换及恢复符合配置 | 通过（内存健康表） | `fallback_switches_after_failure_threshold_and_recovers` |
| 节点更新导致引用失效时明确报错 | 通过 | `stale_selection_is_explicit_error`、`empty_group_missing_reference_and_duplicate_node_are_detected`、UI `ConfigIssue` |
| 嵌套循环不能启用 | 通过 | `cycle_is_reported_and_cannot_be_enabled`、`ProxyGroupValidation.wouldCreateCycle` |
| 热更新已有/新建连接行为符合文档 | 代码与文档完成；真机并发未验收 | `Ctx.decision` 读写锁；`nativeReloadRules` |
| 规则测试显示命中来源/解析链/最终动作 | 代码与 JVM 编译通过；无真机点击 | `RuleTestDialog`、`nativeTestRule` |
| TCP/UDP 分开解析 | 通过 | `udp_never_uses_tcp_probe_or_trojan_node`、`rule_test_reports_udp_unsupported_without_claiming_tcp_node` |

## 7. 测试与构建

### 7.1 Rust

```text
cargo test
lib                 77 passed
cert_name_probe      1 passed
compat_fixtures     13 passed
compat_rules          1 passed
core_test            28 passed
mitm_test            14 passed
总计                134 passed / 0 failed
```

M2 基线为 123；M3 新增 11 个测试（10 个策略组/解析 + 1 个规则测试 TCP/UDP 分离）。

### 7.2 Kotlin

```text
./gradlew :app:testDebugUnitTest
94 tests / 20 suites / 0 failures / 0 errors / 0 skipped
```

新增 `ProxyGroupTest` 6 项，并扩展 `ConfigFileTest` 的 v3、策略组往返、组选择不落 `.conf`、套用配置保留设备选择。

### 7.3 Lint 与构建

```text
./gradlew :app:lintDebug
0 error / 38 warning / 3 information

./gradlew clean :app:verifyKernel :app:assembleDebug
BUILD SUCCESSFUL
```

Lint 的 warning 均为既有依赖/图标/Compose API 提示，无 error。

### 7.4 产物

- APK：`app/build/outputs/apk/debug/app-debug.apk`
- 版本：`versionCode 70`、`versionName 2.0`
- 内核：`1.11.5`，`app:verifyKernel` 通过
- APK：42,003,911 字节，SHA-256 `f690a6b1e03553f628d7a6b0292f9446c09cf69d037e5b629ae618283fb25b8c`
- 源码包 SHA-256 以交付目录 `SHA256SUMS.txt` 为准。

## 8. 已知限制

1. **无 Android 真机**：策略组编辑、规则动作选组、最终策略选组、规则测试双结果只做了编译/JVM 单测，未做真机点击与重启验收。
2. **无真实节点/测速端点**：`probe_node` 与后台健康循环没有对外部 URL 的端到端验证；故障切换测试使用内存健康表。
3. **UDP 无主动探测**：只按 `ss` / `socks5` 协议能力过滤；UDP 健康状态不会因 TCP 成功而变真。
4. **Clash/Loon 导入不转组**：配置来源解析器仍只导入规则/DNS 子集，`proxy-groups` 不会自动转换为 `ProxyGroup`；原生 JSON/UI 可创建。
5. **url-test 自动结果不持久化**：跨重启稳定的是 `select` 的手动选择；`url-test` 重启后先按持久化选择/首成员，再探测。
6. **热更新建连窗口**：决策快照原子；决策后到 `outbound::connect` 之间节点被删除时，会明确报“引用已失效”，不会回落到其他节点。
7. **失效选择没有一键清理 UI**：目前通过诊断提示和重新选择处理，未提供批量清理入口。

## 9. 关键文件

- `core/src/strategy.rs`：组校验、解析、TCP/UDP 健康、健康循环，以及 10 个策略组专项测试。
- `core/src/config.rs`：`ProxyGroup`、`proxy_groups`、`group_selections`。
- `core/src/engine.rs`：`Action::Group/Missing`、`classify_action`。
- `core/src/outbound.rs`：`probe_node`、`wrap_tls`、显式节点不回退。
- `core/src/netstack.rs`：TCP/UDP 分开解析、无节点策略、决策读锁、TCP 健康记录。
- `core/src/lib.rs`：策略快照/热更、规则测试 TCP/UDP 双结果。
- `app/src/main/java/com/namu/dns/Models.kt`：Kotlin `ProxyGroup`、组选择。
- `app/src/main/java/com/namu/dns/core/config/ConfigFile.kt`：配置 v3 与设备侧字段排除。
- `app/src/main/java/com/namu/dns/ConfigStore.kt`：下发 `proxy_groups` / `group_selections`。
- `app/src/main/java/com/namu/dns/core/config/ProxyGroupValidation.kt`：壳层校验与循环阻断。
- `app/src/main/java/com/namu/dns/ui/Dialogs.kt`：策略组编辑、规则测试双结果展示。
