# M7 产品体验与发布验证报告

版本：南门DNS 2.3.8 / versionCode 82 / 内核 1.12.5（M7 首版为 2.3.7 / 81）
日期：2026-11-20
范围：节点/订阅/策略组管理、插件预览与开关、实时连接、命中诊断、日志导出、备份恢复、网络切换、重载回滚、崩溃/迁移报告、证书安装引导、系统限制与隐私保护。

> M7 首版按用户要求保持 `2.3.7 / 81`；本轮基础 DNS 默认变更按“下次和改动一起更新版本”升到 `2.3.8 / 82`，内核仍为 1.12.5。

## 1. 结论

M7 的壳层缺口已补齐，内核与协议能力沿用 M3–M6，不在本里程碑重写：

- 新增**完整备份/恢复**：应用配置 + 全部本地 `.conf` 原文，整包校验后恢复，支持 SAF 选择文件。
- 新增**版本迁移与崩溃恢复报告**：启动迁移计数落盘；未捕获异常留痕；设置页可查看。
- 新增**重载失败回滚**：VPN 服务保留最后一次成功下发的 JSON，热重载/整核重启失败时回退；`ConfigStore.buildNative` 异常不再让 `reloading` 卡死。
- 新增**实时连接面板**：聚合连接数、当前节点、底层网络、运行时长、DNS/MITM 统计和最近连接日志。
- 新增**当前网络**展示：区分 Wi‑Fi / 移动数据 / 以太网、计费/不计费、已验证/未验证；网络切换后的隧道重建仍由服务回调完成。
- 新增**命中诊断入口**：数据页可直接打开已有 `RuleTestDialog`，与运行时使用同一套内核算规则。
- 新增**隐私与系统限制**说明：本地数据、证书边界、Private DNS、Root/非 Root、后台限制。
- 证书安装区增加四步引导：生成模块 → KernelSU/Magisk 安装 → 重启 → 回本页核对指纹/检测状态。

**未完成/未验证**：Android 真机/模拟器矩阵、VPN 授权、前后台、重启、网络切换、Root/非 Root、真实代理与目标应用测试；延迟、吞吐、内存、电量、稳定性基线均**未采集**。本机 `adb devices` 为空、`emulator -list-avds` 无输出，不能用编译结果替代设备实测，也不能编造数值。

## 2. 能力核对

| M7 项 | 状态 | 实现/入口 | 说明 |
|---|---|---|---|
| 节点管理 | 已有，M7 复核 | `ui/NodesScreen.kt` | 订阅导入/刷新、搜索、排序、分组、多选删除、单节点测速 |
| 订阅管理 | 已有，M7 复核 | `SubscriptionDialog` | Clash 订阅、Base64/节点链接，可追加或清空 |
| 策略组管理 | 已有，M7 复核 | `ProxyGroupsDialog` | select / url-test / fallback 新增、编辑、删除、成员选择、循环/空组/重名校验 |
| 插件预览 | 已有，M7 复核 | `ui/ModulesScreen.kt` | 导入前预览、分段能力、脚本能力、跳过原因、重复提示 |
| 逐项开关 | 已有（模块级） | 模块卡片 `IosSwitch` | 每个模块独立启用/停用；**不提供逐条规则开关**，避免与模块语义冲突 |
| 实时连接 | 新增面板 | `ui/M7Dialogs.kt` `LiveConnectionsDialog` | 聚合计数 + 最近连接日志；内核未暴露五元组，不伪造连接列表 |
| 命中诊断 | 新增入口 | `DataScreen` → `RuleTestDialog` | 输入域名/IPv4，按当前配置与模块规则命中 |
| 日志导出 | 已有 | `ui/LogsScreen.kt` → `Actions.exportText` | 运行日志导出 txt；DNS 日志有独立页面 |
| 备份恢复 | **新增** | `M7Backup.kt` + `BackupRestoreDialog` | AppConfig + 全部 `.conf`；恢复前整包校验 |
| 网络切换 | 已有 + 新增展示 | `NamuVpnService` 网络回调；`NetworkStatus` | Wi‑Fi/蜂窝切换后延迟重建 TUN；设置/数据页展示当前底层网络 |
| 重载失败回滚 | **新增** | `NamuVpnService.reloadConfig/rollbackToLastGood` | 保留 last-good JSON；失败回滚，仍失败才提示手动重连 |
| 崩溃恢复 | **新增留痕** | `CrashGuard.kt` + 启动迁移 | 配置层清 `.tmp`、坏目标回退；未捕获异常记录到下次启动报告 |
| 版本迁移报告 | **新增** | `MigrationReportStore.kt` | 记录 scanned/migrated/skipped/failed/recovered/restored |
| 证书安装引导 | 已有 + 新增步骤 | `ui/MitmScreen.kt` | 模块安装、仅导出证书、指纹核对、系统证书区检测 |
| 系统限制/隐私 | **新增说明** | `PrivacyAndLimitsDialog` | 本地数据、证书风险、Private DNS、Root/非 Root、后台限制 |

## 3. 备份与恢复

### 3.1 格式

```json
{
  "schema": 1,
  "createdAt": 1763...,
  "appVersion": "2.3.7",
  "versionCode": 81,
  "activeConfig": "default.conf",
  "configVersion": 3,
  "app": { "...AppConfig..." },
  "configFiles": { "default.conf": "{...}", "work.conf": "{...}" }
}
```

- 导出文件名：`南门DNS-备份-yyyyMMdd-HHmmss.json`，写入 `Download/NamuDNS`，MIME `application/json`。
- 备份包含节点密码/UUID、订阅地址、模块 URL，属于敏感数据；UI 明确提示，仅本地保存，不上传。
- 恢复上限 32 MiB；先校验 schema、`app` 配置、全部 `.conf` 均为合法 JSON，再写入。
- 恢复顺序：写 `.conf` → 切 active → 应用 AppConfig → 缺 active 时创建 → 重建模块 → 已连接则内核重载。
- 备份/恢复不改变内核版本与 App 版本号。

### 3.2 边界

- 备份不含内核二进制、APK、证书私钥；CA 私钥仍在应用私有目录，不进入备份。
- 恢复不会自动合并节点；以备份中的 AppConfig 为准，当前新增节点会被覆盖。
- 恢复后模块文件由 `ConfigStore.rebuildModules` 重新合并；模块缓存文件本身不打包。

## 4. 迁移与崩溃恢复

- 启动时 `ConfigFileStore.migrateLegacy` 继续负责：旧格式迁移、`.tmp` 清理、目标损坏从 `.legacy.bak` 恢复、默认配置创建。
- `MigrationReportStore` 将 `Result` 计数写入 `namu_maintenance` SharedPreferences；设置页展示最近一次迁移。
- `CrashGuard.install` 保留原 `UncaughtExceptionHandler`，只记录时间、线程、异常类型/消息/堆栈（最多 6000 字符），随后仍交给原处理器；不吞崩溃、不上传。
- 报告只显示计数和异常摘要，不读取节点密码、订阅 URL 或规则正文。

## 5. 重载失败回滚

`NamuVpnService` 维护 `lastGoodJson`：

1. `startVpn` / `rebuildTunnel` 成功下发后更新 `lastGoodJson`。
2. `reloadConfig` 优先 `nativeReloadRules(newJson)`；失败再 `nativeStart(pfd.fd, newJson)`。
3. 两者都失败或 `ConfigStore.buildNative` 抛异常时，调用 `rollbackToLastGood`：
   - 先 `nativeReloadRules(lastGoodJson)`；
   - 失败再 `nativeStart(pfd.fd, lastGoodJson)`；
   - 模式已变化（`activeMode != failedMode`）时交给 `rebuildTunnel`，不在旧 TUN 上强行回滚。
4. 回滚成功提示「已回滚到上一版配置」；回滚失败才提示「请手动重连」。
5. `reloading` 在 `finally` 中复位；`pendingReload` 只触发一次，避免配置生成持续失败时无限重载。

`lastGoodJson` 只在当前进程内存中保留；进程被杀后由下次冷启动按当前配置重新下发。这样不在磁盘上额外保存一份含节点密码的 JSON。

## 6. 实时连接与网络状态

- `LiveConnectionsDialog` 展示：运行状态、当前节点、活跃/累计连接、运行时长、底层网络、DNS 查询/缓存命中、MITM 解密/改写、最近连接相关日志。
- 内核对壳层当前只暴露 `activeConns/totalConns/uptime/up/down` 等聚合统计，**没有逐连接五元组**；面板明确标注这一点，不用日志拼造“连接列表”。
- `NetworkStatus` 过滤 VPN 自身，读取底层 `allNetworks`，按已验证/传输类型排序；展示 Wi‑Fi、移动数据、以太网、计费状态和链路下行估算。
- 网络切换仍由 `NamuVpnService` 的 `NetworkCallback` 触发延迟重建 TUN；本轮只补可观测性，不改变原有重建策略。

## 7. 隐私与系统限制

| 项 | 处理 |
|---|---|
| 诊断报告/日志/DNS 记录 | 仅本地文件或应用私有目录，无遥测、无账号上传 |
| 备份 | 含节点凭据，用户主动导出；UI 提示敏感 |
| MITM | 仅启用且安装 CA 后解密命中域名；银行/支付建议跳过或关闭 |
| CA 卸载 | 卸载应用前先在系统证书/模块移除；避免残留信任 |
| Private DNS | strict 模式可能绕过本地过滤；可 Root 临时关闭，非 Root 需手动处理 |
| Root/非 Root | Root 只用于可选系统证书区；未 Root 仍可用 VpnService + 用户 CA |
| 后台 | 部分 ROM 会清理 VPN 服务，需要允许自启动/后台运行 |
| VPN 并发 | Android 同时只允许一个 VPN；建立失败会提示检查其他 VPN |

## 8. 测试与构建证据

本轮已验证（无设备可执行的部分）：

| 检查 | 结果 |
|---|---|
| `:app:compileDebugKotlin` | 通过 |
| `:app:testDebugUnitTest` | 24 个 suite、**118** 个测试，0 failure / 0 error / 0 skip |
| 新增 `M7BackupTest` / `RuleSetCompatTest` | M7 备份 3 项；规则集 5 项 |
| `:app:lintDebug` | 0 error；38 warning、3 information（lint XML 共 41 issue） |
| `:app:verifyKernel` | 通过（内核 stamp 未改） |
| 清洁构建 `assembleDebug` | **BUILD SUCCESSFUL in 3m 3s，39 tasks 全执行** |
| APK 版本 | `versionCode=82 versionName=2.3.8` |
| APK 内 `.so` | `arm64-v8a` 7,856,992 B / `armeabi-v7a` 5,315,364 B，版本 1.12.5 |

> 单测总数含本轮新增 3 项；Lint 无新增 error。warning 为项目既有（deprecated `stopForeground`、`allNetworks`、SDK 版本提示等）。

## 9. Android 矩阵与性能基线（未执行）

本机没有 Android 真机，也没有可用 AVD：

```
$ adb devices
List of devices attached
（空）

$ emulator -list-avds
（空）
```

因此以下矩阵全部 **BLOCKED（无设备）**，不是“通过”：

| 矩阵项 | 计划覆盖 | 状态 |
|---|---|---|
| Android 版本 | 12 / 13 / 14 / 15 / 16 | 未执行 |
| 机型/ROM | Pixel/AOSP + 至少一个国产 ROM | 未执行 |
| VPN 授权 | 首次授权、拒绝后再次授权 | 未执行 |
| 前后台 | 切后台、锁屏、回前台 | 未执行 |
| 重启 | 软重启、强制停止后重连 | 未执行 |
| 网络切换 | Wi‑Fi ↔ 蜂窝、飞行模式 | 未执行 |
| Root/非 Root | KernelSU/Magisk 与非 Root | 未执行 |
| 真实代理 | SS/Trojan/VLESS 至少各一条 | 未执行 |
| 目标应用 | 浏览器、B 站、酷安、闲鱼等 | 未执行 |

性能基线同样未采集；下表中的“设备基线”必须由实际设备跑出，当前不填任何推测值：

| 指标 | 方法 | 当前结果 |
|---|---|---|
| 连接延迟 | 同一节点 TCP/TLS 握手多次取分位 | 未采集 |
| 吞吐 | 大文件下载/上传，记录稳定段速率 | 未采集 |
| 内存 | `dumpsys meminfo` 连接前后、长时间运行 | 未采集 |
| 电量 | 固定屏幕亮度/网络，1 小时耗电对比 | 未采集 |
| 稳定性 | 连续连接/切换/重启，记录崩溃与重连次数 | 未采集 |
| 对比环境 | 同机同网，关闭 VPN / 其他客户端 | 未建立 |

## 10. 已知限制与下一步

1. **无设备**：M7 验收矩阵、真实代理、目标应用和性能基线必须在有设备的环境补跑；报告不得用编译时间、静态内存或估算值代替。
2. **无逐连接五元组**：内核对壳层只提供聚合计数；要展示真实连接列表，需要内核新增连接事件/查询接口，属于后续内核任务。
3. **无逐条规则开关**：当前是模块级开关；逐条规则开关会改变模块合并语义，未在本轮引入。
4. **`lastGoodJson` 不持久化**：仅覆盖运行中的热重载回滚；冷启动失败仍按当前配置处理。
5. **备份不含 CA 私钥**：换机恢复后需要重新生成/安装 CA。
6. **版本号**：M7 首版按要求保持 2.3.7 / 81；2.3.8 是随后“基础 DNS 跟随系统 + 规则集/PROTOCOL”增量版本，版本号保持 2.3.8 / 82，内核版本仍为 1.12.5。

## 11. 交付检查

- [x] 代码编译通过
- [x] 单测通过（118/118，24 suites）
- [x] Lint 0 error
- [ ] 真机矩阵（无设备，blocked）
- [ ] 性能基线（无设备，blocked）
- [x] APK/源码打包（见下方交付物）
- [x] 新源码包内 `scripts/m0_validate.py` 通过（`errors: []`）
- [x] GitHub 提交/推送（`main` 与 `v2.3.8`，提交见 `git log`）

## 12. 2.3.8 后续变更：基础 DNS 跟随系统

- 基础配置 DNS 从阿里 DoH 改为 `system`，读取底层 Wi‑Fi/蜂窝/以太网 DNS；没有系统 DNS 时 fail-closed，不回落第三方。
- 旧基础配置一次性迁移只匹配「阿里 DoH + 223.5.5.5 + 无 Header/Bootstrap/远端配置」；用户自定义配置不覆盖。
- 设置页新增「跟随手机默认 DNS」选项，保留手动 DoH/DoT/UDP。
- 详见 `docs/DNS_SYSTEM_DEFAULT.md`。

## 12.1 2.3.8 增量：规则集与 PROTOCOL

- `RULE-SET` / `DOMAIN-SET` 在导入/同步时拉取并缓存，`rebuildModules` 展开为普通规则；集合策略覆盖行内策略。
- `DOMAIN-SET` 支持 `.x` 后缀（含 apex）、`*.x` 通配子域、裸域名精确匹配。
- `PROTOCOL,TCP|UDP` 由内核按连接类型匹配；其他值加载期拒绝并告警。
- 纯规则集模块可导入；拉取失败保留旧缓存，未缓存时不生效。
- Rust 185/185、Kotlin 118/118（24 suites）、Lint 0 error / 38 warning / 3 information。
- 详见 `docs/RULESET_PROTOCOL.md`。

## 12.2 2.3.8 增量：h2 空闲连接握手超时修复

- 问题：`h2 服务端握手超时` 成片出现，目标含 `app/api/api.live.bilibili.com`，每条约 10 秒。
- 根因：`h2::serve` 把上游连接的 10 秒超时误用于等待客户端 h2 preface；cronet 预热的备用 TLS 连接 10 秒内不发 preface 就被当成错误。
- 修复：客户端 preface 等待改为 60 秒，超时按空闲连接安静回收（info 日志 + `Ok`）；上游连接仍 10 秒。
- 回归：新增 `h2_idle_client_preface_is_reclaimed_quietly`；Rust 185/185。
- 详见 `docs/H2_IDLE_TIMEOUT.md`。

## 12.3 2.3.8 增量：TUN 数据面 Phase 1

- 目标：不换协议栈，先消除静默丢包、复用缓冲、把写阻塞从固定 20ms 重试改为事件驱动。
- 收发侧增加缓冲池：读 TUN 直接复用 2048 字节缓冲，`set_len` 后交给 smoltcp；TxToken 复用缓冲，写成功后回池。
- `transmit()` 在 tx 队列达到 256 时返回 `None`，让 smoltcp 保留在 socket 发送缓冲，不再静默丢包；新增 `tunTxBackpressure` 计数。
- `pending_out` 高水位改为 1024：达到后暂停从 tx 队列取包并暂停读 TUN，形成端到端背压；不再 `truncate(512)`。
- 写 TUN 返回 `WouldBlock` 后，用 `AsyncFd::writable()` 等待可写事件；有 backlog 时兜底定时器缩短到 1ms。
- 诊断页/报告新增「背压」计数；`tunPendingDrop` 保留为极端兜底字段，当前路径不再触发。
- Rust 191/191；Kotlin 119/119（24 suites）；Lint 0 error / 38 warning / 3 information。
- 未做真机吞吐复测（当前无 ADB 设备）；Phase 1 的验收点是 `tunTxDrop`、`tunPendingDrop` 和 `tunWriteWouldBlock` 是否下降，而不是直接承诺回到 588 Mbps。

## 12.4 2.3.8 增量：128K TCP/MITM 缓冲档位

- smoltcp 每条 TCP 连接 rx/tx 缓冲从 32K 抬到 128K；MITM 本地 duplex 从 64K 抬到 128K；DNS TCP duplex 保持 64K，DNS 查询路径不动。
- 每活跃 TCP 连接的协议栈缓冲从 64K 增到 256K，增量约 192KB；100 条活跃连接约 +18.75MB，叠加任务/管道开销后接近旧评估的 +25MB；连接上限和正文改写内存上限不变。
- 新增常量断言 `buffer_plan_uses_128k_tcp_and_mitm_pipes`，锁定 TCP/MITM/DNS 三档缓冲，防止后续误回退。
- 验证：Rust 192/192；Kotlin 119/119（24 suites）；Lint 0 error / 38 warning / 3 information；M0 `errors: []`。
- 当前无 ADB 设备，未做真机吞吐复测；下一轮需要在 `mitmConns > 0` 的 A/B 测速里同时观察下行、Native 堆和 LMK 压力。

## 12.5 2.3.8 增量：64K 档回退 + 出站数据事件唤醒

- 回退动因：128K 档在真机诊断中未见下行改善。三次诊断报告里测速 8443 连接全部为 `DIRECT`，MITM 一次未介入，`mitmConns` 为 0 或 3 次握手失败，A/B 无法对比；同时每活跃连接的协议栈缓冲从 64K 抬到 256K，Native 堆与 PSS 上升。按用户决定回退到基线档位。
- 回退内容：`TCP_SOCKET_BUFFER` 128K → 32K（每方向 32K，合计 64K）；`MITM_DUPLEX_CAP` 128K → 64K；`DNS_TCP_DUPLEX_CAP` 保持 64K。断言测试改名 `buffer_plan_uses_32k_tcp_and_mitm_pipes`。
- 同期修正数据面唤醒（静态核实后确认的架构缺口）：
  - 主循环新增共享 `Arc<Notify>`：`relay_stream` 每读到上游数据并送入 `from_relay` 通道后 `notify_one()`，主循环 `select!` 新增 `notified()` 分支。此前唤醒源只有 TUN 可读、TUN 可写、UDP 响应、DNS 响应和定时器，出站数据无专属唤醒。
  - 非空闲兜底间隔维持 20ms（`IDLE_SAFETY_WAIT_MS`），并新增 `has_relay_backlog`：通道仍有残留时按 1ms 跑，避免被背压打断的一轮要等兜底定时器。兜底不靠收紧定时器去刷吞吐——挂着空闲长连接时更密的定时器是纯耗电，快路径由 Notify 负责。
  - 每轮从 relay 通道搬入 `pending` 的块数 16 → 32（`RELAY_DRAIN_BURST`）。此前单连接稳态吞吐被「块数 × 块大小 / 轮询间隔」限制在约 100 Mbps 量级。
  - 背压语义不变：通道满时 `server_tx.send().await` 阻塞并收缩上游接收窗口，不静默丢包。
- 新增测试 `relay_drain_is_event_driven_not_timer_bound`，锁定「兜底 ≥20ms、单轮搬运 ≥512KB」：出站提速必须来自事件唤醒，不能靠缩短定时器。
- 验证：Rust 193/193；Kotlin 119/119（24 suites）；Lint 0 error / 38 warning / 3 information；M0 `errors: []`。
- 真机对照（00:56 诊断，运行 1 分 47 秒）：背压 0 次、backlog 峰值 116、`tunTxDrop`/`tunPendingDrop` 均为 0，下行 1.79 GB、上行 812 MB；Native 堆 33.5 MB、PSS 269,695 KB，较 128K 档的 47.6–54.4 MB / 274,540–277,095 KB 明显回落。该次会话 `mitmConns` 仍为 0，MITM 未介入，A/B 对比仍缺。
- 新内核哈希：arm64 `0dcc5d2316c1fdeb6956151c575567c33a0303bcf674491f7b127a3562cca626`；armv7 `4390cba29185559aa46869693b7ce30e2fec1065087504c420b382aba083fcbc`。
- 未做真机吞吐复测（当前无 ADB 设备）。验收点：同一测速服务器、同一链路速率下，DNS+MITM 全开与关 MITM 的下行差距是否收窄，且 `tunTxDrop`/`tunPendingDrop` 保持为 0。

## 12.6 2.3.8 增量：出站多地址改并发竞速

- 问题：`connect_any` 串行尝试前两个地址、每个 4s；注释自述「双栈里常见首个地址不可达」，却仍串行等首个地址超时才试下一个，双栈场景白等约 4s，表现为「半天才出数据」。
- 修复：拆出 `connect_one`（单地址 4s 超时 + `set_nodelay`）与 `race_two`（并发竞速），`connect_any` 按候选数分派。两个地址同时发起，先成功者胜出；先返回失败则继续等另一个（另一个一直在并发跑，不额外增加等待）。
- 影响面：仅当候选地址 ≥2 时行为改变。当前配置 `fakeIp=false` 且节点数为 0，DIRECT 走「已有真实 IP 直接连」分支只传单地址，改动前不触发串行等待；开启 fake-IP 或使用域名节点时才会命中。
- 核算后未改的部分（记录判断依据）：
  - 「DIRECT 绕过自研 DNS」不成立：fake-IP 分支走 `dns.resolve_real()`，内部有 `real_cache`、`block_aaaa`、规则 `filter` 与加密上游；非 fake-IP 分支直接使用 TUN 捕获的真实 IP，不重复解析。
  - 真正走系统解析的是 `tls_connect()` → `tcp_connect()` → `resolve_all()` → `lookup_host`，用于 MITM 上游连目标站点。当前 `mitmConns=0` 未命中，收益低且需把 `DnsEngine` 透传到 TLS 调用链，暂不改。
- 验证：Rust 193/193；清洁构建 `verifyKernel` 通过。

## 12.7 2.3.8 增量：UDP 目的端点缓冲放大

- 问题：`add_udp_dst_socket` 每方向仅 `8192 字节 / 16 metadata`。QUIC 包约 1400 字节，只装得下 5 个包；而 UDP 无背压语义，缓冲满即丢，大流量 QUIC 会被这个缓冲先卡住。
- 修复：改为 `UDP_DST_BUF = 32KB`、`UDP_META_SLOTS = 64`（metadata 槽位必须与缓冲容量匹配，否则槽位先耗尽会提前丢包）。每目的端点内存从 16KB 增至 64KB，增量 48KB。
- 新增测试 `udp_dst_buffer_fits_real_quic_bursts`，锁定「32KB 至少容纳 20 个 QUIC 包且 metadata 槽位不先耗尽」。
- 未改（评估后记录）：UDP 决策仍是每包 `reverse.lock()` + `decide_action` 重算，`udp_clients` 只缓存 tx 句柄不缓存 action/mode。按五元组缓存 action 需要配合规则热更的失效机制，风险中等，暂不落地。出站连接池同样暂不做——当前 `mitmConns=0`，MITM 未命中，连接池无用户。
- 验证：Rust 194/194。

## 13. 交付物

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `南门DNS-2.3.8-自研内核.apk` | 44,652,317 B | `de8162ed4cc825a4d5a97016c1e3a822bde74a096f07d9b470928efe4af78baa` |
| `南门DNS-2.3.8-自研内核-完整源码.zip` | 见交付时文件列表 | 见根目录 `SHA256SUMS.txt`（避免报告自引用导致 hash 变化） |

- APK 版本：`versionCode=82`、`versionName=2.3.8`。
- 源码 zip 的最终 SHA-256 以根目录 `SHA256SUMS.txt` 为准；报告不内嵌自身压缩包的 hash，避免自引用。
- 源码包从 `work/v134` 根打包，排除 `build/`、`app/build/`、`core/target/`、`.gradle/`、`.kotlin/`、`.git/`、`local.properties`、`keystore/`、`*.apk`、`*.zip`、`*.log`。
- 源码包内 `scripts/m0_validate.py` 校验结果：`versionName=2.3.8`、`versionCode=82`、`code_source_sha256=1fbc4ec71ffaac81c22aefc4731933c07ac13d77f47da2852eddfa77b0be645c`、`errors: []`。
