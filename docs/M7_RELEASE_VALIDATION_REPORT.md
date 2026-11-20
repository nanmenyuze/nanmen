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
| `:app:testDebugUnitTest` | 23 个 suite、**113** 个测试，0 failure / 0 error / 0 skip |
| 新增 `M7BackupTest` | 3 项：正常解析、schema 拒绝、坏 `.conf` 在写入前拒绝 |
| `:app:lintDebug` | 0 error；38 warning、3 information（lint XML 共 41 issue） |
| `:app:verifyKernel` | 通过（内核 stamp 未改） |
| 清洁构建 `assembleDebug` | **BUILD SUCCESSFUL in 4m 45s，54 tasks 全执行** |
| APK 版本 | `versionCode=82 versionName=2.3.8` |
| APK 内 `.so` | `arm64-v8a` 7,859,592 B / `armeabi-v7a` 5,321,508 B，版本 1.12.5 |

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
6. **版本号**：M7 首版按要求保持 2.3.7 / 81；2.3.8 是随后“基础 DNS 跟随系统”变更的版本，内核未变。

## 11. 交付检查

- [x] 代码编译通过
- [x] 单测通过（109/109）
- [x] Lint 0 error
- [ ] 真机矩阵（无设备，blocked）
- [ ] 性能基线（无设备，blocked）
- [x] APK/源码打包（见下方交付物）
- [x] 新源码包内 `scripts/m0_validate.py` 通过（`errors: []`）
- [ ] GitHub 提交/推送（本轮只做本地交付，未推送）

## 12. 2.3.8 后续变更：基础 DNS 跟随系统

- 基础配置 DNS 从阿里 DoH 改为 `system`，读取底层 Wi‑Fi/蜂窝/以太网 DNS；没有系统 DNS 时 fail-closed，不回落第三方。
- 旧基础配置一次性迁移只匹配「阿里 DoH + 223.5.5.5 + 无 Header/Bootstrap/远端配置」；用户自定义配置不覆盖。
- 设置页新增「跟随手机默认 DNS」选项，保留手动 DoH/DoT/UDP。
- 详见 `docs/DNS_SYSTEM_DEFAULT.md`。

## 13. 交付物

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `南门DNS-2.3.8-自研内核.apk` | 44,635,933 B | `b1919c8f4a9aeb2ac911600ccf8a0d1be0f0a3484ed4b1fe5aada4f3d63aa8bc` |
| `南门DNS-2.3.8-自研内核-完整源码.zip` | 见交付时文件列表 | 见根目录 `SHA256SUMS.txt`（避免报告自引用导致 hash 变化） |

- APK 版本：`versionCode=82`、`versionName=2.3.8`。
- 源码 zip 的最终 SHA-256 以根目录 `SHA256SUMS.txt` 为准；报告不内嵌自身压缩包的 hash，避免自引用。
- 源码包从 `work/v134` 根打包，排除 `build/`、`app/build/`、`core/target/`、`.gradle/`、`.kotlin/`、`.git/`、`local.properties`、`keystore/`、`*.apk`、`*.zip`、`*.log`。
- 源码包内 `scripts/m0_validate.py` 校验结果：`versionName=2.3.8`、`versionCode=82`、`code_source_sha256=1feb6cc7dc4f637d3e461de3f569fb2256783223b9746b36c49c966a00a29c2e`、`errors: []`。
