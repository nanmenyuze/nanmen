# M2：统一配置模型与迁移

> 状态：**IMPLEMENTED_WITH_BLOCKERS**（代码/单测/清洁构建可验收；无设备与真实外部配置样本做端到端）
> 日期：2026-11-20
> 版本：南门DNS 2.0 / Android 12+ / 内核 1.11.5（内核本阶段不改）

## 1. 版本化模型

`ConfigFile` 新增 `version`（序列化 key 为 `version`，当前 `CURRENT_VERSION=2`）：

- 旧 2.x 配置文件缺 `version` 时按 v1 读取；迁移时升到 v2。
- 旧版扁平 AppConfig JSON 由 `fromLegacyJson` 补 `general` 后升到 v2。
- `general / rules / ruleSources / modules / customAds / mitm` 保持原有字段，不改含义。
- `nodes / selected / subscription` 仍属于设备侧，不写入 `.conf`。
- 未知根字段保存在 `ConfigFile.unknownRoot`，同步转入 `AppConfig.configUnknown`；保存时按原 key/JSON 值写回，不覆盖已知字段。
- `AppConfig.toJson` 也会合并未建模根字段，保证 DataStore 快照往返不丢。

## 2. 来源解析器接口

新增 `core/config/ConfigSource.kt`：

- `ConfigFormat`：`NATIVE / CLASH / LOON / SHADOWROCKET / UNKNOWN`
- `ConfigSourceParser`：`score + parse`
- `ConfigSourcePreview`：来源、模型版本、支持/部分支持/跳过、未知段落、逐项 issue、节点/规则/模块/MITM 计数
- `ConfigIssue` 的 `path` 可直接定位：`ruleSources[1].id`、`modules[0].url`、`proxy-groups[g].proxies[n]`、`[Rule] line N`

当前策略：

| 来源 | 识别 | 预览 | 导入/启用 |
|---|---|---|---|
| 原生 JSON | 是 | 是 | 是；未知根字段保留 |
| Clash YAML | 是 | 是 | 只导入规则/DNS 模式子集；节点仍走订阅导入 |
| Loon .conf | 是 | 是 | 否；避免解析成功即启用 |
| 小火箭 .conf | 是 | 是 | 否；先做识别/诊断框架 |

## 3. 迁移、备份与恢复

`ConfigFileMigration`：

- 迁移前保留 `foo.conf.legacy.bak`，重复迁移不覆盖旧备份。
- 写 `.tmp` 后原子替换；写后校验失败时从 backup 恢复。
- `recover(dir)` 在每次迁移/启动前执行：
  - 目标合法时清理残留 `.tmp`
  - 目标缺失且 `.tmp` 合法时恢复
  - 目标损坏/被截断且 `.legacy.bak` 合法时回退
- `ConfigFileStore.save` 每次覆盖前保留 `foo.conf.bak`；保存后校验内容，失败回滚；`ConfigFileInfoDialog` 增加“回退到上一版”。
- `AppContainer` 在迁移/恢复发生后重新加载 active `.conf`，避免继续用迁移前的 DataStore 快照。

## 4. 验收对照

| 验收项 | 测试/实现 |
|---|---|
| 旧配置迁移、重复迁移 | `ConfigFileMigrationTest::legacy conf gets general and migration is idempotent`、`version one config is upgraded...` |
| 失败回滚/重启恢复 | `recover removes stale tmp...`、`recover restores truncated target`、`ConfigFileStore` 写后校验 |
| 导入—保存—加载不丢已支持内容 | `ConfigFileTest::nested config round trips`、`legacy import preserves rules mitm and device nodes` |
| 未知原文保留 | `ConfigFileTest::unknown root fields survive import and re-save`、`unknown fields also survive AppConfig json round trip` |
| 错误引用/重复名称定位 | `ConfigSourceTest::native json...`、`clash preview...`、`loon preview...` |
| 旧节点/规则/MITM 运行不变 | 内核未改；配置模型测试断言 rules/mitm/nodes 不变 |

## 5. 构建与阻塞

| 项目 | M2 结果 |
|---|---|
| Kotlin 单测 | 87/87，19 suites，failures=0，errors=0 |
| Rust 单测 | 123/123（M2 未改内核，沿用 M1） |
| `verifyKernel` | 通过 |
| Lint | 0 error / 48 warning / 3 info |
| 清洁构建 | `clean app/build` 后 `:app:verifyKernel :app:assembleDebug`，BUILD SUCCESSFUL，2m 50s，38 tasks |
| APK | 41,807,303 字节；SHA-256 `a1dd4a5f4194dd604a06f842f449baa1e266fd0d955bc40b7bfa4a9698a8dd18` |
| 源码包 | 完整源码 zip；哈希见交付根目录 `SHA256SUMS.txt`（避免包内自引用） |

- 阻塞：无 Android 真机/模拟器；无真实 Loon/小火箭/Clash 配置文件、无真实订阅服务，端到端预览点击和真实节点出站未验收。
- Loon/小火箭仍只识别/预览，不启用；Clash 只导入已实现规则子集，不导入节点。
- 已知限制：原生模型保留未知**根字段**；嵌套未知参数未逐项深合并。Loon/小火箭未知段只进入预览，不落盘。
