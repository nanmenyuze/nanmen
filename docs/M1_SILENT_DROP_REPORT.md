# M1：消除静默丢弃与修复基线缺陷

> 状态：**IMPLEMENTED_WITH_BLOCKERS**（代码、单测、清洁构建可验收；无真机/真实订阅服务，端到端未验收）
> 日期：2026-11-19
> 版本：南门DNS 2.0 / versionCode 69 / 内核 1.11.5 / Android 12+

## 1. 交付范围

### 1.1 节点/订阅逐项诊断

`core/src/subscribe.rs` 的 `ParseResult` 新增：

- `diagnostics: [{line, scheme, category, reason, raw}]`
- `diagnostic_counts: {unknown_scheme, unsupported_protocol, unsupported_param, invalid}`
- `total_lines`
- `unsupported` 现在等于所有跳过条目数，不再只覆盖少数协议

分类口径：

| category | 含义 | 示例 |
|---|---|---|
| `unknown_scheme` | 完全未知的 URI scheme | `foo://...` |
| `unsupported_protocol` | 已知但内核未实现 | `vmess://`、`ssr://`、`wireguard://`、`anytls://`、`snell://`、`shadowtls://` |
| `unsupported_param` | 协议可识别，但关键参数未实现 | VLESS `security=Reality`、非空 `flow`、`type=grpc`；SS `plugin`；Trojan `type=grpc` |
| `invalid` | URI/字段本身无效，或被解析器拒绝 | 缺 UUID/密码、无有效端口、未识别订阅格式 |

UI/日志安全：

- `raw` 是**脱敏后的原文**，不是原始凭据。
- userinfo 整体替换为 `<redacted>@host`。
- `password/passwd/pwd/token/access_token/secret/auth/authorization/uuid/key/private_key` 查询参数值替换为 `<redacted>`。
- `vmess://` 和全 Base64 `ss://` 整段隐藏。
- `warnings` 只输出条数摘要与前 3 条原因，不输出凭据。

导入行为：

- 混合有效/未知节点：有效节点照常导入，未知条目不消失，UI 显示“有效 N / 输入 M / 跳过 K”和逐条原因。
- 全部条目被跳过：不再抛出无信息的“没有解析到节点”，而是返回 0 节点诊断结果；不覆盖现有节点。
- 未识别订阅格式（例如把 Loon `.conf` 当节点列表粘贴）：输出 `invalid` 诊断，不再静默返回空。

### 1.2 AdBlock 单竖线、例外与无效语法

`ModuleParser` 修复：

- `||domain^`：后缀，命中子域名。
- `|domain|`：精确，不命中子域名。
- `@@||domain^` / `@@|domain|`：写入 `ParsedModule.allowLines`，由 `ConfigStore.rebuildModules` 和 `modules_block.txt` 交给 `FilterEngine`。
- hosts 行：`0.0.0.0 domain` / `127.0.0.1 domain` / `::1 domain`，按精确域名处理。
- 裸域名：按后缀处理。
- `$third-party` 等条件、`##` 元素隐藏、路径/通配符、连续点域名等：按原因计入 `ignoredReasons`，不再被静默截断成主域名。
- `isValidAdsDomain` 新增连续点拒绝；`normalizeAdsDomain` 支持单竖线输入。

模块页和预览明确说明：当前只实现 DNS 层可表达的语义；`$` 条件、脚本、进程名等不支持。

### 1.3 DOMAIN-REGEX / PORT 全链路

- `ModuleParser.supportedRouteTypes` 加入 `DOMAIN-REGEX`，并保留 `PORT`。
- `makeRule` 新增值校验：
  - 正则必须可编译；
  - 端口必须 1–65535；
  - IPv4/IPv6 CIDR 前缀和地址必须合法；
  - 域名必须是合法域名。
- 手动规则 UI 新增「正则」「IPv6 段」「端口」，并显示实时错误、非法值禁用“添加”。
- 路由规则仍写入 `module_rules` / 应用配置，最终由 Rust `RuleEngine` 的 `DOMAIN-REGEX` 与 `PORT` 执行。
- 非法规则不会进入持久化或引擎，而是计入 `ignoredReasons`。

### 1.4 HTTPS 代理 TLS 验证

- `parse_http` 对 `https://` 置 `tls=true`；`connect_http` 在 `node.tls=true` 时先 `tls_connect(server, port, sni)`，再发 `CONNECT`。
- 新增 `core_test::https_proxy_connects_with_tls_before_connect`：本地 rcgen/rustls TLS 代理只接受 TLS；若客户端把 HTTPS 当明文 HTTP，测试会在 TLS 握手处失败。
- 节点列表将 `http + tls=true` 显示为 `HTTPS`，分享链接也输出 `https://`，不再显示成 HTTP。

### 1.5 模块导入预览

- 预览显示：`完整支持 N 条 · 部分支持 N 条 · 跳过 N 条`。
- 明细显示阻断/分流/例外/MITM 数量，以及跳过原因分类。
- `[Rule]` 中目标策略不支持（例如策略组名丢失）时记录 `lostRouteTargets`；预览标红，确认按钮要求用户打开“我已确认丢失的分流目标”开关后才可继续。

## 2. 测试与验收对照

| 验收项 | 实现/测试 |
|---|---|
| 混合有效/未知节点不少算 | `compat_fixtures::mixed_valid_and_unknown_nodes_are_all_counted`；`total_lines=3`、`nodes=1`、`skipped=2` |
| 未知 scheme / 协议 / 参数计数 | `ssr_and_wireguard_are_diagnosed`、`tuic_and_anytls_are_diagnosed`、`vless_reality_and_grpc_are_rejected_with_diagnosis` |
| 凭据脱敏 | `diagnostic_raw_is_redacted` |
| 精确域名不误伤子域名 | `engine::adblock_single_pipe_exact_and_allow`；`exact_domain_does_not_match_subdomains` |
| 单竖线/锚点/例外 | Kotlin `adblock allow and exact forms are preserved`；Rust 同上 |
| 无效 AdBlock 语法 | Kotlin `invalid adblock syntax and conditional options are counted` |
| REGEX/PORT 解析与校验 | Kotlin `domain regex and port are validated and route targets surfaced` |
| REGEX/PORT 引擎执行 | `core_test::domain_regex_and_port_rules_execute` |
| HTTPS 不静默当 HTTP | `core_test::https_proxy_connects_with_tls_before_connect`；`http_and_https_proxy_import` |
| 既有 DNS/订阅/MITM 回归 | 全量 Rust/Kotlin 测试 |

## 3. 构建与测试结果

- 清洁构建目录：`work/m1-clean`（从 `work/v134` 复制，排除 `app/build`、`build`、`core/target`、`.gradle`、`.kotlin`）
- 构建命令：`./gradlew :app:verifyKernel :app:assembleDebug`
- 结果：`BUILD SUCCESSFUL`，38 个 task，1m 27s
- 单测：Rust **123/123**（66 lib + 1 cert + 13 compat_fixtures + 1 compat_rules + 28 core_test + 14 mitm）；Kotlin **75/75**（18 suites）
- Lint：**0 error / 48 warning**（均为依赖版本、图标/资源、`minSdk 31` 后无效 SDK 分支等既有告警）
- APK：41,774,535 字节，SHA-256 `f575c431a88672d72153e48d9c31368c7dd8d1de4a95b34835cc3e21fb6a5d57`
- APK 元数据：`com.namu.dns`、versionCode 69、versionName 2.0、minSdk 31、targetSdk 36、compileSdk 36

## 4. 当前阻塞

- 无 Android 真机/模拟器：UI 预览、开关和导入弹窗只做了编译与 JVM 单测，未做真机点击验收。
- 无真实订阅服务、真实 HTTPS 代理、真实 Loon/Shadowrocket 客户端：HTTPS 用本地 TLS 测试代理验证；Loon 端到端兼容仍未验收。
- 未实现协议（SSR/WireGuard/AnyTLS/Snell/ShadowTLS/VMess/Hysteria2/TUIC）仍会跳过；M1 只保证“被诊断”，不保证“能连接”。
- 模块 `$` 条件、脚本、进程名等仍不支持；预览会明确列出跳过原因。
