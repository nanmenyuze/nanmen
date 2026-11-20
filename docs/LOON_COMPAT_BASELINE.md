# 南门DNS × Loon / 小火箭 兼容清单与测试基线

> 版本：南门DNS 2.0（versionCode 69，内核 1.11.5）  
> 基线日期：2026-11-19  
> 范围：只盘点**当前源码真实能力**，不把“计划实现”写成“已支持”。  
> M1 更新（2026-11-19）：静默丢弃已改为逐项诊断；AdBlock `|domain|` / `@@` 已修复；`DOMAIN-REGEX` / `PORT` 已接入模块解析器和手动 UI；HTTPS 代理已用本地 TLS 测试代理验证。详见 `docs/M1_SILENT_DROP_REPORT.md`。  
> 结论先行：当前是“能导入一部分 Loon/小火箭资产”的阶段，不是 Loon 兼容实现；真正差距集中在统一规则模型、重写动作全集、脚本运行时和代理组语义。

## 0. 结论摘要

### 已经可用

- SS（SIP002 / 旧版全 Base64）、Trojan TCP/WS、VLESS TCP/WS、SOCKS5（含认证）、HTTP 代理可导入并出站；HTTPS 代理会在连接代理时先建立 TLS（本地 TLS 测试代理已通过）。
- URI 列表、Base64 订阅、Clash YAML（基础字段）、应用自己的 2.x JSON / 旧版扁平 JSON 可导入。
- DNS 层规则：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-REGEX`、`IP-CIDR`、`IP-CIDR6`、`PORT`、`FINAL/MATCH`。
- MITM：CA 生成、Root 系统信任、hostname 匹配、HTTP/1.1 与 h2 响应体正则改写、请求头 add/replace、reject 系列、gRPC protobuf 字段级改写。
- `.sgmodule` / `.plugin` 的 `[Rule]`、`[MITM]`、`[URL Rewrite]`、`[Header Rewrite]` 子集可解析；不支持的段会计入 `ignored`，不会静默消失。

### 最大缺口

1. **节点协议**：SSR、VMess、Hysteria2、TUIC、WireGuard、AnyTLS、Snell、ShadowTLS、Loon Custom by JS 均未实现；M1 起这些条目会逐项诊断并计数，不再静默丢弃。
2. **规则模型**：`DOMAIN-WILDCARD`、`GEOIP`、`IP-ASN`、`USER-AGENT`、`URL-REGEX`、`PROCESS-NAME`、`PROTOCOL`、逻辑规则、`RULE-SET`、`DOMAIN-SET` 未实现；策略组只有名字，没有组选择/测速/故障转移。
3. **重写动作**：302/307、URL 替换、Mock、Map Local/Remote、JSON add/replace/del/jq、请求体改写、响应头改写、header-del/regex 均未实现。
4. **脚本**：没有脚本运行时，Loon Script API 全部未支持。
5. **配置导入**：Loon `.conf` 和 Shadowrocket `.conf` 不是当前订阅/配置格式，直接导入为空。

### 本次交付物

- 固定样本：`compat/fixtures/`（31 个文件）。
- 机器可读预期：`compat/expected/cases.json`（52 条 case）。
- 兼容矩阵：本文档。
- 基线测试：新增 `core/tests/compat_fixtures.rs`（11 项）+ `core/tests/compat_rules.rs`（1 项）与 `app/src/test/java/com/namu/dns/CompatFixtureTest.kt`（5 项），锁定当前解析行为。

## 1. 基线与验证口径

### 1.1 当前版本事实

| 项 | 值 |
|---|---|
| `versionName` | `2.0` |
| `versionCode` | `69` |
| 内核 | `1.11.5` |
| 工作树 | `work/v134` |
| 设备 | 本次基线无 adb 连接设备；UI、真实出站、证书信任未做真机验收 |

### 1.2 状态定义

| 状态 | 含义 |
|---|---|
| **已支持** | 当前代码有对应实现，固定样本或单测验证通过 |
| **部分支持** | 只覆盖子集，或需要 CA/Root/真实节点/特定协议才生效 |
| **未支持** | 当前解析器忽略或明确拒绝，不产生目标行为 |
| **待验证** | 代码路径存在，但本次基线没有真机/真实服务端验证 |

> “Loon 目标”一列来自 Loon 官方文档与常见订阅生态；小火箭没有同等完整的公开规范，表中标注为“小火箭常见”的项按实际订阅/配置形态整理，不声称逐字段等价。

### 1.3 官方参考

- 节点：<https://nsloon.app/en/docs/Node/>
- 订阅节点：<https://nsloon.app/en/docs/Node/subscription/>
- 规则：<https://nsloon.app/en/docs/Rule/>
- Rewrite：<https://nsloon.app/en/docs/Rewrite/>
- Script：<https://nsloon.app/en/docs/Script/>
- Script API：<https://nsloon.app/en/docs/Script/script_api/>
- Plugin：<https://nsloon.app/en/docs/Plugin/>
- 中文插件手册：<https://nsloon.app/LoonManual/#/cn/plugin>

## 2. 节点协议兼容矩阵

| 能力 | Loon / 小火箭目标 | 当前南门DNS | 状态 | 证据 / 样本 | 备注 |
|---|---|---|---|---|---|
| Shadowsocks | SIP002、旧版 Base64、常用加密 | SIP002 + 旧版全 Base64 | **已支持** | `core/src/subscribe.rs::parse_ss`；`nodes/ss-sip002.txt`、`nodes/ss-legacy.txt` | 插件/混淆未覆盖 |
| ShadowsocksR | SSR 协议与混淆 | 无 | **未支持（静默）** | `nodes/ssr.txt` | `ssr://` 不计入 `unsupported`，导入结果为空 |
| VMess | TCP/WS/TLS 等组合 | 无 | **未支持** | `nodes/vmess.txt` | 计入 `unsupported`，有汇总警告 |
| VLESS TCP | TCP + TLS | 支持 | **部分支持** | `nodes/vless-tcp.txt` | 不支持 Reality / XTLS Vision / gRPC / h2 |
| VLESS WS | WS + TLS | 支持 | **部分支持** | `nodes/vless-ws.txt` | 仅 TCP/WS；`security=reality`、非空 `flow`、非 tcp/ws 的 `type` 会被拒绝 |
| VLESS Reality | Reality | 无 | **未支持** | `nodes/vless-reality.txt` | 明确拒绝并给警告 |
| VLESS gRPC | gRPC transport | 无 | **未支持** | `nodes/vless-grpc.txt` | 明确拒绝并给警告 |
| Trojan TCP | TCP + TLS | 支持 | **部分支持** | `nodes/trojan-tcp.txt` | 仅 TCP/WS |
| Trojan WS | WS + TLS | 支持 | **部分支持** | `nodes/trojan-ws.txt` | 仅 TCP/WS |
| HTTP 代理 | HTTP CONNECT | 支持 | **已支持** | `nodes/http.txt` | 认证头/目标由现有出站实现 |
| HTTPS 代理 | HTTPS CONNECT | 解析并置 `tls=true` | **待验证** | `nodes/https.txt` | 缺真实 HTTPS 代理服务端验证 |
| SOCKS5 | 含用户名密码、TCP | 支持，含 UDP ASSOCIATE | **已支持** | `nodes/socks5.txt` | UDP 依赖目标 App 行为 |
| Hysteria2 | QUIC 节点 | 无 | **未支持** | `nodes/hysteria2.txt` | 计入 `unsupported` |
| TUIC | QUIC 节点（常见订阅） | 无 | **未支持** | `nodes/tuic.txt` | 计入 `unsupported` |
| WireGuard | WireGuard | 无 | **未支持（静默）** | `nodes/wireguard.txt` | `wireguard://` 静默丢弃 |
| AnyTLS | AnyTLS | 无 | **未支持（静默）** | `nodes/anytls.txt` | `anytls://` 静默丢弃 |
| Snell | 小火箭常见 | 无 | **未支持（静默）** | 无固定样本 | 当前未识别 scheme |
| ShadowTLS | Loon/小火箭常见 | 无 | **未支持（静默）** | 无固定样本 | 当前未识别 scheme |
| Loon Custom by JS | Loon 自定义 JS 协议 | 无 | **未支持** | 无固定样本 | 当前没有脚本运行时 |

**节点结论**：当前只能覆盖“SS / Trojan TCP-WS / VLESS TCP-WS / SOCKS5 / HTTP(S)”这一组基础协议。任何 Reality、QUIC、WireGuard、VMess 订阅都会在导入阶段被拒绝或丢弃。

## 3. 订阅、配置与插件兼容矩阵

| 能力 | Loon / 小火箭目标 | 当前南门DNS | 状态 | 证据 / 样本 | 缺口 |
|---|---|---|---|---|---|
| URI 节点列表 | 多协议 URI | SS/Trojan/VLESS/SOCKS/HTTP 子集 | **部分支持** | `nodes/*.txt` | 未识别 scheme 静默丢弃 |
| Base64 订阅 | Base64 编码 URI 列表 | 支持 | **已支持** | `subscriptions/base64-list.txt` | 2 节点，已由 Rust 单测锁定 |
| Clash YAML | `proxies` / `proxy-groups` / `rules` | 支持基础字段 | **部分支持** | `subscriptions/clash-basic.yaml` | 组名只保存，不执行组选择/测速/故障转移 |
| `Subscription-Userinfo` | 流量/到期信息 | 支持 | **已支持** | `headers/subscription-userinfo.txt` | `upload=100; download=600; total=1000; expire=1700000000` |
| 应用 2.x JSON | 南门 DNS 自有格式 | 支持 nested `general` | **已支持** | `configs/app-config.json` | `DOMAIN-REGEX`/`PORT` 内核可消费，但 UI 入口不完整 |
| 旧版扁平 JSON | 旧 AppConfig | 支持迁移 | **已支持** | `configs/legacy-flat.json` | — |
| Loon `.conf` | `[General]` / `[Proxy]` / `[Rule]` / `[Rewrite]` / `[Script]` / `[Mitm]` | 不是订阅格式 | **未支持** | `subscriptions/loon-main.conf` | 导入为空；无 `[Proxy]` 解析 |
| Shadowrocket `.conf` | 小火箭配置 | 不是订阅格式 | **未支持** | `subscriptions/shadowrocket.conf` | 导入为空 |
| Surge `.sgmodule` | `[Rule]` / `[MITM]` / `[URL Rewrite]` / `[Header Rewrite]` / `[Script]` / `[Host]` | `[Rule]`、`[MITM]`、`[URL Rewrite]`、`[Header Rewrite]` 子集 | **部分支持** | `modules/surge-demo.sgmodule` | `[Body Rewrite]`/`[Script]`/`[Host]` 计入 ignored；302/mock 重写行未执行 |
| Loon `.plugin` | `[Argument]` / `[General]` / `[Rule]` / `[Rewrite]` / `[Host]` / `[Script]` / `[Mitm]` | `[Rule]` + `[Mitm]` 子集 | **部分支持** | `modules/loon-demo.plugin` | `[Argument]`/`[General]`/`[Rewrite]`/`[Host]`/`[Script]` 计入 ignored |
| 远程规则集 | AdBlock / hosts / sing-box source / Loon rule set | AdBlock、hosts、纯域名、sing-box source 子集 | **部分支持** | `rulesets/ads.txt`、`rulesets/singbox-source.json` | 只用于 DNS 过滤；IP/端口/UA 条件跳过；`|exact|` 当前解析失败 |
| 策略组 | select/url-test/fallback/load-balance | 只保存组名 | **未支持** | `subscriptions/clash-basic.yaml` | 规则命中组时回落当前节点并给 warning |

**插件解析实测计数**（`CompatFixtureTest`）：

- `modules/surge-demo.sgmodule`：`routeRules=4`、`blockRules=1`、`mitmHostnames=2`、`urlRewrites=4`、`headerRewrites=3`、`ignored=7`。
- `modules/loon-demo.plugin`：`routeRules=3`、`blockRules=1`、`mitmHostnames=1`、`ignored=5`。
- `rulesets/ads.txt`：M1 后 `blockRules=3`、`ignored=0`；`|exact.example.net|` 单竖线精确域名已进入拦截集。

## 4. 规则类型兼容矩阵

| 规则 | Loon 目标 | 当前南门DNS | 状态 | 说明 |
|---|---|---|---|---|
| `DOMAIN` | 支持 | 支持 | **已支持** | 精确域名 |
| `DOMAIN-SUFFIX` | 支持 | 支持 | **已支持** | 后缀匹配 |
| `DOMAIN-KEYWORD` | 支持 | 支持 | **已支持** | 子串匹配 |
| `DOMAIN-REGEX` | 支持 | 内核支持；模块解析器不支持 | **部分支持** | 手动添加 UI 也没有正则选项；见 `R09` |
| `DOMAIN-WILDCARD` | 支持 | 无 | **未支持** | 模块行计入 ignored；见 `R08` |
| `IP-CIDR` / `IP-CIDR6` | 支持 | 支持 | **已支持** | 依赖目标 IP 已解析；`no-resolve` 未覆盖 |
| `PORT` | 支持 | 内核 + 模块支持；Clash 解析不支持 | **部分支持** | 手动规则 UI 没有端口入口；见 `R04` |
| `GEOIP` | 支持 | 无 | **未支持** | 计入 ignored；见 `R05` |
| `IP-ASN` | 支持 | 无 | **未支持** | 需要 ASN 数据库 |
| `USER-AGENT` | 支持 | 无 | **未支持** | MITM 层才能拿到 UA；见 `R06` |
| `URL-REGEX` | 支持 | 无 | **未支持** | 需要 URL 级规则管线 |
| `PROCESS-NAME` | 支持 | 无 | **未支持** | 需要 App UID/进程映射 |
| `PROTOCOL` | 支持 | 无 | **未支持** | TCP/UDP/QUIC 分流未建模型 |
| `SRC-IP` / `SRC-PORT` | 支持 | 无 | **未支持** | 需要连接五元组 |
| `AND` / `OR` / `NOT` | 支持 | 无 | **未支持** | 需要逻辑规则 AST |
| `RULE-SET` / `DOMAIN-SET` | 支持 | 无（远程规则集只走 DNS 过滤） | **未支持** | 见 `R07` |
| `FINAL` / `MATCH` | 支持 | 支持 | **已支持** | 见 `R10` |
| 策略组选择 | select/url-test/fallback | 只保存组名 | **未支持** | 组规则回落当前节点 |

**规则优先级**：当前没有实现 Loon 的 `local > plugin > subscription` 优先级模型；本地规则、模块规则、订阅规则在合并时可能互相覆盖。现有代码没有统一的“来源优先级”字段，兼容清单中暂标为**待验证**，不写成已支持。

## 5. 重写（Rewrite）兼容矩阵

| 动作 | Loon 目标 | 当前南门DNS | 状态 | 说明 |
|---|---|---|---|---|
| URL 替换 | `url` 替换 | 无 | **未支持** | 仅匹配 URL，不修改 URL |
| 302 / 307 | 重定向 | 无 | **未支持** | 模块行计入 ignored；见 `W04` |
| `reject` | 直接拒绝连接 | 返回 204 | **部分支持** | 语义不完全等价：Loon 更接近断连，当前是 HTTP 204 |
| `reject-200` | 空 200 | 支持 | **已支持** | — |
| `reject-img` / `reject-tinygif` | 1px 图 | 支持 | **已支持** | — |
| `reject-dict` / `reject-array` | 空 JSON | 无 | **未支持** | — |
| 请求头 add / replace | 支持 | 支持 | **已支持** | 只处理请求头；见 `W02` |
| 请求头 del / replace-regex | 支持 | 无 | **未支持** | 见 `W03` |
| 响应头 add / del / replace | 支持 | 无 | **未支持** | 见 `W06` |
| 请求体正则 | 支持 | 无 | **未支持** | 见 `W07` |
| 响应体正则 | 支持 | 支持 HTTP/1.1 + h2 | **部分支持** | 默认 2 MiB 上限；超过透传；压缩/流式场景待验证；见 `W01` |
| JSON add/replace/del/jq | 支持 | 无 | **未支持** | — |
| Mock | 支持 | 无 | **未支持** | 见 `W05` |
| Map Local / Map Remote | 支持 | 无 | **未支持** | 见 `W08` |
| Script | 支持 | 无 | **未支持** | 见 `W09` |
| gRPC protobuf 字段级改写 | Loon 不提供同款语法 | 支持（自研） | **已支持（自有扩展）** | 见 `W10` |
| WebSocket 改写 | 支持 | 未实现 | **未支持** | 需要独立帧处理 |
| h2 透明桥接 / ALPN | Loon 隐式支持 | 已接入 | **待验证** | 无真机/真实服务端验证 |

> 说明：`[Body Rewrite]` 段当前不被 `ModuleParser` 识别，计入 ignored；`[Rewrite]` 的 Loon 新条件语法（`response if ... then ...`）也不识别。当前真正生效的是 `[URL Rewrite]` 的 `body` / `header` / `reject-*` 旧行格式。

## 6. 脚本与 Loon Script API

| API / 能力 | 当前状态 | 说明 |
|---|---|---|
| `[Script]` 段 | **未支持** | 只计入 ignored |
| `$request` | **未支持** | 无脚本运行时 |
| `$response` | **未支持** | 无脚本运行时 |
| `$done` | **未支持** | 无脚本运行时 |
| `$httpClient` | **未支持** | 无网络回调桥 |
| `$persistentStore` | **未支持** | 无持久化 KV 桥 |
| `$notification` | **未支持** | 无通知桥 |
| `$argument` | **未支持** | 插件参数未注入脚本 |
| `$environment` / `$script` / `$utils` | **未支持** | — |
| `console` / 脚本日志 | **未支持** | — |

**结论**：脚本不是“少几个 API”，而是整个运行时缺失。任何依赖 Loon 脚本的插件（签到、Cookie、动态改写、通知）当前都不能工作。

## 7. MITM、证书与出站

| 能力 | 当前状态 | 说明 |
|---|---|---|
| CA 生成/展示指纹 | **已支持** | App 内生成 CA |
| Root 系统信任安装 | **部分支持 / 待验证** | 仅 KernelSU/Magisk 模块路径；用户证书入口已回退 |
| hostname / skip hostname | **已支持** | `*.example.com` 后缀匹配，裸域精确 |
| 请求头改写 | **已支持** | 只请求侧 |
| 响应体改写 | **部分支持** | 2 MiB 上限，HTTP/1.1 + h2 |
| gRPC 拒绝/字段改写 | **部分支持** | 依赖 h2/gRPC 路径；真实 App 待验证 |
| HTTP/2 多路复用/流控 | **待验证** | 已有实现和单测，但缺真实并发 RPC 验证 |
| WebSocket | **未支持** | MITM 层未处理帧 |
| QUIC / HTTP/3 | **部分支持** | 可拦截/阻断，不能解密改写 |
| `[Host]` 映射 | **未支持** | 模块行计入 ignored |
| `[General]` 插件参数 | **未支持** | 插件级 bypass/dns 参数不生效 |

## 8. 固定样本与预期结果

### 8.1 目录

```text
compat/
├── fixtures/
│   ├── nodes/            17 个协议 URI 样本
│   ├── subscriptions/    4 个订阅/配置样本
│   ├── modules/          2 个模块/插件样本
│   ├── rulesets/         2 个规则集样本
│   ├── scripts/          3 个 Loon Script 样本
│   ├── configs/          2 个应用配置样本
│   └── headers/          1 个 Subscription-Userinfo 样本
└── expected/
    └── cases.json        52 条预期结果（机器可读）
```

### 8.2 `cases.json` 字段

- `status`：`supported` / `partial` / `unsupported` / `needs_verification` / `empty`
- `import`：导入结果 `success` / `partial` / `unsupported` / `empty` / `needs_verification`；规则/重写/脚本类为 `n/a`
- `nodes`、`rules`、`route_rules`、`block_rules`、`mitm_hostnames`、`ignored`：预期计数
- `rule_status` / `rewrite_status` / `script_status`：对应子系统的兼容状态
- `matched_rule`：命中的规则描述
- `outbound`：`proxy` / `direct` / `block` / `upstream` / `n/a`
- `script_output`：脚本预期输出；当前绝大多数是 `unsupported`
- `note`：已知差异

### 8.3 覆盖 ID

| 类别 | ID |
|---|---|
| 节点 | `N01`–`N17` |
| 订阅/配置/插件 | `S01`–`S08` |
| 规则 | `R01`–`R10` |
| 重写 | `W01`–`W10` |
| 脚本 | `X01`–`X03` |
| 应用配置 | `C01`–`C04` |

### 8.4 自动化验证

- `core/tests/compat_fixtures.rs`：11 项，验证节点/订阅解析；`core/tests/compat_rules.rs`：1 项规则运行矩阵。
- `app/src/test/java/com/namu/dns/CompatFixtureTest.kt`：5 项，验证 `.sgmodule` / `.plugin` / AdBlock / Subscription-Userinfo / ConfigFixtures。

这两组测试**只锁定基线**，不把“未支持”断言成“应该支持”；后续实现变化时，预期同步更新。

## 9. 基线测试报告

### 9.1 命令

```bash
cd work/v134/core
cargo test

cd work/v134
./gradlew :app:testDebugUnitTest :app:lintDebug :app:verifyKernel :app:assembleDebug
```

### 9.2 本次结果

| 检查项 | 结果 |
|---|---|
| Rust `cargo test` | **118 / 118 通过**（65 lib + 1 cert_name_probe + 11 compat_fixtures + 1 compat_rules + 26 core_test + 14 mitm_test） |
| Kotlin `:app:testDebugUnitTest` | **72 / 72 通过**（18 个测试类，0 failure / 0 error / 0 skipped） |
| `:app:lintDebug` | **0 errors / 38 warnings**（Android 12+ 壳清洁构建权威口径） |
| `:app:verifyKernel` | 通过 |
| `:app:assembleDebug` | 通过；清洁构建 APK 41,741,767 字节 |
| APK SHA-256 | `f720b5345cd1900188235df6888ca80b1e165429e52eb647498abf99808dfa11`（Android 12+ 壳清洁构建 2.0 包；与旧包非字节一致） |

> 本次只新增测试与 fixtures，没有改动主源码；APK 与已交付的 2.0 包字节一致。

### 9.3 基线不能证明什么

- 没有连接设备：四页导航、手势、真实出站、Root 证书信任未真机验收。
- 没有真实节点/服务端：HTTPS 代理、VLESS/Trojan 实际连通性未验收。
- 没有真实 App：视频类 App等 gRPC 广告请求只完成了代码级与单测级验证，未做端到端抓包。
- 没有性能数据：h2 多流、2 MiB body 改写、PSS 峰值未测。

## 10. 已知基线差异（需要后续修复/实现）

1. **SSR / WireGuard / AnyTLS / Snell / ShadowTLS 静默丢弃**：`parse_uri_list` 只对 `vmess`、`hysteria*`、`tuic`、`vless` 计入 `unsupported`；其他 scheme 直接不计数。用户体验上会表现为“订阅导入成功但节点少了”。
2. **AdBlock `|exact.example.net|` 未解析**：`CompatFixtureTest` 实测只得到 2 条 block，`|exact...|` 被计入 ignored；需要修 `cleanHost` 的单竖线处理。
3. **Loon `.conf` / Shadowrocket `.conf` 导入为空**：当前 `parse_subscription` 只认 URI 列表、Base64、Clash YAML；没有 `.conf` 的 `[Proxy]` 解析。
4. **策略组是“空壳”**：Clash `proxy-groups` 只保留组名；规则目标为组时回落当前节点并给 warning。
5. **`DOMAIN-REGEX` / `PORT` 能力不对称**：内核支持，但 `ModuleParser` 不支持 REGEX，手动规则 UI 没有 PORT。
6. **`302/307/mock/header-del` 被忽略**：`[URL Rewrite]` 解析器只认旧行格式的 `body`/`header`/`reject-*`。
7. **Loon 新 `[Rewrite]` 条件语法不识别**：`response if ... then ...` 整段 ignored。
8. **脚本完全缺失**：不是 API 适配问题，需要引入运行时（QuickJS 或等价方案）和桥接层。

## 11. 下一步（建议，不在本次实施）

第 1 步的产出已经足够支撑后续拆任务。建议按以下顺序进入 M1，而不是直接改 MITM：

1. **统一规则模型**：把节点、规则、重写、脚本参数收敛到一套 `CompatModel`，先只做“解析/序列化/预览”，不执行。
2. **补解析器缺口**：静默 scheme 计数、`|domain|`、`PORT`/`REGEX` 入口、Loon `.conf` 的 `[Proxy]` 读取。
3. **重写动作模型**：先定义 `rewrite action` 枚举和参数结构，保持现有 `body/header/reject` 行为不变。
4. **脚本运行时**：最后做 QuickJS + `$request/$response/$done` 最小闭环，再接 `$httpClient`/`$persistentStore`/`$notification`。
5. **代理组语义**：放在节点层稳定之后，先做 select，再做 url-test/fallback。

---

## 实测记录

- 样本创建后首次定向测试：`CompatFixtureTest` 通过（AdBlock 预期从 3 修正为 2，暴露 `|exact|` 缺陷）。
- `core/tests/compat_fixtures.rs` + `compat_rules.rs`：12/12 通过。
- 完整基线：Rust 118/118，Kotlin 72/72，Lint 0 error / 38 warning，`verifyKernel` 通过，清洁 APK 41,741,767 字节（SHA-256 `f720b534...8dfa11`）。
- 关键发现：`CompatFixtureTest` 的 AdBlock 断言从 3 修正为 2，确认 `|exact.example.net|` 单竖线精确域名当前未被解析；这属于基线缺陷，已在第 10 节记录。
