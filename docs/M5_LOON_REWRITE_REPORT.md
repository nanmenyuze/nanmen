# M5 报告：Loon 插件解析与重写

版本：南门DNS `2.2.1`（versionCode `73`），自研内核 `1.11.6`，Android 12+（`minSdk 31`）。

## 1. 插件逐段解析

`ModuleParser.kt` 对 `.plugin` 的段落做逐行解析，并通过 `ParsedModule.sectionStatus` 输出每段“总行数 / 可用行数 / 执行状态 / 说明”。

| 段落 | 当前行为 | 状态 |
|---|---|---|
| `[Rule]` / `[Filter]` / `[AdBlock]` | 域名/分流规则合并到当前配置 | `executed` |
| `[MITM]` | `hostname = ...` 写入 MITM 域名列表，支持 `*.example.com` | `stored`，需启用 MITM 并安装 CA |
| `[URL Rewrite]` | Surge 旧式原始行保存，交给独立 Surge 解析器 | `stored` |
| `[Header Rewrite]` | Surge 原始行保存 | `stored` |
| `[Rewrite]` | Loon 旧版/新版语法解析，支持项送内核 | `stored` 或 `unsupported` |
| `[Argument]` | 记录键值，不做 `${argument}` 运行时替换 | `partial` |
| `[General]` | 记录全局项，不改变内核 DNS/TUN 行为 | `partial` |
| `[Host]` | 记录 `host = ip`，当前不做本地 DNS 覆盖 | `partial` |
| `[Script]` | 保存原始脚本行并明确报告脚本引擎缺失 | `unsupported` |

依赖与功能缺口通过 `ParsedModule.dependencies` 展示，模块导入预览中用橙色文案提示：脚本、参数替换、Host 映射、General 全局项不会被假装执行。

`[Rule]` 同时补齐 `DOMAIN-WILDCARD` 与 `GEOIP(CN)`，与内核 M4 已实现能力对齐；`PROCESS-NAME`、`PROCESS-PATH`、`UID`、`APP` 仍明确拒绝。

## 2. Loon `[Rewrite]` 执行能力

实现位于 `core/src/mitm/loon.rs`，由 `MitmEngine.loon_rules_for(url)` 匹配，Surge `[URL Rewrite]` 与 Loon `[Rewrite]` 在引擎内完全分开编译/匹配，不互相推导语法。

### 已支持

- 旧版（Loon 3.5.1 之前）空格语法：
  - URL 替换：`header`
  - 重定向：`302`、`307`
  - 拒绝：`reject`（直接断开）、`reject-200`、`reject-img`、`reject-dict`、`reject-array`
  - 请求/响应头：`header-add`、`header-del`、`header-replace`、`header-replace-regex`，以及 `request-header-*` / `response-header-*`
  - 请求/响应体：`body-replace-regex`、`body-json-add/replace/del`
  - Mock：`mock-request-body`、`mock-response-body`（inline `data=`，`mock-data-is-base64=true`）
  - 一条规则里的多组 header/body 参数会拆成多条独立动作，不再静默丢参数
- 新版 `request if ${url} ~= /regex/flags then ...` / `response if ...`：
  - `url.replace`
  - `redirect(302/307, url)`
  - `request.header.add/del/replace/replace_regex`
  - `response.header.*`
  - `request.body.replace(_regex)`
  - `response.body.replace(_regex)`
  - `request.json.add/replace/delete`
  - `response.json.*`

### 明确不支持并展示缺口

- `*-json-jq`
- `mock-*.data-path=` 文件/URL 数据
- `script(...)`
- 含 `&&`、`||`、`${enabled}`、header 变量等复杂条件
- `response.body.mock_file`

这些行不会执行，也不会被算作“已支持”。

## 3. HTTP/1.1 与 HTTP/2 接入

- HTTP/1.1：请求 URL/头/mock/reject/redirect、请求体与 JSON、响应头与响应体/JSON 均已接入；请求体规则命中时按 2 MiB 上限缓冲，已知超限或压缩编码时跳过正文改写并原样流式转发；`Expect: 100-continue` 本地先应答。
- HTTP/2：同样接入 Loon 请求计划；请求体按 2 MiB 上限缓冲，超限回 413；请求 mock/正文动作完成后重建上游请求头，确保 Content-Type、Content-Length 与正文一致；跨域 URL 改写使用改写后的 authority/SNI，上游重试也使用新目标。
- 组帧安全：响应头动作删除 `Content-Length`/`Transfer-Encoding` 后，HTTP/1.1 透传路径会补回原始组帧头，避免 keep-alive 客户端无法判断正文结束。
- `reject` 按官方语义处理：HTTP/1.1 直接断开；HTTP/2 `RST_STREAM(CANCEL)`，不伪造 204。
- 响应体超过改写上限、gzip 解码失败、br 等无法解码时，原样透传，不截断、不放大。
- gRPC 二进制帧只允许 Surge 的 protobuf 字段改写；Loon 文本/JSON 动作不碰 gRPC 帧。

## 4. 本地导入

- 模块页：新增「从本地文件导入」，使用 `ActivityResultContracts.OpenDocument` 读取 `.plugin` / `.sgmodule` / 纯文本，先走本地预览，确认后再写入；本地来源标记为 `local://文件名`，`syncModules` 不会把它当远端 URL 重新下载。
- 配置页：`ConfigImportDialog` 新增「从本地文件导入」，读取本地 JSON / Clash / Loon / 小火箭配置（上限 2 MiB），走原有 `ConfigSourceRegistry.preview` 预览与导入。
- 模块预览限制 4 MiB，控制字符校验、重复规则统计、分段能力和脚本缺口展示均保留。

## 5. 测试与验收

- Rust 全量：**148/148**。
  - lib 82
  - cert_name_probe 1
  - compat_fixtures 13
  - compat_rules 1
  - core_test 29
  - mitm_test 18
  - protocol_e2e 4
- Kotlin：**96/96**，20 suites，0 failures / 0 errors / 0 skipped。
- Lint：**0 error / 38 warning / 3 information**。
- `verifyKernel`：通过，两个 ABI 的 `.so` 与 `kernel_version.txt` 哈希一致。
- 清洁构建：`./gradlew clean :app:verifyKernel :app:assembleDebug`，BUILD SUCCESSFUL，39 tasks，2m 31s。
- APK：42,249,671 字节，versionCode 73，versionName 2.2.1，`nativeTestRule` 符号已在两个 ABI 中导出。

M5 新增/强化的 MITM 用例：
- 旧版 `[Rewrite]`：响应体正则、响应头 add、请求头 add、302、mock response、请求体 JSON add、URL 替换、删除 Content-Length 后组帧。
- 新版语法：h2 响应头 add、响应 JSON add、h2 请求 JSON add。
- h2 请求 mock：Content-Type、Content-Length 与正文一致。
- 3 MiB 响应超过 2 MiB 上限：原样透传。
- `reject`：连接断开而非 204。

## 6. 已知边界

- 无 Android 真机、无 iOS/Loon/Shadowrocket 设备，插件界面与本地文件选择器只做代码/单元测试级验证，仍需设备复核。
- HTTP/3 未实现，不宣称已解密或可改写；QUIC 流量继续按现有透明转发处理。
- `[Argument]` 参数替换、`[General]` 全局项、`[Host]` 本地 DNS 覆盖只记录，不执行。
- `[Script]` 缺少 JavaScript 引擎，插件里依赖脚本的请求/响应处理不会执行，界面会显示为功能缺口。
- `data-path` mock、jq、复杂条件未实现，避免用猜测替代语义。
- Loon `.conf` 主动配置导入仍只导入节点/策略组/规则/DNS；`.conf` 里的 `[Rewrite]` 尚未写入 `MitmConfig.loonRewrites`，Loon 重写当前主要来自模块 `.plugin`。
