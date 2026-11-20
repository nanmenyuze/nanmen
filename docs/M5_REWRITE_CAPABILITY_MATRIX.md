# M5 Loon 插件与重写能力矩阵（南门DNS 2.2.1 / 内核 1.11.6）

> 原则：只列出经解析器、内核单测或本地受控 HTTP/1.1、HTTP/2 源站验证的能力。
> `[Rewrite]` 与 Surge `[URL Rewrite]` 是两套语法，支持一种不代表支持另一种。

## 1. 插件段落

| 段落 | 解析 | 执行 | 状态 | 说明 |
|---|---|---|---|---|
| `[Rule]` | 是 | 是 | supported | 常用域名/IP/端口/通配/GEOIP(CN) 规则 |
| `[Filter]` / `[AdBlock]` | 是 | 是 | supported | 阻断/例外规则 |
| `[MITM]` | 是 | 存储 | partial | `hostname = ...` 写入 MITM；需手动启用并安装 CA |
| `[URL Rewrite]` | 是 | 是（Surge 子集） | partial | 走独立 Surge 解析器，不按 Loon 语法推断 |
| `[Header Rewrite]` | 是 | 是（Surge 子集） | partial | 同上 |
| `[Rewrite]` | 是 | 是（Loon 子集） | partial | 见第 2 节 |
| `[Argument]` | 是 | 否 | partial | 只记录键值，不展开 `${argument}` |
| `[General]` | 是 | 否 | partial | 只记录，不改内核 DNS/TUN |
| `[Host]` | 是 | 否 | partial | 只记录 `host = ip`，不做本地 DNS 覆盖 |
| `[Script]` | 原始行保存 | 否 | unsupported | 无 JavaScript 引擎，界面显示功能缺口 |

## 2. Loon `[Rewrite]` 动作

| 动作 | 旧版语法 | 新版语法 | 状态 | 验收 |
|---|---|---|---|---|
| URL 替换 | `header <url>` | `url.replace(...)` | supported | h1 E2E：`/plain` -> `/feed` |
| 重定向 302/307 | `302` / `307` | `redirect(...)` | supported | h1 E2E 302 + Location |
| reject 断开 | `reject` | — | supported | h1 连接 EOF；h2 RST_STREAM |
| reject 200/空 body | `reject-200` | — | supported | 解析/单测 |
| reject 图片/JSON | `reject-img` / `reject-dict` / `reject-array` | — | supported | 解析/单测 |
| 请求头增删改/正则 | `header-*` / `request-header-*` | `request.header.*` | supported | h1/h2 E2E |
| 响应头增删改/正则 | `response-header-*` | `response.header.*` | supported | h1/h2 E2E |
| 请求体正则 | `request-body-replace-regex` | `request.body.replace(_regex)` | supported | 单测/边界 |
| 响应体正则 | `response-body-replace-regex` | `response.body.replace(_regex)` | supported | h1/h2 E2E，含 gzip |
| 请求/响应 JSON 增改删 | `body-json-*` | `request.json.*` / `response.json.*` | supported | h1/h2 E2E |
| 请求/响应 Mock | `mock-*-body` inline `data=` | — | supported | h1/h2 E2E |
| mock Base64 | `mock-data-is-base64=true` | — | supported | 单测 |
| jq | `*-json-jq` | — | unsupported | 明确跳过 |
| mock 文件/URL | `data-path=` | — | unsupported | 明确跳过 |
| 脚本 | `script(...)` | `script(...)` | unsupported | 界面显示缺口 |
| 复杂条件 | — | `&&` / `||` / 变量条件 | unsupported | 明确跳过 |

## 3. 协议与边界

| 场景 | HTTP/1.1 | HTTP/2 | 状态 |
|---|---|---|---|
| URL/头/mock/reject/redirect | 是 | 是 | supported |
| 请求体/JSON 改写 | 是 | 是 | supported，2 MiB 上限 |
| 响应体/JSON 改写 | 是 | 是 | supported，2 MiB 上限，超限透传 |
| gzip 响应解码后改写 | 是 | 是 | supported |
| br 等不可解码 | 原样透传 | 原样透传 | 安全回退 |
| 已知超大请求体 | 跳过改写、流式转发 | 缓冲超限回 413 | 明确边界 |
| 跨域 URL 改写 | 支持新 Host/目标 | 支持新 authority/SNI 与新上游 | supported |
| HTTP/3 / QUIC | — | — | 未实现，不宣称解密或改写 |

## 4. 本地导入

| 入口 | 文件类型 | 上限 | 状态 |
|---|---|---|---|
| 模块页「从本地文件导入」 | `.plugin` / `.sgmodule` / 纯文本 | 4 MiB | supported；预览后确认，`local://文件名` 不参与远端同步 |
| 配置页「从本地文件导入」 | JSON / Clash / Loon / 小火箭配置 | 2 MiB | supported；走原配置预览与导入 |

## 5. 验收边界

- 无 Android 真机、无 iOS/Loon/Shadowrocket 设备；本地文件选择器、MITM UI 与真实导入激活需设备复核。
- 无真实上游 HTTP/3 服务，HTTP/3 不声明已解密。
- `[Script]`、`[Argument]`、`[General]`、`[Host]` 的运行时语义未实现，不能把“能解析”当成“能执行”。
- Loon `.conf` 的 `[Rewrite]` 主动配置导入尚未接入；当前 Loon 重写来自 `.plugin` 模块。
