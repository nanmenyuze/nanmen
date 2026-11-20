# M6 脚本 API 适配与差异表

目标版本：Loon 3.5.3、Shadowrocket 2.2.66（后者版本来自二手页面，尚未 iOS 真机复核）。
本表描述 **南门DNS 2.3.6 / 内核 1.12.5** 的实际行为，不是“全生态兼容”承诺。

状态定义：

- **可用**：本次代码路径和自动化测试覆盖，行为与目标版本的核心语义一致；
- **部分可用**：接口存在，但字段、异步模型或副作用有明确缺口；
- **不可用**：不提供该 API；脚本用到时导入预览会标出。

## 1. 脚本声明语法

| 项目 | Loon 3.5.3 | Shadowrocket 2.2.66 | 南门DNS 2.3 |
|---|---|---|---|
| `http-request <regex> script-path=...` | 支持 | 支持（.sgmodule 常用） | 支持；按完整 URL 正则匹配 |
| `http-response <regex> script-path=...` | 支持 | 支持 | 支持 |
| `type=request,pattern=...` | 非 Loon 官方主格式 | 部分模块使用 | 支持，作为兼容写法 |
| `tag` / `name` | 支持 | 支持 | 支持，作为脚本显示名 |
| `requires-body` | 支持，布尔 | 常用 `1` | 支持 1/true/yes/on |
| `max-size` | v2 文档未列，旧插件可见 | 常用字节数 | 支持；`<=0` 回落 2 MiB，最大 8 MiB |
| `timeout` | 秒，默认 10 | 秒/毫秒均有样本 | 1–60 按秒换算，其余按毫秒；上限 10 s |
| `argument="..."` | 普通字符串 | 常见字符串/参数列表 | `argumentText` 字符串；`[Argument]` 合并为对象 |
| `enable=false` | 支持 | 支持 | 跳过该条，不执行 |
| `binary-body-mode=true` | 支持 Uint8Array | 视模块而定 | **可用**：按开关以 Uint8Array 暴露正文，支持 gRPC/protobuf 原始帧 |
| 相对 `script-path` | 可能支持 | 可能支持 | **不支持**，只接受 http/https |

## 2. 运行时对象与 API

| API/对象 | Loon 3.5.3 | Shadowrocket 2.2.66 | 南门DNS 2.3 状态 | 具体缺口 |
|---|---|---|---|---|
| `$request.url` | 可读写 | 可读写 | **可用** | 只允许同 host；跨域改写拒绝 |
| `$request.method` | 可读写 | 可读写 | **可用** | 仅合法 HTTP token |
| `$request.headers` | 对象 | 对象 | **可用** | 重复头合并为一个对象；大小写不保留 |
| `$request.body` | String / Uint8Array | String | **可用** | 文本模式为 String；`binary-body-mode=true` 时为 Uint8Array，`$done({body})` 可回写原始字节 |
| `$request.h2_trailers` | Build 927+ | 未知 | **不可用** | 未暴露 |
| `$response.status` / `statusCode` | 可读写 | 可读写 | **可用** | 100–599 才生效 |
| `$response.headers` | 对象 | 对象 | **可用** | 重复头合并 |
| `$response.body` | String / Uint8Array | String | **可用** | 文本模式为 String；`binary-body-mode=true` 时为 Uint8Array，gRPC 帧可直接解析并回写 |
| `$response.h2_trailers` | Build 927+ | 未知 | **不可用** | 未暴露 |
| `$done({})` | 保持原值 | 保持原值 | **可用** | 缺省字段保持 |
| `$done({headers:{},body:""})` | 清空 | 清空 | **可用** | 空对象/空串生效 |
| `$done({response:{...}})` | 请求短路 | 请求短路 | **可用** | 请求阶段生成本地响应 |
| `$done()` 无参数 | 文档有“abort request / complete”两种表述 | 通常视为完成 | **部分可用** | 本版按“完成但不修改”处理，不误断流量 |
| 多次 `$done` | 首次生效 | 首次生效 | **可用** | 后续只计数 |
| `$httpClient.get/post/put/delete` | 支持 | 支持 | **可用** | 异步任务队列；回调在脚本求值后由完成队列驱动；见资源上限 |
| `$httpClient.head/options/patch` | 支持 | 支持 | **可用** | 同上 |
| `$httpClient` 回调 | `(error, response, data)` | 同 | **可用** | 异步回调；网络 I/O 在独立 runtime，脚本线程等待完成队列 |
| `$httpClient` headers | 对象/数组 | 对象 | **可用** | 对象、`[["k","v"]]`、`[{name,value}]` 三种形式均解析 |
| `$httpClient` `timeout` 选项 | 支持 | 部分支持 | **可用** | 支持 `timeout`/`timeoutMs`；1–60 按秒，其余按毫秒；默认 4 s，最大 10 s |
| `$httpClient` 私网 | 未限制 | 未限制 | **更严格** | 默认拒绝 localhost/私网/环回；重定向也限制 |
| `$httpClient` 响应大小 | 未限制 | 未限制 | **限制** | 1 MiB |
| `$httpClient` 调用次数 | 未限制 | 未限制 | **限制** | 32 次/脚本 |
| `$persistentStore.read([key])` | 支持，缺省 key | 支持 | **可用** | 缺省 key = `$script.name` 或 `default` |
| `$persistentStore.write(value,[key])` | 支持；undefined 删除 | 支持 | **可用** | 1 MiB / 256 键；超限返回 false |
| `$persistentStore.remove()` | 清空全部 | 未知 | **可用** | 本版另支持 `remove(key)` 扩展 |
| `$argument` | 字符串或插件参数对象 | 字符串/对象 | **可用** | String 与 Object 两种；无参数时 undefined |
| `$notification.post(title,subtitle,content)` | 系统通知 | 系统通知 | **部分可用** | 只记录到运行结果/日志，不弹 Android 通知 |
| `$notification.post` `attach`/`delay` | 支持 | 部分支持 | **不可用** | 参数被忽略 |
| `console.log(value)` | 支持 | 支持 | **可用** | 64 条、每条 512 字符 |
| `setTimeout(cb, ms, ...args)` | 支持 | 支持 | **部分可用** | 同步定时器队列；只执行一次；额外 args 忽略 |
| `setInterval(cb, ms)` | 当前只执行一次 | 支持 | **部分可用** | 按 Loon 当前语义只执行一次 |
| `clearTimeout` / `clearInterval` | 支持 | 支持 | **不可用** | 未提供 |
| `$script.name` | 支持 | 支持 | **可用** | — |
| `$script.startTime` | 支持 | 未知 | **不可用** | 未提供 |
| `$loon` | 支持 | 无 | **不可用** | 未提供 |
| Promise / async 回调 | 支持（运行时有微任务） | 支持 | **可用** | 已驱动 QuickJS 微任务队列；`$httpClient` 改为异步完成队列，async/await 包裹可正常续体 |
| `$config` / `$dns` / `$crypto` / `$utils` | 支持部分 | 视版本 | **不可用** | 未实现 |
| 二进制正文 / Uint8Array | 支持 | 支持 | **可用** | 由 `binary-body-mode=true` 启用；未启用时仍按 UTF-8 文本 |

## 3. 资源限制（南门DNS 侧）

| 项 | 值 |
|---|---|
| QuickJS 内存 | 32 MiB/线程 |
| JS 栈 | 512 KiB |
| 单脚本超时 | 默认 5 s，最大 10 s |
| 脚本并发 | 4；拿不到许可跳过 |
| 单脚本正文 | 默认 2 MiB，最大 8 MiB |
| `$httpClient` | 1 MiB、32 次/脚本；默认 4 s、最大 10 s/次 |
| `$persistentStore` | 1 MiB、256 键 |
| 日志/通知 | 64 条 / 32 条，每条 512 字符 |

## 4. 每插件展示规则

模块导入预览会对每条 `[Script]` 显示：

- **不可用**：脚本正文未缓存（下载失败/被过滤），或脚本声明了尚未实现的 API；
- **部分可用**：脚本源码出现 `require(`、`fetch(`、`XMLHttpRequest`、`WebAssembly` 等未提供能力；Promise/async 已支持，不再因此标记；
- **可用**：只使用 `$request/$response/$done/$httpClient/$persistentStore/$argument/$notification` 等已实现 API。

同时显示请求/响应条数、已缓存条数、无法解析条数，以及 `scriptIssues`。
这是**逐条能力**展示，不代表整个插件生态兼容。
