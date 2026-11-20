# M6 脚本运行时与 API 评估报告

版本：南门DNS 2.3.6 / 内核 1.12.5
日期：2026-11-20
范围：请求/响应脚本、Loon / Shadowrocket 常见脚本 API、QuickJS 选型、资源限制、MITM 接入与验收。

## 1. 结论

选用 **QuickJS-NG（rquickjs 0.12.2）** 嵌入 Rust 内核，不使用 WebView、V8 或 JavaScriptCore。

- QuickJS 是 MIT 许可的小型 C 引擎，编译进两个 Android ABI 后可随内核一起发行；
- rquickjs 提供 Runtime/Context、内存上限、栈上限、中断回调、Persistent 值等本任务需要的能力；
- rquickjs 官方 shipped bindings 不含 Android，本次通过 vendoring `rquickjs-sys` 并补齐
  `aarch64-linux-android` / `armv7-linux-androideabi` 绑定解决，未依赖宿主 `libclang`；
- 双 ABI 交叉编译通过，`.so` 体积从 6.5 MB / 4.2 MB 增至 **7.5 MB / 5.1 MB**，
  且产物中包含 QuickJS 符号/字符串，证明不是“只加依赖没链接”。

**能力边界**：只对已解析的 `[Script]` 规则逐条执行；没有做 Loon/Surge/Shadowrocket
全生态兼容承诺。每个模块的导入预览会展示脚本规则的可用/部分可用/不可用及具体缺口。

## 2. 候选引擎评估

| 候选 | Android ABI | 许可证 | 生命周期/中断 | 资源限制 | 依赖维护 | 结论 |
|---|---|---|---|---|---|---|
| QuickJS-NG + rquickjs 0.12.2 | C 源码随 crate 编译；需补 arm64/armv7 bindings（本次已补） | MIT | 每次执行新建 Runtime/Context；`set_interrupt_handler` 可按墙钟中断 | `set_memory_limit`、`set_max_stack_size` 原生支持 | rquickjs 活跃，QuickJS-NG 自带 C 源码；需维护 vendored bindings | **选用** |
| Boa（纯 Rust JS） | 纯 Rust，理论上可直接交叉编译 | MIT/Apache 双许可 | Rust 运行时，需自行实现执行配额 | 依赖上游 runtime limit | 生态较新，ES 覆盖与性能不确定性高 | 仅桌面调研，未纳入构建 |
| V8 | 需自行构建 Android 大体积库，JIT/ABI 复杂 | BSD 风格 | 强，但体积/线程模型重 | 可配 | 维护成本高，APK 体积不可接受 | 否决 |
| JavaScriptCore | Android 系统库不是 NDK 稳定接口，动态链接不可靠 | LGPL/BSD 混合 | 依赖系统 WebKit | 受系统版本影响 | 不可控 | 否决 |
| Lua/mlua | 可交叉编译 | MIT | 可中断 | 可配 | 与 Loon/Surge JS 插件语法不兼容，需重写全部脚本 | 否决 |

> Boa/V8/JSC 只做了资料评估，没有进入本机构建；不在验收中声称“已测试”。

## 3. 构建与许可证

- `core/Cargo.toml` 引入 `rquickjs = 0.12.2`（features: classes/properties/array-buffer），
  并通过 `[patch.crates-io]` 指向 `core/vendor/rquickjs-sys`。
- `core/vendor/rquickjs-sys` 来自 crates.io 0.12.2，包含 QuickJS 源码与上游许可证。
- 新增绑定：
  - `core/vendor/rquickjs-sys/src/bindings/aarch64-linux-android.rs`
  - `core/vendor/rquickjs-sys/src/bindings/armv7-linux-androideabi.rs`
- 许可证：rquickjs / QuickJS-NG 均为 MIT；源码包必须保留 `core/vendor/rquickjs-sys`
  及其中 `quickjs/` 目录的 LICENSE，不能只发二进制。

构建证据：

```
PATH="$HOME/.cargo/bin:$PATH" bash core/build-android.sh
native libs updated: 1.12.5
app/src/main/jniLibs/arm64-v8a/libnanmen_core.so    7.9 MB
app/src/main/jniLibs/armeabi-v7a/libnanmen_core.so  5.3 MB
```

## 4. 运行时设计

### 4.1 执行模型

- 4 个专用脚本工作线程，每个线程创建并长期持有独立 `Runtime`；每次执行只新建 `Context`，执行完释放 JS 堆对象。
- `rquickjs` 的 `Runtime` 不跨线程；MITM 路径通过通道发送「脚本执行请求」，在专用线程同步执行并带超时等待结果。
- 外层仍用 `spawn_blocking` + 4 并发信号量承接异步调用；拿不到许可时本次跳过并累计诊断计数，不排队拖住隧道。
- 默认拒绝宿主 I/O：脚本没有 `fs`、原生 socket、进程或文件 API；`eval`/`Function` 全局被禁用，能力只经 `$httpClient`、`$persistentStore`、`$notification`、`console` 等白名单函数注入。
- 请求脚本在 Loon `[Rewrite]` 计划之后、上游转发之前执行；响应脚本在响应体收集/解压后执行。
- HTTP/1.1 与 h2 各自接入；h2 的请求脚本修改正文后会重建上游请求头/URI。

### 4.2 资源上限

| 项 | 默认/上限 | 行为 |
|---|---|---|
| QuickJS 内存 | 32 MiB/线程 | 超限由引擎报错，脚本结果回退 |
| JS 栈 | 512 KiB | 超限报错，不 panic |
| 单脚本执行时间 | 默认 5 s，最大 10 s | 中断回调终止死循环；结果回退 |
| 单脚本正文 | 默认 2 MiB，最大 8 MiB | 超限丢弃该脚本结果并记录 |
| `$httpClient` 响应 | 1 MiB | 超限报错 |
| `$httpClient` 调用次数 | 32 次/脚本 | 超限回调返回错误 |
| `$persistentStore` | 1 MiB / 256 键 | 超限 `write` 返回 false |
| `console.log` | 64 条，每条 512 字符 | 超出丢弃 |
| `$notification` | 32 条，每条 512 字符 | 超出丢弃 |
| 脚本并发 | 4 | 超出本次跳过 |

### 4.3 完成/异常语义

- `$done` **首次调用生效**；后续调用只累计 `done_calls`，不覆盖首次结果。
- `$done({})` 保持原值；对象中缺省字段保持原值；`headers:{}` / `body:""` 可清空。
- 请求阶段 `$done({response:{status,headers,body}})` 直接生成本地响应，不再访问上游。
- 脚本抛错、超时、内存/栈超限：该脚本结果丢弃，已命中的后续脚本继续执行；
  若已调用过 `$done`，按首次完成结果继续。
- 超时使用「中断回调 + 墙钟 deadline」双保险；中断抛出的是引擎级不可捕获终止，脚本不能吞掉。
- 超时后先停止 QuickJS 中断计时，再回读 JS 对象，避免回读时再次触发中断。
- 工作线程池记录完成/失败/超时/跳过计数，失败时写入 `mitm.script` 诊断日志。
- `$done()` 在 Loon 文档中存在“abort request”与“finish unchanged”两种表述；
  本版按“完成但不修改”处理，避免误断流量。该差异在 M6 API 矩阵中明确标注。

## 5. API 覆盖（摘要）

详见 `docs/M6_SCRIPT_API_MATRIX.md`。

| API | 状态 | 说明 |
|---|---|---|
| `$request` / `$response` | 可用 | url/method/status/headers/body 文本 |
| `$done` | 可用 | 首次生效、多次计数、嵌套 response 短路 |
| `$httpClient` | 可用 | 7 个方法；异步任务队列 + 独立 runtime；支持 timeout/headers 数组；拒绝私网（含重定向）、1 MiB、32 次上限 |
| `$persistentStore` | 可用（受上限） | 可选 key、落盘、删除、清空；1 MiB/256 键 |
| `$argument` | 可用 | 对象；无参数时为 undefined |
| `$notification` | 部分可用 | 只记录到运行结果/日志，不弹 Android 系统通知 |
| `console.log` | 可用 | 有界日志 |
| `setTimeout` / `setInterval` | 部分可用 | 同步事件队列；按 Loon 当前语义只执行一次 |
| `$script.name` | 可用 | `$script.startTime` / `$loon` 未提供 |
| Promise / async 回调 | 部分可用 | 在 `ctx.with` 之外驱动 QuickJS 微任务队列；async/await、Promise 链、rejection 捕获可用；无独立事件循环 |
| binary-body-mode / Uint8Array | 可用 | 按开关以 Uint8Array 暴露正文；gRPC/protobuf 帧可解析并原字节回写 |
| `$config` / `$dns` / `$crypto` / `$utils` | 不可用 | 未实现，不宣称兼容 |

## 6. 接入位置

- `core/src/script.rs`：QuickJS 运行时、脚本规则编译、`$request/$response/$done/$httpClient/
  $persistentStore/$argument/$notification/console/setTimeout`、资源限制与单元测试。
- `core/src/mitm/rewrite.rs`：`MitmConfig.scripts` / `script_store_file`、`ScriptEngine` 编译。
- `core/src/mitm/mod.rs`：HTTP/1.1 请求/响应脚本、短路响应、脚本结果写回、并发信号量。
- `core/src/mitm/h2.rs`：h2 请求/响应脚本、正文缓冲、脚本本地响应、重启上游 URI/头。
- Kotlin `ModuleParser`：`[Script]` 结构化（phase/pattern/script-path/requires-body/max-size/
  timeout/tag/argument）。
- Kotlin `Actions`：导入/同步时下载 script-path、写入缓存；同步时强制刷新。
- Kotlin `ConfigStore`：把脚本正文与参数合并进 `modules_mitm.json` / native `mitm.scripts`，
  并下发 `script_store_file`。
- Kotlin `ModulesScreen`：导入预览橙色警示并显示 remote script-path；逐条显示脚本可用/部分可用/不可用与缺口。不提供模块级脚本开关或额外来源确认。

## 7. 验收证据

已执行：

- `cargo test --manifest-path core/Cargo.toml --lib script`：全部通过；
  覆盖 `$done` 多次、请求对象回读、死循环中断、持久化重启、参数、通知/日志、
  `$httpClient` 本地服务、规则过滤、setTimeout、Promise/async、删除 key。
- `cargo test --manifest-path core/Cargo.toml`：全量通过（详见 README/`baseline.json` 的最新计数）；
  新增 `mitm_scripts_mutate_request_response_and_short_circuit`（HTTP/1.1）与
  `mitm_h2_scripts_mutate_request_and_response`（h2）；新增 `binary_frame` 自写二进制脚本验收。
- Android 双 ABI 构建通过，QuickJS 已链接。

尚未执行/无法执行：

- 无 Android 真机，无法验证脚本在真实 App 流量下的长期稳定性；
- 无 iOS / Loon 3.5.3 / Shadowrocket 2.2.66 设备，无法逐项对照真实运行时；
- 无真实授权脚本样本全集，只用公开语法与自建样本覆盖核心 API；
- `$config/$dns/$crypto/$utils` 仍未实现；二进制正文已由自写 gRPC 帧脚本与单测覆盖，但仍无 iOS 真机对照。

## 8. 风险与后续

1. `$httpClient` 已改为异步任务队列和独立 runtime；脚本执行线程仍在完成队列上等待，因此高并发脚本数仍受 4 个工作线程限制，单脚本内最多 32 次请求。
2. `$persistentStore` 的写入是整文件快照；高频写入可能放大 I/O。
3. `$notification` 目前不弹系统通知，只进入运行结果/日志；后续可通过 JNI 接 Android 通知。
4. h2 响应脚本已支持 `binary-body-mode` 的 gRPC 二进制；普通 gRPC 未声明二进制脚本时仍只走 Surge protobuf 改写。
5. 脚本跨域 URL 改写不支持，避免脚本静默改变目标域名；同 host 的 path 改写可用。
