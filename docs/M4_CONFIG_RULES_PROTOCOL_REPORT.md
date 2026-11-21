# M4 报告：配置、规则集和协议

版本：南门DNS `2.1`（versionCode `71`），自研内核 `1.11.5`，Android 12+（`minSdk 31`）。

## 1. 配置格式导入

### Loon `.conf` / 小火箭 `.conf`
- `ConfigSource.kt` 的 `parseSectionConfig` 从“只预览”改为真正解析并允许导入：
  - `[Proxy]`：SS、Trojan、VLESS、SOCKS5、HTTP/HTTPS；解析 server/port/凭据/TLS/SNI/WS path/host。
  - `[Proxy Group]`：`select`、`url-test`、`fallback`，保留成员与组参数；内置 `DIRECT/REJECT/PROXY` 不作为成员。
  - `[Rule]`：常用域名/IP/端口规则、`FINAL`/`MATCH`；组名优先于节点名，节点目标写为 `node:<name>`。
  - `[General]`：`dns-server`、`doh-server`、`dns-fallback`、`ipv6=false`。
  - 未知段落写入 `unknownRoot.sourceUnknownSections`，不冒充已支持。
- 节点属于设备侧：`ConfigSourceResult.nodes` 返回解析结果，`ConfigRepository.import` 在保存新配置后激活它并合并节点；不会把导入内容覆盖到旧 active `.conf`。
- `PROCESS-NAME`、`UID`、`APP`、`APP-NAME` 规则：已支持（2026-11-21 起）。`UID` 以数值直接下发；包名类规则保留包名，在下发内核前由壳层用 PackageManager 解析成 UID。识别连接归属依赖 Root 读取 socket 表，详见 `docs/APP_ISOLATION.md`。
- `PROCESS-PATH`：仍不支持，需要路径到包名的映射，导入时 WARNING 跳过。

### Clash YAML
- `ClashConfigParser` 解析 `proxy-groups` 的 `name/type/proxies`，导入为 `ConfigFile.proxyGroups`。
- 规则目标不再回落 `proxy`：组名保留为动作，节点目标写 `node:<name>`，内置 `DIRECT/REJECT/PROXY` 仍映射为直连/拦截/当前节点；组名与内置同名时组名优先。
- 规则子集新增 `DOMAIN-WILDCARD`、`GEOIP`。
- `proxies` 仍属于设备节点列表，不写入 `.conf`；节点继续由 URI/Clash 订阅导入。

### URI / Clash 订阅
- Rust `ParseResult` 新增 `proxy_groups`，`to_json` 输出完整 `ProxyGroup` 对象。
- Clash `map_clash_target` 组名优先，不再输出“策略组暂不支持”的回落 warning。
- Kotlin `Actions.importSubscription` 解析 `proxy_groups` 并合并到设备 `AppConfig.proxyGroups`，清理失效的 `groupSelections`。

## 2. 规则集与缓存

- `RuleSource` 新增 `etag`、`lastModified`、`lastAttemptAt`、`stale`、`cacheBytes`。
- `syncRuleSources`：
  - 支持 `If-None-Match` / `If-Modified-Since`；`304` 直接复用本地缓存，不重写文件。
  - 成功时记录 ETag/Last-Modified、大小、行数、检测格式（adblock/domain/clash-rules/clash-yaml）。
  - 失败时保留上一份 `.bak`/当前文件，标记 `stale=true`；`ConfigStore.ensureAssets` 仍会回退到 `.bak`。
  - UI 显示“失败·用旧缓存”，不把失败源从规则列表移除。
- 保留 8MB 上限、逐源错误隔离、`.tmp` 原子替换、http→https 降级拦截。

## 3. 规则引擎

- 新增 `DOMAIN-WILDCARD`：大小写不敏感 glob 正则，`*` 任意字符、`?` 单字符。
- 新增 `GEOIP(CN)`：使用内置 CN IP 库；`cn_direct=false` 时也加载 CN IP 文件，因为 GEOIP 与“CN 直连”是两个独立能力。
- 非 CN GEOIP 不猜测，告警后跳过。
- `PROCESS-NAME`/`APP`/`APP-NAME`/`UID` 已由壳层展开成 UID 规则后下发，内核接受数值 UID 规则；`PROCESS-PATH` 及未知规则类型仍在内核加载时明确告警拒绝，不再静默丢弃。

## 4. 协议验收

详见 `docs/M4_PROTOCOL_CAPABILITY_MATRIX.md`。

新增 `core/tests/protocol_e2e.rs`：
- Trojan 明文本地受控服务端：握手、双向、重连、端口关闭失败。
- VLESS 明文本地受控服务端：握手、双向、重连、非法 UUID 失败。
- SOCKS5：握手、双向、重连。
- SOCKS5 UDP ASSOCIATE：UDP relay 单独收发包；不与 TCP 健康混用。

未实现协议（VMess、Reality、Hysteria2、TUIC）保持准确拒绝；能力矩阵记录依赖/许可证/ABI 评估，不声称可用。

## 5. 测试与验收

- Rust：139/139（lib 77、cert_name_probe 1、compat_fixtures 13、compat_rules 1、core_test 29、mitm_test 14、protocol_e2e 4）。
- Kotlin：95/95，20 suites，0 failures。
- Lint、清洁构建、APK/源码包数字见 `compat/expected/baseline.json` 与根 `SHA256SUMS.txt`。

已知边界：
- 无 Android 真机、无 iOS/Loon/Shadowrocket 设备，导入后的 UI 行为和真实配置激活需设备复核。
- 无真实订阅/服务端，304 在线行为只做了代码路径与本地逻辑验证。
- Loon/小火箭的 Rewrite/Script 仍未执行；只有节点/组/规则/DNS 子集导入。
