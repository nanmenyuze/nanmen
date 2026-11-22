# 南门DNS 2.9.1

> 内核 crate / JNI：`nanmen_core` / `libnanmen_core.so`；许可证：**GPL-3.0-only**（见 `LICENSE`、`NOTICE`、`THIRD_PARTY_NOTICES.md`）。

> 2.9.1 正式版（内核 1.13.22，versionCode 105）：壳层与调度审计修复。
> - 配置异步保存：入队时冻结 active 配置名和配置快照，改完 A 立刻切 B 不会再把 A 写进 B。
> - TUN 参数：热重载比较 `mode + mtu + fullRoute` 完整 `TunnelSpec`，连接中改 MTU 或 DNS-only 全量接管会真正重建 TUN。
> - 备份：导出/恢复 `files/modules/module_*.sgmodule`、`files/scripts/script_*.js`、`files/ruleset_*.txt`，新机恢复本地导入模块不再因为 `local://` 没有远程地址而失效；缺正文模块和规则集/脚本依赖问题回显到恢复结果。
> - Clash 导入：`load-balance` 不再降级成 `select`，保留 `lb_mode`/`strategy`（缺省 round-robin）与 `switch_interval`。
> - 模块同步：下载结束按当前模块对象合并，只写同步字段，保留用户刚改的 `enabled`、`intervalSeconds`、`url`；同 id URL 已变则丢弃旧结果。
> - 订阅刷新：`refreshSubscription()` 返回 `ImportResult`，零节点提示“未解析到可用节点，已保留上次节点”，部分成功显示可用/跳过数量，不再一律说“已刷新”。
> - cron：`CompiledScriptRule` 编译期缓存 `CronSpec`，调度键包含 cron 表达式，改时间后旧时间不再命中；延迟任务执行前回查脚本是否仍存在且 cron/trigger/正文未变；无解表达式 6 小时复查一次，不再每秒扫描 527040 分钟。
> - 验收：Rust 256 lib + 全量集成测试、Kotlin 199/199、lint 0 error / 38 warning；两套 ABI 16K 对齐，V2 证书与 2.9 连续。

> 2.6 = Android 12+ 应用壳（`minSdk 31`）+ 自研 MITM 去广告内核（1.13.0）。在 2.3.7 基础上补齐 M7 备份/恢复、迁移与崩溃报告、实时连接/网络状态、重载失败回滚，并把基础配置 DNS 改为跟随手机底层网络，新增 RULE-SET / DOMAIN-SET / PROTOCOL 规则能力，并修复 h2 空闲连接被误判握手超时；内核版本仍为 1.12.5。
>
> 2.3.8 测试包追加（不改版本号）：按 App 分流（`UID`/`PROCESS-NAME`/`APP` 规则 + Root 读 socket 表，见 `docs/APP_ISOLATION.md`）；DNS-only 默认全量接管（硬编码 DNS 与 DoT 853 进 TUN，可在配置页关闭）；上游应答的 CNAME 链检测（拦截 CNAME 伪装）；分流 `REJECT` 域名规则并入 DNS 过滤（DNS-only 下也真正拦截）；新增「纯过滤」模式（全量 TUN、不需要节点、代理类动作自动降级直连，可做连接层 REJECT / 853 拦截 / MITM，`AutoConnect` 也允许无节点自动连接）；MITM 支持按 App 生效（全部 / 仅选中 / 跳过选中，TCP 443 用 socket 表定位 UID，银行与证书固定应用可精确排除）；Loon 旧版 `url - action` 写法（社区模块最常见的 `- reject-dict`）不再被当成不支持而丢弃。
>
> 2.3.8 测试包再追加（不改版本号）：逐连接快照表与「实时连接」列表（内核 `conns.rs` 记录 UID/域名/IP/端口/动作/命中规则/MITM 标记/存活时长，JNI `nativeConnections(since)` 增量下发，壳层每秒轮询、按内核活跃总数自动淘汰已关闭条目）；Surge `.sgmodule` 的 `[URL Rewrite]` 补齐 `302`/`307`、3 段 `header`（URL 替换）与 `mock`/`mock-request-body`/`mock-response-body`（翻译成等价 Loon 规则执行，不再计为不支持）；修正 Loon 旧语法 `^url https://new 302|header`（动作在末位）被整行丢弃的问题。内核 1.12.8。
>
> 2.6 正式版 = 合并两条迭代线。数据面（来自 2.3.9~2.3.12，内核 1.12.9）：TUN 收发改缓冲池 + 批量写 + 背压诊断（`tunTxDrop`/`tunPendingDrop`/`tunPendingPeak`/`tunTxBackpressure`/`tunWriteWouldBlock`/`tunWriteError`）；ICMP Echo 本地回显；直连拨号熔断（按目标冷却、连续失败自愈、`dialBreakerRejected`）与「保持真实失败时序」的抑制策略；并发上限改为淘汰最久空闲（`tcpLimitEvicted`）而非拒绝新连接；空闲兜底回收（`tcpIdleReaped`）；HTTPS/HTTP 连通性探测本地代答；切网滞回（5s 确认窗口）与重建失败自动重试；节点级 `udp:false` 与 SOCKS5/Trojan/VLESS UDP。过滤与分流（来自 2.3.8 测试包，内核 1.13.0）：按 App 分流（`uidmap` + Root 读 socket 表）、按 App MITM、CNAME 伪装拦截、DNS-only 全量接管、纯过滤无节点模式、Surge `[URL Rewrite]` 的 302/307/header/mock 映射、Loon `url target action` 旧语法、逐连接快照与「实时连接」列表。

> 2.6.1 正式版（只调数据面档位与 TCP 小包参数，内核 1.13.1）：下行三档成对抬到 512 —— `MAX_TX_QUEUE`（smoltcp tx 暂存包）512、`MAX_PENDING_OUT`（待写 TUN 队列，512×2048B≈1MB）512、`MAX_TX_WRITE_BURST`（每轮写入，≈1MB/轮）512；读侧 `MAX_RX_BURST` 64→512。并把读 TUN 从「依赖 select 的 readable 分支被选中」改为每轮固定执行的非阻塞步骤（`readable` 只负责唤醒并清就绪位），避免边沿触发或漏唤醒把 RX 停住——RX 一停 ACK 回填就慢，下行窗口会跟着被压。`SNI_WAIT_MS` 保持 60ms 不动。同时关闭 TCP Nagle（`set_nagle_enabled(false)`）、延迟 ACK 从 smoltcp 默认 10ms 压到 5ms，减少小包合并与确认等待叠加出来的 RTT 级停顿。>

> 2.6.2 正式版（内核 1.13.2）：把「单流慢」的主因补上——`TCP_SOCKET_BUFFER` 128K→512K（窗口缩放 shift=1→3，单流上限从 128K/RTT 抬到 512K/RTT），并配内存水位守卫：512K 档只给前 128 个 TCP socket，超出降级到 128K 档，1024 条连接最坏 ≈352MB（裸提会到 1GB）；判别仪表新增 `tcpRecvFull`（本地接收缓冲打成满/窗口 0）、`tcpSendStalled`（对端零窗口导致发送停滞，附一次性告警日志）、每连接累计字节（`up`/`down`，壳层差分算速率并在「实时连接」显示）、`tcpBufferDenied`；QUIC 假活回落开关落到配置项 `quicFallback`（默认开，443/UDP 2.5s 无回包判黑洞，10 分钟内对同一目标丢弃 QUIC）；源码 zip 不再夹带构建机 `local.properties`。> 版本：2.6（versionCode 90）；内核 1.13.0。

> 2.6.3 正式版（内核 1.13.3，只修 2.6.2 的口径问题，无新增功能面）：大档名额改「并发」口径（`TCP_SOCKETS` 随 socket 关闭立刻归还，新连接可补位，不再被开机早期的推送/IM 长连接长期占满），新增 `bigTierInUse` 诊断；判别仪表从「次数」改为「条件成立期间累计毫秒」（`tcpRecvFull` = 接收缓冲满且 relay 仍有余量积压，`tcpSendStalled` = 待发非空但对端零窗口，超 3s 打一条告警），每连接速率改由内核 10s 采样写进快照（`upBps`/`downBps`）并打 top-5 日志；QUIC 黑洞判定改为按 (目的 IP, 端口)、仅在有上行活动时计时（纯空闲不判死）、收到该会话任何下行包即清除，并新增 `quicBlackholed` 计数与切网清空（壳层 `nativeClearQuicBlackhole`）。

> 2.6.4 正式版：规则集载体兼容与 CSV 拆分修复。`RuleSetExpander` 不再只认 Surge 文本，新增 Clash `payload:` YAML 与 sing-box source JSON 解析（`domain`/`domain_suffix`/`domain_keyword`/`domain_regex`），含 `ip_cidr`、端口等非域名条件的规则整条跳过（AND 语义，不误杀）；二进制 `.srs` 明确提示端上不解析；空内容、未缓存、整集一条都没展开都会写进 `modules_mitm.json` 的 `ruleSetIssues`，模块页可见，不再静默失效。`parseRuleLine` 改走统一的 `RuleLineParser`：按策略位置切分，`DOMAIN-REGEX,^ads{1,3}\.x\.com$` 的 `{m,n}` 不再被逗号截断，`IP-CIDR,x,DIRECT,no-resolve` 的尾随选项也不会顶掉动作；规则集行允许省略策略，由集合策略覆盖。内核保持 1.13.4，未改动数据面。
> 2.6.3 热修（内核 1.13.4，版本号不动）：修掉 `TCP_SOCKETS` 在「正常关闭（FIN 走完 state==Closed）」路径上的漏减——该路径原先用裸 `sockets.remove`，没归还大档计数，导致计数单调上涨、`next_tcp_buffer_bytes` 对之后所有新监听器永久返回 128K，把 512K 修复整条废掉；改为统一走 `release_tcp_socket`。`tcpBufferDenied` 接线：水位降级分支真正计数。速率 top-5 日志加 `512K`/`128K` 档位标签，便于下一份诊断直接闭环。`bigTierInUse` 刷新移出 QUIC 开关分支，关掉 QUIC 回落时仪表不再冻结。

> 2.7 正式版（内核 1.13.13）：这一版把数据面从「调参数」推到「换基线 + 加能力」。
> - 内核依赖 smoltcp 0.11 → 0.14，TCP 栈行为与 0.14 对齐后再叠加本项目的档位/守卫。
> - TUN 巨帧 MTU 9000（壳 `setMtu` 与内核 `iface` 取同一配置值，`establish` 失败回退 1500 并写回配置）；队列不再按包数写死，而是按 1MB 字节预算随 MTU 换算（1500 档仍 512 包，9000 档约 116 包，排队字节量与背压口径不漂移）；单包上限抬到 9216。
> - 上游 per-socket `TCP_CONGESTION=bbr`（`tcpBbrOk`/`tcpBbrFail` 计数，内核不支持时静默回退 cubic）；同时采样 SO_RCVBUF/SO_SNDBUF 自动调窗真实值（`upstreamRcvbufMax`/`upstreamSndbufMax`），不锁死缓冲以免关掉自动调窗。
> - 金融连接保护（默认开，设置页可关）：银行/证券/云闪付等独立 App 整包不 MITM；微信/支付宝/QQ 按域名硬排除（`finance.rs` 内置 tenpay/wechatpay/alipay 支付与账号域名）+ 域名分词金融关键字启发，只豁免混合 App 的关键字启发，硬排除优先；命中计入 `mitmFinanceSkipped`。
> - QUIC Initial 解析（`quic.rs`）：从 Initial 包取 SNI，补上「DNS 映射缺失时 QUIC 无域名可判」的空档。
> - 脚本 `$argument` 按声明类型注入（string/number/boolean），Rewrite/Script 条件与动作里的 `${参数}` 按默认值先展开；参数类型随模块一起下发内核。
> - MITM 诊断补齐：`mitmReqs`/`mitmNoRule`/`mitmH2Failed`/`mitmTlsAborted`/`mitmCanceled`/`mitmBypassed` 与临时放行域名快照 `mitmBypassHosts`；DNS 侧新增 `dnsAnySplit`（ANY 拆 A+AAAA 本地合并）与 `dnsUpstreamFail`；主循环新增 `loopRoundMsLast`/`loopRoundMsMax` 与 `tunPoolMiss`；诊断页展示实际 MTU、上游 socket 缓冲峰值与 BBR 生效/回退条数。
> - 保留 2.6.3 的正常关闭计数漏减热修与 2.6.4 的规则集/CSV 解析修复。版本 2.7 / versionCode 95。

> 2.8 正式版（内核 1.13.19，versionCode 102）：MITM 证书与运行时观测补强，并调整自愿打赏入口。
> - 系统 CA 支持一键安装/更新：检测 Magisk/KernelSU/APatch 后写入 `/data/adb/modules/namu_mitm_ca`，证书先落到常驻 `cacerts_staging`，再整目录 bind 到 Conscrypt APEX/legacy 证书库；bind 前 `cmp` 幂等，随后 `nsenter` 注入 init 与 zygote/zygote64 命名空间（PID 去重）。无 Root 时只导出带指纹前缀的模块 zip，不写半吊子模块。
> - 新增「移除系统 CA」：只按 `/proc/mounts` 里 `source == 我们 staging` 精确 umount，逐层校验到无残留，再删模块/日志/状态；APEX 自身和其他模块的挂载一律不碰。
> - CA 状态改为临时文件 + rename 原子写，结尾带 `done=1`；UI 轮询完成标记后回显。模块只含证书段，私钥不出 App 私有目录。
> - 证书模块冲突检测：复用 Root 通道读 init/zygote 挂载栈，最上层不是我们时提示「重新注入」；无 Root 退化为 DER 不一致提示。
> - MITM 大响应提前直通：非文本 Content-Type 且没有二进制脚本，或 `Content-Length > 2 MiB`，在响应头改写后直接流式透传；chunked 超限回退前先 flush 已缓冲前缀，不丢字节。新增 `mitmBodyBypassed`。
> - MITM host 维度观测：按 host 记录 conns/failed/canceled/noRule/rewritten，256 条近似 LRU；stats 输出失败 Top10 与无规则 Top10，UI 支持复制域名与一键加入 skip（只影响新连接）。数据只在本机内存，不上报。
> - 打赏入口移除微信收款码；支付宝改为个人收款码深链 `alipayqr://platformapi/startapp?saId=10000007&qrcode=<编码后的收款码链接>`，点一下直接进「向你付款」页，金额由付款人自填；未安装支付宝时回退 https，仍失败则显示收款码图片。
> - 验收：Rust 236/236、Kotlin 178/178、lint 0 error、两套 ABI 16K 对齐。

> 2.9 正式版（内核 1.13.21，versionCode 104）：六项维修与 A1/B2/B1。
> - host 收敛：B站模块只保留实际有 rewrite/script 的 host，补大会员/开屏/满意度调研规则，DNS 规则补 `cm.bilibili.com`；Host 榜单“加入跳过”改为可逆 toggle，`skipHostnames` 移除即恢复，下一次热重载仅影响新连接；榜单无规则率改按请求数（不是连接数）统计。
> - BBR：首条 WAN socket 试设 `TCP_CONGESTION=bbr` 并 getsockopt 复核，缓存支持/不支持；不支持后不再逐连接 setsockopt，`tcpBbrFail` 只保留探测失败/真实异常，手动总开关仍可强制关。
> - 观测：缓冲池未命中拆 `tunPoolMissRx`/`tunPoolMissTx`；熔断日志改为“冷却中，本机按拨号失败时序收尾（未发 SYN）”；Private DNS `mode=off` 不再展示残留 specifier。
> - A1：备份恢复成功后调用 `MitmManager.export` 复用/生成 CA，再用 `RootCaManager.inspect` 核对；同机同证书不提示，只有指纹变化或系统库/模块都没有匹配证书时才一键安装。
> - B2：叶子证书按 host single-flight，并发首连只签一次；rcgen 放阻塞线程池，不压 async worker；等待有界（128）、4s 超时/打满回退直签，新增 `mitmLeafCacheHit/Miss`、等待/超时/打满/实际签发指标。
> - B1：outbound tcp/tls 拨号与握手指标；MITM 上游池默认关闭，开启后 h1 独占租约、h2 按对端 `SETTINGS_MAX_CONCURRENT_STREAMS` 限流，池键含 host/port/scheme/ALPN/SNI/insecure + target/action；h2 仅在 header 未发出时重试，不盲重试已上传正文。
> - 测试：Rust 252/252 lib + 全量集成、Kotlin 181/181、lint 0 error；两 ABI 16K 对齐。

> 2.8.1 正式版（内核 1.13.20，versionCode 103）：补齐模块改写与脚本运行时的剩余缺口。
> - jq 不再限定 mini 子集：新增自有 lexer/parser/evaluator，覆盖 `.a.b`/`.[]`、管道与逗号、数组/对象构造、`map`/`select`/`del`、比较与算术、`if`、`//`、赋值、`to_entries`/`from_entries`/`with_entries`、`sort`/`sort_by`/`unique`/`unique_by`、字符串函数与 `@base64/@json/@uri/@csv`；`json-jq`/`-jq` 导入不再拒绝。
> - Map Local 除 `data=` 内联外，支持 `data-path=`/`file=`，运行时相对 App 私有目录读取，文件缺失回退 404；Map Remote 翻译为 URL 前缀改写，跨域后按新 host 重建目标并保留路径/查询串。
> - Script v2 条件支持 method、status、request/response header、request/response body 与运行期 Argument 比较；请求正文条件自动触发正文缓冲。Argument 导入即按声明类型注入 `$argument`，运行期修改不重编译脚本。
> - JS 新增 `$environment`（App/系统/设备/语言/时区/版本）与 `$utils`（字节长度、Base64、MD5/SHA1/SHA256/HMAC、URL escape/unescape、geoLookup/getNetworkInfo 占位对象）；`require` 仅开放 crypto/base64/util 内置纯函数模块，不开放文件系统/网络/进程。`$notification.post` 写入 JSONL 队列，由 VPN 前台服务轮询转成系统通知（Android 13+ 检查通知权限）。
> - `[MITM]` 支持 `skip` 列表并合并进内核 `skip_hostnames`，其余细项保留审计；`[General]` 识别 skip-proxy/bypass/dns-server 等常用键，可执行项由壳层接入，TUN 路由项保留原文不虚假承诺。
> - 验收：Rust 248/248 lib + 全量集成测试、Kotlin 179/179、lint 0 error、两套 ABI 16K 对齐。

> 2.7.1 测试版（内核 1.13.13，versionCode 96）：Surge `[Header Rewrite]` 在请求侧 `set_header` 之后，同步把同一条规则追加到 `plan.response_headers`，h1/h2 的 terminal 与上游响应两条路都执行（保持双向兼容，避免只改响应头导致现有模块的请求头改写失效）。Kotlin 新增 `[Map Local]`：`data=` 内联正文翻译成 `mock-response-body`，`status-code=`/`header=` 一并透传，`data-path=`/`file=` 与 `[Map Remote]` 显式报不支持。Script v2 条件不再只限单条 `${url}`：Kotlin 原样透传条件表达式，内核复用 `LoonCond` 条件树，`pattern` 退化为 URL 预筛，实际执行前用 `ScriptMessage.headers` 精确求值；不认的条件继续显式报错。

## 壳设计文档

- Android 12+ 应用壳设计：`docs/UI_SHELL_ANDROID12.md`

## Loon / 小火箭兼容性基线（第 1 步）

- 兼容矩阵：`docs/LOON_COMPAT_BASELINE.md`（节点协议、配置/插件、规则、重写、Script API、MITM）
- M0 基线报告：`docs/M0_BASELINE_REPORT.md`（环境、目标版本、清洁构建、阻塞项）
- M1 修复报告：`docs/M1_SILENT_DROP_REPORT.md`（逐项诊断、AdBlock、REGEX/PORT、HTTPS TLS、模块预览）
- M2 统一配置报告：`docs/M2_UNIFIED_CONFIG_REPORT.md`（版本化模型、来源解析、迁移备份、回滚恢复）
- M3 策略组报告：`docs/M3_STRATEGY_GROUP_REPORT.md`（select/url-test/fallback、组嵌套、TCP/UDP 分离、热更新）
- M4 配置/规则/协议报告：`docs/M4_CONFIG_RULES_PROTOCOL_REPORT.md`（Loon/小火箭导入、Clash 组、规则源缓存、规则扩展）
- M4 协议能力矩阵：`docs/M4_PROTOCOL_CAPABILITY_MATRIX.md`（已实现组合、VMess/Reality/Hysteria2/TUIC 评估与拒绝边界）
- M5 Loon 重写报告：`docs/M5_LOON_REWRITE_REPORT.md`（插件逐段解析、旧/新 [Rewrite]、HTTP/1.1 与 h2、本地导入）
- M6 脚本引擎报告：`docs/M6_SCRIPT_ENGINE_REPORT.md`（QuickJS 选型、ABI/许可证、生命周期、资源限制、MITM 接入）
- M6 脚本 API 矩阵：`docs/M6_SCRIPT_API_MATRIX.md`（`$request/$response/$done`、`$httpClient`、`$persistentStore`、Loon/小火箭差异）
- M7 发布验证报告：`docs/M7_RELEASE_VALIDATION_REPORT.md`（备份恢复、迁移/崩溃报告、重载回滚、实时连接、证书/隐私/限制）
- DNS 默认说明：`docs/DNS_SYSTEM_DEFAULT.md`（基础配置跟随手机 DNS、旧默认迁移、fail-closed）
- 规则集说明：`docs/RULESET_PROTOCOL.md`（RULE-SET / DOMAIN-SET 缓存展开、PROTOCOL、未实现边界）
- h2 超时修复：`docs/H2_IDLE_TIMEOUT.md`（客户端 preface 60s、空闲连接安静回收）
- M5 重写能力矩阵：`docs/M5_REWRITE_CAPABILITY_MATRIX.md`（逐动作支持/不支持边界）
- 固定样本：`compat/fixtures/` 48 个，机器可读预期：`compat/expected/cases.json` 52 条
- 机读矩阵：`compat/matrix.json` 99 行；逐 case 覆盖：`compat/expected/coverage.json` 52 条
- 回归基线：`core/tests/compat_fixtures.rs` 13 项、`core/tests/compat_rules.rs` 1 项、`app/src/test/java/com/namu/dns/CompatFixtureTest.kt` 9 项
- 2.6 基线：Rust 174 lib + 集成套件全通过、Kotlin 全通过、`verifyKernel` 通过；APK/源码 hash 见构建产物与 `SHA256SUMS.txt`
- 规则集/PROTOCOL：`RULE-SET` / `DOMAIN-SET` 导入时缓存并展开，`PROTOCOL,TCP|UDP` 由内核按连接类型匹配；纯规则集模块可导入；详见 `docs/RULESET_PROTOCOL.md`
- 状态：**IMPLEMENTED_WITH_BLOCKERS**；M6 代码/单测通过，脚本端到端仍未验收（无真机、无 iOS/Loon/Shadowrocket 对照设备、无真实授权脚本全集）
- 结论：模块可解析 Loon `.plugin` 的 `[Argument]/[General]/[Rule]/[Rewrite]/[Host]/[Script]/[MITM]`，执行常用 `[Rewrite]` 与结构化 `[Script]`；参数替换、Host 映射、General 全局项仍只记录并展示功能缺口；应用/UID 规则、VMess/Reality/Hysteria2/TUIC 仍明确拒绝

## M6：脚本运行时与 API

- 选型 QuickJS（`rquickjs` 0.12.2，MIT），Rust 内核直接编译/链接；Android arm64-v8a / armeabi-v7a 两套绑定已入库，`.so` 符号与体积验证通过。
- 4 个专用脚本线程，每线程独立 QuickJS Runtime；内存 32 MiB/线程、栈 512 KiB、默认超时 5 s（上限 10 s）；`$done` 首次生效、多次只计数；死循环/超时会被中断，不拖垮隧道。
- 沙箱默认无宿主 fs/net/process API，`eval`/`Function` 全局禁用，能力只经白名单函数注入；完成/失败/超时/跳过计数写入脚本诊断日志。
- 已实现 `$request`、`$response`、`$done`、`$httpClient`（get/post/put/delete/head/options/patch）、`$persistentStore`、`$argument`、`$notification`、`console.log`、`setTimeout/setInterval`。
- `binary-body-mode=true`：`$request/$response.body` 以 Uint8Array 暴露，支持自写 gRPC 帧脚本按原始字节解析和 `$done({body})` 回写；`binary_frame` 验收已纳入 Rust 测试。
- `$httpClient` 改为异步任务队列 + 独立 Tokio runtime：支持 `timeout`/`timeoutMs`（50 ms–10 s）、headers 对象/数组、回调在脚本求值后由完成队列驱动；不再在回调里同步阻塞网络 I/O。
- 三项 MITM 热路径优化：叶子证书缓存满 128 条只 FIFO 淘汰最老一条、HostMatcher 后缀匹配不再 `format!` 分配、HTTP/1 头部扫描从上次末尾增量继续。
- 已驱动 QuickJS 微任务队列：`async/await`、Promise 链、Promise rejection 捕获、`$httpClient` 回调后的续体都能继续执行并调用 `$done`；新增 5 条公开 API 验收测试（请求改写、异步网络、持久化、2 MiB 大正文、请求短路）。
- 请求脚本可改方法/URL/头/正文，`$done({response})` 可短路生成本地响应；响应脚本可改状态/头/正文；HTTP/1.1 与 h2 都接入，声明 `binary-body-mode` 的 gRPC 响应可进入脚本。
- 安全边界：默认拒绝 localhost/私网/环回（含重定向），单次脚本最多 32 次 HTTP、响应 1 MiB；`$httpClient` 默认 4 s、最大 10 s；持久化 1 MiB/256 键；脚本并发 4，拿不到许可直接跳过。
- Kotlin 链路：`[Script]` 结构化解析（phase/pattern/script-path/requires-body/max-size/timeout/tag/argument/enable/binary-body-mode），导入/同步时下载并缓存脚本。
- 导入预览用橙色警示展示脚本数量与 remote `script-path` 来源；不提供模块级脚本开关或额外来源确认。
- 解析器修复：Surge `%APPEND%` MITM 前缀、中段通配主机（`m*.maps.example.com`）、`URL-REGEX ..., REJECT` 转为 MITM 重写；17 个自写合成模块样本已纳入回归；真实模块库仍通过 URL 导入，不随源码仓库分发。
- 差异表与未验收项见 `docs/M6_SCRIPT_API_MATRIX.md`；不承诺 Loon/Surge/Shadowrocket 全生态兼容。

## M5：Loon 插件解析与重写

- 模块页与配置页都新增「从本地文件导入」：本地读取、预览、确认后落盘；本地模块标记 `local://文件名`，不会被远端同步误拉取。
- `ModuleParser` 逐段输出行数/可用行数/状态；`[Rule]` 执行，`[MITM]/[URL Rewrite]/[Header Rewrite]/[Rewrite]` 存储，`[Argument]/[General]/[Host]` 部分记录；`[Script]` 的运行时支持已由 M6 接入，旧式 `script(...)` 动作或缺少 `script-path` 的行仍明确报缺口。
- 新增 `core/src/mitm/loon.rs`：支持 Loon 旧版空格语法和新版 `request/response if ... then ...`；URL 替换、302/307、reject、请求/响应头、请求/响应体正则、JSON 增改删、inline mock。
- HTTP/1.1 与 HTTP/2 都接入 Loon 请求计划：2 MiB 正文预算、超限/压缩回退、`Expect: 100-continue`、跨域改写、响应头组帧补回；`reject` HTTP/1.1 断开、h2 RST_STREAM。
- 明确不支持：`jq`、`data-path` 文件 mock、`script(...)`、`&&`/`||` 等复杂条件；不把 Surge `[URL Rewrite]` 的支持推导成 Loon `[Rewrite]`。
- 版本：2.2.1（versionCode 73），内核 1.11.6；Rust 148/148、Kotlin 96/96、Lint 0 error/38 warning。

## M4：配置、规则集和协议

- Loon/小火箭 `.conf` 从预览改为导入：内联节点、`select/url-test/fallback` 组、常用规则、DNS；未知段落保留，应用/UID 规则拒绝。
- Clash 规则目标保留策略组名，组名优先于内置 `PROXY`；`proxy-groups` 导入为设备策略组；`proxies` 节点仍走订阅。
- 远程规则源支持 `ETag`/`Last-Modified` 条件请求，304 复用缓存；失败保留旧文件和 `.bak`，UI 标记“失败·用旧缓存”。
- 规则引擎新增 `DOMAIN-WILDCARD`、`GEOIP(CN)`；`PROCESS-NAME`/`UID` 等无可靠数据源的规则明确拒绝，不静默丢弃。
- 协议新增本地受控服务端验收：Trojan/VLESS/SOCKS5 建立、双向、失败、重连；SOCKS5 / Trojan / VLESS UDP 单独验证（含节点级 udp:false）；未实现的 VMess/Reality/Hysteria2/TUIC 准确拒绝。
- 版本：2.1（versionCode 71），内核 1.11.5；Rust 139/139、Kotlin 95/95、Lint 0 error/38 warning。

## M3：策略组与规则分流

- `select` / `url-test` / `fallback` 三种组：手动选择持久化、最低延迟选择、按顺序故障切换与恢复阈值
- 组可嵌套；规则和最终策略可直接写组名，`node:` 强制节点；解析链显示“顶层组 → … → 叶子节点”
- 组选择存 `AppConfig.groupSelections`，随 DataStore 持久化，不写入 `.conf`；节点更新导致选择失效时明确报错并禁用该组
- 内核与壳层双校验：空组、重复组名/成员/节点、自引用、嵌套循环（DFS + 保存前 `wouldCreateCycle`）、缺失引用、节点/组同名
- TCP/UDP 分开解析：UDP 只允许 `ss`/`socks5`，TCP 探测结果不写 UDP 健康；规则测试同时展示 TCP/UDP 判定
- 健康检查按组 `test_url` / `interval` / `timeout` / `failure_threshold` / `recovery_threshold` 执行；`select` 不自动切换
- 热更新用 `Ctx.decision` 读写锁保证新连接看到同一代规则/组/节点快照；已有连接继续旧节点
- 配置模型升到 v3；Rust 134/134、Kotlin 94/94、Lint 0 error / 38 warning、清洁构建通过

## M2：统一配置模型与迁移

- `ConfigFile` 增加 `version`（当前 v2）；旧扁平 JSON 与缺 version 的 2.x 文件自动迁移。
- 未知根字段通过 `unknownRoot` / `AppConfig.configUnknown` 原样保留，保存时不覆盖已知字段。
- 新增 `ConfigSourceParser`：原生 JSON、Clash、Loon、小火箭统一识别/诊断/预览；Loon/小火箭只预览不启用。
- Clash 只导入已实现规则/DNS 模式子集，节点仍走订阅导入；错误引用与重复名称按路径定位。
- 迁移前保留 `.legacy.bak`，写 `.tmp` 原子替换并校验；`recover()` 处理残留 tmp、缺失/截断目标；`ConfigFileStore` 保存前保留 `.bak`，配置详情可回退上一版。

## M1：消除静默丢弃与修复基线缺陷

- 订阅解析新增 `diagnostics` / `diagnostic_counts` / `total_lines`：未知 scheme、已知不支持协议、不支持参数、无效条目逐项计数；`raw` 已脱敏。
- 混合有效/未知节点不少算；全部条目被跳过时也返回诊断，不覆盖现有节点。
- AdBlock 支持 `||domain^` 后缀、`|domain|` 精确、`hosts`、裸域名和 `@@` 例外；`$` 条件、元素隐藏、无效语法按原因跳过。
- 模块解析器与手动规则 UI 接入 `DOMAIN-REGEX` / `PORT` / `IP-CIDR6`，非法值在导入前拒绝；规则继续走持久化与 `RuleEngine` 执行。
- HTTPS 代理节点先 TLS 握手再 `CONNECT`，UI 显示为 `HTTPS`；新增本地 TLS 测试代理回归。
- 模块导入预览显示完整支持/部分支持/跳过项；丢失分流目标时必须确认后才能导入。

## 2.0 Android 12+ 应用壳（versionCode 70，历史基线）

- 最低系统改为 Android 12（API 31）；旧壳改动已删除，采用本壳的整页捕获 + Dock 硬件模糊
- 底栏为「首页 · 策略 · 数据 · 设置」四项等宽玻璃 Dock；Dock 背景用 Android 12 RenderEffect 模糊采样底下页面，图标/文字/短线独立绘制
- 页面内容可滚入 Dock 下方；列表末端按实际底栏高度留白（`LocalDockClearance`），不再固定 34dp
- 策略页分「规则｜模块」两段，切页保留导航状态；首页显示真实连接状态、本次查询与拦截数，并保留代理节点入口
- 公共顶栏改为主题底色，Accent 松绿；切页短淡入，无待机循环动画
- 版本名 2.0，versionCode 70；内核仍为 1.11.5

## 1.34.0 gRPC protobuf 字段级改写（versionCode 68）

- h2 的 `application/grpc` 200 响应命中 body 规则时，按 5 字节 gRPC 帧解析 protobuf wire format，递归改写字符串/bytes 字段值
- 不依赖 proto schema，不改变字段号、wire type、字段顺序或帧边界；普通字段、嵌套消息、同一响应多帧都支持
- 压缩帧（flag=1）原样保留；gRPC-Web 不走该路径；解析失败、输出超限或未命中改动时回退原始流式转发
- 改写成功更新 `content-length`，保留 `grpc-encoding`、`content-encoding` 与 trailers；`mitm_rewritten` 照常计数
- 复用全局改写预算，gRPC 按三份正文上限预留，最多 2 条流并发
- 新增 5 项 protobuf 单元测试 + 1 项 h2 gRPC 端到端测试；Rust 测试 106 项通过

## 1.34.0 h2 并发与内存修复（versionCode 67）

- h2 请求上传与上游响应改为并发推进：客户端先发一条消息、等服务端回话再发下一条时，不再互相等待；响应提前结束时停止向已结束的请求流继续写
- DATA 发送按当前可用流控窗口分片，不再等窗口攒够整个 16 KiB 块；小窗口传大响应时，同一连接的短请求也能完成
- 客户端主动取消上传按 `RST_STREAM` 识别为流级取消，不再把共享上游连接标记失效；取消一条上传后，后续 RPC 仍复用原连接
- h2 正文改写增加全局内存预算：每条流按原文、解压结果、改写结果三份预留，最多 2 条流同时改写；额度不足直接原样流式转发，回退时立即释放额度
- 新增 4 项回归：双工提前响应、小窗口大响应、取消上传复用连接、预算额度控制；Rust 测试 100 项通过

## 1.34.0 全面检查（versionCode 66）

- 首启引导明确产品定位：DNS 广告过滤无需 Root、开箱即用；MITM 去广告面向 Root 设备
- MITM 系统级信任继续只走 KernelSU/Magisk 系统信任模块；安装并重启后所有 App 信任 CA，证书绑定应用按握手失败自动放行
- 保留 v65 的精简 Root 定位，不回退用户证书区安装入口

## 1.34.0 精简 Root 定位（versionCode 65）

- DNS 广告过滤无需 Root；MITM 去广告面向 Root 设备
- 移除 MITM 页「用户证书区（本应用可见）」状态与「安装到用户证书区（无 Root）」入口
- 删除 `MitmManager.installUserCert` / `userCertInstalled`、`MitmViewModel` 对应状态与回调，以及相关单测
- MITM 系统级信任只保留 KernelSU/Magisk 系统信任模块：生成含本机 CA 的模块 zip，安装后重启，全 App 信任且重启不丢
- 仍保留 CA 生成、PEM/DER 导出、CA SHA-256 指纹与系统证书区 DER 比对；首启引导文案同步为 Root 模块方案

## 1.34.0 h2 健壮性修复（versionCode 64）

- 清理 `ca.rs` 测试中未使用的 `HandshakeSignatureValid` / `ServerCertVerified` import，`cargo check` 0 warning
- `te` 请求头按 HTTP/2 规范处理：只保留 `te: trailers`，其余值（含多值中的非 trailers）全部删除，避免上游因非法 TE 拒绝请求
- 上游连接改为惰性建立：只有非拒绝 stream 才建连；连接失败自动重试 1 次，仍失败才返回 502；拒绝流不再无谓握手
- 上游 `send_request` 失败会按代际失效旧连接并重连重试；请求体转发失败只失效同代连接，避免误伤其他 stream 新建的连接

## 1.34.0 HTTP/2 响应体改写（versionCode 63）

- h2 MITM 在 `200`、非 HEAD、文本类 `Content-Type`、`Content-Length <= body_limit` 的响应上重组 DATA 帧，gzip/deflate 解码后复用 HTTP/1.1 的 rewrite 引擎
- 改写成功时移除旧 `Content-Encoding` / `Content-Length`，写入新 `Content-Length`，并保留响应 trailers；`200 改写 h2 x→y 字节` 计入 `mitmRewritten`
- 超过 `body_limit` 立即回退为「原始响应头 + 已收原始字节 + 剩余流式转发」，不把大正文读进内存；br/zstd、解压超限、改写放大超限同样原样透传
- SSE、multipart、NDJSON 不进入响应体改写；gRPC 从 v68 起单独走 protobuf 字段级改写
- 一条下游 h2 连接只建立一条上游 TLS/h2 连接，连接内多个 stream 复用；集成测试两条并发 RPC 的上游 TLS accept 为 1，本机端到端 45ms
- 新增测试：gzip 响应改写、DATA 超限回退、一条下游连接并发 RPC 的上游握手数

## 1.34.0 MITM h2 与 gRPC 拒绝（versionCode 62）

- MITM 服务端 ALPN 改为 `h2, http/1.1`：客户端优先协商 h2，不支持 h2 的客户端仍回落 HTTP/1.1
- 新增 HTTP/2 透明桥接：按 stream 解析请求头/URL，请求体、响应体按流控窗口分块转发，不把大响应无界缓存在内存
- URL 规则命中 gRPC（`Content-Type: application/grpc*`）时，用 HTTP/2 trailers 返回 `grpc-status: 7` 与 `grpc-message`，客户端按 gRPC 错误处理；普通 HTTP/2 拒绝仍返回 204/200/tinygif
- 拒绝、放行、握手分别计入 `mitmRejected` / `mitmConns` / `mitmFailed`；视频 App gRPC 广告请求被 URL 规则命中后即可出数

## 1.34.0 系统信任模块装证书（versionCode 61）

- MITM 页的「生成系统信任模块（KernelSU/Magisk）」：在 App 内生成含本机 CA 的模块 zip 到「下载/NamuDNS」，用 KernelSU/Magisk 从存储安装后重启
- 模块自包含证书（只取 `ca.pem` 的证书段，不把私钥写进模块），开机早期合并 Android 14+ Conscrypt APEX 或旧版系统证书目录；tmpfs 叠加，不修改只读分区，重启不丢
- 模块含 `customize.sh` 设置脚本权限；`post-fs-data.sh` 启动早期注入，`service.sh` 在 APEX 时序异常时兜底并绑定到 Zygote；不再 umount 现有系统/APEX 挂载
- 生成后系统证书区状态仍按 APEX DER 比对；重启后回到 MITM 页显示「已检测到」即模块生效

## 1.34.0 A 批优化（壳层）

- A1 快捷设置磁贴：下拉通知栏一键连接/断开，未授权 VPN 时跳回 App 引导
- A2 大屏/折叠屏：内容区最大 640dp 并居中，避免全宽单列过于空旷
- A3 日志跟随：手动上滑自动暂停自动滚动，按钮改为「暂停滚动 / 回到最新」，兼容 Compose 1.7 的滚动状态检测

## 1.34.0 B 批体验优化（壳层）

- B1 通知栏：运行中每 2 秒刷新实时速率，新增「切换节点」动作；点按直达节点页
- B2 节点排序：默认 / 延迟优先（未测速排最后）/ 名称 / 分组，未测速节点显示「—」
- B3 规则管理：单条规则启用开关，禁用规则不下发内核；规则列表支持按类型/值/动作搜索
- B4 首启引导：VPN 权限、导入服务器、私人 DNS 与 Root 三页；设置页可重新查看

## 1.34.0 全面审查修复（versionCode 53）

- 修复 minSdk 24–25 兼容：Root/su 进程不再调用 API 26 的 `waitFor(timeout)` / `destroyForcibly`，导航栏浅色图标资源拆到 `values-v27`
- 修复 su 输出读取先于超时判断导致的永久阻塞；统一后台读输出、轮询退出、超时销毁
- VPN 启动统一走 `NamuVpnService.start()`，前台服务启动被拒绝时清除“启动中”状态；内核缺失和服务销毁路径补齐状态/后台恢复处理
- 修复扫码页 CameraX `ExperimentalGetImage` 显式 opt-in、导航枚举混淆保留，以及 MITM 导出文件名提示

## 1.34.0 M2/M4（versionCode 54）

- M2：MITM 页的忙碌态、CA 状态、证书导出/安装与域名保存收进 `MitmViewModel`，切页状态不丢；JVM 行为测试覆盖导出失败、安装失败、开关联动等路径
- M4：配置详情新增 MITM 分区，展示启用状态、手动域名/跳过域名数量，并直达证书与规则管理页
- 保留 versionCode 53 的 minSdk 24/25 进程兼容、su 超时、启动失败状态、主题资源和 CameraX opt-in 修复

## 1.34.0 MITM 稳定性与证书安装修复（versionCode 57）

- 请求体改为头解析后按原始组帧流式转发，>8 MiB 上传不再整段读入内存；补 `Expect: 100-continue` 本地应答，避免客户端等待死锁
- 请求头长度语义严格校验：非法/冲突的 `Content-Length`、`Content-Length` 与 `Transfer-Encoding` 并存、非 chunked 的传输编码直接拒绝，堵住请求走私入口
- 响应改写上限同时约束压缩前大小、解压后输出和改写后输出；gzip/deflate 解压超过上限、改写放大超过上限时都回退原始响应
- WebSocket 请求保留 `Upgrade` 语义，收到 101 后把客户端与上游切换为双向字节隧道；不再把 `Connection: Upgrade` 改成 `close`
- MITM/日志中的请求路径默认去掉查询串，诊断报告不再带出临时签名或 token；代理 WebSocket 日志同样脱敏
- DNS 反向映射记录同一 IP 的域名冲突；只有唯一映射时才允许用 UDP 443 丢包迫使 QUIC 回落 TCP，共享 CDN IP 不再误伤其他域名
- 用户证书安装适配 Android 10+：系统禁止 Intent 直装 CA，改为导出 PEM/DER 到 `下载/NamuDNS` 并打开安全设置；Android 9 及以下保留系统安装页。MITM 页继续显示 CA SHA-256 指纹与用户证书区检测状态

## 1.34.0 证书信任与 SNI 修复（versionCode 56）

- 443 连接不再先用 DNS 反向映射决定 MITM 域名：优先读取本次 ClientHello 的 SNI，CDN 共用 IP 时按真实 SNI 签发叶子证书；读不到 SNI 就不 MITM，透明转发
- 路由与上游 TLS 也优先使用 SNI，避免反向域名属于其他站点时继续用错域名；SNI 缺失时才回落到反向映射
- MITM 页显示当前 CA 的 SHA-256 指纹；从系统证书安装界面返回本页时，通过 `AndroidCAStore` 按 DER 比对用户证书区，显示“已检测到/未检测到”，便于排除重装后残留旧证书

## 1.34.0：MITM 去广告合并

- 内核：并入 `core/src/mitm`（CA 生成、HTTP/1.1 over TLS 解密、URL 正则拒绝/响应体改写、Header 改写、UDP 443 QUIC 拦截回落 TCP、握手失败 5 分钟自动放行、响应体上限 2MB）
- 兼容 1.33 壳下发的原始规则行：`MitmConfig` 新增 `url_rewrites` / `header_rewrites`，`skip_hostnames` 作为 `skip` 别名；内核在 `from_config` 时复用 Surge 解析器编译成结构化规则，避免「开关开了但规则不生效」
- 壳：新增「设置 → MITM 去广告」页（总开关、CA 生成、KernelSU/Magisk 系统信任模块、仅导出 PEM/DER、手动域名/跳过域名编辑、模块规则计数、运行数据）
- 壳：`NativeCore.nativeMitmExportCa`、`StatsData` 五个 MITM 计数、`Actions.setMitmEnabled/setMitmHostnames/setMitmSkip`（写配置 → 重建模块合并 → 运行中热重载）
- 壳：配置下发补齐 `ca_file` / `body_limit` / `fail_open_ttl` / `upstream_insecure`；证书路径与 `MitmManager.caFile` 一致
- 数据页新增「MITM 去广告」统计区块；模块页文案更新为 MITM/URL/Header 重写已生效
- 版本：壳 1.34.0（versionCode 61，系统信任模块装证书版），内核 1.11.1
- 使用：先在「MITM 去广告」生成 CA；系统级信任走 KernelSU/Magisk 系统信任模块，安装后重启生效；银行/支付类建议加入跳过列表

## 壳 1.33.0：M1 MITM-Ready

- 配置文件新增 `mitm` 分区：`enabled`、`hostnames`、`skipHostnames`、`urlRewrites`、`headerRewrites`；旧配置缺该键时默认空，不改变既有配置行为
- `AppConfig` / `ConfigFile` 双向保留 MITM 分区；`ConfigFile.fromAppConfig` 与 `toAppConfig` 均不丢数据，配置文件切换可带走 MITM
- `ModuleParser` 解析 `[MITM] hostname = ...`（逗号分隔、支持 `*.example.com` 通配）和裸 hostname 行；`[URL Rewrite]` / `[Header Rewrite]` 保存原始规则行；`[Script]`、`[Host]` 等仍计入 ignored，避免静默失效
- 纯 MITM 模块不会产生 DNS 阻断/分流规则；`ConfigStore.rebuildModules` 额外生成 `modules_mitm.json`，启用模块的 hostname/URL 重写/Header 重写合并进内核配置顶层 `mitm`
- 当前仅存储/合并数据，内核 1.10 忽略未知字段；实际解密、证书与 UI 编辑入口留给内核 1.11 / M2，避免把「Ready」误当成已生效

## 壳 1.32.1：审查修复

- Rust `dns_query_log_aggregates_same_domain` / `dns_query_log_keeps_latest_entries` 共用 `DNS_LOG_TEST_LOCK`，默认并行 `cargo test` 不再互相清空全局 DNS 日志；本机连续 15 轮默认并行测试 26/26 通过
- composable `NamuApp` 改名为 `NamuAppShell`，与 Application 类 `com.namu.dns.NamuApp` 区分；`MainActivity` 调用同步更新
- `PrivateDnsController.hasRoot()` 改为解析 `su -c id` 输出里的 `uid=0`，不再只看退出码
- Private DNS 恢复失败时保留 pending，下次启动/覆盖安装继续重试；VPN 服务 `onDestroy` 也补一次恢复，避免全局设置长期停在 off（卸载瞬间无法执行代码，这是 Android 限制）

## 壳 1.32.0：无障碍、触感、设置收尾

- 5.1 `IosSwitch` 增加 `Role.Switch` 与 `stateDescription`，TalkBack 可播报「已开启/已关闭/不可用」；开关实际触控区 51×48dp。T 按钮、首页/配置详情按钮、`TextAction`、`MiniTextAction`、筛选 chip、节点测速按钮等小控件统一扩到至少 48dp
- 5.2 连接开关、首页/服务器页切节点、底部 Tab 切换加 `TextHandleMove` 轻触反馈；节点详情弹窗里切换节点也会触发
- 5.3 设置页「外观」继续支持跟随系统/浅色/深色并同步状态栏/导航栏图标明暗；「延迟测试方法」落到 `pingMethod` 配置，可选 TCP 握手或 TLS 握手，首页测速、节点单测和自动选节点共用；「自动连接」入口继续可用；首页顶部新增订阅信息行（剩余流量、已用/总量、到期、更新时间，点击可刷新）
- 5.4 统一清理重复 import；首页连通性测试和服务器单节点测速状态提升到 `HomeViewModel` / `NodesViewModel`，切页不丢；`EmptyState` 支持图标；运行日志/DNS 查询日志自动滚动改为 `animateScrollToItem`
- 测速方法默认 TCP 兼容所有节点；TLS 握手只适合 TLS 节点，但能发现「TCP 端口通、TLS 握手失败」的情况。自动选节点仍由 WorkManager 每 15 分钟执行

## 壳 1.31.0：按需连接、订阅管理、扫码、节点页与 WorkManager

- 4.1 新增 `AutoConnectReceiver`（BOOT_COMPLETED / MY_PACKAGE_REPLACED）和默认网络回调；开启「自动连接」且 VPN 已授权时自动拉起前台服务。未授权/无节点时降级为通知，不在后台弹 Activity
- 4.2 `fetchTextResult` 带回响应头，解析 `subscription-userinfo` 的 upload/download/total/expire，持久化到 active 配置；首页和服务器页展示剩余流量、到期与更新时间；首页/服务器页支持下拉刷新；`SubscriptionUpdateWorker` 每 6 小时更新
- 4.3 新增 `ScanScreen`：CameraX 预览 + MLKit 二维码识别，识别节点/订阅二维码后走现有导入流程；拒绝相机权限或相机不可用时切换手动粘贴；顶部扫码入口从占位改为真实 `ScanRoute`
- 4.4 服务器页改为 `LazyColumn`，支持名称/地址/分组/协议搜索、单节点测速、长按多选批量删除；分组折叠状态用 SharedPreferences 记忆；NodeRow 增加按压缩放反馈
- 4.5 新增 `RuleUpdateWorker` / `NodeTestWorker`，替代 Activity `LaunchedEffect` 里的规则更新和自动测速循环，划掉界面后仍由 WorkManager 周期执行

## 壳 1.30.0：实时速率、内核统计、深色模式与日志增强

- 3.1 新增 `SpeedSampler`：对累计 up/down 做 1 秒差分并保留最近 60 个采样点，全部使用 Long 运算，避免大流量下 Float 精度抖动；数据页用 Canvas 双色 sparkline 展示上行/下行曲线
- 3.2 数据页补齐内核已输出但壳未接的统计：活跃连接、运行时长、总连接、stale/负缓存/并发合并/rebind/回落、AAAA 拦截，以及 DNS 延迟 `<10/<50/<100/<300/<1000/≥1000` 六档柱状图
- 3.3 `NamuColors` 拆成 light/dark 双套调色板，`NamuTheme(darkTheme)` 支持跟随系统/浅色/深色；设置页「外观」可切换并持久化到 active 配置，顶栏、底栏、卡片、弹窗、日志页均按深色重新校准
- 3.4 运行日志支持 E/W/I 级别与关键字过滤；DNS 查询支持拦截/放行/失败/过滤与域名搜索；点按条目展开全文，长按复制单条

## 壳 1.29.0：配置文件模型、迁移与两级配置页

- 2.1 新增 `ConfigFile` / `GeneralConfig` 模型：`general` 分区收纳 DNS、隧道、路由、规则更新等标量设置，顶层保存 `rules` / `ruleSources` / `modules` / `customAds`；`general` 使用嵌套 JSON，同时兼容旧版扁平 `.conf`
- 2.2 启动时一次性迁移旧 `.conf`：缺失的 general 字段用当前全局设置补齐，旧文件已有键优先；已有 `general` 的文件直接跳过，重复启动不重写、不丢规则；迁移前保留 `*.legacy.bak`
- 2.3 新增 `ConfigRepository`：切换配置时先改 active 名再整体替换内存配置，触发 `onApplied` 重建模块并让运行中的服务走 `ACTION_RELOAD`；`default.conf` 不可删除，删除当前配置回落到 default，支持新建/导入/删除
- 2.4 配置页改为两级：一级是配置文件列表，点任意文件进入二级详情；详情按「当前配置 / 通用 / 规则 / 模块」分区，模块区可直接进入模块管理
- 2.5 配置改动只写当前 active `.conf`，不再刷新全局 `default.json`；启动时优先读取 active 文件，DataStore 里的快照仅用于保留节点/订阅并在文件缺失时兜底

## 壳 1.28.0：运行状态层重构

- `SettingsRepository` 改用 DataStore（`namu_settings`），首次启动一次性幂等迁移旧 `namu_prefs` / `namu_private_dns`；旧偏好保留但不再读写
- `StatsRepository` 在 IO 线程轮询 `nativeStats`，用前后帧差分计算上行/下行实时速率；断开后保留最后一次会话统计，重连时重置
- 服务状态切换后的补帧也由容器内的 IO 协程执行，`nativeStats/nativeLogs/nativeDnsLogs` 不再从主线程调用
- `LogRepository` 按 `sinceId` 增量拉取 `nativeLogs` / `nativeDnsLogs`，通过 `StateFlow` 暴露运行日志与 DNS 日志，最多保留 300 条
- `HomeViewModel` / `DataViewModel` / `SettingsViewModel` 各自暴露 `UiState`，页面不再直接读 `App` 的可变字段；用 Turbine 覆盖配置、运行状态、日志与设置的状态流转
- `App` 只剩 `context` 与 `AppContainer` 入口；`MainActivity`、`NamuVpnService`、`Diagnostics`、配置/节点/模块/日志/对话框全部迁移到仓库或容器
- 数据页接入实时速率展示；断开连接不再清空本次会话统计

## 壳 1.27.0：外壳与 UI 架构重构

- 加入 ViewModel / Navigation Compose / DataStore / kotlinx.serialization / WorkManager 与测试库
- 新增 `Routes.kt`：首页、配置、数据、设置、节点、日志（运行/DNS 两种 kind）、配置详情、模块、扫码全部改为 `@Serializable` 类型安全路由
- 新增 `AppContainer` 手动 DI 容器与 6 个仓库接口/默认实现：Config、Node、Rule、Stats、Log、Settings；默认实现先委托现有 `App` / `Actions` / `ConfigStore`，行为不变
- 新增 `NamuNavHost`：Navigation Compose 接管原 `AnimatedContent` + 5 个布尔导航；顶栏标题、返回按钮、底栏显示随当前路由联动，原屏幕回调全部映射为路由跳转
- `MainActivity` 删除 `HomeTab`、`showLogs`、`showDnsLogs`、`showConfigDetail`、`showModules`、`showNodes` 布尔状态，只保留 VPN 权限/启停/重启职责
- 「扫码」保留为独立 `ScanRoute` 路由对象；当前左上角扫码入口仍复用节点导入流程，避免改变现有行为

## 内核 1.10.0 / 壳 1.26.0：负缓存、日志聚合、复核策略与连接诊断

1. **本地拦截 NXDOMAIN 带 SOA**
   - `blocked_response` 现在在权威区写入 `block.namu.dns.` 的 SOA，TTL/MINIMUM 取配置 `dns.block_ttl`（默认 60 秒，可在「配置 → DNS → 拦截 TTL」切换 15/30/60/120/300）
   - 客户端可按 RFC 2308 做否定缓存，减少广告 SDK 每几十毫秒重试一次
   - 新增本地拦截应答缓存（同一 TTL），热门广告域不再重复查 10 万条规则；换规则时自动清空
   - 上游 NXDOMAIN 没有 SOA 时，负缓存 TTL 由 `dns.negative_ttl` 控制（默认 30 秒）
   - 拦截明细只写 DNS 查询日志，不再写运行日志；运行日志保留连接错误/嗅探/启动等关键信息

2. **同域名重复日志 5 秒窗口聚合**
   - DNS 查询日志按「域名+类型+动作+原因」聚合 5 秒，日志项新增 `count`
   - 日志页显示「本地规则 · 5 秒 120 次」，导出/诊断报告保留准确次数与平均耗时
   - 首次加载/导出会先把未到期的窗口落盘，不会出现「有查询但页面空白」

3. **复核策略拆分，fallback 支持 DoH/DoT**
   - 默认只复核私网/保留/广播等明显异常，不再因为「非中国大陆 IP」就重新查明文 UDP
   - 新增 `dns.fallback_geo_check`（默认 false）：只有显式开启后才把非 CN IP 交给备用复核
   - `fallback` 现在支持 `udp://`、`tls://`、`dot://`、`https://`（DoH），与主上游共用 `query_kind`
   - 统计把备用查询拆成：主上游失败 / 熔断 / 竞速胜出 / 策略复核；报告里的「备用查询」不再被误读成「DoH 失败次数」

4. **指标口径与连接失败信息**
   - `dnsAvgMs` 明确为「上游查询平均耗时」；新增 `dnsLocalAvgMs` 统计本地拦截/缓存/过滤应答耗时
   - 新增 `dnsCacheLookups`，缓存命中率只按「真正进入缓存路径」的查询计算，不再被 820 次本地拦截拉低
   - 连接日志带 `#连接编号`、目标域名/IP、端口、实际动作、耗时；失败示例：
     `#37 连接失败 sdk.e.qq.com:443 [rule] 耗时 4002ms: 直连超时 8.8.8.8:443`
   - 直连超时错误本身也带上具体地址，并发连接可一一对应

## 内核 1.9.8 / 壳 1.25.9：DNS 端点迁出 TUN 接口地址

- 修复「私人 DNS 已关闭、VPN 已连接，但 DNS 查询仍为 0」：原来 `addAddress("10.10.10.2")` 与 `addDnsServer("10.10.10.2")` 用了同一个地址，Android 内核会把发往本机接口地址的报文直接本机投递，不写进 TUN
- DNS 端点改为 `10.10.10.53` / `fd00:1::53`：不再作为 VpnService 接口地址，只加 `/32`、`/128` 路由与 `addDnsServer`，报文必须经过 TUN 才能到达内核
- smoltcp 侧仍把 `10.10.10.53`、`fd00:1::53` 加为接口地址并绑定 53 端口，保证应答源地址正确
- 保留 1.25.8 的「TUN 内所有 :53 劫持」：应用硬编码 `8.8.8.8:53`、`114.114.114.114:53` 仍会进本地引擎

## 内核 1.9.7 / 壳 1.25.8：DNS 劫持范围、Fake-IP 排除与 fallback 污染复核

- DNS 劫持从「只认固定 DNS 地址」扩到 TUN 内所有目的地址的 53 端口：UDP 按目的地址动态建 socket，应答源仍保持 8.8.8.8:53 / 114.114.114.114:53；TCP/53 同样由本地 DNS 服务端应答，且不再被分流规则误拦
- Fake-IP 增加排除表（mihomo fake-ip-filter 同款）：`dns.msftncsi.com`、`www.msftconnecttest.com`、captive portal、`*.lan`/`*.local`、NTP、STUN 等返回真实地址，避免联网探测、NTP、STUN 误判；配置 `dns.fake_ip_filter` 可追加
- fallback 增加污染复核（mihomo fallback-filter 同款）：主上游应答命中私网/保留网段或非 CN IP 时，用 fallback 复核，结果可用才替换；CN 段复用 `cnip.txt`，`dns.fallback_filter` 默认开
- 后台刷新与直连真实解析统一走同一套熔断/污染复核路径，不再绕开 fallback-filter

## 内核 1.9.6 / 壳 1.25.7：无 Root 下的 DoT 853 拦截

- `decide_action` 对 853 早退 Block，TCP 连接主动 RST，尝试让系统私人 DNS 回落
- 数据页与诊断报告新增 DoT/DoQ 853 拦截计数
- 实测：Android Private DNS 若走系统受保护解析器，853 包可能根本不进 TUN，仍会出现 DNS 查询 0；此路径不能替代关闭私人 DNS

## 内核 1.9.4 / 壳 1.25.1：动画耗电与诊断线程修复

- GroupCard 仅在 glow=true 时创建无限呼吸动画，其余卡片不再持续请求帧
- 诊断报告改到 Dispatchers.Default 构建，JNI/内存/日志拼装不再压主线程
- README 与注释统一为实际导出路径 `Download/NamuDNS`
- 缓存落盘重载保留精确剩余 TTL，1/2 秒短 TTL 不再被抬到 5 秒
- AsyncFd::new 迁移到 AsyncFd::register，清掉内核最后一个编译警告

## 内核 1.9.3 / 壳 1.25.0：动画、诊断报告与 10 万规则基线

- UI 动效：连接卡片呼吸描边、行副标题切换上滑淡入、开关按压回弹、节点行按压缩放、日志条目入场动画
- 诊断报告：数据页「导出诊断报告」，包含设备/系统、内核版本、运行时长、请求与缓存命中率、DNS 延迟分桶、内存、网络、两份日志
- 内核新增 DNS 上游延迟分布（<10/50/100/300/1000ms 与 ≥1s 六档）

## 内核 1.9.2 / 壳 1.24.2：断网恢复、构建可移植与 TTL 严格化

- 网络切换：可用性优先（已验证网络压过未验证 Wi-Fi）；断网后恢复、重建中再次切网都会补一次隧道重建
- 构建：链接器全部由 NDK 路径推导，删除 `.cargo/config.toml` 里的绝对路径；`cargo build --locked`
- 构建校验：哈希纳入 Cargo.toml / Cargo.lock 与两个 `.so` 自身摘要，防止二进制被误替换
- DNS 否定缓存：移除 10 秒下限，TTL=0 不缓存，0/1/2 秒短 TTL 不走 serve-stale
- 节点导入：SOCKS5/HTTP 用户名密码做百分号解码，IPv6 主机去掉方括号；补导入→分享→再导入测试

## 内核 1.9.1 / 壳 1.24.1：审查修复与日志导出

- 构建校验改为「源码内容 SHA-256」比对：zip 解压/git 检出不再因 mtime 重置误报，改代码才需要重编内核
- DNS 缓存写入键直接使用原始请求键（含 DO/CD），修复上游应答 DO=0 时「写入键≠查询键」永不命中
- 模块规则跨模块按 类型|值|动作 去重，与预览文案「导入后自动去重」一致
- 「测试规则」提示改为分流语义（命中即停、FINAL 最后），不再混入 DNS 白名单说法
- 日志与 DNS 查询页新增「导出」：写入「Download/NamuDNS/namu_log_时间.txt」，Android 9 及以下写到应用外部目录
- 清理 udp.rs 死代码 endpoint 与多余 mut

## 内核 1.9.0 / 壳 1.24.0：功能与体验

- 规则诊断：规则带来源（配置/订阅/模块名）；「测试规则」显示命中规则、来源、判定动作与实际使用节点，并说明白名单优先、FINAL 最后
- 规则管理：模块导入改为「先预览后确认」，预览显示阻断/分流/不支持条数、与现有模块重复条数；确认后自动去重
- 连接稳定性：沿用并加固 Wi-Fi/蜂窝切换重建 TUN（500ms 防抖）、反复启停串行化
- 日志治理：单条日志超过 1KB 截断，环形缓冲仍为 600 条，避免异常报文撑爆内存

## 内核 1.8.2 / 壳 1.23.3：稳定性收尾

- 否定缓存按 RFC 2308 取 SOA 记录 TTL 与 SOA MINIMUM 的较小值；缓存命中时应答/权威区/附加区 TTL 一并递减
- 缓存写入键与查询键统一（qclass/DO/CD），修复 1.23.2 引入的「写入键与查询键不一致导致永不命中」
- 订阅重定向的鉴权头校验改为完整同源：协议、主机、有效端口三者一致才允许携带
- 构建可靠性：`build-android.sh` 去掉 NDK 硬编码路径；新增 Gradle `verifyKernel` 任务，校验 `.so` 版本戳与 Rust 源码新旧

## 内核 1.8.1 / 壳 1.23.2：稳定性修复

- Fake-IP UDP 回包源地址还原：直连与 SS/SOCKS5 都按客户端原始目标回包，QUIC、游戏、语音通话不再被套接字丢弃
- DNS 缓存与并发合并键加入 qclass、DO、CD，避免不同语义查询复用错误应答
- sing-box 规则含端口/取反/进程等不支持条件时整条跳过并告警，不再只保留域名条件造成误拦截
- 分享链接补全 insecure、flow、WebSocket 参数，修复 vless 重复 fragment；IPv6 服务器统一加方括号；SS 用 URL-safe Base64

## 壳 1.23.0 / 内核 1.8.0：全面代码审查修复（46 个测试全部通过）

**高优先级修复**
- 热重载现在一并更新运行配置/节点/选中线路（Ctx.cfg/nodes/selected 改为可热更）：
  连接中切换「域名嗅探」、修改节点参数不再静默失效；Kotlin 侧移除只比节点名的 nodesKey，
  一律优先热重载、失败才整核重启
- TCP 半关闭语义修正：客户端 FIN 只关闭 client→server 方向，服务端响应继续读到 EOF；
  netstack/ss/vless/ws 的中继桥接全部改为「写侧结束后继续读完读侧」，不再丢响应数据
- VLESS 订阅解析：security 缺省按规范视为 none（明文）；Clash YAML 的 tls 按布尔读取；
  Reality/XTLS Vision/grpc 等未实现节点计入 unsupported 并给出警告，不再静默导入必失败的节点
- WebSocket/HTTP CONNECT 握手保留头部之后的早到数据（PrefixedStream/链式读取），
  服务端 101/200 后紧跟首帧不再丢失；头部扫描改增量，状态码只解析状态行

**中等与低危修复**
- DNS 缓存重启重载时把报文内 TTL 压到剩余有效期，杜绝 TTL 膨胀
- 新增 nativeTestRule：「测试规则」直接调内核 RuleEngine::decide_detail，
  含模块规则/CN 直连/模式覆盖/无节点策略，与运行时完全一致
- 直连 Fake-IP 还原改走本地 DNS 引擎（resolve_real：加密上游+缓存+rebind 防护），
  不再向物理网络系统 DNS 泄露直连域名；UDP 直连同样受益
- 全锥 UDP 会话只接受「发送过的目标」回来的包，阻断路径外注入
- SOCKS5 UDP ASSOCIATE 握手加 12s 超时；VLESS 响应头读取加 8s 超时
- 停止后统计保留：Stats 增加 stopped_at 冻结 uptime，nativeStats 停止后返回会话汇总
- 关键词 AC 构造失败回退逐条 contains（原空模式兜底会拦截一切域名）
- VPN 启动全程后台线程；每秒轮询的 JNI/JSON 解析移出主线程；配置落盘走单线程后台队列
- SOCKS/VLESS 地址编码超 255 字节域名直接报错（原截断长度字节会破坏协议流）
- 缓存改 O(1) 命中 LRU（last_use 序号），落盘按热度取前 4096；命中免全量解析
- 分流规则值加载期归一化：DOMAIN-KEYWORD 大小写不敏感，后缀匹配零分配
- 出站 TLS 配置全局缓存（secure/insecure 各一份），不再每连接重建根证书库
- CN IP 库：u64 计算杜绝 /0 移位溢出，加载时合并重叠区间保证二分正确
- rebind 防护补充 0.0.0.0/广播/组播/CGNAT 100.64/10/基准段 198.18/15
- bootstrap 解析校验应答 ID/question；移除 tcp_query 恒假的长度检查死代码
- WS：回 Pong、校验 Sec-WebSocket-Accept、分片累积 4MB 上限
- SS UDP 增加 salt 重放防护；分享链接 ss 改 URL-safe Base64、密码 percent-encode
- 明文 HTTP 订阅导入给出警告；拒绝 HTTPS→HTTP 降级跳转
- 缺 rules 键的配置回退默认私网直连规则；TCP 并发上限 1024；DNS 待发队列上限 256；
  TUN 部分写入显式报错；DNS over TCP 查询并发处理（RFC 7766 允许乱序应答）
- 竞速查询输家保持存活，失败场景不再重复发起新查询
- 清理死代码：Config.custom_rules、trojan::bridge、dns::gethostname/name

**回归测试**：新增 12 个针对性测试（VLESS 缺省/Reality 拒绝/Clash 布尔 tls、超长域名编码、
缓存 TTL 不膨胀、关键词大小写、CN /0 与重叠、SS UDP 重放、统计冻结、decide_detail 一致性、
WS 早到数据+Accept 校验、HTTP CONNECT 早到数据）。`cargo test --release` 46 个测试全部通过。

**构建说明（内核）**：需要 Rust stable + Android NDK。示例（arm64）：
`rustup target add aarch64-linux-android`，配置 NDK 链接器后
`cargo build --release --target aarch64-linux-android`，产物替换
`app/src/main/jniLibs/arm64-v8a/libnanmen_core.so`（armeabi-v7a 同理）。



Kotlin 壳 + 自研 Rust 内核（`core/`，crate `nanmen_core`，JNI `libnanmen_core.so`）。本版本内核 1.12.5，
通过对照第三方开源内核（sing-box 1.14 / dnsproxy / mosdns / AdGuard Home / mihomo）修补自研内核短板。

## 壳 1.22.0：多配置文件（内核沿用 1.7.2）

- 新增 ConfigFileStore：每份配置独立存成 `filesDir/configs/*.conf`（JSON），只含 DNS/规则/模块等配置字段，不含服务器
- 配置页改成小火箭式：恢复默认 / 新建配置文件 / 导入本地配置 / 从 URL 导入 / 测试规则 / 模块 + 本地文件列表
- 文件行显示修改时间与大小、默认配置橙点、正在使用蓝勾、蓝色「i」进详情
- 切换配置文件：整体替换 DNS、规则、模块并重建模块索引，服务器节点与订阅保持不变；连接中自动热重启
- 详情里可设为当前、复制配置内容、删除（default.conf 不允许删除）
- 设置改动会同步回写当前 .conf，不会出现「设置改了但文件还是旧的」
- 新增「测试规则」：输入域名/IPv4，按当前规则顺序匹配并显示命中的规则与动作

## 壳 1.21.0：服务器分组折叠（内核沿用 1.7.2）

- 节点新增 group 字段（订阅取域名、剪贴板导入记「手动导入」），内核忽略该字段，不影响连接
- 导入订阅新增「追加到现有节点」开关：关闭=清空重导，开启=保留已有分组、同名节点覆盖
- 首页服务器列表按来源分组，分组标题带数量与旋转箭头，展开/收起用高度+淡入动画
- 「添加」和「管理」拆成两个入口

## 内核 1.7.2：映射落盘窗口收紧

- 周期落盘 60s → 30s；停止、热重载仍是即时落盘。磁盘文件仍只存最近 8192 条，大小不随运行时间增长。
- 结论：重启后「查不到域名」的窗口从最长 60s 缩到最长 30s，正常停止/切配置几乎无窗口。

## 壳 1.20.0（内核 1.7.2）

- 首页服务器行的「i」打开节点详情弹窗：协议、地址、加密/SNI/路径、延迟、是否当前
- 详情内可直接「设为当前」「复制分享链接」「删除该服务器」（删除后自动重选首个节点并在连接中重启内核）

## 壳 1.19.0：动效与统一（内核沿用 1.7.1）

- 页面切换：Tab 与二级页统一用淡入 + 轻微横向滑入的过渡
- 底部胶囊标签栏：选中态改为滑动的高亮胶囊，图标文字颜色渐变
- 设置行：iOS 式点按反馈（轻微内缩 + 淡灰底），不再生硬
- 分组卡片：进屏时上浮淡入；圆角与左右边距统一为 14dp / 12dp
- 弹窗：缩放 + 淡入出现
- 数据页指标：数值变化带补间动画
- 日志页：列表改为圆角卡片，与其它页面统一
- 修复：服务器行的蓝色「i」按钮原来会误触切换节点，现在进入服务器管理

## 内核 1.7.1：外部审查修正（第八批）

- 精确域名规则不再向子域名回溯（原来 example.com 会误伤 a.example.com）；后缀规则语义不变，补了单测
- 关闭 Fake-IP 时也记录「真实 IP → 域名」反向映射，UDP 才能命中域名规则
- rebind 防护的拦截结果不再被日志记成「放行」；后台缓存刷新同样过 rebind 检查
- 连续保存配置不再丢最后一次：重载进行中收到新请求会排队，结束后补跑
- DoT 连接池排队时间计入 8s 总预算；UDP 会话空闲回收 300s → 180s
- nativeStart 等 TUN 协议栈真正就绪（最多 300ms）后才返回，界面不再提前显示「已连接」

## 壳 1.17.0：小火箭式 UI（内核沿用 1.7.0）

- 首页：首行改为当前节点名 + 连接开关；连通性测试右侧改成小火箭式圆形「T」按钮
- 首页节点行：圆形协议徽标、延迟右置、蓝色「i」信息按钮（进入服务器管理）
- 设置页：按小火箭分组为「高级（延迟测试方法/诊断/外观）」与「隧道（隧道/代理/TCP/UDP）」
- 数据页：日志分组增加「自动删除」开关（连接前清空上次日志，真实生效）；新增「服务器节点」分组：导入节点、导出节点（复制分享链接到剪贴板）、删除所有节点（二次确认）
- 底部标签栏改为小火箭式悬浮胶囊

## 内核 1.7.0：终检修正（第七批）

终检时发现 1.6.0 声称修复的「并发合并应答 ID 回写」实际没有写进代码（字符串替换未命中、未复核）。
本版真正落地，并新增端到端测试（本地假上游 + 两个并发请求不同 ID），去掉补丁该测试必失败，防止再犯。

同时加固：
- DoT 写入前校验查询长度 ≤ 65535（超长会破坏长度前缀）
- TCP DNS 应答长度前缀超 16 位时丢弃（避免截断成错误长度）
- 订阅解析：YAML 端口超过 65535 视为无效节点（原 as u16 会静默回绕到别的端口）

## 内核 1.6.0 增量（第六批）

- DoT 改为 4 条连接的小连接池：突发解析不再排队等单条 TLS 连接；空闲 30s 回收，出错自动重连重试
- 直连与 TLS 连接支持双栈回落：解析出多个地址时依次尝试前两个（各 4s），避免首个 IPv6 地址不可达就整体失败；已是真实 IP 的连接不再重复解析
- 节点列表改为 Arc 共享：每条 TCP 连接不再整份克隆节点配置（高并发下减少分配）
- TCP 收包与 TCP DNS 读循环复用 scratch buffer：不再每个报文新建 16KB

## 内核 1.5.0：全量内审（第五批）

内审范围：dns.rs / netstack.rs / lib.rs / engine.rs / outbound.rs / proto/* / subscribe.rs / sniff.rs / udp.rs，重点看崩溃点、协议正确性、资源泄漏。

修复（用户可感）：
- single-flight 合并应答没有改回请求方 ID：并发查询时跟随者收到 leader 的 ID，客户端按 RFC 丢弃应答，表现为偶发"解析超时"。现在合并后统一回写本查询 ID
- UDP DNS 应答不按客户端 EDNS 载荷截断：非 EDNS 客户端（声明 512）可能收到 1232 字节应答被丢弃。现在超长应答置 TC 位只留问题段，客户端按标准改走 TCP（本内核内置 TCP DNS 服务端）

修复（健壮性）：
- 落盘改为脏标记驱动：只有缓存/Fake-IP 真正变化才写盘，避免每 60s 无条件写几 MB
- Fake-IP 落盘只保留最近 8192 条，防止长期运行后文件膨胀
- race 分支与全局锁的 unwrap 改为容错（poison 锁不再 panic）

已知但本轮不改（记录在案）：
- 应用自带 DoH / DoH3 / HTTPDNS 时仍可能绕过本地过滤：DNS-only 全量接管后 53 端口任意目的地址都已被劫持、853 默认被 `block_dot` 拒绝，但 443 上的加密 DNS 在不开 MITM 时无法识别；系统私人 DNS 仍建议关闭或设为自动
- 单条 DoT 连接串行化，突发查询会排队（可扩成 2-4 条连接池）
- 直连域名用系统解析，查询会走底层网络 DNS（隐私上可接受）
- WS 握手未校验 Sec-WebSocket-Accept、早到帧会丢弃（自建节点场景影响小）

## 内核 1.4.0 增量（第四批）

- DNS 缓存落盘预热：停止/每 60s 把缓存（含负缓存）写盘，启动时载入，重启后热域首次解析直接命中（sing-box cache_file 同款）
- Fake-IP 池满改为按分配顺序淘汰最老映射，不再整表清空——整表清空会让存量 Fake-IP 指到错误域名
- 统计新增 dnsAvgMs（上游平均往返耗时）；数据页新增「DNS」卡片：查询数 / 缓存命中 / 平均耗时

## 内核 1.3.0 增量（第三批）

- DoT 连接复用：TLS 配置与证书库只加载一次，查询复用同一条 TLS 连接，空闲 30s 或出错才重连（原来每查询一次完整 TCP+TLS 握手并重读系统证书）
- bootstrap 修正：上游写域名时用 bootstrap DNS 真正解析出 IP（原实现直接把 bootstrap 地址当上游地址连，等于连错服务器）
- 转发查询 EDNS 载荷抬到 1232：减少大应答被 512 字节截断后回退 TCP；UDP 接收缓冲 2048→4096
- `dns.block_aaaa`「关闭 AAAA」：节点只有 v4 出口时返回空 NOERROR，避免 App 拿到 v6 地址连不通（mihomo ipv6:false 同款），设置页可开关
- 关键词规则改用 Aho-Corasick 单次扫描（规则上万条时不再逐条 contains）

## 内核 1.2.0 增量（第二批）

- single-flight 并发去重：同域并发查询共享一次上游请求，跟随者直接复用结果（AdGuard/dnsproxy 同款）
- 上游熔断：连续 3 次失败后 30s 内直接走备用，到期半开试探主上游（mihomo health-check / AdGuard failover）
- DNS rebind 防护 `dns.rebind_protection`（默认开）：公网域解析出私网/环回/链路本地地址视为投毒，白名单豁免（dnsmasq stop-dns-rebind / AdGuard）
- 真 LRU：缓存命中移到队尾，不再 FIFO 误淘汰热域（mosdns lru）
- 热域预取：命中 ≥3 且剩余 TTL < 1/5 时后台刷新（mosdns prefetch）
- AdGuard `$important` 语义：显式 important 拦截优先于 `@@` 例外白名单
- 配置/规则热重载：节点与线路不变时 `nativeReloadRules` 只换过滤/分流/DNS 引擎，TUN 与连接不中断；旧 Fake-IP 先落盘再由新引擎加载（sing-box serviceReload）
- 统计扩展：dnsCached / dnsStale / dnsNegative / dnsCoalesced / dnsRebind / dnsFallback / dnsTcpRetry

## 内核 1.1.0 修补清单（参考来源）

- 应答校验：ID / question / opcode / QR 全比对，错配应答不进缓存（dnsproxy、sing-box）
- UDP 应答 TC 截断自动转 TCP 重查（sing-box、dnsproxy）
- 负缓存：NXDOMAIN / 空 NOERROR 按 SOA minimum TTL 缓存，SERVFAIL 不缓存（sing-box extractNegativeTTL）
- 乐观缓存：过期条目先应答（TTL 压到 5）再后台刷新，`dns.serve_expired` 可关（mosdns serve-expired、sing-box optimistic）
- 主/备上游并发竞速 `dns.race`，先回先用（dnsproxy parallel、sing-box race）
- 转发前剥离 EDNS Client Subnet，避免泄露客户端网段（AdGuard、dnsproxy 默认）
- Fake-IP 映射落盘 `fake_ip_file`，60s 周期 + 停止时 flush，重启后连接层仍可反查域名（mihomo、sing-box cache_file store_fakeip）
- 规则格式新增 sing-box source rule-set（domain / domain_suffix / domain_keyword / domain_regex），
  与订阅生态同格式；AdBlock / hosts / 纯域名语法保留
- 缓存命中递减 TTL、Fake-IP、反向映射、嗅探、拦截应答模式（nxdomain/zero）为自研原有能力，保留

## 构建

- JDK 17、Android SDK（compileSdk 36 / minSdk 31）、Gradle 8.14
- Rust：`cargo build --release --target aarch64-linux-android`（及 armv7-linux-androideabi），
  需设置 `CC_<target>` / `AR_<target>` 指向 NDK r28 的 clang / llvm-ar；
  `.cargo/config.toml` 已配置 linker 与 16K 页对齐
- 产物 `core/target/<target>/release/libnanmen_core.so` 放入 `app/src/main/jniLibs/<abi>/`
- 签名：`keystore/namu.jks` + `keystore.properties`（不随源码包分发）
- `./gradlew :app:assembleRelease`

## 测试

`cd core && cargo test`：195 个内核单测 + 集成测试（应答校验 / ECS 剥离 / 负缓存 / 乐观缓存 / sing-box 规则接入 / 拦截应答 / Fake-IP 反向映射 / 嗅探 / SS UDP / 订阅解析 / MITM 脚本与 TLS / 巨帧队列 / 金融排除等）。
## 自愿打赏（可选）

南门DNS 以 **GPL-3.0-only** 开源，**全部功能完整开放，无任何付费内容、会员或功能解锁**。如果它对你有帮助，可以自愿请作者喝杯咖啡。打赏前请知悉：

- 打赏**完全自愿**，不构成对任何软件、服务或功能的购买；
- 打赏**不解锁任何功能**，不换取优先支持、定制开发或其他对价；
- 本项目仅供学习与研究，**不提供任何代理服务、节点订阅或跨境网络服务**，打赏不会改变这一性质，也不产生任何服务义务；
- 请量力而行，学生与经济尚未独立的朋友尤其不建议打赏。

打赏入口：App「设置 → 关于 → 支持作者」。目前只保留支付宝个人收款入口：点击后通过 `alipayqr://platformapi/startapp?saId=10000007&qrcode=...` 深链直接进入支付宝「向你付款」页，金额由付款人自己填写；未安装支付宝时回退打开收款码网页，仍无法打开则显示收款码图片。爱发电入口默认关闭，可在 `DonateDialog.kt` 的 `DonateInfo.AFDIAN_URL` 填写后显示。
