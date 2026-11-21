# 按 App 隔离（UID 匹配）

**状态**：已实现（TCP 连接维度），版本 2.3.8 / 内核 1.12.5。
**解决的第 5 点**：`PROCESS-NAME` / `UID` / `APP` 规则此前被「无 Android UID/进程名数据源」拒绝，所有规则都是全局生效。

## 1. 为什么必须由壳层提供数据

内核是 Kotlin → Rust 单向 JNI：`lib.rs` 里只有壳层调内核的入口，没有保存 `JavaVM` 供内核反向回调。
TUN 里也只能看到 IP 包的五元组，看不到「这个连接属于哪个 App」。

因此 UID 不可能由内核实时查询，只能由壳层读系统表后**主动下发**。

## 2. 数据链路

```
root 读 /proc/net/tcp{,6}     壳层每 2 秒
   ↓ 五元组 + uid
UidResolver.parseProcNet      纯函数，可单测
   ↓ 紧凑 JSON [[lip,lp,rip,rp,uid],...]
NativeCore.nativeSetUidMap    整表替换，8192 条上限
   ↓
Ctx.uid_map (RwLock<UidMap>)  两个索引：精确五元组 + (源端口,目标,目标端口)
   ↓ TCP accept 时查一次
MatchInput { domain, ip, port, kind, uid }
   ↓
RuleEngine::decide_input      RuleKind::Uid(u32) 参与匹配
```

### 为什么需要「源端口 + 目标」的退化索引

TUN 包里看到的源地址是 VPN 接口地址（如 `10.10.10.1`），
而 `/proc/net/tcp` 里 App socket 的 local 地址是物理网卡地址（蜂窝 `10.x` 或 Wi-Fi `192.168.x`）。
两者天然不一致，只做精确五元组会一条都命中不了。源端口由内核分配，配合目标地址足以定位。

## 3. 包名规则如何落地

内核只认数值 UID。配置里保留用户写的包名（可读、换机后自动重解析）：

- `AppUidResolver` 用 `PackageManager.getApplicationInfo(pkg).uid` 解析；
- 进程名带子进程后缀（`com.example.app:push`）取冒号前的包名；
- 展开发生在 `ConfigStore.buildNative`，即每次下发内核前；
- 未安装的包解析不到 uid，该条跳过并记日志，不会下发一条永不命中的规则。

## 4. 安全边界

- **未知 ≠ 0**。查不到归属时 `uid = None`，UID 规则一律不命中。UID 0 是 root，
  把未知当 0 会让「只拦某 App」的规则误伤 root 流量。
- **普通读取不可信**。非 root 进程读 `/proc/net/tcp` 会「成功」但只有自己名下的 socket，
  所以必须先试 `su`，普通读取只作无 root 兜底。
- **整表替换而非增量合并**。已关闭的连接必须从表里消失，否则会留下幽灵归属把流量判错。
- **连续失败退避**。无 root 设备连续 3 次失败后退避到 10 秒一次，并下发一次空表明确告知内核，
  不会拿着过期表误判，也不会每 2 秒白跑一次 su。

## 5. 当前限制

| 限制 | 原因 | 影响 |
| --- | --- | --- |
| 只对 TCP 生效 | UDP socket 多为 unconnected（remote 为 `0.0.0.0:0`），五元组无法定位 | QUIC（UDP 443）流量不受 UID 规则影响；QUIC 拦截仍按域名生效 |
| 需要 Root | `/proc/net/tcp` 全表读取受 SELinux 限制 | 无 root 时规则静默不生效；数据页会显示「归属未知」与原因 |
| 最长 2 秒延迟 | 轮询周期 | 新建连接在首次轮询前可能查不到归属（记为 unknown，不误判） |
| 多用户/工作资料 | `getApplicationInfo` 默认用户 | 分身应用可能解析成主用户 uid |

## 6. 验证方式

- Rust：`uidmap` 7 个用例（整表替换、未知不返回 0、坏行跳过、退化索引、上限），
  `engine` 4 个用例（UID 参与匹配、只命中指定 App、未知不命中、非法值拒绝）。
- Kotlin：`UidResolverTest` 10 个用例（IPv4/IPv6 解码、LISTEN 跳过、SYN_SENT 保留、JSON 输出）。
- 运行时：连接日志现在带 `uid=`；数据页「按 App 分流」显示已识别/未知/下发条目。
  用 `UID,10100,BLOCK` 这类规则配合日志即可确认「只对目标 App 生效」。

## 7. 示例

Loon 风格配置：

```
[Rule]
PROCESS-NAME,com.bilibili.app,BLOCK
DOMAIN-SUFFIX,bilibili.com,DIRECT
```

含义：只对 B 站拦广告域名，微信等其他应用的同名域名请求不受影响。
