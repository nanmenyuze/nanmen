use crate::config::{Config, Node, Target};
use crate::dns::DnsEngine;
use crate::engine::{Action, ConnKind, FilterEngine, RuleEngine};
use crate::logging;
use crate::outbound::{self, BoxStream};
use crate::stats::Stats;
use crate::strategy::{HealthRegistry, NoNodePolicy, StrategySet, Transport};
use crate::udp::UdpMode;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Address,
    Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, Notify};

pub struct Ctx {
    /// 运行配置可热更：nativeReloadRules 会整体替换，
    /// netstack 一律通过下面的快照方法读取，不再持有旧值。
    pub cfg: std::sync::RwLock<Config>,
    pub filter: Arc<FilterEngine>,
    pub rules: Arc<std::sync::RwLock<Arc<RuleEngine>>>,
    pub dns: Arc<std::sync::RwLock<Arc<DnsEngine>>>,
    pub stats: Arc<Stats>,
    pub shutdown: Arc<AtomicBool>,
    pub nodes: Arc<std::sync::RwLock<Arc<Vec<Node>>>>,
    pub selected: Arc<std::sync::RwLock<Option<String>>>,
    /// M3 策略组快照；热重载整体替换，已有连接继续使用旧解析结果。
    pub strategy: Arc<std::sync::RwLock<Arc<StrategySet>>>,
    /// TCP/UDP 分开记录的健康状态。
    pub health: Arc<HealthRegistry>,
    /// 配置热更与“新连接决策”共用的读写锁：保证规则/策略组/节点/选中项是一次完整快照。
    /// 已有连接不持有它，热更不会中断它们。
    pub decision: Arc<std::sync::RwLock<()>>,
    /// MITM 去广告状态（引擎 + CA），热重载整体替换。
    pub mitm: Arc<std::sync::RwLock<Arc<crate::mitm::MitmState>>>,
    /// 五元组 → 归属 UID。由壳层用 root 读 socket 表后整表下发；
    /// 没有 root 时为空，UID 规则不生效而不是猜。
    pub uid_map: Arc<std::sync::RwLock<crate::uidmap::UidMap>>,
    /// 活跃 TCP 连接快照，供壳层「实时连接」页轮询。
    pub conns: Arc<std::sync::RwLock<crate::conns::ConnTable>>,
    /// 壳层切网（蜂窝↔Wi-Fi）时置位：主循环下一轮清空 QUIC 黑洞判定。
    /// 旧网络上的「UDP 假活」结论不能带到新网络，否则新链路会被误压制 10 分钟。
    pub quic_clear: Arc<AtomicBool>,
}

impl Ctx {
    pub fn dns(&self) -> Arc<DnsEngine> {
        self.dns.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
    pub fn mode(&self) -> String {
        self.cfg.read().unwrap_or_else(|p| p.into_inner()).mode.clone()
    }
    pub fn block_dot(&self) -> bool {
        self.cfg.read().unwrap_or_else(|p| p.into_inner()).block_dot
    }
    pub fn sniff(&self) -> bool {
        self.cfg.read().unwrap_or_else(|p| p.into_inner()).sniff
    }
    pub fn block_when_no_node(&self) -> bool {
        self.cfg.read().unwrap_or_else(|p| p.into_inner()).block_when_no_node
    }
    pub fn nodes_snapshot(&self) -> Arc<Vec<Node>> {
        self.nodes.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
    pub fn selected_snapshot(&self) -> Option<String> {
        self.selected.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
    pub fn strategy_snapshot(&self) -> Arc<StrategySet> {
        self.strategy.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
    pub fn mitm(&self) -> Arc<crate::mitm::MitmState> {
        self.mitm.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

struct TunDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    rx_pool: Arc<Mutex<Vec<Vec<u8>>>>,
    tx_pool: Arc<Mutex<Vec<Vec<u8>>>>,
    mtu: usize,
    queue_cap: usize,
    pending_cap: usize,
    write_burst: usize,
    stats: Arc<Stats>,
}

/// smoltcp 的延迟 ACK 时长。默认 10ms 会让下行 ACK 回填慢半拍，
/// 在高带宽链路上一旦窗口被 ACK 节奏卡住，表现就是瞬时速率上不去、抖动变大。
/// 5ms 是「少发几个纯 ACK 包」和「窗口不断流」之间的折中。
const ACK_DELAY_MS: u64 = 5;
/// 1500 档的包数上限参考值（测试与默认口径）；运行时按实际 MTU 由 queue_caps 换算。
#[cfg(test)]
const MAX_TX_QUEUE: usize = 512;
/// 1500 档参考值（测试口径）；运行时上限见 queue_caps / device.pending_cap。
#[cfg(test)]
const MAX_PENDING_OUT: usize = 512;
/// TUN tx 队列 / pending_out 的字节预算（≈1MB）：按实际 MTU 换算成包数上限，
/// 背压口径不随巨帧漂移（1500 档仍 512 包，9000 档约 116 包，字节总量不变）。
/// 1MB 在 100Mbps 满载的理论排队时延约 85ms，但队列只在瞬时突发时堆积，
/// 稳态由写 TUN 的消费速度决定；多余的长期积压仍由 TCP 窗口流控回压，不丢包。
const TUN_QUEUE_BYTES: usize = 1024 * 1024;
/// 由字节预算按 MTU 换算的包数上限三元组：(tx 队列, pending_out, 单轮写 burst)。
/// 写 burst 与 pending_out 同档：一轮可清空整个队列，单轮写入是 memcpy 级，
/// 仍远低于旧逻辑「一口气 + 慢写」导致的几十 ms 饿死区间。
fn queue_caps(mtu: usize) -> (usize, usize, usize) {
    let per = (TUN_QUEUE_BYTES / mtu.max(1)).clamp(64, 512);
    (per, per, per)
}
/// QUIC 假活探测窗口：客户端发了 443/UDP 包，这么久没有任何回包就判定该目标
/// UDP 不可用（蜂窝网上的 QUIC 黑洞），之后对同一目标丢弃 QUIC 让客户端回退 TCP。
const QUIC_PROBE_WAIT_MS: u64 = 2500;
/// 握手无回包判黑洞的窗口：比 QUIC_PROBE_WAIT_MS 长，覆盖 Initial 丢包后
/// PTO 重传的正常握手耗时（2.5s 会把加载期/弱网握手误判成黑洞）。
/// 只对「从未见过下行」的流生效；见过下行=握手已完成，豁免判死。
const QUIC_HANDSHAKE_WAIT_MS: u64 = 5000;
/// 判定为 UDP 黑洞后的压制时长；到期会重新试探，避免网络恢复后一直走 TCP。
const QUIC_BLACKHOLE_TTL_SECS: u64 = 600;
/// 直连拨号熔断：首次失败容忍（瞬时抖动），第 2 次连续失败起冷却 10s，
/// 之后翻倍、封顶 60s。冷却期内同目标新连接直接 RST，不发 SYN 白等 2s。
const DIAL_BREAKER_BASE_SECS: u64 = 10;
const DIAL_BREAKER_CAP_SECS: u64 = 60;
/// 新连接等待首包（SNI/HTTP 探测判定）的上限。180ms 会把「连上就不发数据」
/// 的延迟探测类连接每条凭空加 180ms；60ms 足够覆盖正常 TLS ClientHello 到达。
const SNI_WAIT_MS: u64 = 60;
/// 每轮主循环从 TUN 连续读取的包数上限。
/// 64 档在跑量时读侧先见底：RX 一停，ACK 回填就慢，反过来把下行窗口压住。
/// 抬到 512 与写侧对齐；读取是非阻塞的，读到 WouldBlock 立刻停，不会长时间占住单轮。
const MAX_RX_BURST: usize = 512;
/// 每轮主循环从 relay 通道搬入 pending 的最大块数（128×16K≈2MB/轮，实际受 pending 字节上限约束）。
/// 太小会把单连接吞吐压成「块数 × 块大小 / 轮询间隔」，太大则单连接 pending 占内存。
const RELAY_DRAIN_BURST: usize = 128;
/// 非空闲时的兜底轮询间隔。出站数据由 Notify 事件唤醒，兜底只管「万一漏唤醒」，
/// 因此保持 20ms：挂着的空闲长连接不该被更密的定时器反复空转，那是纯耗电。
const IDLE_SAFETY_WAIT_MS: u64 = 20;
/// 收发缓冲池上限；每个缓冲最多 MAX_TUN_PACKET 字节（巨帧档 9216）。
/// 512 档换更少的每包分配（虚拟 worst-case 约 9MB，物理按实际写入增长）。
const MAX_POOL: usize = 512;
/// TUN 单包上限：必须 ≥ 壳 setMtu 的最大档（9000）+ 余量，否则巨帧包在读侧被截断。
/// 池缓冲走惰性零页，物理内存按真实写入增长，虚拟worst-case 128×9216×2≈2.3MB。
const MAX_TUN_PACKET: usize = 9216;
/// 每条 TCP 连接在 smoltcp 内的收发缓冲（每方向 512K）。
/// 关键不只是缓冲大小：smoltcp 0.11 的接收窗口缩放 shift = log2(rx_cap) - 16，
/// 512K 时 shift=3、通告窗口 ~512K，单流上限从「128K / RTT」抬到「512K / RTT」：
/// RTT 40ms 时 128K 档只有 ~25Mbps，512K 档能到 ~100Mbps——这就是「单流慢、
/// RTT 抖一下下载就掉」的主因，只放宽 TUN 队列治不了它（积压只是从 pending
/// 挪回 socket 缓冲，窗口该关的时候照样关）。
const TCP_SOCKET_BUFFER: usize = 512 * 1024;
/// 大档发送方向（smoltcp→App，本机腿）单独缩到 256K：这条腿 RTT 亚毫秒，
/// 256K 的突发吸收绰绰有余；下游真正的突发吸收由 TCP_PENDING_CAP(2MB)＋滞回承担。
/// 接收方向不缩：它是上行对调度抖动的突发闸门（单轮循环搬多少受 recv 缓冲约束），
/// 对称缩会把「调度尖刺→上行掉速」的老病 reintroduce。
const TCP_SOCKET_BUFFER_TX: usize = 256 * 1024;
/// 内存水位降级档：活跃 TCP socket 超过 `TCP_BUFFER_HIGH_TIER_MAX` 后新建的用 128K。
/// 不设这条守卫，1024 条连接每条双向 1MB，最坏会顶到 1GB，VPN 进程会被 LMK 直接杀。
const TCP_SOCKET_BUFFER_MIN: usize = 128 * 1024;
/// 用大档的「当前并发」socket 数量上限（不是历史前 128 条）：
/// 大档名额随 socket 关闭立刻释放，新连接可以补位——否则开机早期的推送/IM 长连接
/// 会把大档占满，后面真正跑量的下载只能拿 128K。
/// 名额按真实大档占用（BIG_TIER_IN_USE）判定，不再用 socket 总数代理：
/// 总数含 listener/降级档/关闭中，代理口径会把名额虚占满、也会骗诊断仪表。
/// 内存口径：vec![0u8; N] 走 alloc_zeroed→calloc 的惰性零页，物理页按真实写入增长，
/// 所以纸面 worst-case 是虚拟口径，PSS 只随真实流量涨，LMK 风险比纸面小。
const TCP_BUFFER_HIGH_TIER_MAX: usize = 128;
/// 判别仪表的采样节拍（毫秒），计数按「条件成立期间累计 ms」记。
const METER_TICK_MS: u64 = 500;
/// 活跃 smoltcp TCP socket 数（listener 与已建连接共用同一个 socket，只算一次）。
/// 只用于决定新 socket 用哪一档缓冲；漏减只会让后续连接降级，不会造成内存越界。
static TCP_SOCKETS: AtomicUsize = AtomicUsize::new(0);
/// 真实大档占用数：add_listener 拿大档时 +1，release_tcp_socket 按 recv 容量判档 -1。
/// 既是名额判定依据，也是诊断 bigTierInUse 的唯一口径（不再 min(总数,128) 代理）。
static BIG_TIER_IN_USE: AtomicUsize = AtomicUsize::new(0);

/// 返回 (接收缓冲字节, 是否因水位降级)。降级要记进 `tcpBufferDenied`，
/// 否则「守卫悄悄把大档收走了」在诊断里完全看不出来。
fn next_tcp_buffer_bytes() -> (usize, bool) {
    if BIG_TIER_IN_USE.load(Ordering::Relaxed) < TCP_BUFFER_HIGH_TIER_MAX {
        (TCP_SOCKET_BUFFER, false)
    } else {
        (TCP_SOCKET_BUFFER_MIN, true)
    }
}

/// 所有 TCP socket 的销毁都必须走这里：abort + remove + 归还计数。
fn release_tcp_socket(sockets: &mut SocketSet<'_>, handle: SocketHandle) {
    // 先读容量判档再 remove：大档 recv=512K、降级档 recv=128K，可区分。
    let big = sockets
        .get::<tcp::Socket>(handle)
        .recv_capacity()
        == TCP_SOCKET_BUFFER;
    sockets.get_mut::<tcp::Socket>(handle).abort();
    let _ = sockets.remove(handle);
    TCP_SOCKETS.fetch_sub(1, Ordering::Relaxed);
    if big {
        BIG_TIER_IN_USE.fetch_sub(1, Ordering::Relaxed);
    }
}
/// MITM 本地双工管道容量；DNS TCP 管道同档 64K。
const MITM_DUPLEX_CAP: usize = 128 * 1024;
const DNS_TCP_DUPLEX_CAP: usize = 64 * 1024;
/// 每个 UDP 目的端点的单方向缓冲。QUIC 包约 1400 字节，巨帧档 App 可能发更大的
/// UDP 数据报；32K 旧档在 9000 MTU 下只装得下 3 个大包，满即丢；64K 在跑量时
/// 仍会因瞬时突发顶格，故抬到 256K（虚拟内存，物理按实际包增长）。
const UDP_DST_BUF: usize = 256 * 1024;
/// metadata 槽位必须跟缓冲容量匹配：槽位先耗尽会提前丢包，缓冲再大也没用。
const UDP_META_SLOTS: usize = 256;

/// TCP keep-alive 探测间隔。运营商 NAT / 家用路由器的空闲映射通常 3~5 分钟就被静默清掉，
/// 不主动探测的话长连接会「看着还连着、实际已经死了」：推送延迟、消息半天不到、游戏掉线。
/// 60s 一次 ACK 探测足以把 NAT 映射续住，又不像 15s 那样频繁唤醒射频。
const TCP_KEEPALIVE_SECS: u64 = 60;
/// smoltcp 连接超时。keep-alive 探测或在途数据连续 180s 没有任何回应即判死并发 RST：
/// 切网/上游静默死亡后连接不会无限重传，也不会一直占着 1024 名额。
const TCP_DEAD_TIMEOUT_SECS: u64 = 180;
/// 长时间零业务数据的兜底回收。keepalive 仍在跑，有心跳/推送的长连接（微信等）不受影响；
/// 这里只清「对端已经消失、但恰好被中间盒吞掉 RST/FIN」的僵尸连接。
const TCP_IDLE_REAP_SECS: u64 = 2 * 60 * 60;
/// 并发连接硬上限。满了先淘汰最久没有业务数据的连接，绝不直接拒绝新连接——
/// 旧逻辑「达到上限就拒绝」会让所有 APP 一起断网，只能重启内核。
const MAX_TCP_CONNS: usize = 1024;
/// accept 之后等待 SNI/首包/探测判定的连接上限。每个连接带 256K 收发缓冲，
/// 不封顶的话半开连接就能把内存吃光。
const MAX_PENDING_ACCEPT: usize = 512;
/// 单连接下行 pending 字节上限。客户端收不动（零窗口/进程冻结/暂停下载）时，
/// smoltcp 发送缓冲塞满后若继续无脑从 relay 通道搬运，pending 会无界增长，
/// 一条卡住的大下载就能吃几百 MB，最终 LMK 杀进程表现为「随机全断」。
/// 达到上限即停止搬运 → 通道填满 → relay 暂停读上游 → 真实 TCP 窗口自然收紧。
/// 取 2MB（4 倍 recv 缓冲 / 8 倍 tx 缓冲）：512K 旧档恰等于一个 smoltcp 缓冲，
/// 高 BDP 单流一次 RTT 抖动就填满 pending→停搬→上游暂停→吞吐反复触顶；
/// 2MB 给出足够的突发吸收。停搬带滞回（≥2MB 暂停、≤1MB 恢复，见 TCP_PENDING_RESUME），
/// 单阈值会在门槛处开/关振荡（2.3.12 滞回修复的同款教训）。
/// 内存守卫：pending 是真实字节（非惰性零页），但每流封顶 2MB × 活跃流数，
/// 另有 1024 连接上限与空闲回收兜底，风险可控。
const TCP_PENDING_CAP: usize = 2 * 1024 * 1024;
/// 滞回恢复水位：暂停后必须排空到 ≤1MB 才恢复搬运，避免阈值处振荡。
const TCP_PENDING_RESUME: usize = 1024 * 1024;

struct TunRxToken {
    data: Option<Vec<u8>>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
}
struct TunTxToken {
    tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
    cap: usize,
    stats: Arc<Stats>,
}

/// 池未命中（不得不新分配）的次数：判断池是否还偏小。
static POOL_MISS: AtomicUsize = AtomicUsize::new(0);
/// 供诊断输出读取池未命中次数。
pub fn pool_misses() -> usize {
    POOL_MISS.load(Ordering::Relaxed)
}

fn pool_take(pool: &Mutex<Vec<Vec<u8>>>, capacity: usize) -> Vec<u8> {
    let mut g = match pool.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    match g.pop() {
        Some(b) => b,
        None => {
            POOL_MISS.fetch_add(1, Ordering::Relaxed);
            Vec::with_capacity(capacity)
        }
    }
}

fn pool_put(pool: &Mutex<Vec<Vec<u8>>>, buf: Vec<u8>) {
    if buf.capacity() > MAX_TUN_PACKET {
        return;
    }
    let mut g = match pool.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if g.len() < MAX_POOL {
        g.push(buf);
    }
}

impl TunDevice {
    fn new(mtu: usize, stats: Arc<Stats>) -> Self {
        let (queue_cap, pending_cap, write_burst) = queue_caps(mtu);
        Self {
            rx: VecDeque::with_capacity(MAX_RX_BURST),
            tx: Arc::new(Mutex::new(VecDeque::with_capacity(queue_cap))),
            rx_pool: Arc::new(Mutex::new(Vec::with_capacity(MAX_POOL))),
            tx_pool: Arc::new(Mutex::new(Vec::with_capacity(MAX_POOL))),
            mtu,
            queue_cap,
            pending_cap,
            write_burst,
            stats,
        }
    }

    /// 从池里取一个缓冲直接读 TUN；读满后 set_len，避免每包分配和清零。
    fn read_rx(&mut self, fd: RawFd) -> io::Result<Option<Vec<u8>>> {
        let mut buf = pool_take(&self.rx_pool, MAX_TUN_PACKET);
        buf.clear();
        if buf.capacity() < MAX_TUN_PACKET {
            buf.reserve(MAX_TUN_PACKET - buf.capacity());
        }
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                MAX_TUN_PACKET,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            pool_put(&self.rx_pool, buf);
            return Err(err);
        }
        if n == 0 {
            pool_put(&self.rx_pool, buf);
            return Ok(None);
        }
        // 内核刚刚写满了 n 字节，set_len 后这段内存已初始化。
        unsafe { buf.set_len(n as usize) };
        Ok(Some(buf))
    }

    fn drain_tx_into(&self, pending: &mut VecDeque<Vec<u8>>, limit: usize) {
        if limit == 0 {
            return;
        }
        let mut g = match self.tx.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut taken = 0;
        while taken < limit {
            match g.pop_front() {
                Some(pkt) => {
                    pending.push_back(pkt);
                    taken += 1;
                }
                None => break,
            }
        }
    }

    fn recycle_tx(&self, buf: Vec<u8>) {
        pool_put(&self.tx_pool, buf);
    }
}

impl Device for TunDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((
            TunRxToken {
                data: Some(pkt),
                pool: self.rx_pool.clone(),
            },
            TunTxToken {
                tx: self.tx.clone(),
                pool: self.tx_pool.clone(),
                cap: self.queue_cap,
                stats: self.stats.clone(),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        {
            let g = match self.tx.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if g.len() >= self.queue_cap {
                // 高水位返回 None，smoltcp 会把报文保留在 socket 发送缓冲，
                // 下一次 poll 再试；这是背压，不是丢包。
                self.stats.tun_tx_backpressure.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        Some(TunTxToken {
            tx: self.tx.clone(),
            pool: self.tx_pool.clone(),
            cap: self.queue_cap,
            stats: self.stats.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

impl RxToken for TunRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let data = self.data.take().expect("TunRxToken consumed twice");
        let r = f(&data);
        pool_put(&self.pool, data);
        r
    }
}

impl Drop for TunRxToken {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            pool_put(&self.pool, data);
        }
    }
}

impl TxToken for TunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = pool_take(&self.pool, len.max(MAX_TUN_PACKET));
        buf.clear();
        buf.resize(len, 0);
        let r = f(&mut buf);
        let mut g = match self.tx.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if g.len() < self.cap {
            g.push_back(buf);
        } else {
            // transmit() 已做高水位检查；这里只是最后一道保护，正常不应命中。
            drop(g);
            pool_put(&self.pool, buf);
            self.stats.tun_tx_drop.fetch_add(1, Ordering::Relaxed);
        }
        r
    }
}

/// 记录 pending_out 峰值；高水位只做背压，不再截断。
fn note_pending_out(pending: &VecDeque<Vec<u8>>, stats: &Stats) {
    stats
        .tun_pending_peak
        .fetch_max(pending.len() as u64, Ordering::Relaxed);
}

/// 连通性探测（captive portal / 网络验证）域名清单。
/// Android NetworkMonitor、GMS 与各家 ROM 用这些域名判断网络「能不能上网」。
/// 探测走 VPN 全部超时（海外直连不可达）时，系统会把 VPN 一直标成「未验证」
/// 并每 3s 重探一轮；很多 App（含测速）要等网络「已验证」回调才开始干活，
/// 这正是测速迟迟不出数的系统级原因之一。Surge/Loon 对这类探测都做本地处理。
const PROBE_HOSTS: &[&str] = &[
    "www.google.com",
    "www.google.cn",
    "connectivitycheck.gstatic.com",
    "www.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "clients4.google.com",
    "connect.rom.miui.com",
    "connectivitycheck.platform.hicloud.com",
    "connectivitycheck.platform.hihonorcloud.com",
    "conn1.oppomobile.com",
    "conn2.oppomobile.com",
    "wifi.vivo.com.cn",
    "captive.apple.com",
    "www.msftconnecttest.com",
    "www.msftncsi.com",
    // GMS 后台域名：直连必不通，不快速 RST 的话 GMS 每 2s 一轮无限重试，
    // 白占连接名额和主循环时间片。RST 后 GMS 进入自己的指数退避。
    // 与上面一样只拦直连：配了节点走代理时不受影响。
    "firebaseinstallations.googleapis.com",
    "checkin.gstatic.com",
    "android.clients.google.com",
    "mtalk.google.com",
    "alt1-mtalk.google.com",
    "alt2-mtalk.google.com",
    "alt3-mtalk.google.com",
    "alt4-mtalk.google.com",
    "alt5-mtalk.google.com",
    "alt6-mtalk.google.com",
    "alt7-mtalk.google.com",
    "alt8-mtalk.google.com",
];

fn is_probe_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    PROBE_HOSTS.iter().any(|p| h == *p)
}

/// HTTP 连通性探测本地代答：只应答「探测域名 + 探测路径」的组合，
/// 正常网页流量（其他路径/域名）原样放行，不影响真实业务。
/// 头部不完整或非明文 HTTP 返回 None，由调用方决定等待或放行。
fn probe_http_response(req: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(req).ok()?;
    let end = text.find("\r\n\r\n")?;
    let head = &text[..end];
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next()?;
    if method != "GET" && method != "HEAD" {
        return None;
    }
    let path = parts.next()?;
    let host = lines.find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.eq_ignore_ascii_case("host") {
            Some(v.trim())
        } else {
            None
        }
    })?;
    if !is_probe_host(host) {
        return None;
    }
    let path = path.split('?').next().unwrap_or(path);
    let body: &[u8] = match path {
        "/generate_204" | "/gen_204" | "/generate204" => {
            return Some(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-cache\r\n\r\n".to_vec(),
            );
        }
        "/hotspot-detect.html" | "/library/test/success.html" => {
            b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
        }
        "/connecttest.txt" => b"Microsoft Connect Test",
        "/ncsi.txt" => b"Microsoft NCSI",
        "/success.txt" => b"success\n",
        _ => return None,
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-cache\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    Some(out)
}

struct TcpConn {
    handle: SocketHandle,
    /// 连接快照 id；本地代答/熔断抑制/DNS over TCP 等没有真实出站的连接为 None。
    snap: Option<u64>, 
    to_relay: Option<mpsc::Sender<Vec<u8>>>,
    from_relay: mpsc::Receiver<Vec<u8>>,
    pending: VecDeque<Vec<u8>>,
    /// pending 中的总字节数，与 TCP_PENDING_CAP 配对形成下行背压。
    pending_bytes: usize,
    /// 下行背压滞回标志：pending ≥2MB 置位停搬，≤1MB 清零恢复。
    /// 没有它，单阈值会在门槛处每轮开/关振荡，relay 读上游跟着抖。
    relay_paused: bool,
    /// 主循环搬走 pending/通道数据后通知 relay 恢复读上游。
    /// 没有它，relay 在通道满时会永久停读（mpsc 不会因容量释放唤醒发送方）。
    read_wake: Arc<Notify>,
    relay_closed: bool,
    client_closed: bool,
    closing: bool,
    /// 最后一次有业务数据流动的时刻（任一方向）。keepalive ACK 不算业务数据：
    /// 上限淘汰和空闲回收只按真实流量排序，避免把「心跳很密但没数据」的连接误判成活跃。
    last_active: Instant,
    /// 每连接流量计（上行/下行累计字节），壳层据此算速率。
    meter: Option<Arc<crate::conns::ConnMeter>>,
    /// 接收缓冲是否已进入「满」状态：只在进入时计数一次，避免每轮重复 +1。
    recv_full: bool,
    /// 发送被对端零窗口卡住的起始时刻；用于停滞告警与判别计数。
    send_stall_since: Option<Instant>,
    /// 停滞告警是否已经打过（>3s 只打一条，不刷屏）。
    send_stall_logged: bool,
    /// 上次速率采样时的累计字节（10s 差分用）。
    rate_prev_up: u64,
    rate_prev_down: u64,
}

/// 是否还有出站数据躺在 relay 通道里没搬进 smoltcp。
/// 用于把兜底轮询收紧到 1ms：Notify 只保证「有新数据」时唤醒，
/// 但被背压打断的一轮可能只搬了一部分，这里保证剩余部分不等到兜底间隔。
fn has_relay_backlog(conns: &[TcpConn]) -> bool {
    // 滞回暂停中的连接不算 backlog：它是故意停搬，1ms 兜底轮询围着它空转是纯耗电；
    // 恢复由主循环每轮的 drain_relay_to_pending 按低水位判定，不依赖兜底间隔。
    conns.iter().any(|c| !c.relay_paused && !c.from_relay.is_empty())
}

/// 把下行数据从 relay 通道搬入 pending，受 TCP_PENDING_CAP 字节上限约束。
/// 返回是否搬到了数据（调用方据此更新活跃时间）。搬到数据即唤醒 relay：
/// 通道腾出了容量，它可以恢复读上游了。
fn drain_relay_to_pending(conn: &mut TcpConn) -> bool {
    // 滞回：≥2MB 暂停、≤1MB 恢复。暂停期间不搬也不唤醒 relay，
    // 让通道保持满、上游窗口保持收紧，直到 pending 真正排空到低水位。
    if !conn.relay_paused && conn.pending_bytes >= TCP_PENDING_CAP {
        conn.relay_paused = true;
    }
    if conn.relay_paused && conn.pending_bytes <= TCP_PENDING_RESUME {
        conn.relay_paused = false;
    }
    if conn.relay_paused {
        return false;
    }
    let mut drained = false;
    while conn.pending_bytes < TCP_PENDING_CAP {
        match conn.from_relay.try_recv() {
            Ok(data) => {
                drained = true;
                conn.pending_bytes += data.len();
                conn.pending.push_back(data);
                if conn.pending.len() >= RELAY_DRAIN_BURST {
                    break;
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                conn.relay_closed = true;
                break;
            }
        }
    }
    if drained {
        conn.read_wake.notify_one();
    }
    drained
}

/// 熔断键：优先按「域名+端口」计，纯 IP 连接（测速服务器等）才按「IP+端口」。
/// 只按 IP 计会让 CDN 下同 IP:443 的不同域名互相连坐——一个域名失败，
/// 同 IP 的另一个域名也被冷却，而它们的真实可达性未必相同。
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum DialKey {
    Name(String, u16),
    Addr(IpAddr, u16),
}

fn dial_key(domain: Option<&str>, ip: IpAddr, port: u16) -> DialKey {
    match domain {
        Some(d) if !d.is_empty() => DialKey::Name(d.to_ascii_lowercase(), port),
        _ => DialKey::Addr(ip, port),
    }
}

/// 直连拨号失败冷却表。只记 DIRECT：代理节点已有健康登记 + top3 回落，不重复管。
#[derive(Default)]
struct DialFails {
    /// 值=(连续失败次数, 冷却截止)。
    fails: HashMap<DialKey, (u32, Instant)>,
    /// 近期失败（键+时刻），用于区分「目标全死了」和「本机链路出问题了」。
    recent: VecDeque<(DialKey, Instant)>,
    /// 链路自愈：多目标同时失败时暂停熔断，期间一律真实拨号。
    suspend_until: Option<Instant>,
}

/// 链路自愈判据：10s 内 ≥8 个不同目标失败，基本只能是本机链路问题
/// （信号差/切网瞬间/上游断），此时熔断纯属误伤，清空并暂停。
const LINK_FAIL_WINDOW_SECS: u64 = 10;
const LINK_FAIL_DISTINCT_TARGETS: usize = 8;
/// 自愈后暂停熔断的时长：给链路恢复留时间，暂停期也不累计失败。
const LINK_SELF_HEAL_SUSPEND_SECS: u64 = 30;
/// 熔断命中后的失败时序：必须与真实拨号超时（outbound 2s）一致。
const SUPPRESSED_DIAL_FAIL_SECS: u64 = 2;

/// 按连续失败次数算冷却时长：1 次不冷却，2 次 10s，翻倍封顶 60s。
fn dial_cooldown(fails: u32) -> Option<Duration> {
    if fails < 2 {
        return None;
    }
    let exp = (fails - 2).min(6);
    Some(Duration::from_secs(
        (DIAL_BREAKER_BASE_SECS << exp).min(DIAL_BREAKER_CAP_SECS),
    ))
}

fn dial_breaker_active(fails: &DialFails, key: &DialKey, now: Instant) -> bool {
    // 链路自愈暂停期一律不熔断：这时候失败多半不是目标的错。
    if fails.suspend_until.map(|u| now < u).unwrap_or(false) {
        return false;
    }
    fails.fails.get(key).map(|(_, until)| now < *until).unwrap_or(false)
}

/// 记录一次直连失败；返回 true 表示触发了链路自愈（调用方负责打日志）。
fn dial_breaker_record(fails: &mut DialFails, key: DialKey, now: Instant) -> bool {
    if fails.suspend_until.map(|u| now < u).unwrap_or(false) {
        // 暂停期不累计：链路恢复过程中的失败不该被记成目标的连续失败。
        return false;
    }
    fails.suspend_until = None;
    let e = fails.fails.entry(key.clone()).or_insert((0, now));
    e.0 = e.0.saturating_add(1);
    if let Some(cd) = dial_cooldown(e.0) {
        e.1 = now + cd;
    }
    let window = Duration::from_secs(LINK_FAIL_WINDOW_SECS);
    fails.recent.push_back((key, now));
    while fails
        .recent
        .front()
        .map(|(_, t)| now.saturating_duration_since(*t) > window)
        .unwrap_or(false)
    {
        fails.recent.pop_front();
    }
    let distinct: std::collections::HashSet<&DialKey> =
        fails.recent.iter().map(|(k, _)| k).collect();
    if distinct.len() >= LINK_FAIL_DISTINCT_TARGETS {
        fails.fails.clear();
        fails.recent.clear();
        fails.suspend_until = Some(now + Duration::from_secs(LINK_SELF_HEAL_SUSPEND_SECS));
        return true;
    }
    false
}

fn dial_breaker_clear(fails: &mut DialFails, key: &DialKey) {
    fails.fails.remove(key);
}

/// 熔断表清陈旧：冷却结束超过 5 分钟且无新失败的条目丢弃，
/// 保留近期条目以便再次失败时继续升级冷却。
fn dial_breaker_sweep(fails: &mut DialFails) {
    fails
        .fails
        .retain(|_, (_, until)| until.elapsed() < Duration::from_secs(300));
}

/// 上限淘汰的排序键：先按「有没有堆积」分组（有堆积的排在后面，别踢正在传输的连接），
/// 同组内越久没有业务数据越先淘汰。
fn victim_rank(idle: Duration, busy: bool) -> (u8, std::cmp::Reverse<u128>) {
    (busy as u8, std::cmp::Reverse(idle.as_millis()))
}

/// 选择上限压力下要被淘汰的连接。closing 的不选（已经在四次挥手，马上自己释放）。
fn pick_victim(conns: &[TcpConn], now: Instant) -> Option<usize> {
    conns
        .iter()
        .enumerate()
        .filter(|(_, c)| !c.closing)
        .min_by_key(|(_, c)| {
            victim_rank(
                now.saturating_duration_since(c.last_active),
                !c.pending.is_empty() || !c.from_relay.is_empty(),
            )
        })
        .map(|(idx, _)| idx)
}

/// 空闲回收判据：既没堆积、也没有半关闭流程，且超过兜底阈值才回收。
/// 正在慢速传输（有 pending/from_relay 数据）的连接绝不按时间踢掉。
fn should_reap_idle(idle: Duration, busy: bool, closing: bool) -> bool {
    !closing && !busy && idle >= Duration::from_secs(TCP_IDLE_REAP_SECS)
}


struct UdpClient {
    tx: mpsc::Sender<(Target, Vec<u8>)>,
    last: Instant,
}

fn smol_now(start: Instant) -> SmolInstant {
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

fn dns_v6_addr() -> Ipv6Address {
    Ipv6Address::new(0xfd00, 0x0001, 0, 0, 0, 0, 0, 53)
}

fn dns_v4_addr() -> Ipv4Address {
    Ipv4Address::new(10, 10, 10, 53)
}

fn is_local_dns_endpoint(ep: IpEndpoint) -> bool {
    if ep.port != 53 {
        return false;
    }
    match ep.addr {
        IpAddress::Ipv4(a) => a == dns_v4_addr(),
        IpAddress::Ipv6(a) => a == dns_v6_addr(),
    }
}

fn write_tun(fd: RawFd, data: &[u8]) -> io::Result<()> {
    let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // TUN 正常按整包写入；部分写意味着包会被截断，必须显式报错而不是静默丢弃。
    if (n as usize) != data.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "TUN 部分写入"));
    }
    Ok(())
}

/// RFC 1071 因特网校验和（16 位反码求和）。
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let w = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            (chunk[0] as u16) << 8
        };
        sum += w as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 合成 ICMP echo reply（v4 type 8→0 / v6 type 128→129），本地代答。
/// 用户态栈不转发 ICMP：测速/探活类 App 用 ping 给服务器排序选路，
/// 全部超时会让它不停重选服务器、测速迟迟不出数（Clash/sing-box TUN 同样本地代答）。
/// 非 echo request、截断或校验和错误的报文返回 None。
fn icmp_echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    let version = *pkt.first()? >> 4;
    match version {
        4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Icmp {
                return None;
            }
            let ihl = ip.header_len() as usize;
            let total = ip.total_len() as usize;
            if total > pkt.len() || ihl >= total {
                return None;
            }
            let icmp = &pkt[ihl..total];
            if icmp.len() < 8 || icmp[0] != 8 || icmp[1] != 0 {
                return None;
            }
            if inet_checksum(icmp) != 0 {
                return None;
            }
            let mut out = pkt[..total].to_vec();
            // 交换 src/dst：16 位求和可交换，IPv4 头校验和不变，TTL 不动。
            out[12..16].copy_from_slice(&pkt[16..20]);
            out[16..20].copy_from_slice(&pkt[12..16]);
            out[ihl] = 0;
            out[ihl + 2] = 0;
            out[ihl + 3] = 0;
            let c = inet_checksum(&out[ihl..]);
            out[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
            Some(out)
        }
        6 => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Icmpv6 {
                return None;
            }
            let start = 40;
            let end = start + ip.payload_len() as usize;
            if end > pkt.len() {
                return None;
            }
            let icmp = &pkt[start..end];
            if icmp.len() < 8 || icmp[0] != 128 || icmp[1] != 0 {
                return None;
            }
            let mut out = pkt[..end].to_vec();
            out[8..24].copy_from_slice(&pkt[24..40]);
            out[24..40].copy_from_slice(&pkt[8..24]);
            out[start] = 129;
            out[start + 2] = 0;
            out[start + 3] = 0;
            // ICMPv6 校验和含伪头：src + dst + 上层长度 + next_header(58)。
            let mut sum = 0u32;
            for chunk in out[8..40].chunks(2) {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            }
            let len = out.len() - start;
            sum += (len as u32) >> 16;
            sum += (len as u32) & 0xFFFF;
            sum += 58;
            for chunk in out[start..].chunks(2) {
                let w = if chunk.len() == 2 {
                    u16::from_be_bytes([chunk[0], chunk[1]])
                } else {
                    (chunk[0] as u16) << 8
                };
                sum += w as u32;
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let c = !(sum as u16);
            // RFC 4443：ICMPv6 校验和不允许为 0（0 表示未计算）。
            let c = if c == 0 { 0xFFFF } else { c };
            out[start + 2..start + 4].copy_from_slice(&c.to_be_bytes());
            Some(out)
        }
        _ => None,
    }
}

fn lookup_tcp_dst(pkt: &[u8]) -> Option<(u16, IpAddress)> {
    let version = *pkt.first()? >> 4;
    match version {
        4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            if tcp.syn() && !tcp.ack() {
                Some((tcp.dst_port(), IpAddress::Ipv4(ip.dst_addr())))
            } else {
                None
            }
        }
        6 => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            if tcp.syn() && !tcp.ack() {
                Some((tcp.dst_port(), IpAddress::Ipv6(ip.dst_addr())))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn lookup_udp_flow(pkt: &[u8]) -> Option<(IpEndpoint, IpEndpoint)> {
    let version = *pkt.first()? >> 4;
    match version {
        4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some((
                IpEndpoint::new(IpAddress::Ipv4(ip.src_addr()), udp.src_port()),
                IpEndpoint::new(IpAddress::Ipv4(ip.dst_addr()), udp.dst_port()),
            ))
        }
        6 => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some((
                IpEndpoint::new(IpAddress::Ipv6(ip.src_addr()), udp.src_port()),
                IpEndpoint::new(IpAddress::Ipv6(ip.dst_addr()), udp.dst_port()),
            ))
        }
        _ => None,
    }
}

/// 取 UDP 载荷（QUIC Initial 嗅探用）。解析失败一律 None，不影响转发路径。
fn udp_payload(pkt: &[u8]) -> Option<&[u8]> {
    match *pkt.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            Some(UdpPacket::new_checked(ip.payload()).ok()?.payload())
        }
        6 => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            Some(UdpPacket::new_checked(ip.payload()).ok()?.payload())
        }
        _ => None,
    }
}

fn add_listener(
    sockets: &mut SocketSet<'_>,
    addr: IpAddress,
    port: u16,
    stats: &crate::stats::Stats,
) -> Option<SocketHandle> {
    let (buf_bytes, downgraded) = next_tcp_buffer_bytes();
    if downgraded {
        stats.tcp_buffer_denied.fetch_add(1, Ordering::Relaxed);
    }
    // 非对称缓冲：recv 512K 保住上行突发闸门；tx 大档 256K（本机腿足够），
    // 降级档双向同 128K。
    let tx_bytes = if downgraded { buf_bytes } else { TCP_SOCKET_BUFFER_TX };
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; buf_bytes]),
        tcp::SocketBuffer::new(vec![0u8; tx_bytes]),
    );
    // 这个 TUN 数据面是「一条 TCP 连接就是一条本地 smoltcp 连接」，监听 socket 直接
    // 转成已建立连接（state != Listen 后原地复用），所以在这里设一次即全程生效。
    // 关 Nagle：小包（TLS 握手、请求头、交互式请求）被合并就是固定的 RTT 级等待，
    // 这里换不到「少发几个包」的收益，只剩延迟成本。
    socket.set_nagle_enabled(false);
    // 延迟 ACK：smoltcp 默认 10ms，压到 5ms。ACK 回填更快，下行窗口不会因为
    // 等 ACK 而断流；多出来的纯 ACK 包走本机 TUN 上行，几乎没有成本。
    socket.set_ack_delay(Some(Duration::from_millis(ACK_DELAY_MS).into()));
    // 监听 socket 上设一次，accept 出来的连接自动继承：
    // keepalive 负责续住空闲长连接并配合 timeout 识别静默死亡的对端；
    // timeout 同时兜住「SYN 之后客户端消失」的半开连接，避免永久占用缓冲。
    socket.set_keep_alive(Some(Duration::from_secs(TCP_KEEPALIVE_SECS).into()));
    socket.set_timeout(Some(Duration::from_secs(TCP_DEAD_TIMEOUT_SECS).into()));
    if socket
        .listen(IpListenEndpoint {
            addr: Some(addr),
            port,
        })
        .is_err()
    {
        return None;
    }
    TCP_SOCKETS.fetch_add(1, Ordering::Relaxed);
    if !downgraded {
        BIG_TIER_IN_USE.fetch_add(1, Ordering::Relaxed);
    }
    Some(sockets.add(socket))
}

fn add_udp_dst_socket(
    sockets: &mut SocketSet<'_>,
    addr: IpAddress,
    port: u16,
) -> Option<SocketHandle> {
    let mut socket = udp::Socket::new(
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0u8; UDP_DST_BUF],
        ),
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0u8; UDP_DST_BUF],
        ),
    );
    if socket
        .bind(IpListenEndpoint {
            addr: Some(addr),
            port,
        })
        .is_err()
    {
        return None;
    }
    Some(sockets.add(socket))
}

/// 全锥型 UDP 会话：一个客户端源端口对应一个真实/代理 UDP 通道。
fn spawn_udp_client(
    client: IpEndpoint,
    mode: UdpMode,
    resp_tx: mpsc::Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
    dns: Arc<DnsEngine>,
) -> Option<mpsc::Sender<(Target, Vec<u8>)>> {
    let (tx, rx) = mpsc::channel::<(Target, Vec<u8>)>(64);
    tokio::spawn(crate::udp::run(client, mode, rx, resp_tx, dns));
    Some(tx)
}

fn selected_node(ctx: &Ctx) -> Option<Node> {
    let nodes = ctx.nodes_snapshot();
    if let Some(name) = ctx.selected_snapshot() {
        if let Some(n) = nodes.iter().find(|n| n.name == name) {
            return Some(n.clone());
        }
    }
    nodes.first().cloned()
}

fn udp_mode(ctx: &Ctx, action: &Action) -> UdpMode {
    let node = match action {
        Action::Direct => return UdpMode::Direct,
        Action::Block => return UdpMode::Unsupported("规则拦截".into()),
        Action::Proxy => match selected_node(ctx) {
            Some(n) => n,
            None => return UdpMode::Unsupported("没有可用节点".into()),
        },
        Action::Node(name) => {
            // 策略组已在 decide_action 中解析为具体节点；这里不再回落到当前选中节点。
            let nodes = ctx.nodes_snapshot();
            match nodes.iter().find(|n| &n.name == name).cloned() {
                Some(n) => n,
                None => return UdpMode::Unsupported(format!("节点不存在: {}（引用已失效）", name)),
            }
        }
        Action::Group(name) => {
            return UdpMode::Unsupported(format!("策略组未解析: {}", name));
        }
        Action::Missing(name) => {
            return UdpMode::Unsupported(format!("策略引用不存在: {}", name));
        }
    };
    // 节点级 udp:false 优先：即使协议本身支持 UDP，也按用户配置拒绝转发。
    if !node.udp_supported() {
        return if node.udp == Some(false) {
            UdpMode::Unsupported(format!("{} 节点已关闭 UDP（udp: false）", node.label()))
        } else {
            UdpMode::Unsupported(format!("{} 节点不支持 UDP", node.kind))
        };
    }
    match node.kind.as_str() {
        "ss" => UdpMode::Ss(node),
        "socks5" => UdpMode::Socks5(node),
        "trojan" => UdpMode::Trojan(node),
        "vless" => UdpMode::Vless(node),
        other => UdpMode::Unsupported(format!("{} 节点暂不支持 UDP", other)),
    }
}

/// 带 App 归属的判定：`uid` 为 None 表示归属未知，UID 规则不参与匹配。
fn decide_action_uid(
    ctx: &Ctx,
    domain: Option<&str>,
    ip: IpAddr,
    port: u16,
    kind: ConnKind,
    uid: Option<u32>,
) -> Action {
    decide_detail_for(ctx, domain, ip, port, kind, uid).0
}

/// 同 decide_action_uid，额外返回「为什么这么判」的可读说明，供连接列表展示。
/// 说明是多行文案，调用方展示时取第一行即可。
fn decide_detail_for(
    ctx: &Ctx,
    domain: Option<&str>,
    ip: IpAddr,
    port: u16,
    kind: ConnKind,
    uid: Option<u32>,
) -> (Action, String) {
    // mihomo/sing-box 同款：853 是 DoT/DoQ，私人 DNS 开着时会绕过 53 劫持。
    // 直接拒绝，让 Android 的 opportunistic 模式回落到 VPN DNS。
    if port == 853 && ctx.block_dot() {
        ctx.stats.dot_blocked.fetch_add(1, Ordering::Relaxed);
        return (Action::Block, "DoT(853) 已阻断".to_string());
    }
    let mut detail: String;
    let mut action = match ctx.mode().as_str() {
        "global" => {
            detail = "全局模式：全部流量走节点".to_string();
            Action::Proxy
        }
        "dns_only" => {
            detail = "仅 DNS 接管：流量直连".to_string();
            Action::Direct
        }
        _ => {
            let (a, d) = ctx
                .rules
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .decide_input(&crate::engine::MatchInput {
                    domain,
                    ip,
                    port,
                    kind,
                    uid,
                });
            detail = d;
            a
        }
    };
    // 策略组只在规则/最终策略真正引用它时展开；global 模式仍走当前选中节点。
    if let Action::Group(name) = action.clone() {
        action = resolve_group_action(ctx, &name, kind, domain);
        detail = format!(
            "策略组 {} → {}",
            name,
            ctx.rules.read().unwrap_or_else(|p| p.into_inner()).decision_label(&action)
        );
    }
    if let Action::Missing(name) = &action {
        logging::warn(
            "strategy",
            format!("规则引用的目标已失效：{}；按拦截处理，不回落到当前选中节点", name),
        );
        return (Action::Block, format!("{}；目标 {} 已失效，按拦截处理", detail, name));
    }
    if let Action::Node(name) = &action {
        if !ctx.nodes_snapshot().iter().any(|n| &n.name == name) {
            logging::warn(
                "strategy",
                format!("节点已不存在：{}；按拦截处理，不回落到当前选中节点", name),
            );
            return (Action::Block, format!("{}；节点 {} 已不存在，按拦截处理", detail, name));
        }
    }
    if matches!(action, Action::Proxy) && ctx.nodes_snapshot().is_empty() {
        action = if ctx.block_when_no_node() {
            Action::Block
        } else {
            Action::Direct
        };
        detail = format!(
            "{}；无可用节点，已降级为{}",
            detail,
            if action == Action::Block { "拦截" } else { "直连" }
        );
    }
    // HTTPS 连通性探测：直连时这些海外域名根本不可达，挂 4~7s 等超时只会让
    // 系统验证反复失败、每 3s 重探一轮。立即 RST 让 NetworkMonitor 快速回落
    // 到 HTTP 探测（由 probe_http_response 本地代答），VPN 网络秒级变「已验证」。
    // 只拦直连：配置了代理节点时探测走节点，不受影响。
    if port == 443 && matches!(action, Action::Direct) {
        if let Some(d) = domain {
            if is_probe_host(d) {
                logging::info("probe", format!("连通性探测快速拒绝 {}:{}（直连不可达）", d, port));
                return (Action::Block, "连通性探测：直连不可达，快速拒绝".to_string());
            }
        }
    }
    (action, detail)
}

fn resolve_group_action(ctx: &Ctx, name: &str, kind: ConnKind, domain: Option<&str>) -> Action {
    let strategy = ctx.strategy_snapshot();
    let transport = match kind {
        ConnKind::Tcp => Transport::Tcp,
        ConnKind::Udp => Transport::Udp,
    };
    match strategy.resolve_group(name, transport, &ctx.health) {
        Ok(r) => {
            logging::info(
                "strategy",
                format!(
                    "{} [{}] 策略组解析：{}",
                    domain.unwrap_or("-"),
                    if kind == ConnKind::Tcp { "TCP" } else { "UDP" },
                    r.chain.join(" -> ")
                ),
            );
            Action::Node(r.node)
        }
        Err(e) => {
            let policy = e.policy.chosen(ctx.block_when_no_node());
            logging::warn(
                "strategy",
                format!(
                    "{} [{}] 策略组解析失败：{}（链：{}）；无可用节点策略={:?}",
                    domain.unwrap_or("-"),
                    if kind == ConnKind::Tcp { "TCP" } else { "UDP" },
                    e.message,
                    e.chain.join(" -> "),
                    match policy {
                        NoNodePolicy::Block => "BLOCK",
                        NoNodePolicy::Direct => "DIRECT",
                        NoNodePolicy::Global => "GLOBAL",
                    }
                ),
            );
            match policy {
                NoNodePolicy::Direct => Action::Direct,
                _ => Action::Block,
            }
        }
    }
}

async fn relay_stream(
    stream: BoxStream,
    mut client_rx: mpsc::Receiver<Vec<u8>>,
    server_tx: mpsc::Sender<Vec<u8>>,
    relay_wake: Arc<Notify>,
    read_wake: Arc<Notify>,
) {
    let (mut r, mut w) = tokio::io::split(stream);
    let mut buf = vec![0u8; 16384];
    // 半关闭语义：客户端停止发送（channel 关闭）只关出站写侧，
    // 服务端方向的响应必须继续读完，否则半关闭客户端会丢响应。
    let mut client_done = false;
    // 下行背压：通道满时绝不能阻塞在 send().await——select 会卡在发送分支，
    // 上传方向跟着一起停摆（双向流互卡）。改为把读到的块暂存 staged、
    // 禁用读分支，等主循环搬走数据后 read_wake 唤醒；上传分支全程可服务。
    let mut staged: Option<Vec<u8>> = None;
    loop {
        if let Some(data) = staged.take() {
            match server_tx.try_send(data) {
                Ok(_) => {
                    // 出站数据已入 channel：必须显式唤醒主循环，
                    // 否则它只能靠兜底定时器醒来，稳态下载被判死在上限里。
                    relay_wake.notify_one();
                }
                Err(mpsc::error::TrySendError::Full(data)) => staged = Some(data),
                Err(mpsc::error::TrySendError::Closed(_)) => break,
            }
        }
        tokio::select! {
            msg = client_rx.recv(), if !client_done => {
                match msg {
                    Some(data) => {
                        if w.write_all(&data).await.is_err() { break; }
                    }
                    None => {
                        client_done = true;
                        let _ = w.shutdown().await;
                    }
                }
            }
            res = r.read(&mut buf), if staged.is_none() && server_tx.capacity() > 0 => {
                match res {
                    Ok(0) => break,
                    Ok(n) => staged = Some(buf[..n].to_vec()),
                    Err(_) => break,
                }
            }
            _ = read_wake.notified(), if staged.is_some() || server_tx.capacity() == 0 => {}
        }
    }
    let _ = w.shutdown().await;
}

async fn dns_tcp_server(dns: Arc<DnsEngine>, pipe: DuplexStream) {
    let (mut pr, pw) = tokio::io::split(pipe);
    // RFC 7766 允许乱序应答（客户端按 ID 匹配）：每条查询独立 spawn，
    // 慢查询不再阻塞同一连接上的后续 pipelined 查询。
    let pw = Arc::new(tokio::sync::Mutex::new(pw));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 8192];
    loop {
        let n = match pr.read(&mut chunk).await {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        loop {
            if buf.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() < 2 + len {
                break;
            }
            let query = buf[2..2 + len].to_vec();
            buf.drain(..2 + len);
            let dns = dns.clone();
            let pw = pw.clone();
            tokio::spawn(async move {
                if let Some(resp) = dns.resolve(&query).await {
                    if resp.len() > 0xFFFF {
                        // DNS over TCP 的长度前缀只有 16 位，超长应答只能丢弃
                        return;
                    }
                    let mut out = Vec::with_capacity(resp.len() + 2);
                    out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                    out.extend_from_slice(&resp);
                    let _ = pw.lock().await.write_all(&out).await;
                }
            });
        }
    }
}

/// TUN 协议栈是否已进入读循环：nativeStart 用它做「启动成功」确认。
pub static STACK_READY: AtomicBool = AtomicBool::new(false);

pub async fn run(fd: RawFd, ctx: Arc<Ctx>) -> io::Result<()> {
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(dup_fd) };
    let flags = unsafe { libc::fcntl(dup_fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
    let async_fd = unsafe { tokio::io::unix::AsyncFd::register(owned)? };
    STACK_READY.store(true, Ordering::Release);

    let mtu = ctx
        .cfg
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .mtu
        .clamp(1280, 9000);
    ctx.stats.tun_mtu.store(mtu as i64, Ordering::Relaxed);
    let mut device = TunDevice::new(mtu, ctx.stats.clone());
    let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
    iface_cfg.random_seed = rand::random();
    let mut iface = Interface::new(iface_cfg, &mut device, smol_now(Instant::now()));
    iface.update_ip_addrs(|addrs| {
        let mut failed = 0usize;
        for cidr in [
            IpCidr::new(IpAddress::v4(10, 10, 10, 1), 24),
            // DNS 端点必须在 TUN 内但又不是 Android 接口地址：
            // 若和 addAddress 相同，内核会把发往它的报文当本机投递，根本不写进 TUN。
            IpCidr::new(IpAddress::v4(10, 10, 10, 53), 32),
            IpCidr::new(
                IpAddress::Ipv6(Ipv6Address::new(0xfd00, 1, 0, 0, 0, 0, 0, 1)),
                64,
            ),
            IpCidr::new(IpAddress::Ipv6(dns_v6_addr()), 128),
        ] {
            if addrs.push(cidr).is_err() {
                failed += 1;
            }
        }
        if failed > 0 {
            logging::warn(
                "netstack",
                format!("TUN 地址容量不足，{} 个地址未加入（IPv6 可能不可用）", failed),
            );
        }
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 10, 10, 1));
    let _ = iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0xfd00, 1, 0, 0, 0, 0, 0, 1));
    // 关键：允许接管发往任意公网 IP / IPv6 的报文（TUN 模式必需）
    iface.set_any_ip(true);

    let mut sockets = SocketSet::new(vec![]);

    let mut dns4_socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 16384]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 16384]),
    );
    dns4_socket
        .bind(IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(dns_v4_addr())),
            port: 53,
        })
        .map_err(|e| outbound::io_err(format!("绑定 IPv4 DNS 端口失败: {:?}", e)))?;
    let dns4_handle = sockets.add(dns4_socket);

    let mut dns6_socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 16384]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 16384]),
    );
    dns6_socket
        .bind(IpListenEndpoint {
            addr: Some(IpAddress::Ipv6(dns_v6_addr())),
            port: 53,
        })
        .map_err(|e| outbound::io_err(format!("绑定 IPv6 DNS 端口失败: {:?}", e)))?;
    let dns6_handle = sockets.add(dns6_socket);

    let (dns_tx, mut dns_rx) = mpsc::channel::<(SocketHandle, IpEndpoint, Vec<u8>)>(128);
    let mut dns_pending: VecDeque<(SocketHandle, IpEndpoint, Vec<u8>)> = VecDeque::new();
    // 任意目的地址的 53 端口：按目的地址动态建 socket，应答源地址才能保持 8.8.8.8:53 等原值。
    let mut dns_udp_dsts: HashMap<(IpAddress, u16), (SocketHandle, Instant)> = HashMap::new();

    // 同一 endpoint 允许挂多个 listener：smoltcp 的 listen() 不做全局 endpoint 唯一性校验，
    // process_tcp 按插入顺序取第一个 accepts() 的 socket，Listen socket 遇到带 ACK 的包会让位。
    let mut listeners: HashMap<(IpAddress, u16), Vec<(SocketHandle, Instant)>> = HashMap::new();
    // 本轮 RX burst 里已被某个 SYN 认领的 listener。poll 在 burst 之后才跑，
    // 期间所有 listener 都还是 Listen，按状态判据会全部命中同一个 socket，
    // 第二条 SYN 无人认领会被 iface 直接 RST（不是静默等重传）。
    let mut claimed: HashSet<SocketHandle> = HashSet::new();
    // QUIC 假活探测：(目标 IP, 目标端口) → (首次上行时刻, 最近上行时刻)。
    // 只有「持续有上行、却一个回包都没见到」才算假活；纯空闲会话不判死，
    // 否则 keepalive 间隔长的 QUIC 会被误杀。
    let mut quic_probe: HashMap<(IpAddress, u16), (Instant, Instant, bool)> = HashMap::new();
    // 判为 UDP 黑洞的目标 + 判定时刻；冷却按 (IP, port)，有效期 10 分钟。
    let mut quic_blackhole: HashMap<(IpAddress, u16), Instant> = HashMap::new();
    let mut pending_accept: Vec<(IpAddress, u16, SocketHandle, Instant)> = Vec::new();
    let mut conns: Vec<TcpConn> = Vec::new();
    // 判别仪表节拍：每 500ms 扫一次连接队列水位。
    let mut last_meter = Instant::now();
    // 每连接速率采样节拍：10s 一次（太短会被瞬时抖动放大）。
    let mut last_rate_sample = Instant::now();
    // 出站数据唤醒：relay 读到上游数据后 notify，主循环立刻排空，
    // 而不是只能等兜底定时器；否则单连接稳态吞吐被「每轮块数 / 轮询间隔」卡死。
    let relay_wake = Arc::new(Notify::new());

    let mut udp_dsts: HashMap<(IpAddress, u16), (SocketHandle, Instant)> = HashMap::new();
    let mut udp_clients: HashMap<(IpAddress, u16, IpAddress, u16), UdpClient> = HashMap::new();
    let (udp_resp_tx, mut udp_resp_rx) = mpsc::channel::<(IpEndpoint, IpEndpoint, Vec<u8>)>(256);
    let mut udp_replies: VecDeque<(IpEndpoint, IpEndpoint, Vec<u8>)> = VecDeque::new();

    let mut pending_out: VecDeque<Vec<u8>> = VecDeque::new();
    let mut write_blocked = false;
    let mut last_sweep = Instant::now();
    // 直连拨号失败冷却表：主循环判定 + 拨号任务记录，跨任务共享。
    let dial_fails: Arc<Mutex<DialFails>> = Arc::new(Mutex::new(DialFails::default()));
    let start = Instant::now();

    logging::info(
        "tun",
        "用户态协议栈已启动 (10.10.10.1/24, fd00:1::1/64, DNS 10.10.10.53 + fd00:1::53)",
    );

    // 主循环耗时仪表：结算「select 返回 → 本轮处理完、下一轮 select 前」的时间。
    // 长轮会饿死同循环里的其他连接，这个数比主观体感可靠。
    let mut round_started: Option<Instant> = None;
    loop {
        if ctx.shutdown.load(Ordering::Relaxed) {
            break;
        }
        if let Some(t) = round_started.take() {
            let ms = t.elapsed().as_millis() as u64;
            ctx.stats.loop_round_ms_last.store(ms, Ordering::Relaxed);
            ctx.stats.loop_round_ms_max.fetch_max(ms, Ordering::Relaxed);
        }
        // 切网（蜂窝↔Wi-Fi）后旧网络的 QUIC 假活结论必须失效：壳层置位，这里整表清空。
        if ctx.quic_clear.swap(false, Ordering::Relaxed) {
            let n = quic_blackhole.len();
            quic_blackhole.clear();
            quic_probe.clear();
            if n > 0 {
                logging::info("tun", format!("网络切换：清空 {} 条 QUIC 黑洞判定", n));
            }
        }

        // 空闲时降低唤醒频率；有 tx backlog 或写阻塞时保持 1ms 兜底。
        // 新报文到达、TUN 可写、出站数据入队都会立即唤醒，这里的兜底只防漏唤醒。
        let idle = conns.is_empty() && udp_clients.is_empty();
        let backlogged = pending_out.len() >= device.pending_cap;
        let wait = if write_blocked || !pending_out.is_empty() || has_relay_backlog(&conns) {
            Duration::from_millis(1)
        } else if idle {
            Duration::from_millis(250)
        } else {
            Duration::from_millis(IDLE_SAFETY_WAIT_MS)
        };
        // 事件驱动：TUN 可读、TUN 可写、UDP 响应、DNS 响应任一到达即唤醒。
        // backlog 达到高水位时暂停读 TUN，背压回内核，避免 pending_out 无界增长。
        tokio::select! {
            // readable 只负责唤醒并清掉就绪位；真正的读取在下方固定步骤执行，
            // 不再「赌 select 选中这个分支」——边沿触发或漏唤醒会把 RX 停住，
            // RX 一停 ACK 回填就慢，下行窗口跟着被压。
            r = async_fd.readable(), if !backlogged => {
                if let Ok(mut g) = r {
                    g.clear_ready();
                }
            }
            r = async_fd.writable(), if write_blocked => {
                if let Ok(mut g) = r {
                    g.clear_ready();
                    write_blocked = false;
                }
            }
            r = udp_resp_rx.recv() => {
                if let Some((client, remote, data)) = r {
                    // 该会话任何下行包（含 ACK/PING）都算握手活着：标记已建立
                    // （豁免黑洞判定），不再直接删探测记录——删记录会丢「见过下行」
                    // 的信息，纯上传流下一轮上行又会被当成握手无回包误判。
                    let key = (remote.addr, remote.port);
                    if let Some(p) = quic_probe.get_mut(&key) {
                        p.2 = true;
                    }
                    quic_blackhole.remove(&key);
                    if udp_replies.len() < 512 {
                        udp_replies.push_back((remote, client, data));
                    }
                }
            }
            r = dns_rx.recv() => {
                if let Some((handle, ep, data)) = r {
                    if dns_pending.len() < 256 {
                        dns_pending.push_back((handle, ep, data));
                    }
                }
            }
            // 出站数据到达即唤醒：relay 读到上游数据后 notify_one，
            // 这里醒来后紧接着的 drain 段把 channel 搬进 smoltcp。
            // Notify 会保留一个 permit，drain 与唤醒之间不会丢事件。
            _ = relay_wake.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }

        round_started = Some(Instant::now());
        claimed.clear();
        // 读 TUN 是每轮固定步骤：非阻塞读到 WouldBlock 即止，单轮最多 MAX_RX_BURST 包。
        // backlog 到高水位时仍然跳过，把背压留给上行（避免 pending_out 无界增长）。
        if !backlogged {
            let mut rounds = 0;
            loop {
                rounds += 1;
                if rounds > MAX_RX_BURST {
                    break;
                }
                match device.read_rx(async_fd.get_ref().as_raw_fd()) {
                    Ok(Some(pkt)) => {
                        ctx.stats
                            .up_bytes
                            .fetch_add(pkt.len() as u64, Ordering::Relaxed);
                        // ICMP echo 本地代答：不进 smoltcp（它不路由非本机目的地址，
                        // 转发型 ping 会被静默丢弃），直接合成应答写回 TUN。
                        if let Some(reply) = icmp_echo_reply(&pkt) {
                            if pending_out.len() < device.pending_cap {
                                pending_out.push_back(reply);
                            }
                            continue;
                        }
                        if let Some((port, addr)) = lookup_tcp_dst(&pkt) {
                            let key = (addr, port);
                            // 每条 SYN 独占一个未被认领的 Listen socket；没有就新建。
                            let mut reuse = None;
                            if let Some(v) = listeners.get(&key) {
                                for (h, _) in v {
                                    if !claimed.contains(h)
                                        && sockets.get::<tcp::Socket>(*h).state() == tcp::State::Listen
                                    {
                                        reuse = Some(*h);
                                        break;
                                    }
                                }
                            }
                            let handle = match reuse {
                                Some(h) => Some(h),
                                None => add_listener(&mut sockets, addr, port, &ctx.stats).map(|h| {
                                    listeners.entry(key).or_default().push((h, Instant::now()));
                                    h
                                }),
                            };
                            if let Some(h) = handle {
                                claimed.insert(h);
                            }
                        }
                        if let Some((src, dst)) = lookup_udp_flow(&pkt) {
                            if dst.port == 53 {
                                // TUN 内所有 :53 一律交给本地 DNS 引擎（mihomo dns-hijack any:53）。
                                // 本地 10.10.10.53/fd00:1::53 已有固定 socket；其他目的地址按地址动态建，
                                // 这样应答源仍是 8.8.8.8:53、114.114.114.114:53，客户端不会因源地址不符丢弃。
                                if !is_local_dns_endpoint(dst)
                                    && !dns_udp_dsts.contains_key(&(dst.addr, dst.port))
                                {
                                    if dns_udp_dsts.len() >= 256 {
                                        if let Some(oldest) = dns_udp_dsts
                                            .iter()
                                            .min_by_key(|(_, (_, t))| *t)
                                            .map(|(k, _)| *k)
                                        {
                                            if let Some((h, _)) = dns_udp_dsts.remove(&oldest) {
                                                let _ = sockets.remove(h);
                                            }
                                        }
                                    }
                                    if let Some(h) = add_udp_dst_socket(&mut sockets, dst.addr, dst.port) {
                                        dns_udp_dsts.insert((dst.addr, dst.port), (h, Instant::now()));
                                    }
                                }
                            } else {
                                // QUIC 精确迫降：共享 CDN IP 上反查必然 ambiguous，旧门永不开，
                                // App 走 HTTP/3 就整条绕过 MITM。这里直接解 Initial 的 SNI，
                                // 命中 MITM 清单才丢包；同 IP 的非 MITM 域名不受连坐。
                                if dst.port == 443 {
                                    if let Some(payload) = udp_payload(&pkt) {
                                        if let Some(sni) = crate::quic::initial_sni(payload) {
                                            let client_uid = ctx.uid_map.read().ok().and_then(|m| {
                                                m.lookup_flow(
                                                    IpAddr::from(src.addr),
                                                    src.port,
                                                    IpAddr::from(dst.addr),
                                                    dst.port,
                                                )
                                            });
                                            if ctx.mitm().should_mitm_uid(&sni, client_uid) {
                                                ctx.stats.mitm_quic_blocked.fetch_add(1, Ordering::Relaxed);
                                                continue;
                                            }
                                        }
                                    }
                                }
                                let domain = ctx
                                    .dns()
                                    .reverse
                                    .lock()
                                    .ok()
                                    .and_then(|m| m.lookup_confident(IpAddr::from(dst.addr)));
                                // 只有反向映射唯一时才丢 QUIC/HTTP3；共享 CDN IP 上
                                // 其他域名不能被一起迫降到 TCP。
                                if dst.port == 443
                                    && domain
                                        .as_deref()
                                        .map(|d| ctx.mitm().should_mitm(d))
                                        .unwrap_or(false)
                                {
                                    ctx.stats.mitm_quic_blocked.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                let decision_guard = ctx
                                    .decision
                                    .read()
                                    .unwrap_or_else(|p| p.into_inner());
                                let action = decide_action_uid(
                                    &ctx,
                                    domain.as_deref(),
                                    IpAddr::from(dst.addr),
                                    dst.port,
                                    ConnKind::Udp,
                                    None,
                                );
                                let mode = udp_mode(&ctx, &action);
                                drop(decision_guard);
                                // QUIC 假活回落：这个目标已被判为 UDP 黑洞时，直接吞掉 QUIC
                                    // 包（不发、也不建会话），让客户端自己的 Happy Eyeballs 回退 TCP。
                                if dst.port == 443
                                    && ctx
                                        .cfg
                                        .read()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .quic_fallback
                                {
                                    let key = (dst.addr, dst.port);
                                    if let Some(t) = quic_blackhole.get(&key) {
                                        if Instant::now().duration_since(*t)
                                            < Duration::from_secs(QUIC_BLACKHOLE_TTL_SECS)
                                        {
                                            ctx.stats.quic_fallback.fetch_add(1, Ordering::Relaxed);
                                            continue;
                                        }
                                        quic_blackhole.remove(&key);
                                    }
                                    let now_up = Instant::now();
                                    quic_probe
                                        .entry(key)
                                        .and_modify(|(_, last, _)| *last = now_up)
                                        .or_insert((now_up, now_up, false));
                                }
                                if !matches!(mode, UdpMode::Unsupported(_)) {
                                    if !udp_dsts.contains_key(&(dst.addr, dst.port)) {
                                        if let Some(h) = add_udp_dst_socket(&mut sockets, dst.addr, dst.port) {
                                            udp_dsts.insert((dst.addr, dst.port), (h, Instant::now()));
                                        }
                                    }
                                    // 同一客户端源端口访问不同目标时，必须使用独立会话，
                                    // 否则后续目标会沿用第一个目标的直连/代理模式。
                                    let key = (src.addr, src.port, dst.addr, dst.port);
                                    if !udp_clients.contains_key(&key) {
                                        if udp_clients.len() >= 512 {
                                            if let Some(oldest) = udp_clients
                                                .iter()
                                                .min_by_key(|(_, c)| c.last)
                                                .map(|(k, _)| *k)
                                            {
                                                udp_clients.remove(&oldest);
                                            }
                                        }
                                        if let Some(tx) = spawn_udp_client(src, mode, udp_resp_tx.clone(), ctx.dns()) {
                                            udp_clients.insert(key, UdpClient { tx, last: Instant::now() });
                                        }
                                    }
                                }
                            }
                        }
                        device.rx.push_back(pkt);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            logging::warn("tun", format!("读取失败: {}", e));
                        }
                        break;
                    }
                }
            }
        }

        // 协作让出①：RX burst 之后让同 worker 的拨号/DNS 任务跑一轮，
        // 避免长轮把它们饿死（排队尖刺的来源）。
        tokio::task::yield_now().await;
        let now = smol_now(start);
        let _ = iface.poll(now, &mut device, &mut sockets);

        // TCP 监听器 -> 已建立连接
        let mut lost: Vec<(IpAddress, u16, SocketHandle)> = Vec::new();
        let mut accepted: Vec<(IpAddress, u16, SocketHandle, Instant)> = Vec::new();
        for (key, v) in listeners.iter() {
            for (handle, _) in v {
                let state = sockets.get::<tcp::Socket>(*handle).state();
                if state != tcp::State::Listen {
                    lost.push((key.0, key.1, *handle));
                    accepted.push((key.0, key.1, *handle, Instant::now()));
                }
            }
        }
        for (addr, port, handle) in lost {
            let mut empty = false;
            if let Some(v) = listeners.get_mut(&(addr, port)) {
                v.retain(|(h, _)| *h != handle);
                empty = v.is_empty();
            }
            if empty {
                listeners.remove(&(addr, port));
            }
        }
        for (addr, port, handle, accepted_at) in accepted {
            // 半开连接也要封顶：每个 socket 带 256K 缓冲，只靠 listeners 上限兜不住。
            // 超限时先清掉最早那一条（它等首包/握手的时间最长，基本已经废了）。
            if pending_accept.len() >= MAX_PENDING_ACCEPT {
                let (a, p, h, _) = pending_accept.remove(0);
                logging::warn(
                    "tun",
                    format!("等待首包的连接过多({})，丢弃最早一条 {}:{}", MAX_PENDING_ACCEPT, IpAddr::from(a), p),
                );
                release_tcp_socket(&mut sockets, h);
            }
            pending_accept.push((addr, port, handle, accepted_at));
        }
        // 不再为已消费端口预建 standby listener：收包路径只在 SYN&&!ACK 时按需建，
        // 下一条新连接的 SYN 自己会拿到 socket。预建的 standby 每个白占 512K+256K 大档，
        // 挂到过期才释放，会把大档名额挤给空气、让真连接触发降级。

        // 新连接建立
        let mut still_pending = Vec::new();
        for (addr, port, handle, accepted_at) in pending_accept.into_iter() {
            let state = sockets.get::<tcp::Socket>(handle).state();
            match state {
                tcp::State::Established => {
                    // 连接总数上限：每条连接带协议栈缓冲与中继任务，不能让内存无界增长。
                    // 但绝不能像旧逻辑那样「满了就拒绝新连接」——那会让所有 APP 一起断网。
                    // 先淘汰最久没有业务数据的那条（死连接早就该被 keepalive/timeout 清掉，
                    // 走到这里说明对端还活着但没流量），实在没有可淘汰的才拒绝。
                    if conns.len() >= MAX_TCP_CONNS {
                        let now_i = Instant::now();
                        if let Some(idx) = pick_victim(&conns, now_i) {
                            let victim = conns.swap_remove(idx);
                            ctx.conns
                                .write()
                                .unwrap_or_else(|p| p.into_inner())
                                .remove(victim.snap);
                            let victim_ep = sockets
                                .get::<tcp::Socket>(victim.handle)
                                .remote_endpoint()
                                .map(|e| e.to_string())
                                .unwrap_or_else(|| "-".into());
                            let idle_secs = now_i
                                .saturating_duration_since(victim.last_active)
                                .as_secs();
                            release_tcp_socket(&mut sockets, victim.handle);
                            ctx.stats.active_conns.fetch_sub(1, Ordering::Relaxed);
                            ctx.stats.tcp_limit_evicted.fetch_add(1, Ordering::Relaxed);
                            logging::warn(
                                "tun",
                                format!(
                                    "并发连接达到上限({})，淘汰最久空闲连接 {}（空闲 {}s）",
                                    MAX_TCP_CONNS, victim_ep, idle_secs
                                ),
                            );
                        } else {
                            logging::warn(
                                "tun",
                                format!("并发连接达到上限({})，暂无可淘汰连接，拒绝新连接", MAX_TCP_CONNS),
                            );
                            release_tcp_socket(&mut sockets, handle);
                            continue;
                        }
                    }
                    let remote = sockets.get::<tcp::Socket>(handle).remote_endpoint();
                    let local_ip = IpAddr::from(addr);
                    // App 归属：用 (客户端端口, 目标地址, 目标端口) 查壳层下发的 socket 表。
                    // 客户端 IP 只作精确匹配用——TUN 里是 VPN 地址、表里是物理网卡地址，
                    // 所以真正的定位靠端口，IP 对不上是常态而不是异常。
                    let client_uid = remote.and_then(|r| {
                        let client_ip = IpAddr::from(r.addr);
                        ctx.uid_map
                            .read()
                            .ok()
                            .and_then(|m| m.lookup_flow(client_ip, r.port, local_ip, port))
                    });
                    if client_uid.is_some() {
                        ctx.stats.uid_resolved.fetch_add(1, Ordering::Relaxed);
                    } else if ctx.rules.read().unwrap_or_else(|p| p.into_inner()).has_uid_rules() {
                        ctx.stats.uid_unknown.fetch_add(1, Ordering::Relaxed);
                    }
                    let mut domain = ctx
                        .dns()
                        .reverse
                        .lock()
                        .ok()
                        .and_then(|m| m.lookup(local_ip));
                    let dns_conn = port == 53;
                    let mut sni: Option<String> = None;
                    // 443 不能只信 DNS 反向映射：CDN 共用 IP 时反向域名可能属于
                    // 另一个站点。优先从本次 ClientHello 读取 SNI；读不到就不 MITM，
                    // 由上层透明转发，避免签出与 SNI 不匹配的叶子证书。
                    if ctx.sniff() && !dns_conn && (domain.is_none() || port == 443) {
                        // 443 也要短暂等待首包：反向映射可能属于 CDN 共用 IP 的另一个站点。
                        // 最多等 SNI_WAIT_MS，避免 Server-first 协议被长时间卡住。
                        let mut first = [0u8; 2048];
                        let n = sockets
                            .get_mut::<tcp::Socket>(handle)
                            .peek_slice(&mut first)
                            .unwrap_or(0);
                        if n > 0 {
                            let sniffed = crate::sniff::sniff_domain(&first[..n]);
                            if sniffed.is_some() {
                                sni = sniffed.clone();
                            }
                            if domain.is_none() {
                                domain = sniffed;
                            }
                        }
                        let may_be_tls = n > 0 && first[0] == 0x16;
                        // 反向映射已有域名、且 MITM 不可能命中时不再等首包：
                        // 延迟探测类连接连上后不发数据，等待只会凭空加延迟。
                        // （MITM 可能命中时仍必须等 SNI，避免签错证书。）
                        let mitm_maybe = domain
                            .as_deref()
                            .map(|d| ctx.mitm().should_mitm(d))
                            .unwrap_or(true);
                        if (domain.is_none() || (port == 443 && sni.is_none()))
                            && accepted_at.elapsed() < Duration::from_millis(SNI_WAIT_MS)
                            && (n == 0 || may_be_tls)
                            && (domain.is_none() || mitm_maybe)
                        {
                            still_pending.push((addr, port, handle, accepted_at));
                            continue;
                        }
                        if let Some(d) = domain.as_deref() {
                            if let Ok(mut rev) = ctx.dns.read().unwrap_or_else(|p| p.into_inner()).reverse.lock() {
                                rev.insert(local_ip, d, 120);
                            }
                            logging::info("sniff", format!("{}:{} -> {}", local_ip, port, d));
                        }
                    }
                    // HTTP 连通性探测本地代答：系统/ROM 的 generate_204 等探测
                    // 直接回 204/Success，让 VPN 网络立即通过「已验证」，
                    // App 不再等验证回调，探测风暴也就此停止。
                    if !dns_conn && port == 80 {
                        let mut first = [0u8; 2048];
                        let n = sockets
                            .get_mut::<tcp::Socket>(handle)
                            .peek_slice(&mut first)
                            .unwrap_or(0);
                        if n > 0 {
                            if let Some(resp) = probe_http_response(&first[..n]) {
                                let (stx, srx) = mpsc::channel::<Vec<u8>>(1);
                                let _ = stx.try_send(resp);
                                drop(stx); // 响应发完即 EOF：主循环排空后正常四次挥手
                                conns.push(TcpConn {
                                    handle,
                                    snap: None,
                                    to_relay: None,
                                    from_relay: srx,
                                    pending: VecDeque::new(),
                                    pending_bytes: 0, relay_paused: false,
                                    read_wake: Arc::new(Notify::new()),
                                    relay_closed: false,
                                    client_closed: false,
                                    closing: false,
                                    last_active: Instant::now(),
                                    meter: None,
                                    recv_full: false,
                                    send_stall_since: None,
                                    send_stall_logged: false,
                                    rate_prev_up: 0,
                                    rate_prev_down: 0,
                                });
                                ctx.stats.active_conns.fetch_add(1, Ordering::Relaxed);
                                ctx.stats.total_conns.fetch_add(1, Ordering::Relaxed);
                                logging::info("probe", format!("连通性探测本地代答 {}:{}", local_ip, port));
                                continue;
                            }
                            // 头部还没收全：最多再等 SNI_WAIT_MS，避免探测请求分包漏判。
                            if !first[..n].windows(4).any(|w| w == b"\r\n\r\n")
                                && accepted_at.elapsed() < Duration::from_millis(SNI_WAIT_MS)
                            {
                                still_pending.push((addr, port, handle, accepted_at));
                                continue;
                            }
                        } else if accepted_at.elapsed() < Duration::from_millis(SNI_WAIT_MS) {
                            still_pending.push((addr, port, handle, accepted_at));
                            continue;
                        }
                    }
                    let route_domain = sni.clone().or_else(|| domain.clone());
                    let mitm_host = if port == 443 { sni.clone() } else { route_domain.clone() };
                    let target = Target {
                        ip: local_ip,
                        port,
                        domain: route_domain.clone(),
                    };
                    // 任意目的地址的 TCP/53 都由本地 DNS 服务端应答；
                    // 不能再走规则判定，否则命中外网规则会被 BLOCK 掉。
                    let decision_guard = ctx
                        .decision
                        .read()
                        .unwrap_or_else(|p| p.into_inner());
                    let (action, rule_detail) = if dns_conn {
                        (Action::Direct, "DNS over TCP：本地应答".to_string())
                    } else {
                        decide_detail_for(
                            &ctx,
                            route_domain.as_deref(),
                            local_ip,
                            port,
                            ConnKind::Tcp,
                            client_uid,
                        )
                    };
                    let conn_id = ctx.stats.new_conn_id();
                    let target_label = route_domain.clone().unwrap_or_else(|| local_ip.to_string());
                    let action_label = ctx
                        .rules
                        .read()
                        .unwrap_or_else(|p| p.into_inner())
                        .decision_label(&action);
                    drop(decision_guard);
                    logging::info(
                        "conn",
                        format!(
                            "#{} {}:{} [{}]-> {}",
                            conn_id,
                            target_label,
                            port,
                            action_label,
                            remote
                                .map(|r| r.to_string())
                                .unwrap_or_else(|| "-".into())
                        ),
                    );

                    if matches!(action, Action::Block) {
                        // 主动 RST：DoT 探测快速失败，Android 才能尽快回落；
                        // 规则拦截的连接也不该挂着等超时。
                        release_tcp_socket(&mut sockets, handle);
                        continue;
                    }
                    // 直连熔断：冷却期内抑制真实拨号（不发 SYN、不占拨号 worker），
                    // 但绝不立即 RST——测速/探活 App 会把「秒拒」当成另一种结果，
                    // 延迟读数和服务器排序都会被污染。保持与真实不可达完全一致的
                    // 失败时序：静默等待后按「拨号失败」的同一条路径关闭连接。
                    if !dns_conn && matches!(action, Action::Direct) {
                        let key = dial_key(route_domain.as_deref(), local_ip, port);
                        let suppressed = {
                            let br = dial_fails.lock().unwrap_or_else(|p| p.into_inner());
                            dial_breaker_active(&br, &key, Instant::now())
                        };
                        if suppressed {
                            let (stx, srx) = mpsc::channel::<Vec<u8>>(1);
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(SUPPRESSED_DIAL_FAIL_SECS)).await;
                                // 与拨号失败 Err 分支完全相同的收尾：drop sender →
                                // 主循环 relay_closed → 正常四次挥手，而不是 RST。
                                drop(stx);
                            });
                            conns.push(TcpConn {
                                handle,
                                snap: None,
                                to_relay: None,
                                from_relay: srx,
                                pending: VecDeque::new(),
                                pending_bytes: 0, relay_paused: false,
                                read_wake: Arc::new(Notify::new()),
                                relay_closed: false,
                                client_closed: false,
                                closing: false,
                                last_active: Instant::now(),
                                meter: None,
                                recv_full: false,
                                send_stall_since: None,
                                send_stall_logged: false,
                                rate_prev_up: 0,
                                rate_prev_down: 0,
                            });
                            ctx.stats.active_conns.fetch_add(1, Ordering::Relaxed);
                            ctx.stats.total_conns.fetch_add(1, Ordering::Relaxed);
                            ctx.stats.dial_breaker_rejected.fetch_add(1, Ordering::Relaxed);
                            logging::info(
                                "conn",
                                format!(
                                    "#{} 熔断抑制拨号 {}:{}（{}s 后按原时序失败）",
                                    conn_id, target_label, port, SUPPRESSED_DIAL_FAIL_SECS
                                ),
                            );
                            continue;
                        }
                    }
                    // MITM：SNI/反向映射命中域名列表的 443 连接改走本地 TLS 终止 + 规则改写。
                    // 金融保护先于一切命中：支付/银行连接被劫持不是「解不开」，而是被弄断。
                    let mitm_state = ctx.mitm();
                    if let Some(reason) = mitm_state
                        .engine
                        .finance_bypass(client_uid, mitm_host.as_deref())
                    {
                        ctx.stats.mitm_finance_skipped.fetch_add(1, Ordering::Relaxed);
                        logging::info(
                            "mitm",
                            format!(
                                "#{} 金融保护跳过 {}（{}，uid={}）",
                                conn_id,
                                mitm_host.clone().unwrap_or_default(),
                                reason,
                                client_uid.map(|u| u.to_string()).unwrap_or_else(|| "未知".into())
                            ),
                        );
                    }
                    // 临时放行窗口内该域名完全不解密：这是「改写突然失效」的直接来源，
                    // 必须逐条可见，否则诊断只能看到改写数不涨却找不到原因。
                    if !dns_conn && port == 443 {
                        if let Some(d) = mitm_host.as_deref() {
                            if let Some(left) = mitm_state.engine.bypass_remaining(d) {
                                ctx.stats.mitm_bypassed.fetch_add(1, Ordering::Relaxed);
                                logging::info(
                                    "mitm",
                                    format!("#{} {} 处于临时放行窗口（剩 {}s），本条不解密", conn_id, d, left),
                                );
                            }
                        }
                    }
                    let mitm_hit = !dns_conn
                        && port == 443
                        && mitm_state.engine.finance_bypass(client_uid, mitm_host.as_deref()).is_none()
                        && mitm_host
                            .as_deref()
                            .map(|d| mitm_state.should_mitm_uid(d, client_uid))
                            .unwrap_or(false);
                    if mitm_hit {
                        let (a, b) = tokio::io::duplex(MITM_DUPLEX_CAP);
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                        let (stx, srx) = mpsc::channel::<Vec<u8>>(64);
                        let host = mitm_host.clone().unwrap_or_default();
                        let ctx2 = ctx.clone();
                        let ms = mitm_state.clone();
                        let action2 = action.clone();
                        let target2 = target.clone();
                        tokio::spawn(async move {
                            crate::mitm::handle(a, host, target2, action2, ctx2, ms, conn_id).await;
                        });
                        let read_wake = Arc::new(Notify::new());
                        tokio::spawn(relay_stream(Box::new(b), rx, stx, relay_wake.clone(), read_wake.clone()));
                        let (snap, meter) = ctx
                            .conns
                            .write()
                            .unwrap_or_else(|p| p.into_inner())
                            .insert(
                                client_uid,
                                mitm_host.clone(),
                                local_ip.to_string(),
                                port,
                                action_label.clone(),
                                rule_detail.split('\n').next().unwrap_or("").to_string(),
                                true,
                            );
                        conns.push(TcpConn {
                            handle,
                            snap: Some(snap),
                            to_relay: Some(tx),
                            from_relay: srx,
                            pending: VecDeque::new(),
                            pending_bytes: 0, relay_paused: false,
                            read_wake,
                            relay_closed: false,
                            client_closed: false,
                            closing: false,
                            last_active: Instant::now(),
                            meter: Some(meter),
                            recv_full: false,
                            send_stall_since: None,
                            send_stall_logged: false,
                            rate_prev_up: 0,
                            rate_prev_down: 0,
                        });
                        ctx.stats.active_conns.fetch_add(1, Ordering::Relaxed);
                        ctx.stats.total_conns.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if dns_conn {
                        let (a, b) = tokio::io::duplex(DNS_TCP_DUPLEX_CAP);
                        let dns = ctx.dns.read().unwrap_or_else(|p| p.into_inner()).clone();
                        tokio::spawn(dns_tcp_server(dns, a));
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                        let (stx, srx) = mpsc::channel::<Vec<u8>>(64);
                        let read_wake = Arc::new(Notify::new());
                        tokio::spawn(relay_stream(Box::new(b), rx, stx, relay_wake.clone(), read_wake.clone()));
                        conns.push(TcpConn {
                            handle,
                            snap: None,
                            to_relay: Some(tx),
                            from_relay: srx,
                            pending: VecDeque::new(),
                            pending_bytes: 0, relay_paused: false,
                            read_wake,
                            relay_closed: false,
                            client_closed: false,
                            closing: false,
                            last_active: Instant::now(),
                            meter: None,
                            recv_full: false,
                            send_stall_since: None,
                            send_stall_logged: false,
                            rate_prev_up: 0,
                            rate_prev_down: 0,
                        });
                        ctx.stats.active_conns.fetch_add(1, Ordering::Relaxed);
                        ctx.stats.total_conns.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                        let (stx, srx) = mpsc::channel::<Vec<u8>>(64);
                        let nodes = ctx.nodes_snapshot();
                        let selected = ctx.selected_snapshot();
                        let dns = ctx.dns();
                        let action2 = action.clone();
                        let target_label2 = target_label.clone();
                        let action_label2 = action_label.clone();
                        let health = ctx.health.clone();
                        let health_action = action2.clone();
                        let health_started = Instant::now();
                        // 唤醒句柄必须在外层 clone 后 move 进 spawn 块，
                        // 否则 Arc 被 move 走，主循环这一轮之后就拿不到它了。
                        let relay_wake2 = relay_wake.clone();
                        let read_wake = Arc::new(Notify::new());
                        let read_wake2 = read_wake.clone();
                        let dial_fails2 = dial_fails.clone();
                        let breaker_key = dial_key(route_domain.as_deref(), local_ip, port);
                        tokio::spawn(async move {
                            // 分段计时：排队（accept→任务首次执行）与拨号分开，
                            // 否则「耗时 7914ms」分不清是 2s 拨号超时还是任务被调度挂住。
                            let dial_start = Instant::now();
                            let result = outbound::connect(&action2, &nodes, selected.as_deref(), target, Some(&dns)).await;
                            let dial_ms = dial_start.elapsed().as_millis();
                            if let Action::Node(name) = &health_action {
                                // 用真实连接结果更新 TCP 健康；UDP 状态绝不从这里推导。
                                health.record(
                                    name,
                                    Transport::Tcp,
                                    result.is_ok(),
                                    if result.is_ok() {
                                        Some(health_started.elapsed().as_millis() as u64)
                                    } else {
                                        None
                                    },
                                    3,
                                    2,
                                    crate::stats::now_ms(),
                                );
                            }
                            match result {
                                Ok(stream) => {
                                    // 直连成功即清除冷却计数：路径恢复后不该继续被熔断。
                                    if matches!(health_action, Action::Direct) {
                                        dial_breaker_clear(
                                            &mut dial_fails2.lock().unwrap_or_else(|p| p.into_inner()),
                                            &breaker_key,
                                        );
                                    }
                                    relay_stream(stream, rx, stx, relay_wake2, read_wake2).await
                                }
                                Err(e) => {
                                    // 直连失败记入冷却表：连续失败升级冷却，阻断无限重试。
                                    // 多目标同时失败会触发链路自愈（判定为本机链路问题）。
                                    if matches!(health_action, Action::Direct) {
                                        let healed = dial_breaker_record(
                                            &mut dial_fails2.lock().unwrap_or_else(|p| p.into_inner()),
                                            breaker_key,
                                            Instant::now(),
                                        );
                                        if healed {
                                            logging::warn(
                                                "conn",
                                                format!(
                                                    "{}s 内多个不同目标拨号失败，判定为本地链路问题：清空熔断并暂停 {}s",
                                                    LINK_FAIL_WINDOW_SECS, LINK_SELF_HEAL_SUSPEND_SECS
                                                ),
                                            );
                                        }
                                    }
                                    logging::warn(
                                        "conn",
                                        format!(
                                            "#{} 连接失败 {}:{} [{}] 耗时 {}ms（排队 {}ms + 拨号 {}ms）: {}",
                                            conn_id,
                                            target_label2,
                                            port,
                                            action_label2,
                                            accepted_at.elapsed().as_millis(),
                                            dial_start.duration_since(accepted_at).as_millis(),
                                            dial_ms,
                                            e
                                        ),
                                    );
                                    drop(stx);
                                }
                            }
                        });
                        let (snap, meter) = ctx
                            .conns
                            .write()
                            .unwrap_or_else(|p| p.into_inner())
                            .insert(
                                client_uid,
                                route_domain.clone(),
                                local_ip.to_string(),
                                port,
                                action_label.clone(),
                                rule_detail.split('\n').next().unwrap_or("").to_string(),
                                false,
                            );
                        conns.push(TcpConn {
                            handle,
                            snap: Some(snap),
                            to_relay: Some(tx),
                            from_relay: srx,
                            pending: VecDeque::new(),
                            pending_bytes: 0, relay_paused: false,
                            read_wake,
                            relay_closed: false,
                            client_closed: false,
                            closing: false,
                            last_active: Instant::now(),
                            meter: Some(meter),
                            recv_full: false,
                            send_stall_since: None,
                            send_stall_logged: false,
                            rate_prev_up: 0,
                            rate_prev_down: 0,
                        });
                        ctx.stats.active_conns.fetch_add(1, Ordering::Relaxed);
                        ctx.stats.total_conns.fetch_add(1, Ordering::Relaxed);
                    }
                }
                tcp::State::Closed => {
                    release_tcp_socket(&mut sockets, handle);
                }
                _ => {
                    still_pending.push((addr, port, handle, accepted_at));
                }
            }
        }
        pending_accept = still_pending;

        // TCP 连接数据（scratch 复用，避免每个报文都新建 16KB）
        let mut dead: Vec<usize> = Vec::new();
        let mut tcp_scratch = vec![0u8; 16384];
        // 每轮只取一次时钟：1024 条连接全调 Instant::now 是无谓的系统调用开销。
        let now_i = Instant::now();
        for (idx, conn) in conns.iter_mut().enumerate() {
            let mut touched = false;
            let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
            if sock.state() == tcp::State::Closed {
                dead.push(idx);
                continue;
            }

            while sock.can_recv() && conn.to_relay.as_ref().map(|t| t.capacity() > 0).unwrap_or(false) {
                match sock.recv_slice(&mut tcp_scratch) {
                    Ok(n) if n > 0 => {
                        touched = true;
                        if let Some(m) = conn.meter.as_ref() {
                            m.up.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        let data = tcp_scratch[..n].to_vec();
                        match conn.to_relay.as_ref().unwrap().try_send(data) {
                            Ok(_) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => break,
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                conn.to_relay = None;
                                conn.relay_closed = true;
                                break;
                            }
                        }
                    }
                    _ => break,
                }
            }

            if sock.state() == tcp::State::CloseWait {
                conn.client_closed = true;
            }
            // 客户端半关闭（FIN）：只停止 client->server 方向——drop to_relay
            // 让中继关闭出站写侧；服务端响应要继续收到 relay EOF，不能整条关闭。
            if conn.client_closed && conn.to_relay.is_some() {
                conn.to_relay = None;
            }

            // 下行背压：pending 到上限就停止搬运，让通道填满、relay 停读上游。
            if drain_relay_to_pending(conn) {
                touched = true;
            }
            // best-fit：send_slice 返回实际入队字节数，头块写不完就部分写入、
            // 剩余留在队头下轮续写——字节流顺序不变，也不因单块装不下而整环停摆。
            while sock.can_send() {
                match conn.pending.front_mut() {
                    Some(front) => match sock.send_slice(front) {
                        Ok(n) if n == front.len() => {
                            touched = true;
                            conn.pending_bytes -= front.len();
                            if let Some(m) = conn.meter.as_ref() {
                                m.down.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            conn.pending.pop_front();
                        }
                        Ok(0) => break,
                        Ok(n) => {
                            touched = true;
                            conn.pending_bytes -= n;
                            if let Some(m) = conn.meter.as_ref() {
                                m.down.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            front.drain(..n);
                        }
                        Err(_) => break,
                    },
                    None => break,
                }
            }
            // 只有服务端方向也结束（relay_closed）且缓冲排空后才真正关闭。
            if conn.relay_closed
                && conn.pending.is_empty()
                && !conn.closing
                && matches!(sock.state(), tcp::State::Established | tcp::State::CloseWait)
            {
                sock.close();
                conn.closing = true;
                conn.to_relay = None;
            }
            if sock.state() == tcp::State::Closed {
                dead.push(idx);
            } else if touched {
                conn.last_active = now_i;
            }
        }
        if !dead.is_empty() {
            let mut removed = 0i64;
            for idx in dead.into_iter().rev() {
                let conn = conns.swap_remove(idx);
                // 正常关闭（FIN 走完 state==Closed）也必须归还大档计数，
                // 否则 TCP_SOCKETS 只增不减，后面的新连接永远被降级到 128K。
                release_tcp_socket(&mut sockets, conn.handle);
                ctx.conns
                    .write()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(conn.snap);
                removed += 1;
            }
            ctx.stats.active_conns.fetch_sub(removed, Ordering::Relaxed);
        }

        // 数据面判别仪表：每 500ms 采样一次，按「条件成立期间累计毫秒」记，不记轮数。
        // 主循环 wait 在 1ms/空闲之间切换，轮数换算出来会失真；毫秒口径可以直接
        // 换算成「这段时间里有多少比例在等」。
        if last_meter.elapsed() >= Duration::from_millis(METER_TICK_MS) {
            last_meter = Instant::now();
            let now_m = Instant::now();
            for conn in conns.iter_mut() {
                let sock = sockets.get::<tcp::Socket>(conn.handle);
                let rc = sock.recv_capacity();
                let rq = sock.recv_queue();
                let sc = sock.send_capacity();
                let sq = sock.send_queue();
                // H1 实锤：本地接收缓冲满，并且 relay 侧还有积压（上游数据已经躺在通道里）。
                // 只满足前者可能是对端在灌包而我们正在搬；两个同时成立才是「收不下」。
                let recv_pressure = rc > 0
                    && rq >= rc
                    && (!conn.from_relay.is_empty() || !conn.pending.is_empty());
                if recv_pressure && !conn.recv_full {
                    conn.recv_full = true;
                } else if !recv_pressure {
                    conn.recv_full = false;
                }
                if recv_pressure {
                    ctx.stats.tcp_recv_full.fetch_add(METER_TICK_MS, Ordering::Relaxed);
                }
                // 发送侧：待发队列非空、对端通告窗口为 0 → 对端不收。
                if sq > 0 && sc == 0 {
                    ctx.stats.tcp_send_stalled.fetch_add(METER_TICK_MS, Ordering::Relaxed);
                    let since = *conn.send_stall_since.get_or_insert(now_m);
                    if !conn.send_stall_logged
                        && now_m.duration_since(since) >= Duration::from_secs(3)
                    {
                        conn.send_stall_logged = true;
                        let ep = sock
                            .remote_endpoint()
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "-".into());
                        logging::warn(
                            "tun",
                            format!(
                                "发送停滞超过 3s：{} 对端零窗口，待发 {}B（本地接收队列 {}/{}B）",
                                ep, sq, rq, rc
                            ),
                        );
                    }
                } else {
                    conn.send_stall_since = None;
                    conn.send_stall_logged = false;
                }
            }
        }

        // 每连接速率：10s 采样一次，用累计字节差分写进连接快照；诊断再打 top-N。
        if last_rate_sample.elapsed() >= Duration::from_secs(10) {
            last_rate_sample = Instant::now();
            let secs = 10.0f64;
            let mut top: Vec<(u64, u64, &'static str)> = Vec::new();
            let mut table = ctx
                .conns
                .write()
                .unwrap_or_else(|p| p.into_inner());
            for conn in conns.iter_mut() {
                let Some(id) = conn.snap else { continue };
                let Some(m) = conn.meter.as_ref() else { continue };
                let up = m.up.load(Ordering::Relaxed);
                let down = m.down.load(Ordering::Relaxed);
                let up_bps = ((up.saturating_sub(conn.rate_prev_up)) as f64 / secs) as u64;
                let down_bps = ((down.saturating_sub(conn.rate_prev_down)) as f64 / secs) as u64;
                conn.rate_prev_up = up;
                conn.rate_prev_down = down;
                table.set_rates(id, up_bps, down_bps);
                if down_bps > 0 {
                    // 档位标签：诊断时要能一眼看出这条流是不是被降到了 128K。
                    let tier = if sockets
                        .get::<tcp::Socket>(conn.handle)
                        .recv_capacity()
                        >= TCP_SOCKET_BUFFER
                    {
                        "512K"
                    } else {
                        "128K"
                    };
                    top.push((id, down_bps, tier));
                }
            }
            drop(table);
            top.sort_by(|a, b| b.1.cmp(&a.1));
            if !top.is_empty() {
                logging::info(
                    "tun",
                    format!(
                        "连接速率 top{}：{}",
                        top.len().min(5),
                        top.iter()
                            .take(5)
                            .map(|(id, bps, tier)| format!("#{} {} {}KB/s", id, tier, bps / 1024))
                            .collect::<Vec<_>>()
                            .join(" · ")
                    ),
                );
            }
        }

        // 协作让出②：连接遍历（最重的一段）之后，拨号/DNS 任务插队执行。
        tokio::task::yield_now().await;

        // UDP 客户端 -> 远端：从每个目标地址的 smoltcp socket 收取数据
        {
            let mut incoming: Vec<(IpEndpoint, IpEndpoint, Vec<u8>)> = Vec::new();
            for (dst_key, (handle, _)) in udp_dsts.iter() {
                let s = sockets.get_mut::<udp::Socket>(*handle);
                while s.can_recv() {
                    let mut buf = vec![0u8; 4096];
                    match s.recv_slice(&mut buf) {
                        Ok((n, meta)) => {
                            buf.truncate(n);
                            incoming.push((
                                IpEndpoint::new(dst_key.0, dst_key.1),
                                meta.endpoint,
                                buf,
                            ));
                        }
                        Err(_) => break,
                    }
                }
            }
            let mut dead_udp: Vec<(IpAddress, u16, IpAddress, u16)> = Vec::new();
            for (dst, client, data) in incoming {
                let key = (client.addr, client.port, dst.addr, dst.port);
                let domain = ctx
                    .dns()
                    .reverse
                    .lock()
                    .ok()
                    .and_then(|m| m.lookup(IpAddr::from(dst.addr)));
                let target = Target {
                    ip: IpAddr::from(dst.addr),
                    port: dst.port,
                    domain,
                };
                if let Some(sess) = udp_clients.get_mut(&key) {
                    sess.last = Instant::now();
                    match sess.tx.try_send((target, data)) {
                        Ok(_) => {}
                        // 队列满只是瞬时背压，等下一包；通道关闭才是代理会话已经结束。
                        Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => dead_udp.push(key),
                    }
                }
            }
            // 代理任务退出后立刻移除，后续包会重建会话；否则要等 180s 空闲清扫，
            // 中途所有 UDP（QUIC/游戏/语音）都会被静默丢掉。
            for key in dead_udp {
                udp_clients.remove(&key);
            }
        }

        // 远端 -> UDP 客户端：把响应写回透明 UDP socket（源地址保持为远端地址）
        while let Ok((client, remote, data)) = udp_resp_rx.try_recv() {
            let dst_key = (remote.addr, remote.port);
            if !udp_dsts.contains_key(&dst_key) {
                if udp_dsts.len() >= 1024 {
                    if let Some(oldest) = udp_dsts.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| *k) {
                        if let Some((h, _)) = udp_dsts.remove(&oldest) {
                            let _ = sockets.remove(h);
                        }
                    }
                }
                if let Some(h) = add_udp_dst_socket(&mut sockets, remote.addr, remote.port) {
                    udp_dsts.insert(dst_key, (h, Instant::now()));
                } else {
                    continue;
                }
            }
            if let Some((handle, _)) = udp_dsts.get(&dst_key) {
                let s = sockets.get_mut::<udp::Socket>(*handle);
                if s.can_send() {
                    if s.send_slice(&data, IpEndpoint::new(client.addr, client.port)).is_ok() {
                        continue;
                    }
                }
            }
            if udp_replies.len() < 512 {
                udp_replies.push_back((remote, client, data));
            }
        }
        while let Some((remote, client, data)) = udp_replies.front() {
            let dst_key = (remote.addr, remote.port);
            match udp_dsts.get(&dst_key) {
                Some((handle, _)) => {
                    let s = sockets.get_mut::<udp::Socket>(*handle);
                    if s.can_send() {
                        if s.send_slice(data, IpEndpoint::new(client.addr, client.port)).is_ok() {
                            udp_replies.pop_front();
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                None => {
                    udp_replies.pop_front();
                }
            }
        }

        // 定期回收闲置监听器 / UDP 会话，避免长期运行累积 socket
        if last_sweep.elapsed() >= Duration::from_secs(10) {
            // 熔断表清陈旧：冷却结束超过 5 分钟且无新失败的条目丢弃，
            // 保留近期条目以便再次失败时继续升级冷却。
            dial_breaker_sweep(&mut dial_fails.lock().unwrap_or_else(|p| p.into_inner()));
            last_sweep = Instant::now();
            let now_i = Instant::now();

            // QUIC 假活判定：探测窗口内一次回包都没有 → 判黑洞，压制一段时间。
            if ctx
                .cfg
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .quic_fallback
            {
                let mut judged: Vec<(IpAddress, u16)> = Vec::new();
                let mut idle: Vec<(IpAddress, u16)> = Vec::new();
                for (key, (first, last, saw_down)) in quic_probe.iter() {
                    if now_i.duration_since(*last) >= Duration::from_millis(QUIC_PROBE_WAIT_MS) {
                        // 已经静默了：纯空闲会话不判死，只丢掉探测记录，下次上行重新计时。
                        idle.push(*key);
                    } else if !saw_down
                        && now_i.duration_since(*first)
                            >= Duration::from_millis(QUIC_HANDSHAKE_WAIT_MS)
                    {
                        // 窗口内一直有上行、却从头到尾没见过任何下行 = 握手无回包 → 判黑洞。
                        // 已建立流（saw_down）豁免：纯上传阶段（同步/备份/上报）本来就没有
                        // 下行，判死会把健康 QUIC 白拆成 TCP。
                        judged.push(*key);
                    }
                }
                for key in idle {
                    quic_probe.remove(&key);
                }
                for key in judged {
                    quic_probe.remove(&key);
                    if !quic_blackhole.contains_key(&key) {
                        quic_blackhole.insert(key, now_i);
                        ctx.stats.quic_blackholed.fetch_add(1, Ordering::Relaxed);
                        logging::warn(
                            "tun",
                            format!(
                                "QUIC 握手无回包：{}:{} 持续 {}ms 有上行但无任何下行回包（握手未完成），{}s 内丢弃它的 QUIC 让客户端回落 TCP；已建立流豁免此判定",
                                key.0, key.1, QUIC_HANDSHAKE_WAIT_MS, QUIC_BLACKHOLE_TTL_SECS
                            ),
                        );
                    }
                }
                // 过期黑洞重新试探。
                let expired: Vec<(IpAddress, u16)> = quic_blackhole
                    .iter()
                    .filter(|(_, t)| now_i.duration_since(**t) >= Duration::from_secs(QUIC_BLACKHOLE_TTL_SECS))
                    .map(|(k, _)| *k)
                    .collect();
                for key in expired {
                    quic_blackhole.remove(&key);
                }
            }

            // 诊断口径：真实大档占用（分配/释放处维护），不再用 min(socket 总数,128)
            // 代理——总数含 listener/降级档/关闭中，既虚占名额也骗仪表。
            // 必须放在 QUIC 开关之外——否则关掉 QUIC 回落，这个仪表就冻住了。
            ctx.stats.big_tier_in_use.store(
                BIG_TIER_IN_USE.load(Ordering::Relaxed) as i64,
                Ordering::Relaxed,
            );

            // TCP 空闲/僵尸连接回收。对端静默死亡时 keepalive + smoltcp timeout 会先
            // abort；这里兜「还能回 ACK、但长时间没有任何业务数据」的僵尸连接。
            // 有堆积（慢速传输中）或已在关闭流程的连接不动，避免误杀。
            let mut reap: Vec<usize> = Vec::new();
            for (idx, conn) in conns.iter().enumerate() {
                let busy = !conn.pending.is_empty() || !conn.from_relay.is_empty();
                if should_reap_idle(
                    now_i.saturating_duration_since(conn.last_active),
                    busy,
                    conn.closing,
                ) {
                    reap.push(idx);
                }
            }
            if !reap.is_empty() {
                let mut removed = 0i64;
                for idx in reap.into_iter().rev() {
                    let conn = conns.swap_remove(idx);
                    ctx.conns
                        .write()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(conn.snap);
                    let idle_secs = now_i
                        .saturating_duration_since(conn.last_active)
                        .as_secs();
                    let ep = sockets
                        .get::<tcp::Socket>(conn.handle)
                        .remote_endpoint()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "-".into());
                    release_tcp_socket(&mut sockets, conn.handle);
                    ctx.stats.tcp_idle_reaped.fetch_add(1, Ordering::Relaxed);
                    removed += 1;
                    logging::info(
                        "tun",
                        format!("空闲回收 TCP 连接 {}（空闲 {}s）", ep, idle_secs),
                    );
                }
                ctx.stats.active_conns.fetch_sub(removed, Ordering::Relaxed);
            }

            let expired_udp: Vec<(IpAddress, u16, IpAddress, u16)> = udp_clients
                .iter()
                .filter(|(_, c)| now_i.duration_since(c.last) > Duration::from_secs(180))
                .map(|(k, _)| *k)
                .collect();
            for key in expired_udp {
                udp_clients.remove(&key);
            }

            let expired_dst: Vec<(IpAddress, u16)> = udp_dsts
                .iter()
                .filter(|(_, (h, t))| {
                    let s = sockets.get::<udp::Socket>(*h);
                    (s.can_recv() == false && s.can_send() == false)
                        && now_i.duration_since(*t) > Duration::from_secs(90)
                })
                .map(|(k, _)| *k)
                .collect();
            for key in expired_dst {
                if let Some((h, _)) = udp_dsts.remove(&key) {
                    let _ = sockets.remove(h);
                }
            }

            let expired_dns_dst: Vec<(IpAddress, u16)> = dns_udp_dsts
                .iter()
                .filter(|(_, (h, t))| {
                    let s = sockets.get::<udp::Socket>(*h);
                    (s.can_recv() == false && s.can_send() == false)
                        && now_i.duration_since(*t) > Duration::from_secs(90)
                })
                .map(|(k, _)| *k)
                .collect();
            for key in expired_dns_dst {
                if let Some((h, _)) = dns_udp_dsts.remove(&key) {
                    let _ = sockets.remove(h);
                }
            }

            let mut expired_listeners: Vec<((IpAddress, u16), SocketHandle)> = Vec::new();
            for (key, v) in listeners.iter() {
                for (handle, created) in v {
                    let listening = sockets.get::<tcp::Socket>(*handle).state() == tcp::State::Listen;
                    if listening && now_i.duration_since(*created) > Duration::from_secs(25) {
                        expired_listeners.push((*key, *handle));
                    }
                }
            }
            let total_listeners: usize = listeners.values().map(|v| v.len()).sum();
            if total_listeners > 1200 {
                let mut olds: Vec<((IpAddress, u16), SocketHandle, Instant)> = Vec::new();
                for (key, v) in listeners.iter() {
                    for (handle, created) in v {
                        if sockets.get::<tcp::Socket>(*handle).state() == tcp::State::Listen {
                            olds.push((*key, *handle, *created));
                        }
                    }
                }
                olds.sort_by_key(|(_, _, c)| *c);
                let need = total_listeners.saturating_sub(1200);
                for (key, handle, _) in olds.into_iter().take(need) {
                    expired_listeners.push((key, handle));
                }
            }
            for (key, handle) in expired_listeners {
                let mut empty = false;
                if let Some(v) = listeners.get_mut(&key) {
                    if let Some(pos) = v.iter().position(|(h, _)| *h == handle) {
                        let (h, _) = v.remove(pos);
                        release_tcp_socket(&mut sockets, h);
                    }
                    empty = v.is_empty();
                }
                if empty {
                    listeners.remove(&key);
                }
            }
        }

        // DNS UDP：固定 10.10.10.53/fd00:1::53 + 任意目的地址的动态 :53 socket
        {
            let mut queries: Vec<(SocketHandle, IpEndpoint, Vec<u8>)> = Vec::new();
            for handle in [dns4_handle, dns6_handle] {
                let s = sockets.get_mut::<udp::Socket>(handle);
                while s.can_recv() {
                    let mut buf = vec![0u8; 2048];
                    match s.recv_slice(&mut buf) {
                        Ok((n, meta)) => {
                            buf.truncate(n);
                            queries.push((handle, meta.endpoint, buf));
                        }
                        Err(_) => break,
                    }
                }
            }
            for (_, (handle, last)) in dns_udp_dsts.iter_mut() {
                let s = sockets.get_mut::<udp::Socket>(*handle);
                let mut got = false;
                while s.can_recv() {
                    let mut buf = vec![0u8; 2048];
                    match s.recv_slice(&mut buf) {
                        Ok((n, meta)) => {
                            buf.truncate(n);
                            queries.push((*handle, meta.endpoint, buf));
                            got = true;
                        }
                        Err(_) => break,
                    }
                }
                if got {
                    *last = Instant::now();
                }
            }
            for (handle, endpoint, buf) in queries {
                let dns = ctx.dns.read().unwrap_or_else(|p| p.into_inner()).clone();
                let tx = dns_tx.clone();
                tokio::spawn(async move {
                    if let Some(resp) = dns.resolve(&buf).await {
                        // UDP 客户端按自身 EDNS 大小收包，超长回 TC 让客户端走 TCP
                        let resp = crate::dns::fit_udp_response(&buf, resp);
                        let _ = tx.send((handle, endpoint, resp)).await;
                    }
                });
            }
        }
        loop {
            if dns_pending.len() >= 256 {
                break;
            }
            match dns_rx.try_recv() {
                Ok((handle, ep, data)) => dns_pending.push_back((handle, ep, data)),
                Err(_) => break,
            }
        }
        while let Some((handle, ep, data)) = dns_pending.front() {
            let s = sockets.get_mut::<udp::Socket>(*handle);
            if s.can_send() {
                if s.send_slice(data, *ep).is_ok() {
                    dns_pending.pop_front();
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // 发送到 TUN
        let _ = iface.poll(smol_now(start), &mut device, &mut sockets);
        if pending_out.len() < device.pending_cap {
            let room = device.pending_cap - pending_out.len();
            device.drain_tx_into(&mut pending_out, room);
        }
        note_pending_out(&pending_out, &ctx.stats);
        let mut tx_written = 0usize;
        while let Some(pkt) = pending_out.pop_front() {
            match write_tun(async_fd.get_ref().as_raw_fd(), &pkt) {
                Ok(_) => {
                    ctx.stats.down_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    device.recycle_tx(pkt);
                    write_blocked = false;
                    tx_written += 1;
                    // 每轮封顶：剩余包留在 pending_out，等待逻辑见其非空即 1ms 兜底，
                    // 吞吐不降，但单轮时长有界，拨号/DNS 不再被长轮压住。
                    if tx_written >= device.write_burst {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ctx.stats.tun_write_would_block.fetch_add(1, Ordering::Relaxed);
                    pending_out.push_front(pkt);
                    write_blocked = true;
                    break;
                }
                Err(e) => {
                    ctx.stats.tun_write_error.fetch_add(1, Ordering::Relaxed);
                    logging::warn("tun", format!("写入失败: {}", e));
                    device.recycle_tx(pkt);
                    write_blocked = false;
                    break;
                }
            }
        }
        // 协作让出③：TX 写出后让出，本轮结束前再给其他任务一次机会。
        tokio::task::yield_now().await;
    }

    logging::info("tun", "协议栈已停止");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_stats() -> Arc<Stats> {
        Arc::new(Stats::new())
    }

    #[test]
    fn http_probe_gets_local_answer() {
        // Android/ROM 的 generate_204 探测：本地回 204
        let req = b"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nUser-Agent: dalvik\r\n\r\n";
        assert!(probe_http_response(req).unwrap().starts_with(b"HTTP/1.1 204"));
        let req2 = b"GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
        assert!(probe_http_response(req2).unwrap().starts_with(b"HTTP/1.1 204"));
        // Apple 探测：回 Success 页面
        let req3 = b"GET /hotspot-detect.html HTTP/1.0\r\nHost: captive.apple.com\r\n\r\n";
        let r3 = probe_http_response(req3).unwrap();
        assert!(r3.starts_with(b"HTTP/1.1 200"));
        assert!(r3.windows(7).any(|w| w == b"Success"));
        // 微软探测
        let req4 = b"GET /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\n\r\n";
        assert!(probe_http_response(req4).unwrap().windows(22).any(|w| w == b"Microsoft Connect Test"));
        // 正常路径 / 非探测域名：不代答，原样放行
        assert!(probe_http_response(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n").is_none());
        assert!(probe_http_response(b"GET /generate_204 HTTP/1.1\r\nHost: example.com\r\n\r\n").is_none());
        // 头部不完整 / 非明文 HTTP：不代答
        assert!(probe_http_response(b"GET /generate_204 HTTP/1.1\r\nHost: gstatic").is_none());
        assert!(probe_http_response(&[0x16, 0x03, 0x01, 0x00]).is_none());
    }

    #[test]
    fn probe_hosts_match_exactly() {
        assert!(is_probe_host("www.google.com"));
        assert!(is_probe_host("ConnectivityCheck.Gstatic.com."));
        assert!(is_probe_host("captive.apple.com"));
        // 精确匹配：不能把子串/相似域名误判成探测
        assert!(!is_probe_host("google.com"));
        assert!(!is_probe_host("evil-www.google.com"));
        assert!(!is_probe_host("www.google.com.attacker.cn"));
        assert!(!is_probe_host("gstatic.com"));
    }

    #[test]
    fn icmpv4_echo_request_gets_local_reply() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 1;
        pkt[12..16].copy_from_slice(&[10, 10, 10, 2]);
        pkt[16..20].copy_from_slice(&[1, 2, 3, 4]);
        let hc = inet_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&hc.to_be_bytes());
        pkt[20] = 8;
        pkt[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
        let ic = inet_checksum(&pkt[20..]);
        pkt[22..24].copy_from_slice(&ic.to_be_bytes());

        let reply = icmp_echo_reply(&pkt).expect("应生成本地应答");
        assert_eq!(reply[20], 0);
        assert_eq!(&reply[12..16], &[1, 2, 3, 4]);
        assert_eq!(&reply[16..20], &[10, 10, 10, 2]);
        assert_eq!(inet_checksum(&reply[..20]), 0);
        assert_eq!(inet_checksum(&reply[20..]), 0);
        assert_eq!(&reply[24..28], &pkt[24..28]);
        // echo reply、非 ICMP、截断报文都不代答
        assert!(icmp_echo_reply(&reply).is_none());
        let mut tcp = pkt.clone();
        tcp[9] = 6;
        assert!(icmp_echo_reply(&tcp).is_none());
        assert!(icmp_echo_reply(&pkt[..10]).is_none());
    }

    #[test]
    fn icmpv6_echo_request_gets_local_reply() {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt[6] = 58;
        pkt[7] = 64;
        pkt[8] = 0xfd;
        pkt[23] = 2;
        pkt[24] = 0x24;
        pkt[39] = 1;
        pkt[40] = 128;
        let mut sum = 0u32;
        for c in pkt[8..40].chunks(2) {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        sum += 8 + 58;
        for c in pkt[40..].chunks(2) {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        pkt[42..44].copy_from_slice(&(!(sum as u16)).to_be_bytes());

        let reply = icmp_echo_reply(&pkt).expect("应生成本地应答");
        assert_eq!(reply[40], 129);
        assert_eq!(&reply[8..24], &pkt[24..40]);
        assert_eq!(&reply[24..40], &pkt[8..24]);
        let mut sum = 0u32;
        for c in reply[8..40].chunks(2) {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        sum += 8 + 58;
        for c in reply[40..].chunks(2) {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF);
        assert!(icmp_echo_reply(&reply).is_none());
    }

    #[test]
    fn tcp_keepalive_and_timeout_plan() {
        // keepalive 必须明显早于运营商 NAT 的空闲映射回收（3~5 分钟）。
        assert!(TCP_KEEPALIVE_SECS <= 60);
        // 判死不能拖到默认 TCP 重传的十几分钟，也不能短到误杀慢速链路。
        assert!((120..=300).contains(&TCP_DEAD_TIMEOUT_SECS));
        // 空闲兜底要明显长于正常心跳间隔，避免误杀微信这类长连接。
        assert!(TCP_IDLE_REAP_SECS >= 1800);
        // 上限仍然保持 1024（每条连接 256K 缓冲），只是满了改为淘汰而不是拒绝。
        assert_eq!(MAX_TCP_CONNS, 1024);
        assert!(MAX_PENDING_ACCEPT < MAX_TCP_CONNS);
    }

    #[test]
    fn victim_rank_prefers_idle_and_oldest() {
        // 有堆积的连接排后面：正在传输的连接要优先保留。
        assert!(
            victim_rank(Duration::from_secs(60), false)
                < victim_rank(Duration::from_secs(0), true)
        );
        // 同为空闲时，越久没有业务数据越先淘汰。
        assert!(
            victim_rank(Duration::from_secs(600), false)
                < victim_rank(Duration::from_secs(60), false)
        );
        // 同为堆积时同样按空闲时间排序。
        assert!(
            victim_rank(Duration::from_secs(600), true)
                < victim_rank(Duration::from_secs(60), true)
        );
    }

    #[test]
    fn idle_reap_never_kills_busy_or_closing() {
        let over = Duration::from_secs(TCP_IDLE_REAP_SECS + 1);
        let under = Duration::from_secs(TCP_IDLE_REAP_SECS - 1);
        assert!(should_reap_idle(over, false, false));
        assert!(!should_reap_idle(over, true, false));
        assert!(!should_reap_idle(over, false, true));
        assert!(!should_reap_idle(under, false, false));
    }

    #[test]
    fn buffer_plan_uses_512k_tcp_and_memory_guard() {
        // recv 512K 保住上行突发闸门（窗口缩放 shift=3）；tx 大档 256K，
        // 本机腿亚毫秒 RTT 足够，下游突发吸收交给 pending 2MB＋滞回。
        assert_eq!(TCP_SOCKET_BUFFER, 512 * 1024);
        assert_eq!(TCP_SOCKET_BUFFER_TX, 256 * 1024);
        assert!(TCP_SOCKET_BUFFER_TX < TCP_SOCKET_BUFFER);
        // 水位守卫：大档只给当前并发前 128 条 socket，其余降级 128K。
        assert_eq!(TCP_SOCKET_BUFFER_MIN, 128 * 1024);
        assert!(TCP_BUFFER_HIGH_TIER_MAX >= 64);
        // 最坏内存：128×(512K+256K) + (1024-128)×256K ≈ 352MB 虚拟口径，
        // 远低于「裸提 1024 条全 512K 双向」的 1GB；惰性零页下 PSS 只随真实流量涨。
        assert!(
            TCP_BUFFER_HIGH_TIER_MAX * (TCP_SOCKET_BUFFER + TCP_SOCKET_BUFFER_TX)
                + (1024 - TCP_BUFFER_HIGH_TIER_MAX) * 2 * TCP_SOCKET_BUFFER_MIN
                <= 384 * 1024 * 1024
        );
        assert_eq!(MITM_DUPLEX_CAP, 128 * 1024);
        assert_eq!(DNS_TCP_DUPLEX_CAP, 64 * 1024);
    }

    #[test]
    fn quic_fallback_probe_window_is_sane() {
        // 探测窗口要覆盖蜂窝 RTT（太短会把正常 QUIC 误判成假活），也不能拖太久。
        assert!(QUIC_PROBE_WAIT_MS >= 1000);
        assert!(QUIC_PROBE_WAIT_MS <= 4000);
        // 握手无回包窗口必须比静默窗口长（覆盖 PTO 重传），又不至于拖到分钟级。
        assert!(QUIC_HANDSHAKE_WAIT_MS > QUIC_PROBE_WAIT_MS);
        assert!(QUIC_HANDSHAKE_WAIT_MS <= 10_000);
        // 黑洞有效期至少几分钟，否则客户端每轮都要重新踩一次假活。
        assert!(QUIC_BLACKHOLE_TTL_SECS >= 300);
    }

    #[test]
    fn latency_plan_caps_queueing_and_sniff_wait() {
        // 字节预算 ≈1MB：1500 档仍 512 包；巨帧 9000 档按字节换算，背压口径不漂移。
        assert_eq!(queue_caps(1500), (512, 512, 512));
        let (q, p, b) = queue_caps(9000);
        assert_eq!(q, p);
        assert_eq!(b, p);
        assert!(p >= 64);
        assert!(p * 9000 <= TUN_QUEUE_BYTES + 9000);
        // 首包等待不能回到 180ms：延迟探测类连接连上不发数据，等待即纯延迟。
        assert!(SNI_WAIT_MS <= 60);
    }

    #[test]
    fn relay_drain_is_event_driven_not_timer_bound() {
        // 出站数据必须由 Notify 唤醒，不能靠收紧兜底定时器去刷吞吐：
        // 兜底保持 20ms，挂着空闲长连接时不该被更密的定时器空转（那是纯耗电）。
        assert!(IDLE_SAFETY_WAIT_MS >= 20);
        // 单次唤醒搬够 512KB，漏唤醒时的最坏下限也不至于掉回 100Mbps 量级。
        const RELAY_CHUNK: usize = 16384;
        assert!(RELAY_DRAIN_BURST * RELAY_CHUNK >= 512 * 1024);
    }

    #[test]
    fn pending_cap_bounds_downstream_memory() {
        // 上限必须明显大于 smoltcp 缓冲（健康连接不受影响）：2MB = 4×recv / 8×tx，
        // 高 BDP 单流一次 RTT 抖动不会填满 pending 就停搬。
        assert!(TCP_PENDING_CAP >= 4 * TCP_SOCKET_BUFFER);
        assert!(TCP_PENDING_CAP <= 2 * 1024 * 1024);
        // 滞回恢复水位必须严格低于暂停水位，否则门槛处开/关振荡。
        assert!(TCP_PENDING_RESUME < TCP_PENDING_CAP);
        assert!(TCP_PENDING_RESUME >= TCP_SOCKET_BUFFER);
    }

    fn dummy_handle() -> SocketHandle {
        let mut sockets = SocketSet::new(vec![]);
        let s = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; 2048]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; 2048]),
        );
        sockets.add(s)
    }

    #[tokio::test]
    async fn drain_stops_at_pending_cap_and_wakes_relay() {
        let (stx, srx) = mpsc::channel::<Vec<u8>>(200);
        let mut conn = TcpConn {
            handle: dummy_handle(),
            snap: None,
            to_relay: None,
            from_relay: srx,
            pending: VecDeque::new(),
            pending_bytes: 0, relay_paused: false,
            read_wake: Arc::new(Notify::new()),
            relay_closed: false,
            client_closed: false,
            closing: false,
            last_active: Instant::now(),
            meter: None,
            recv_full: false,
            send_stall_since: None,
            send_stall_logged: false,
            rate_prev_up: 0,
            rate_prev_down: 0,
        };
        // 灌 2.24MB（140×16K），超过 2MB 上限；单轮最多搬 RELAY_DRAIN_BURST 块，
        // 循环搬到滞回暂停为止。
        for _ in 0..140 {
            stx.send(vec![7u8; 16384]).await.unwrap();
        }
        let mut moved = false;
        while drain_relay_to_pending(&mut conn) {
            moved = true;
        }
        assert!(moved);
        // 搬运在达到上限后停止：最多超出一个块（先检查后搬运）。
        assert!(conn.pending_bytes >= TCP_PENDING_CAP);
        assert!(conn.pending_bytes <= TCP_PENDING_CAP + 16384);
        assert!(conn.relay_paused);
        assert!(!conn.relay_closed);
        // 搬到数据必须唤醒 relay（permit 已存，立即就绪）。
        assert!(tokio::time::timeout(Duration::from_millis(50), conn.read_wake.notified())
            .await
            .is_ok());
        // 暂停期间继续搬运无效：通道里还有数据但 pending 未到低水位。
        assert!(!drain_relay_to_pending(&mut conn));
        // 滞回：只排空到 1.5MB（高于 1MB 恢复水位）不得恢复搬运，
        // 单阈值实现会在这里立刻恢复→门槛处振荡。
        while conn.pending_bytes > 1_500_000 {
            let f = conn.pending.pop_front().unwrap();
            conn.pending_bytes -= f.len();
        }
        assert!(!drain_relay_to_pending(&mut conn));
        assert!(conn.relay_paused);
        // 模拟发送 loop 把 pending 写进 smoltcp 排空到低水位以下，下一轮恢复搬运。
        conn.pending.clear();
        conn.pending_bytes = 0;
        assert!(drain_relay_to_pending(&mut conn));
        assert!(!conn.relay_paused);
        assert!(conn.pending_bytes > 0);
    }

    #[tokio::test]
    async fn relay_backpressure_keeps_upload_flowing() {
        // 下行通道满（客户端收不动）时，上传方向必须仍可写：
        // 旧实现阻塞在 send().await 会把 select 卡死，双向一起停摆。
        let (upstream, relay_end) = tokio::io::duplex(64 * 1024);
        let (ctx_tx, ctx_rx) = mpsc::channel::<Vec<u8>>(64);
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(2);
        let relay_wake = Arc::new(Notify::new());
        let read_wake = Arc::new(Notify::new());
        let h = tokio::spawn(relay_stream(
            Box::new(relay_end),
            ctx_rx,
            stx,
            relay_wake.clone(),
            read_wake.clone(),
        ));
        let (mut up_r, mut up_w) = tokio::io::split(upstream);
        // 上游猛灌 1MB，无人消费 srx → 通道满 + staged → relay 停读。
        tokio::spawn(async move {
            let data = vec![9u8; 16384];
            for _ in 0..64 {
                if up_w.write_all(&data).await.is_err() {
                    break;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        // 下行已背压，上传 PING 仍必须穿过 relay 到达上游。
        ctx_tx.send(b"PING".to_vec()).await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), up_r.read_exact(&mut buf))
            .await
            .expect("背压期间上传方向被卡死")
            .unwrap();
        assert_eq!(&buf, b"PING");
        // 主循环搬走数据并唤醒后，下行恢复流动。
        while srx.try_recv().is_ok() {}
        read_wake.notify_one();
        let got = tokio::time::timeout(Duration::from_secs(2), srx.recv())
            .await
            .expect("唤醒后下行未恢复");
        assert!(got.is_some());
        h.abort();
    }

    #[test]
    fn probe_hosts_cover_gms_background() {
        assert!(is_probe_host("firebaseinstallations.googleapis.com"));
        assert!(is_probe_host("checkin.gstatic.com"));
        assert!(is_probe_host("android.clients.google.com"));
        assert!(is_probe_host("mtalk.google.com"));
        assert!(is_probe_host("alt5-mtalk.google.com"));
        // 正常业务域名不能被探测清单误伤（清单是精确匹配，不含通配）。
        assert!(!is_probe_host("firebase.googleapis.com"));
        assert!(!is_probe_host("www.googleapis.com"));
        assert!(!is_probe_host("mtalk.google.com.example.com"));
    }

    #[test]
    fn dial_breaker_cooldown_escalates_and_caps() {
        assert_eq!(dial_cooldown(0), None);
        assert_eq!(dial_cooldown(1), None);
        assert_eq!(dial_cooldown(2), Some(Duration::from_secs(10)));
        assert_eq!(dial_cooldown(3), Some(Duration::from_secs(20)));
        assert_eq!(dial_cooldown(4), Some(Duration::from_secs(40)));
        assert_eq!(dial_cooldown(5), Some(Duration::from_secs(60)));
        assert_eq!(dial_cooldown(50), Some(Duration::from_secs(60)));
    }

    #[test]
    fn dial_breaker_record_active_clear() {
        let mut f = DialFails::default();
        let key = dial_key(None, IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)), 443);
        let now = Instant::now();
        // 首次失败：容忍，不冷却。
        assert!(!dial_breaker_record(&mut f, key.clone(), now));
        assert!(!dial_breaker_active(&f, &key, now));
        // 第二次连续失败：进入 10s 冷却。
        assert!(!dial_breaker_record(&mut f, key.clone(), now));
        assert!(dial_breaker_active(&f, &key, now));
        assert!(!dial_breaker_active(&f, &key, now + Duration::from_secs(11)));
        // 成功即清除：路径恢复后不再被熔断。
        dial_breaker_clear(&mut f, &key);
        assert!(!dial_breaker_active(&f, &key, now));
    }

    #[test]
    fn dial_breaker_key_isolates_cdn_domains_on_same_ip() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(104, 16, 1, 1));
        let mut f = DialFails::default();
        let now = Instant::now();
        let a = dial_key(Some("a.example.com"), ip, 443);
        let b = dial_key(Some("b.example.com"), ip, 443);
        let bare = dial_key(None, ip, 443);
        // 同一个 IP:443 上的 a 连续失败进入冷却，b 和裸 IP 连接都不能被连坐。
        dial_breaker_record(&mut f, a.clone(), now);
        dial_breaker_record(&mut f, a.clone(), now);
        assert!(dial_breaker_active(&f, &a, now));
        assert!(!dial_breaker_active(&f, &b, now));
        assert!(!dial_breaker_active(&f, &bare, now));
        // 同域名不同端口也是不同目标。
        assert!(!dial_breaker_active(&f, &dial_key(Some("a.example.com"), ip, 80), now));
        // 域名大小写归一：同一域名不因为大小写差异被当成两个目标。
        assert_eq!(
            dial_key(Some("A.Example.COM"), ip, 443),
            dial_key(Some("a.example.com"), ip, 443)
        );
    }

    #[test]
    fn dial_breaker_self_heals_when_link_fails() {
        let mut f = DialFails::default();
        let now = Instant::now();
        // 先让某个目标进入冷却。
        let victim = dial_key(None, IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 443);
        dial_breaker_record(&mut f, victim.clone(), now);
        dial_breaker_record(&mut f, victim.clone(), now);
        assert!(dial_breaker_active(&f, &victim, now));
        // 10s 窗口内不同目标接连失败（含上面的 victim，满 8 个即触发）：
        // 触发后进入暂停期，后续 record 返回 false，所以要累计「是否曾触发」。
        let mut healed = false;
        for i in 0..LINK_FAIL_DISTINCT_TARGETS {
            let k = dial_key(
                Some(&format!("host{}.example.com", i)),
                IpAddr::V4(std::net::Ipv4Addr::new(2, 2, 2, 2)),
                443,
            );
            healed = dial_breaker_record(&mut f, k, now) || healed;
        }
        assert!(healed, "多目标同时失败应触发链路自愈");
        // 自愈后：旧冷却被清空，暂停期内一律不熔断。
        assert!(!dial_breaker_active(&f, &victim, now));
        assert!(f.fails.is_empty());
        // 暂停期内的失败不累计（链路恢复中的失败不是目标的错）。
        assert!(!dial_breaker_record(&mut f, victim.clone(), now));
        assert!(!dial_breaker_active(&f, &victim, now));
        // 暂停期结束后恢复正常判定。
        let after = now + Duration::from_secs(LINK_SELF_HEAL_SUSPEND_SECS + 1);
        dial_breaker_record(&mut f, victim.clone(), after);
        dial_breaker_record(&mut f, victim.clone(), after);
        assert!(dial_breaker_active(&f, &victim, after));
    }

    #[test]
    fn suppressed_dial_keeps_real_failure_timing() {
        // 熔断抑制拨号后必须保持与真实拨号超时相同的失败时序：
        // 立即 RST 会让测速/探活 App 把「秒拒」当成另一种结果，污染延迟读数。
        assert_eq!(SUPPRESSED_DIAL_FAIL_SECS, 2);
        // 自愈判据必须明显严于「单个目标反复失败」，否则正常重试也会误触暂停。
        assert!(LINK_FAIL_DISTINCT_TARGETS >= 8);
        assert!(LINK_SELF_HEAL_SUSPEND_SECS >= 30);
    }

    #[test]
    fn tx_write_burst_bounds_round_length() {
        // 封顶必须不大于 pending_out 容量（否则上限无意义），
        // 又不能太小（单轮搬运量过低会抬高调度开销）；巨帧档同口径换算。
        for mtu in [1500, 9000] {
            let (q, p, b) = queue_caps(mtu);
            assert!(b <= p);
            assert!(b >= 64);
            assert_eq!(q, p);
        }
    }

    #[test]
    fn udp_dst_buffer_fits_real_quic_bursts() {
        // QUIC 包约 1400 字节；8192 的旧档只装得下 5 个包，而 UDP 满即丢。
        const QUIC_PKT: usize = 1400;
        assert!(UDP_DST_BUF / QUIC_PKT >= 20);
        // metadata 槽位不能先于缓冲耗尽，否则扩容缓冲毫无意义。
        assert!(UDP_META_SLOTS >= UDP_DST_BUF / QUIC_PKT);
    }

    #[test]
    fn tx_token_queue_full_counts_silent_drop() {
        let stats = test_stats();
        let tx = Arc::new(Mutex::new(
            (0..MAX_TX_QUEUE)
                .map(|_| vec![0u8; 4])
                .collect::<VecDeque<_>>(),
        ));
        let pool = Arc::new(Mutex::new(Vec::new()));
        let token = TunTxToken {
            tx: tx.clone(),
            pool: pool.clone(),
            cap: MAX_TX_QUEUE,
            stats: stats.clone(),
        };
        let len = token.consume(4, |buf| {
            buf[0] = 1;
            buf.len()
        });
        assert_eq!(len, 4);
        assert_eq!(
            tx.lock().unwrap_or_else(|p| p.into_inner()).len(),
            MAX_TX_QUEUE
        );
        assert_eq!(stats.tun_tx_drop.load(Ordering::Relaxed), 1);
        assert_eq!(stats.tun_pending_drop.load(Ordering::Relaxed), 0);
        assert_eq!(pool.lock().unwrap_or_else(|p| p.into_inner()).len(), 1);
    }

    #[test]
    fn tx_token_queue_below_limit_keeps_packet() {
        let stats = test_stats();
        let tx = Arc::new(Mutex::new(
            (0..MAX_TX_QUEUE - 1)
                .map(|_| vec![0u8; 4])
                .collect::<VecDeque<_>>(),
        ));
        let pool = Arc::new(Mutex::new(Vec::new()));
        let token = TunTxToken {
            tx: tx.clone(),
            pool,
            cap: MAX_TX_QUEUE,
            stats: stats.clone(),
        };
        let _ = token.consume(4, |buf| {
            buf.fill(2);
        });
        assert_eq!(
            tx.lock().unwrap_or_else(|p| p.into_inner()).len(),
            MAX_TX_QUEUE
        );
        assert_eq!(stats.tun_tx_drop.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn transmit_returns_none_at_tx_high_water() {
        let stats = test_stats();
        let mut device = TunDevice::new(1500, stats.clone());
        {
            let mut g = device.tx.lock().unwrap_or_else(|p| p.into_inner());
            for _ in 0..MAX_TX_QUEUE {
                g.push_back(vec![0u8; 4]);
            }
        }
        assert!(device.transmit(SmolInstant::from_millis(0)).is_none());
        assert_eq!(stats.tun_tx_backpressure.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn pending_out_peak_is_counted_without_truncation() {
        let stats = test_stats();
        let mut pending: VecDeque<Vec<u8>> = (0..MAX_PENDING_OUT + 7)
            .map(|i| vec![i as u8])
            .collect();
        note_pending_out(&pending, &stats);
        // 高水位是背压信号，不再截断 pending_out。
        assert_eq!(pending.len(), MAX_PENDING_OUT + 7);
        assert_eq!(
            stats.tun_pending_peak.load(Ordering::Relaxed),
            (MAX_PENDING_OUT + 7) as u64
        );
        assert_eq!(stats.tun_pending_drop.load(Ordering::Relaxed), 0);

        // 峰值只增不减；后续较短队列不应覆盖历史峰值。
        pending.truncate(3);
        note_pending_out(&pending, &stats);
        assert_eq!(
            stats.tun_pending_peak.load(Ordering::Relaxed),
            (MAX_PENDING_OUT + 7) as u64
        );
    }

    #[test]
    fn drain_tx_into_respects_remaining_room() {
        let stats = test_stats();
        let device = TunDevice::new(1500, stats);
        {
            let mut g = device.tx.lock().unwrap_or_else(|p| p.into_inner());
            for i in 0..5u8 {
                g.push_back(vec![i; 4]);
            }
        }
        let mut pending = VecDeque::new();
        device.drain_tx_into(&mut pending, 3);
        assert_eq!(pending.len(), 3);
        assert_eq!(
            device.tx.lock().unwrap_or_else(|p| p.into_inner()).len(),
            2
        );
    }
}
