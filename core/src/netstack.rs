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
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

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
    tx: Arc<Mutex<Vec<Vec<u8>>>>,
    mtu: usize,
}

struct TunRxToken(Vec<u8>);
struct TunTxToken {
    tx: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl TunDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::with_capacity(256),
            tx: Arc::new(Mutex::new(Vec::new())),
            mtu,
        }
    }
    fn take_tx(&self) -> Vec<Vec<u8>> {
        match self.tx.lock() {
            Ok(mut g) => g.drain(..).collect(),
            Err(p) => p.into_inner().drain(..).collect(),
        }
    }
}

impl Device for TunDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((TunRxToken(pkt), TunTxToken { tx: self.tx.clone() }))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken { tx: self.tx.clone() })
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
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut data = self.0;
        f(&mut data)
    }
}

impl TxToken for TunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        if let Ok(mut g) = self.tx.lock() {
            if g.len() < 256 {
                g.push(buf);
            }
        }
        r
    }
}

struct TcpConn {
    handle: SocketHandle,
    to_relay: Option<mpsc::Sender<Vec<u8>>>,
    from_relay: mpsc::Receiver<Vec<u8>>,
    pending: VecDeque<Vec<u8>>,
    relay_closed: bool,
    client_closed: bool,
    closing: bool,
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

fn read_tun(fd: RawFd) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 2048];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Ok(Vec::new());
    }
    buf.truncate(n as usize);
    Ok(buf)
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

fn add_listener(sockets: &mut SocketSet<'_>, addr: IpAddress, port: u16) -> Option<SocketHandle> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 32768]),
        tcp::SocketBuffer::new(vec![0u8; 32768]),
    );
    if socket
        .listen(IpListenEndpoint {
            addr: Some(addr),
            port,
        })
        .is_err()
    {
        return None;
    }
    Some(sockets.add(socket))
}

fn add_udp_dst_socket(
    sockets: &mut SocketSet<'_>,
    addr: IpAddress,
    port: u16,
) -> Option<SocketHandle> {
    let mut socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8192]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8192]),
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
    match node.kind.as_str() {
        "ss" => UdpMode::Ss(node),
        "socks5" => UdpMode::Socks5(node),
        other => UdpMode::Unsupported(format!("{} 节点暂不支持 UDP", other)),
    }
}

fn decide_action(
    ctx: &Ctx,
    domain: Option<&str>,
    ip: IpAddr,
    port: u16,
    kind: ConnKind,
) -> Action {
    // mihomo/sing-box 同款：853 是 DoT/DoQ，私人 DNS 开着时会绕过 53 劫持。
    // 直接拒绝，让 Android 的 opportunistic 模式回落到 VPN DNS。
    if port == 853 && ctx.block_dot() {
        ctx.stats.dot_blocked.fetch_add(1, Ordering::Relaxed);
        return Action::Block;
    }
    let mut action = match ctx.mode().as_str() {
        "global" => Action::Proxy,
        "dns_only" => Action::Direct,
        _ => ctx.rules.read().unwrap_or_else(|p| p.into_inner()).decide(domain, ip, port, kind),
    };
    // 策略组只在规则/最终策略真正引用它时展开；global 模式仍走当前选中节点。
    if let Action::Group(name) = action.clone() {
        action = resolve_group_action(ctx, &name, kind, domain);
    }
    if let Action::Missing(name) = &action {
        logging::warn(
            "strategy",
            format!("规则引用的目标已失效：{}；按拦截处理，不回落到当前选中节点", name),
        );
        return Action::Block;
    }
    if let Action::Node(name) = &action {
        if !ctx.nodes_snapshot().iter().any(|n| &n.name == name) {
            logging::warn(
                "strategy",
                format!("节点已不存在：{}；按拦截处理，不回落到当前选中节点", name),
            );
            return Action::Block;
        }
    }
    if matches!(action, Action::Proxy) && ctx.nodes_snapshot().is_empty() {
        action = if ctx.block_when_no_node() {
            Action::Block
        } else {
            Action::Direct
        };
    }
    action
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
) {
    let (mut r, mut w) = tokio::io::split(stream);
    let mut buf = vec![0u8; 16384];
    // 半关闭语义：客户端停止发送（channel 关闭）只关出站写侧，
    // 服务端方向的响应必须继续读完，否则半关闭客户端会丢响应。
    let mut client_done = false;
    loop {
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
            res = r.read(&mut buf) => {
                match res {
                    Ok(0) => break,
                    Ok(n) => {
                        if server_tx.send(buf[..n].to_vec()).await.is_err() { break; }
                    }
                    Err(_) => break,
                }
            }
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

    let mut device = TunDevice::new(1500);
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

    let mut listeners: HashMap<(IpAddress, u16), (SocketHandle, Instant)> = HashMap::new();
    let mut pending_accept: Vec<(IpAddress, u16, SocketHandle, Instant)> = Vec::new();
    let mut conns: Vec<TcpConn> = Vec::new();

    let mut udp_dsts: HashMap<(IpAddress, u16), (SocketHandle, Instant)> = HashMap::new();
    let mut udp_clients: HashMap<(IpAddress, u16, IpAddress, u16), UdpClient> = HashMap::new();
    let (udp_resp_tx, mut udp_resp_rx) = mpsc::channel::<(IpEndpoint, IpEndpoint, Vec<u8>)>(256);
    let mut udp_replies: VecDeque<(IpEndpoint, IpEndpoint, Vec<u8>)> = VecDeque::new();

    let mut pending_out: VecDeque<Vec<u8>> = VecDeque::new();
    let mut last_sweep = Instant::now();
    let start = Instant::now();

    logging::info(
        "tun",
        "用户态协议栈已启动 (10.10.10.1/24, fd00:1::1/64, DNS 10.10.10.53 + fd00:1::53)",
    );

    loop {
        if ctx.shutdown.load(Ordering::Relaxed) {
            break;
        }

        // 空闲时降低唤醒频率；有活动连接时保持较低调度延迟。新报文到达会立即唤醒 AsyncFd。
        let idle = conns.is_empty() && udp_clients.is_empty();
        let wait = if idle {
            Duration::from_millis(250)
        } else {
            Duration::from_millis(20)
        };
        // 事件驱动：TUN 可读、UDP 响应、DNS 响应任一到达即唤醒；空闲时仅保留兜底定时器。
        let mut guard = None;
        tokio::select! {
            r = async_fd.readable() => {
                if let Ok(g) = r {
                    guard = Some(g);
                }
            }
            r = udp_resp_rx.recv() => {
                if let Some((client, remote, data)) = r {
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
            _ = tokio::time::sleep(wait) => {}
        }

        if let Some(g) = guard.as_mut() {
            let mut rounds = 0;
            loop {
                rounds += 1;
                if rounds > 64 {
                    break;
                }
                let r = g.try_io(|inner| read_tun(inner.get_ref().as_raw_fd()));
                match r {
                    Ok(Ok(pkt)) => {
                        if pkt.is_empty() {
                            break;
                        }
                        ctx.stats
                            .up_bytes
                            .fetch_add(pkt.len() as u64, Ordering::Relaxed);
                        if let Some((port, addr)) = lookup_tcp_dst(&pkt) {
                            if !listeners.contains_key(&(addr, port)) {
                                if let Some(h) = add_listener(&mut sockets, addr, port) {
                                    listeners.insert((addr, port), (h, Instant::now()));
                                }
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
                                let action = decide_action(
                                    &ctx,
                                    domain.as_deref(),
                                    IpAddr::from(dst.addr),
                                    dst.port,
                                    ConnKind::Udp,
                                );
                                let mode = udp_mode(&ctx, &action);
                                drop(decision_guard);
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
                    Ok(Err(e)) => {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            logging::warn("tun", format!("读取失败: {}", e));
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
        }

        let now = smol_now(start);
        let _ = iface.poll(now, &mut device, &mut sockets);

        // TCP 监听器 -> 已建立连接
        let mut lost: Vec<(IpAddress, u16)> = Vec::new();
        let mut accepted: Vec<(IpAddress, u16, SocketHandle, Instant)> = Vec::new();
        for (key, (handle, _)) in listeners.iter() {
            let state = sockets.get::<tcp::Socket>(*handle).state();
            if state != tcp::State::Listen {
                lost.push(*key);
                accepted.push((key.0, key.1, *handle, Instant::now()));
            }
        }
        for key in lost {
            listeners.remove(&key);
        }
        for (addr, port, handle, accepted_at) in accepted {
            pending_accept.push((addr, port, handle, accepted_at));
        }
        // 保证每个已消费的端口仍有监听器（后续新连接）
        let mut new_listeners: Vec<(IpAddress, u16, SocketHandle)> = Vec::new();
        for (addr, port, h, _) in pending_accept.iter() {
            if sockets.get::<tcp::Socket>(*h).state() == tcp::State::Established
                && !listeners.contains_key(&(*addr, *port))
            {
                if let Some(nh) = add_listener(&mut sockets, *addr, *port) {
                    new_listeners.push((*addr, *port, nh));
                }
            }
        }
        for (addr, port, h) in new_listeners {
            listeners.insert((addr, port), (h, Instant::now()));
        }

        // 新连接建立
        let mut still_pending = Vec::new();
        for (addr, port, handle, accepted_at) in pending_accept.into_iter() {
            let state = sockets.get::<tcp::Socket>(handle).state();
            match state {
                tcp::State::Established => {
                    // 连接总数上限：每条连接带协议栈缓冲与中继任务，
                    // 高并发下宁可拒绝新连接，也不能让内存无界增长。
                    if conns.len() >= 1024 {
                        logging::warn("tun", "并发连接达到上限(1024)，拒绝新连接");
                        let _ = sockets.remove(handle);
                        continue;
                    }
                    let remote = sockets.get::<tcp::Socket>(handle).remote_endpoint();
                    let local_ip = IpAddr::from(addr);
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
                        // 最多等 180ms，避免 Server-first 协议被长时间卡住。
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
                        if (domain.is_none() || (port == 443 && sni.is_none()))
                            && accepted_at.elapsed() < Duration::from_millis(180)
                            && (n == 0 || may_be_tls)
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
                    let action = if dns_conn {
                        Action::Direct
                    } else {
                        decide_action(
                            &ctx,
                            route_domain.as_deref(),
                            local_ip,
                            port,
                            ConnKind::Tcp,
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
                        sockets.get_mut::<tcp::Socket>(handle).abort();
                        let _ = sockets.remove(handle);
                        continue;
                    }
                    // MITM：SNI/反向映射命中域名列表的 443 连接改走本地 TLS 终止 + 规则改写。
                    let mitm_state = ctx.mitm();
                    let mitm_hit = !dns_conn
                        && port == 443
                        && mitm_host
                            .as_deref()
                            .map(|d| mitm_state.should_mitm(d))
                            .unwrap_or(false);
                    if mitm_hit {
                        let (a, b) = tokio::io::duplex(64 * 1024);
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
                        tokio::spawn(relay_stream(Box::new(b), rx, stx));
                        conns.push(TcpConn {
                            handle,
                            to_relay: Some(tx),
                            from_relay: srx,
                            pending: VecDeque::new(),
                            relay_closed: false,
                            client_closed: false,
                            closing: false,
                        });
                        ctx.stats.active_conns.fetch_add(1, Ordering::Relaxed);
                        ctx.stats.total_conns.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if dns_conn {
                        let (a, b) = tokio::io::duplex(64 * 1024);
                        let dns = ctx.dns.read().unwrap_or_else(|p| p.into_inner()).clone();
                        tokio::spawn(dns_tcp_server(dns, a));
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                        let (stx, srx) = mpsc::channel::<Vec<u8>>(64);
                        tokio::spawn(relay_stream(Box::new(b), rx, stx));
                        conns.push(TcpConn {
                            handle,
                            to_relay: Some(tx),
                            from_relay: srx,
                            pending: VecDeque::new(),
                            relay_closed: false,
                            client_closed: false,
                            closing: false,
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
                        tokio::spawn(async move {
                            let result = outbound::connect(&action2, &nodes, selected.as_deref(), target, Some(&dns)).await;
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
                                Ok(stream) => relay_stream(stream, rx, stx).await,
                                Err(e) => {
                                    logging::warn(
                                        "conn",
                                        format!(
                                            "#{} 连接失败 {}:{} [{}] 耗时 {}ms: {}",
                                            conn_id,
                                            target_label2,
                                            port,
                                            action_label2,
                                            accepted_at.elapsed().as_millis(),
                                            e
                                        ),
                                    );
                                    drop(stx);
                                }
                            }
                        });
                        conns.push(TcpConn {
                            handle,
                            to_relay: Some(tx),
                            from_relay: srx,
                            pending: VecDeque::new(),
                            relay_closed: false,
                            client_closed: false,
                            closing: false,
                        });
                        ctx.stats.active_conns.fetch_add(1, Ordering::Relaxed);
                        ctx.stats.total_conns.fetch_add(1, Ordering::Relaxed);
                    }
                }
                tcp::State::Closed => {
                    let _ = sockets.remove(handle);
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
        for (idx, conn) in conns.iter_mut().enumerate() {
            let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
            if sock.state() == tcp::State::Closed {
                dead.push(idx);
                continue;
            }

            while sock.can_recv() && conn.to_relay.as_ref().map(|t| t.capacity() > 0).unwrap_or(false) {
                match sock.recv_slice(&mut tcp_scratch) {
                    Ok(n) if n > 0 => {
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

            loop {
                match conn.from_relay.try_recv() {
                    Ok(data) => {
                        conn.pending.push_back(data);
                        if conn.pending.len() >= 16 {
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
            while sock.can_send() {
                match conn.pending.front_mut() {
                    Some(front) => match sock.send_slice(front) {
                        Ok(n) if n == front.len() => {
                            conn.pending.pop_front();
                        }
                        Ok(n) => {
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
            }
        }
        if !dead.is_empty() {
            let mut removed = 0i64;
            for idx in dead.into_iter().rev() {
                let conn = conns.swap_remove(idx);
                let _ = sockets.remove(conn.handle);
                removed += 1;
            }
            ctx.stats.active_conns.fetch_sub(removed, Ordering::Relaxed);
        }

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
                    let _ = sess.tx.try_send((target, data));
                }
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
            last_sweep = Instant::now();
            let now_i = Instant::now();

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

            let mut expired_listeners: Vec<(IpAddress, u16)> = Vec::new();
            for (key, (handle, created)) in listeners.iter() {
                let listening = sockets.get::<tcp::Socket>(*handle).state() == tcp::State::Listen;
                if listening && now_i.duration_since(*created) > Duration::from_secs(25) {
                    expired_listeners.push(*key);
                }
            }
            if listeners.len() > 1200 {
                let mut olds: Vec<((IpAddress, u16), Instant)> = listeners
                    .iter()
                    .filter(|(_, (h, _))| sockets.get::<tcp::Socket>(*h).state() == tcp::State::Listen)
                    .map(|(k, (_, c))| (*k, *c))
                    .collect();
                olds.sort_by_key(|(_, c)| *c);
                let need = listeners.len().saturating_sub(1200);
                for (key, _) in olds.into_iter().take(need) {
                    expired_listeners.push(key);
                }
            }
            for key in expired_listeners {
                if let Some((handle, _)) = listeners.remove(&key) {
                    let _ = sockets.remove(handle);
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
        for pkt in device.take_tx() {
            pending_out.push_back(pkt);
        }
        while let Some(pkt) = pending_out.pop_front() {
            match write_tun(async_fd.get_ref().as_raw_fd(), &pkt) {
                Ok(_) => {
                    ctx.stats.down_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    pending_out.push_front(pkt);
                    break;
                }
                Err(e) => {
                    logging::warn("tun", format!("写入失败: {}", e));
                    break;
                }
            }
        }
        if pending_out.len() > 512 {
            pending_out.truncate(512);
        }
    }

    logging::info("tun", "协议栈已停止");
    Ok(())
}
