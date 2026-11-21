use crate::config::{Node, Target};
use crate::dns::DnsEngine;
use crate::outbound;
use crate::outbound::io_err;
use crate::proto::ss::SsUdpCipher;
use crate::proto::{socks, trojan, vless};
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[derive(Clone)]
pub enum UdpMode {
    Direct,
    Ss(Node),
    Socks5(Node),
    /// Trojan UDP ASSOCIATE：报文结构与 SOCKS5 一致，走 TCP/TLS 隧道。
    Trojan(Node),
    /// VLESS UDP：请求头带目标地址，双向 [2 字节长度][载荷] 分帧。
    Vless(Node),
    Unsupported(String),
}

/// 带上限的映射表：满了按插入顺序淘汰最旧一条，绝不整表清空。
/// 整表清空会把所有活跃 QUIC/语音流的回包映射瞬间丢光，
/// 回包因源地址不匹配被内核丢弃，表现为一阵突发丢包/卡顿。
struct BoundedMap<K: std::hash::Hash + Eq + Clone, V> {
    map: HashMap<K, V>,
    order: std::collections::VecDeque<K>,
    cap: usize,
}

impl<K: std::hash::Hash + Eq + Clone, V> BoundedMap<K, V> {
    fn new(cap: usize) -> Self {
        Self { map: HashMap::new(), order: std::collections::VecDeque::new(), cap }
    }

    fn insert(&mut self, k: K, v: V) {
        if !self.map.contains_key(&k) {
            if self.map.len() >= self.cap {
                // order 里可能有已失效的旧键（重复插入不重排），跳过直到真正删掉一条。
                while let Some(old) = self.order.pop_front() {
                    if self.map.remove(&old).is_some() {
                        break;
                    }
                }
            }
            self.order.push_back(k.clone());
        }
        self.map.insert(k, v);
    }

    fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// 单个客户端源端口的 UDP 会话：Direct 为全锥 NAT；SS/SOCKS5/Trojan/VLESS 把报文封装到代理。
pub async fn run(
    client: IpEndpoint,
    mode: UdpMode,
    rx: mpsc::Receiver<(Target, Vec<u8>)>,
    resp: mpsc::Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
    dns: Arc<DnsEngine>,
) {
    match mode {
        UdpMode::Direct => direct(client, rx, resp, dns).await,
        UdpMode::Ss(node) => ss_udp(client, node, rx, resp).await,
        UdpMode::Socks5(node) => socks_udp(client, node, rx, resp).await,
        UdpMode::Trojan(node) => trojan_udp(client, node, rx, resp).await,
        UdpMode::Vless(node) => vless_udp(client, node, rx, resp).await,
        UdpMode::Unsupported(reason) => {
            crate::logging::warn("udp", format!("UDP 未转发: {}", reason));
        }
    }
}

fn unspecified(addr: IpAddress) -> SocketAddr {
    match addr {
        IpAddress::Ipv4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        IpAddress::Ipv6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn target_key(target: &Target) -> String {
    match target.domain.as_deref() {
        Some(d) => format!("{}|{}", d, target.port),
        None => format!("{}|{}", target.ip, target.port),
    }
}

async fn direct(
    client: IpEndpoint,
    mut rx: mpsc::Receiver<(Target, Vec<u8>)>,
    resp: mpsc::Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
    dns: Arc<DnsEngine>,
) {
    let socket = match UdpSocket::bind(unspecified(client.addr)).await {
        Ok(s) => s,
        Err(e) => {
            crate::logging::warn("udp", format!("绑定 UDP 失败: {}", e));
            return;
        }
    };
    let mut buf = vec![0u8; 65535];
    // 全锥 NAT 复用同一 socket，只接受「本会话发送过的目标」回来的包。
    // 同时记录 真实目的地址 -> 客户端原始目标（可能是 Fake-IP）：
    // 回包源地址必须还原成客户端请求的地址，否则内核/UDP 套接字会因源不匹配丢弃
    // （QUIC、游戏、语音通话表现为完全不通）。
    let mut sent_targets: BoundedMap<SocketAddr, IpEndpoint> = BoundedMap::new(1024);
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some((target, data)) => {
                        let original = IpEndpoint::new(IpAddress::from(target.ip), target.port);
                        let dst = if outbound::is_fake_ip(target.ip) {
                            match target.domain.as_deref() {
                                // 走本地 DNS 引擎（带缓存），不再逐包问系统 DNS。
                                Some(domain) => match dns.resolve_real(domain, target.port).await {
                                    Some(addrs) => match addrs.into_iter().next() {
                                        Some(addr) => addr,
                                        None => continue,
                                    },
                                    None => continue,
                                },
                                None => continue,
                            }
                        } else {
                            SocketAddr::new(target.ip, target.port)
                        };
                        sent_targets.insert(dst, original);
                        let _ = socket.send_to(&data, dst).await;
                    }
                    None => break,
                }
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, from)) => {
                        let Some(original) = sent_targets.get(&from).copied() else {
                            continue;
                        };
                        if resp.send((client, original, buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

async fn ss_udp(
    client: IpEndpoint,
    node: Node,
    mut rx: mpsc::Receiver<(Target, Vec<u8>)>,
    resp: mpsc::Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
) {
    let cipher = match SsUdpCipher::new(&node) {
        Ok(c) => c,
        Err(e) => {
            crate::logging::warn("udp", format!("SS UDP 初始化失败: {}", e));
            return;
        }
    };
    let server = match outbound::resolve(&node.server, node.port).await {
        Ok(s) => s,
        Err(e) => {
            crate::logging::warn("udp", format!("SS UDP 解析服务器失败: {}", e));
            return;
        }
    };
    let socket = match UdpSocket::bind(unspecified(IpAddress::from(server.ip()))).await {
        Ok(s) => s,
        Err(_) => return,
    };
    if socket.connect(server).await.is_err() {
        return;
    }
    crate::logging::info("udp", format!("SS UDP 已启用: {}", node.label()));
    let mut buf = vec![0u8; 65535];
    let mut last_target: Option<IpEndpoint> = None;
    let mut target_map: BoundedMap<String, IpEndpoint> = BoundedMap::new(1024);
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some((target, data)) => {
                        let original = IpEndpoint::new(IpAddress::from(target.ip), target.port);
                        last_target = Some(original);
                        target_map.insert(target_key(&target), original);
                        if let Ok(packet) = cipher.seal(&target, &data) {
                            let _ = socket.send(&packet).await;
                        }
                    }
                    None => break,
                }
            }
            res = socket.recv(&mut buf) => {
                match res {
                    Ok(n) => {
                        if let Ok((target, payload)) = cipher.open(&buf[..n]) {
                            // 优先还原成客户端原始请求的目标（Fake-IP），保证回包源地址一致。
                            let remote = target_map
                                .get(&target_key(&target))
                                .copied()
                                .or(last_target)
                                .unwrap_or_else(|| IpEndpoint::new(IpAddress::from(target.ip), target.port));
                            if resp.send((client, remote, payload)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

async fn socks_udp(
    client: IpEndpoint,
    node: Node,
    mut rx: mpsc::Receiver<(Target, Vec<u8>)>,
    resp: mpsc::Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
) {
    let mut s = match socks::udp_associate(&node).await {
        Ok(s) => s,
        Err(e) => {
            crate::logging::warn("udp", format!("SOCKS5 UDP 初始化失败: {}", e));
            return;
        }
    };
    let mut buf = vec![0u8; 65535];
    let mut ctl_buf = [0u8; 64];
    let mut last_target: Option<IpEndpoint> = None;
    let mut target_map: BoundedMap<String, IpEndpoint> = BoundedMap::new(1024);
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some((target, data)) => {
                        let original = IpEndpoint::new(IpAddress::from(target.ip), target.port);
                        last_target = Some(original);
                        target_map.insert(target_key(&target), original);
                        let mut packet = vec![0u8, 0u8, 0u8];
                        if outbound::encode_socks_addr(&mut packet, &target).is_err() {
                            continue;
                        }
                        packet.extend_from_slice(&data);
                        let _ = s.socket.send(&packet).await;
                    }
                    None => break,
                }
            }
            res = s.socket.recv(&mut buf) => {
                match res {
                    Ok(n) => {
                        if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
                            continue;
                        }
                        match outbound::parse_socks_addr_bytes(&buf, 3) {
                            Ok((domain, ip, port, offset)) => {
                                let key = match domain.as_deref() {
                                    Some(d) => format!("{}|{}", d, port),
                                    None => format!("{}|{}", ip, port),
                                };
                                let remote = target_map
                                    .get(&key)
                                    .copied()
                                    .or(last_target)
                                    .unwrap_or_else(|| IpEndpoint::new(IpAddress::from(ip), port));
                                if resp.send((client, remote, buf[offset..n].to_vec())).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    Err(_) => break,
                }
            }
            ctl = s.control.read(&mut ctl_buf) => {
                match ctl {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }
}

/// 解析一帧 Trojan UDP：[SOCKS5 地址][2 字节大端长度][载荷]。
/// 数据不够时返回 `Ok(None)`（继续读），只有明确的格式错误才返回 Err，
/// 不能把「还没收全」当成坏包直接断流。
fn parse_trojan_udp(buf: &[u8]) -> io::Result<Option<(Target, Vec<u8>, usize)>> {
    let Some(atyp) = buf.first().copied() else {
        return Ok(None);
    };
    let mut i = 1usize;
    let (domain, ip) = match atyp {
        0x01 => {
            let Some(b) = buf.get(i..i + 4) else { return Ok(None) };
            i += 4;
            (None, IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        }
        0x04 => {
            let Some(b) = buf.get(i..i + 16) else { return Ok(None) };
            i += 16;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            (None, IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        0x03 => {
            let Some(&len) = buf.get(i) else { return Ok(None) };
            i += 1;
            let len = len as usize;
            let Some(b) = buf.get(i..i + len) else { return Ok(None) };
            let d = String::from_utf8_lossy(b).to_string();
            if d.is_empty() {
                return Err(io_err("Trojan UDP 空域名"));
            }
            i += len;
            (Some(d), IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        }
        other => return Err(io_err(format!("Trojan UDP 未知地址类型: {}", other))),
    };
    let Some(rest) = buf.get(i..i + 4) else { return Ok(None) };
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
    if len == 0 {
        return Err(io_err("Trojan UDP 空载荷"));
    }
    i += 4;
    let Some(payload) = buf.get(i..i + len) else { return Ok(None) };
    Ok(Some((
        Target { ip, port, domain },
        payload.to_vec(),
        i + len,
    )))
}

/// 解析一帧 VLESS UDP：[2 字节大端长度][载荷]。
fn parse_vless_udp(buf: &[u8]) -> io::Result<Option<(Vec<u8>, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len == 0 {
        return Err(io_err("VLESS UDP 空载荷"));
    }
    if buf.len() < 2 + len {
        return Ok(None);
    }
    Ok(Some((buf[2..2 + len].to_vec(), 2 + len)))
}

fn vless_frame(payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.is_empty() {
        return Err(io_err("VLESS UDP 空载荷"));
    }
    if payload.len() > u16::MAX as usize {
        return Err(io_err("VLESS UDP 载荷超过 65535 字节"));
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Trojan UDP：每个源端口一条 TCP/TLS 隧道，报文按 SOCKS5 地址逐包封装。
async fn trojan_udp(
    client: IpEndpoint,
    node: Node,
    mut rx: mpsc::Receiver<(Target, Vec<u8>)>,
    resp: mpsc::Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
) {
    // 会话按「源端口 + 目标」建键，所以第一条包就确定了唯一出口目标；
    // 用它填 UDP ASSOCIATE 请求里的地址（服务器忽略该字段时也完全兼容）。
    let Some((first_target, first_data)) = rx.recv().await else {
        return;
    };
    let original = IpEndpoint::new(IpAddress::from(first_target.ip), first_target.port);
    let mut stream = match trojan::udp_associate(&node, &first_target).await {
        Ok(s) => s,
        Err(e) => {
            crate::logging::warn("udp", format!("Trojan UDP 初始化失败: {}", e));
            return;
        }
    };
    match trojan::encode_udp_frame(&first_target, &first_data) {
        Ok(frame) => {
            if stream.write_all(&frame).await.is_err() {
                return;
            }
        }
        Err(_) => return,
    }
    let (mut r, mut w) = tokio::io::split(stream);
    let mut rbuf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut tmp = vec![0u8; 16384];
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some((target, data)) => {
                        if let Ok(frame) = trojan::encode_udp_frame(&target, &data) {
                            if w.write_all(&frame).await.is_err() {
                                break;
                            }
                        }
                    }
                    None => break,
                }
            }
            res = r.read(&mut tmp) => {
                let n = match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                rbuf.extend_from_slice(&tmp[..n]);
                if rbuf.len() > 512 * 1024 {
                    crate::logging::warn("udp", "Trojan UDP 接收缓冲超过 512K，断开");
                    break;
                }
                loop {
                    match parse_trojan_udp(&rbuf) {
                        Ok(Some((_target, payload, used))) => {
                            rbuf.drain(..used);
                            // 会话只对应一个目标，回包源地址统一还原成客户端请求的原始地址
                            // （Fake-IP 场景下必须是它，否则内核会因源地址不匹配丢弃）。
                            if resp.send((client, original, payload)).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            crate::logging::warn("udp", format!("Trojan UDP 帧格式错误: {}", e));
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// VLESS UDP：一条连接对应一个目标，双向都是长度前缀帧。
async fn vless_udp(
    client: IpEndpoint,
    node: Node,
    mut rx: mpsc::Receiver<(Target, Vec<u8>)>,
    resp: mpsc::Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
) {
    let Some((first_target, first_data)) = rx.recv().await else {
        return;
    };
    let original = IpEndpoint::new(IpAddress::from(first_target.ip), first_target.port);
    let mut stream = match vless::udp_associate(&node, &first_target).await {
        Ok(s) => s,
        Err(e) => {
            crate::logging::warn("udp", format!("VLESS UDP 初始化失败: {}", e));
            return;
        }
    };
    match vless_frame(&first_data) {
        Ok(frame) => {
            if stream.write_all(&frame).await.is_err() {
                return;
            }
        }
        Err(_) => return,
    }
    // 首包先发出去，再读响应头：Xray 系服务端可能等到第一个 UDP 包才回响应头。
    if let Err(e) = vless::read_response_header(&mut stream).await {
        crate::logging::warn("udp", format!("VLESS UDP 响应头失败: {}", e));
        return;
    }
    let (mut r, mut w) = tokio::io::split(stream);
    let mut rbuf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut tmp = vec![0u8; 16384];
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some((_target, data)) => {
                        if let Ok(frame) = vless_frame(&data) {
                            if w.write_all(&frame).await.is_err() {
                                break;
                            }
                        }
                    }
                    None => break,
                }
            }
            res = r.read(&mut tmp) => {
                let n = match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                rbuf.extend_from_slice(&tmp[..n]);
                if rbuf.len() > 512 * 1024 {
                    crate::logging::warn("udp", "VLESS UDP 接收缓冲超过 512K，断开");
                    break;
                }
                loop {
                    match parse_vless_udp(&rbuf) {
                        Ok(Some((payload, used))) => {
                            rbuf.drain(..used);
                            if resp.send((client, original, payload)).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            crate::logging::warn("udp", format!("VLESS UDP 帧格式错误: {}", e));
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod udp_proto_tests {
    use super::*;
    use tokio::net::TcpListener;

    fn test_node(kind: &str, port: u16) -> Node {
        serde_json::from_value(serde_json::json!({
            "name": format!("{}-udp-test", kind),
            "type": kind,
            "server": "127.0.0.1",
            "port": port,
            "password": "pass",
            "uuid": "11111111-2222-3333-4444-555555555555",
            "tls": false
        }))
        .unwrap()
    }

    fn target() -> Target {
        Target {
            ip: "93.184.216.34".parse().unwrap(),
            port: 443,
            domain: None,
        }
    }

    #[test]
    fn trojan_frame_roundtrip_and_partial() {
        let t = target();
        let frame = trojan::encode_udp_frame(&t, b"hello").unwrap();
        let parsed = parse_trojan_udp(&frame).unwrap().expect("完整帧应可解析");
        assert_eq!(parsed.0.ip, t.ip);
        assert_eq!(parsed.0.port, t.port);
        assert_eq!(parsed.1, b"hello");
        assert_eq!(parsed.2, frame.len());

        // 少一字节必须判「还要继续读」，不能当成坏包断开
        assert!(parse_trojan_udp(&frame[..frame.len() - 1]).unwrap().is_none());
        assert!(parse_trojan_udp(&frame[..1]).unwrap().is_none());
    }

    #[test]
    fn vless_frame_parse() {
        let frame = vless_frame(b"world").unwrap();
        let parsed = parse_vless_udp(&frame).unwrap().unwrap();
        assert_eq!(parsed.0, b"world");
        assert_eq!(parsed.1, frame.len());
        assert!(parse_vless_udp(&frame[..1]).unwrap().is_none());
    }

    #[test]
    fn node_udp_switch_respected() {
        let mut n = test_node("trojan", 443);
        assert!(n.udp_supported());
        n.udp = Some(false);
        assert!(!n.udp_supported());
    }

    #[tokio::test]
    async fn trojan_udp_roundtrip_with_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // 密码哈希 56 字节 + CRLF
            let mut auth = [0u8; 58];
            s.read_exact(&mut auth).await.unwrap();
            // 命令 + IPv4 地址 + 端口 + CRLF
            let mut cmd = [0u8; 1];
            s.read_exact(&mut cmd).await.unwrap();
            assert_eq!(cmd[0], 0x03);
            let mut addr = [0u8; 7];
            s.read_exact(&mut addr).await.unwrap();
            let mut crlf = [0u8; 2];
            s.read_exact(&mut crlf).await.unwrap();
            // 第一帧：地址(7) + 长度(2) + 载荷
            let mut hdr = [0u8; 9];
            s.read_exact(&mut hdr).await.unwrap();
            let len = u16::from_be_bytes([hdr[7], hdr[8]]) as usize;
            let mut payload = vec![0u8; len];
            s.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload, b"ping");
            // 回一帧同样的地址 + pong
            let mut resp = Vec::new();
            resp.extend_from_slice(&hdr[..7]);
            resp.extend_from_slice(&(4u16).to_be_bytes());
            resp.extend_from_slice(b"pong");
            s.write_all(&resp).await.unwrap();
        });

        let node = test_node("trojan", port);
        let (tx, rx) = mpsc::channel::<(Target, Vec<u8>)>(8);
        let (resp_tx, mut resp_rx) = mpsc::channel::<(IpEndpoint, IpEndpoint, Vec<u8>)>(8);
        let client = IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), 5555);
        let task = tokio::spawn(trojan_udp(client, node, rx, resp_tx));
        tx.send((target(), b"ping".to_vec())).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), resp_rx.recv())
            .await
            .expect("5s 内应收到回包")
            .expect("回包通道应打开");
        assert_eq!(got.0, client);
        assert_eq!(got.1, IpEndpoint::new(IpAddress::v4(93, 184, 216, 34), 443));
        assert_eq!(got.2, b"pong");
        drop(tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn vless_udp_roundtrip_with_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // VLESS 请求头：版本(1)+UUID(16)+addons(1)+命令(1)+端口(2)+ATYP(1)+IPv4(4)
            let mut hdr = [0u8; 26];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[18], 0x02, "命令应为 UDP");
            // 响应头：版本 + addons 长度
            s.write_all(&[0u8, 0u8]).await.unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0u8; n];
            s.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload, b"ping");
            s.write_all(&[0u8, 4u8]).await.unwrap();
            s.write_all(b"pong").await.unwrap();
        });

        let node = test_node("vless", port);
        let (tx, rx) = mpsc::channel::<(Target, Vec<u8>)>(8);
        let (resp_tx, mut resp_rx) = mpsc::channel::<(IpEndpoint, IpEndpoint, Vec<u8>)>(8);
        let client = IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), 5556);
        let task = tokio::spawn(vless_udp(client, node, rx, resp_tx));
        tx.send((target(), b"ping".to_vec())).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), resp_rx.recv())
            .await
            .expect("5s 内应收到回包")
            .expect("回包通道应打开");
        assert_eq!(got.0, client);
        assert_eq!(got.2, b"pong");
        drop(tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }

    #[test]
    fn bounded_map_evicts_oldest_not_all() {
        let mut m: BoundedMap<u32, u32> = BoundedMap::new(4);
        for i in 0..4 {
            m.insert(i, i * 10);
        }
        assert_eq!(m.len(), 4);
        // 满了再插：只淘汰最旧一条，其余活跃映射必须保留。
        m.insert(4, 40);
        assert_eq!(m.len(), 4);
        assert_eq!(m.get(&0), None);
        assert_eq!(m.get(&1), Some(&10));
        assert_eq!(m.get(&4), Some(&40));
        // 重复插入已有键：不触发淘汰、不膨胀。
        m.insert(2, 200);
        assert_eq!(m.len(), 4);
        assert_eq!(m.get(&2), Some(&200));
        assert_eq!(m.get(&1), Some(&10));
        // 继续插入按序淘汰。
        m.insert(5, 50);
        assert_eq!(m.get(&1), None);
        assert_eq!(m.get(&3), Some(&30));
    }

    #[test]
    fn bounded_map_at_scale_keeps_recent() {
        let mut m: BoundedMap<u32, u32> = BoundedMap::new(1024);
        for i in 0..2048 {
            m.insert(i, i);
        }
        assert_eq!(m.len(), 1024);
        assert_eq!(m.get(&1023), None);
        assert_eq!(m.get(&1024), Some(&1024));
        assert_eq!(m.get(&2047), Some(&2047));
    }
}
