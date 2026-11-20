use crate::config::{Node, Target};
use crate::dns::DnsEngine;
use crate::outbound;
use crate::proto::ss::SsUdpCipher;
use crate::proto::socks;
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[derive(Clone)]
pub enum UdpMode {
    Direct,
    Ss(Node),
    Socks5(Node),
    Unsupported(String),
}

/// 单个客户端源端口的 UDP 会话：Direct 为全锥 NAT；SS/SOCKS5 把报文封装到代理。
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
    let mut sent_targets: HashMap<SocketAddr, IpEndpoint> = HashMap::new();
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
                        if sent_targets.len() >= 1024 {
                            sent_targets.clear();
                        }
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
    let mut target_map: HashMap<String, IpEndpoint> = HashMap::new();
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some((target, data)) => {
                        let original = IpEndpoint::new(IpAddress::from(target.ip), target.port);
                        last_target = Some(original);
                        if target_map.len() >= 1024 {
                            target_map.clear();
                        }
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
    let mut target_map: HashMap<String, IpEndpoint> = HashMap::new();
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some((target, data)) => {
                        let original = IpEndpoint::new(IpAddress::from(target.ip), target.port);
                        last_target = Some(original);
                        if target_map.len() >= 1024 {
                            target_map.clear();
                        }
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
