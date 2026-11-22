use crate::config::{Node, Target};
use crate::outbound::{encode_socks_addr, io_err, tls_connect, tcp_connect, BoxStream};
use base64::Engine;
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

pub async fn connect_socks5(node: &Node, target: Target) -> io::Result<BoxStream> {
    let mut sock = tcp_connect(&node.server, node.port).await?;
    let user = node.uuid.clone().unwrap_or_default();
    let pass = node.password.clone().unwrap_or_default();
    let need_auth = !user.is_empty();

    if need_auth {
        sock.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        sock.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut rep = [0u8; 2];
    sock.read_exact(&mut rep).await?;
    if rep[0] != 0x05 {
        return Err(io_err("SOCKS5 版本错误"));
    }
    if rep[1] == 0x02 {
        let mut auth = vec![0x01u8, user.len() as u8];
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass.as_bytes());
        sock.write_all(&auth).await?;
        let mut st = [0u8; 2];
        sock.read_exact(&mut st).await?;
        if st[1] != 0 {
            return Err(io_err("SOCKS5 认证失败"));
        }
    } else if rep[1] != 0x00 {
        return Err(io_err("SOCKS5 无可用认证方式"));
    }

    let mut req = vec![0x05u8, 0x01, 0x00];
    encode_socks_addr(&mut req, &target)?;
    sock.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    sock.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(io_err(format!("SOCKS5 连接失败: code {}", hdr[1])));
    }
    match hdr[3] {
        0x01 => {
            let mut b = [0u8; 6];
            sock.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize + 2];
            sock.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 18];
            sock.read_exact(&mut b).await?;
        }
        _ => return Err(io_err("SOCKS5 地址类型错误")),
    }
    crate::logging::info("socks", format!("SOCKS5 已连接 {} -> {}", node.label(), crate::outbound::display_target(&target)));
    Ok(Box::new(sock))
}

/// SOCKS5 UDP ASSOCIATE：控制连接保活，数据走 UDP relay，每包带 RSV/FRAG + 目标地址。
pub struct Socks5Udp {
    pub control: BoxStream,
    pub socket: UdpSocket,
}

pub async fn udp_associate(node: &Node) -> io::Result<Socks5Udp> {
    // 整个握手包超时：黑洞服务器接受连接后不回数据时，会话任务不能永久挂起。
    tokio::time::timeout(std::time::Duration::from_secs(12), udp_associate_inner(node))
        .await
        .map_err(|_| io_err("SOCKS5 UDP ASSOCIATE 握手超时"))?
}

async fn udp_associate_inner(node: &Node) -> io::Result<Socks5Udp> {
    let mut sock = tcp_connect(&node.server, node.port).await?;
    let user = node.uuid.clone().unwrap_or_default();
    let pass = node.password.clone().unwrap_or_default();
    let need_auth = !user.is_empty();

    if need_auth {
        sock.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        sock.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut rep = [0u8; 2];
    sock.read_exact(&mut rep).await?;
    if rep[0] != 0x05 {
        return Err(io_err("SOCKS5 版本错误"));
    }
    if rep[1] == 0x02 {
        let mut auth = vec![0x01u8, user.len() as u8];
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass.as_bytes());
        sock.write_all(&auth).await?;
        let mut st = [0u8; 2];
        sock.read_exact(&mut st).await?;
        if st[1] != 0 {
            return Err(io_err("SOCKS5 认证失败"));
        }
    } else if rep[1] != 0x00 {
        return Err(io_err("SOCKS5 无可用认证方式"));
    }

    // UDP ASSOCIATE，客户端地址留空由代理分配
    let req = [0x05u8, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    sock.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(io_err(format!("SOCKS5 UDP ASSOCIATE 失败: code {}", hdr[1])));
    }
    let mut raw = vec![hdr[3]];
    match hdr[3] {
        0x01 => {
            let mut b = [0u8; 6];
            sock.read_exact(&mut b).await?;
            raw.extend_from_slice(&b);
        }
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await?;
            raw.push(l[0]);
            let mut b = vec![0u8; l[0] as usize + 2];
            sock.read_exact(&mut b).await?;
            raw.extend_from_slice(&b);
        }
        0x04 => {
            let mut b = [0u8; 18];
            sock.read_exact(&mut b).await?;
            raw.extend_from_slice(&b);
        }
        _ => return Err(io_err("SOCKS5 UDP 地址类型错误")),
    }
    let (domain, ip, port, _offset) =
        crate::outbound::parse_socks_addr_bytes(&raw, 0)?;
    let mut relay_ip = ip;
    if relay_ip.is_unspecified() {
        if let Ok(a) = crate::outbound::resolve(&node.server, node.port).await {
            relay_ip = a.ip();
        }
    }
    if let Some(d) = domain {
        if let Ok(a) = crate::outbound::resolve(&d, port).await {
            relay_ip = a.ip();
        }
    }
    if port == 0 {
        return Err(io_err("SOCKS5 UDP relay 端口为 0"));
    }
    let relay = SocketAddr::new(relay_ip, port);
    let bind: SocketAddr = if relay.is_ipv4() {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(relay).await?;
    crate::logging::info("socks", format!("SOCKS5 UDP relay: {} (via {})", relay, node.label()));
    Ok(Socks5Udp { control: sock, socket })
}

pub async fn connect_http(node: &Node, target: Target) -> io::Result<BoxStream> {
    let use_tls = node.tls.unwrap_or(false);
    let mut sock: BoxStream = if use_tls {
        Box::new(tls_connect(&node.server, node.port, &node.server, node.insecure.unwrap_or(false)).await?)
    } else {
        Box::new(tcp_connect(&node.server, node.port).await?)
    };
    let host = match &target.domain {
        Some(d) => d.clone(),
        None => target.ip.to_string(),
    };
    let mut req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: keep-alive\r\n",
        host, target.port, host, target.port
    );
    let user = node.uuid.clone().unwrap_or_default();
    let pass = node.password.clone().unwrap_or_default();
    if !user.is_empty() {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", token));
    }
    req.push_str("\r\n");
    sock.write_all(req.as_bytes()).await?;

    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    let mut scan_from = 0usize;
    let end = loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            return Err(io_err("HTTP 代理被关闭"));
        }
        head.extend_from_slice(&buf[..n]);
        // 增量扫描头部结束位置，避免每读一次全量重扫。
        if let Some(pos) = head[scan_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            break scan_from + pos + 4;
        }
        scan_from = head.len().saturating_sub(3);
        if head.len() > 8192 {
            return Err(io_err("HTTP 代理响应过长"));
        }
    };
    let text = String::from_utf8_lossy(&head[..end]);
    let status_line = text.lines().next().unwrap_or("");
    // 只解析状态行的状态码，避免误匹配头部其它位置的 " 200 "。
    let status_ok = status_line.split_whitespace().nth(1) == Some("200");
    if !status_ok {
        return Err(io_err(format!("HTTP CONNECT 失败: {}", status_line)));
    }
    crate::logging::info("http", format!("HTTP 代理已连接 {} -> {}", node.label(), crate::outbound::display_target(&target)));
    // 与头部一起读到的早到数据必须保留，接在返回流前面，不能丢弃。
    let leftover = head[end..].to_vec();
    if leftover.is_empty() {
        Ok(sock)
    } else {
        Ok(Box::new(crate::outbound::PrefixedStream::new(leftover, sock)))
    }
}
