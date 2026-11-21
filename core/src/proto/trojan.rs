use crate::config::{Node, Target};
use crate::logging;
use crate::outbound::{encode_socks_addr, tls_connect, BoxStream};
use sha2::{Digest, Sha224};
use std::io;
use tokio::io::AsyncWriteExt;

/// Trojan 命令字：1=CONNECT（TCP），3=UDP ASSOCIATE。
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// 建传输层：TLS（可关）+ 可选 WebSocket。TCP/UDP 共用，保证两条路径的
/// SNI、证书校验、WS Host/Path 行为完全一致。
async fn open_stream(node: &Node) -> io::Result<BoxStream> {
    let host = node.server.clone();
    let port = node.port;
    let sni = node.sni.clone().unwrap_or_else(|| host.clone());
    let insecure = node.insecure.unwrap_or(false);
    let use_tls = node.tls.unwrap_or(true);

    let mut stream: BoxStream = if use_tls {
        Box::new(tls_connect(&host, port, &sni, insecure).await?)
    } else {
        Box::new(crate::outbound::tcp_connect(&host, port).await?)
    };

    if node.ws_path.is_some() || node.method.as_deref() == Some("ws") {
        let path = node.ws_path.clone().unwrap_or_else(|| "/".into());
        let ws_host = node.ws_host.clone().unwrap_or_else(|| sni.clone());
        stream = crate::proto::ws::wrap(stream, &path, &ws_host).await?;
    }
    Ok(stream)
}

/// Trojan 握手第一部分：密码的 SHA224 十六进制 + CRLF。
async fn write_auth(stream: &mut BoxStream, node: &Node) -> io::Result<()> {
    let password = node.password.clone().unwrap_or_default();
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let hash = hex_encode(&hasher.finalize());
    stream.write_all(hash.as_bytes()).await?;
    stream.write_all(b"\r\n").await
}

pub async fn connect(node: &Node, target: Target) -> io::Result<BoxStream> {
    let mut stream = open_stream(node).await?;
    write_auth(&mut stream, node).await?;

    // Trojan 请求：密码哈希 + CRLF + 命令(1=CONNECT) + SOCKS 地址 + CRLF
    stream.write_all(&[CMD_CONNECT]).await?;
    let mut addr = Vec::new();
    encode_socks_addr(&mut addr, &target)?;
    stream.write_all(&addr).await?;
    stream.write_all(b"\r\n").await?;

    logging::info("trojan", format!("已连接 {} -> {}", node.label(), crate::outbound::display_target(&target)));
    Ok(stream)
}

/// 建立 Trojan UDP ASSOCIATE 通道。Trojan 的 UDP 报文结构与 SOCKS5 一致，
/// 只是整条流跑在 TCP/TLS 隧道里；这里的 target 是本次会话唯一的出口目标。
pub async fn udp_associate(node: &Node, target: &Target) -> io::Result<BoxStream> {
    let mut stream = open_stream(node).await?;
    write_auth(&mut stream, node).await?;
    stream.write_all(&[CMD_UDP_ASSOCIATE]).await?;
    let mut addr = Vec::new();
    encode_socks_addr(&mut addr, target)?;
    stream.write_all(&addr).await?;
    stream.write_all(b"\r\n").await?;

    logging::info(
        "trojan",
        format!("UDP ASSOCIATE {} -> {}", node.label(), crate::outbound::display_target(target)),
    );
    Ok(stream)
}

/// Trojan UDP 帧：[SOCKS5 地址][2 字节大端长度][载荷]。
pub fn encode_udp_frame(target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.is_empty() {
        return Err(crate::outbound::io_err("Trojan UDP 空载荷"));
    }
    if payload.len() > u16::MAX as usize {
        return Err(crate::outbound::io_err("Trojan UDP 载荷超过 65535 字节"));
    }
    let mut out = Vec::with_capacity(32 + payload.len());
    encode_socks_addr(&mut out, target)?;
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
