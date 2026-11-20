use crate::config::{Node, Target};
use crate::logging;
use crate::outbound::{encode_socks_addr, tls_connect, BoxStream};
use sha2::{Digest, Sha224};
use std::io;
use tokio::io::AsyncWriteExt;

pub async fn connect(node: &Node, target: Target) -> io::Result<BoxStream> {
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

    // Trojan over WebSocket
    if node.ws_path.is_some() || node.method.as_deref() == Some("ws") {
        let path = node.ws_path.clone().unwrap_or_else(|| "/".into());
        let ws_host = node.ws_host.clone().unwrap_or_else(|| sni.clone());
        stream = crate::proto::ws::wrap(stream, &path, &ws_host).await?;
    }

    let password = node.password.clone().unwrap_or_default();
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let hash = hex_encode(&hasher.finalize());
    stream.write_all(hash.as_bytes()).await?;
    stream.write_all(b"\r\n").await?;

    // Trojan 请求：密码哈希 + CRLF + 命令(1=CONNECT) + SOCKS 地址 + CRLF
    stream.write_all(&[0x01]).await?;
    let mut addr = Vec::new();
    encode_socks_addr(&mut addr, &target)?;
    stream.write_all(&addr).await?;
    stream.write_all(b"\r\n").await?;

    logging::info("trojan", format!("已连接 {} -> {}", node.label(), crate::outbound::display_target(&target)));
    Ok(stream)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
