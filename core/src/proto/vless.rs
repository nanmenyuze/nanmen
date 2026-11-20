use crate::config::{Node, Target};
use crate::logging;
use crate::outbound::{encode_vless_addr, io_err, tls_connect, BoxStream};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

pub async fn connect(node: &Node, target: Target) -> io::Result<BoxStream> {
    let host = node.server.clone();
    let port = node.port;
    let sni = node.sni.clone().unwrap_or_else(|| host.clone());
    let insecure = node.insecure.unwrap_or(false);
    let use_tls = node.tls.unwrap_or(true);
    let network = node.method.clone().unwrap_or_else(|| "tcp".into());

    let mut stream: BoxStream = if use_tls {
        Box::new(tls_connect(&host, port, &sni, insecure).await?)
    } else {
        Box::new(crate::outbound::tcp_connect(&host, port).await?)
    };

    if network == "ws" || node.ws_path.is_some() {
        let path = node.ws_path.clone().unwrap_or_else(|| "/".into());
        let ws_host = node.ws_host.clone().unwrap_or_else(|| sni.clone());
        stream = crate::proto::ws::wrap(stream, &path, &ws_host).await?;
    }

    let uuid = parse_uuid(node.uuid.as_deref().unwrap_or(""))?;
    let mut header = Vec::with_capacity(24);
    header.push(0u8); // version
    header.extend_from_slice(&uuid);
    header.push(0u8); // addons length
    header.push(1u8); // command: tcp
    encode_vless_addr(&mut header, &target)?;
    stream.write_all(&header).await?;

    let (pipe_a, pipe_b) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        // 响应头读取必须有超时：黑洞服务器不回数据时不能把任务永久挂起。
        let mut hdr = [0u8; 2];
        let read_hdr = tokio::time::timeout(std::time::Duration::from_secs(8), stream.read_exact(&mut hdr)).await;
        match read_hdr {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let addons = hdr[1] as usize;
        if addons > 0 {
            let mut skip = vec![0u8; addons];
            if stream.read_exact(&mut skip).await.is_err() {
                return;
            }
        }
        bridge_stream(stream, pipe_a).await;
    });

    logging::info("vless", format!("已连接 {} -> {}", node.label(), crate::outbound::display_target(&target)));
    Ok(Box::new(pipe_b))
}

pub fn parse_uuid(s: &str) -> io::Result<[u8; 16]> {
    let clean: String = s.chars().filter(|c| *c != '-').collect();
    if clean.len() != 32 {
        return Err(io_err("VLESS UUID 格式错误"));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_val(clean.as_bytes()[i * 2])?;
        let lo = hex_val(clean.as_bytes()[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(b: u8) -> io::Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(io_err("UUID 含非法字符")),
    }
}

async fn bridge_stream(mut stream: BoxStream, pipe: DuplexStream) {
    let (mut sr, mut sw) = tokio::io::split(&mut stream);
    let (mut pr, mut pw) = tokio::io::split(pipe);
    let read_loop = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = sr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            pw.write_all(&buf[..n]).await?;
        }
        Ok::<(), io::Error>(())
    };
    let write_loop = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = pr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            sw.write_all(&buf[..n]).await?;
        }
        Ok::<(), io::Error>(())
    };
    tokio::pin!(read_loop);
    tokio::pin!(write_loop);
    // 半关闭语义：写侧先结束（客户端 FIN）时继续读完服务端响应，不能直接丢弃读侧。
    tokio::select! {
        r = &mut read_loop => { if let Err(e) = r { logging::warn("vless", format!("读失败 {}", e)); } }
        r = &mut write_loop => {
            if let Err(e) = r { logging::warn("vless", format!("写失败 {}", e)); }
            if let Err(e) = read_loop.await { logging::warn("vless", format!("读失败 {}", e)); }
        }
    }
}
