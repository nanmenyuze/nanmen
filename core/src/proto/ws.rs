use crate::logging;
use crate::outbound::{io_err, BoxStream};
use base64::Engine;
use rand::RngCore;
use sha1::{Digest, Sha1};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

/// 单条消息的分片累积上限：单帧 1MB 限制挡不住无限分片，必须有总量上限。
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub async fn wrap(mut stream: BoxStream, path: &str, host: &str) -> io::Result<BoxStream> {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let ws_key = base64::engine::general_purpose::STANDARD.encode(key);
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Linux; Android 14)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host, ws_key
    );
    stream.write_all(req.as_bytes()).await?;

    let mut resp = Vec::new();
    let mut buf = [0u8; 1024];
    let mut scan_from = 0usize;
    let end = loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io_err("WebSocket 握手被关闭"));
        }
        resp.extend_from_slice(&buf[..n]);
        if let Some(pos) = resp[scan_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            break scan_from + pos + 4;
        }
        scan_from = resp.len().saturating_sub(3);
        if resp.len() > 8192 {
            return Err(io_err("WebSocket 响应过长"));
        }
    };
    let head = String::from_utf8_lossy(&resp[..end]);
    let status_ok = head.starts_with("HTTP/1.1 101") || head.starts_with("HTTP/1.0 101");
    if !status_ok {
        return Err(io_err(format!(
            "WebSocket 握手失败: {}",
            head.lines().next().unwrap_or("")
        )));
    }
    // 校验 Sec-WebSocket-Accept：确认对端真的理解 WebSocket，而不是缓存/代理误答。
    let mut hasher = Sha1::new();
    hasher.update(format!("{}{}", ws_key, WS_GUID).as_bytes());
    let expected = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    let accept_ok = head.lines().any(|line| {
        // 只小写头部名进行比较；Base64 值大小写敏感，不能一起转小写。
        let mut parts = line.splitn(2, ':');
        let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim();
        name == "sec-websocket-accept" && value == expected
    });
    if !accept_ok {
        return Err(io_err("WebSocket 握手缺少有效的 Sec-WebSocket-Accept"));
    }

    // 与 101 头部一起读到的早到数据（服务端可能紧跟首个帧）必须保留。
    let leftover = resp[end..].to_vec();
    let (pipe_a, pipe_b) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        run(stream, pipe_a, leftover).await;
    });
    logging::info(
        "ws",
        format!(
            "WebSocket 已建立 {}",
            path.split('?').next().unwrap_or(&path)
        ),
    );
    Ok(Box::new(pipe_b))
}

async fn run(stream: BoxStream, pipe: DuplexStream, leftover: Vec<u8>) {
    let (sr, mut sw) = tokio::io::split(stream);
    let (mut pr, mut pw) = tokio::io::split(pipe);
    // 早到数据接在流前面一起解析。
    let mut sr = std::io::Cursor::new(leftover).chain(sr);
    // Ping 由读侧发现、写侧回 Pong（两个循环不能同时持有写半）。
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);

    let read_loop = async {
        let mut out: Vec<u8> = Vec::new();
        loop {
            let (opcode, fin, payload) = read_frame(&mut sr).await?;
            match opcode {
                0x8 => return Err(io_err("WebSocket 已关闭")),
                0x9 => {
                    // Ping 必须回 Pong，否则部分服务端会主动断连。
                    let _ = ctrl_tx.try_send(payload);
                    continue;
                }
                0xA => continue,
                _ => {}
            }
            if out.len() + payload.len() > MAX_MESSAGE {
                return Err(io_err("WebSocket 消息超过 4MB 上限"));
            }
            out.extend_from_slice(&payload);
            if fin {
                if !out.is_empty() {
                    pw.write_all(&out).await?;
                }
                out.clear();
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    let write_loop = async {
        let mut buf = vec![0u8; 16384];
        let mut ctrl_closed = false;
        loop {
            tokio::select! {
                ping = ctrl_rx.recv(), if !ctrl_closed => {
                    match ping {
                        Some(payload) => write_frame(&mut sw, 0xA, &payload).await?,
                        None => { ctrl_closed = true; }
                    }
                }
                r = pr.read(&mut buf) => {
                    let n = r?;
                    if n == 0 {
                        break;
                    }
                    write_frame(&mut sw, 0x2, &buf[..n]).await?;
                }
            }
        }
        Ok::<(), io::Error>(())
    };
    tokio::pin!(read_loop);
    tokio::pin!(write_loop);
    // 半关闭语义：写侧先结束（客户端 FIN）时继续读完服务端响应。
    tokio::select! {
        r = &mut read_loop => { if let Err(e) = r { logging::warn("ws", format!("读失败 {}", e)); } }
        r = &mut write_loop => {
            if let Err(e) = r { logging::warn("ws", format!("写失败 {}", e)); }
            if let Err(e) = read_loop.await { logging::warn("ws", format!("读失败 {}", e)); }
        }
    }
}

/// 读一个完整帧：返回 (opcode, fin, 已解掩码的负载)。
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(u8, bool, Vec<u8>)> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h).await?;
    let fin = h[0] & 0x80 != 0;
    let opcode = h[0] & 0x0f;
    let masked = h[1] & 0x80 != 0;
    let mut len = (h[1] & 0x7f) as usize;
    if len == 126 {
        let mut l = [0u8; 2];
        r.read_exact(&mut l).await?;
        len = u16::from_be_bytes(l) as usize;
    } else if len == 127 {
        let mut l = [0u8; 8];
        r.read_exact(&mut l).await?;
        len = u64::from_be_bytes(l) as usize;
    }
    if len > 1 << 20 {
        return Err(io_err("WebSocket 帧过大"));
    }
    let mut mask = [0u8; 4];
    if masked {
        r.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    if masked {
        for i in 0..len {
            payload[i] ^= mask[i % 4];
        }
    }
    Ok((opcode, fin, payload))
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, opcode: u8, data: &[u8]) -> io::Result<()> {
    let mut h = Vec::with_capacity(14);
    h.push(0x80 | opcode);
    let mut mask = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mask);
    if data.len() < 126 {
        h.push(0x80 | data.len() as u8);
    } else if data.len() < 65536 {
        h.push(0x80 | 126);
        h.extend_from_slice(&(data.len() as u16).to_be_bytes());
    } else {
        h.push(0x80 | 127);
        h.extend_from_slice(&(data.len() as u64).to_be_bytes());
    }
    h.extend_from_slice(&mask);
    let mut payload = data.to_vec();
    for i in 0..payload.len() {
        payload[i] ^= mask[i % 4];
    }
    w.write_all(&h).await?;
    w.write_all(&payload).await?;
    Ok(())
}
