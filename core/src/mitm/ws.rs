//! WebSocket 帧改写（仅 h1 Upgrade）。
//!
//! 只有 URL 真正命中 `[WebSocket Rewrite]` 规则时才进入帧模式；没命中时调用方
//! 继续走 `copy_bidirectional`，不解析任何帧。进入帧模式前会剥掉
//! `Sec-WebSocket-Extensions`，因此 permessage-deflate 等扩展不会被协商，
//! 后续按未压缩帧解析（日志会标明这次降级）。
//!
//! 支持：
//! - `ws-block`：命中 URL 后发 close 1008，随后半关闭；
//! - `ws-text-replace <regex> <replacement>`：全局文本替换；
//! - `ws-text-replace <url-regex> <text-regex> <replacement>`：按 URL 命中后替换。
//!
//! 客户端→上游的帧解 mask 后按需重写，再用随机 mask 重新编码；上游→客户端
//! 保持不掩码。二进制一律透传；文本消息聚合完成后再改写，失败则原帧回放。

use regex::bytes::Regex;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 单条聚合消息上限，与 MITM 的 body_limit 对齐。
pub const WS_MESSAGE_LIMIT: usize = 2 * 1024 * 1024;
/// 单帧硬上限，防止异常对端用超大长度拖垮内存；超过按协议错误断开。
pub const WS_FRAME_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum WsAction {
    Block,
    TextReplace { re: Regex, replacement: String },
}

#[derive(Debug, Clone)]
pub struct WsRule {
    pub url: Regex,
    pub action: WsAction,
}

#[derive(Debug, Clone, Default)]
pub struct WsRules {
    pub rules: Vec<WsRule>,
    pub unsupported: usize,
}

/// 单条连接命中的动作集合。没有命中时 `active == false`，调用方保持零代价透传。
#[derive(Debug, Clone, Default)]
pub struct WsPlan {
    pub active: bool,
    pub block: bool,
    pub replacements: Vec<(Regex, String)>,
}

impl WsPlan {
    pub fn has_replacements(&self) -> bool {
        !self.replacements.is_empty()
    }
}

impl WsRules {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn plan(&self, host: &str, path: &str) -> WsPlan {
        if self.rules.is_empty() {
            return WsPlan::default();
        }
        let https = format!("https://{}{}", host, path);
        let wss = format!("wss://{}{}", host, path);
        let ws = format!("ws://{}{}", host, path);
        let mut plan = WsPlan::default();
        for rule in &self.rules {
            if !rule.url.is_match(https.as_bytes())
                && !rule.url.is_match(wss.as_bytes())
                && !rule.url.is_match(ws.as_bytes())
            {
                continue;
            }
            plan.active = true;
            match &rule.action {
                WsAction::Block => plan.block = true,
                WsAction::TextReplace { re, replacement } => {
                    plan.replacements.push((re.clone(), replacement.clone()));
                }
            }
        }
        plan
    }

    /// 解析 `[WebSocket Rewrite]` 的原始行。无法解析的行计入 unsupported。
    pub fn parse(lines: &[String]) -> Self {
        let mut rules = Vec::new();
        let mut unsupported = 0usize;
        for raw in lines {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let tokens = tokenize(line);
            if tokens.is_empty() {
                unsupported += 1;
                continue;
            }
            let action = tokens[0].to_ascii_lowercase();
            match action.as_str() {
                "ws-block" => {
                    // 允许 `ws-block` 单独出现（匹配所有 URL），也允许带 URL 正则。
                    let url = tokens.get(1).cloned().unwrap_or_else(|| ".*".to_string());
                    match Regex::new(&url) {
                        Ok(url) => rules.push(WsRule {
                            url,
                            action: WsAction::Block,
                        }),
                        Err(_) => unsupported += 1,
                    }
                }
                "ws-text-replace" => {
                    // 2 个参数：全局文本正则 + 替换
                    // 3/4 个参数：URL 正则 + 文本正则 + 替换（替换可含空格）
                    let (url, text_re, replacement) = match tokens.len() {
                        3 => (".*".to_string(), tokens[1].clone(), tokens[2].clone()),
                        4 => (tokens[1].clone(), tokens[2].clone(), tokens[3].clone()),
                        n if n > 4 => (tokens[1].clone(), tokens[2].clone(), tokens[3..].join(" ")),
                        _ => {
                            unsupported += 1;
                            continue;
                        }
                    };
                    let url = match Regex::new(&url) {
                        Ok(r) => r,
                        Err(_) => {
                            unsupported += 1;
                            continue;
                        }
                    };
                    let re = match Regex::new(&text_re) {
                        Ok(r) => r,
                        Err(_) => {
                            unsupported += 1;
                            continue;
                        }
                    };
                    rules.push(WsRule {
                        url,
                        action: WsAction::TextReplace { re, replacement },
                    });
                }
                _ => unsupported += 1,
            }
        }
        Self { rules, unsupported }
    }
}

fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[derive(Debug, Clone)]
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    raw: Vec<u8>,
}

fn parse_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, String> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let len7 = (buf[1] & 0x7f) as usize;
    let mut header = 2usize;
    let payload_len = match len7 {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            header = 4;
            u16::from_be_bytes([buf[2], buf[3]]) as usize
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            header = 10;
            let n = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]);
            if n > usize::MAX as u64 {
                return Err("WebSocket 帧长度溢出".to_string());
            }
            n as usize
        }
        n => n,
    };
    if opcode >= 0x8 && (payload_len > 125 || !fin) {
        return Err("WebSocket 控制帧格式非法".to_string());
    }
    if payload_len > WS_FRAME_LIMIT {
        return Err("WebSocket 单帧超过硬上限".to_string());
    }
    let mask = if masked {
        if buf.len() < header + 4 {
            return Ok(None);
        }
        let m = [
            buf[header],
            buf[header + 1],
            buf[header + 2],
            buf[header + 3],
        ];
        header += 4;
        Some(m)
    } else {
        None
    };
    let total = header
        .checked_add(payload_len)
        .ok_or_else(|| "WebSocket 帧长度溢出".to_string())?;
    if buf.len() < total {
        return Ok(None);
    }
    let raw = buf[..total].to_vec();
    let mut payload = buf[header..total].to_vec();
    if let Some(mask) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok(Some((
        Frame {
            fin,
            opcode,
            payload,
            raw,
        },
        total,
    )))
}

fn encode_frame(fin: bool, opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(if fin { 0x80 | opcode } else { opcode });
    let mask_bit = if masked { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if masked {
        let key = random_mask();
        out.extend_from_slice(&key);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ key[i & 3]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    out
}

fn random_mask() -> [u8; 4] {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    [
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsFlow {
    Continue,
    Closed,
}

struct Message {
    opcode: u8,
    payload: Vec<u8>,
    raws: Vec<Vec<u8>>,
}

struct Relay {
    buf: Vec<u8>,
    msg: Option<Message>,
    /// 超限后只透传，直到当前消息结束。
    passthrough: bool,
    /// 客户端→上游方向需要重新掩码。
    masked: bool,
    /// 是否有文本改写规则；没有时文本帧也可直接透传。
    rewrite: bool,
}

impl Relay {
    fn new(masked: bool, rewrite: bool) -> Self {
        Self {
            buf: Vec::new(),
            msg: None,
            passthrough: false,
            masked,
            rewrite,
        }
    }

    async fn feed<W: AsyncWrite + Unpin>(
        &mut self,
        data: &[u8],
        out: &mut W,
        plan: &WsPlan,
    ) -> io::Result<WsFlow> {
        self.buf.extend_from_slice(data);
        loop {
            let parsed = match parse_frame(&self.buf) {
                Ok(Some(v)) => v,
                Ok(None) => break,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };
            let (frame, used) = parsed;
            self.buf.drain(..used);

            if frame.opcode == 0x8 {
                out.write_all(&frame.raw).await?;
                return Ok(WsFlow::Closed);
            }
            if frame.opcode == 0x9 || frame.opcode == 0xA {
                // ping/pong 可随时插入，直接透传。
                out.write_all(&frame.raw).await?;
                continue;
            }
            if self.passthrough {
                out.write_all(&frame.raw).await?;
                if frame.fin {
                    self.passthrough = false;
                }
                continue;
            }
            if frame.opcode == 0x2 || !self.rewrite {
                // 二进制一律透传；没有文本规则时文本也零拷贝透传。
                out.write_all(&frame.raw).await?;
                continue;
            }
            if frame.opcode != 0x1 && frame.opcode != 0x0 {
                // 未知数据 opcode：不猜，原样透传。
                out.write_all(&frame.raw).await?;
                continue;
            }
            if frame.opcode == 0x0 && self.msg.is_none() {
                // 没有起始帧的 continuation：原样透传。
                out.write_all(&frame.raw).await?;
                continue;
            }
            let msg = self.msg.get_or_insert_with(|| Message {
                opcode: 0x1,
                payload: Vec::new(),
                raws: Vec::new(),
            });
            msg.payload.extend_from_slice(&frame.payload);
            msg.raws.push(frame.raw);
            if msg.payload.len() > WS_MESSAGE_LIMIT {
                // 超限：已缓冲的原帧先 flush，之后当前消息剩余帧流式透传。
                for raw in std::mem::take(&mut msg.raws) {
                    out.write_all(&raw).await?;
                }
                self.msg = None;
                self.passthrough = true;
                continue;
            }
            if !frame.fin {
                continue;
            }
            let msg = self.msg.take().expect("message checked above");
            let mut text = msg.payload.clone();
            let mut changed = false;
            for (re, replacement) in &plan.replacements {
                let after = re.replace_all(&text, replacement.as_bytes());
                if after != text {
                    text = after.into_owned();
                    changed = true;
                }
            }
            if changed {
                // 同一条消息用单帧发出；对端只关心 FIN/opcode，不依赖原始分片。
                let encoded = encode_frame(true, msg.opcode, &text, self.masked);
                out.write_all(&encoded).await?;
            } else {
                // 没改动就原帧回放，保持原分片与掩码。
                for raw in msg.raws {
                    out.write_all(&raw).await?;
                }
            }
        }
        Ok(WsFlow::Continue)
    }
}

async fn send_close<W: AsyncWrite + Unpin>(
    out: &mut W,
    code: u16,
    masked: bool,
    reason: &[u8],
) -> io::Result<()> {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(reason);
    let frame = encode_frame(true, 0x8, &payload, masked);
    out.write_all(&frame).await?;
    out.flush().await?;
    Ok(())
}

/// 进入帧模式后的双向 relay。
///
/// `early_client` / `early_upstream` 是握手读取时残留在 Buffered 里的字节，
/// 必须先从对应方向喂给解析器，否则首帧会被丢掉。
#[allow(clippy::too_many_arguments)]
pub async fn relay<C, U>(
    client: &mut C,
    upstream: &mut U,
    early_client: &[u8],
    early_upstream: &[u8],
    plan: WsPlan,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut c2s = Relay::new(true, plan.has_replacements());
    let mut s2c = Relay::new(false, plan.has_replacements());

    if plan.block {
        send_close(client, 1008, false, b"blocked by WebSocket rule").await?;
        send_close(upstream, 1008, true, b"blocked by WebSocket rule").await?;
        let _ = client.shutdown().await;
        let _ = upstream.shutdown().await;
        return Ok(());
    }

    if !early_client.is_empty() {
        if c2s.feed(early_client, upstream, &plan).await? == WsFlow::Closed {
            let _ = client.shutdown().await;
        }
    }
    if !early_upstream.is_empty() {
        if s2c.feed(early_upstream, client, &plan).await? == WsFlow::Closed {
            let _ = upstream.shutdown().await;
        }
    }

    let mut cbuf = vec![0u8; 16 * 1024];
    let mut ubuf = vec![0u8; 16 * 1024];
    let mut client_eof = false;
    let mut upstream_eof = false;
    while !(client_eof && upstream_eof) {
        tokio::select! {
            r = client.read(&mut cbuf), if !client_eof => {
                match r {
                    Ok(0) => {
                        client_eof = true;
                        let _ = upstream.shutdown().await;
                    }
                    Ok(n) => {
                        if c2s.feed(&cbuf[..n], upstream, &plan).await? == WsFlow::Closed {
                            let _ = client.shutdown().await;
                            client_eof = true;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                        client_eof = true;
                        let _ = upstream.shutdown().await;
                    }
                    Err(e) => return Err(e),
                }
            }
            r = upstream.read(&mut ubuf), if !upstream_eof => {
                match r {
                    Ok(0) => {
                        upstream_eof = true;
                        let _ = client.shutdown().await;
                    }
                    Ok(n) => {
                        if s2c.feed(&ubuf[..n], client, &plan).await? == WsFlow::Closed {
                            let _ = upstream.shutdown().await;
                            upstream_eof = true;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                        upstream_eof = true;
                        let _ = client.shutdown().await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct VecWriter(Mutex<Vec<u8>>);

    impl AsyncWrite for VecWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn frame(fin: bool, opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
        encode_frame(fin, opcode, payload, masked)
    }

    fn decode_all(bytes: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while let Some((f, used)) = parse_frame(rest).unwrap() {
            rest = &rest[used..];
            out.push(f);
        }
        out
    }

    #[test]
    fn parses_fragments_and_control_frames() {
        let mut buf = frame(false, 0x1, b"hel", true);
        buf.extend_from_slice(&frame(true, 0x9, b"ping", true));
        buf.extend(frame(true, 0x0, b"lo", true));
        let frames = decode_all(&buf);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].payload, b"hel");
        assert_eq!(frames[1].opcode, 0x9);
        assert_eq!(frames[2].payload, b"lo");
    }

    #[tokio::test]
    async fn rewrites_text_message_and_remasks_client_frames() {
        let rules = WsRules::parse(&["ws-text-replace https://example.com/ws foo bar".into()]);
        let plan = rules.plan("example.com", "/ws");
        assert!(plan.active);
        let mut out = VecWriter::default();
        let mut c2s = Relay::new(true, true);
        let mut input = frame(false, 0x1, b"foo-", true);
        input.extend(frame(true, 0x0, b"foo", true));
        c2s.feed(&input, &mut out, &plan).await.unwrap();
        let frames = decode_all(&out.0.lock().unwrap());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"bar-bar");
        // 解码成功即说明客户端→上游帧的 mask 合法。
        assert_eq!(frames[0].opcode, 0x1);
    }

    #[tokio::test]
    async fn binary_and_ping_pass_through_unchanged() {
        let rules = WsRules::parse(&["ws-text-replace foo bar".into()]);
        let plan = rules.plan("example.com", "/ws");
        let mut out = VecWriter::default();
        let mut s2c = Relay::new(false, true);
        let mut input = frame(true, 0x2, b"foo", false);
        input.extend(frame(true, 0x9, b"x", false));
        s2c.feed(&input, &mut out, &plan).await.unwrap();
        let bytes = out.0.lock().unwrap().clone();
        assert_eq!(bytes, input);
    }

    #[tokio::test]
    async fn oversized_message_flushes_original_frames_then_streams() {
        let rules = WsRules::parse(&["ws-text-replace foo bar".into()]);
        let plan = rules.plan("example.com", "/ws");
        let mut out = VecWriter::default();
        let mut c2s = Relay::new(true, true);
        let big = vec![b'a'; WS_MESSAGE_LIMIT + 1];
        let input = frame(true, 0x1, &big, true);
        c2s.feed(&input, &mut out, &plan).await.unwrap();
        let bytes = out.0.lock().unwrap().clone();
        assert_eq!(bytes, input, "超限必须原帧透传");
    }

    #[tokio::test]
    async fn rewrites_64k_text_frame_and_upstream_frame_is_unmasked() {
        let rules = WsRules::parse(&["ws-text-replace foo bar".into()]);
        let plan = rules.plan("example.com", "/ws");
        let mut out = VecWriter::default();
        let mut s2c = Relay::new(false, true);
        let payload = vec![b'f'; 64 * 1024];
        let input = frame(true, 0x1, &payload, false);
        s2c.feed(&input, &mut out, &plan).await.unwrap();
        let bytes = out.0.lock().unwrap().clone();
        assert_eq!(bytes[1] & 0x80, 0, "上游→客户端帧不得掩码");
        let frames = decode_all(&bytes);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload.len(), 64 * 1024);
    }

    #[tokio::test]
    async fn close_codes_are_passed_through_unchanged() {
        for code in [1000u16, 1001u16] {
            let mut out = VecWriter::default();
            let mut c2s = Relay::new(true, true);
            let plan = WsPlan::default();
            let mut payload = code.to_be_bytes().to_vec();
            payload.extend_from_slice(b"bye");
            let input = frame(true, 0x8, &payload, true);
            let flow = c2s.feed(&input, &mut out, &plan).await.unwrap();
            assert_eq!(flow, WsFlow::Closed);
            assert_eq!(*out.0.lock().unwrap(), input);
        }
    }

    #[tokio::test]
    async fn block_sends_close_1008() {
        let rules = WsRules::parse(&["ws-block https://example.com/blocked".into()]);
        let plan = rules.plan("example.com", "/blocked");
        assert!(plan.block);
        let mut out = VecWriter::default();
        send_close(&mut out, 1008, false, b"blocked").await.unwrap();
        let frames = decode_all(&out.0.lock().unwrap());
        assert_eq!(frames[0].opcode, 0x8);
        assert_eq!(&frames[0].payload[..2], &1008u16.to_be_bytes());
    }
}
