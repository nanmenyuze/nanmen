//! MITM 用的最小 HTTP/1.1 解析与组帧：keep-alive、content-length、chunked、
//! gzip/deflate 解码。只服务 MITM 连接，不影响内核其他路径。
//!
//! 设计约束：
//! - 头部上限 64KB；请求体默认流式转发，不再整体读入内存。
//! - 响应体改写上限由 MitmEngine.body_limit 控制；压缩前、解压后和改写后的
//!   输出都受该上限约束，超限时原样透传（保持原始组帧，不做任何解码）。
//! - 解析失败一律返回错误由上层断连/放行，绝不 panic。

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_HEAD: usize = 64 * 1024;
pub const MAX_REQ_BODY: usize = 8 * 1024 * 1024;

pub type Headers = Vec<(String, String)>;

/// 请求体组帧：None 表示无正文；Length 保留 Content-Length；Chunked 原样转发 chunk。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyKind {
    None,
    Length(u64),
    Chunked,
}

/// 请求头解析结果：正文尚未读取，交给转发层流式搬运。
#[derive(Clone)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    pub headers: Headers,
    pub keep_alive: bool,
    pub body: BodyKind,
}

pub fn get_header<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn set_header(headers: &mut Headers, name: &str, value: &str) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    headers.push((name.to_string(), value.to_string()));
}

pub fn remove_header(headers: &mut Headers, name: &str) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
}

fn io_err(msg: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// 带残留缓冲的流读取器：keep-alive 下同一连接可能粘着下一个请求的字节。
pub struct Buffered<S> {
    pub stream: S,
    pub buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Buffered<S> {
    pub fn new(stream: S) -> Self {
        Self { stream, buf: Vec::new() }
    }

    async fn fill(&mut self) -> io::Result<usize> {
        let mut tmp = [0u8; 8192];
        let n = self.stream.read(&mut tmp).await?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    /// 读到 \r\n\r\n 为止，返回完整头部（含终止符）；连接干净关闭返回 None。
    pub async fn read_head(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut scan_from = 0usize;
        loop {
            if let Some(pos) = find_head_end_from(&self.buf, scan_from) {
                let head = self.buf[..pos + 4].to_vec();
                self.buf.drain(..pos + 4);
                return Ok(Some(head));
            }
            // 下次只从“上次末尾回退 3 字节”开始扫，覆盖跨块拼接的 \r\n\r\n。
            scan_from = self.buf.len().saturating_sub(3);
            if self.buf.len() > MAX_HEAD {
                return Err(io_err("HTTP 头部超过 64KB"));
            }
            if self.fill().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io_err("连接在头部中途关闭"))
                };
            }
        }
    }

    pub async fn read_n(&mut self, n: usize) -> io::Result<Vec<u8>> {
        while self.buf.len() < n {
            if self.fill().await? == 0 {
                return Err(io_err("连接在正文中途关闭"));
            }
        }
        let out = self.buf[..n].to_vec();
        self.buf.drain(..n);
        Ok(out)
    }

    /// 读到 EOF，最多 limit+1 字节；返回 (数据, 是否超限)。
    pub async fn read_to_end_limit(&mut self, limit: usize) -> io::Result<(Vec<u8>, bool)> {
        while self.buf.len() <= limit {
            if self.fill().await? == 0 {
                let out = std::mem::take(&mut self.buf);
                return Ok((out, false));
            }
        }
        let out = std::mem::take(&mut self.buf);
        Ok((out, true))
    }

    /// 透传恰好 n 字节正文（先消耗残留缓冲，再从流里补齐）。
    pub async fn pipe_n<W: AsyncWrite + Unpin>(&mut self, out: &mut W, n: u64) -> io::Result<()> {
        let from_buf = (self.buf.len() as u64).min(n);
        if from_buf > 0 {
            out.write_all(&self.buf[..from_buf as usize]).await?;
            self.buf.drain(..from_buf as usize);
        }
        let rest = n - from_buf;
        if rest > 0 {
            tokio::io::copy(&mut (&mut self.stream).take(rest), out).await?;
        }
        out.flush().await
    }

    /// 把残留缓冲 + 剩余流原样写给对端（透传路径）。
    pub async fn pipe_rest<W: AsyncWrite + Unpin>(&mut self, out: &mut W) -> io::Result<()> {
        if !self.buf.is_empty() {
            out.write_all(&self.buf).await?;
            self.buf.clear();
        }
        tokio::io::copy(&mut self.stream, out).await?;
        out.flush().await
    }
}

fn find_head_end_from(buf: &[u8], from: usize) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let start = from.min(buf.len().saturating_sub(3));
    buf[start..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| start + i)
}

// ---------------- 请求 ----------------

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

fn parse_headers(raw: &[httparse::Header<'_>]) -> Headers {
    raw.iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).trim().to_string(),
            )
        })
        .collect()
}

fn chunked(headers: &Headers) -> bool {
    get_header(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

fn content_length(headers: &Headers) -> Option<u64> {
    get_header(headers, "content-length")?.trim().parse().ok()
}

fn request_body_kind(headers: &Headers) -> io::Result<BodyKind> {
    let mut content_length: Option<u64> = None;
    let mut has_te = false;
    let mut te_chunked = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            let raw = value.trim();
            let n: u64 = raw
                .parse()
                .map_err(|_| io_err(format!("非法 Content-Length: {}", raw)))?;
            if let Some(old) = content_length {
                if old != n {
                    return Err(io_err("冲突的 Content-Length"));
                }
            }
            content_length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            has_te = true;
            if value.to_ascii_lowercase().contains("chunked") {
                te_chunked = true;
            }
        }
    }
    if has_te && content_length.is_some() {
        // 同时出现两种长度语义是典型的请求走私入口，直接判错而不是猜一个。
        return Err(io_err("Content-Length 与 Transfer-Encoding 不能同时出现"));
    }
    if has_te {
        if te_chunked {
            return Ok(BodyKind::Chunked);
        }
        return Err(io_err("不支持的 Transfer-Encoding"));
    }
    match content_length {
        Some(0) => Ok(BodyKind::None),
        Some(n) => Ok(BodyKind::Length(n)),
        None => Ok(BodyKind::None),
    }
}

/// 只解析请求头，不读取正文；调用方按 URL 命中规则后再决定拒绝或流式转发。
pub async fn read_request_head<S: AsyncRead + Unpin>(
    io: &mut Buffered<S>,
) -> io::Result<Option<RequestHead>> {
    let Some(head) = io.read_head().await? else {
        return Ok(None);
    };
    let mut hdrs = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut hdrs);
    match req.parse(&head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(io_err("HTTP 请求解析失败")),
    }
    let method = req.method.unwrap_or("GET").to_string();
    let path = req.path.unwrap_or("/").to_string();
    let headers = parse_headers(req.headers);
    let keep_alive = match get_header(&headers, "connection") {
        Some(v) if v.eq_ignore_ascii_case("close") => false,
        Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
        _ => true, // HTTP/1.1 默认长连接
    };
    let body = request_body_kind(&headers)?;
    Ok(Some(RequestHead { method, path, headers, keep_alive, body }))
}

/// 按组帧读取完整请求体并解码 chunked；超过 limit 返回错误，由调用方决定回退。
pub async fn read_body_limited<S: AsyncRead + Unpin>(
    io: &mut Buffered<S>,
    kind: BodyKind,
    limit: usize,
) -> io::Result<Vec<u8>> {
    match kind {
        BodyKind::None => Ok(Vec::new()),
        BodyKind::Length(n) => {
            if n > limit as u64 {
                return Err(io_err("请求体超过改写上限"));
            }
            io.read_n(n as usize).await
        }
        BodyKind::Chunked => read_chunked_body(io, limit).await,
    }
}

/// 兼容旧调用方/测试：解析头并读出完整请求体（仅测试与小请求使用）。
pub async fn read_request<S: AsyncRead + Unpin>(
    io: &mut Buffered<S>,
) -> io::Result<Option<Request>> {
    let Some(head) = read_request_head(io).await? else {
        return Ok(None);
    };
    let RequestHead { method, path, headers, keep_alive, body: kind } = head;
    let body = match kind {
        BodyKind::None => Vec::new(),
        BodyKind::Chunked => read_chunked_body(io, MAX_REQ_BODY).await?,
        BodyKind::Length(len) => {
            if len > MAX_REQ_BODY as u64 {
                return Err(io_err("请求体超过 8MB"));
            }
            io.read_n(len as usize).await?
        }
    };
    Ok(Some(Request { method, path, headers, body, keep_alive }))
}

/// 从流里读 chunked 正文并解码（请求体用；响应体透传时不解码）。
async fn read_chunked_body<S: AsyncRead + Unpin>(
    io: &mut Buffered<S>,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        //  chunk-size 行
        let line = read_line(io, 1024).await?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| io_err(format!("非法 chunk 长度: {}", size_str)))?;
        if size == 0 {
            // trailer：读到空行为止（可能没有 trailer，直接 \r\n）
            loop {
                let l = read_line(io, MAX_HEAD).await?;
                if l.is_empty() {
                    break;
                }
            }
            return Ok(out);
        }
        if out.len() + size > limit {
            return Err(io_err("chunked 正文超过上限"));
        }
        let mut chunk = io.read_n(size).await?;
        out.append(&mut chunk);
        let crlf = io.read_n(2).await?;
        if crlf != b"\r\n" {
            return Err(io_err("chunk 结尾缺少 CRLF"));
        }
    }
}

async fn read_line<S: AsyncRead + Unpin>(io: &mut Buffered<S>, limit: usize) -> io::Result<String> {
    loop {
        if let Some(pos) = io.buf.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&io.buf[..pos]).to_string();
            io.buf.drain(..pos + 2);
            return Ok(line);
        }
        if io.buf.len() > limit {
            return Err(io_err("行超长"));
        }
        if io.fill().await? == 0 {
            return Err(io_err("连接在行中途关闭"));
        }
    }
}

pub fn serialize_request(req: &Request) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + req.body.len());
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method, req.path).as_bytes());
    for (k, v) in &req.headers {
        out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);
    out
}

/// 只序列化请求头；正文由 forward_request_body 流式写到上游。
pub fn serialize_request_head(req: &RequestHead) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method, req.path).as_bytes());
    for (k, v) in &req.headers {
        out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// 是否是 HTTP Upgrade 请求（WebSocket 等）。
pub fn is_upgrade_request(headers: &Headers) -> bool {
    get_header(headers, "upgrade").is_some()
        && get_header(headers, "connection")
            .map(|v| {
                v.to_ascii_lowercase()
                    .split(',')
                    .any(|s| s.trim() == "upgrade")
            })
            .unwrap_or(false)
}

/// 是否是 101 Switching Protocols 响应。
pub fn is_upgrade_response(headers: &Headers) -> bool {
    get_header(headers, "upgrade").is_some()
        && get_header(headers, "connection")
            .map(|v| {
                v.to_ascii_lowercase()
                    .split(',')
                    .any(|s| s.trim() == "upgrade")
            })
            .unwrap_or(false)
}

/// 日志用路径：去掉查询串，避免临时签名/token 进入运行日志和诊断报告。
pub fn redact_path(path: &str) -> String {
    path.split('?').next().unwrap_or(path).to_string()
}

/// 把请求正文从客户端流式搬到上游；不缓存整个请求体。
pub async fn forward_request_body<S, W>(
    io: &mut Buffered<S>,
    out: &mut W,
    body: BodyKind,
) -> io::Result<()>
where
    S: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        BodyKind::None => Ok(()),
        BodyKind::Length(n) => io.pipe_n(out, n).await,
        BodyKind::Chunked => stream_chunked_body(io, out).await,
    }
}

/// chunked 请求体原样流式转发：chunk 头、数据、结尾和 trailer 都保留。
async fn stream_chunked_body<S, W>(io: &mut Buffered<S>, out: &mut W) -> io::Result<()>
where
    S: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let line = read_line(io, 1024).await?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| io_err(format!("非法 chunk 长度: {}", size_str)))?;
        out.write_all(line.as_bytes()).await?;
        out.write_all(b"\r\n").await?;
        if size == 0 {
            loop {
                let trailer = read_line(io, MAX_HEAD).await?;
                out.write_all(trailer.as_bytes()).await?;
                out.write_all(b"\r\n").await?;
                if trailer.is_empty() {
                    return Ok(());
                }
            }
        }
        // 直接按 size 搬运，避免把大 chunk 先读进 Vec。
        io.pipe_n(out, size as u64).await?;
        let crlf = io.read_n(2).await?;
        if crlf != b"\r\n" {
            return Err(io_err("chunk 结尾缺少 CRLF"));
        }
        out.write_all(b"\r\n").await?;
    }
}

// ---------------- 响应 ----------------

pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub headers: Headers,
}

#[derive(Debug, PartialEq)]
pub enum Framing {
    Length(u64),
    Chunked,
    Eof,
    None,
}

pub fn response_framing(head: &ResponseHead, req_method: &str) -> Framing {
    if req_method.eq_ignore_ascii_case("HEAD")
        || head.status == 204
        || head.status == 304
        || (100..200).contains(&head.status)
    {
        return Framing::None;
    }
    if chunked(&head.headers) {
        return Framing::Chunked;
    }
    if let Some(len) = content_length(&head.headers) {
        return Framing::Length(len);
    }
    Framing::Eof
}

pub async fn read_response_head<S: AsyncRead + Unpin>(
    io: &mut Buffered<S>,
) -> io::Result<ResponseHead> {
    let head = io
        .read_head()
        .await?
        .ok_or_else(|| io_err("上游未返回响应即关闭"))?;
    let mut hdrs = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut hdrs);
    match resp.parse(&head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(io_err("HTTP 响应解析失败")),
    }
    Ok(ResponseHead {
        status: resp.code.unwrap_or(200),
        reason: resp.reason.unwrap_or("OK").to_string(),
        headers: parse_headers(resp.headers),
    })
}

/// 解码完整接收的 chunked 原始字节（改写路径用；不完整返回 None）。
pub fn decode_chunked(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut p = 0usize;
    loop {
        let eol = raw[p..].windows(2).position(|w| w == b"\r\n")? + p;
        let size_str = std::str::from_utf8(&raw[p..eol]).ok()?.split(';').next()?.trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        p = eol + 2;
        if size == 0 {
            return Some(out); // trailer 丢弃
        }
        if p + size + 2 > raw.len() {
            return None;
        }
        out.extend_from_slice(&raw[p..p + size]);
        if &raw[p + size..p + size + 2] != b"\r\n" {
            return None;
        }
        p += size + 2;
    }
}

/// 内容编码解码：gzip / deflate / identity；br 等不支持的返回 None（上层透传）。
pub fn decode_content(body: &[u8], encoding: &str) -> Option<Vec<u8>> {
    decode_content_limited(body, encoding, usize::MAX)
}

/// 带解压输出上限的版本：解压后超过 limit 返回 None，调用方原样透传。
pub fn decode_content_limited(body: &[u8], encoding: &str, limit: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    fn read_limited<R: Read>(reader: R, limit: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut capped = reader.take(limit.saturating_add(1) as u64);
        capped.read_to_end(&mut out).ok()?;
        if out.len() > limit {
            None
        } else {
            Some(out)
        }
    }
    let enc = encoding.trim().to_ascii_lowercase();
    match enc.as_str() {
        "" | "identity" => Some(body.to_vec()),
        "gzip" => read_limited(flate2::read::GzDecoder::new(body), limit),
        "deflate" => {
            if let Some(out) = read_limited(flate2::read::ZlibDecoder::new(body), limit) {
                return Some(out);
            }
            // 有些服务器发裸 deflate 流；zlib 失败时再试一次。
            read_limited(flate2::read::DeflateDecoder::new(body), limit)
        }
        _ => None,
    }
}

pub fn gzip_encode(body: &[u8]) -> io::Result<Vec<u8>> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(body)?;
    e.finish()
}

pub fn serialize_response(status: u16, reason: &str, headers: &Headers, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status, reason).as_bytes());
    for (k, v) in headers {
        out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// 1x1 透明 GIF（reject-tinygif 用，43 字节标准像素）。
pub const TINY_GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_decode_basic() {
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(raw).unwrap(), b"Wikipedia");
        // 带 trailer 与 chunk 扩展
        let raw2 = b"3;ext=1\r\nabc\r\n0\r\nX-T: v\r\n\r\n";
        assert_eq!(decode_chunked(raw2).unwrap(), b"abc");
        assert!(decode_chunked(b"5\r\nab").is_none());
    }

    #[test]
    fn gzip_roundtrip() {
        let body = br#"{"items":[1,2],"ad_items":[9]}"#;
        let enc = gzip_encode(body).unwrap();
        assert_eq!(decode_content(&enc, "gzip").unwrap(), body);
        assert_eq!(decode_content(body, "identity").unwrap(), body);
        assert!(decode_content(body, "br").is_none());
    }

    #[tokio::test]
    async fn request_parse_keepalive_and_leftover() {
        let data = b"GET /a HTTP/1.1\r\nHost: x.com\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\nHost: x.com\r\nConnection: close\r\n\r\n";
        let cursor = std::io::Cursor::new(data.to_vec());
        let mut io = Buffered::new(cursor);
        let r1 = read_request(&mut io).await.unwrap().unwrap();
        assert_eq!(r1.path, "/a");
        assert_eq!(r1.body, b"abc");
        assert!(r1.keep_alive);
        let r2 = read_request(&mut io).await.unwrap().unwrap();
        assert_eq!(r2.path, "/b");
        assert!(!r2.keep_alive);
        assert!(read_request(&mut io).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn request_chunked_body() {
        let data = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let mut io = Buffered::new(std::io::Cursor::new(data.to_vec()));
        let r = read_request(&mut io).await.unwrap().unwrap();
        assert_eq!(r.body, b"abcde");
    }

    #[test]
    fn head_end_scan_can_resume_with_overlap() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let end = find_head_end_from(buf, 0).unwrap();
        assert_eq!(find_head_end_from(buf, end.saturating_sub(3)), Some(end));
        assert_eq!(find_head_end_from(buf, buf.len()), None);
        // 不足 4 字节时不会 panic
        assert_eq!(find_head_end_from(b"abc", 0), None);
    }

    #[test]
    fn framing_rules() {
        let mk = |status: u16, hs: Headers| ResponseHead { status, reason: "OK".into(), headers: hs };
        assert_eq!(response_framing(&mk(204, vec![]), "GET"), Framing::None);
        assert_eq!(response_framing(&mk(200, vec![]), "HEAD"), Framing::None);
        assert_eq!(
            response_framing(&mk(200, vec![("Content-Length".into(), "5".into())]), "GET"),
            Framing::Length(5)
        );
        assert_eq!(
            response_framing(&mk(200, vec![("Transfer-Encoding".into(), "chunked".into())]), "GET"),
            Framing::Chunked
        );
        assert_eq!(response_framing(&mk(200, vec![]), "GET"), Framing::Eof);
    }

    #[test]
    fn header_helpers() {
        let mut h: Headers = vec![("Content-Type".into(), "application/json".into())];
        set_header(&mut h, "content-type", "text/plain");
        assert_eq!(h.len(), 1);
        assert_eq!(get_header(&h, "Content-Type"), Some("text/plain"));
        remove_header(&mut h, "CONTENT-TYPE");
        assert!(h.is_empty());
    }

    #[test]
    fn path_log_redacts_query() {
        assert_eq!(redact_path("/api/list?token=secret&x=1"), "/api/list");
        assert_eq!(redact_path("/plain"), "/plain");
    }

    #[tokio::test]
    async fn request_head_accepts_large_content_length_without_reading_body() {
        let data = b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 9000000\r\n\r\n";
        let mut io = Buffered::new(std::io::Cursor::new(data.to_vec()));
        let head = read_request_head(&mut io).await.unwrap().unwrap();
        assert_eq!(head.body, BodyKind::Length(9_000_000));
        assert!(io.buf.is_empty());
    }

    #[tokio::test]
    async fn request_head_rejects_bad_content_length() {
        let data = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 12x\r\n\r\n";
        let mut io = Buffered::new(std::io::Cursor::new(data.to_vec()));
        assert!(read_request_head(&mut io).await.is_err());

        let data = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let mut io = Buffered::new(std::io::Cursor::new(data.to_vec()));
        assert!(read_request_head(&mut io).await.is_err());
    }

    #[tokio::test]
    async fn request_body_streams_length_and_chunked() {
        let data = b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc";
        let mut io = Buffered::new(std::io::Cursor::new(data.to_vec()));
        let head = read_request_head(&mut io).await.unwrap().unwrap();
        let mut out = Vec::new();
        forward_request_body(&mut io, &mut out, head.body).await.unwrap();
        assert_eq!(out, b"abc");

        let data = b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3;e=1\r\nabc\r\n0\r\nX-T: v\r\n\r\n";
        let mut io = Buffered::new(std::io::Cursor::new(data.to_vec()));
        let head = read_request_head(&mut io).await.unwrap().unwrap();
        let mut out = Vec::new();
        forward_request_body(&mut io, &mut out, head.body).await.unwrap();
        assert_eq!(out, b"3;e=1\r\nabc\r\n0\r\nX-T: v\r\n\r\n");
    }

    #[test]
    fn decompress_limit_blocks_bomb() {
        let body = vec![b'a'; 1024 * 1024];
        let enc = gzip_encode(&body).unwrap();
        assert!(decode_content_limited(&enc, "gzip", 4096).is_none());
        assert_eq!(decode_content_limited(&enc, "gzip", 2 * 1024 * 1024).unwrap().len(), body.len());
    }

    #[test]
    fn upgrade_helpers() {
        let h: Headers = vec![
            ("Connection".into(), "keep-alive, Upgrade".into()),
            ("Upgrade".into(), "websocket".into()),
        ];
        assert!(is_upgrade_request(&h));
        assert!(is_upgrade_response(&h));
    }
}
