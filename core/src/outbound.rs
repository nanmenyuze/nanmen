use crate::config::{Node, Target};
use crate::dns::DnsEngine;
use crate::engine::Action;
use crate::logging;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxStream = Box<dyn AsyncStream>;

/// 握手时与头部一起读到的「早到数据」必须保留：
/// 前缀读完后无缝接上底层流，而不是丢弃（ws/HTTP CONNECT 首包丢失的根因）。
pub struct PrefixedStream {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: BoxStream,
}

impl PrefixedStream {
    pub fn new(prefix: Vec<u8>, inner: BoxStream) -> Self {
        Self { prefix: std::io::Cursor::new(prefix), inner }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let pos = self.prefix.position() as usize;
        if pos < self.prefix.get_ref().len() {
            let remaining = &self.prefix.get_ref()[pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            let new_pos = pos as u64 + n as u64;
            self.prefix.set_position(new_pos);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn connect(
    action: &Action,
    nodes: &[Node],
    selected: Option<&str>,
    target: Target,
    dns: Option<&Arc<DnsEngine>>,
) -> io::Result<BoxStream> {
    match action {
        Action::Block => Err(io_err("被规则拦截")),
        Action::Direct => direct(&target, dns).await,
        Action::Proxy => {
            if nodes.is_empty() {
                return Err(io_err("没有可用节点，请先导入订阅"));
            }
            let mut ordered: Vec<&Node> = Vec::new();
            if let Some(name) = selected {
                if let Some(n) = nodes.iter().find(|n| n.name == name) {
                    ordered.push(n);
                }
            }
            for n in nodes.iter() {
                if ordered.iter().any(|x| std::ptr::eq(*x, n)) {
                    continue;
                }
                if ordered.len() >= 3 {
                    break;
                }
                ordered.push(n);
            }
            let mut last_err = io_err("没有可用节点，请先导入订阅");
            for (idx, node) in ordered.iter().enumerate() {
                match proxy(node, target.clone()).await {
                    Ok(s) => {
                        if idx > 0 {
                            logging::warn(
                                "proxy",
                                format!("首选节点失败，已回落到 {}", node.label()),
                            );
                        }
                        return Ok(s);
                    }
                    Err(e) => {
                        last_err = e;
                    }
                }
            }
            Err(last_err)
        }
        Action::Node(name) => {
            // M3：规则/策略组解析出的显式节点失效时必须报错，不能静默回落到当前选中节点。
            let node = nodes
                .iter()
                .find(|n| &n.name == name)
                .ok_or_else(|| io_err(format!("节点不存在: {}（引用已失效）", name)))?;
            proxy(node, target).await
        }
        Action::Group(name) => Err(io_err(format!("策略组未解析: {}", name))),
        Action::Missing(name) => Err(io_err(format!("策略引用不存在: {}", name))),
    }
}

async fn proxy(node: &Node, target: Target) -> io::Result<BoxStream> {
    let fut = async {
        match node.kind.as_str() {
            "ss" => crate::proto::ss::connect(node, target).await,
            "trojan" => crate::proto::trojan::connect(node, target).await,
            "vless" => crate::proto::vless::connect(node, target).await,
            "socks5" => crate::proto::socks::connect_socks5(node, target).await,
            "http" => crate::proto::socks::connect_http(node, target).await,
            other => Err(io_err(format!("不支持的节点类型: {}", other))),
        }
    };
    match tokio::time::timeout(Duration::from_secs(12), fut).await {
        Ok(r) => r,
        Err(_) => Err(io_err("代理连接超时")),
    }
}

async fn direct(target: &Target, dns: Option<&Arc<DnsEngine>>) -> io::Result<BoxStream> {
    // Fake-IP 只用于让流量进入 TUN，直连前必须还原真实地址；
    // 代理节点则直接接收域名，不做本地解析。
    let sock = if is_fake_ip(target.ip) {
        let Some(domain) = target.domain.as_deref() else {
            return Err(io_err("Fake-IP 缺少域名映射"));
        };
        // 优先走本地 DNS 引擎（加密上游 + 缓存 + rebind 防护），
        // 不再向物理网络系统 DNS 泄露直连域名；无引擎时才回退系统解析。
        let addrs = match dns {
            Some(d) => d
                .resolve_real(domain, target.port)
                .await
                .ok_or_else(|| io_err(format!("直连解析 {} 失败", domain)))?,
            None => resolve_all(domain, target.port).await?,
        };
        connect_any(&addrs).await?
    } else {
        // 已有真实 IP 就直接连该地址，不再重复解析（避免连到 CDN 的另一个节点）
        connect_any(&[SocketAddr::new(target.ip, target.port)]).await?
    };
    Ok(Box::new(sock))
}

pub async fn tcp_connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs = resolve_all(host, port).await?;
    connect_any(&addrs).await
}

pub async fn resolve(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| io_err(format!("解析 {} 失败: {}", host, e)))?;
    addrs.into_iter().next().ok_or_else(|| io_err("没有解析结果"))
}

/// 解析出多个地址（去重，最多 4 个），双栈下可依次尝试。
pub async fn resolve_all(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| io_err(format!("解析 {} 失败: {}", host, e)))?;
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in addrs {
        if !out.contains(&a) {
            out.push(a);
        }
        if out.len() >= 4 {
            break;
        }
    }
    if out.is_empty() {
        return Err(io_err("没有解析结果"));
    }
    Ok(out)
}

/// 单地址连接：2s 超时，成功后关 Nagle（交互式代理流量不能被 Nagle 拖延迟）。
/// 4s 对「不可达备选服务器」判死太慢：测速类 App 会串行试多个服务器，
/// 每个白等 4s 把出数时间越拖越长；国内正常服务器 TCP 握手极少超过 1s。
async fn connect_one(addr: SocketAddr) -> io::Result<TcpStream> {
    match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => {
            s.set_nodelay(true).ok();
            tune_tcp(&s);
            Ok(s)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io_err(format!("直连超时 {}", addr))),
    }
}

/// 上游空闲多久开始 keepalive 探测（秒）。
/// 运营商 NAT / 家用路由器的 TCP 映射通常空闲 3~5 分钟就被静默回收；
/// Linux 默认 keepalive 要 7200s 才发第一个探测，等于没有。
const UPSTREAM_KEEPALIVE_IDLE_SECS: libc::c_int = 60;
/// 探测间隔（秒）与探测次数：4 次无回应即判定对端死亡，总时长 ≈ 60s + 15s×4。
const UPSTREAM_KEEPALIVE_INTVL_SECS: libc::c_int = 15;
const UPSTREAM_KEEPALIVE_PROBES: libc::c_int = 4;
/// 有未确认数据时的内核级判死时间（毫秒）。默认 TCP 重传要 ~15 分钟才放弃，
/// 手机切网后中继任务会一直挂在这条死连接上，APP 侧只能干等到超时。
const UPSTREAM_USER_TIMEOUT_MS: libc::c_int = 120_000;

unsafe fn set_sockopt_int(fd: std::os::fd::RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
    // 必须取 value 的地址：直接把整数 as *const 会变成「地址 = 60」的野指针，
    // setsockopt 返回 EFAULT 但不会报错，选项静默不生效（编译期看不出来）。
    libc::setsockopt(
        fd,
        level,
        name,
        &value as *const libc::c_int as *const libc::c_void,
        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    );
}

/// 给所有上游 TCP 打开保活和判死超时。TUN 侧到 APP 是本机回环，没有 NAT；
/// 真正会被运营商静默掐掉的是「手机 -> 节点/目标站」这一段，必须在这里收紧。
/// 失败只忽略（不同内核个别选项可能不可用），不影响连接本身。
pub fn tune_tcp(stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    unsafe {
        set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
        set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, UPSTREAM_KEEPALIVE_IDLE_SECS);
        set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, UPSTREAM_KEEPALIVE_INTVL_SECS);
        set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, UPSTREAM_KEEPALIVE_PROBES);
        set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, UPSTREAM_USER_TIMEOUT_MS);
    }
}

/// 双地址并发竞速（happy-eyeballs 的简化版）：两边同时发起，先成功者胜出。
/// 串行等首个地址会让「双栈首个地址不可达」白等整个超时，慢启动正是这么来的。
async fn race_two(a: SocketAddr, b: SocketAddr) -> io::Result<TcpStream> {
    let mut fa = Box::pin(connect_one(a));
    let mut fb = Box::pin(connect_one(b));
    tokio::select! {
        r = fa.as_mut() => match r {
            Ok(s) => Ok(s),
            // 先返回失败不代表另一个也失败：另一个一直在并发跑，等它出结果。
            Err(e1) => fb.await.map_err(|_| e1),
        },
        r = fb.as_mut() => match r {
            Ok(s) => Ok(s),
            Err(e2) => fa.await.map_err(|_| e2),
        },
    }
}

pub async fn connect_any(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    // v4 优先（stable sort，同族内保持原顺序）：竞速名额只有两个，
    // 若按 getaddrinfo 原序取前两个，可能全是不可达 v6（含污染结果），
    // 可用 v4 被挤在名额外，只能白等超时后失败。
    let mut ordered: Vec<SocketAddr> = addrs.to_vec();
    ordered.sort_by_key(|a| a.is_ipv6());
    let cands: Vec<SocketAddr> = ordered.iter().take(2).copied().collect();
    match cands.as_slice() {
        [] => Err(io_err("没有可用地址")),
        [one] => connect_one(*one).await,
        [a, b] => race_two(*a, *b).await,
        _ => unreachable!("take(2) 保证最多两个候选地址"),
    }
}

pub fn is_fake_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 198 && (o[1] == 18 || o[1] == 19)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfc00 && s[1] == 1 && s[2] == 0 && s[3] == 1
        }
    }
}

pub fn io_err(msg: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.to_string())
}


/// 通过真实节点探测一个测速 URL。只测 TCP/HTTP 路径；调用方必须把结果写入 TCP 健康状态，
/// 不能据此宣称同一节点的 UDP 可用。
pub async fn probe_node(node: &Node, url: &str, timeout: Duration) -> io::Result<u16> {
    let parsed = url::Url::parse(url).map_err(|e| io_err(format!("测速 URL 无效: {}", e)))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| io_err("测速 URL 缺少主机"))?
        .to_string();
    let port = parsed.port_or_known_default().ok_or_else(|| io_err("测速 URL 缺少端口"))?;
    let https = parsed.scheme() == "https";
    let path = if parsed.query().is_some() {
        format!("{}?{}", parsed.path(), parsed.query().unwrap_or(""))
    } else if parsed.path().is_empty() {
        "/".to_string()
    } else {
        parsed.path().to_string()
    };
    let target = Target {
        // 域名交给协议层发送；ip 只作为 target 结构占位。
        ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        port,
        domain: Some(host.clone()),
    };
    let fut = async move {
        let stream = proxy(node, target).await?;
        let mut stream: BoxStream = if https {
            wrap_tls(stream, &host, false).await?
        } else {
            stream
        };
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NamuDNS-HealthCheck/1\r\nConnection: close\r\n\r\n",
            path, host
        );
        stream.write_all(req.as_bytes()).await?;
        let mut buf = [0u8; 64];
        let mut read = 0usize;
        loop {
            let n = stream.read(&mut buf[read..]).await?;
            if n == 0 {
                break;
            }
            read += n;
            if buf[..read].windows(2).any(|w| w == b"\r\n") || read >= buf.len() {
                break;
            }
        }
        if read == 0 {
            return Err(io_err("测速 URL 未返回数据"));
        }
        let first = String::from_utf8_lossy(&buf[..read]);
        let code: u16 = first
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io_err("测速 URL 返回非 HTTP 响应"))?;
        if (200..400).contains(&code) {
            Ok(code)
        } else {
            Err(io_err(format!("测速 URL 返回 HTTP {}", code)))
        }
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| io_err("健康检查超时"))?
}

async fn wrap_tls(stream: BoxStream, sni: &str, insecure: bool) -> io::Result<BoxStream> {
    let config = if insecure { TLS_INSECURE.clone() } else { TLS_SECURE.clone() };
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = server_name(sni)?;
    let tls = tokio::time::timeout(Duration::from_secs(8), connector.connect(name, stream))
        .await
        .map_err(|_| io_err("TLS 握手超时"))?
        .map_err(|e| io_err(format!("TLS 握手失败: {}", e)))?;
    Ok(Box::new(tls))
}

// ---------------- TLS ----------------

#[derive(Debug)]
struct NoVerifier {
    schemes: Vec<rustls::SignatureScheme>,
}

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

/// TLS 配置全局缓存：根证书库解析开销大，不能每条连接都重建。
static TLS_SECURE: once_cell::sync::Lazy<Arc<rustls::ClientConfig>> = once_cell::sync::Lazy::new(|| {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
});

static TLS_INSECURE: once_cell::sync::Lazy<Arc<rustls::ClientConfig>> = once_cell::sync::Lazy::new(|| {
    let provider = rustls::crypto::ring::default_provider();
    let schemes = provider.signature_verification_algorithms.supported_schemes();
    let verifier = Arc::new(NoVerifier { schemes });
    Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    )
});

pub async fn tls_connect(host: &str, port: u16, sni: &str, insecure: bool) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = tcp_connect(host, port).await?;
    let config = if insecure { TLS_INSECURE.clone() } else { TLS_SECURE.clone() };
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = server_name(sni)?;
    let tls = tokio::time::timeout(Duration::from_secs(8), connector.connect(name, tcp))
        .await
        .map_err(|_| io_err("TLS 握手超时"))?
        .map_err(|e| io_err(format!("TLS 握手失败: {}", e)))?;
    logging::info("tls", format!("已建立 TLS: {}:{} ({})", host, port, sni));
    Ok(tls)
}

/// MITM 上游 TLS：HTTP/1.1 路径只提 http/1.1；h2 路径单独提 h2，
/// 避免真实服务器协商到无法解析的协议。
static MITM_TLS_SECURE: once_cell::sync::Lazy<Arc<rustls::ClientConfig>> =
    once_cell::sync::Lazy::new(|| {
        let mut c = TLS_SECURE.as_ref().clone();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(c)
    });

static MITM_TLS_INSECURE: once_cell::sync::Lazy<Arc<rustls::ClientConfig>> =
    once_cell::sync::Lazy::new(|| {
        let mut c = TLS_INSECURE.as_ref().clone();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(c)
    });

static MITM_TLS_H2_SECURE: once_cell::sync::Lazy<Arc<rustls::ClientConfig>> =
    once_cell::sync::Lazy::new(|| {
        let mut c = TLS_SECURE.as_ref().clone();
        c.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(c)
    });

static MITM_TLS_H2_INSECURE: once_cell::sync::Lazy<Arc<rustls::ClientConfig>> =
    once_cell::sync::Lazy::new(|| {
        let mut c = TLS_INSECURE.as_ref().clone();
        c.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(c)
    });

/// 在已建立的出站流（直连 TCP 或代理隧道）上叠加到真实服务器的 TLS。
pub async fn tls_wrap(
    stream: BoxStream,
    sni: &str,
    insecure: bool,
) -> io::Result<tokio_rustls::client::TlsStream<BoxStream>> {
    let config = if insecure { MITM_TLS_INSECURE.clone() } else { MITM_TLS_SECURE.clone() };
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = server_name(sni)?;
    let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, stream))
        .await
        .map_err(|_| io_err("MITM 上游 TLS 握手超时"))?
        .map_err(|e| io_err(format!("MITM 上游 TLS 握手失败: {}", e)))?;
    Ok(tls)
}

/// MITM h2 上游：必须协商到 h2，否则降级回 HTTP/1.1 的字节流不能交给 h2 解析。
pub async fn tls_wrap_h2(
    stream: BoxStream,
    sni: &str,
    insecure: bool,
) -> io::Result<tokio_rustls::client::TlsStream<BoxStream>> {
    let config = if insecure { MITM_TLS_H2_INSECURE.clone() } else { MITM_TLS_H2_SECURE.clone() };
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = server_name(sni)?;
    let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, stream))
        .await
        .map_err(|_| io_err("MITM h2 上游 TLS 握手超时"))?
        .map_err(|e| io_err(format!("MITM h2 上游 TLS 握手失败: {}", e)))?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(io_err("MITM h2 上游未协商到 h2"));
    }
    Ok(tls)
}

fn server_name(sni: &str) -> io::Result<rustls::pki_types::ServerName<'static>> {
    if let Ok(ip) = sni.parse::<IpAddr>() {
        return Ok(rustls::pki_types::ServerName::IpAddress(ip.into()));
    }
    rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|e| io_err(format!("非法 SNI {}: {}", sni, e)))
}

// ---------------- 地址编码 ----------------

pub fn encode_socks_addr(buf: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    if let Some(domain) = &target.domain {
        // 长度字节只有 8 位：超长域名必须拒绝，不能截断长度却写入全部字节（协议流会错位）。
        if domain.len() > 255 {
            return Err(io_err("域名超过 255 字节，无法编码"));
        }
        buf.push(0x03);
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain.as_bytes());
    } else {
        match target.ip {
            IpAddr::V4(v4) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(0x04);
                buf.extend_from_slice(&v6.octets());
            }
        }
    }
    buf.extend_from_slice(&(target.port).to_be_bytes());
    Ok(())
}

/// VLESS 地址类型：1=IPv4, 2=域名, 3=IPv6
pub fn encode_vless_addr(buf: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    // VLESS 规范与 SOCKS5 不同：端口写在地址类型/地址之前（port-then-address）。
    buf.extend_from_slice(&(target.port).to_be_bytes());
    if let Some(domain) = &target.domain {
        if domain.len() > 255 {
            return Err(io_err("域名超过 255 字节，无法编码"));
        }
        buf.push(0x02);
        // VLESS 域名长度是 1 字节（与 SOCKS5 一致），不是 2 字节。
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain.as_bytes());
    } else {
        match target.ip {
            IpAddr::V4(v4) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(0x03);
                buf.extend_from_slice(&v6.octets());
            }
        }
    }
    Ok(())
}

/// 解析 SOCKS5 地址（ATYP + ADDR + PORT），返回域名/IP、端口与负载起始偏移。
pub fn parse_socks_addr_bytes(
    buf: &[u8],
    offset: usize,
) -> io::Result<(Option<String>, IpAddr, u16, usize)> {
    let mut i = offset;
    let atyp = *buf.get(i).ok_or_else(|| io_err("地址长度不足"))?;
    i += 1;
    let (domain, ip) = match atyp {
        0x01 => {
            let b = buf.get(i..i + 4).ok_or_else(|| io_err("IPv4 地址长度不足"))?;
            i += 4;
            (
                None,
                IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])),
            )
        }
        0x03 => {
            let len = *buf.get(i).ok_or_else(|| io_err("域名长度不足"))? as usize;
            i += 1;
            let b = buf.get(i..i + len).ok_or_else(|| io_err("域名长度不足"))?;
            i += len;
            let d = String::from_utf8_lossy(b).to_string();
            if d.is_empty() {
                return Err(io_err("空域名"));
            }
            (Some(d), IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        }
        0x04 => {
            let b = buf.get(i..i + 16).ok_or_else(|| io_err("IPv6 地址长度不足"))?;
            i += 16;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            (None, IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        other => return Err(io_err(format!("未知地址类型: {}", other))),
    };
    let port_bytes = buf.get(i..i + 2).ok_or_else(|| io_err("端口长度不足"))?;
    i += 2;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    Ok((domain, ip, port, i))
}

pub fn display_target(t: &Target) -> String {
    match &t.domain {
        Some(d) => format!("{}:{}", d, t.port),
        None => format!("{}:{}", t.ip, t.port),
    }
}

#[cfg(test)]
mod keepalive_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    unsafe fn get_sockopt_int(fd: std::os::fd::RawFd, level: libc::c_int, name: libc::c_int) -> libc::c_int {
        let mut v: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            level,
            name,
            &mut v as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        );
        assert_eq!(rc, 0, "getsockopt {} 失败", name);
        v
    }

    #[tokio::test]
    async fn tune_tcp_options_are_actually_applied() {
        // 只断言常量不够：setsockopt 的指针参数写错会静默失败，
        // 必须用 getsockopt 回读，确认内核真的收下了。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        tune_tcp(&client);
        let fd = client.as_raw_fd();
        unsafe {
            assert_eq!(get_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
            assert_eq!(
                get_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE),
                UPSTREAM_KEEPALIVE_IDLE_SECS
            );
            assert_eq!(
                get_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL),
                UPSTREAM_KEEPALIVE_INTVL_SECS
            );
            assert_eq!(
                get_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT),
                UPSTREAM_KEEPALIVE_PROBES
            );
            assert_eq!(
                get_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT),
                UPSTREAM_USER_TIMEOUT_MS
            );
        }
        drop(listener);
    }

    #[test]
    fn upstream_keepalive_beats_nat_expiry() {
        // 运营商 NAT 空闲映射 3~5 分钟就没了：探测必须明显早于它。
        assert!(UPSTREAM_KEEPALIVE_IDLE_SECS <= 60);
        assert!(UPSTREAM_KEEPALIVE_INTVL_SECS <= 30);
        assert!(UPSTREAM_KEEPALIVE_PROBES >= 3);
        // 判死不能拖回默认 TCP 的 15 分钟：手机切网后中继必须尽快释放。
        assert!(UPSTREAM_USER_TIMEOUT_MS <= 180_000);
    }
}
