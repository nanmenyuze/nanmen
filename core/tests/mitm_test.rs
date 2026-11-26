//! MITM 端到端集成测试：
//! 本地 TLS 源站 ←(真实 TLS)← MITM 编排 ←(duplex + 信任测试 CA 的 TLS 客户端)← 测试
//! 覆盖：URL 拒绝、JSON 响应体改写、gzip 响应改写、普通透传、keep-alive、
//! 握手失败自动放行、统计计数。

use nanmen_core::config::Target;
use nanmen_core::engine::Action;
use nanmen_core::mitm::http1::{self, Buffered};
use nanmen_core::mitm::{MitmConfig, MitmRuleConf, MitmState};
use nanmen_core::netstack::Ctx;
use nanmen_core::script::{ScriptMessage, ScriptPhase, ScriptRuleConf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::AsyncWriteExt;
fn tmp_ca(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("namu_mitm_e2e_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name).to_string_lossy().to_string();
    let _ = std::fs::remove_file(&p);
    p
}

fn rule(pattern: &str, action: &str, body_pattern: &str, replacement: &str) -> MitmRuleConf {
    MitmRuleConf {
        pattern: pattern.into(),
        action: action.into(),
        body_pattern: body_pattern.into(),
        replacement: replacement.into(),
        header_field: String::new(),
        source: None,
        raw: String::new(),
    }
}

fn proto_varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out
}

fn proto_string_field(num: u8, text: &str) -> Vec<u8> {
    let mut out = proto_varint(u64::from(num) << 3 | 2);
    out.extend_from_slice(&proto_varint(text.len() as u64));
    out.extend_from_slice(text.as_bytes());
    out
}

fn proto_bytes_field(num: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = proto_varint(u64::from(num) << 3 | 2);
    out.extend_from_slice(&proto_varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn test_ctx(state: Arc<MitmState>, stats: Arc<nanmen_core::stats::Stats>) -> Arc<Ctx> {
    let cfg = nanmen_core::config::Config::default();
    let filter = Arc::new(nanmen_core::engine::build_filter(&cfg));
    let rules = Arc::new(RwLock::new(Arc::new(
        nanmen_core::engine::RuleEngine::from_config(&cfg),
    )));
    let dns = Arc::new(RwLock::new(Arc::new(nanmen_core::dns::DnsEngine::new(
        &cfg.dns,
        filter.clone(),
        stats.clone(),
        "nxdomain",
        true,
        false,
        false,
    ))));
    let strategy = Arc::new(nanmen_core::strategy::StrategySet::from_config(&cfg));
    Arc::new(Ctx {
        cfg: RwLock::new(cfg),
        filter,
        rules,
        dns,
        stats,
        shutdown: Arc::new(AtomicBool::new(false)),
        nodes: Arc::new(RwLock::new(Arc::new(Vec::new()))),
        selected: Arc::new(RwLock::new(None)),
        strategy: Arc::new(RwLock::new(strategy)),
        health: Arc::new(nanmen_core::strategy::HealthRegistry::new()),
        decision: Arc::new(RwLock::new(())),
        mitm: Arc::new(RwLock::new(state)),
        uid_map: Arc::new(RwLock::new(nanmen_core::uidmap::UidMap::default())),
        conns: Arc::new(RwLock::new(nanmen_core::conns::ConnTable::new())),
        quic_clear: Arc::new(AtomicBool::new(false)),
    })
}

/// 自签源站：按路径返回固定内容（含 gzip 场景）。
async fn spawn_origin() -> (u16, Arc<rcgen::KeyPair>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["api.test.local".to_string()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2040, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    let mut scfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der.into())
        .unwrap();
    scfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut io = Buffered::new(tls);
                while let Ok(Some(req)) = http1::read_request(&mut io).await {
                    let (status, ctype, body): (u16, &str, Vec<u8>) = match req.path.as_str() {
                        "/feed" => (
                            200,
                            "application/json",
                            br#"{"items":[1,2],"ad_items":[{"id":9}],"ok":1}"#.to_vec(),
                        ),
                        "/gz" => {
                            let plain = br#"{"list":[1],"ad_items":[7],"tail":2}"#;
                            (200, "application/json", http1::gzip_encode(plain).unwrap())
                        }
                        "/plain" => (200, "text/plain", b"hello".to_vec()),
                        "/noclen" => (200, "text/plain", b"hello".to_vec()),
                        "/echo" => (200, "application/json", req.body.clone()),
                        "/big" => (200, "text/plain", vec![b'x'; 3 * 1024 * 1024]),
                        _ => (404, "text/plain", b"nf".to_vec()),
                    };
                    let mut headers: http1::Headers = vec![
                        ("Content-Type".into(), ctype.into()),
                        ("Content-Length".into(), body.len().to_string()),
                        ("Connection".into(), "close".into()),
                    ];
                    if req.path == "/gz" {
                        headers.push(("Content-Encoding".into(), "gzip".into()));
                    }
                    let resp = http1::serialize_response(status, "OK", &headers, &body);
                    if io.stream.write_all(&resp).await.is_err() {
                        break;
                    }
                    let _ = io.stream.flush().await;
                    break; // 源站按 connection: close 处理
                }
            });
        }
    });
    (port, Arc::new(key))
}

fn client_config(ca_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))
        .unwrap();
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn h2_client_config(ca_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut cfg = (*client_config(ca_der)).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

/// 完成 h2 握手的源站：`/gz` 返回 gzip JSON，其余路径返回 hello。
/// 记录 TLS accept 次数，用于验证一条下游连接上的多个 RPC 只握手一次。
async fn spawn_h2_origin() -> (u16, Arc<rcgen::KeyPair>, Arc<AtomicUsize>) {
    let (port, key, accepts, _) = spawn_h2_origin_with_fail(0).await;
    (port, key, accepts)
}

/// `fail_first` 个 TCP 连接会被直接丢弃，用于模拟上游瞬时不可用。
async fn spawn_h2_origin_with_fail(
    fail_first: usize,
) -> (u16, Arc<rcgen::KeyPair>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["grpc.test.local".to_string()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2040, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    let mut scfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der.into())
        .unwrap();
    scfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let tcp_accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    let tcp_accepts_task = tcp_accepts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let seen = tcp_accepts_task.fetch_add(1, Ordering::Relaxed) + 1;
            if seen <= fail_first {
                drop(sock);
                continue;
            }
            let acceptor = acceptor.clone();
            let accepts = accepts_task.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                accepts.fetch_add(1, Ordering::Relaxed);
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let path = req.uri().path().to_string();
                    // /duplex：收到首段请求体后先回一段响应，再继续等剩余请求体，
                    // 用于验证 MITM 不会等上传结束才读上游响应。
                    if path == "/duplex" {
                        // 必须把单流处理放到独立任务，否则这里 await 请求体会停住
                        // 连接 future，源站的响应帧永远发不出去。
                        tokio::spawn(async move {
                            let mut req_body = req.into_body();
                            let first = match req_body.data().await {
                                Some(Ok(chunk)) => chunk,
                                _ => return,
                            };
                            let len = first.len();
                            let _ = req_body.flow_control().release_capacity(len);
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-type", "text/plain")
                                .body(())
                                .unwrap();
                            let Ok(mut send) = respond.send_response(response, false) else {
                                return;
                            };
                            if send
                                .send_data(bytes::Bytes::from_static(b"first"), false)
                                .is_err()
                            {
                                return;
                            }
                            while let Some(Ok(chunk)) = req_body.data().await {
                                let len = chunk.len();
                                let _ = req_body.flow_control().release_capacity(len);
                            }
                            let _ = send.send_data(bytes::Bytes::from_static(b"last"), true);
                        });
                        continue;
                    }
                    // /echo-headers：回显请求 Content-Type/Content-Length 与正文，用于验证
                    // Loon 请求 mock 改写后上游收到的头与正文一致。
                    if path == "/echo-headers" {
                        tokio::spawn(async move {
                            let ctype = req
                                .headers()
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let clen = req
                                .headers()
                                .get("content-length")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let mut req_body = req.into_body();
                            let mut got = Vec::new();
                            while let Some(Ok(chunk)) = req_body.data().await {
                                let len = chunk.len();
                                got.extend_from_slice(&chunk);
                                let _ = req_body.flow_control().release_capacity(len);
                            }
                            let value = serde_json::json!({
                                "content-type": ctype,
                                "content-length": clen,
                                "body": String::from_utf8_lossy(&got),
                            });
                            let body = serde_json::to_vec(&value).unwrap();
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .header("content-length", body.len().to_string())
                                .body(())
                                .unwrap();
                            let Ok(mut send) = respond.send_response(response, false) else {
                                return;
                            };
                            let _ = send.send_data(bytes::Bytes::from(body), true);
                        });
                        continue;
                    }
                    // /echo：读完整请求体后原样返回，用于验证 h2 请求体被改写。
                    if path == "/echo" {
                        tokio::spawn(async move {
                            let mut req_body = req.into_body();
                            let mut got = Vec::new();
                            while let Some(Ok(chunk)) = req_body.data().await {
                                let len = chunk.len();
                                got.extend_from_slice(&chunk);
                                let _ = req_body.flow_control().release_capacity(len);
                            }
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .header("content-length", got.len().to_string())
                                .body(())
                                .unwrap();
                            let Ok(mut send) = respond.send_response(response, false) else {
                                return;
                            };
                            let _ = send.send_data(bytes::Bytes::from(got), true);
                        });
                        continue;
                    }
                    // /slow：一直读到请求体结束才响应；客户端中途 RST 时源站侧不会回包。
                    if path == "/slow" {
                        tokio::spawn(async move {
                            let mut req_body = req.into_body();
                            while let Some(Ok(chunk)) = req_body.data().await {
                                let len = chunk.len();
                                let _ = req_body.flow_control().release_capacity(len);
                            }
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-type", "text/plain")
                                .body(())
                                .unwrap();
                            let Ok(mut send) = respond.send_response(response, false) else {
                                return;
                            };
                            let _ = send.send_data(bytes::Bytes::from_static(b"slow"), true);
                        });
                        continue;
                    }
                    let (ctype, encoding, body, with_len) = if path == "/grpc" {
                        let inner = proto_string_field(1, "inner ad");
                        let mut payload = proto_string_field(1, "top ad");
                        payload.extend_from_slice(&proto_bytes_field(2, &inner));
                        ("application/grpc", None, grpc_frame(&payload), true)
                    } else if path == "/gz" {
                        let plain = br#"{"list":[1],"ad_items":[7],"tail":2}"#;
                        (
                            "application/json",
                            Some("gzip"),
                            http1::gzip_encode(plain).unwrap(),
                            true,
                        )
                    } else if path == "/binary" {
                        ("application/octet-stream", None, vec![0, 255, 2], true)
                    } else if path == "/big" {
                        // 故意不写 content-length，用来触发 DATA 超限回退路径。
                        ("text/plain", None, vec![b'x'; 9000], false)
                    } else {
                        ("text/plain", None, b"hello".to_vec(), true)
                    };
                    let mut builder = http::Response::builder()
                        .status(200)
                        .header("content-type", ctype);
                    if with_len {
                        builder = builder.header("content-length", body.len().to_string());
                    }
                    if let Some(enc) = encoding {
                        builder = builder.header("content-encoding", enc);
                    }
                    let response = builder.body(()).unwrap();
                    let Ok(mut send) = respond.send_response(response, false) else {
                        return;
                    };
                    let _ = send.send_data(bytes::Bytes::from(body), true);
                }
            });
        }
    });
    (port, Arc::new(key), accepts, tcp_accepts)
}

async fn client_request(
    tls: &mut tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
    path: &str,
) -> (u16, Vec<u8>) {
    let (status, body, _headers) = client_request_headers(tls, "GET", path, &[], None).await;
    (status, body)
}

async fn client_request_headers(
    tls: &mut tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: Option<&[u8]>,
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: api.test.local\r\nAccept-Encoding: gzip\r\n",
        method, path
    );
    for (k, v) in extra {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    let mut raw = req.into_bytes();
    if let Some(b) = body {
        raw.extend_from_slice(b);
    }
    tls.write_all(&raw).await.unwrap();
    tls.flush().await.unwrap();
    let mut io = Buffered::new(tls);
    let head = http1::read_response_head(&mut io).await.unwrap();
    let framing = http1::response_framing(&head, method);
    let body = match framing {
        http1::Framing::Length(n) => io.read_n(n as usize).await.unwrap(),
        http1::Framing::None => Vec::new(),
        http1::Framing::Eof => io.read_to_end_limit(1 << 20).await.unwrap().0,
        http1::Framing::Chunked => {
            let raw = io.read_to_end_limit(1 << 20).await.unwrap().0;
            http1::decode_chunked(&raw).unwrap()
        }
    };
    (head.status, body, head.headers)
}

/// 启一个 h2 MITM 并返回已完成 h2 握手的客户端 TLS。
async fn start_h2_mitm(
    ca_path: &str,
    origin_port: u16,
    cfg: MitmConfig,
) -> (
    Arc<MitmState>,
    tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
) {
    let state = Arc::new(MitmState::build(&cfg));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats);
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(ca_path).unwrap();
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: origin_port,
        domain: Some("grpc.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "grpc.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            47,
        )
        .await;
    });
    let connector = tokio_rustls::TlsConnector::from(h2_client_config(ca.ca_der()));
    let name = rustls::pki_types::ServerName::try_from("grpc.test.local").unwrap();
    let tls = connector.connect(name, client_side).await.unwrap();
    (state, tls)
}

#[tokio::test]
async fn mitm_reject_rewrite_passthrough_keepalive() {
    let ca_path = tmp_ca("e2e_ca.pem");
    let (port, _origin_key) = spawn_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["api.test.local".into()],
        rules: vec![
            rule(r"^https://api\.test\.local/ad", "reject", "", ""),
            rule(
                r"^https://api\.test\.local/(feed|gz)",
                "body",
                r#""ad_items":\[[^\]]*\],"#,
                "",
            ),
        ],
        upstream_insecure: true, // 源站是自签证书
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    assert!(state.active());
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(&ca_path).unwrap();
    let ccfg = client_config(ca.ca_der());

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port,
        domain: Some("api.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "api.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            1,
        )
        .await;
    });
    let connector = tokio_rustls::TlsConnector::from(ccfg);
    let name = rustls::pki_types::ServerName::try_from("api.test.local").unwrap();
    let mut tls = connector.connect(name, client_side).await.unwrap();

    // 1) 广告 URL 被拒绝（204），连接保持
    let (status, body) = client_request(&mut tls, "/ad?id=1").await;
    assert_eq!(status, 204);
    assert!(body.is_empty());
    // 2) JSON 响应体广告字段被删除
    let (status, body) = client_request(&mut tls, "/feed").await;
    assert_eq!(status, 200);
    assert_eq!(body, br#"{"items":[1,2],"ok":1}"#);
    // 3) gzip 响应同样可改写
    let (status, body) = client_request(&mut tls, "/gz").await;
    assert_eq!(status, 200);
    assert_eq!(body, br#"{"list":[1],"tail":2}"#);
    // 4) 无规则命中的内容原样透传
    let (status, body) = client_request(&mut tls, "/plain").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello");

    assert_eq!(stats.mitm_conns.load(Ordering::Relaxed), 1);
    assert_eq!(stats.mitm_rejected.load(Ordering::Relaxed), 1);
    assert_eq!(stats.mitm_rewritten.load(Ordering::Relaxed), 2);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_scripts_mutate_request_response_and_short_circuit() {
    let ca_path = tmp_ca("e2e_script_ca.pem");
    let (port, _origin_key) = spawn_origin().await;
    let req_src = Arc::new(std::sync::RwLock::new(Vec::new()));
    {
        let mut v = req_src.write().unwrap();
        v.push(ScriptRuleConf {
            name: "rewrite request body".into(),
            phase: "request".into(),
            pattern: r"^https://api\.test\.local/echo$".into(),
            source: "$done({body:\"script-body\"});".into(),
            requires_body: true,
            ..Default::default()
        });
        v.push(ScriptRuleConf {
            name: "local response".into(),
            phase: "request".into(),
            pattern: r"^https://api\.test\.local/short$".into(),
            source: "$done({response:{status:201,headers:{\"x-local\":\"1\"},body:\"local\"}});"
                .into(),
            ..Default::default()
        });
        v.push(ScriptRuleConf {
            name: "rewrite response".into(),
            phase: "response".into(),
            pattern: r"^https://api\.test\.local/echo$".into(),
            source: "$done({headers:{\"content-type\":\"text/plain\",\"x-script\":\"yes\"},body:\"resp:\"+$response.body});".into(),
            ..Default::default()
        });
    }
    let scripts = req_src.read().unwrap().clone();
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["api.test.local".into()],
        scripts,
        upstream_insecure: true,
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    assert!(state.active());
    assert_eq!(state.engine.scripts.rules.len(), 3);
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(&ca_path).unwrap();
    let ccfg = client_config(ca.ca_der());

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port,
        domain: Some("api.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "api.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            2,
        )
        .await;
    });
    let connector = tokio_rustls::TlsConnector::from(ccfg);
    let name = rustls::pki_types::ServerName::try_from("api.test.local").unwrap();
    let mut tls = connector.connect(name, client_side).await.unwrap();

    // 请求脚本改正文 + 响应脚本改正文/头：一次往返同时覆盖两个阶段。
    let (status, body, headers) =
        client_request_headers(&mut tls, "POST", "/echo", &[], Some(b"client-body")).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"resp:script-body");
    assert!(headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-script") && v == "yes"));

    // 请求脚本本地短路：不上源站，直接返回 201。
    let (status, body) = client_request(&mut tls, "/short").await;
    assert_eq!(status, 201);
    assert_eq!(body, b"local");

    // 未命中脚本的请求保持透传。
    let (status, body) = client_request(&mut tls, "/plain").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello");
    assert!(stats.mitm_rewritten.load(Ordering::Relaxed) >= 2);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_handshake_failure_marks_bypass() {
    let ca_path = tmp_ca("e2e_bypass.pem");
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["pinned.test.local".into()],
        rules: vec![],
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    assert!(state.should_mitm("pinned.test.local"));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: 443,
        domain: Some("pinned.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "pinned.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            2,
        )
        .await;
    });
    // 客户端不信任 MITM CA（模拟 cert pinning）：握手必须失败
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let ccfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let connector = tokio_rustls::TlsConnector::from(ccfg);
    let name = rustls::pki_types::ServerName::try_from("pinned.test.local").unwrap();
    let result = connector.connect(name, client_side).await;
    assert!(result.is_err());
    // 失败后域名进入临时放行名单，后续连接恢复透明转发
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!state.should_mitm("pinned.test.local"));
    assert_eq!(stats.mitm_failed.load(Ordering::Relaxed), 1);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_grpc_reject_uses_trailers() {
    let ca_path = tmp_ca("e2e_h2_grpc.pem");
    let (origin_port, _origin_key, _origin_accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        rules: vec![rule(r"^https://grpc\.test\.local/ad", "reject", "", "")],
        upstream_insecure: true,
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(&ca_path).unwrap();

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: origin_port,
        domain: Some("grpc.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "grpc.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            42,
        )
        .await;
    });

    let connector = tokio_rustls::TlsConnector::from(h2_client_config(ca.ca_der()));
    let name = rustls::pki_types::ServerName::try_from("grpc.test.local").unwrap();
    let tls = connector.connect(name, client_side).await.unwrap();
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = http::Request::builder()
        .method("POST")
        .uri("https://grpc.test.local/ad")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (resp_fut, _req_body) = send.send_request(req, true).unwrap();
    // 请求体已结束，不需要再发 DATA。
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    while let Some(chunk) = body.data().await {
        chunk.unwrap();
    }
    let trailers = body
        .trailers()
        .await
        .unwrap()
        .expect("gRPC 必须有 trailers");
    assert_eq!(trailers.get("grpc-status").unwrap(), "7");
    assert_eq!(stats.mitm_conns.load(Ordering::Relaxed), 1);
    assert_eq!(stats.mitm_rejected.load(Ordering::Relaxed), 1);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn h2_binary_response_runs_binary_script() {
    let ca_path = tmp_ca("e2e_h2_binary_script.pem");
    let (port, _, _) = spawn_h2_origin().await;
    let config = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        scripts: vec![ScriptRuleConf {
            phase: "response".into(),
            pattern: r"/binary$".into(),
            source: "const b = $response.body; $done({body: new Uint8Array([b[0] + 1, b[1], b[2]])});".into(),
            binary_body_mode: true,
            ..Default::default()
        }],
        upstream_insecure: true,
        ..Default::default()
    };
    let (_, tls) = start_h2_mitm(&ca_path, port, config).await;
    let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(connection);
    let request = http::Request::get("https://grpc.test.local/binary").body(()).unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    let received = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut body = response.await.unwrap().into_body();
        let mut output = Vec::new();
        while let Some(chunk) = body.data().await {
            output.extend_from_slice(&chunk.unwrap());
        }
        output
    })
    .await
    .unwrap();
    assert_eq!(received, [1, 255, 2]);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_scripts_mutate_request_and_response() {
    let ca_path = tmp_ca("e2e_h2_script.pem");
    let (origin_port, _origin_key, _accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        scripts: vec![
            ScriptRuleConf {
                name: "h2 request".into(),
                phase: "request".into(),
                pattern: r"^https://grpc\.test\.local/echo$".into(),
                source: "$done({body:\"h2-body\"});".into(),
                requires_body: true,
                ..Default::default()
            },
            ScriptRuleConf {
                name: "h2 response".into(),
                phase: "response".into(),
                pattern: r"^https://grpc\.test\.local/echo$".into(),
                source: "$done({headers:{\"content-type\":\"text/plain\"},body:\"h2-resp:\"+$response.body});".into(),
                ..Default::default()
            },
        ],
        upstream_insecure: true,
        ..Default::default()
    };
    let (state, tls) = start_h2_mitm(&ca_path, origin_port, cfg).await;
    assert_eq!(state.engine.scripts.rules.len(), 2);
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = http::Request::builder()
        .method("POST")
        .uri("https://grpc.test.local/echo")
        .body(())
        .unwrap();
    let (resp_fut, mut upload) = send.send_request(req, false).unwrap();
    upload
        .send_data(bytes::Bytes::from_static(b"client-body"), true)
        .unwrap();
    let resp = resp_fut.await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let len = chunk.len();
        got.extend_from_slice(&chunk);
        body.flow_control().release_capacity(len).unwrap();
    }
    assert_eq!(got, b"h2-resp:h2-body");
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_passthrough_streams_body() {
    let ca_path = tmp_ca("e2e_h2_pass.pem");
    let (origin_port, _origin_key, _origin_accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        upstream_insecure: true,
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(&ca_path).unwrap();

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: origin_port,
        domain: Some("grpc.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "grpc.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            43,
        )
        .await;
    });

    let connector = tokio_rustls::TlsConnector::from(h2_client_config(ca.ca_der()));
    let name = rustls::pki_types::ServerName::try_from("grpc.test.local").unwrap();
    let tls = connector.connect(name, client_side).await.unwrap();
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = http::Request::builder()
        .method("POST")
        .uri("https://grpc.test.local/plain")
        .header("content-type", "text/plain")
        .body(())
        .unwrap();
    let (resp_fut, mut req_body) = send.send_request(req, false).unwrap();
    req_body
        .send_data(bytes::Bytes::from_static(b"abc"), true)
        .unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, b"hello");
    assert_eq!(stats.mitm_conns.load(Ordering::Relaxed), 1);
    assert_eq!(stats.mitm_rejected.load(Ordering::Relaxed), 0);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_response_body_rewrite_decodes_gzip() {
    let ca_path = tmp_ca("e2e_h2_rewrite.pem");
    let (origin_port, _origin_key, _origin_accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        rules: vec![rule(
            r"^https://grpc\.test\.local/gz",
            "body",
            r#""ad_items":\[[^\]]*\],"#,
            "",
        )],
        upstream_insecure: true,
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(&ca_path).unwrap();

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: origin_port,
        domain: Some("grpc.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "grpc.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            44,
        )
        .await;
    });

    let connector = tokio_rustls::TlsConnector::from(h2_client_config(ca.ca_der()));
    let name = rustls::pki_types::ServerName::try_from("grpc.test.local").unwrap();
    let tls = connector.connect(name, client_side).await.unwrap();
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = http::Request::builder()
        .method("GET")
        .uri("https://grpc.test.local/gz")
        .body(())
        .unwrap();
    let (resp_fut, _req_body) = send.send_request(req, true).unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("content-encoding").is_none());
    let header_len = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert_eq!(header_len, br#"{"list":[1],"tail":2}"#.len());
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, br#"{"list":[1],"tail":2}"#);
    assert_eq!(stats.mitm_rewritten.load(Ordering::Relaxed), 1);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_reuses_one_upstream_connection_for_concurrent_streams() {
    let ca_path = tmp_ca("e2e_h2_reuse.pem");
    let (origin_port, _origin_key, origin_accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        upstream_insecure: true,
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(&ca_path).unwrap();

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: origin_port,
        domain: Some("grpc.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "grpc.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            45,
        )
        .await;
    });

    let connector = tokio_rustls::TlsConnector::from(h2_client_config(ca.ca_der()));
    let name = rustls::pki_types::ServerName::try_from("grpc.test.local").unwrap();
    let tls = connector.connect(name, client_side).await.unwrap();
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let started = std::time::Instant::now();
    let mut futures = Vec::new();
    for path in ["/plain?rpc=1", "/plain?rpc=2"] {
        let req = http::Request::builder()
            .method("GET")
            .uri(format!("https://grpc.test.local{}", path))
            .body(())
            .unwrap();
        let (resp_fut, _body) = send.send_request(req, true).unwrap();
        futures.push(resp_fut);
    }
    for resp_fut in futures {
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let mut body = resp.into_body();
        while let Some(chunk) = body.data().await {
            chunk.unwrap();
        }
    }
    // 一条下游 h2 连接上的两个 RPC 共用一条上游 TLS/h2 连接。
    assert_eq!(origin_accepts.load(Ordering::Relaxed), 1);
    eprintln!(
        "h2 reuse: 2 RPC, upstream TLS accepts={}, elapsed={:?}",
        origin_accepts.load(Ordering::Relaxed),
        started.elapsed()
    );
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_upstream_connect_retries_transient_failure() {
    let ca_path = tmp_ca("e2e_h2_retry.pem");
    let (origin_port, _origin_key, origin_accepts, origin_tcp_accepts) =
        spawn_h2_origin_with_fail(1).await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        upstream_insecure: true,
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(&ca_path).unwrap();

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: origin_port,
        domain: Some("grpc.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "grpc.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            47,
        )
        .await;
    });

    let connector = tokio_rustls::TlsConnector::from(h2_client_config(ca.ca_der()));
    let name = rustls::pki_types::ServerName::try_from("grpc.test.local").unwrap();
    let tls = connector.connect(name, client_side).await.unwrap();
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = http::Request::builder()
        .method("GET")
        .uri("https://grpc.test.local/plain")
        .body(())
        .unwrap();
    let (resp_fut, _req_body) = send.send_request(req, true).unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, b"hello");
    // 第一次 TCP 连接被上游丢掉，第二次成功；客户端仍拿到 200。
    assert_eq!(origin_tcp_accepts.load(Ordering::Relaxed), 2);
    assert_eq!(origin_accepts.load(Ordering::Relaxed), 1);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_body_overflow_falls_back_to_raw_stream() {
    let ca_path = tmp_ca("e2e_h2_overflow.pem");
    let (origin_port, _origin_key, _origin_accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        rules: vec![rule(r"^https://grpc\.test\.local/big", "body", "x", "y")],
        upstream_insecure: true,
        body_limit: 4096,
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(&ca_path).unwrap();

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: origin_port,
        domain: Some("grpc.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "grpc.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            46,
        )
        .await;
    });

    let connector = tokio_rustls::TlsConnector::from(h2_client_config(ca.ca_der()));
    let name = rustls::pki_types::ServerName::try_from("grpc.test.local").unwrap();
    let tls = connector.connect(name, client_side).await.unwrap();
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = http::Request::builder()
        .method("GET")
        .uri("https://grpc.test.local/big")
        .body(())
        .unwrap();
    let (resp_fut, _req_body) = send.send_request(req, true).unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got.len(), 9000);
    assert!(got.iter().all(|b| *b == b'x'));
    assert_eq!(stats.mitm_rewritten.load(Ordering::Relaxed), 0);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_body_limit_passthrough() {
    let ca_path = tmp_ca("e2e_limit.pem");
    let (port, _k) = spawn_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["api.test.local".into()],
        rules: vec![rule(
            r"^https://api\.test\.local/feed",
            "body",
            "items",
            "ITEMS",
        )],
        upstream_insecure: true,
        body_limit: 4096, // 最小上限 also 足够 /feed；用 /plain 验证无规则透传不受影响
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats.clone());
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(&ca_path).unwrap();
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port,
        domain: Some("api.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "api.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            3,
        )
        .await;
    });
    let connector = tokio_rustls::TlsConnector::from(client_config(ca.ca_der()));
    let name = rustls::pki_types::ServerName::try_from("api.test.local").unwrap();
    let mut tls = connector.connect(name, client_side).await.unwrap();
    let (status, body) = client_request(&mut tls, "/feed").await;
    assert_eq!(status, 200);
    // 正则 items 同时命中 ad_items 内部子串，两处都被替换（符合 replace_all 语义）
    assert_eq!(body, br#"{"ITEMS":[1,2],"ad_ITEMS":[{"id":9}],"ok":1}"#);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_duplex_response_before_request_end() {
    let ca_path = tmp_ca("e2e_h2_duplex.pem");
    let (origin_port, _origin_key, _origin_accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        upstream_insecure: true,
        ..Default::default()
    };
    let (_state, tls) = start_h2_mitm(&ca_path, origin_port, cfg).await;
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = http::Request::builder()
        .method("POST")
        .uri("https://grpc.test.local/duplex")
        .body(())
        .unwrap();
    let (resp_fut, mut req_body) = send.send_request(req, false).unwrap();
    req_body
        .send_data(bytes::Bytes::from_static(b"part1"), false)
        .unwrap();
    // 客户端发完首段后等回包；MITM 必须先转发响应头/首段，而不是等上传结束。
    let resp = tokio::time::timeout(std::time::Duration::from_secs(3), resp_fut)
        .await
        .expect("MITM 未在上传结束前转回响应")
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let first = tokio::time::timeout(std::time::Duration::from_secs(3), body.data())
        .await
        .expect("未收到源站首段响应")
        .unwrap()
        .unwrap();
    assert_eq!(first.as_ref(), b"first");
    let _ = body.flow_control().release_capacity(first.len());

    req_body
        .send_data(bytes::Bytes::from_static(b"part2"), false)
        .unwrap();
    req_body.send_data(bytes::Bytes::new(), true).unwrap();
    let last = tokio::time::timeout(std::time::Duration::from_secs(3), body.data())
        .await
        .expect("未收到源站尾段响应")
        .unwrap()
        .unwrap();
    assert_eq!(last.as_ref(), b"last");
    let _ = body.flow_control().release_capacity(last.len());
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_small_window_streams_without_stalling() {
    let ca_path = tmp_ca("e2e_h2_small_window.pem");
    let (origin_port, _origin_key, _origin_accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        upstream_insecure: true,
        ..Default::default()
    };
    let (_state, tls) = start_h2_mitm(&ca_path, origin_port, cfg).await;
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(1024)
        .initial_connection_window_size(1024);
    let (mut send, conn): (h2::client::SendRequest<bytes::Bytes>, _) =
        builder.handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let big_req = http::Request::builder()
        .method("GET")
        .uri("https://grpc.test.local/big")
        .body(())
        .unwrap();
    let (big_resp, _big_body) = send.send_request(big_req, true).unwrap();
    let short_req = http::Request::builder()
        .method("GET")
        .uri("https://grpc.test.local/plain")
        .body(())
        .unwrap();
    let (short_resp, _short_body) = send.send_request(short_req, true).unwrap();

    // 先读完短请求：小窗口下它也必须能完成。
    let short = tokio::time::timeout(std::time::Duration::from_secs(5), short_resp)
        .await
        .expect("短请求被大响应拖死")
        .unwrap();
    let mut short_body = short.into_body();
    let mut short_buf = Vec::new();
    while let Some(chunk) = short_body.data().await {
        let chunk = chunk.unwrap();
        let len = chunk.len();
        short_buf.extend_from_slice(&chunk);
        let _ = short_body.flow_control().release_capacity(len);
    }
    assert_eq!(short_buf, b"hello");

    let big = tokio::time::timeout(std::time::Duration::from_secs(8), big_resp)
        .await
        .expect("大响应头超时")
        .unwrap();
    assert_eq!(big.status(), 200);
    let mut big_body = big.into_body();
    let mut big_buf = Vec::new();
    let read_all = async {
        while let Some(chunk) = big_body.data().await {
            let chunk = chunk.unwrap();
            let len = chunk.len();
            big_buf.extend_from_slice(&chunk);
            let _ = big_body.flow_control().release_capacity(len);
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(8), read_all)
        .await
        .expect("小窗口下大响应停住");
    assert_eq!(big_buf.len(), 9000);
    assert!(big_buf.iter().all(|b| *b == b'x'));
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_h2_canceled_upload_keeps_upstream_connection() {
    let ca_path = tmp_ca("e2e_h2_cancel.pem");
    let (origin_port, _origin_key, origin_accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        upstream_insecure: true,
        ..Default::default()
    };
    let (_state, tls) = start_h2_mitm(&ca_path, origin_port, cfg).await;
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = http::Request::builder()
        .method("POST")
        .uri("https://grpc.test.local/slow")
        .body(())
        .unwrap();
    let (resp_fut, mut req_body) = send.send_request(req, false).unwrap();
    req_body
        .send_data(bytes::Bytes::from_static(b"partial"), false)
        .unwrap();
    req_body.send_reset(h2::Reason::CANCEL);
    drop(resp_fut);
    // 给 MITM 一点时间处理上传流被取消，而不是整条上游连接失效。
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let next = http::Request::builder()
        .method("GET")
        .uri("https://grpc.test.local/plain")
        .body(())
        .unwrap();
    let (next_resp, _next_body) = send.send_request(next, true).unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), next_resp)
        .await
        .expect("取消一个上传后，后续 RPC 未能继续")
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let len = chunk.len();
        got.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(len);
    }
    assert_eq!(got, b"hello");
    // 取消单个上传不应让共享上游连接重建。
    assert_eq!(origin_accepts.load(Ordering::Relaxed), 1);
    let _ = std::fs::remove_file(&ca_path);
}

#[test]
fn rewrite_budget_caps_and_releases() {
    let budget = nanmen_core::mitm::RewriteBudget::new(10);
    let p1 = budget.try_acquire(6).unwrap();
    let p2 = budget.try_acquire(4).unwrap();
    assert!(budget.try_acquire(1).is_none());
    drop(p1);
    let p3 = budget.try_acquire(6).unwrap();
    drop(p2);
    drop(p3);
    assert!(budget.try_acquire(10).is_some());
}

#[tokio::test]
async fn mitm_h2_grpc_body_rewrites_protobuf_fields() {
    let ca_path = tmp_ca("e2e_h2_grpc_body.pem");
    let (origin_port, _origin_key, _origin_accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        rules: vec![rule(r"^https://grpc\.test\.local/grpc", "body", "ad", "x")],
        upstream_insecure: true,
        body_limit: 4096,
        ..Default::default()
    };
    let (_state, tls) = start_h2_mitm(&ca_path, origin_port, cfg).await;
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = http::Request::builder()
        .method("GET")
        .uri("https://grpc.test.local/grpc")
        .body(())
        .unwrap();
    let (resp_fut, _req_body) = send.send_request(req, true).unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/grpc"));
    let content_length = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .expect("改写后应写回新的 content-length");
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let len = chunk.len();
        got.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(len);
    }
    // 帧头保留；顶层与嵌套 protobuf 字符串都应从 ad 改成 x。
    assert_eq!(got[0], 0);
    assert!(got.windows(5).any(|w| w == b"top x"));
    assert!(got.windows(7).any(|w| w == b"inner x"));
    assert_eq!(content_length, got.len());
    let _ = std::fs::remove_file(&ca_path);
}

async fn start_h1_mitm(
    ca_path: &str,
    origin_port: u16,
    cfg: MitmConfig,
) -> tokio_rustls::client::TlsStream<tokio::io::DuplexStream> {
    let state = Arc::new(MitmState::build(&cfg));
    let stats = Arc::new(nanmen_core::stats::Stats::new());
    let ctx = test_ctx(state.clone(), stats);
    let ca = nanmen_core::mitm::ca::MitmCa::load_or_generate(ca_path).unwrap();
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: origin_port,
        domain: Some("api.test.local".into()),
    };
    let ctx2 = ctx.clone();
    let st2 = state.clone();
    tokio::spawn(async move {
        nanmen_core::mitm::handle(
            server_side,
            "api.test.local".into(),
            target,
            Action::Direct,
            ctx2,
            st2,
            48,
        )
        .await;
    });
    let connector = tokio_rustls::TlsConnector::from(client_config(ca.ca_der()));
    let name = rustls::pki_types::ServerName::try_from("api.test.local").unwrap();
    connector.connect(name, client_side).await.unwrap()
}

#[tokio::test]
async fn mitm_loon_old_rewrite_http1_headers_body_redirect_mock_request_json() {
    let ca_path = tmp_ca("e2e_loon_h1.pem");
    let (port, _origin_key) = spawn_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["api.test.local".into()],
        loon_rewrites: vec![
            r#"^https://api\.test\.local/feed response-body-replace-regex "\"ad_items\":\[[^\]]*\]," """#.to_string(),
            r"^https://api\.test\.local/feed response-header-add X-Loon yes".to_string(),
            r"^https://api\.test\.local/feed request-header-add X-Req 1".to_string(),
            r"^https://api\.test\.local/ad 302 https://example.com/new".to_string(),
            r"^https://api\.test\.local/plain header https://api.test.local/feed".to_string(),
            r"^https://api\.test\.local/feed response-header-add X-Order yes".to_string(),
            r"^https://api\.test\.local/drop reject".to_string(),
            r"^https://api\.test\.local/noclen response-header-del Content-Length".to_string(),
            r#"^https://api\.test\.local/mock mock-response-body data-type=json data="{\"ok\":1}" status-code=201"#.to_string(),
            r"^https://api\.test\.local/echo request-body-json-add data.enabled true".to_string(),
        ],
        upstream_insecure: true,
        ..Default::default()
    };
    let mut tls = start_h1_mitm(&ca_path, port, cfg).await;

    let (status, body, headers) = client_request_headers(&mut tls, "GET", "/feed", &[], None).await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("ad_items").is_none());
    assert_eq!(v["ok"], 1);
    assert_eq!(http1::get_header(&headers, "x-loon"), Some("yes"));
    assert_eq!(http1::get_header(&headers, "x-order"), Some("yes"));

    // URL 替换：/plain -> /feed。不同 URL 正则只在原 URL 命中时收集响应动作，
    // 因此 /feed 的响应头规则不会因替换后的 URL 再匹配一次。
    let (status, body, _headers) =
        client_request_headers(&mut tls, "GET", "/plain", &[], None).await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ok"], 1);

    // 响应头删除 Content-Length 后，透传路径仍必须补回组帧头。
    let (status, body, headers) =
        client_request_headers(&mut tls, "GET", "/noclen", &[], None).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello");
    assert_eq!(http1::get_header(&headers, "content-length"), Some("5"));

    let (status, _body, headers) = client_request_headers(&mut tls, "GET", "/ad", &[], None).await;
    assert_eq!(status, 302);
    assert_eq!(
        http1::get_header(&headers, "location"),
        Some("https://example.com/new")
    );

    let (status, body, _headers) =
        client_request_headers(&mut tls, "GET", "/mock", &[], None).await;
    assert_eq!(status, 201);
    assert_eq!(body, br#"{"ok":1}"#);

    let (status, body, _headers) = client_request_headers(
        &mut tls,
        "POST",
        "/echo",
        &[("Content-Type", "application/json")],
        Some(br#"{"a":1}"#),
    )
    .await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["data"]["enabled"], true);
    assert_eq!(v["a"], 1);

    // Loon `reject` = 直接断开，不能返回 204。
    let req = b"GET /drop HTTP/1.1\r\nHost: api.test.local\r\n\r\n".to_vec();
    let _ = tls.write_all(&req).await;
    let _ = tls.flush().await;
    let mut io = Buffered::new(&mut tls);
    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        http1::read_response_head(&mut io),
    )
    .await;
    assert!(
        closed.is_err() || closed.unwrap().is_err(),
        "reject 必须断开而不是返回 204"
    );
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_loon_new_syntax_h2_response_json_headers_and_request_json() {
    let ca_path = tmp_ca("e2e_loon_h2.pem");
    let (port, _origin_key, _accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        loon_rewrites: vec![
            r#"response if ${url} ~= /^https:\/\/grpc\.test\.local\/gz/ then response.header.add("X-Loon", "1"); response.json.add("data.added", true)"#.to_string(),
            r#"request if ${url} ~= /^https:\/\/grpc\.test\.local\/echo/ then request.json.add("added", true)"#.to_string(),
        ],
        upstream_insecure: true,
        ..Default::default()
    };
    let (_state, tls) = start_h2_mitm(&ca_path, port, cfg).await;
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = http::Request::builder()
        .method("GET")
        .uri("https://grpc.test.local/gz")
        .body(())
        .unwrap();
    let (resp_fut, _b) = send.send_request(req, true).unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.headers().get("x-loon").unwrap(), "1");
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    let v: serde_json::Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(v["data"]["added"], true);
    assert_eq!(v["tail"], 2);

    let req = http::Request::builder()
        .method("POST")
        .uri("https://grpc.test.local/echo")
        .header("content-type", "application/json")
        .body(())
        .unwrap();
    let (resp_fut, mut req_body) = send.send_request(req, false).unwrap();
    req_body
        .send_data(bytes::Bytes::from_static(br#"{"a":1}"#), true)
        .unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
        .await
        .unwrap()
        .unwrap();
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    let v: serde_json::Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(v["added"], true);
    assert_eq!(v["a"], 1);
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_loon_response_over_limit_passthrough() {
    let ca_path = tmp_ca("e2e_loon_big.pem");
    let (port, _origin_key) = spawn_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["api.test.local".into()],
        // 3MiB 响应超过 2MiB 改写上限：必须原样透传，不能被截断或放大。
        loon_rewrites: vec![
            r"^https://api\.test\.local/big response-body-replace-regex x y".to_string(),
        ],
        upstream_insecure: true,
        ..Default::default()
    };
    let mut tls = start_h1_mitm(&ca_path, port, cfg).await;
    let (status, body, _headers) = client_request_headers(&mut tls, "GET", "/big", &[], None).await;
    assert_eq!(status, 200);
    assert_eq!(body.len(), 3 * 1024 * 1024);
    assert!(body.iter().all(|b| *b == b'x'));
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn mitm_loon_h2_request_mock_rewrites_content_type_and_length() {
    let ca_path = tmp_ca("e2e_loon_h2_mock.pem");
    let (port, _origin_key, _accepts) = spawn_h2_origin().await;
    let cfg = MitmConfig {
        enabled: true,
        ca_file: ca_path.clone(),
        hostnames: vec!["grpc.test.local".into()],
        loon_rewrites: vec![
            r#"^https://grpc\.test\.local/echo mock-request-body data-type=text data="mock-body""#
                .to_string(),
        ],
        upstream_insecure: true,
        ..Default::default()
    };
    let (_state, tls) = start_h2_mitm(&ca_path, port, cfg).await;
    let (mut send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = http::Request::builder()
        .method("POST")
        .uri("https://grpc.test.local/echo-headers")
        .header("content-type", "application/json")
        .body(())
        .unwrap();
    let (resp_fut, mut req_body) = send.send_request(req, false).unwrap();
    req_body
        .send_data(bytes::Bytes::from_static(br#"{"a":1}"#), true)
        .unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), resp_fut)
        .await
        .unwrap()
        .unwrap();
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    let v: serde_json::Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(v["content-type"], "text/plain");
    assert_eq!(v["content-length"], "9");
    assert_eq!(v["body"], "mock-body");
    let _ = std::fs::remove_file(&ca_path);
}

#[derive(Debug)]
struct IdleNoVerify(Arc<rustls::crypto::CryptoProvider>);
impl rustls::client::danger::ServerCertVerifier for IdleNoVerify {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _s: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _n: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// 空闲/备用连接：客户端完成 TLS（ALPN h2）但不发 h2 preface。
/// 应按空闲连接安静回收（Ok），而不是当成错误 warn。回归「h2 服务端握手超时」噪声。
#[tokio::test]
async fn h2_idle_client_preface_is_reclaimed_quietly() {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["idle.test.local".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    let mut scfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der.into())
        .unwrap();
    scfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        acceptor.accept(sock).await.unwrap()
    });

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let ccfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(IdleNoVerify(provider)))
        .with_no_client_auth();
    let mut ccfg = ccfg;
    ccfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
    let sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("idle.test.local").unwrap();
    let _client_tls = connector.connect(name, sock).await.unwrap();
    let server_tls = server.await.unwrap();
    // 客户端保持连接但永不发 preface。

    let state = Arc::new(MitmState::build(&MitmConfig::default()));
    let stats = Arc::new(nanmen_core::stats::Stats::default());
    let ctx = test_ctx(state.clone(), stats);
    let target = Target {
        ip: "127.0.0.1".parse().unwrap(),
        port: 443,
        domain: Some("idle.test.local".into()),
    };
    let res = nanmen_core::mitm::h2::serve_with_preface_timeout(
        server_tls,
        "idle.test.local".into(),
        target,
        Action::Direct,
        ctx,
        state,
        1,
        Arc::new(nanmen_core::mitm::ConnTrace::default()),
        std::time::Duration::from_millis(200),
    )
    .await;
    assert!(res.is_ok(), "空闲连接应安静回收，实际: {:?}", res.err());
}

/// 并发配额耗尽时，旧实现会 try_acquire 失败即原样透传并标 skipped，
/// 等于把模块本该改写的正文吃掉。这里锁定：不得静默跳过，必须排队，
/// 排不上就明确报错且正文保持原样。
#[tokio::test]
async fn script_slot_exhaustion_fails_loudly_instead_of_silent_bypass() {
    let cfg = MitmConfig {
        enabled: true,
        hostnames: vec!["slot.test.local".into()],
        scripts: vec![ScriptRuleConf {
            name: "slot".into(),
            phase: "request".into(),
            pattern: r"^https://slot\.test\.local/x$".into(),
            source: "$done({body:\"rewritten\"});".into(),
            requires_body: true,
            timeout_ms: 50,
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut state = MitmState::build(&cfg);
    // 配额归零，模拟并发打满
    state.script_slots = Arc::new(tokio::sync::Semaphore::new(0));
    let state = Arc::new(state);

    let msg = ScriptMessage {
        url: "https://slot.test.local/x".into(),
        method: "GET".into(),
        status: 200,
        headers: Vec::new(),
        body: "orig".into(),
        body_bytes: None,
    };
    let r = state
        .run_scripts(ScriptPhase::Request, "https://slot.test.local/x", &msg)
        .await;

    assert!(!r.skipped, "配额不足不得静默跳过: {:?}", r.errors);
    assert_eq!(r.matched, 1, "命中的脚本数必须体现在结果里");
    assert!(
        r.errors.iter().any(|e| e.contains("排队超时")),
        "排不上时应明确报排队失败: {:?}",
        r.errors
    );
    assert_eq!(r.message.body, "orig", "未执行时正文必须原样透传");
}

/// 配额被占满但随后释放：必须排队等到许可并照常执行，
/// 模块应得的结果不能因内部限流而丢失。
#[tokio::test]
async fn script_slot_waits_then_applies_rewrite() {
    let cfg = MitmConfig {
        enabled: true,
        hostnames: vec!["slot.test.local".into()],
        scripts: vec![ScriptRuleConf {
            name: "slot".into(),
            phase: "request".into(),
            pattern: r"^https://slot\.test\.local/x$".into(),
            source: "$done({body:\"rewritten\"});".into(),
            requires_body: true,
            timeout_ms: 300,
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = Arc::new(MitmState::build(&cfg));
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(
            state
                .script_slots
                .clone()
                .try_acquire_owned()
                .expect("4 个许可应能全部占用"),
        );
    }
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        drop(held);
    });

    let msg = ScriptMessage {
        url: "https://slot.test.local/x".into(),
        method: "GET".into(),
        status: 200,
        headers: Vec::new(),
        body: "orig".into(),
        body_bytes: None,
    };
    let r = state
        .run_scripts(ScriptPhase::Request, "https://slot.test.local/x", &msg)
        .await;

    assert!(!r.skipped, "排队成功不得标记跳过");
    assert!(r.errors.is_empty(), "排队后应正常执行: {:?}", r.errors);
    assert_eq!(
        r.message.body, "rewritten",
        "模块应得的改写结果不能被并发状况吃掉"
    );
}
