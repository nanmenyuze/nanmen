use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use nanmen_core::config::{Config, DnsConfig, RuleConf};
use nanmen_core::dns::DnsEngine;
use nanmen_core::engine::{Action, ConnKind, FilterEngine, RuleEngine};
use nanmen_core::stats::Stats;
use nanmen_core::subscribe::parse_subscription;
use std::sync::Arc;
use std::sync::Mutex;

/// DNS 日志是进程级全局环形缓冲，两个会 clear 的用例必须串行，避免互相清空。
static DNS_LOG_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn filter_adblock_and_allow() {
    let mut f = FilterEngine::new();
    f.load_text(
        "! comment\n\
         ||ads.example.com^\n\
         ||tracker.test^$third-party\n\
         0.0.0.0 hosts.example.org\n\
         plain.example.net\n\
         /banner[0-9]+/\n\
         video.example.com##.ad-banner\n",
    );
    assert!(f.is_blocked("ads.example.com"));
    assert!(f.is_blocked("sub.ads.example.com"));
    assert!(!f.is_blocked("example.com"));
    // 带条件、元素隐藏规则不能在 DNS 层判断，必须跳过而不是截成主域名
    assert!(!f.is_blocked("tracker.test"));
    assert!(f.skipped >= 2);
    assert!(!f.is_blocked("video.example.com"));
    assert!(f.is_blocked("hosts.example.org"));
    assert!(f.is_blocked("plain.example.net"));
    // URL 正则同样不是 DNS 规则，跳过而不是匹配域名
    assert!(!f.is_blocked("banner123.some.site"));
    // allowlist 优先
    f.load_text("@@||ads.example.com^$document");
    assert!(!f.is_blocked("ads.example.com"));
    assert!(!f.is_blocked("sub.ads.example.com"));
}

#[test]
fn domain_regex_and_port_rules_execute() {
    let cfg = Config {
        rules: vec![
            RuleConf {
                kind: "DOMAIN-REGEX".into(),
                value: r"^ad[0-9]+\.example\.com$".into(),
                action: "block".into(),
                source: None,
                meta: None,
            no_resolve: false,
        },
            RuleConf {
                kind: "PORT".into(),
                value: "8443".into(),
                action: "block".into(),
                source: None,
                meta: None,
            no_resolve: false,
        },
        ],
        final_policy: "direct".into(),
        ..Default::default()
    };
    let engine = RuleEngine::from_config(&cfg);
    assert_eq!(
        engine.decide(
            Some("ad12.example.com"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Block
    );
    assert_eq!(
        engine.decide(
            Some("good.example.com"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Direct
    );
    assert_eq!(
        engine.decide(
            Some("good.example.com"),
            "1.2.3.4".parse().unwrap(),
            8443,
            ConnKind::Tcp
        ),
        Action::Block
    );
    assert_eq!(
        engine.decide(
            Some("good.example.com"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Udp
        ),
        Action::Direct
    );
}

#[test]
fn rules_split() {
    let cfg = Config {
        rules: vec![
            RuleConf {
                kind: "DOMAIN-SUFFIX".into(),
                value: "google.com".into(),
                action: "proxy".into(),
                source: None,
                meta: None,
            no_resolve: false,
        },
            RuleConf {
                kind: "DOMAIN".into(),
                value: "direct.example".into(),
                action: "direct".into(),
                source: None,
                meta: None,
            no_resolve: false,
        },
            RuleConf {
                kind: "IP-CIDR".into(),
                value: "10.0.0.0/8".into(),
                action: "block".into(),
                source: None,
                meta: None,
            no_resolve: false,
        },
        ],
        final_policy: "direct".into(),
        cn_direct: false,
        ..Default::default()
    };
    let engine = RuleEngine::from_config(&cfg);
    assert_eq!(
        engine.decide(
            Some("www.google.com"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Proxy
    );
    assert_eq!(
        engine.decide(
            Some("direct.example"),
            "9.9.9.9".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Direct
    );
    assert_eq!(
        engine.decide(None, "10.1.2.3".parse().unwrap(), 443, ConnKind::Tcp),
        Action::Block
    );
    assert_eq!(
        engine.decide(
            Some("other.site"),
            "8.8.8.8".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Direct
    );
}

#[test]
fn cn_direct_before_final() {
    let cn = std::env::temp_dir().join(format!("namu_cn_test_{}.txt", std::process::id()));
    std::fs::write(&cn, "video.example.com\n").unwrap();
    let cfg = Config {
        rules: vec![RuleConf {
            kind: "DOMAIN-SUFFIX".into(),
            value: "google.com".into(),
            action: "proxy".into(),
            source: None,
            meta: None,
            no_resolve: false,
        }],
        final_policy: "proxy".into(),
        cn_direct: true,
        cn_domains_file: Some(cn.to_string_lossy().to_string()),
        ..Default::default()
    };
    let engine = RuleEngine::from_config(&cfg);
    let _ = std::fs::remove_file(&cn);
    assert_eq!(
        engine.decide(
            Some("www.video.example.com"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Direct
    );
    assert_eq!(
        engine.decide(
            Some("www.google.com"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Proxy
    );
    assert_eq!(
        engine.decide(
            Some("other.example"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Proxy
    );
}

#[test]
fn clash_yaml_parse() {
    let yaml = r#"
proxies:
  - name: "ss-1"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pass
  - name: "tj-1"
    type: trojan
    server: 5.6.7.8
    port: 443
    password: secret
    sni: example.com
    skip-cert-verify: true
  - name: "vl-1"
    type: vless
    server: 9.9.9.9
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: ws
    tls: true
    servername: cdn.example.com
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
  - name: vmess-x
    type: vmess
    server: 7.7.7.7
    port: 443
    uuid: 1111
proxy-groups:
  - name: Proxy
    type: select
    proxies: ["ss-1"]
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN,local.test,DIRECT
  - MATCH,Proxy
"#;
    let r = parse_subscription(yaml);
    assert_eq!(r.nodes.len(), 4);
    assert_eq!(r.unsupported, 0);
    assert_eq!(r.nodes[0].kind, "ss");
    assert_eq!(r.nodes[0].method.as_deref(), Some("aes-256-gcm"));
    assert_eq!(r.nodes[1].insecure, Some(true));
    assert_eq!(r.nodes[2].ws_path.as_deref(), Some("/ray"));
    assert_eq!(r.nodes[2].ws_host.as_deref(), Some("cdn.example.com"));
    assert_eq!(r.rules.len(), 2);
    assert_eq!(r.rules[0].action, "Proxy");
    assert_eq!(r.rules[1].action, "direct");
    // M4：组名保留为动作，不再回落当前节点
    assert_eq!(r.final_policy.as_deref(), Some("Proxy"));
    assert_eq!(r.proxy_groups.len(), 1);
    assert_eq!(r.proxy_groups[0].name, "Proxy");
    assert_eq!(r.proxy_groups[0].kind, "select");
    assert_eq!(r.proxy_groups[0].members, vec!["ss-1".to_string()]);
    assert!(!r.warnings.iter().any(|w| w.contains("策略组 Proxy")));
}

#[test]
fn base64_uri_parse() {
    use base64::Engine;
    let lines = "trojan://pass@1.2.3.4:443?sni=example.com#HK%20Node\n\
                 vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443?security=tls&type=tcp&sni=cdn.test#VL\n\
                 ss://YWVzLTI1Ni1nY206cGFzcw==@9.9.9.9:8388#SS";
    let encoded = base64::engine::general_purpose::STANDARD.encode(lines);
    let r = parse_subscription(&encoded);
    assert_eq!(r.nodes.len(), 3);
    assert_eq!(r.nodes[0].name, "HK Node");
    assert_eq!(
        r.nodes[1].uuid.as_deref(),
        Some("11111111-2222-3333-4444-555555555555")
    );
    assert_eq!(r.nodes[2].method.as_deref(), Some("aes-256-gcm"));
}

#[test]
fn dns_block_response() {
    let mut filter = FilterEngine::new();
    filter.load_text("||ads.test^");
    let stats = Arc::new(Stats::new());
    let dns = Arc::new(DnsEngine::new(
        &DnsConfig {
            upstream: "udp://127.0.0.1:9".into(),
            ..Default::default()
        },
        Arc::new(filter),
        stats.clone(),
        "nxdomain",
        true,
        false,
        true,
    ));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut msg = Message::new();
    msg.set_id(42).set_message_type(MessageType::Query);
    msg.add_query(Query::query(
        Name::from_ascii("sub.ads.test").unwrap(),
        RecordType::A,
    ));
    let req = msg.to_vec().unwrap();
    let resp = rt.block_on(dns.resolve(&req)).unwrap();
    let parsed = Message::from_vec(&resp).unwrap();
    assert_eq!(parsed.response_code(), ResponseCode::NXDomain);
    assert_eq!(
        stats.dns_blocked.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn socks_addr_parse_ipv6_and_domain() {
    let v4 = [0x01u8, 1, 2, 3, 4, 0x01, 0xbb];
    let (d, ip, port, off) = nanmen_core::outbound::parse_socks_addr_bytes(&v4, 0).unwrap();
    assert!(d.is_none());
    assert_eq!(ip.to_string(), "1.2.3.4");
    assert_eq!(port, 443);
    assert_eq!(off, 7);

    let domain = [
        0x03u8, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x00, 0x50,
    ];
    let (d, _, port, off) = nanmen_core::outbound::parse_socks_addr_bytes(&domain, 0).unwrap();
    assert_eq!(d.as_deref(), Some("example.com"));
    assert_eq!(port, 80);
    assert_eq!(off, 15);
}

#[test]
fn vless_domain_addr_is_one_byte_length() {
    use nanmen_core::config::Target;
    use nanmen_core::outbound::encode_vless_addr;
    let target = Target {
        domain: Some("example.com".into()),
        ip: "1.2.3.4".parse().unwrap(),
        port: 443,
    };
    let mut buf = Vec::new();
    encode_vless_addr(&mut buf, &target).unwrap();
    assert_eq!(&buf[0..2], &[1, 187]); // 443，端口在地址前
    assert_eq!(buf[2], 0x02);
    assert_eq!(buf[3], 11);
    assert_eq!(&buf[4..15], b"example.com");
    assert_eq!(buf.len(), 15);
}

#[test]
fn ss_udp_roundtrip() {
    let node = nanmen_core::config::Node {
        name: "test".into(),
        kind: "ss".into(),
        server: "127.0.0.1".into(),
        port: 8388,
        method: Some("aes-256-gcm".into()),
        password: Some("secret".into()),
        uuid: None,
        sni: None,
        insecure: None,
        tls: None,
        ws_path: None,
        ws_host: None,
        flow: None,
        udp: None,
    };
    let cipher = nanmen_core::proto::ss::SsUdpCipher::new(&node).unwrap();
    let target = nanmen_core::config::Target {
        ip: "93.184.216.34".parse().unwrap(),
        port: 443,
        domain: Some("example.com".into()),
    };
    let sealed = cipher.seal(&target, b"payload").unwrap();
    let (out, payload) = cipher.open(&sealed).unwrap();
    assert_eq!(out.domain.as_deref(), Some("example.com"));
    assert_eq!(out.port, 443);
    assert_eq!(payload, b"payload");
}

#[test]
fn fake_ip_response_has_stable_reverse_mapping() {
    let stats = Arc::new(Stats::new());
    let dns = Arc::new(DnsEngine::new(
        &DnsConfig {
            upstream: "udp://127.0.0.1:9".into(),
            ..Default::default()
        },
        Arc::new(FilterEngine::new()),
        stats,
        "nxdomain",
        true,
        true,
        true,
    ));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut msg = Message::new();
    msg.set_id(7).set_message_type(MessageType::Query);
    msg.add_query(Query::query(
        Name::from_ascii("www.example.com").unwrap(),
        RecordType::A,
    ));
    let req = msg.to_vec().unwrap();
    let first = rt.block_on(dns.resolve(&req)).unwrap();
    let second = rt.block_on(dns.resolve(&req)).unwrap();
    let a = Message::from_vec(&first).unwrap();
    let b = Message::from_vec(&second).unwrap();
    let ip = match a.answers()[0].data() {
        Some(RData::A(v4)) => std::net::IpAddr::V4(v4.0),
        other => panic!("expected fake A answer: {:?}", other),
    };
    assert!(nanmen_core::outbound::is_fake_ip(ip));
    assert_eq!(first[2..], second[2..]);
    assert_eq!(b.answers()[0].data(), a.answers()[0].data());
    assert_eq!(
        dns.reverse.lock().unwrap().lookup(ip).as_deref(),
        Some("www.example.com")
    );

    let mut msg6 = Message::new();
    msg6.set_id(8).set_message_type(MessageType::Query);
    msg6.add_query(Query::query(
        Name::from_ascii("www.example.com").unwrap(),
        RecordType::AAAA,
    ));
    let resp6 = rt.block_on(dns.resolve(&msg6.to_vec().unwrap())).unwrap();
    let parsed6 = Message::from_vec(&resp6).unwrap();
    match parsed6.answers()[0].data() {
        Some(RData::AAAA(v6)) => assert!(nanmen_core::outbound::is_fake_ip(std::net::IpAddr::V6(
            v6.0
        ))),
        other => panic!("expected fake AAAA answer: {:?}", other),
    }
}

#[test]
fn sniff_http_host_and_tls_sni() {
    let http = b"GET / HTTP/1.1\r\nHost: Example.COM:443\r\nUser-Agent: test\r\n\r\n";
    assert_eq!(
        nanmen_core::sniff::sniff_domain(http).as_deref(),
        Some("example.com")
    );

    let name = b"www.example.com";
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0u8; 32]);
    body.push(0); // session id
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0); // null compression
    body.extend_from_slice(&((sni_ext.len() + 4) as u16).to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&sni_ext);

    let mut hello = vec![0x01];
    let len = body.len();
    hello.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    hello.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    assert_eq!(
        nanmen_core::sniff::sniff_domain(&record).as_deref(),
        Some("www.example.com")
    );
}

#[test]
fn remote_dns_config_supports_bootstrap_headers_and_query_log() {
    let cfg: Config = serde_json::from_str(
        r#"{
            "mode":"dns_only",
            "dns":{
                "upstream":"https://dns.example.com/dns-query",
                "bootstrap":"203.0.113.10",
                "fallback":"",
                "headers":{"X-Namu-Token":"secret"},
                "query_log":true
            }
        }"#,
    )
    .unwrap();
    assert_eq!(cfg.dns.bootstrap, "203.0.113.10");
    assert_eq!(
        cfg.dns.headers.get("X-Namu-Token").map(String::as_str),
        Some("secret")
    );
    assert_eq!(cfg.dns.fallback, "");
    assert!(cfg.dns.query_log);
}

#[test]
fn dns_query_log_aggregates_same_domain() {
    let _guard = DNS_LOG_TEST_LOCK.lock().unwrap();
    nanmen_core::dns_log::clear();
    for _ in 0..12 {
        nanmen_core::dns_log::add("sdk.e.qq.com", "A", "拦截", "本地规则", 0);
    }
    let json = nanmen_core::dns_log::json_since(0);
    let items: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    // 其他并行用例也会写全局日志，这里只断言目标域名自身的聚合结果。
    let item = items
        .iter()
        .find(|it| it["domain"] == "sdk.e.qq.com")
        .expect("目标域名日志缺失");
    assert_eq!(item["count"], 12);
}

#[test]
fn dns_query_log_keeps_latest_entries() {
    let _guard = DNS_LOG_TEST_LOCK.lock().unwrap();
    nanmen_core::dns_log::clear();
    for i in 0..520 {
        nanmen_core::dns_log::add(
            &format!("q{}.example.com", i),
            "A",
            if i % 2 == 0 { "拦截" } else { "放行" },
            "test",
            i as u64,
        );
    }
    let json = nanmen_core::dns_log::json_since(0);
    let items: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert_eq!(items.len(), 500);
    // 并行用例可能追加少量日志，最后一条不一定是 q519；但最新 q519 必须仍在 500 条窗口内。
    assert!(items.iter().any(|it| it["domain"] == "q519.example.com"));
}

#[test]
fn coalesced_queries_keep_own_ids() {
    use std::sync::atomic::Ordering;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // 本地假上游：延迟 200ms 再回，保证第二个查询一定落在 single-flight 里
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(req) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let mut resp = Message::new();
                resp.set_id(req.id())
                    .set_message_type(MessageType::Response)
                    .set_recursion_available(true);
                for q in req.queries() {
                    resp.add_query(q.clone());
                }
                if let Some(q) = req.queries().first() {
                    resp.add_answer(hickory_proto::rr::Record::from_rdata(
                        q.name().clone(),
                        300,
                        RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                            1, 2, 3, 4,
                        ))),
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                let _ = sock.send_to(&resp.to_vec().unwrap_or_default(), peer).await;
            }
        });

        let stats = Arc::new(Stats::new());
        let cfg = DnsConfig {
            upstream: format!("udp://{}", addr),
            ..Default::default()
        };
        let dns = Arc::new(DnsEngine::new(
            &cfg,
            Arc::new(FilterEngine::new()),
            stats.clone(),
            "nxdomain",
            true,
            false,
            false,
        ));
        let make = |id: u16| {
            let mut m = Message::new();
            m.set_id(id)
                .set_message_type(MessageType::Query)
                .set_recursion_desired(true);
            m.add_query(Query::query(
                Name::from_ascii("same.example.com").unwrap(),
                RecordType::A,
            ));
            m.to_vec().unwrap()
        };
        let (d1, q1) = (dns.clone(), make(11));
        let (d2, q2) = (dns.clone(), make(22));
        let (r1, r2) = tokio::join!(
            tokio::spawn(async move { d1.resolve(&q1).await.unwrap() }),
            tokio::spawn(async move { d2.resolve(&q2).await.unwrap() })
        );
        let r1 = r1.unwrap();
        let r2 = r2.unwrap();
        // 合并后每个请求必须拿到自己的 ID，否则客户端会丢弃应答
        assert_eq!(Message::from_vec(&r1).unwrap().id(), 11);
        assert_eq!(Message::from_vec(&r2).unwrap().id(), 22);
        assert_eq!(Message::from_vec(&r1).unwrap().answers().len(), 1);
        assert_eq!(Message::from_vec(&r2).unwrap().answers().len(), 1);
        assert!(stats.dns_coalesced.load(Ordering::Relaxed) >= 1);
    });
}

// ---------------- 1.8.0 修复回归测试 ----------------

#[test]
fn vless_uri_without_security_defaults_to_plain() {
    // 缺省 security 按规范是 none（明文 TCP），不能默认 TLS
    let r = parse_subscription(
        "vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443?type=tcp#Plain",
    );
    assert_eq!(r.nodes.len(), 1);
    assert_eq!(r.nodes[0].tls, Some(false));
}

#[test]
fn vless_reality_and_vision_rejected_with_warning() {
    let r = parse_subscription(
        "vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443?security=reality#R\n\
         vless://11111111-2222-3333-4444-555555555555@5.6.7.9:443?security=tls&flow=xtls-rprx-vision#V",
    );
    assert_eq!(r.nodes.len(), 0);
    assert_eq!(r.unsupported, 2);
    assert!(r.warnings.iter().any(|w| w.contains("Reality")));
}

#[test]
fn clash_vless_tls_boolean_false_respected() {
    let yaml = r#"
proxies:
  - name: vl-plain
    type: vless
    server: 9.9.9.9
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    tls: false
  - name: vl-reality
    type: vless
    server: 9.9.9.10
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    tls: true
    reality-opts:
      public-key: abc
"#;
    let r = parse_subscription(yaml);
    assert_eq!(r.nodes.len(), 1);
    assert_eq!(r.nodes[0].tls, Some(false));
    assert_eq!(r.unsupported, 1);
}

#[test]
fn encode_addr_rejects_oversized_domain() {
    use nanmen_core::config::Target;
    let target = Target {
        domain: Some("a".repeat(300)),
        ip: "1.2.3.4".parse().unwrap(),
        port: 443,
    };
    let mut buf = Vec::new();
    assert!(nanmen_core::outbound::encode_socks_addr(&mut buf, &target).is_err());
    let mut buf2 = Vec::new();
    assert!(nanmen_core::outbound::encode_vless_addr(&mut buf2, &target).is_err());
}

#[test]
fn route_keyword_rule_case_insensitive() {
    let cfg = Config {
        rules: vec![RuleConf {
            kind: "DOMAIN-KEYWORD".into(),
            value: "Google".into(),
            action: "proxy".into(),
            source: None,
            meta: None,
            no_resolve: false,
        }],
        final_policy: "direct".into(),
        cn_direct: false,
        ..Default::default()
    };
    let engine = RuleEngine::from_config(&cfg);
    assert_eq!(
        engine.decide(
            Some("www.google.com"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Proxy
    );
}

#[test]
fn cn_ip_zero_prefix_and_overlap_handled() {
    let dir = std::env::temp_dir().join(format!("namu-cn0-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cnip.txt");
    // /0 会触发旧实现的移位溢出；重叠区间会破坏二分查找前提
    std::fs::write(&path, "0.0.0.0/0\n1.2.3.0/24\n1.2.3.128/25\n").unwrap();
    let cfg = Config {
        cn_direct: true,
        cn_ip_file: Some(path.to_string_lossy().to_string()),
        final_policy: "proxy".into(),
        ..Default::default()
    };
    let engine = RuleEngine::from_config(&cfg);
    assert_eq!(
        engine.decide(None, "8.8.8.8".parse().unwrap(), 443, ConnKind::Tcp),
        Action::Direct
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ss_udp_replay_rejected() {
    let node = nanmen_core::config::Node {
        name: "test".into(),
        kind: "ss".into(),
        server: "127.0.0.1".into(),
        port: 8388,
        method: Some("aes-256-gcm".into()),
        password: Some("secret".into()),
        uuid: None,
        sni: None,
        insecure: None,
        tls: None,
        ws_path: None,
        ws_host: None,
        flow: None,
        udp: None,
    };
    let cipher = nanmen_core::proto::ss::SsUdpCipher::new(&node).unwrap();
    let target = nanmen_core::config::Target {
        ip: "93.184.216.34".parse().unwrap(),
        port: 443,
        domain: Some("example.com".into()),
    };
    let sealed = cipher.seal(&target, b"payload").unwrap();
    assert!(cipher.open(&sealed).is_ok());
    // 同一报文（同 salt）第二次必须被拒绝
    assert!(cipher.open(&sealed).is_err());
}

#[test]
fn stats_uptime_frozen_after_stop() {
    let s = Stats::new();
    std::thread::sleep(std::time::Duration::from_millis(30));
    s.stopped_at.store(
        nanmen_core::stats::now_ms() as i64,
        std::sync::atomic::Ordering::Relaxed,
    );
    let j1: serde_json::Value = serde_json::from_str(&s.to_json()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    let j2: serde_json::Value = serde_json::from_str(&s.to_json()).unwrap();
    assert_eq!(j1["uptime"], j2["uptime"]);
}

#[test]
fn stats_exposes_tun_egress_diagnostics() {
    use std::sync::atomic::Ordering;
    let s = Stats::new();
    s.tun_tx_drop.fetch_add(2, Ordering::Relaxed);
    s.tun_pending_drop.fetch_add(3, Ordering::Relaxed);
    s.tun_pending_peak.fetch_add(700, Ordering::Relaxed);
    s.tun_tx_backpressure.fetch_add(6, Ordering::Relaxed);
    s.tun_write_would_block.fetch_add(4, Ordering::Relaxed);
    s.tun_write_error.fetch_add(5, Ordering::Relaxed);
    let j: serde_json::Value = serde_json::from_str(&s.to_json()).unwrap();
    assert_eq!(j["tunTxDrop"], 2);
    assert_eq!(j["tunPendingDrop"], 3);
    assert_eq!(j["tunPendingPeak"], 700);
    assert_eq!(j["tunTxBackpressure"], 6);
    assert_eq!(j["tunWriteWouldBlock"], 4);
    assert_eq!(j["tunWriteError"], 5);
}

#[test]
fn decide_detail_matches_decide() {
    let cfg = Config {
        rules: vec![
            RuleConf {
                kind: "DOMAIN-SUFFIX".into(),
                value: ".Google.com".into(),
                action: "proxy".into(),
                source: None,
                meta: None,
            no_resolve: false,
        },
            RuleConf {
                kind: "FINAL".into(),
                value: String::new(),
                action: "direct".into(),
                source: None,
                meta: None,
            no_resolve: false,
        },
        ],
        cn_direct: false,
        ..Default::default()
    };
    let engine = RuleEngine::from_config(&cfg);
    let ip = "1.2.3.4".parse().unwrap();
    let (action, detail) = engine.decide_detail(Some("www.google.com"), ip, 443, ConnKind::Tcp);
    assert_eq!(
        action,
        engine.decide(Some("www.google.com"), ip, 443, ConnKind::Tcp)
    );
    assert!(detail.contains("第 1 条"));
    let (action2, detail2) = engine.decide_detail(Some("other.example"), ip, 443, ConnKind::Tcp);
    assert_eq!(action2, Action::Direct);
    assert!(detail2.contains("最终策略"));
}

#[test]
fn ws_handshake_keeps_early_data_and_validates_accept() {
    use base64::Engine;
    use sha1::{Digest, Sha1};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            // 读握手请求，提取 Sec-WebSocket-Key
            let mut buf = vec![0u8; 4096];
            let mut acc = Vec::new();
            loop {
                let n = server.read(&mut buf).await.unwrap();
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") { break; }
            }
            let text = String::from_utf8_lossy(&acc).to_string();
            let key = text.lines()
                .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
                .unwrap()
                .split(':').nth(1).unwrap().trim().to_string();
            let mut h = Sha1::new();
            h.update(format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key).as_bytes());
            let accept = base64::engine::general_purpose::STANDARD.encode(h.finalize());
            // 101 响应后紧跟一个二进制帧（早到数据，与头部同包）
            let mut out = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                accept
            ).into_bytes();
            out.extend_from_slice(&[0x82, 0x05]); // FIN + binary, len 5, 服务端不掩码
            out.extend_from_slice(b"hello");
            server.write_all(&out).await.unwrap();
            // 保持连接打开，等测试读完
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        });
        let stream: nanmen_core::outbound::BoxStream = Box::new(client);
        let mut wrapped = nanmen_core::proto::ws::wrap(stream, "/ray", "cdn.example.com").await.unwrap();
        let mut got = [0u8; 5];
        tokio::time::timeout(std::time::Duration::from_secs(2), wrapped.read_exact(&mut got))
            .await.unwrap().unwrap();
        assert_eq!(&got, b"hello");
        server_task.abort();
    });
}

#[test]
fn https_proxy_connects_with_tls_before_connect() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["proxy.test.local".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2040, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der.into())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(scfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // 只接受 TLS；若客户端把 HTTPS 当明文 HTTP，这里会握手失败。
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut acc = Vec::new();
            loop {
                let n = tls.read(&mut buf).await.unwrap();
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(acc.starts_with(b"CONNECT example.com:443 HTTP/1.1"));
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nTLS-EARLY")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        });
        let node = nanmen_core::config::Node {
            name: "https-proxy-test".into(),
            kind: "http".into(),
            server: "127.0.0.1".into(),
            port: addr.port(),
            method: None,
            password: None,
            uuid: None,
            sni: None,
            insecure: Some(true),
            tls: Some(true),
            ws_path: None,
            ws_host: None,
            flow: None,
            udp: None,
        };
        let target = nanmen_core::config::Target {
            ip: "93.184.216.34".parse().unwrap(),
            port: 443,
            domain: Some("example.com".into()),
        };
        let mut stream = nanmen_core::proto::socks::connect_http(&node, target)
            .await
            .unwrap();
        let mut got = [0u8; 9];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_exact(&mut got),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&got, b"TLS-EARLY");
        server_task.abort();
    });
}

#[test]
fn http_connect_keeps_early_data() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut acc = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // 200 响应后紧跟早到数据
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nEARLY")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        });
        let node = nanmen_core::config::Node {
            name: "http-test".into(),
            kind: "http".into(),
            server: "127.0.0.1".into(),
            port: addr.port(),
            method: None,
            password: None,
            uuid: None,
            sni: None,
            insecure: None,
            tls: Some(false),
            ws_path: None,
            ws_host: None,
            flow: None,
            udp: None,
        };
        let target = nanmen_core::config::Target {
            ip: "93.184.216.34".parse().unwrap(),
            port: 443,
            domain: Some("example.com".into()),
        };
        let mut stream = nanmen_core::proto::socks::connect_http(&node, target)
            .await
            .unwrap();
        let mut got = [0u8; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_exact(&mut got),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&got, b"EARLY");
        server_task.abort();
    });
}

#[test]
fn wildcard_and_geoip_rules_match_common_clash_syntax() {
    let cn = std::env::temp_dir().join(format!("namu_geoip_test_{}.txt", std::process::id()));
    std::fs::write(&cn, "203.0.113.0/24\n").unwrap();
    let cfg = Config {
        rules: vec![
            RuleConf {
                kind: "DOMAIN-WILDCARD".into(),
                value: "*.ads.example.com".into(),
                action: "block".into(),
                source: None,
                meta: None,
            no_resolve: false,
        },
            RuleConf {
                kind: "GEOIP".into(),
                value: "CN".into(),
                action: "direct".into(),
                source: None,
                meta: None,
            no_resolve: false,
        },
        ],
        cn_direct: false,
        cn_ip_file: Some(cn.to_string_lossy().to_string()),
        final_policy: "proxy".into(),
        ..Default::default()
    };
    let engine = RuleEngine::from_config(&cfg);
    let _ = std::fs::remove_file(&cn);
    assert_eq!(
        engine.decide(
            Some("a.ads.example.com"),
            "198.51.100.1".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Block
    );
    assert_eq!(
        engine.decide(
            Some("good.example.com"),
            "198.51.100.1".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Proxy
    );
    assert_eq!(
        engine.decide(
            Some("good.example.com"),
            "203.0.113.9".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Direct
    );
}

/// 合成模块使用中段通配 MITM 主机（m*.maps.example.com / img*.shop.example.com）。
/// HostMatcher 必须按 glob 全匹配支持，且不误伤子域/后缀伪装。
#[test]
fn host_matcher_mid_wildcard_globs() {
    use nanmen_core::mitm::rewrite::HostMatcher;
    let m = HostMatcher::new(&[
        "m*.maps.example.com".to_string(),
        "img*.shop.example.com".to_string(),
    ]);
    assert!(m.matches("m1.maps.example.com"));
    assert!(m.matches("mxy.maps.example.com"));
    assert!(m.matches("img10.shop.example.com"));
    assert!(!m.matches("maps.example.com"));
    assert!(!m.matches("xm1.maps.example.com"));
    assert!(!m.matches("m1.maps.example.com.evil.com"));
    assert!(!m.is_empty());
}

/// PROTOCOL 规则按连接类型（TCP/UDP）匹配；无效值加载期拒绝，不当成不匹配静默。
#[test]
fn protocol_rule_matches_conn_kind() {
    let cfg = Config {
        rules: vec![RuleConf {
            kind: "PROTOCOL".into(),
            value: "UDP".into(),
            action: "block".into(),
            source: None,
            meta: None,
            no_resolve: false,
        }],
        final_policy: "direct".into(),
        ..Default::default()
    };
    let engine = RuleEngine::from_config(&cfg);
    assert_eq!(
        engine.decide(
            Some("x.example.com"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Udp
        ),
        Action::Block
    );
    assert_eq!(
        engine.decide(
            Some("x.example.com"),
            "1.2.3.4".parse().unwrap(),
            443,
            ConnKind::Tcp
        ),
        Action::Direct
    );
}

#[test]
fn protocol_rule_invalid_value_is_rejected() {
    let cfg = Config {
        rules: vec![RuleConf {
            kind: "PROTOCOL".into(),
            value: "ICMP".into(),
            action: "block".into(),
            source: None,
            meta: None,
            no_resolve: false,
        }],
        final_policy: "direct".into(),
        ..Default::default()
    };
    let engine = RuleEngine::from_config(&cfg);
    assert_eq!(
        engine.decide(None, "1.2.3.4".parse().unwrap(), 443, ConnKind::Udp),
        Action::Direct
    );
    assert_eq!(
        engine.decide(None, "1.2.3.4".parse().unwrap(), 443, ConnKind::Tcp),
        Action::Direct
    );
}
