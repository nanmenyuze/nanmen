use crate::config::{Node, ProxyGroup, RuleConf};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use url::Url;

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(v) = URL_SAFE_NO_PAD.decode(cleaned.as_bytes()) {
        return Some(v);
    }
    let padded = format!(
        "{}{}",
        cleaned,
        "=".repeat((4 - cleaned.len() % 4) % 4)
    );
    URL_SAFE
        .decode(padded.as_bytes())
        .or_else(|_| STANDARD.decode(padded.as_bytes()))
        .ok()
}

pub struct ParseResult {
    pub nodes: Vec<Node>,
    pub rules: Vec<RuleConf>,
    pub groups: Vec<String>,
    /// Clash proxy-groups 的完整策略组对象；M4 起传给 Kotlin 侧。
    pub proxy_groups: Vec<ProxyGroup>,
    /// 未能导入的条目总数（未知 scheme、协议不支持、参数不支持、无效 URI）。
    pub unsupported: usize,
    pub final_policy: Option<String>,
    pub warnings: Vec<String>,
    pub routing: bool,
    /// 逐条诊断；raw 字段已脱敏，可安全展示/写日志。
    pub diagnostics: Vec<NodeDiagnostic>,
    pub diagnostic_counts: DiagnosticCounts,
    pub total_lines: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DiagnosticCounts {
    pub unknown_scheme: usize,
    pub unsupported_protocol: usize,
    pub unsupported_param: usize,
    pub invalid: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeDiagnostic {
    pub line: usize,
    pub scheme: String,
    pub category: String,
    pub reason: String,
    /// 原文的脱敏形式：保留 scheme/host/port/非敏感参数，掩掉 userinfo 与 token/password 等。
    pub raw: String,
}

impl ParseResult {
    pub fn to_json(&self) -> String {
        json!({
            "nodes": self.nodes,
            "rules": self.rules,
            "groups": self.groups,
            "proxy_groups": self.proxy_groups,
            "unsupported": self.unsupported,
            "final": self.final_policy,
            "warnings": self.warnings,
            "routing": self.routing,
            "diagnostics": self.diagnostics,
            "diagnostic_counts": self.diagnostic_counts,
            "total_lines": self.total_lines,
        })
        .to_string()
    }
}

fn empty_result(routing: bool) -> ParseResult {
    ParseResult {
        nodes: vec![],
        rules: vec![],
        groups: vec![],
        proxy_groups: vec![],
        unsupported: 0,
        final_policy: None,
        warnings: vec![],
        routing,
        diagnostics: vec![],
        diagnostic_counts: DiagnosticCounts::default(),
        total_lines: 0,
    }
}

fn count_diagnostics(diags: &[NodeDiagnostic]) -> DiagnosticCounts {
    let mut c = DiagnosticCounts::default();
    for d in diags {
        match d.category.as_str() {
            "unknown_scheme" => c.unknown_scheme += 1,
            "unsupported_protocol" => c.unsupported_protocol += 1,
            "unsupported_param" => c.unsupported_param += 1,
            _ => c.invalid += 1,
        }
    }
    c
}

/// URI 原文脱敏：userinfo 整体替换；常见凭据参数值替换；VMess/全 Base64 SS 整段隐藏。
fn redact_uri(raw: &str) -> String {
    let line = raw.trim();
    let Some((scheme, rest)) = line.split_once("://") else {
        return line.to_string();
    };
    let scheme_lower = scheme.to_ascii_lowercase();
    let (main, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    if scheme_lower == "vmess" {
        return format!("{}://<redacted>{}", scheme, if fragment.is_empty() { "" } else { "#<redacted>" });
    }
    if scheme_lower == "ss" && !main.contains('@') {
        return format!("{}://<redacted>{}", scheme, if fragment.is_empty() { "" } else { "#<redacted>" });
    }
    let (body, query) = main.split_once('?').unwrap_or((main, ""));
    let body = if let Some(at) = body.rfind('@') {
        format!("<redacted>@{}", &body[at + 1..])
    } else {
        body.to_string()
    };
    let mut q = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let sensitive = matches!(
            k.to_ascii_lowercase().as_str(),
            "password" | "passwd" | "pwd" | "token" | "access_token" | "secret"
                | "auth" | "authorization" | "uuid" | "key" | "private_key"
        );
        q.push(if sensitive { format!("{}=<redacted>", k) } else { format!("{}={}", k, v) });
    }
    let mut out = format!("{}://{}", scheme, body);
    if !q.is_empty() {
        out.push('?');
        out.push_str(&q.join("&"));
    }
    if !fragment.is_empty() {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

fn diagnose_uri(raw: &str, line: usize) -> NodeDiagnostic {
    let lower = raw.trim().to_ascii_lowercase();
    let scheme = lower.split("://").next().unwrap_or("").to_string();
    let known_uri = matches!(scheme.as_str(), "ss" | "trojan" | "vless" | "socks5" | "socks" | "http" | "https");
    let known_unsupported = matches!(
        scheme.as_str(),
        "vmess" | "hysteria" | "hysteria2" | "hy2" | "tuic" | "ssr" | "wireguard" | "wg"
            | "anytls" | "snell" | "shadowtls" | "juicity" | "mieru" | "ssh" | "h2" | "http2"
    );
    let (category, reason) = if known_unsupported {
        ("unsupported_protocol", format!("{} 协议暂不支持，已跳过", scheme))
    } else if !known_uri {
        ("unknown_scheme", format!("未知 URI scheme：{}", if scheme.is_empty() { "无" } else { &scheme }))
    } else {
        classify_uri_failure(raw, &scheme)
    };
    NodeDiagnostic { line, scheme, category: category.into(), reason, raw: redact_uri(raw) }
}

fn classify_uri_failure(raw: &str, scheme: &str) -> (&'static str, String) {
    let Ok(u) = Url::parse(raw.trim()) else {
        return ("invalid", "URI 格式无效".into());
    };
    let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
    match scheme {
        "vless" => {
            if q.get("security").map(|s| s.eq_ignore_ascii_case("reality")).unwrap_or(false) {
                return ("unsupported_param", "不支持 security=Reality".into());
            }
            if q.get("flow").map(|f| !f.is_empty()).unwrap_or(false) {
                return ("unsupported_param", "不支持非空 flow（XTLS Vision）".into());
            }
            if let Some(net) = q.get("type").or_else(|| q.get("network")) {
                if net != "tcp" && net != "ws" {
                    return ("unsupported_param", format!("不支持传输类型 {}（仅 tcp/ws）", net));
                }
            }
            ("invalid", "VLESS 缺少 UUID 或主机/端口无效".into())
        }
        "trojan" => {
            if q.get("security").map(|s| s.eq_ignore_ascii_case("reality")).unwrap_or(false) {
                return ("unsupported_param", "不支持 security=Reality".into());
            }
            if q.get("flow").map(|f| !f.is_empty()).unwrap_or(false) {
                return ("unsupported_param", "不支持非空 flow".into());
            }
            if let Some(net) = q.get("type").or_else(|| q.get("network")) {
                if net != "tcp" && net != "ws" {
                    return ("unsupported_param", format!("不支持传输类型 {}（仅 tcp/ws）", net));
                }
            }
            ("invalid", "Trojan 缺少密码或主机/端口无效".into())
        }
        "ss" => {
            if q.contains_key("plugin") {
                ("unsupported_param", "不支持 SIP003 plugin".into())
            } else {
                ("invalid", "SS 缺少有效凭据/主机/端口".into())
            }
        }
        "http" | "https" => {
            if u.username().is_empty() && u.password().is_none() && u.port().is_none() {
                ("invalid", "HTTP(S) 代理需要端口或认证信息".into())
            } else {
                ("invalid", "HTTP(S) 代理 URL 无效".into())
            }
        }
        _ => ("invalid", format!("{} URI 缺少有效主机/端口", scheme)),
    }
}

pub fn parse_subscription(text: &str) -> ParseResult {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return empty_result(false);
    }
    // 先尝试 Clash / YAML
    if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(trimmed) {
        if value.get("proxies").is_some() {
            return parse_clash(&value);
        }
    }
    // base64 订阅
    if !trimmed.contains("://") {
        if let Some(decoded) = b64_decode(trimmed) {
            if let Ok(s) = String::from_utf8(decoded) {
                if s.contains("://") {
                    return parse_uri_list(&s);
                }
            }
        }
        let diagnostic = NodeDiagnostic {
            line: 1,
            scheme: "text".into(),
            category: "invalid".into(),
            reason: "未识别的订阅格式：需要 Base64 节点列表、URI 行或 Clash YAML".into(),
            raw: "（非 URI 订阅文本已隐藏）".into(),
        };
        let counts = count_diagnostics(std::slice::from_ref(&diagnostic));
        return ParseResult {
            nodes: vec![],
            rules: vec![],
            groups: vec![],
            proxy_groups: vec![],
            unsupported: 1,
            final_policy: None,
            warnings: diagnostic_warnings(std::slice::from_ref(&diagnostic), &counts),
            routing: false,
            diagnostics: vec![diagnostic],
            diagnostic_counts: counts,
            total_lines: trimmed.lines().count().max(1),
        };
    }
    parse_uri_list(trimmed)
}

fn yaml_str(v: &serde_yaml::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}
fn yaml_u16(v: &serde_yaml::Value, key: &str) -> u16 {
    // 超过 u16 的端口视为无效（0 会被调用方拒绝），避免 as u16 静默回绕到别的端口
    match v.get(key).and_then(|x| x.as_u64()) {
        Some(n) if n <= 65535 => n as u16,
        _ => 0,
    }
}

fn yaml_u64(v: &serde_yaml::Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|x| {
        x.as_u64()
            .or_else(|| x.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
    })
}
fn yaml_bool(v: &serde_yaml::Value, key: &str) -> Option<bool> {
    v.get(key).and_then(|x| x.as_bool())
}

fn diagnostic_summary(c: &DiagnosticCounts) -> String {
    let mut parts = Vec::new();
    if c.unknown_scheme > 0 { parts.push(format!("未知 scheme {}", c.unknown_scheme)); }
    if c.unsupported_protocol > 0 { parts.push(format!("已知不支持协议 {}", c.unsupported_protocol)); }
    if c.unsupported_param > 0 { parts.push(format!("不支持参数 {}", c.unsupported_param)); }
    if c.invalid > 0 { parts.push(format!("无效条目 {}", c.invalid)); }
    if parts.is_empty() { return String::new(); }
    format!(
        "跳过 {} 个节点：{}",
        c.unknown_scheme + c.unsupported_protocol + c.unsupported_param + c.invalid,
        parts.join("，")
    )
}

fn diagnostic_warnings(diags: &[NodeDiagnostic], counts: &DiagnosticCounts) -> Vec<String> {
    if diags.is_empty() {
        return vec![];
    }
    let mut out = vec![diagnostic_summary(counts)];
    for d in diags.iter().take(3) {
        out.push(format!("第 {} 行 {}：{}", d.line, d.scheme, d.reason));
    }
    out
}

fn clash_diagnostic(v: &serde_yaml::Value, line: usize) -> NodeDiagnostic {
    let kind = yaml_str(v, "type").unwrap_or_else(|| "unknown".into());
    let server = yaml_str(v, "server").unwrap_or_default();
    let port = yaml_u16(v, "port");
    let name = yaml_str(v, "name").unwrap_or_default();
    let (category, reason) = if server.is_empty() || port == 0 {
        ("invalid", format!("{} 节点缺少有效 server/port", kind))
    } else if kind == "vless" {
        let reality = v.get("reality-opts").is_some();
        let flow = yaml_str(v, "flow").map(|f| !f.is_empty()).unwrap_or(false);
        let net = yaml_str(v, "network").unwrap_or_else(|| "tcp".into());
        if reality || flow || (net != "tcp" && net != "ws") {
            ("unsupported_param", format!("VLESS 参数不支持（reality={} flow={} network={}）", reality, flow, net))
        } else {
            ("invalid", "VLESS 节点字段无效".into())
        }
    } else if kind == "trojan" {
        let reality = v.get("reality-opts").is_some();
        let flow = yaml_str(v, "flow").map(|f| !f.is_empty()).unwrap_or(false);
        let net = yaml_str(v, "network").unwrap_or_else(|| "tcp".into());
        if reality || flow || (net != "tcp" && net != "ws") {
            ("unsupported_param", format!("Trojan 参数不支持（reality={} flow={} network={}）", reality, flow, net))
        } else {
            ("invalid", "Trojan 节点字段无效".into())
        }
    } else {
        ("unsupported_protocol", format!("{} 协议暂不支持，已跳过", kind))
    };
    let raw = format!("{}://{}:{}{}", kind, server, port, if name.is_empty() { String::new() } else { format!("（{}）", name) });
    NodeDiagnostic { line, scheme: kind, category: category.into(), reason, raw }
}

fn parse_clash(value: &serde_yaml::Value) -> ParseResult {
    let mut nodes = Vec::new();
    let mut diagnostics: Vec<NodeDiagnostic> = Vec::new();
    let mut warnings = Vec::new();
    let mut total_lines = 0usize;
    if let Some(list) = value.get("proxies").and_then(|p| p.as_sequence()) {
        for (idx, item) in list.iter().enumerate() {
            total_lines += 1;
            match clash_node(item) {
                Some(n) => nodes.push(n),
                None => diagnostics.push(clash_diagnostic(item, idx + 1)),
            }
        }
    }
    let node_names: std::collections::HashSet<String> =
        nodes.iter().map(|n| n.name.clone()).collect();
    let mut groups = Vec::new();
    let mut proxy_groups: Vec<ProxyGroup> = Vec::new();
    let mut group_names = std::collections::HashSet::new();
    if let Some(list) = value.get("proxy-groups").and_then(|p| p.as_sequence()) {
        for g in list {
            let Some(name) = yaml_str(g, "name") else { continue };
            if name.trim().is_empty() {
                continue;
            }
            if !group_names.insert(name.clone()) {
                warnings.push(format!("重复策略组名 {}，已跳过后者", name));
                continue;
            }
            groups.push(name.clone());
            let kind = match yaml_str(g, "type").unwrap_or_else(|| "select".into()).to_ascii_lowercase().as_str() {
                "url-test" | "urltest" => "url-test",
                "fallback" => "fallback",
                _ => "select",
            };
            let mut members = Vec::new();
            if let Some(list) = g.get("proxies").and_then(|p| p.as_sequence()) {
                for m in list {
                    if let Some(member) = m.as_str() {
                        let m = member.trim();
                        if m.is_empty() {
                            continue;
                        }
                        if m.eq_ignore_ascii_case("DIRECT")
                            || m.eq_ignore_ascii_case("REJECT")
                            || m.eq_ignore_ascii_case("PROXY")
                        {
                            warnings.push(format!("策略组 {} 忽略内置成员 {}", name, m));
                            continue;
                        }
                        // 成员可能引用后面的组，这里只去重，导入后再由内核校验解析链。
                        if !members.iter().any(|x: &String| x == m) {
                            members.push(m.to_string());
                        }
                    }
                }
            }
            if members.is_empty() {
                warnings.push(format!("策略组 {} 没有有效成员，已跳过", name));
                continue;
            }
            let test_url = yaml_str(g, "url").unwrap_or_else(|| "http://www.gstatic.com/generate_204".into());
            let interval = yaml_u64(g, "interval").unwrap_or(600);
            let timeout = yaml_u64(g, "timeout").unwrap_or(5_000);
            let tolerance = yaml_u64(g, "tolerance").unwrap_or(50);
            proxy_groups.push(ProxyGroup {
                name,
                kind: kind.into(),
                members,
                test_url,
                interval,
                timeout,
                tolerance,
                failure_threshold: 3,
                recovery_threshold: 2,
                no_node_action: "global".into(),
            });
        }
    }
    let mut rules = Vec::new();
    let mut final_policy = None;
    if let Some(list) = value.get("rules").and_then(|p| p.as_sequence()) {
        for r in list {
            if let Some(s) = r.as_str() {
                let Some((kind, rest)) = s.split_once(',') else { continue };
                let kind_up = kind.trim().to_ascii_uppercase();
                if kind_up == "MATCH" || kind_up == "FINAL" {
                    let target = rest.trim();
                    let (action, warning) =
                        map_clash_target(target, &node_names, &group_names);
                    if let Some(w) = warning {
                        warnings.push(w);
                    }
                    final_policy = Some(action);
                    continue;
                }
                if !supported_clash_rule(&kind_up) {
                    warnings.push(format!("跳过不支持的规则: {}", s));
                    continue;
                }
                let rest = if rest.to_ascii_lowercase().ends_with(",no-resolve") {
                    &rest[..rest.len() - ",no-resolve".len()]
                } else {
                    rest
                };
                let parts: Vec<&str> = rest.split(',').collect();
                if parts.len() >= 2 {
                    let target = parts[parts.len() - 1].trim();
                    let (action, warning) =
                        map_clash_target(target, &node_names, &group_names);
                    if let Some(w) = warning {
                        warnings.push(w);
                    }
                    rules.push(RuleConf {
                        kind: kind_up,
                        value: parts[..parts.len() - 1].join(","),
                        action,
                        source: Some("订阅".into()),
                    });
                }
            }
        }
    }
    let counts = count_diagnostics(&diagnostics);
    warnings.extend(diagnostic_warnings(&diagnostics, &counts));
    ParseResult {
        nodes,
        rules,
        groups,
        proxy_groups,
        unsupported: diagnostics.len(),
        final_policy,
        warnings,
        routing: true,
        diagnostic_counts: counts,
        diagnostics,
        total_lines,
    }
}

fn supported_clash_rule(kind: &str) -> bool {
    matches!(
        kind,
        "DOMAIN"
            | "DOMAIN-SUFFIX"
            | "DOMAIN-KEYWORD"
            | "DOMAIN-REGEX"
            | "IP-CIDR"
            | "IP-CIDR6"
            | "PORT"
    )
}

fn map_clash_target(
    target: &str,
    node_names: &std::collections::HashSet<String>,
    group_names: &std::collections::HashSet<String>,
) -> (String, Option<String>) {
    let t = target.trim();
    // 组名优先：Clash 默认组经常直接叫 Proxy。
    if group_names.contains(t) {
        return (t.to_string(), None);
    }
    if node_names.contains(t) {
        return (format!("node:{}", t), None);
    }
    if t.eq_ignore_ascii_case("DIRECT") {
        return ("direct".into(), None);
    }
    if t.eq_ignore_ascii_case("REJECT") || t.eq_ignore_ascii_case("REJECT-DROP") {
        return ("block".into(), None);
    }
    if t.eq_ignore_ascii_case("PROXY") {
        return ("proxy".into(), None);
    }
    (
        "proxy".into(),
        Some(format!("未知策略 {}，相关规则回落到当前选中节点", t)),
    )
}

fn clash_node(v: &serde_yaml::Value) -> Option<Node> {
    let kind = yaml_str(v, "type")?;
    let server = yaml_str(v, "server")?;
    let port = yaml_u16(v, "port");
    if port == 0 {
        return None;
    }
    let name = yaml_str(v, "name").unwrap_or_else(|| format!("{}:{}", server, port));
    match kind.as_str() {
        "ss" | "shadowsocks" => Some(Node {
            name,
            kind: "ss".into(),
            server,
            port,
            method: yaml_str(v, "cipher").or_else(|| yaml_str(v, "method")),
            password: yaml_str(v, "password"),
            uuid: None,
            sni: None,
            insecure: None,
            tls: None,
            ws_path: None,
            ws_host: None,
            flow: None,
        }),
        "trojan" => Some(Node {
            name,
            kind: "trojan".into(),
            server,
            port,
            method: None,
            password: yaml_str(v, "password"),
            uuid: None,
            sni: yaml_str(v, "sni").or_else(|| yaml_str(v, "servername")),
            insecure: yaml_bool(v, "skip-cert-verify"),
            tls: Some(true),
            ws_path: v
                .get("ws-opts")
                .and_then(|w| yaml_str(w, "path"))
                .or_else(|| yaml_str(v, "path")),
            ws_host: v
                .get("ws-opts")
                .and_then(|w| w.get("headers"))
                .and_then(|h| yaml_str(h, "Host"))
                .or_else(|| yaml_str(v, "host")),
            flow: None,
        }),
        "vless" => {
            // Reality / XTLS Vision 未实现：计入不支持，而不是静默导入必连不上的节点。
            if v.get("reality-opts").is_some()
                || yaml_str(v, "flow").map(|f| !f.is_empty()).unwrap_or(false)
            {
                return None;
            }
            // grpc/h2 等未实现的网络类型同样拒绝。
            if let Some(net) = yaml_str(v, "network") {
                if net != "tcp" && net != "ws" {
                    return None;
                }
            }
            Some(Node {
            name,
            kind: "vless".into(),
            server,
            port,
            method: None,
            password: None,
            uuid: yaml_str(v, "uuid"),
            sni: yaml_str(v, "servername").or_else(|| yaml_str(v, "sni")),
            insecure: yaml_bool(v, "skip-cert-verify"),
            // Clash 的 tls 是布尔字段：先按布尔读，再兼容字符串写法；缺省按明文。
            tls: Some(
                yaml_bool(v, "tls")
                    .or_else(|| yaml_str(v, "tls").map(|t| t == "tls"))
                    .unwrap_or(false),
            ),
            ws_path: v
                .get("ws-opts")
                .and_then(|w| yaml_str(w, "path"))
                .or_else(|| yaml_str(v, "path")),
            ws_host: v
                .get("ws-opts")
                .and_then(|w| w.get("headers"))
                .and_then(|h| yaml_str(h, "Host"))
                .or_else(|| yaml_str(v, "host")),
            flow: yaml_str(v, "flow"),
            })
        }
        "socks5" | "socks" => Some(Node {
            name,
            kind: "socks5".into(),
            server,
            port,
            method: None,
            password: yaml_str(v, "password"),
            uuid: yaml_str(v, "username"),
            sni: None,
            insecure: None,
            tls: None,
            ws_path: None,
            ws_host: None,
            flow: None,
        }),
        "http" | "https" => Some(Node {
            name,
            kind: "http".into(),
            server,
            port,
            method: None,
            password: yaml_str(v, "password"),
            uuid: yaml_str(v, "username"),
            sni: None,
            insecure: None,
            tls: Some(kind == "https"),
            ws_path: None,
            ws_host: None,
            flow: None,
        }),
        _ => None,
    }
}

fn parse_uri_list(text: &str) -> ParseResult {
    let mut nodes = Vec::new();
    let mut diagnostics: Vec<NodeDiagnostic> = Vec::new();
    let mut total_lines = 0usize;
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        total_lines += 1;
        match parse_uri(line) {
            Some(n) => nodes.push(n),
            None => diagnostics.push(diagnose_uri(line, line_no + 1)),
        }
    }
    let counts = count_diagnostics(&diagnostics);
    let warnings = diagnostic_warnings(&diagnostics, &counts);
    ParseResult {
        nodes,
        rules: vec![],
        groups: vec![],
        proxy_groups: vec![],
        unsupported: diagnostics.len(),
        final_policy: None,
        warnings,
        routing: false,
        diagnostics,
        diagnostic_counts: counts,
        total_lines,
    }
}

fn parse_uri(line: &str) -> Option<Node> {
    let scheme = line.split("://").next()?.to_ascii_lowercase();
    match scheme.as_str() {
        "ss" => parse_ss(line),
        "trojan" => parse_trojan(line),
        "vless" => parse_vless(line),
        "socks5" | "socks" => parse_socks(line),
        "http" | "https" => parse_http(line),
        _ => None,
    }
}

/// Url 对非特殊 scheme 的 IPv6 主机会保留方括号，内核连接需要裸地址。
fn host_of(u: &Url) -> Option<String> {
    u.host_str().map(|h| {
        h.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    })
}

fn decode_name(u: &Url) -> String {
    let raw = u.fragment().unwrap_or("");
    percent_encoding::percent_decode_str(raw)
        .decode_utf8_lossy()
        .to_string()
}

fn parse_ss(line: &str) -> Option<Node> {
    let body = line.strip_prefix("ss://")?;
    // SIP003 plugin 需要额外的本地插件进程；内核没有实现，不能静默丢掉 query 后
    // 把带插件的节点当普通 SS 导入（否则用户会得到一个必然连不上的节点）。
    let before_fragment = body.split_once('#').map(|(a, _)| a).unwrap_or(body);
    if let Some((_, query)) = before_fragment.split_once('?') {
        if query.split('&').any(|p| p.split_once('=').map(|(k, _)| k.eq_ignore_ascii_case("plugin")).unwrap_or(false)) {
            return None;
        }
    }
    let (main, fragment) = match body.split_once('#') {
        Some((a, b)) => (a, Some(b.to_string())),
        None => (body, None),
    };
    let main = main.split('?').next().unwrap_or(main);
    let name = fragment
        .map(|f| percent_encoding::percent_decode_str(&f).decode_utf8_lossy().to_string())
        .unwrap_or_default();

    if let Some((userinfo, hostpart)) = main.rsplit_once('@') {
        let decoded = b64_decode(userinfo)?;
        let cred = String::from_utf8(decoded).ok()?;
        let (method, password) = cred.split_once(':')?;
        let (host, port) = split_host_port(hostpart)?;
        return Some(Node {
            name: if name.is_empty() { format!("{}:{}", host, port) } else { name },
            kind: "ss".into(),
            server: host,
            port,
            method: Some(method.to_string()),
            password: Some(password.to_string()),
            uuid: None,
            sni: None,
            insecure: None,
            tls: None,
            ws_path: None,
            ws_host: None,
            flow: None,
        });
    }
    // 全 base64 旧格式
    let decoded = b64_decode(main)?;
    let text = String::from_utf8(decoded).ok()?;
    let (cred, hostpart) = text.rsplit_once('@')?;
    let (method, password) = cred.split_once(':')?;
    let (host, port) = split_host_port(hostpart)?;
    Some(Node {
        name: if name.is_empty() { format!("{}:{}", host, port) } else { name },
        kind: "ss".into(),
        server: host,
        port,
        method: Some(method.to_string()),
        password: Some(password.to_string()),
        uuid: None,
        sni: None,
        insecure: None,
        tls: None,
        ws_path: None,
        ws_host: None,
        flow: None,
    })
}

fn split_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim_end_matches('/');
    let (host, port) = if s.starts_with('[') {
        let end = s.find(']')?;
        let host = s[1..end].to_string();
        let port = s[end + 1..].trim_start_matches(':').parse::<u16>().ok()?;
        (host, port)
    } else {
        let (h, p) = s.rsplit_once(':')?;
        (h.to_string(), p.parse::<u16>().ok()?)
    };
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}

fn parse_trojan(line: &str) -> Option<Node> {
    let u = Url::parse(line).ok()?;
    let host = host_of(&u)?;
    let port = u.port().unwrap_or(443);
    let password = percent_encoding::percent_decode_str(u.username())
        .decode_utf8_lossy()
        .to_string();
    let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
    // 只支持 TCP/WS；Reality/flow/grpc 等未实现参数必须拒绝并给出诊断。
    if q.get("security").map(|s| s.eq_ignore_ascii_case("reality")).unwrap_or(false)
        || q.get("flow").map(|f| !f.is_empty()).unwrap_or(false)
    {
        return None;
    }
    let network = q.get("type").cloned().or_else(|| q.get("network").cloned()).unwrap_or_else(|| "tcp".into());
    if network != "tcp" && network != "ws" {
        return None;
    }
    let insecure = q.get("allowInsecure").map(|v| v == "1" || v == "true");
    Some(Node {
        name: {
            let n = decode_name(&u);
            if n.is_empty() { format!("{}:{}", host, port) } else { n }
        },
        kind: "trojan".into(),
        server: host,
        port,
        method: None,
        password: Some(password),
        uuid: None,
        sni: q.get("sni").cloned().or_else(|| q.get("peer").cloned()),
        insecure,
        tls: Some(true),
        ws_path: q.get("path").cloned(),
        ws_host: q.get("host").cloned(),
        flow: None,
    })
}

fn parse_vless(line: &str) -> Option<Node> {
    let u = Url::parse(line).ok()?;
    let host = host_of(&u)?;
    let port = u.port().unwrap_or(443);
    let uuid = u.username().to_string();
    if uuid.is_empty() {
        return None;
    }
    let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
    // Reality / XTLS Vision 未实现：拒绝导入（调用方计入 unsupported 并给出警告）。
    if q.get("security").map(|s| s.eq_ignore_ascii_case("reality")).unwrap_or(false)
        || q.get("flow").map(|f| !f.is_empty()).unwrap_or(false)
    {
        return None;
    }
    // grpc/h2 等未实现的网络类型同样拒绝。
    let network = q.get("type").cloned().unwrap_or_else(|| "tcp".into());
    if network != "tcp" && network != "ws" {
        return None;
    }
    // VLESS 分享链接规范：security 缺省为 none（明文 TCP），不能默认按 TLS 处理。
    let tls = q.get("security").map(|s| s.eq_ignore_ascii_case("tls")).unwrap_or(false);
    Some(Node {
        name: {
            let n = decode_name(&u);
            if n.is_empty() { format!("{}:{}", host, port) } else { n }
        },
        kind: "vless".into(),
        server: host,
        port,
        method: Some(network),
        password: None,
        uuid: Some(uuid),
        sni: q.get("sni").cloned().or_else(|| q.get("peer").cloned()),
        insecure: q.get("allowInsecure").map(|v| v == "1" || v == "true"),
        tls: Some(tls),
        ws_path: q.get("path").cloned(),
        ws_host: q.get("host").cloned(),
        flow: q.get("flow").cloned(),
    })
}

fn parse_socks(line: &str) -> Option<Node> {
    let u = Url::parse(line).ok()?;
    let host = host_of(&u)?;
    let port = u.port().unwrap_or(1080);
    Some(Node {
        name: {
            let n = decode_name(&u);
            if n.is_empty() { format!("{}:{}", host, port) } else { n }
        },
        kind: "socks5".into(),
        server: host,
        port,
        method: None,
        password: Some(percent_encoding::percent_decode_str(u.password().unwrap_or(""))
            .decode_utf8_lossy()
            .to_string()),
        uuid: Some(percent_encoding::percent_decode_str(u.username())
            .decode_utf8_lossy()
            .to_string()),
        sni: None,
        insecure: None,
        tls: None,
        ws_path: None,
        ws_host: None,
        flow: None,
    })
}

fn parse_http(line: &str) -> Option<Node> {
    let u = Url::parse(line).ok()?;
    let host = host_of(&u)?;
    let port = u.port().unwrap_or(if u.scheme() == "https" { 443 } else { 80 });
    let user = percent_encoding::percent_decode_str(u.username())
        .decode_utf8_lossy()
        .to_string();
    let pass = u.password().map(|p| {
        percent_encoding::percent_decode_str(p)
            .decode_utf8_lossy()
            .to_string()
    });
    if user.is_empty() && pass.is_none() && u.port().is_none() {
        return None;
    }
    Some(Node {
        name: {
            let n = decode_name(&u);
            if n.is_empty() { format!("{}:{}", host, port) } else { n }
        },
        kind: "http".into(),
        server: host,
        port,
        method: None,
        password: pass,
        uuid: if user.is_empty() { None } else { Some(user) },
        sni: None,
        insecure: None,
        tls: Some(u.scheme() == "https"),
        ws_path: None,
        ws_host: None,
        flow: None,
    })
}

pub fn parse_to_json(text: &str) -> String {
    parse_subscription(text).to_json()
}

#[allow(dead_code)]
pub fn value_of(json_text: &str) -> Option<Value> {
    serde_json::from_str(json_text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first(text: &str) -> Value {
        let v: Value = serde_json::from_str(&parse_to_json(text)).unwrap();
        v["nodes"][0].clone()
    }

    #[test]
    fn socks5_percent_decodes_credentials() {
        let n = first("socks5://user%40name:p%40ss@1.2.3.4:1080#%E4%B8%AD%E6%96%87");
        assert_eq!(n["uuid"], "user@name");
        assert_eq!(n["password"], "p@ss");
        assert_eq!(n["name"], "中文");
        assert_eq!(n["server"], "1.2.3.4");
        assert_eq!(n["port"], 1080);
    }

    #[test]
    fn socks5_chinese_user_and_ipv6() {
        let n = first("socks5://%E7%94%A8%E6%88%B7:pw@[2001:db8::1]:1080#v6");
        assert_eq!(n["uuid"], "用户");
        assert_eq!(n["server"], "2001:db8::1");
        assert_eq!(n["port"], 1080);
    }

    #[test]
    fn http_percent_decodes_credentials_and_tls() {
        let n = first("https://u%3Aser:p%2Fass@example.com:8443#h");
        assert_eq!(n["uuid"], "u:ser");
        assert_eq!(n["password"], "p/ass");
        assert_eq!(n["system_proxy"], Value::Null);
        assert_eq!(n["tls"], true);
        assert_eq!(n["server"], "example.com");
        assert_eq!(n["port"], 8443);
    }

    #[test]
    fn http_empty_password_is_none() {
        let n = first("http://user@example.com:8080#h");
        assert_eq!(n["uuid"], "user");
        assert_eq!(n["password"], Value::Null);
        assert_eq!(n["tls"], false);
    }
}
