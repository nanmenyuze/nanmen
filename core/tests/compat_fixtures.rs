//! 兼容性基线：把 compat/fixtures 中的固定样本喂给现有订阅解析器，
//! 记录当前真实行为。这里不断言“应该支持”，只锁定基线，供后续逐项改进。

use nanmen_core::subscribe::parse_to_json;
use serde_json::Value;

fn parse(path: &str) -> Value {
    let candidates = [
        format!("../compat/fixtures/{path}"),
        format!("compat/fixtures/{path}"),
    ];
    let text = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_else(|| panic!("fixture not found: {path}"));
    serde_json::from_str(&parse_to_json(&text)).unwrap()
}

fn nodes(v: &Value) -> usize {
    v["nodes"].as_array().map(|a| a.len()).unwrap_or(0)
}

fn unsupported(v: &Value) -> usize {
    v["unsupported"].as_u64().unwrap_or(0) as usize
}

fn diag_count(v: &Value, key: &str) -> usize {
    v["diagnostic_counts"][key].as_u64().unwrap_or(0) as usize
}

fn diagnostics(v: &Value) -> &Vec<Value> {
    v["diagnostics"].as_array().unwrap()
}

fn warnings(v: &Value) -> Vec<String> {
    v["warnings"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn ss_sip002_imports() {
    let v = parse("nodes/ss-sip002.txt");
    assert_eq!(nodes(&v), 1);
    assert_eq!(v["nodes"][0]["type"], "ss");
    assert_eq!(unsupported(&v), 0);
}

#[test]
fn ss_legacy_imports() {
    let v = parse("nodes/ss-legacy.txt");
    assert_eq!(nodes(&v), 1);
    assert_eq!(v["nodes"][0]["type"], "ss");
}

#[test]
fn vmess_imports_while_hysteria_is_diagnosed() {
    let vmess = parse("nodes/vmess.txt");
    assert_eq!(nodes(&vmess), 1);
    assert_eq!(unsupported(&vmess), 0);
    assert_eq!(vmess["nodes"][0]["type"], "vmess");
    let hy2 = parse("nodes/hysteria2.txt");
    assert_eq!(nodes(&hy2), 0);
    assert_eq!(unsupported(&hy2), 1);
}

#[test]
fn ssr_and_wireguard_are_diagnosed() {
    let ssr = parse("nodes/ssr.txt");
    assert_eq!(nodes(&ssr), 0);
    assert_eq!(unsupported(&ssr), 1);
    assert_eq!(diag_count(&ssr, "unsupported_protocol"), 1);
    assert_eq!(diagnostics(&ssr)[0]["category"], "unsupported_protocol");
    assert!(!warnings(&ssr).is_empty());
    let wg = parse("nodes/wireguard.txt");
    assert_eq!(nodes(&wg), 0);
    assert_eq!(unsupported(&wg), 1);
    assert_eq!(diag_count(&wg, "unsupported_protocol"), 1);
}

#[test]
fn vless_reality_and_grpc_are_rejected_with_diagnosis() {
    let v = parse("nodes/vless-reality.txt");
    assert_eq!(nodes(&v), 0);
    assert_eq!(unsupported(&v), 1);
    assert_eq!(diag_count(&v, "unsupported_param"), 1);
    assert!(diagnostics(&v)[0]["reason"]
        .as_str()
        .unwrap()
        .contains("Reality"));

    let v = parse("nodes/vless-grpc.txt");
    assert_eq!(nodes(&v), 0);
    assert_eq!(unsupported(&v), 1);
    assert_eq!(diag_count(&v, "unsupported_param"), 1);
}

#[test]
fn tuic_and_anytls_are_diagnosed() {
    let tuic = parse("nodes/tuic.txt");
    assert_eq!(nodes(&tuic), 0);
    assert_eq!(unsupported(&tuic), 1);
    assert_eq!(diag_count(&tuic, "unsupported_protocol"), 1);
    let anytls = parse("nodes/anytls.txt");
    assert_eq!(nodes(&anytls), 0);
    assert_eq!(unsupported(&anytls), 1);
    assert_eq!(diag_count(&anytls, "unsupported_protocol"), 1);
}

#[test]
fn mixed_valid_and_unknown_nodes_are_all_counted() {
    let base = std::fs::read_to_string("../compat/fixtures/nodes/ss-sip002.txt")
        .or_else(|_| std::fs::read_to_string("compat/fixtures/nodes/ss-sip002.txt"))
        .unwrap();
    let text = format!("{base}\ntuic://u:p@example.com:443#T\nfoo://bar#X\n");
    let v: Value = serde_json::from_str(&parse_to_json(&text)).unwrap();
    assert_eq!(nodes(&v), 1);
    assert_eq!(v["total_lines"].as_u64().unwrap(), 3);
    assert_eq!(unsupported(&v), 2);
    assert_eq!(diag_count(&v, "unsupported_protocol"), 1);
    assert_eq!(diag_count(&v, "unknown_scheme"), 1);
}

#[test]
fn diagnostic_raw_is_redacted() {
    let v: Value = serde_json::from_str(&parse_to_json(
        "vless://uuid-secret@example.com:443?security=reality&flow=xtls-rprx-vision&token=abc#x",
    ))
    .unwrap();
    let d = &v["diagnostics"][0];
    let raw = d["raw"].as_str().unwrap();
    assert!(!raw.contains("uuid-secret"), "{raw}");
    assert!(!raw.contains("token=abc"), "{raw}");
    assert!(raw.contains("<redacted>"), "{raw}");
}

#[test]
fn vless_tcp_ws_trojan_and_socks_import() {
    for path in [
        "nodes/vless-tcp.txt",
        "nodes/vless-ws.txt",
        "nodes/trojan-tcp.txt",
        "nodes/trojan-ws.txt",
        "nodes/socks5.txt",
    ] {
        let v = parse(path);
        assert_eq!(nodes(&v), 1, "{path}");
    }
}

#[test]
fn http_and_https_proxy_import() {
    for path in ["nodes/http.txt", "nodes/https.txt"] {
        let v = parse(path);
        assert_eq!(nodes(&v), 1, "{path}");
        assert_eq!(v["nodes"][0]["type"], "http", "{path}");
        assert_eq!(v["nodes"][0]["tls"], path.ends_with("https.txt"), "{path}");
    }
}

#[test]
fn base64_subscription_decodes_uris() {
    let v = parse("subscriptions/base64-list.txt");
    assert_eq!(nodes(&v), 2);
    assert!(v["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["type"] == "ss"));
    assert!(v["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["type"] == "trojan"));
}

#[test]
fn clash_subscription_imports_nodes_rules_groups() {
    let v = parse("subscriptions/clash-basic.yaml");
    assert_eq!(nodes(&v), 3);
    assert_eq!(v["rules"].as_array().unwrap().len(), 3);
    assert_eq!(v["groups"].as_array().unwrap().len(), 1);
    assert_eq!(v["proxy_groups"].as_array().unwrap().len(), 1);
    assert_eq!(v["proxy_groups"][0]["name"], "Proxy");
    assert_eq!(v["final"], "Proxy");
}

#[test]
fn loon_and_shadowrocket_conf_are_not_subscription_formats() {
    for path in [
        "subscriptions/loon-main.conf",
        "subscriptions/shadowrocket.conf",
    ] {
        let v = parse(path);
        assert_eq!(nodes(&v), 0, "{path}");
        assert_eq!(v["routing"], false, "{path}");
    }
}
