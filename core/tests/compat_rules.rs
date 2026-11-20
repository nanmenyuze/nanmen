//! 规则运行行为基线：用固定规则直接驱动 RuleEngine，区分“解析计数”和“实际命中”。

use nanmen_core::config::{Config, RuleConf};
use nanmen_core::engine::{Action, ConnKind, RuleEngine};
use std::net::IpAddr;

fn engine(rules: Vec<RuleConf>) -> RuleEngine {
    let cfg = Config {
        rules,
        final_policy: "proxy".into(),
        cn_direct: false,
        ..Default::default()
    };
    RuleEngine::from_config(&cfg)
}

fn rule(kind: &str, value: &str, action: &str) -> RuleConf {
    RuleConf {
        kind: kind.into(),
        value: value.into(),
        action: action.into(),
        source: None,
    }
}

#[test]
fn rule_runtime_matrix() {
    let engine = engine(vec![
        rule("DOMAIN-SUFFIX", "ads.example.com", "block"),
        rule("DOMAIN", "cdn.example.net", "direct"),
        rule("IP-CIDR", "203.0.113.0/24", "proxy"),
        rule("PORT", "8443", "proxy"),
        rule("DOMAIN-REGEX", r"^ad[0-9]+\.example\.com$", "block"),
    ]);
    let ip: IpAddr = "203.0.113.7".parse().unwrap();

    assert_eq!(
        engine.decide(Some("ads.example.com"), ip, 443, ConnKind::Tcp),
        Action::Block,
        "R01 DOMAIN-SUFFIX"
    );
    assert_eq!(
        engine.decide(Some("cdn.example.net"), ip, 443, ConnKind::Tcp),
        Action::Direct,
        "R02 DOMAIN"
    );
    assert_eq!(
        engine.decide(Some("other.example.org"), ip, 443, ConnKind::Tcp),
        Action::Proxy,
        "R03 IP-CIDR"
    );
    assert_eq!(
        engine.decide(Some("other.example.org"), "198.51.100.1".parse().unwrap(), 8443, ConnKind::Tcp),
        Action::Proxy,
        "R04 PORT"
    );
    assert_eq!(
        engine.decide(Some("ad123.example.com"), "198.51.100.1".parse().unwrap(), 443, ConnKind::Tcp),
        Action::Block,
        "R09 DOMAIN-REGEX"
    );
    assert_eq!(
        engine.decide(Some("unmatched.example.org"), "198.51.100.1".parse().unwrap(), 443, ConnKind::Tcp),
        Action::Proxy,
        "R10 FINAL"
    );
}
