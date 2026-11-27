use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn default_hit_history_enabled() -> bool { true }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub selected: Option<String>,
    #[serde(default = "default_final")]
    pub final_policy: String,
    #[serde(default)]
    pub rules: Vec<RuleConf>,
    /// M3 策略组：select / url-test / fallback，可嵌套引用其他组。
    #[serde(default)]
    pub proxy_groups: Vec<ProxyGroup>,
    /// 设备侧持久化的组选择；不写入配置文件，重启/热更后仍生效。
    #[serde(default)]
    pub group_selections: BTreeMap<String, String>,
    #[serde(default)]
    pub ads_files: Vec<String>,
    /// D3 历史桶落盘路径；空 = 仅内存。
    #[serde(default)]
    pub hit_history_file: Option<String>,
    /// D2：命中摘要开关；关闭后内存仍可诊断，但不落盘。
    #[serde(default = "default_hit_history_enabled")]
    pub hit_history_enabled: bool,
    /// D0 规则身份表：DNS/分流/Host 由顶层下发；MITM 各段在 mitm.rule_meta。
    #[serde(default)]
    pub rule_meta: Vec<crate::hits::RuleMeta>,
    #[serde(default)]
    pub cn_domains_file: Option<String>,
    #[serde(default)]
    pub cn_ip_file: Option<String>,
    #[serde(default = "default_true")]
    pub block_enabled: bool,
    #[serde(default = "default_block_mode")]
    pub block_mode: String,
    /// 蜂窝 UDP 假活（QUIC 黑洞）自动回落 TCP：443/UDP 在探测窗口内没有任何回包，
    /// 即判定该目标 QUIC 假活，之后对同一目标丢弃 QUIC 包，由客户端自己回退 TCP。
    #[serde(rename = "quicFallback", default = "default_true")]
    pub quic_fallback: bool,
    #[serde(default = "default_true")]
    pub cn_direct: bool,
    #[serde(default = "default_true")]
    pub block_when_no_node: bool,
    /// TUN 模式下的 Fake-IP DNS 应答；dns_only 下强制关闭。
    #[serde(default)]
    pub fake_ip: bool,
    /// Fake-IP 映射落盘路径（mihomo/sing-box cache_file 同款），重启后连接层仍能反查域名。
    #[serde(default)]
    pub fake_ip_file: Option<String>,
    /// 对 TCP 连接嗅探 TLS SNI / HTTP Host；443 优先使用 SNI，不依赖 DNS 反向映射。
    #[serde(default = "default_true")]
    pub sniff: bool,
    /// IPv6 总开关：false 时壳层不建 v6 TUN 地址/路由，内核等效关闭 AAAA。
    #[serde(default = "default_true")]
    pub ipv6: bool,
    /// prefer-ipv6：直连候选地址 v6 优先（默认 v4 优先保可达）。
    #[serde(default)]
    pub prefer_ipv6: bool,
    /// 当前配置的域名后缀绕过列表，优先于普通分流规则直连。
    #[serde(default)]
    pub skip_proxy: Vec<String>,
    /// 拦截 DoT/DoQ（853）迫使系统私人 DNS 回落到 VPN 下发的 53 端口。
    #[serde(default = "default_true")]
    pub block_dot: bool,
    /// MITM 去广告（HTTPS 解密 + URL 拦截 + 响应体改写），默认关闭。
    #[serde(default)]
    pub mitm: crate::mitm::MitmConfig,
    /// TUN MTU：App↔VPN 是纯本机内存拷贝，巨帧把包数降约 6 倍（syscall/拷贝/耗电同降）。
    /// 壳 setMtu 取同一值；establish 失败时壳回退 1500 并写回配置，保证两侧一致。
    #[serde(default = "default_mtu")]
    pub mtu: usize,
    /// 上游（WAN 腿）per-socket TCP_CONGESTION=bbr；内核不支持时静默回退 cubic。
    #[serde(default = "default_true")]
    pub bbr: bool,
    /// TUN 收包校验和验收。默认关：RX 报文全部由本机内核协议栈生成，
    /// 校验和必然正确，逐包验收是纯开销。设 true 恢复逐包验收，
    /// 用于真机 A/B 对照（配合 loopCpuUs / loopThreadCpuPct 指标）。
    #[serde(default)]
    pub tun_rx_checksum_verify: bool,
}

fn default_mode() -> String {
    "rule".into()
}
fn default_final() -> String {
    "proxy".into()
}
fn default_true() -> bool {
    true
}
fn default_block_mode() -> String {
    "nxdomain".into()
}
fn default_mtu() -> usize {
    9000
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ipv6: true,
            prefer_ipv6: false,
            mode: default_mode(),
            dns: DnsConfig::default(),
            nodes: Vec::new(),
            selected: None,
            final_policy: default_final(),
            rules: Vec::new(),
            proxy_groups: Vec::new(),
            group_selections: BTreeMap::new(),
            ads_files: Vec::new(),
            hit_history_file: None,
            hit_history_enabled: true,
            rule_meta: Vec::new(),
            cn_domains_file: None,
            cn_ip_file: None,
            block_enabled: true,
            block_mode: default_block_mode(),
            quic_fallback: true,
            cn_direct: true,
            block_when_no_node: true,
            fake_ip: false,
            fake_ip_file: None,
            sniff: true,
            skip_proxy: Vec::new(),
            block_dot: true,
            mitm: crate::mitm::MitmConfig::default(),
            mtu: default_mtu(),
            bbr: true,
            tun_rx_checksum_verify: false,
        }
    }
}

/// 一个策略组。成员名称可以指向节点，也可以指向另一个策略组。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyGroup {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default = "default_group_type")]
    pub kind: String,
    #[serde(default, alias = "proxies")]
    pub members: Vec<String>,
    #[serde(default = "default_test_url")]
    pub test_url: String,
    /// 健康检查间隔，秒。
    #[serde(default = "default_interval")]
    pub interval: u64,
    /// 单次探测超时，毫秒。
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// url-test 切换容差，毫秒；当前节点仍在该范围内不来回切换。
    #[serde(default = "default_tolerance")]
    pub tolerance: u64,
    /// 连续失败达到该次数才标记不可用。
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// 连续成功达到该次数才恢复可用，避免抖动。
    #[serde(default = "default_recovery_threshold")]
    pub recovery_threshold: u32,
    /// 组内无可用成员：global 沿全局 block_when_no_node，block 拦截，direct 直连。
    #[serde(default = "default_no_node_action")]
    pub no_node_action: String,
    /// load-balance 选路方式：consistent-hash（默认）/ round-robin。
    #[serde(default, alias = "lbMode", alias = "strategy")]
    pub lb_mode: String,
    /// 自动切换最短间隔，秒；当前节点不可用时立即切换，不受此限。
    #[serde(default = "default_switch_interval")]
    pub switch_interval: u64,
}

impl Default for ProxyGroup {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: default_group_type(),
            members: Vec::new(),
            test_url: default_test_url(),
            interval: default_interval(),
            timeout: default_timeout(),
            tolerance: default_tolerance(),
            failure_threshold: default_failure_threshold(),
            recovery_threshold: default_recovery_threshold(),
            no_node_action: default_no_node_action(),
            lb_mode: String::new(),
            switch_interval: default_switch_interval(),
        }
    }
}

fn default_group_type() -> String {
    "select".into()
}
fn default_test_url() -> String {
    "http://www.gstatic.com/generate_204".into()
}
fn default_interval() -> u64 {
    600
}
fn default_timeout() -> u64 {
    5_000
}
fn default_tolerance() -> u64 {
    50
}
fn default_failure_threshold() -> u32 {
    3
}
fn default_recovery_threshold() -> u32 {
    2
}
fn default_no_node_action() -> String {
    "global".into()
}
fn default_switch_interval() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsPolicyConf {
    /// 后缀语义：裸域与 `*.` 前缀都匹配该域及其全部子域。
    #[serde(default)]
    pub pattern: String,
    /// 逗号/换行分隔的上游列表，支持 udp/tcp/doh/dot 与 host:port。
    #[serde(default)]
    pub servers: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    #[serde(default = "default_upstream")]
    pub upstream: String,
    #[serde(default)]
    pub fallback: String,
    #[serde(default)]
    pub bootstrap: String,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Surge/Loon `[Host]` 域名映射：直接 IP、CNAME 别名或 server 指定上游。
    /// 外壳合并模块与当前配置后下发；空 = 不覆盖任何域名。
    #[serde(default)]
    pub hosts: std::collections::BTreeMap<String, String>,
    /// [Host] 条目的归因身份；key 为 hostnames 表里的原始 key（小写）。
    #[serde(default)]
    pub host_meta: Vec<crate::hits::RuleMeta>,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u32,
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
    #[serde(default = "default_true")]
    pub query_log: bool,
    /// 乐观缓存（mosdns serve-expired / sing-box optimistic 同款）：
    /// 过期条目先应答再后台刷新，上游抖动时不断网。
    #[serde(default = "default_true")]
    pub serve_expired: bool,
    /// 主/备上游并发竞速（dnsproxy parallel / sing-box race 同款），先回先用。
    #[serde(default)]
    pub race: bool,
    /// DNS rebind 防护（dnsmasq/AdGuard 同款）：公网域解析出私网地址视为投毒。
    #[serde(default = "default_true")]
    pub rebind_protection: bool,
    /// DNS 缓存落盘路径（空 = 不落盘），重启后热域直接命中。
    #[serde(default)]
    pub cache_file: String,
    /// 关闭 AAAA（节点只有 v4 出口时避免 App 拿到 v6 地址连不通），默认开。
    #[serde(default)]
    pub block_aaaa: bool,
    /// Fake-IP 排除表（mihomo fake-ip-filter 同款），命中后走真实解析。
    /// 内置 msftncsi/connecttest、captive portal、局域网、NTP/STUN 等基线，这里只追加。
    #[serde(default)]
    pub fake_ip_filter: Vec<String>,
    /// 异常应答复核（只检查私网/保留/广播等明显异常，不把「境外 IP」当污染）。
    /// 命中异常时才向 fallback 复核，fallback 可用才替换主上游结果。
    #[serde(default = "default_true")]
    pub fallback_filter: bool,
    /// 是否额外把「非中国大陆 IP」也交给 fallback 复核。
    /// 默认关闭：境外 IP 本身不代表污染，开启后才做地域分流式复核。
    #[serde(default)]
    pub fallback_geo_check: bool,
    /// 本地拦截 NXDOMAIN 携带的 SOA TTL（同时作为本地拦截缓存时长），默认 60 秒。
    #[serde(default = "default_block_ttl")]
    pub block_ttl: u32,
    /// 上游 NXDOMAIN 没有 SOA 时使用的保守负缓存 TTL，默认 30 秒。
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl: u32,
    /// Surge/Loon `[DNS]` 按域名策略：最长后缀命中者替换本次查询主上游（列表内有序重试）。
    #[serde(default)]
    pub policies: Vec<DnsPolicyConf>,
    /// hijack-dns：TUN 内全部 :53（UDP+TCP）接管到本地解析；false 时 53 走正常路由。
    #[serde(default = "default_true")]
    pub hijack: bool,
}

fn default_upstream() -> String {
    "https://dns.alidns.com/dns-query".into()
}
fn default_cache_ttl() -> u32 {
    600
}
fn default_cache_size() -> usize {
    2048
}
fn default_block_ttl() -> u32 {
    60
}
fn default_negative_ttl() -> u32 {
    30
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            policies: Vec::new(),
            hijack: true,
            upstream: default_upstream(),
            fallback: String::new(),
            bootstrap: String::new(),
            headers: Default::default(),
            hosts: Default::default(),
            host_meta: Vec::new(),
            cache_ttl: default_cache_ttl(),
            cache_size: default_cache_size(),
            query_log: true,
            serve_expired: true,
            race: false,
            rebind_protection: true,
            cache_file: String::new(),
            block_aaaa: false,
            fake_ip_filter: Vec::new(),
            fallback_filter: true,
            fallback_geo_check: false,
            block_ttl: default_block_ttl(),
            negative_ttl: default_negative_ttl(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Node {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub insecure: Option<bool>,
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default)]
    pub ws_path: Option<String>,
    #[serde(default)]
    pub ws_host: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    /// 节点级 UDP 开关。Clash 订阅里的 `udp: false`、分享链接的 `udp=false`
    /// 都落到这里；缺省跟随协议能力（SS/SOCKS5/Trojan/VLESS 可用）。
    #[serde(default)]
    pub udp: Option<bool>,
}

impl Node {
    pub fn label(&self) -> String {
        if self.name.is_empty() {
            format!("{}:{}", self.server, self.port)
        } else {
            self.name.clone()
        }
    }

    /// 节点是否允许转发 UDP：显式 `udp: false` 优先，其次看协议是否实现。
    pub fn udp_supported(&self) -> bool {
        if self.udp == Some(false) {
            return false;
        }
        matches!(self.kind.as_str(), "ss" | "socks5" | "trojan" | "vless")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleConf {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    pub action: String,
    /// 规则来源（配置 / 模块名），用于「规则诊断」展示；旧配置缺省为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// D0 稳定身份；旧配置缺省时由 source/规则序号兜底。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<crate::hits::RuleMeta>,
    /// Clash `no-resolve`：目标带域名时 IP/GEOIP 规则不参与匹配。
    #[serde(default, alias = "noResolve", skip_serializing_if = "std::ops::Not::not")]
    pub no_resolve: bool,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub domain: Option<String>,
}

/// 配置桥字符串字段路径：壳层经 JSONObject 序列化，个别路径可能把数字/布尔
/// 写进字符串字段（如 PORT 规则值、节点凭据）。严格 serde 会整份拒绝、内核
/// 无法启动。解析前按这些路径把标量统一转字符串；数字字段（port/mtu/超时等）
/// 不在表内，不受影响。`[]`=数组每项，`*`=对象每个值。
const STRING_PATHS: &[&str] = &[
    "mode",
    "final_policy",
    "block_mode",
    "selected",
    "dns.upstream",
    "dns.fallback",
    "dns.bootstrap",
    "dns.hosts.*",
    "dns.headers.*",
    "rules[].type",
    "rules[].value",
    "rules[].action",
    "rules[].source",
    "rules[].meta.section",
    "rules[].meta.key",
    "rules[].meta.rule_id",
    "rules[].meta.source_type",
    "rules[].meta.source_id",
    "rules[].meta.source_name",
    "nodes[].name",
    "nodes[].server",
    "nodes[].method",
    "nodes[].password",
    "nodes[].uuid",
    "nodes[].sni",
    "nodes[].ws_path",
    "nodes[].ws_host",
    "nodes[].flow",
    "proxy_groups[].name",
    "proxy_groups[].type",
    "proxy_groups[].members[]",
    "proxy_groups[].test_url",
    "proxy_groups[].no_node_action",
    "proxy_groups[].lb_mode",
    "group_selections.*",
    "ads_files[]",
    "skip_proxy[]",
    "cn_domains_file",
    "cn_ip_file",
    "fake_ip_file",
    "hit_history_file",
    "mitm.ca_file",
    "mitm.hostnames[]",
    "mitm.skip[]",
    "mitm.url_rewrites[]",
    "mitm.header_rewrites[]",
    "mitm.loon_rewrites[]",
    "mitm.body_rewrites[]",
    "mitm.websocket_rewrites[]",
    "mitm.script_store_file",
    "mitm.mock_base_dir",
    "mitm.notification_file",
    "mitm.environment.*",
    "mitm.app_mode",
    "mitm.rules[].pattern",
    "mitm.rules[].action",
    "mitm.rules[].body_pattern",
    "mitm.rules[].replacement",
    "mitm.rules[].header_field",
    "mitm.rules[].source",
    "mitm.rules[].raw",
    "mitm.scripts[].name",
    "mitm.scripts[].phase",
    "mitm.scripts[].pattern",
    "mitm.scripts[].condition",
    "mitm.scripts[].source",
    "mitm.scripts[].arguments.*",
    "mitm.scripts[].argument_types.*",
    "mitm.scripts[].argument_values.*",
    "mitm.scripts[].cron",
    "mitm.scripts[].trigger",
    "mitm.scripts[].argument_text",
    "mitm.rule_meta[].section",
    "mitm.rule_meta[].key",
    "mitm.rule_meta[].rule_id",
    "mitm.rule_meta[].source_type",
    "mitm.rule_meta[].source_id",
    "mitm.rule_meta[].source_name",
    "dns.host_meta[].section",
    "dns.host_meta[].key",
    "dns.host_meta[].rule_id",
    "dns.host_meta[].source_type",
    "dns.host_meta[].source_id",
    "dns.host_meta[].source_name",
    "rules[].meta.updated_at",
    "rules[].meta.expiry",
    "mitm.rule_meta[].updated_at",
    "mitm.rule_meta[].expiry",
    "dns.host_meta[].updated_at",
    "dns.host_meta[].expiry",
    "scripts[].name",
    "scripts[].file",
    "scripts[].args",
    "nodes[].type",
];

fn coerce_string_at(v: &mut serde_json::Value, path: &[&str]) {
    if path.is_empty() {
        match v {
            serde_json::Value::Number(n) => *v = serde_json::Value::String(n.to_string()),
            serde_json::Value::Bool(b) => *v = serde_json::Value::String(b.to_string()),
            _ => {}
        }
        return;
    }
    match path[0] {
        "[]" => {
            if let serde_json::Value::Array(a) = v {
                for it in a.iter_mut() {
                    coerce_string_at(it, &path[1..]);
                }
            }
        }
        "*" => {
            if let serde_json::Value::Object(m) = v {
                for (_, it) in m.iter_mut() {
                    coerce_string_at(it, &path[1..]);
                }
            }
        }
        k => {
            if let serde_json::Value::Object(m) = v {
                if let Some(it) = m.get_mut(k) {
                    coerce_string_at(it, &path[1..]);
                }
            }
        }
    }
}

/// 壳层下发配置的统一入口：先按字符串字段路径宽容化标量，再严格反序列化。
pub fn parse_lenient(json: &str) -> Result<Config, String> {
    let mut v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    // 字符串 "null"/"NULL" 由 engine 归一化；但真正的 JSON null 会让 String
    // 字段反序列化失败（整份拒绝→内核启动失败）。final_policy 为 JSON null
    // 时按缺省值 proxy 处理，与「字段缺省」一致，避免代理配置兜底落空。
    if let Some(fp) = v.get_mut("final_policy") {
        if fp.is_null() {
            *fp = serde_json::Value::String(default_final());
        }
    }
    for path in STRING_PATHS {
        // 表里数组段写作 "rules[]"，统一成 "rules.[]" 再按点分割
        let norm = if path.contains(".[]") {
            (*path).to_string()
        } else {
            path.replace("[]", ".[]")
        };
        let segs: Vec<&str> = norm.split('.').collect();
        coerce_string_at(&mut v, &segs);
    }
    serde_json::from_value(v).map_err(|e| e.to_string())
}

/// 解析失败时截取报错列附近的 JSON 片段，日志能直接看到是哪个键写错了类型。
pub fn error_context(json: &str, err: &str) -> String {
    let col = err
        .rsplit("column ")
        .next()
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<usize>().ok());
    match col {
        Some(c) if c > 0 => {
            let start = c.saturating_sub(80);
            let end = (c + 40).min(json.len());
            if start < end {
                format!("…{}…", &json[start..end])
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod lenient_tests {
    use super::*;

    #[test]
    fn numeric_scalars_in_string_fields_are_coerced() {
        // 回归：壳层某路径把 PORT 规则值/节点凭据写成数字，严格 serde 整份拒绝
        // 导致「内核启动失败」。宽容解析必须转字符串后正常启动，数字字段不受影响。
        let json = r#"{
            "mode": "filter_only",
            "rules": [{"type": "PORT", "value": 16648, "action": "direct"}],
            "nodes": [{"name": "n", "type": "ss", "server": "1.2.3.4", "port": 443, "password": 123456}],
            "mtu": 9000,
            "dns": {"hosts": {"a.example.com": 16648}}
        }"#;
        let cfg = parse_lenient(json).expect("数字标量应被宽容转字符串");
        assert_eq!(cfg.rules[0].value, "16648");
        assert_eq!(cfg.nodes[0].password.as_deref(), Some("123456"));
        assert_eq!(cfg.nodes[0].port, 443);
        assert_eq!(cfg.mtu, 9000);
        assert_eq!(cfg.dns.hosts.get("a.example.com").map(String::as_str), Some("16648"));
    }

    #[test]
    fn rules_accept_android_no_resolve_flag() {
        let cfg = parse_lenient(
            r#"{"rules":[{"type":"IP-CIDR","value":"192.0.2.0/24","action":"direct","noResolve":true}]}"#,
        ).unwrap();
        assert!(cfg.rules[0].no_resolve);
    }

    #[test]
    fn json_null_final_policy_defaults_to_proxy() {
        // 真正的 JSON null（非字符串 "null"）会让 String 反序列化失败；
        // 配置解析层必须按缺省值 proxy 兜底，避免代理配置最终策略落空。
        let cfg = parse_lenient(r#"{"mode":"rule","final_policy":null}"#)
            .expect("JSON null final_policy 应被宽容处理");
        assert_eq!(cfg.final_policy, "proxy");
        let cfg2 = parse_lenient(r#"{"mode":"rule"}"#).unwrap();
        assert_eq!(cfg2.final_policy, "proxy");
        // 字符串 "null" 原样保留，交由 engine 归一化。
        let cfg3 = parse_lenient(r#"{"final_policy":"null"}"#).unwrap();
        assert_eq!(cfg3.final_policy, "null");
    }

    #[test]
    fn error_context_shows_offending_key() {
        let json = r#"{"rules":[{"type":"PORT","value":16648,"action":"direct"}]}"#;
        let err = "invalid type: integer `16648`, expected a string at line 1 column 33";
        let ctx = error_context(json, err);
        assert!(ctx.contains("value"), "上下文应包含出错键: {}", ctx);
    }
}
