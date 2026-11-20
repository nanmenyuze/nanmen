use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    #[serde(default)]
    pub cn_domains_file: Option<String>,
    #[serde(default)]
    pub cn_ip_file: Option<String>,
    #[serde(default = "default_true")]
    pub block_enabled: bool,
    #[serde(default = "default_block_mode")]
    pub block_mode: String,
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
    /// 拦截 DoT/DoQ（853）迫使系统私人 DNS 回落到 VPN 下发的 53 端口。
    #[serde(default = "default_true")]
    pub block_dot: bool,
    /// MITM 去广告（HTTPS 解密 + URL 拦截 + 响应体改写），默认关闭。
    #[serde(default)]
    pub mitm: crate::mitm::MitmConfig,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            dns: DnsConfig::default(),
            nodes: Vec::new(),
            selected: None,
            final_policy: default_final(),
            rules: Vec::new(),
            proxy_groups: Vec::new(),
            group_selections: BTreeMap::new(),
            ads_files: Vec::new(),
            cn_domains_file: None,
            cn_ip_file: None,
            block_enabled: true,
            block_mode: default_block_mode(),
            cn_direct: true,
            block_when_no_node: true,
            fake_ip: false,
            fake_ip_file: None,
            sniff: true,
            block_dot: true,
            mitm: crate::mitm::MitmConfig::default(),
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
        }
    }
}

fn default_group_type() -> String { "select".into() }
fn default_test_url() -> String { "http://www.gstatic.com/generate_204".into() }
fn default_interval() -> u64 { 600 }
fn default_timeout() -> u64 { 5_000 }
fn default_tolerance() -> u64 { 50 }
fn default_failure_threshold() -> u32 { 3 }
fn default_recovery_threshold() -> u32 { 2 }
fn default_no_node_action() -> String { "global".into() }


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    #[serde(default = "default_upstream")]
    pub upstream: String,
    #[serde(default = "default_fallback")]
    pub fallback: String,
    #[serde(default)]
    pub bootstrap: String,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
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
}

fn default_upstream() -> String {
    "https://dns.alidns.com/dns-query".into()
}
fn default_fallback() -> String {
    "223.5.5.5".into()
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
            upstream: default_upstream(),
            fallback: default_fallback(),
            bootstrap: String::new(),
            headers: Default::default(),
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
}

impl Node {
    pub fn label(&self) -> String {
        if self.name.is_empty() {
            format!("{}:{}", self.server, self.port)
        } else {
            self.name.clone()
        }
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
}

#[derive(Debug, Clone)]
pub struct Target {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub domain: Option<String>,
}
