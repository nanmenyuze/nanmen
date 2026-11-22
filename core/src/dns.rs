use crate::config::DnsConfig;
use crate::dns_log;
use crate::engine::FilterEngine;
use crate::logging;
use crate::stats::{FallbackReason, Stats};
use base64::Engine as _;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use once_cell::sync::Lazy;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Clone)]
struct CacheEntry {
    bytes: Vec<u8>,
    /// 预解析结果：命中时免去每次全量解析 DNS 报文。
    msg: Option<Message>,
    expire: Instant,
    created: Instant,
    hits: u32,
    orig_ttl: u32,
    /// 最近使用序号：命中 O(1) 更新，淘汰时低频扫描最小值（真 LRU 语义）。
    last_use: u64,
}

/// RFC 2308 否定缓存 TTL：取 SOA 记录自身 TTL 与 SOA MINIMUM 的较小值。
fn negative_ttl(msg: &Message) -> Option<u32> {
    msg.name_servers().iter().find_map(|r| match r.data() {
        Some(RData::SOA(s)) => Some(r.ttl().min(s.minimum())),
        _ => None,
    })
}

/// 缓存键：域名 + 类型 + 类别 + DO/CD 标志，避免不同查询语义复用同一应答。
fn cache_key(
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    dnssec_ok: bool,
    cd: bool,
) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        qname,
        u16::from(qtype),
        u16::from(qclass),
        u8::from(dnssec_ok),
        u8::from(cd)
    )
}

struct Cache {
    map: HashMap<String, CacheEntry>,
    clock: u64,
    cap: usize,
    max_ttl: u32,
    /// 乐观缓存窗口：过期后仍可先应答的时长（mosdns serve-expired 同款）
    stale_window: Duration,
    refreshing: HashSet<String>,
    /// 有变化才落盘，避免每 60s 无条件写几 MB。
    dirty: bool,
}

impl Cache {
    fn new(cap: usize, max_ttl: u32) -> Self {
        Self {
            map: HashMap::new(),
            clock: 0,
            cap: cap.max(64),
            max_ttl,
            stale_window: Duration::from_secs(3600),
            refreshing: HashSet::new(),
            dirty: false,
        }
    }
    /// 返回 (应答, 是否过期条目)。过期条目在窗口内保留，供后台刷新。
    fn get(&mut self, key: &str, id: u16) -> Option<(Vec<u8>, bool)> {
        let now = Instant::now();
        let entry = self.map.get(key)?;
        let stale = entry.expire <= now;
        // 0/1/2 秒级短 TTL 不允许走 serve-stale，否则等于把 2 秒延长到一小时。
        if stale && (entry.orig_ttl <= 2 || now.duration_since(entry.expire) > self.stale_window) {
            self.map.remove(key);
            return None;
        }
        let elapsed = now.duration_since(entry.created).as_secs() as u32;
        let bytes = entry.bytes.clone();
        let msg = entry.msg.clone();
        // 缓存命中必须递减 TTL，否则下游会一直使用过期地址。
        self.clock += 1;
        let clock = self.clock;
        if let Some(e) = self.map.get_mut(key) {
            e.hits = e.hits.saturating_add(1);
            e.last_use = clock;
        }
        if let Some(mut msg) = msg {
            msg.set_id(id);
            // 应答、权威区、附加区都要递减：否定缓存带 SOA，SOA TTL 不减会让下游
            // 继续按原始负缓存时间判定，地址变更后仍然拿旧结果。
            let shrink = |r: &mut Record| {
                let ttl = if stale {
                    5
                } else {
                    r.ttl().saturating_sub(elapsed)
                };
                r.set_ttl(ttl);
            };
            for ans in msg.answers_mut() {
                shrink(ans);
            }
            for ns in msg.name_servers_mut() {
                shrink(ns);
            }
            for extra in msg.additionals_mut() {
                shrink(extra);
            }
            if let Ok(out) = msg.to_vec() {
                return Some((out, stale));
            }
        }
        let mut bytes = bytes;
        if bytes.len() >= 2 {
            bytes[0..2].copy_from_slice(&id.to_be_bytes());
        }
        Some((bytes, stale))
    }
    /// 热域预取（mosdns prefetch 同款）：命中>=3 且剩余 TTL 不足 1/5 时后台刷新。
    fn prefetch_due(&self, key: &str) -> bool {
        let Some(e) = self.map.get(key) else {
            return false;
        };
        let now = Instant::now();
        if e.expire <= now || e.hits < 3 || e.orig_ttl == 0 {
            return false;
        }
        let remaining = e.expire.duration_since(now).as_secs() as u32;
        remaining < (e.orig_ttl / 5).max(5)
    }
    fn mark_refreshing(&mut self, key: &str) -> bool {
        self.refreshing.insert(key.to_string())
    }
    fn finish_refresh(&mut self, key: &str) {
        self.refreshing.remove(key);
    }
    fn put(&mut self, key: String, mut bytes: Vec<u8>, ttl: u32) {
        if bytes.len() < 2 {
            return;
        }
        bytes[0..2].copy_from_slice(&0u16.to_be_bytes());
        self.dirty = true;
        let ttl = ttl.min(self.max_ttl.max(30));
        let created = Instant::now();
        let expire = created + Duration::from_secs(ttl as u64);
        let msg = Message::from_vec(&bytes).ok();
        self.clock += 1;
        let entry = CacheEntry {
            bytes,
            msg,
            expire,
            created,
            hits: 0,
            orig_ttl: ttl,
            last_use: self.clock,
        };
        if self.map.contains_key(&key) {
            self.map.insert(key, entry);
            return;
        }
        while self.map.len() >= self.cap {
            // 淘汰最久未用：扫描只发生在缓存满的低频路径，命中路径保持 O(1)。
            let victim = self
                .map
                .iter()
                .min_by_key(|(_, e)| e.last_use)
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => {
                    self.map.remove(&k);
                }
                None => break,
            }
        }
        self.map.insert(key, entry);
    }
}

struct ReverseEntry {
    domain: String,
    expires: Instant,
    /// 同一 IP 被多个域名共用（典型是 CDN）。此时反向域名只能作为候选，
    /// 不能作为 QUIC 443 丢包的可靠依据。
    ambiguous: bool,
}

pub struct ReverseMap {
    map: HashMap<IpAddr, ReverseEntry>,
    cap: usize,
}

impl ReverseMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            cap: 8192,
        }
    }
    pub fn insert(&mut self, ip: IpAddr, domain: &str, ttl: u32) {
        let now = Instant::now();
        if self.map.len() > self.cap {
            self.map.retain(|_, e| e.expires > now);
            if self.map.len() > self.cap {
                self.map.clear();
            }
        }
        let expires = now + Duration::from_secs(ttl.max(5) as u64);
        if let Some(existing) = self.map.get_mut(&ip) {
            if existing.expires > now {
                if !existing.domain.eq_ignore_ascii_case(domain) {
                    existing.ambiguous = true;
                }
                existing.domain = domain.to_string();
                existing.expires = expires;
                return;
            }
        }
        self.map.insert(
            ip,
            ReverseEntry {
                domain: domain.to_string(),
                expires,
                ambiguous: false,
            },
        );
    }
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let e = self.map.get(&ip)?;
        if e.expires <= Instant::now() {
            return None;
        }
        Some(e.domain.clone())
    }
    /// 只在反向映射唯一时返回；QUIC 443 丢包等破坏性策略使用。
    pub fn lookup_confident(&self, ip: IpAddr) -> Option<String> {
        let e = self.map.get(&ip)?;
        if e.expires <= Instant::now() || e.ambiguous {
            return None;
        }
        Some(e.domain.clone())
    }
}

struct FakeIpPool {
    by_domain: HashMap<String, IpAddr>,
    /// 分配顺序，池满时淘汰最老一条（原来整表清空会让存量 Fake-IP 指向错的域名）。
    order: VecDeque<String>,
    next4: u32,
    next6: u64,
    dirty: bool,
}

impl FakeIpPool {
    fn new() -> Self {
        Self {
            by_domain: HashMap::new(),
            order: VecDeque::new(),
            next4: 0xC6120001, // 198.18.0.1，Clash 常用 Fake-IP 段
            next6: 1,
            dirty: false,
        }
    }

    fn allocate(&mut self, domain: &str, qtype: RecordType) -> IpAddr {
        let v4 = qtype == RecordType::A;
        let key = format!("{}|{}", if v4 { "4" } else { "6" }, domain);
        if let Some(ip) = self.by_domain.get(&key) {
            return *ip;
        }
        // 池满后按分配顺序淘汰最老一条，保留其余映射（整表清空会误路由）。
        while self.by_domain.len() >= 65536 {
            match self.order.pop_front() {
                Some(old) => {
                    self.by_domain.remove(&old);
                }
                None => break,
            }
        }
        self.dirty = true;
        self.order.push_back(key.clone());
        let ip = if v4 {
            let ip = IpAddr::V4(Ipv4Addr::from(self.next4));
            self.next4 = if self.next4 >= 0xC613FFFE {
                0xC6120001
            } else {
                self.next4 + 1
            };
            ip
        } else {
            let n = self.next6 as u16;
            let ip = IpAddr::V6(Ipv6Addr::new(0xfc00, 1, 0, 1, 0, 0, 0, n));
            self.next6 = if self.next6 >= 0xFFFE {
                1
            } else {
                self.next6 + 1
            };
            ip
        };
        self.by_domain.insert(key, ip);
        ip
    }

    /// mihomo/sing-box cache_file 同款：Fake-IP 映射落盘，重启后连接层仍能反查域名。
    fn save(&mut self, path: &str) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        // 只保存最近 8192 条，避免长期运行后文件涨到几 MB、每 60s 写盘耗电。
        let mut saved: HashMap<&String, &IpAddr> = HashMap::new();
        for key in self.order.iter().rev().take(8192) {
            if let Some(ip) = self.by_domain.get(key) {
                saved.insert(key, ip);
            }
        }
        let json = serde_json::json!({
            "by_domain": saved,
            "next4": self.next4,
            "next6": self.next6,
        });
        let tmp = format!("{}.tmp", path);
        if std::fs::write(&tmp, json.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    fn load(&mut self, path: &str) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            return;
        };
        if let Some(map) = v.get("by_domain").and_then(|m| m.as_object()) {
            for (k, val) in map {
                if let Some(s) = val.as_str() {
                    if let Ok(ip) = s.parse::<IpAddr>() {
                        self.by_domain.insert(k.clone(), ip);
                        self.order.push_back(k.clone());
                    }
                }
            }
        }
        if let Some(n) = v.get("next4").and_then(|n| n.as_u64()) {
            self.next4 = n as u32;
        }
        if let Some(n) = v.get("next6").and_then(|n| n.as_u64()) {
            self.next6 = n;
        }
    }
}

#[derive(Clone)]
enum UpstreamKind {
    Doh(reqwest::Client, String, HeaderMap),
    Dot(String, u16),
    Udp(String, u16),
}

const HOST_TTL: u32 = 60;

/// `[Host]` 一条配置的已解析形态。`*.domain` 只是匹配修饰，不改变这四类语义。
#[derive(Clone)]
enum HostEntry {
    /// 直接 IP：A/AAAA 本地构造应答，仍受 AAAA 过滤约束，不进 Fake-IP。
    Ip(Vec<IpAddr>),
    /// CNAME 别名：原 qname 改写为别名走上游，应答补 CNAME 链，不进 Fake-IP。
    Alias(String),
    /// server 指定上游：只在 query_upstream 按域名替换主上游，其余链路不动。
    Server(UpstreamKind),
}

#[derive(Clone, Default)]
struct HostMap {
    exact: HashMap<String, HostEntry>,
    /// (去掉 `*.` 的域名, 值)；按最长后缀匹配。
    wildcard: Vec<(String, HostEntry)>,
    /// 解析期拒绝的条目，启动/热重载时写日志，不静默失效。
    rejected: Vec<String>,
}

impl HostMap {
    fn from_config(
        cfg: &DnsConfig,
        primary: &UpstreamKind,
        fallback: Option<&UpstreamKind>,
    ) -> Self {
        let mut map = HostMap::default();
        let mut allowed: HashSet<&'static str> = HashSet::new();
        allowed.insert(upstream_protocol(primary));
        if let Some(f) = fallback {
            allowed.insert(upstream_protocol(f));
        }
        for (raw_key, raw_value) in &cfg.hosts {
            let key = raw_key.trim().trim_end_matches('.').to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            let (name, wildcard) = if let Some(base) = key.strip_prefix("*.") {
                (base.trim_end_matches('.').to_string(), true)
            } else {
                (key.clone(), false)
            };
            if name.is_empty() || !valid_host_name(&name) {
                map.rejected
                    .push(format!("{} = {}（域名无效）", raw_key, raw_value));
                continue;
            }
            match parse_host_value(raw_value, cfg, &allowed) {
                Ok(entry) => {
                    if wildcard {
                        map.wildcard.push((name, entry));
                    } else {
                        map.exact.insert(name, entry);
                    }
                }
                Err(reason) => map
                    .rejected
                    .push(format!("{} = {}（{}）", raw_key, raw_value, reason)),
            }
        }
        // 最长后缀优先；同一后缀重复时先配置者优先（BTreeMap 已保证 key 唯一）。
        map.wildcard.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        map
    }

    fn lookup(&self, host: &str) -> Option<&HostEntry> {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            return None;
        }
        if let Some(e) = self.exact.get(&h) {
            return Some(e);
        }
        self.wildcard.iter().find_map(|(base, entry)| {
            // *.example.com 只匹配子域，不匹配 apex；避免把用户没写的根域一起覆盖。
            if h.len() > base.len()
                && h.ends_with(base)
                && h.as_bytes().get(h.len() - base.len() - 1) == Some(&b'.')
            {
                Some(entry)
            } else {
                None
            }
        })
    }
}

fn upstream_protocol(kind: &UpstreamKind) -> &'static str {
    match kind {
        UpstreamKind::Doh(_, url, _) if url.starts_with("https://") => "https",
        UpstreamKind::Doh(_, _, _) => "http",
        UpstreamKind::Dot(_, _) => "tls",
        UpstreamKind::Udp(_, _) => "udp",
    }
}

fn valid_host_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 || name.contains('*') {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn parse_host_value(
    raw: &str,
    cfg: &DnsConfig,
    allowed: &HashSet<&'static str>,
) -> Result<HostEntry, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("值为空".into());
    }
    if let Some(rest) = value.strip_prefix("server:") {
        let server = rest.trim();
        if server.is_empty() {
            return Err("server 后缺少上游".into());
        }
        if server.eq_ignore_ascii_case("system") {
            return Err("server:system 在 TUN 下语义不成立".into());
        }
        if server.starts_with("http://") {
            return Err("DoH 只接受 https://".into());
        }
        let protocol = if server.starts_with("https://") {
            "https"
        } else if server.starts_with("tls://") || server.starts_with("dot://") {
            "tls"
        } else if server.starts_with("udp://") || !server.contains("://") {
            "udp"
        } else {
            return Err("仅支持 udp://、tls://、https://".into());
        };
        if !allowed.contains(protocol) {
            return Err(format!("当前上游链没有 {} 客户端", protocol));
        }
        let kind = build_upstream(cfg, server).ok_or_else(|| "上游地址无法解析".to_string())?;
        // 协议门已按上游链校验；这里只保留已存在的 UpstreamKind 变体，
        // 不为 Host 单独新建一套传输实现。
        return Ok(HostEntry::Server(kind));
    }
    let parts: Vec<&str> = value
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return Err("值为空".into());
    }
    if parts.iter().all(|p| p.parse::<IpAddr>().is_ok()) {
        let ips: Vec<IpAddr> = parts.iter().filter_map(|p| p.parse().ok()).collect();
        if ips.is_empty() {
            return Err("IP 地址无效".into());
        }
        return Ok(HostEntry::Ip(ips));
    }
    if parts.len() != 1 {
        return Err("别名只能是一个域名，不能与 IP 混写".into());
    }
    let alias = parts[0].trim_end_matches('.');
    if alias.parse::<IpAddr>().is_ok() || !valid_host_name(alias) {
        return Err("别名域名无效".into());
    }
    Ok(HostEntry::Alias(alias.to_ascii_lowercase()))
}

pub struct DnsEngine {
    filter: std::sync::RwLock<Arc<FilterEngine>>,
    pub stats: Arc<Stats>,
    pub reverse: Mutex<ReverseMap>,
    cache: Mutex<Cache>,
    primary: UpstreamKind,
    /// 备用上游支持 udp://、tls://、https://（DoH）三种写法。
    fallback: Option<UpstreamKind>,
    block_mode: String,
    block_enabled: bool,
    fake_enabled: bool,
    fake_pool: Mutex<FakeIpPool>,
    fake_path: Option<String>,
    /// Fake-IP 排除表：局域网、联网探测、NTP/STUN 等必须返回真实地址。
    fake_filter: Vec<String>,
    /// fallback 污染复核开关与 CN IP 段（来自 cnip.txt）。
    fallback_filter: bool,
    /// 是否把「非 CN IP」也作为复核条件；默认关闭，避免把正常境外 CDN 当污染。
    fallback_geo_check: bool,
    block_ttl: u32,
    negative_ttl: u32,
    cn_ips: std::sync::RwLock<Vec<(u32, u32)>>,
    bootstrap: String,
    query_log: bool,
    serve_expired: bool,
    race: bool,
    rebind_protection: bool,
    inflight: Mutex<HashMap<String, Arc<tokio::sync::OnceCell<Option<(Vec<u8>, &'static str)>>>>>,
    breaker: Mutex<Breaker>,
    /// 本地拦截应答缓存：TTL 内跳过规则查询/报文构造；换规则时清空。
    blocked_cache: Mutex<HashMap<String, (Vec<u8>, Instant)>>,
    block_aaaa: bool,
    /// 缓存落盘路径（sing-box cache_file 同款）：重启后热域仍然命中。
    cache_path: Option<String>,
    /// DoT 连接池（sing-box/dnsproxy 同款）：复用 TLS 连接，且最多 4 条并行，
    /// 突发查询不再排在单条连接后面。
    dot_pool: tokio::sync::Mutex<Vec<DotConn>>,
    dot_sem: tokio::sync::Semaphore,
    /// 直连还原真实 IP 的解析缓存：走本引擎上游而不是物理网络系统 DNS，
    /// 避免直连域名泄露给 ISP，也避免逐连接/逐包重复解析。
    real_cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
    /// `[Host]` 配置态；热重载换整颗 DNS 引擎，配置改动不会沿用旧结论。
    hosts: std::sync::RwLock<Arc<HostMap>>,
}

struct DotConn {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    last_used: Instant,
}

/// 证书库与 TLS 配置只加载一次（原来每次查询都读一遍系统证书）。
static TLS_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store())
        .with_no_client_auth();
    Arc::new(config)
});

/// 上游熔断（mihomo health-check / AdGuard failover 同款）：
/// 连续 3 次失败后 30s 内直接走备用，到期半开试探主上游。
struct Breaker {
    fails: u32,
    open_until: Option<Instant>,
}

impl DnsEngine {
    pub fn new(
        cfg: &DnsConfig,
        filter: Arc<FilterEngine>,
        stats: Arc<Stats>,
        block_mode: &str,
        block_enabled: bool,
        fake_enabled: bool,
        query_log: bool,
    ) -> Self {
        let primary = parse_upstream(cfg);
        let fallback = parse_fallback(cfg);
        let mut fake_filter = default_fake_filter();
        for p in &cfg.fake_ip_filter {
            let p = p.trim().trim_end_matches('.').to_ascii_lowercase();
            if !p.is_empty() && !fake_filter.contains(&p) {
                fake_filter.push(p);
            }
        }
        let hosts = HostMap::from_config(cfg, &primary, fallback.as_ref());
        for issue in &hosts.rejected {
            logging::warn("dns", format!("Host 配置未生效：{}", issue));
        }
        Self {
            filter: std::sync::RwLock::new(filter),
            stats,
            reverse: Mutex::new(ReverseMap::new()),
            cache: Mutex::new(Cache::new(cfg.cache_size, cfg.cache_ttl)),
            primary,
            fallback,
            block_mode: block_mode.to_string(),
            block_enabled,
            fake_enabled,
            fake_pool: Mutex::new(FakeIpPool::new()),
            fake_path: None,
            fake_filter,
            fallback_filter: cfg.fallback_filter,
            fallback_geo_check: cfg.fallback_geo_check,
            block_ttl: cfg.block_ttl.max(1),
            negative_ttl: cfg.negative_ttl,
            cn_ips: std::sync::RwLock::new(Vec::new()),
            bootstrap: cfg.bootstrap.clone(),
            query_log,
            serve_expired: cfg.serve_expired,
            race: cfg.race,
            rebind_protection: cfg.rebind_protection,
            inflight: Mutex::new(HashMap::new()),
            breaker: Mutex::new(Breaker {
                fails: 0,
                open_until: None,
            }),
            blocked_cache: Mutex::new(HashMap::new()),
            block_aaaa: cfg.block_aaaa,
            cache_path: None,
            dot_pool: tokio::sync::Mutex::new(Vec::new()),
            dot_sem: tokio::sync::Semaphore::new(4),
            real_cache: Mutex::new(HashMap::new()),
            hosts: std::sync::RwLock::new(Arc::new(hosts)),
        }
    }

    /// 规则热重载（sing-box serviceReload 同款）：换过滤引擎，不重启 TUN。
    pub fn swap_filter(&self, filter: Arc<FilterEngine>) {
        if let Ok(mut f) = self.filter.write() {
            *f = filter;
        }
        // 规则变了，旧拦截结论不能继续命中。
        if let Ok(mut c) = self.blocked_cache.lock() {
            c.clear();
        }
    }

    /// `[Host]` 配置热替换：和 swap_filter 一样清掉旧结论，避免改映射后仍回旧 IP。
    /// 当前外壳走整颗 DNS 引擎热重载；保留这个方法给后续原地刷新复用。
    pub fn swap_hosts(&self, cfg: &DnsConfig) {
        let primary = self.primary.clone();
        let map = HostMap::from_config(cfg, &primary, self.fallback.as_ref());
        for issue in &map.rejected {
            logging::warn("dns", format!("Host 配置未生效：{}", issue));
        }
        if let Ok(mut h) = self.hosts.write() {
            *h = Arc::new(map);
        }
        self.clear_query_caches();
    }

    fn clear_query_caches(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.map.clear();
        }
        if let Ok(mut c) = self.blocked_cache.lock() {
            c.clear();
        }
        if let Ok(mut c) = self.real_cache.lock() {
            c.clear();
        }
        if let Ok(mut c) = self.inflight.lock() {
            c.clear();
        }
    }

    fn host_entry(&self, qname: &str) -> Option<HostEntry> {
        self.hosts
            .read()
            .map(|h| h.lookup(qname).cloned())
            .unwrap_or_else(|p| p.into_inner().lookup(qname).cloned())
    }

    fn host_server(&self, qname: &str) -> Option<UpstreamKind> {
        match self.host_entry(qname) {
            Some(HostEntry::Server(kind)) => Some(kind),
            _ => None,
        }
    }

    pub fn set_fake_path(&mut self, path: Option<String>) {
        if let Some(p) = &path {
            if let Ok(mut pool) = self.fake_pool.lock() {
                pool.load(p);
            }
        }
        self.fake_path = path;
    }

    /// CN IP 段由 cnip.txt 加载；为空时 fallback 复核只拦保留/污染网段。
    pub fn set_cn_ips(&self, ips: Vec<(u32, u32)>) {
        if let Ok(mut r) = self.cn_ips.write() {
            *r = ips;
        }
    }

    pub fn set_cache_path(&mut self, path: Option<String>) {
        if let Some(p) = &path {
            self.load_cache(p);
        }
        self.cache_path = path;
    }

    fn load_cache(&self, path: &str) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            return;
        };
        let Some(arr) = v.get("entries").and_then(|a| a.as_array()) else {
            return;
        };
        let now = crate::stats::now_ms() / 1000;
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        for item in arr {
            let (Some(k), Some(b), Some(e)) = (
                item.get("k").and_then(|x| x.as_str()),
                item.get("b").and_then(|x| x.as_str()),
                item.get("e").and_then(|x| x.as_u64()),
            ) else {
                continue;
            };
            if e <= now {
                continue;
            }
            let Ok(mut bytes) = base64::engine::general_purpose::STANDARD.decode(b) else {
                continue;
            };
            // 保留剩余 TTL 的精确值：抬到 5 秒会让 1/2 秒的短 TTL 条目
            // 绕过「orig_ttl <= 2 不 serve-stale」的限制，重启后反而多活几秒。
            let ttl = (e - now) as u32;
            // 关键：把报文内的记录 TTL 也压到剩余有效期。否则重载后 created 重置，
            // get() 按报文里的原始 TTL 递减，下游会拿到膨胀的 TTL（重启后旧地址被久用）。
            if let Ok(mut msg) = Message::from_vec(&bytes) {
                for rec in msg.answers_mut() {
                    rec.set_ttl(rec.ttl().min(ttl));
                }
                for rec in msg.name_servers_mut() {
                    rec.set_ttl(rec.ttl().min(ttl));
                }
                for rec in msg.additionals_mut() {
                    rec.set_ttl(rec.ttl().min(ttl));
                }
                if let Ok(b) = msg.to_vec() {
                    bytes = b;
                }
            }
            cache.put(k.to_string(), bytes, ttl);
        }
        logging::info("dns", format!("缓存预热载入 {} 条", cache.map.len()));
    }

    pub fn save_cache(&self) {
        let Some(p) = &self.cache_path else { return };
        {
            let Ok(mut c) = self.cache.lock() else { return };
            if !c.dirty {
                return;
            }
            c.dirty = false;
        }
        let now = Instant::now();
        let now_unix = crate::stats::now_ms() / 1000;
        let entries: Vec<serde_json::Value> = {
            let Ok(c) = self.cache.lock() else { return };
            // 按最近使用排序取前 4096：落盘保热域，而不是 HashMap 遍历序的随机子集。
            let mut hot: Vec<(&String, &CacheEntry)> =
                c.map.iter().filter(|(_, e)| e.expire > now).collect();
            hot.sort_by(|a, b| b.1.last_use.cmp(&a.1.last_use));
            hot.into_iter()
                .take(4096)
                .map(|(k, e)| {
                    serde_json::json!({
                        "k": k,
                        "b": base64::engine::general_purpose::STANDARD.encode(&e.bytes),
                        "e": now_unix + e.expire.duration_since(now).as_secs(),
                    })
                })
                .collect()
        };
        if entries.is_empty() {
            return;
        }
        let body = serde_json::json!({"v": 1, "entries": entries}).to_string();
        let tmp = format!("{}.tmp", p);
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }

    /// 停止/周期落盘：Fake-IP 映射 + DNS 缓存一起保存。
    pub fn save_state(&self) {
        self.save_fakeip();
        self.save_cache();
    }

    pub fn save_fakeip(&self) {
        if let Some(p) = &self.fake_path {
            if let Ok(mut pool) = self.fake_pool.lock() {
                pool.save(p);
            }
        }
    }

    /// 直连路径的真实解析：Fake-IP 还原 / 直连域名统一走本引擎上游
    /// （DoH/DoT/UDP + 缓存 + rebind 防护），不经过 Fake-IP 与广告拦截，
    /// 也不再向物理网络系统 DNS 泄露直连域名。
    pub async fn resolve_real(&self, domain: &str, port: u16) -> Option<Vec<SocketAddr>> {
        let key = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if key.is_empty() {
            return None;
        }
        if let Ok(cache) = self.real_cache.lock() {
            if let Some((ips, exp)) = cache.get(&key) {
                if *exp > Instant::now() {
                    return Some(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
                }
            }
        }
        let mut name = Name::from_ascii(&key).ok()?;
        // 直连真实解析也要遵守 [Host]：IP 直接返回，别名换 qname 查上游，
        // server 由 query_upstream 里的域名级上游选择接管。
        if let Some(entry) = self.host_entry(&key) {
            match entry {
                HostEntry::Ip(ips) => {
                    let usable: Vec<IpAddr> = ips
                        .into_iter()
                        .filter(|ip| match ip {
                            IpAddr::V4(_) => true,
                            IpAddr::V6(_) => !self.block_aaaa,
                        })
                        .collect();
                    if usable.is_empty() {
                        return None;
                    }
                    return Some(
                        usable
                            .into_iter()
                            .map(|ip| SocketAddr::new(ip, port))
                            .collect(),
                    );
                }
                HostEntry::Alias(alias) => {
                    name = Name::from_ascii(alias).ok()?;
                }
                HostEntry::Server(_) => {}
            }
        }
        let qtypes: &[RecordType] = if self.block_aaaa {
            &[RecordType::A]
        } else {
            &[RecordType::A, RecordType::AAAA]
        };
        let filter = self
            .filter
            .read()
            .map(|f| f.clone())
            .unwrap_or_else(|p| p.into_inner().clone());
        let mut out: Vec<IpAddr> = Vec::new();
        let mut min_ttl: u32 = 300;
        for qtype in qtypes {
            let mut msg = Message::new();
            msg.set_id(rand::random())
                .set_message_type(MessageType::Query)
                .set_op_code(OpCode::Query)
                .set_recursion_desired(true)
                .add_query(Query::query(name.clone(), *qtype));
            let fwd = prepare_forward(&msg);
            let Ok(bytes) = fwd.to_vec() else { continue };
            let Some(resp) = self.query_upstream(&bytes, &msg).await else {
                continue;
            };
            if self.rebind_protection && is_rebind(&resp, &key, &filter) {
                logging::warn("dns", format!("rebind 防护拦截(直连解析) {}", key));
                continue;
            }
            let Ok(rmsg) = Message::from_vec(&resp) else {
                continue;
            };
            for ans in rmsg.answers() {
                let ip = match ans.data() {
                    Some(RData::A(a)) => IpAddr::V4(a.0),
                    Some(RData::AAAA(a)) => IpAddr::V6(a.0),
                    _ => continue,
                };
                min_ttl = min_ttl.min(ans.ttl().max(5));
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
        if out.is_empty() {
            return None;
        }
        if let Ok(mut cache) = self.real_cache.lock() {
            if cache.len() >= 4096 {
                let now = Instant::now();
                cache.retain(|_, (_, exp)| *exp > now);
                if cache.len() >= 4096 {
                    cache.clear();
                }
            }
            cache.insert(
                key,
                (
                    out.clone(),
                    Instant::now() + Duration::from_secs(min_ttl.min(600) as u64),
                ),
            );
        }
        Some(
            out.into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
        )
    }

    pub async fn resolve(self: &Arc<Self>, req_bytes: &[u8]) -> Option<Vec<u8>> {
        self.resolve_impl(req_bytes, true).await
    }

    /// count_query=false 供 ANY 拆分的内部子查询使用：查询计数只在顶层记一次，
    /// 缓存/过滤/熔断/备用等路径与普通查询完全共用。
    async fn resolve_impl(
        self: &Arc<Self>,
        req_bytes: &[u8],
        count_query: bool,
    ) -> Option<Vec<u8>> {
        let req = match Message::from_vec(req_bytes) {
            Ok(m) => m,
            Err(_) => return None,
        };
        if req.message_type() != MessageType::Query || req.op_code() != OpCode::Query {
            return None;
        }
        let query = req.queries().first()?.clone();
        let qname = query
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let qtype = query.query_type();
        let id = req.id();
        let qtype_label = format!("{:?}", qtype);
        let started = Instant::now();
        if count_query {
            self.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
        }

        // 缓存与并发合并必须区分 qclass、DO、CD：带 DO 的查询要求 DNSSEC 记录，
        // 与普通查询共用条目会把无签名应答回给校验方；CD 影响上游是否做校验。
        let qclass = req
            .queries()
            .first()
            .map(|q| q.query_class())
            .unwrap_or(DNSClass::IN);
        let key = cache_key(
            &qname,
            qtype,
            qclass,
            req.extensions()
                .as_ref()
                .map(|e| e.dnssec_ok())
                .unwrap_or(false),
            req.checking_disabled(),
        );

        let filter = self
            .filter
            .read()
            .map(|f| f.clone())
            .unwrap_or_else(|p| p.into_inner().clone());
        if self.block_enabled && filter.is_blocked(&qname) {
            self.stats.dns_blocked.fetch_add(1, Ordering::Relaxed);
            // 本地拦截应答缓存：规则命中的热门广告域在 TTL 内直接复用应答，
            // 不再每次构造报文/查规则；换规则时 swap_filter 会清空。
            let cached = self
                .blocked_cache
                .lock()
                .ok()
                .and_then(|c| c.get(&key).cloned())
                .filter(|(_, exp)| *exp > Instant::now());
            let resp = match cached {
                Some((resp, _)) => resp,
                None => {
                    let resp = self.blocked_response(&req, qtype);
                    if let Ok(mut c) = self.blocked_cache.lock() {
                        if c.len() >= 2048 {
                            let now = Instant::now();
                            c.retain(|_, (_, exp)| *exp > now);
                            if c.len() >= 2048 {
                                c.clear();
                            }
                        }
                        c.insert(
                            key.clone(),
                            (
                                resp.clone(),
                                Instant::now() + Duration::from_secs(self.block_ttl as u64),
                            ),
                        );
                    }
                    resp
                }
            };
            self.stats
                .record_local_ms(started.elapsed().as_millis() as u64);
            if self.query_log {
                dns_log::add(
                    &qname,
                    &qtype_label,
                    "拦截",
                    "本地规则",
                    started.elapsed().as_millis() as u64,
                );
            }
            return Some(resp);
        }

        // Host 在拦截之后、AAAA/缓存/Fake-IP 之前生效：
        // - IP/别名在本地直接应答，跳过 Fake-IP；
        // - server 只记录为本次 query_upstream 的主上游，链路其余部分不动。
        // AAAA 关闭时，IP/别名同样返回空 NOERROR，不能因为 Host 绕过 AAAA 过滤。
        if qclass == DNSClass::IN {
            if let Some(entry) = self.host_entry(&qname) {
                match entry {
                    HostEntry::Ip(ips) => {
                        let resp = self.host_ip_response(&req, qtype, &qname, &ips);
                        self.stats
                            .record_local_ms(started.elapsed().as_millis() as u64);
                        if self.query_log {
                            dns_log::add(
                                &qname,
                                &qtype_label,
                                "放行",
                                "Host·IP",
                                started.elapsed().as_millis() as u64,
                            );
                        }
                        return Some(resp);
                    }
                    HostEntry::Alias(alias) => {
                        let resp = if self.block_aaaa && qtype == RecordType::AAAA {
                            self.stats.dns_aaaa_blocked.fetch_add(1, Ordering::Relaxed);
                            self.empty_response(&req)
                        } else {
                            self.host_alias_response(&req, qtype, &qname, &alias).await
                        };
                        self.stats
                            .record_local_ms(started.elapsed().as_millis() as u64);
                        if self.query_log {
                            dns_log::add(
                                &qname,
                                &qtype_label,
                                "放行",
                                "Host·别名",
                                started.elapsed().as_millis() as u64,
                            );
                        }
                        return Some(resp);
                    }
                    HostEntry::Server(_) => {
                        // 由 exchange_with_breaker 读取同一份 HostMap 选择上游；
                        // 仍继续走 AAAA 过滤/缓存/Fake-IP/上游的固定顺序。
                    }
                }
            }
        }

        // AAAA 过滤：节点只有 v4 出口时，放行 AAAA 会让 App 拿到 v6 地址后连不通（mihomo ipv6:false 同款）。
        if self.block_aaaa && qtype == RecordType::AAAA {
            self.stats.dns_aaaa_blocked.fetch_add(1, Ordering::Relaxed);
            self.stats
                .record_local_ms(started.elapsed().as_millis() as u64);
            if self.query_log {
                dns_log::add(
                    &qname,
                    &qtype_label,
                    "过滤",
                    "AAAA 已关闭",
                    started.elapsed().as_millis() as u64,
                );
            }
            return Some(self.empty_response(&req));
        }

        if self.fake_enabled
            && (qtype == RecordType::A || qtype == RecordType::AAAA)
            && !self.is_fake_filtered(&qname)
        {
            self.stats
                .record_local_ms(started.elapsed().as_millis() as u64);
            if self.query_log {
                dns_log::add(
                    &qname,
                    &qtype_label,
                    "放行",
                    "Fake-IP",
                    started.elapsed().as_millis() as u64,
                );
            }
            return Some(self.fake_response(&req, qtype, &qname));
        }

        // ANY 不再转发上游：本地拆 A+AAAA 并行查询再合并应答（见 resolve_any）。
        if qtype == RecordType::ANY {
            return Some(self.resolve_any(&req, &qname, id, started).await);
        }

        self.stats.dns_cache_lookups.fetch_add(1, Ordering::Relaxed);
        let cached = self.cache.lock().ok().and_then(|mut c| c.get(&key, id));
        if let Some((cached, stale)) = cached {
            if !stale {
                self.stats.dns_cached.fetch_add(1, Ordering::Relaxed);
                let due = self
                    .cache
                    .lock()
                    .ok()
                    .map(|c| c.prefetch_due(&key))
                    .unwrap_or(false);
                if due {
                    self.spawn_refresh(&key, &qname, &req);
                }
                self.stats
                    .record_local_ms(started.elapsed().as_millis() as u64);
                if self.query_log {
                    dns_log::add(
                        &qname,
                        &qtype_label,
                        "放行",
                        "本地缓存",
                        started.elapsed().as_millis() as u64,
                    );
                }
                return Some(cached);
            }
            if self.serve_expired {
                // 乐观缓存：先应答过期条目（TTL 已在 get 里压到 5），后台刷新。
                self.stats.dns_stale.fetch_add(1, Ordering::Relaxed);
                self.spawn_refresh(&key, &qname, &req);
                self.stats
                    .record_local_ms(started.elapsed().as_millis() as u64);
                if self.query_log {
                    dns_log::add(
                        &qname,
                        &qtype_label,
                        "放行",
                        "过期缓存",
                        started.elapsed().as_millis() as u64,
                    );
                }
                return Some(cached);
            }
        }

        // 隐私：转发前剥掉 EDNS Client Subnet（AdGuard/dnsproxy 默认行为）。
        let fwd = prepare_forward(&req);
        let fwd_bytes = fwd.to_vec().unwrap_or_else(|_| req_bytes.to_vec());
        // single-flight：同域并发查询共享一次上游请求（AdGuard/dnsproxy 同款）。
        let (cell, leader) = {
            let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
            let existed = map.contains_key(&key);
            let cell: Arc<tokio::sync::OnceCell<Option<(Vec<u8>, &'static str)>>> = map
                .entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::OnceCell::new()))
                .clone();
            (cell, !existed)
        };
        let qname2 = qname.clone();
        let key2 = key.clone();
        let key3 = key.clone();
        // 日志标签要同时给闭包和外层用：闭包是 move 的，必须各持一份。
        let qtype_label_inner = qtype_label.clone();
        let engine = self.clone();
        let req2 = req.clone();
        let resp = cell
            .get_or_init(|| async move {
                let t0 = Instant::now();
                let (r, _via) = engine.exchange_with_breaker(&fwd_bytes, &req2).await;
                engine.stats.record_dns_ms(t0.elapsed().as_millis() as u64);
                let r = match r {
                    Some(r) => {
                        if engine.rebind_protection && is_rebind(&r, &qname2, &filter) {
                            engine.stats.dns_rebind.fetch_add(1, Ordering::Relaxed);
                            logging::warn("dns", format!("rebind 防护拦截 {}", qname2));
                            Some((engine.blocked_response(&req2, qtype), "rebind"))
                        } else if let Some(target) = blocked_cname_target(&r, &filter, qtype) {
                            // CNAME 伪装：查询名是第一方正常域名，广告域名藏在应答链里。
                            // 只查 qname 会整条放过去，这里对链上目标再过一遍规则。
                            engine
                                .stats
                                .dns_cname_blocked
                                .fetch_add(1, Ordering::Relaxed);
                            engine.stats.dns_blocked.fetch_add(1, Ordering::Relaxed);
                            logging::info(
                                "dns",
                                format!("CNAME 伪装拦截 {} -> {}", qname2, target),
                            );
                            if engine.query_log {
                                dns_log::add(
                                    &qname2,
                                    &qtype_label_inner,
                                    "拦截",
                                    "CNAME 伪装",
                                    t0.elapsed().as_millis() as u64,
                                );
                            }
                            Some((engine.blocked_response(&req2, qtype), "cname"))
                        } else {
                            engine.cache_and_reverse(&key3, &qname2, &r);
                            Some((r, ""))
                        }
                    }
                    None => None,
                };
                if let Ok(mut map) = engine.inflight.lock() {
                    map.remove(&key2);
                }
                r
            })
            .await
            .clone();
        if !leader {
            self.stats.dns_coalesced.fetch_add(1, Ordering::Relaxed);
        }
        let block_reason: &'static str;
        let mut resp = match resp {
            Some((r, why)) => {
                block_reason = why;
                r
            }
            None => {
                if self.query_log {
                    dns_log::add(
                        &qname,
                        &qtype_label,
                        "失败",
                        "上游无响应",
                        started.elapsed().as_millis() as u64,
                    );
                }
                logging::warn("dns", format!("解析失败 {}", qname));
                return Some(self.servfail_response(&req));
            }
        };
        if self.query_log {
            if !block_reason.is_empty() {
                // CNAME 拦截在上游回调里已经写过日志，这里只补 rebind 的。
                if block_reason == "rebind" {
                    dns_log::add(
                        &qname,
                        &qtype_label,
                        "拦截",
                        "rebind 防护",
                        started.elapsed().as_millis() as u64,
                    );
                }
            } else {
                dns_log::add(
                    &qname,
                    &qtype_label,
                    "放行",
                    if leader { "上游" } else { "并发合并" },
                    started.elapsed().as_millis() as u64,
                );
            }
        }
        // single-flight 复用的是 leader 的应答字节，ID 必须改回本查询自己的，
        // 否则跟随者的客户端会因为 ID 不匹配直接丢弃应答（表现为偶发解析超时）。
        if resp.len() >= 2 {
            resp[0..2].copy_from_slice(&id.to_be_bytes());
        }
        Some(resp)
    }

    /// ANY 本地拆分合并：很多上游（含运营商 DNS）对 ANY 不应答，旧逻辑重试 1-5 次
    /// 白等 3-5s，把平均延迟拖到数百 ms。拆成 A+AAAA 并行（子查询各走缓存/过滤/
    /// 熔断/备用全路径）后合并：任一 NoError 合并记录；都 NXDOMAIN 回 NXDOMAIN；
    /// 都无响应回 SERVFAIL——绝不回空答/NXDOMAIN，否则 App 以为域名不存在。
    async fn resolve_any(
        self: &Arc<Self>,
        req: &Message,
        qname: &str,
        id: u16,
        started: Instant,
    ) -> Vec<u8> {
        use hickory_proto::op::ResponseCode;
        self.stats.dns_any_split.fetch_add(1, Ordering::Relaxed);
        let mut a_req = req.clone();
        a_req.queries_mut()[0].set_query_type(RecordType::A);
        let mut aaaa_req = req.clone();
        aaaa_req.queries_mut()[0].set_query_type(RecordType::AAAA);
        let a_bytes = a_req.to_vec().unwrap_or_default();
        let aaaa_bytes = aaaa_req.to_vec().unwrap_or_default();
        let (a, aaaa) = tokio::join!(
            Box::pin(self.resolve_impl(&a_bytes, false)),
            Box::pin(self.resolve_impl(&aaaa_bytes, false)),
        );
        let ma = a.as_deref().and_then(|b| Message::from_vec(b).ok());
        let mb = aaaa.as_deref().and_then(|b| Message::from_vec(b).ok());
        let ok_a = ma
            .as_ref()
            .map(|m| m.response_code() == ResponseCode::NoError)
            .unwrap_or(false);
        let ok_b = mb
            .as_ref()
            .map(|m| m.response_code() == ResponseCode::NoError)
            .unwrap_or(false);
        let nx_a = ma
            .as_ref()
            .map(|m| m.response_code() == ResponseCode::NXDomain)
            .unwrap_or(false);
        let nx_b = mb
            .as_ref()
            .map(|m| m.response_code() == ResponseCode::NXDomain)
            .unwrap_or(false);
        let mut out = Message::new();
        out.set_id(id);
        out.set_message_type(MessageType::Response);
        out.set_op_code(OpCode::Query);
        out.set_recursion_desired(req.recursion_desired());
        out.set_recursion_available(true);
        out.add_query(req.queries()[0].clone());
        let rcode = if ok_a || ok_b {
            for m in [ma.as_ref(), mb.as_ref()].into_iter().flatten() {
                if m.response_code() == ResponseCode::NoError {
                    out.add_answers(m.answers().iter().cloned());
                }
            }
            ResponseCode::NoError
        } else if nx_a || nx_b {
            for m in [ma.as_ref(), mb.as_ref()].into_iter().flatten() {
                if m.response_code() == ResponseCode::NXDomain {
                    out.add_name_servers(m.name_servers().iter().cloned());
                }
            }
            ResponseCode::NXDomain
        } else {
            ResponseCode::ServFail
        };
        out.set_response_code(rcode);
        // 合并应答不写 ANY 缓存键：让 A/AAAA 各自命中自己的缓存，避免 TTL 混。
        let mut bytes = out.to_vec().unwrap_or_default();
        let limit = req
            .extensions()
            .as_ref()
            .map(|e| e.max_payload() as usize)
            .unwrap_or(512)
            .max(512);
        if bytes.len() > limit {
            // UDP 口径：超限截断置 TC，客户端走 TCP 重试（DNS TCP 路径已有）。
            while bytes.len() > limit && out.answers().len() > 1 {
                out.answers_mut().pop();
                bytes = out.to_vec().unwrap_or_default();
            }
            out.set_truncated(true);
            if bytes.len() > limit {
                out.answers_mut().clear();
            }
            bytes = out.to_vec().unwrap_or_default();
        }
        self.stats
            .record_dns_ms(started.elapsed().as_millis() as u64);
        if self.query_log {
            dns_log::add(
                qname,
                "ANY",
                if rcode == ResponseCode::ServFail {
                    "失败"
                } else {
                    "放行"
                },
                "本地拆分",
                started.elapsed().as_millis() as u64,
            );
        }
        bytes
    }

    fn spawn_refresh(self: &Arc<Self>, key: &str, qname: &str, req: &Message) {
        let should = self
            .cache
            .lock()
            .ok()
            .map(|mut c| c.mark_refreshing(key))
            .unwrap_or(false);
        if !should {
            return;
        }
        let engine = self.clone();
        let fwd = prepare_forward(req);
        let req2 = req.clone();
        let key2 = key.to_string();
        let qname2 = qname.to_string();
        let qt = req.query().map(|q| q.query_type()).unwrap_or(RecordType::A);
        tokio::spawn(async move {
            let bytes = fwd.to_vec().unwrap_or_default();
            let resp = engine.query_upstream(&bytes, &req2).await;
            if let Some(r) = resp {
                let filter = engine
                    .filter
                    .read()
                    .map(|f| f.clone())
                    .unwrap_or_else(|p| p.into_inner().clone());
                if engine.rebind_protection && is_rebind(&r, &qname2, &filter) {
                    // 后台刷新也必须过同一套 rebind 检查，否则坏应答会绕过防护进缓存。
                    engine.stats.dns_rebind.fetch_add(1, Ordering::Relaxed);
                    logging::warn("dns", format!("rebind 防护拦截(刷新) {}", qname2));
                } else if let Some(target) = blocked_cname_target(&r, &filter, qt) {
                    // 刷新路径同样要查 CNAME，否则坏应答会先进缓存、绕过首次查询的检查。
                    engine
                        .stats
                        .dns_cname_blocked
                        .fetch_add(1, Ordering::Relaxed);
                    engine.stats.dns_blocked.fetch_add(1, Ordering::Relaxed);
                    logging::info(
                        "dns",
                        format!("CNAME 伪装拦截(刷新) {} -> {}", qname2, target),
                    );
                } else {
                    engine.cache_and_reverse(&key2, &qname2, &r);
                }
            }
            if let Ok(mut c) = engine.cache.lock() {
                c.finish_refresh(&key2);
            }
        });
    }

    /// 熔断感知的主/备选择：熔断期内直接备用，半开期试探主上游。
    async fn exchange_with_breaker(
        &self,
        fwd: &[u8],
        req: &Message,
    ) -> (Option<Vec<u8>>, &'static str) {
        // Host server 模式：只替换本次查询的主上游，缓存/Fake-IP/过滤链路已经走完。
        // 不把失败回退到全局 fallback：用户显式指定了域名级上游，静默换走会改变预期。
        if let Some(q) = req.queries().first() {
            let qname = q
                .name()
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if let Some(kind) = self.host_server(&qname) {
                let r = self.query_kind(&kind, fwd, req).await;
                self.record_breaker(r.is_some());
                return (r, "Host·指定上游");
            }
        }
        let open = self
            .breaker
            .lock()
            .map(|b| b.open_until.map(|t| Instant::now() < t).unwrap_or(false))
            .unwrap_or(false);
        if open {
            if let Some(fb) = self.fallback.clone() {
                let r = self.query_kind(&fb, fwd, req).await;
                if r.is_some() {
                    self.stats.record_fallback(FallbackReason::Breaker);
                }
                return (r, "备用·熔断");
            }
        }
        if self.race && self.fallback.is_some() {
            let (r, via) = self.race_query(fwd, req).await;
            self.record_breaker(r.is_some());
            return (r, via);
        }
        let r = self.query_primary(fwd, req).await;
        self.record_breaker(r.is_some());
        if let Some(resp) = r {
            // 异常应答复核：默认只复核私网/保留/广播等明显异常；
            // 非 CN IP 只有显式开启 fallback_geo_check 才复核，避免把正常境外 CDN 当污染。
            if self.fallback_filter && self.should_use_fallback(&resp) {
                if let Some(fb) = self.fallback.clone() {
                    if let Some(fb_resp) = self.query_kind(&fb, fwd, req).await {
                        if has_usable_answer(&fb_resp) {
                            self.stats.record_fallback(FallbackReason::Review);
                            return (Some(fb_resp), "备用·污染复核");
                        }
                    }
                }
            }
            return (Some(resp), "上游");
        }
        match self.fallback.clone() {
            Some(fb) => {
                let r = self.query_kind(&fb, fwd, req).await;
                if r.is_some() {
                    self.stats.record_fallback(FallbackReason::PrimaryFailure);
                }
                (r, "备用")
            }
            None => (None, "无备用"),
        }
    }

    fn record_breaker(&self, ok: bool) {
        if !ok {
            // 上游无响应必须计失败：进熔断/备用判定与诊断，
            // 否则「备用查询 0、失败一堆」是统计黑洞。
            self.stats.dns_upstream_fail.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut b) = self.breaker.lock() {
            if ok {
                b.fails = 0;
                b.open_until = None;
            } else {
                b.fails += 1;
                if b.fails >= 3 {
                    b.open_until = Some(Instant::now() + Duration::from_secs(30));
                    b.fails = 0;
                }
            }
        }
    }

    /// 主/备并发竞速（dnsproxy parallel / sing-box race 同款）：先回先用，输家取消。
    /// 写缓存并建立 Fake-IP 反向映射；NXDOMAIN/空 NOERROR 走负缓存（sing-box 同款）。
    fn cache_and_reverse(&self, key: &str, qname: &str, resp: &[u8]) {
        let Ok(msg) = Message::from_vec(resp) else {
            return;
        };
        // 键必须用「原始客户端查询」的键：上游可能在应答里回 DO=0（不支持 DNSSEC
        // 时这是合规行为），若从应答反推就会和查询键不一致，导致永远不命中。
        let key = key.to_string();
        let rcode = msg.response_code();
        let ttl = msg.answers().iter().map(|a| a.ttl()).min();
        match ttl {
            Some(t) => {
                if t > 0 {
                    if let Ok(mut c) = self.cache.lock() {
                        c.put(key.clone(), resp.to_vec(), t);
                    }
                }
            }
            None => {
                if rcode == hickory_proto::op::ResponseCode::NXDomain
                    || (rcode == hickory_proto::op::ResponseCode::NoError
                        && msg.answers().is_empty())
                {
                    // RFC 2308：严格按 SOA 的 min(TTL, MINIMUM)，不再抬到 10 秒下限；
                    // 没有 SOA 时用可配置的保守固定值；TTL=0 表示上游明确「不要缓存」。
                    let ttl = negative_ttl(&msg).unwrap_or(self.negative_ttl).min(300);
                    self.stats.dns_negative.fetch_add(1, Ordering::Relaxed);
                    if ttl > 0 {
                        if let Ok(mut c) = self.cache.lock() {
                            c.put(key.clone(), resp.to_vec(), ttl);
                        }
                    }
                }
            }
        }
        // 真实 IP 也要记反向映射：Fake-IP 关闭时，UDP 只有目的 IP、没有域名，
        // 不记就匹配不到域名规则（只能落 FINAL）。
        for ans in msg.answers() {
            let ip = match ans.data() {
                Some(RData::A(a)) => std::net::IpAddr::V4(a.0),
                Some(RData::AAAA(a)) => std::net::IpAddr::V6(a.0),
                _ => continue,
            };
            if !crate::outbound::is_fake_ip(ip) || self.fake_enabled {
                if let Ok(mut rev) = self.reverse.lock() {
                    rev.insert(ip, qname, ttl.unwrap_or(300).clamp(60, 600));
                }
            }
        }
    }

    async fn race_query(&self, fwd: &[u8], req: &Message) -> (Option<Vec<u8>>, &'static str) {
        let Some(fb) = self.fallback.clone() else {
            return (None, "无备用");
        };
        let primary = self.query_primary(fwd, req);
        let fallback = self.query_kind(&fb, fwd, req);
        tokio::pin!(primary);
        tokio::pin!(fallback);
        let mut p_done = false;
        let mut f_done = false;
        // 先回先用；输家保持存活——一方失败时继续等另一方在途的请求，
        // 而不是取消后重新发起一次全新查询（失败场景延迟翻倍）。
        loop {
            tokio::select! {
                r = &mut primary, if !p_done => {
                    p_done = true;
                    if r.is_some() { return (r, "上游"); }
                }
                r = &mut fallback, if !f_done => {
                    f_done = true;
                    if r.is_some() {
                        self.stats.record_fallback(FallbackReason::Race);
                        return (r, "备用");
                    }
                }
            }
            if p_done && f_done {
                return (None, "无");
            }
        }
    }

    async fn query_upstream(&self, fwd: &[u8], req: &Message) -> Option<Vec<u8>> {
        // 统一走熔断/污染复核路径：后台刷新与直连真实解析不能绕开 fallback-filter。
        self.exchange_with_breaker(fwd, req).await.0
    }

    async fn query_primary(&self, req_bytes: &[u8], req: &Message) -> Option<Vec<u8>> {
        self.query_kind(&self.primary, req_bytes, req).await
    }

    /// 执行任意一种上游：主上游与 fallback 共用，fallback 因此也支持 DoH/DoT/UDP。
    async fn query_kind(
        &self,
        kind: &UpstreamKind,
        req_bytes: &[u8],
        req: &Message,
    ) -> Option<Vec<u8>> {
        match kind {
            UpstreamKind::Doh(client, url, headers) => {
                let resp = client
                    .post(url)
                    .headers(headers.clone())
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .body(req_bytes.to_vec())
                    .send()
                    .await
                    .ok()?;
                if !resp.status().is_success() {
                    return None;
                }
                let bytes = resp.bytes().await.ok()?;
                validate_response(&bytes, req)
            }
            UpstreamKind::Dot(host, port) => {
                let resp = self.dot_query(host, *port, req_bytes).await?;
                validate_response(&resp, req)
            }
            UpstreamKind::Udp(host, port) => {
                let addr = resolve_host(host, *port, &self.bootstrap).await?;
                udp_query(addr, req_bytes, req).await
            }
        }
    }

    /// DoT 查询：从连接池取一条空闲连接，池空则新建（最多 4 条并发）；
    /// 空闲超 30s 或出错时丢弃重连，失败自动重试一次。
    async fn dot_query(&self, host: &str, port: u16, req_bytes: &[u8]) -> Option<Vec<u8>> {
        // 等空闲连接的排队时间也算进 8s 预算，否则池满时总耗时可以无限拉长。
        tokio::time::timeout(Duration::from_secs(8), async {
            let _permit = self.dot_sem.acquire().await.ok()?;
            let cached = {
                let mut pool = self.dot_pool.lock().await;
                let mut conn = None;
                while let Some(c) = pool.pop() {
                    if c.last_used.elapsed() <= Duration::from_secs(30) {
                        conn = Some(c);
                        break;
                    }
                    // 过期连接直接丢弃，继续找下一条
                }
                conn
            };
            let mut conn = match cached {
                Some(c) => c,
                None => DotConn {
                    stream: self.dot_connect(host, port).await?,
                    last_used: Instant::now(),
                },
            };
            let result = match dot_exchange(&mut conn, req_bytes).await {
                Ok(r) => {
                    conn.last_used = Instant::now();
                    Some(r)
                }
                Err(_) => {
                    // 连接可能已被对端关闭：重连后重试一次
                    let mut fresh = DotConn {
                        stream: self.dot_connect(host, port).await?,
                        last_used: Instant::now(),
                    };
                    let r = dot_exchange(&mut fresh, req_bytes).await.ok();
                    if r.is_some() {
                        conn = fresh;
                    }
                    r
                }
            };
            if result.is_some() {
                let mut pool = self.dot_pool.lock().await;
                if pool.len() < 4 {
                    pool.push(conn);
                }
            }
            result
        })
        .await
        .ok()?
    }

    async fn dot_connect(
        &self,
        host: &str,
        port: u16,
    ) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
        let addr = resolve_host(host, port, &self.bootstrap).await?;
        let tcp = TcpStream::connect(addr).await.ok()?;
        tcp.set_nodelay(true).ok();
        // DoT 连接池里的空闲连接同样会被 NAT 清掉：统一开保活，别等 2 小时默认探测。
        crate::outbound::tune_tcp(&tcp);

        let connector = tokio_rustls::TlsConnector::from(TLS_CONFIG.clone());
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
        connector.connect(server_name, tcp).await.ok()
    }

    fn is_fake_filtered(&self, qname: &str) -> bool {
        self.fake_filter
            .iter()
            .any(|pattern| wildcard_match(pattern, qname))
    }

    /// 主上游应答是否需要 fallback 复核：
    /// 1) 命中私网/保留/广播等明显异常 —— 默认开启；
    /// 2) 有 A 记录且不在 CN IP 库 —— 仅 fallback_geo_check=true 时开启。
    /// 「境外 IP」不是污染证据，默认不再因为非 CN 就重新查询明文 UDP。
    fn should_use_fallback(&self, resp: &[u8]) -> bool {
        if !self.fallback_filter {
            return false;
        }
        let Ok(msg) = Message::from_vec(resp) else {
            return false;
        };
        let ranges = self.cn_ips.read().unwrap_or_else(|p| p.into_inner());
        for ans in msg.answers() {
            match ans.data() {
                Some(RData::A(a)) => {
                    let ip = a.0;
                    if is_bogus_v4(ip) {
                        return true;
                    }
                    if self.fallback_geo_check && !ranges.is_empty() && !v4_in_ranges(ip, &ranges) {
                        return true;
                    }
                }
                Some(RData::AAAA(a)) => {
                    if is_bogus_v6(a.0) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Host IP 模式：与 AAAA 过滤共用同一条判定，ANY 同时给 A+AAAA。
    fn host_ip_response(
        &self,
        req: &Message,
        qtype: RecordType,
        _qname: &str,
        ips: &[IpAddr],
    ) -> Vec<u8> {
        let mut resp = Message::new();
        resp.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_op_code(req.op_code())
            .set_recursion_desired(req.recursion_desired())
            .set_recursion_available(true)
            .set_response_code(ResponseCode::NoError);
        for q in req.queries() {
            resp.add_query(q.clone());
        }
        let Some(q) = req.queries().first() else {
            return resp.to_vec().unwrap_or_default();
        };
        let want_v4 = qtype == RecordType::A || qtype == RecordType::ANY;
        let want_v6 = (qtype == RecordType::AAAA || qtype == RecordType::ANY) && !self.block_aaaa;
        for ip in ips {
            match ip {
                IpAddr::V4(v4) if want_v4 => {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        HOST_TTL,
                        RData::A(A(*v4)),
                    ));
                }
                IpAddr::V6(v6) if want_v6 => {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        HOST_TTL,
                        RData::AAAA(AAAA(*v6)),
                    ));
                }
                _ => {}
            }
        }
        resp.to_vec().unwrap_or_default()
    }

    /// Host 别名模式：只把 qname 换成别名查上游，不改缓存/Fake-IP 池；
    /// 应答补一条 original -> alias 的 CNAME，客户端能拿到完整链。
    async fn host_alias_response(
        &self,
        req: &Message,
        _qtype: RecordType,
        _qname: &str,
        alias: &str,
    ) -> Vec<u8> {
        let Ok(alias_name) = Name::from_ascii(alias) else {
            return self.servfail_response(req);
        };
        let mut alias_req = req.clone();
        if let Some(q) = alias_req.queries_mut().first_mut() {
            q.set_name(alias_name.clone());
        }
        let fwd = prepare_forward(&alias_req);
        let Ok(bytes) = fwd.to_vec() else {
            return self.servfail_response(req);
        };
        let Some(upstream) = self.query_upstream(&bytes, &alias_req).await else {
            return self.servfail_response(req);
        };
        let Ok(msg) = Message::from_vec(&upstream) else {
            return self.servfail_response(req);
        };
        let Some(original) = req.queries().first().map(|q| q.name().clone()) else {
            return self.servfail_response(req);
        };
        let mut out = Message::new();
        out.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_op_code(req.op_code())
            .set_recursion_desired(req.recursion_desired())
            .set_recursion_available(msg.recursion_available())
            .set_response_code(msg.response_code());
        for q in req.queries() {
            out.add_query(q.clone());
        }
        out.add_answer(Record::from_rdata(
            original,
            HOST_TTL,
            RData::CNAME(CNAME(alias_name)),
        ));
        out.add_answers(msg.answers().iter().cloned());
        out.add_name_servers(msg.name_servers().iter().cloned());
        out.to_vec().unwrap_or_else(|_| self.servfail_response(req))
    }

    fn fake_response(&self, req: &Message, qtype: RecordType, qname: &str) -> Vec<u8> {
        let ip = match self.fake_pool.lock() {
            Ok(mut pool) => pool.allocate(qname, qtype),
            Err(p) => p.into_inner().allocate(qname, qtype),
        };
        if let Ok(mut rev) = self.reverse.lock() {
            rev.insert(ip, qname, 3600);
        }
        let mut resp = Message::new();
        resp.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_op_code(req.op_code())
            .set_recursion_desired(req.recursion_desired())
            .set_recursion_available(true)
            .set_response_code(ResponseCode::NoError);
        for q in req.queries() {
            resp.add_query(q.clone());
        }
        if let Some(q) = req.queries().first() {
            match ip {
                IpAddr::V4(v4) => {
                    resp.add_answer(Record::from_rdata(q.name().clone(), 60, RData::A(A(v4))))
                }
                IpAddr::V6(v6) => resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    60,
                    RData::AAAA(AAAA(v6)),
                )),
            };
        }
        resp.to_vec().unwrap_or_default()
    }

    /// 空 NOERROR（AAAA 过滤用）：应答存在但无记录，App 会回落到 v4。
    fn empty_response(&self, req: &Message) -> Vec<u8> {
        let mut resp = Message::new();
        resp.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_op_code(req.op_code())
            .set_recursion_desired(req.recursion_desired())
            .set_recursion_available(true)
            .set_response_code(ResponseCode::NoError);
        for q in req.queries() {
            resp.add_query(q.clone());
        }
        resp.to_vec().unwrap_or_default()
    }

    fn blocked_response(&self, req: &Message, qtype: RecordType) -> Vec<u8> {
        let mut resp = Message::new();
        resp.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_op_code(req.op_code())
            .set_recursion_desired(req.recursion_desired())
            .set_recursion_available(true);
        for q in req.queries() {
            resp.add_query(q.clone());
        }
        if self.block_mode == "zero" && (qtype == RecordType::A || qtype == RecordType::AAAA) {
            resp.set_response_code(ResponseCode::NoError);
            if let Some(q) = req.queries().first() {
                if qtype == RecordType::A {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        self.block_ttl,
                        RData::A(A(Ipv4Addr::UNSPECIFIED)),
                    ));
                } else {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        self.block_ttl,
                        RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                    ));
                }
            }
        } else {
            resp.set_response_code(ResponseCode::NXDomain);
            // RFC 2308 否定缓存：NXDOMAIN 必须带 SOA，客户端才会按 TTL 缓存。
            // 之前只返回空 NXDOMAIN，广告 SDK 会每几十毫秒重试一次。
            if let Some(q) = req.queries().first() {
                let soa = SOA::new(
                    Name::from_ascii("block.namu.dns.").expect("static SOA mname"),
                    Name::from_ascii("hostmaster.namu.dns.").expect("static SOA rname"),
                    1,
                    60,
                    30,
                    3600,
                    self.block_ttl,
                );
                let mut rec = Record::from_rdata(q.name().clone(), self.block_ttl, RData::SOA(soa));
                rec.set_record_type(RecordType::SOA);
                resp.add_name_server(rec);
            }
        }
        resp.to_vec().unwrap_or_default()
    }

    fn servfail_response(&self, req: &Message) -> Vec<u8> {
        let mut resp = Message::new();
        resp.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_op_code(req.op_code())
            .set_recursion_desired(req.recursion_desired())
            .set_recursion_available(true)
            .set_response_code(ResponseCode::ServFail);
        for q in req.queries() {
            resp.add_query(q.clone());
        }
        resp.to_vec().unwrap_or_default()
    }
}

/// 应答校验（dnsproxy/sing-box 同款）：ID、question、opcode、QR 都必须与请求一致，
/// 防止错配/伪造应答进缓存或回到客户端。
fn validate_response(bytes: &[u8], req: &Message) -> Option<Vec<u8>> {
    let msg = Message::from_vec(bytes).ok()?;
    if msg.message_type() != MessageType::Response {
        return None;
    }
    if msg.id() != req.id() || msg.op_code() != req.op_code() {
        return None;
    }
    if msg.queries().len() != req.queries().len() {
        return None;
    }
    for (a, b) in msg.queries().iter().zip(req.queries().iter()) {
        if a.name() != b.name()
            || a.query_type() != b.query_type()
            || a.query_class() != b.query_class()
        {
            return None;
        }
    }
    Some(bytes.to_vec())
}

/// 按客户端声明的 UDP 载荷裁剪应答：超长时置 TC 位并只留问题段，
/// 让客户端按标准改走 TCP（我们已内置 TCP DNS 服务端），避免被 stub 直接丢弃。
pub fn fit_udp_response(req: &[u8], resp: Vec<u8>) -> Vec<u8> {
    let Ok(req_msg) = Message::from_vec(req) else {
        return resp;
    };
    let max = req_msg
        .extensions()
        .as_ref()
        .map(|e| e.max_payload() as usize)
        .unwrap_or(512)
        .clamp(512, 4096);
    if resp.len() <= max {
        return resp;
    }
    let Ok(resp_msg) = Message::from_vec(&resp) else {
        return resp;
    };
    let mut out = Message::new();
    out.set_id(req_msg.id())
        .set_message_type(MessageType::Response)
        .set_op_code(req_msg.op_code())
        .set_recursion_desired(req_msg.recursion_desired())
        .set_recursion_available(true)
        .set_truncated(true)
        .set_response_code(resp_msg.response_code());
    for q in req_msg.queries() {
        out.add_query(q.clone());
    }
    out.to_vec().unwrap_or(resp)
}

/// DNS rebind 防护（dnsmasq stop-dns-rebind / AdGuard 同款）：
/// 公网域名解析出私网/环回/链路本地等保留地址视为投毒，白名单域豁免。
/// 检查上游应答的 CNAME 链目标是否命中拦截规则。
///
/// 广告主常用「第一方域名 CNAME 到广告域名」的伪装：查询名本身正常，
/// 只查 qname 会整条放过去。这里对链上每个 CNAME 目标再过一遍规则。
///
/// 只对 A/AAAA 查询生效：其他类型（MX/TXT/SRV）没有「连接目标」语义，
/// 拦截它们只会造成误伤。
fn blocked_cname_target(bytes: &[u8], filter: &FilterEngine, qtype: RecordType) -> Option<String> {
    if qtype != RecordType::A && qtype != RecordType::AAAA {
        return None;
    }
    let msg = Message::from_vec(bytes).ok()?;
    for ans in msg.answers() {
        let Some(RData::CNAME(c)) = ans.data() else {
            continue;
        };
        let target = c.0.to_utf8().trim_end_matches('.').to_ascii_lowercase();
        if target.is_empty() {
            continue;
        }
        if filter.is_blocked(&target) {
            return Some(target);
        }
    }
    None
}

fn is_rebind(bytes: &[u8], qname: &str, filter: &FilterEngine) -> bool {
    if filter.is_allowed(qname) {
        return false;
    }
    let Ok(msg) = Message::from_vec(bytes) else {
        return false;
    };
    msg.answers().iter().any(|a| match a.data() {
        Some(RData::A(a)) => {
            let ip = a.0;
            let o = ip.octets();
            ip.is_private() || ip.is_loopback() || ip.is_link_local()
                || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()
                // CGNAT 100.64/10 与基准测试段 198.18/15（后者与 Fake-IP 段重叠）
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        }
        Some(RData::AAAA(a)) => {
            let ip = a.0;
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xFF00) == 0xFF00 // 组播 ff00::/8
        }
        _ => false,
    })
}

/// Fake-IP 基线排除表（mihomo fake-ip-filter 同款）：
/// 局域网、系统联网探测、NTP/STUN 必须拿真实地址，否则会被 Fake-IP 误判。
fn default_fake_filter() -> Vec<String> {
    [
        "*.lan",
        "*.local",
        "*.localdomain",
        "*.home.arpa",
        "local",
        "localhost",
        "*.localhost",
        "dns.msftncsi.com",
        "www.msftncsi.com",
        "*.msftncsi.com",
        "www.msftconnecttest.com",
        "*.msftconnecttest.com",
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "captive.apple.com",
        "time.*.com",
        "ntp.*.com",
        "*.ntp.org",
        "stun.*",
        "*.stun.*",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// 域名通配符匹配，只支持 `*`（mihomo fake-ip-filter 的常见写法），大小写不敏感。
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn is_bogus_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 240
}

fn is_bogus_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_unspecified()
        || (ip.segments()[0] & 0xFF00) == 0xFF00
}

fn v4_in_ranges(ip: Ipv4Addr, ranges: &[(u32, u32)]) -> bool {
    let n = u32::from(ip);
    let mut lo = 0usize;
    let mut hi = ranges.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (start, end) = ranges[mid];
        if n < start {
            hi = mid;
        } else if n > end {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    false
}

/// fallback 复核结果是否可用：至少有一条非保留 A/AAAA。
fn has_usable_answer(resp: &[u8]) -> bool {
    let Ok(msg) = Message::from_vec(resp) else {
        return false;
    };
    msg.answers().iter().any(|a| match a.data() {
        Some(RData::A(v)) => !is_bogus_v4(v.0),
        Some(RData::AAAA(v)) => !is_bogus_v6(v.0),
        _ => false,
    })
}

/// 转发前准备：剥掉 EDNS Client Subnet（AdGuard/dnsproxy 默认），
/// 并把 EDNS UDP 载荷抬到 1232，减少大应答被截断后回退 TCP（sing-box/dnsproxy 同款）。
fn prepare_forward(req: &Message) -> Message {
    let mut fwd = req.clone();
    match fwd.extensions_mut() {
        Some(edns) => {
            edns.options_mut().remove(EdnsCode::Subnet);
            if edns.max_payload() < 1232 {
                edns.set_max_payload(1232);
            }
        }
        None => {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            fwd.set_edns(edns);
        }
    }
    fwd
}

fn parse_upstream(cfg: &DnsConfig) -> UpstreamKind {
    build_upstream(cfg, &cfg.upstream)
        .or_else(|| build_upstream(cfg, &cfg.fallback))
        .unwrap_or_else(|| UpstreamKind::Udp("223.5.5.5".into(), 53))
}

fn parse_fallback(cfg: &DnsConfig) -> Option<UpstreamKind> {
    let raw = cfg.fallback.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(k) = build_upstream(cfg, raw) {
        return Some(k);
    }
    parse_host_port(raw, 53).map(|(h, p)| UpstreamKind::Udp(h, p))
}

fn build_upstream(cfg: &DnsConfig, raw: &str) -> Option<UpstreamKind> {
    let u = raw.trim();
    if u.is_empty() {
        return None;
    }
    if u.starts_with("https://") || u.starts_with("http://") {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .use_rustls_tls();
        let bootstrap = cfg.bootstrap.trim();
        if !bootstrap.is_empty() {
            if let (Ok(url), Ok(ip)) = (url::Url::parse(u), bootstrap.parse::<IpAddr>()) {
                if let Some(host) = url.host_str() {
                    let port = url.port_or_known_default().unwrap_or(443);
                    builder = builder.resolve(host, SocketAddr::new(ip, port));
                }
            }
        }
        let mut headers = HeaderMap::new();
        for (k, v) in cfg.headers.iter() {
            match (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                (Ok(name), Ok(value)) => {
                    headers.insert(name, value);
                }
                _ => logging::warn("dns", format!("忽略无效 DoH Header: {}", k)),
            }
        }
        let client = builder.build().unwrap_or_else(|_| reqwest::Client::new());
        return Some(UpstreamKind::Doh(client, u.to_string(), headers));
    }
    if let Some(rest) = u
        .strip_prefix("tls://")
        .or_else(|| u.strip_prefix("dot://"))
    {
        let (host, port) = parse_host_port(rest, 853).unwrap_or((rest.to_string(), 853));
        if host.is_empty() {
            return None;
        }
        return Some(UpstreamKind::Dot(host, port));
    }
    let rest = u.strip_prefix("udp://").unwrap_or(u);
    let (host, port) = parse_host_port(rest, 53)?;
    if host.is_empty() {
        return None;
    }
    Some(UpstreamKind::Udp(host, port))
}

fn parse_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    let s = s.trim().trim_end_matches('/');
    if s.is_empty() {
        return None;
    }
    if s.starts_with('[') {
        let end = s.find(']')?;
        let host = s[1..end].to_string();
        let port = s[end + 1..]
            .trim_start_matches(':')
            .trim()
            .parse::<u16>()
            .unwrap_or(default_port);
        return Some((host, port));
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Some((h.to_string(), port));
        }
    }
    Some((s.to_string(), default_port))
}

async fn resolve_host(host: &str, port: u16, bootstrap: &str) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    // 上游写域名时，用 bootstrap DNS 真正解析它，而不是直接把 bootstrap 当上游地址连（原实现的 bug）。
    if let Ok(bs) = bootstrap.trim().parse::<IpAddr>() {
        if let Some(ip) = bootstrap_lookup(bs, host).await {
            return Some(SocketAddr::new(ip, port));
        }
    }
    let target = format!("{}:{}", host, port);
    let mut addrs = tokio::net::lookup_host(target).await.ok()?;
    addrs.next()
}

/// 向 bootstrap DNS 查一次 A / AAAA，拿到上游域名对应的真实 IP。
async fn bootstrap_lookup(bs: IpAddr, host: &str) -> Option<IpAddr> {
    let ok_name = Name::from_ascii(host).ok()?;
    for qtype in [RecordType::A, RecordType::AAAA] {
        let mut msg = Message::new();
        msg.set_id((crate::stats::now_ms() & 0xffff) as u16)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(Query::query(ok_name.clone(), qtype));
        let Ok(bytes) = msg.to_vec() else { continue };
        let bind: SocketAddr = if bs.is_ipv4() {
            "0.0.0.0:0".parse().ok()?
        } else {
            "[::]:0".parse().ok()?
        };
        let sock = UdpSocket::bind(bind).await.ok()?;
        sock.connect(SocketAddr::new(bs, 53)).await.ok()?;
        sock.send(&bytes).await.ok()?;
        let mut buf = vec![0u8; 2048];
        let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await
        else {
            continue;
        };
        buf.truncate(n);
        if let Ok(resp) = Message::from_vec(&buf) {
            // 与主查询同样的校验：ID/类型/question 必须匹配，防伪造应答。
            if resp.id() != msg.id() || resp.message_type() != MessageType::Response {
                continue;
            }
            let question_ok = resp
                .queries()
                .first()
                .map(|q| q.name() == &ok_name && q.query_type() == qtype)
                .unwrap_or(false);
            if !question_ok {
                continue;
            }
            for a in resp.answers() {
                match a.data() {
                    Some(RData::A(v)) => return Some(IpAddr::V4(v.0)),
                    Some(RData::AAAA(v)) => return Some(IpAddr::V6(v.0)),
                    _ => {}
                }
            }
        }
    }
    None
}

async fn dot_exchange(conn: &mut DotConn, req_bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    if req_bytes.len() > 0xFFFF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DoT 查询超过 65535 字节",
        ));
    }
    let mut out = Vec::with_capacity(req_bytes.len() + 2);
    out.extend_from_slice(&(req_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(req_bytes);
    conn.stream.write_all(&out).await?;
    conn.stream.flush().await?;
    let mut len_buf = [0u8; 2];
    conn.stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    conn.stream.read_exact(&mut resp).await?;
    Ok(resp)
}

async fn udp_query(addr: SocketAddr, req: &[u8], orig: &Message) -> Option<Vec<u8>> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(addr).await.ok()?;
    sock.send(req).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    // TC 截断必须转 TCP 重查（sing-box/dnsproxy 同款），否则大应答被截断后缓存脏数据。
    if let Ok(msg) = Message::from_vec(&buf) {
        if msg.truncated() {
            crate::stats::STATS_TCP.fetch_add(1, Ordering::Relaxed);
            return tcp_query(addr, req, orig).await;
        }
    }
    validate_response(&buf, orig)
}

async fn tcp_query(addr: SocketAddr, req: &[u8], orig: &Message) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut tcp = TcpStream::connect(addr).await.ok()?;
        tcp.set_nodelay(true).ok();
        // DoT 连接池里的空闲连接同样会被 NAT 清掉：统一开保活，别等 2 小时默认探测。
        crate::outbound::tune_tcp(&tcp);

        let mut out = Vec::with_capacity(req.len() + 2);
        out.extend_from_slice(&(req.len() as u16).to_be_bytes());
        out.extend_from_slice(req);
        tcp.write_all(&out).await.ok()?;
        let mut len_buf = [0u8; 2];
        tcp.read_exact(&mut len_buf).await.ok()?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > 65535 {
            return None;
        }
        let mut resp = vec![0u8; len];
        tcp.read_exact(&mut resp).await.ok()?;
        validate_response(&resp, orig)
    })
    .await
    .ok()?
}

fn root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_map_classifies_ip_alias_server_and_wildcard() {
        use super::{HostEntry, HostMap, UpstreamKind};
        use crate::config::DnsConfig;
        let mut cfg = DnsConfig::default();
        cfg.hosts
            .insert("ip.example".into(), "1.2.3.4, 2001:db8::1".into());
        cfg.hosts
            .insert("*.wild.example".into(), "alias.example".into());
        cfg.hosts
            .insert("server.example".into(), "server:1.1.1.1".into());
        cfg.hosts
            .insert("bad.example".into(), "server:system".into());
        let primary = UpstreamKind::Udp("223.5.5.5".into(), 53);
        let map = HostMap::from_config(&cfg, &primary, None);
        assert!(matches!(map.lookup("ip.example"), Some(HostEntry::Ip(v)) if v.len() == 2));
        assert!(
            matches!(map.lookup("a.wild.example"), Some(HostEntry::Alias(v)) if v == "alias.example")
        );
        assert!(map.lookup("wild.example").is_none(), "*. 不匹配 apex");
        assert!(matches!(
            map.lookup("server.example"),
            Some(HostEntry::Server(_))
        ));
        assert!(map.lookup("bad.example").is_none());
        assert!(map.rejected.iter().any(|s| s.contains("server:system")));
    }

    #[test]
    fn host_server_gate_uses_existing_upstream_protocols() {
        use super::{HostEntry, HostMap, UpstreamKind};
        use crate::config::DnsConfig;
        let mut cfg = DnsConfig::default();
        cfg.hosts.insert(
            "doh.example".into(),
            "server:https://dns.example/dns-query".into(),
        );
        cfg.hosts
            .insert("udp.example".into(), "server:1.1.1.1".into());
        let doh = UpstreamKind::Doh(
            reqwest::Client::new(),
            "https://dns.alidns.com/dns-query".into(),
            reqwest::header::HeaderMap::new(),
        );
        let map = HostMap::from_config(&cfg, &doh, None);
        assert!(matches!(
            map.lookup("doh.example"),
            Some(HostEntry::Server(UpstreamKind::Doh(..)))
        ));
        assert!(map.lookup("udp.example").is_none());
        assert!(map.rejected.iter().any(|s| s.contains("没有 udp 客户端")));
    }

    #[test]
    fn host_ip_response_does_not_bypass_aaaa_or_fake_ip() {
        use super::{DnsEngine, HOST_TTL};
        use crate::config::DnsConfig;
        use crate::engine::FilterEngine;
        use crate::stats::Stats;
        let mut cfg = DnsConfig::default();
        cfg.hosts
            .insert("ip.example".into(), "1.2.3.4, 2001:db8::1".into());
        let engine = DnsEngine::new(
            &cfg,
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            true,
            false,
        );
        let mut req = query(11, "ip.example");
        req.queries_mut()[0].set_query_type(RecordType::A);
        let bytes = engine.host_ip_response(
            &req,
            RecordType::A,
            "ip.example",
            &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
        );
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.answers().len(), 1);
        assert_eq!(msg.answers()[0].ttl(), HOST_TTL);
        assert!(
            matches!(msg.answers()[0].data(), Some(RData::A(a)) if a.0 == Ipv4Addr::new(1, 2, 3, 4))
        );
        // 关闭 AAAA 时，即使 Host 有 v6 也不返回。
        let engine_blocked = DnsEngine::new(
            &DnsConfig {
                block_aaaa: true,
                ..DnsConfig::default()
            },
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            true,
            false,
        );
        let bytes = engine_blocked.host_ip_response(
            &req,
            RecordType::ANY,
            "ip.example",
            &[IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))],
        );
        let msg = Message::from_vec(&bytes).unwrap();
        assert!(msg.answers().is_empty());
    }

    #[test]
    fn cache_key_isolates_query_semantics() {
        use hickory_proto::rr::{DNSClass, RecordType};
        let plain = cache_key("a.example", RecordType::A, DNSClass::IN, false, false);
        let dnssec = cache_key("a.example", RecordType::A, DNSClass::IN, true, false);
        let cd = cache_key("a.example", RecordType::A, DNSClass::IN, false, true);
        let aaaa = cache_key("a.example", RecordType::AAAA, DNSClass::IN, false, false);
        assert_ne!(plain, dnssec, "DO 位不同不能共用缓存");
        assert_ne!(plain, cd, "CD 位不同不能共用缓存");
        assert_ne!(plain, aaaa);
    }

    use crate::engine::FilterEngine;

    #[test]
    fn cache_persists_across_restart() {
        let dir = std::env::temp_dir().join(format!("namu-cache-{}", crate::stats::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.json").to_string_lossy().to_string();
        let cfg = DnsConfig::default();
        let mut e = DnsEngine::new(
            &cfg,
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        e.set_cache_path(Some(path.clone()));
        let bytes = response_of(&query(1, "warm.example.com")).to_vec().unwrap();
        e.cache
            .lock()
            .unwrap()
            .put("warm.example.com|1".into(), bytes, 600);
        e.save_cache();
        let mut e2 = DnsEngine::new(
            &cfg,
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        e2.set_cache_path(Some(path));
        let mut c = e2.cache.lock().unwrap();
        assert!(c.get("warm.example.com|1", 1).is_some());
        drop(c);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversized_udp_response_truncated() {
        let req = query(3, "big.example.com");
        let mut resp = response_of(&req);
        for i in 0..120u8 {
            resp.add_answer(Record::from_rdata(
                Name::from_str("big.example.com").unwrap(),
                300,
                RData::A(A(Ipv4Addr::new(1, 2, 3, i))),
            ));
        }
        let bytes = resp.to_vec().unwrap();
        assert!(bytes.len() > 512);
        let out = fit_udp_response(&req.to_vec().unwrap(), bytes);
        let msg = Message::from_vec(&out).unwrap();
        assert!(msg.truncated());
        assert!(msg.answers().is_empty());
        assert_eq!(msg.id(), 3);
    }

    #[test]
    fn cname_chain_target_is_blocked() {
        let mut filter = FilterEngine::new();
        filter.add_line("||adserver.example^");
        let mut resp = Message::new();
        resp.set_message_type(MessageType::Response);
        resp.add_answer(Record::from_rdata(
            Name::from_utf8("first-party.example").unwrap(),
            60,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(
                Name::from_utf8("adserver.example").unwrap(),
            )),
        ));
        let bytes = resp.to_vec().unwrap();
        assert_eq!(
            blocked_cname_target(&bytes, &filter, RecordType::A).as_deref(),
            Some("adserver.example"),
            "查询名正常、CNAME 目标命中规则时必须拦截"
        );
        // 非 A/AAAA 查询没有连接目标语义，不检查 CNAME，避免误伤 MX/TXT。
        assert!(blocked_cname_target(&bytes, &filter, RecordType::MX).is_none());
    }

    #[test]
    fn cname_to_clean_target_is_not_blocked() {
        let mut filter = FilterEngine::new();
        filter.add_line("||adserver.example^");
        let mut resp = Message::new();
        resp.set_message_type(MessageType::Response);
        resp.add_answer(Record::from_rdata(
            Name::from_utf8("www.example.com").unwrap(),
            60,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(
                Name::from_utf8("cdn.example.net").unwrap(),
            )),
        ));
        let bytes = resp.to_vec().unwrap();
        assert!(blocked_cname_target(&bytes, &filter, RecordType::A).is_none());
    }

    #[test]
    fn forward_query_advertises_1232() {
        let req = query(3, "a.com");
        let fwd = prepare_forward(&req);
        assert_eq!(fwd.extensions().as_ref().unwrap().max_payload(), 1232);
        // 客户端没带 OPT 时也要补上，保证大应答不被 512 字节截断
        let kept = fwd.extensions().as_ref().unwrap().max_payload();
        assert_eq!(kept, 1232);
    }

    #[test]
    fn keyword_rules_use_aho_corasick() {
        let mut f = FilterEngine::new();
        f.load_singbox_source(r#"{"version":3,"rules":[{"domain_keyword":["adserv","tracker"]}]}"#);
        assert!(f.is_blocked("x.adserv.com"));
        assert!(f.is_blocked("ADTracker.example.com"));
        assert!(!f.is_blocked("example.com"));
    }

    #[test]
    fn aaaa_filtered_when_disabled() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let cfg = DnsConfig {
                block_aaaa: true,
                ..Default::default()
            };
            let e = Arc::new(DnsEngine::new(
                &cfg,
                Arc::new(FilterEngine::new()),
                Arc::new(Stats::new()),
                "nxdomain",
                true,
                false,
                false,
            ));
            let mut req = query(9, "v6.example.com");
            if let Some(q) = req.queries_mut().first_mut() {
                q.set_query_type(RecordType::AAAA);
            }
            let resp = e.resolve(&req.to_vec().unwrap()).await.expect("resp");
            let msg = Message::from_vec(&resp).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NoError);
            assert!(msg.answers().is_empty());
        });
    }

    #[test]
    fn important_overrides_allow() {
        let mut f = FilterEngine::new();
        f.add_line("@@||example.com^");
        f.add_line("||ads.example.com^$important");
        assert!(!f.is_blocked("www.example.com"));
        assert!(f.is_blocked("ads.example.com"));
    }

    #[test]
    fn lru_touch_on_hit() {
        let mut c = Cache {
            map: HashMap::new(),
            clock: 0,
            cap: 2,
            max_ttl: 600,
            stale_window: Duration::from_secs(3600),
            refreshing: HashSet::new(),
            dirty: false,
        };
        let bytes = query(1, "a.com").to_vec().unwrap();
        c.put("a.com|1".into(), bytes.clone(), 600);
        c.put("b.com|1".into(), bytes.clone(), 600);
        assert!(c.get("a.com|1", 1).is_some());
        c.put("c.com|1".into(), bytes, 600);
        assert!(c.get("a.com|1", 1).is_some());
        assert!(c.get("b.com|1", 1).is_none());
    }

    #[test]
    fn prefetch_due_for_hot_entries() {
        let mut c = Cache::new(8, 600);
        let bytes = query(1, "hot.com").to_vec().unwrap();
        c.put("hot.com|1".into(), bytes, 100);
        for _ in 0..3 {
            assert!(c.get("hot.com|1", 1).is_some());
        }
        assert!(!c.prefetch_due("hot.com|1"));
        if let Some(e) = c.map.get_mut("hot.com|1") {
            e.expire = Instant::now() + Duration::from_secs(10);
        }
        assert!(c.prefetch_due("hot.com|1"));
    }

    #[test]
    fn breaker_opens_after_three_failures() {
        let cfg = DnsConfig {
            upstream: "udp://127.0.0.1:1".into(),
            ..Default::default()
        };
        let e = DnsEngine::new(
            &cfg,
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        for _ in 0..3 {
            e.record_breaker(false);
        }
        assert!(e.breaker.lock().unwrap().open_until.is_some());
        e.record_breaker(true);
        assert!(e.breaker.lock().unwrap().open_until.is_none());
    }

    #[test]
    fn rebind_detection_and_whitelist() {
        let f = FilterEngine::new();
        let req = query(7, "pub.example.com");
        let mut resp = response_of(&req);
        resp.add_answer(Record::from_rdata(
            Name::from_str("pub.example.com").unwrap(),
            300,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                192, 168, 1, 1,
            ))),
        ));
        let bytes = resp.to_vec().unwrap();
        assert!(is_rebind(&bytes, "pub.example.com", &f));
        let mut allow = FilterEngine::new();
        allow.add_line("@@||example.com^");
        assert!(!is_rebind(&bytes, "pub.example.com", &allow));
        let mut ok = response_of(&req);
        ok.add_answer(Record::from_rdata(
            Name::from_str("pub.example.com").unwrap(),
            300,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                93, 184, 216, 34,
            ))),
        ));
        assert!(!is_rebind(&ok.to_vec().unwrap(), "pub.example.com", &f));
    }

    #[test]
    fn rebind_covers_reserved_ranges() {
        let f = FilterEngine::new();
        let req = query(7, "pub.example.com");
        for bad in [
            "0.0.0.0",
            "100.64.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            let mut resp = response_of(&req);
            resp.add_answer(Record::from_rdata(
                Name::from_str("pub.example.com").unwrap(),
                300,
                RData::A(bad.parse().unwrap()),
            ));
            assert!(
                is_rebind(&resp.to_vec().unwrap(), "pub.example.com", &f),
                "应拦截 {}",
                bad
            );
        }
    }

    #[test]
    fn cache_reload_does_not_inflate_ttl() {
        // 手工构造落盘文件：剩余有效期 10s，但报文内 TTL 是 600s。
        let mut msg = Message::new();
        msg.set_id(0).set_message_type(MessageType::Response);
        msg.add_query(Query::query(
            Name::from_str("ttl.example.com").unwrap(),
            RecordType::A,
        ));
        msg.add_answer(Record::from_rdata(
            Name::from_str("ttl.example.com").unwrap(),
            600,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                1, 2, 3, 4,
            ))),
        ));
        let bytes = msg.to_vec().unwrap();
        let now = crate::stats::now_ms() / 1000;
        let body = serde_json::json!({
            "v": 1,
            "entries": [{
                "k": "ttl.example.com|1",
                "b": base64::engine::general_purpose::STANDARD.encode(&bytes),
                "e": now + 10,
            }]
        });
        let dir = std::env::temp_dir().join(format!("namu-ttl-test-{}", crate::stats::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.json");
        std::fs::write(&path, body.to_string()).unwrap();

        let mut dns = DnsEngine::new(
            &DnsConfig::default(),
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        dns.set_cache_path(Some(path.to_string_lossy().to_string()));
        let cached = dns
            .cache
            .lock()
            .unwrap()
            .get("ttl.example.com|1", 9)
            .unwrap();
        let parsed = Message::from_vec(&cached.0).unwrap();
        // 重载后下发的 TTL 必须 ≤ 剩余有效期，而不是原始 600s
        assert!(
            parsed.answers()[0].ttl() <= 10,
            "TTL 膨胀: {}",
            parsed.answers()[0].ttl()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;
    use hickory_proto::op::{Edns, Query};
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
    use hickory_proto::rr::rdata::SOA;
    use std::str::FromStr;

    fn query(id: u16, name: &str) -> Message {
        let mut m = Message::new();
        m.set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
        m.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        m
    }

    fn response_of(req: &Message) -> Message {
        let mut r = req.clone();
        r.set_message_type(MessageType::Response);
        r
    }

    #[test]
    fn rejects_mismatched_id() {
        let req = query(7, "a.com");
        let mut resp = response_of(&req);
        resp.set_id(8);
        assert!(validate_response(&resp.to_vec().unwrap(), &req).is_none());
    }

    #[test]
    fn rejects_mismatched_question() {
        let req = query(7, "a.com");
        let mut resp = response_of(&req);
        resp.queries_mut()[0].set_name(Name::from_str("b.com").unwrap());
        assert!(validate_response(&resp.to_vec().unwrap(), &req).is_none());
    }

    #[test]
    fn accepts_matching_response() {
        let req = query(7, "a.com");
        let resp = response_of(&req);
        assert!(validate_response(&resp.to_vec().unwrap(), &req).is_some());
    }

    #[test]
    fn strips_edns_client_subnet() {
        let mut req = query(9, "a.com");
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "1.2.3.4".parse().unwrap(),
                24,
                0,
            )));
        req.set_edns(edns);
        let fwd = prepare_forward(&req);
        assert!(fwd
            .extensions()
            .as_ref()
            .unwrap()
            .option(EdnsCode::Subnet)
            .is_none());
    }

    #[test]
    fn blocked_nxdomain_carries_soa() {
        let cfg = DnsConfig {
            block_ttl: 42,
            ..Default::default()
        };
        let e = DnsEngine::new(
            &cfg,
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        let req = query(7, "ads.example.com");
        let bytes = e.blocked_response(&req, RecordType::A);
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::NXDomain);
        assert!(msg.answers().is_empty());
        let soa = msg.name_servers().iter().find_map(|r| match r.data() {
            Some(RData::SOA(s)) => Some((r.ttl(), s.minimum())),
            _ => None,
        });
        assert_eq!(soa, Some((42, 42)));
        assert_eq!(negative_ttl(&msg), Some(42));
    }

    #[test]
    fn negative_cache_uses_soa_minimum() {
        let engine = DnsEngine::new(
            &DnsConfig::default(),
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        let req = query(1, "nx.example.com");
        let mut resp = response_of(&req);
        resp.set_response_code(ResponseCode::NXDomain);
        let soa = SOA::new(
            Name::from_str("ns.example.com").unwrap(),
            Name::from_str("hostmaster.example.com").unwrap(),
            1,
            3600,
            600,
            86400,
            60,
        );
        let mut rec =
            Record::from_rdata(Name::from_str("example.com").unwrap(), 300, RData::SOA(soa));
        rec.set_record_type(RecordType::SOA);
        resp.add_name_server(rec);
        let key = cache_key("nx.example.com", RecordType::A, DNSClass::IN, false, false);
        engine.cache_and_reverse(&key, "nx.example.com", &resp.to_vec().unwrap());
        let c = engine.cache.lock().unwrap();
        let key = cache_key("nx.example.com", RecordType::A, DNSClass::IN, false, false);
        let entry = c.map.get(&key).expect("negative cached");
        // SOA 记录 TTL=300、MINIMUM=60：负缓存必须取较小值 60，而不是 300。
        assert!(entry.expire.duration_since(entry.created) <= Duration::from_secs(60));
    }

    #[test]
    fn negative_cache_zero_ttl_not_stored() {
        let engine = DnsEngine::new(
            &DnsConfig::default(),
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        let req = query(1, "zero.example.com");
        let mut resp = response_of(&req);
        resp.set_response_code(ResponseCode::NXDomain);
        let soa = SOA::new(
            Name::from_str("ns.example.com").unwrap(),
            Name::from_str("hostmaster.example.com").unwrap(),
            1,
            3600,
            600,
            86400,
            60,
        );
        let mut rec =
            Record::from_rdata(Name::from_str("example.com").unwrap(), 0, RData::SOA(soa));
        rec.set_record_type(RecordType::SOA);
        resp.add_name_server(rec);
        let key = cache_key(
            "zero.example.com",
            RecordType::A,
            DNSClass::IN,
            false,
            false,
        );
        engine.cache_and_reverse(&key, "zero.example.com", &resp.to_vec().unwrap());
        let c = engine.cache.lock().unwrap();
        assert!(!c.map.contains_key(&key), "TTL=0 must not be cached");
    }

    #[test]
    fn reload_keeps_short_ttl_exact() {
        let mut engine = DnsEngine::new(
            &DnsConfig::default(),
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        let bytes = query(1, "short.example.com").to_vec().unwrap();
        let encoded = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        };
        let now = crate::stats::now_ms() / 1000;
        let path = std::env::temp_dir().join(format!("namu_cache_test_{}.json", now));
        std::fs::write(
            &path,
            format!(
                r#"{{"entries":[{{"k":"short","b":"{}","e":{}}}]}}"#,
                encoded,
                now + 2
            ),
        )
        .unwrap();
        engine.set_cache_path(Some(path.to_string_lossy().to_string()));
        {
            let c = engine.cache.lock().unwrap();
            let entry = c.map.get("short").expect("reloaded short entry");
            assert!(entry.orig_ttl <= 2, "reload must not raise TTL above 2s");
            assert!(entry.expire.duration_since(entry.created) <= Duration::from_secs(2));
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn short_negative_ttl_not_served_stale() {
        let mut c = Cache::new(8, 600);
        let bytes = query(1, "short.example.com").to_vec().unwrap();
        c.put("short".into(), bytes, 2);
        if let Some(e) = c.map.get_mut("short") {
            e.expire = Instant::now() - Duration::from_secs(1);
        }
        assert!(
            c.get("short", 2).is_none(),
            "2s TTL must not be extended by stale window"
        );
    }

    #[test]
    fn stale_entry_served_within_window() {
        let mut cache = Cache::new(64, 600);
        let bytes = query(1, "a.com").to_vec().unwrap();
        cache.put("k".into(), bytes.clone(), 30);
        if let Some(e) = cache.map.get_mut("k") {
            e.expire = Instant::now() - Duration::from_secs(5);
        }
        let (_, stale) = cache.get("k", 2).expect("stale served");
        assert!(stale);
        cache.put("k".into(), bytes, 300);
        let (_, stale) = cache.get("k", 3).expect("fresh served");
        assert!(!stale);
    }

    #[test]
    fn fake_filter_wildcards_and_defaults() {
        assert!(wildcard_match("*.msftncsi.com", "dns.msftncsi.com"));
        assert!(wildcard_match("time.*.com", "time.google.com"));
        assert!(!wildcard_match("time.*.com", "ntp.google.com"));
        assert!(wildcard_match("*.lan", "router.lan"));
        assert!(!wildcard_match("*.lan", "example.com"));

        let cfg = DnsConfig::default();
        let e = DnsEngine::new(
            &cfg,
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            true,
            false,
        );
        assert!(e.is_fake_filtered("www.msftconnecttest.com"));
        assert!(e.is_fake_filtered("dns.msftncsi.com"));
        assert!(e.is_fake_filtered("printer.lan"));
        assert!(e.is_fake_filtered("stun.example.com"));
        assert!(!e.is_fake_filtered("www.google.com"));
    }

    #[test]
    fn fallback_filter_flags_non_cn_and_bogus() {
        // 默认只复核明显异常，不把境外 IP 当污染。
        let cfg = DnsConfig {
            fallback_filter: true,
            ..Default::default()
        };
        let e = DnsEngine::new(
            &cfg,
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        // 1.0.0.0/8 作为测试用 CN 段
        e.set_cn_ips(vec![(0x0100_0000, 0x01FF_FFFF)]);

        let req = query(1, "a.example.com");
        let mut cn = response_of(&req);
        cn.add_answer(Record::from_rdata(
            Name::from_str("a.example.com").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        assert!(!e.should_use_fallback(&cn.to_vec().unwrap()));

        let mut foreign = response_of(&req);
        foreign.add_answer(Record::from_rdata(
            Name::from_str("a.example.com").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
        ));
        assert!(!e.should_use_fallback(&foreign.to_vec().unwrap()));
        assert!(has_usable_answer(&foreign.to_vec().unwrap()));

        let mut bogus = response_of(&req);
        bogus.add_answer(Record::from_rdata(
            Name::from_str("a.example.com").unwrap(),
            60,
            RData::A(A(Ipv4Addr::UNSPECIFIED)),
        ));
        assert!(e.should_use_fallback(&bogus.to_vec().unwrap()));

        // 显式开启 geo check 后，非 CN 才进入复核。
        let cfg_geo = DnsConfig {
            fallback_filter: true,
            fallback_geo_check: true,
            ..Default::default()
        };
        let e_geo = DnsEngine::new(
            &cfg_geo,
            Arc::new(FilterEngine::new()),
            Arc::new(Stats::new()),
            "nxdomain",
            true,
            false,
            false,
        );
        e_geo.set_cn_ips(vec![(0x0100_0000, 0x01FF_FFFF)]);
        assert!(e_geo.should_use_fallback(&foreign.to_vec().unwrap()));
        assert!(!has_usable_answer(&bogus.to_vec().unwrap()));
    }

    #[test]
    fn reverse_map_marks_shared_ip_ambiguous() {
        let mut rev = ReverseMap::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        rev.insert(ip, "a.example.com", 60);
        assert_eq!(rev.lookup_confident(ip).as_deref(), Some("a.example.com"));
        rev.insert(ip, "b.example.com", 60);
        assert_eq!(rev.lookup(ip).as_deref(), Some("b.example.com"));
        assert!(
            rev.lookup_confident(ip).is_none(),
            "shared IP must not drive destructive QUIC policy"
        );
    }
}
