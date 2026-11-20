use crate::config::Config;
use crate::logging;
use ipnet::IpNet;
use regex::Regex;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

/// 域名集合：精确匹配 + 后缀匹配（`||example.com^`、`.example.com`）
#[derive(Default, Clone)]
pub struct DomainSet {
    exact: HashSet<String>,
    suffix: HashSet<String>,
}

impl DomainSet {
    pub fn insert_exact(&mut self, d: &str) {
        let d = normalize_domain(d);
        if !d.is_empty() {
            self.exact.insert(d);
        }
    }
    pub fn insert_suffix(&mut self, d: &str) {
        let d = normalize_domain(d);
        if !d.is_empty() {
            self.suffix.insert(d);
        }
    }
    pub fn contains(&self, domain: &str) -> bool {
        // 精确集合只匹配完整域名；只有后缀集合才向父域回溯。
        // 原来把 exact 也放进回溯循环，会让 example.com 误伤 a.example.com。
        if self.exact.contains(domain) {
            return true;
        }
        let mut s = domain;
        loop {
            if self.suffix.contains(s) {
                return true;
            }
            match s.find('.') {
                Some(i) => s = &s[i + 1..],
                None => return false,
            }
        }
    }
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffix.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub fn normalize_domain(d: &str) -> String {
    let d = d.trim().trim_matches('.').to_ascii_lowercase();
    if d.ends_with('.') {
        d.trim_end_matches('.').to_string()
    } else {
        d
    }
}

/// 广告过滤引擎：AdBlock 语法 + hosts 格式 + 纯域名 + sing-box source rule-set
#[derive(Default)]
pub struct FilterEngine {
    allow: DomainSet,
    block: DomainSet,
    /// AdGuard $important 同款：优先级高于例外白名单
    important: DomainSet,
    keywords: Vec<String>,
    /// 关键词规则用 Aho-Corasick 一次扫描（规则上万条时不再逐条 contains）。
    /// 构造失败时存 None，回退逐条 contains——绝不能用空模式兜底（会匹配一切域名）。
    keywords_ac: once_cell::sync::OnceCell<Option<aho_corasick::AhoCorasick>>,
    regexes: Vec<Regex>,
    pub lines: usize,
    pub skipped: usize,
    pub skipped_cosmetic: usize,
    pub skipped_conditional: usize,
    pub skipped_path: usize,
    pub skipped_other: usize,
}

impl FilterEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_file(&mut self, path: &str) {
        let t = std::time::Instant::now();
        match std::fs::read_to_string(path) {
            Ok(text) => {
                if text.trim_start().starts_with('{') {
                    self.load_singbox_source(&text);
                } else {
                    self.load_text(&text);
                }
                logging::info(
                    "filter",
                    format!(
                        "载入规则 {}：{} 行，耗时 {} ms",
                        short_path(path),
                        text.lines().count(),
                        t.elapsed().as_millis()
                    ),
                );
            }
            Err(e) => logging::warn("filter", format!("读取规则失败 {}: {}", short_path(path), e)),
        }
    }

    /// sing-box source rule-set（与 v2/订阅同一格式）：domain / domain_suffix /
    /// domain_keyword / domain_regex 进拦截集；ip_cidr 等 DNS 层表达不了的跳过。
    pub fn load_singbox_source(&mut self, text: &str) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
            logging::warn("filter", "sing-box source 规则 JSON 解析失败");
            return;
        };
        let Some(rules) = v.get("rules").and_then(|r| r.as_array()) else {
            logging::warn("filter", "sing-box source 规则缺少 rules 数组");
            return;
        };
        let mut added = 0usize;
        let mut skipped_rules = 0usize;
        // sing-box 规则的条件是 AND 关系：只要含端口、取反、ip_cidr 等本引擎在 DNS 层
        // 判断不了的条件，整条规则都必须跳过，绝不能只留域名条件继续拦截（会误杀）。
        let supported_keys = ["domain", "domain_suffix", "domain_keyword", "domain_regex"];
        for rule in rules {
            let Some(obj) = rule.as_object() else { continue };
            if obj
                .keys()
                .any(|k| !supported_keys.contains(&k.as_str()))
            {
                skipped_rules += 1;
                self.skipped += 1;
                self.skipped_other += 1;
                continue;
            }
            for key in ["domain", "domain_suffix"] {
                if let Some(arr) = obj.get(key).and_then(|a| a.as_array()) {
                    for d in arr.iter().filter_map(|d| d.as_str()) {
                        if key == "domain" {
                            self.block.insert_exact(d);
                        } else {
                            self.block.insert_suffix(d);
                        }
                        added += 1;
                    }
                }
            }
            if let Some(arr) = obj.get("domain_keyword").and_then(|a| a.as_array()) {
                for k in arr.iter().filter_map(|d| d.as_str()) {
                    let k = k.trim().to_ascii_lowercase();
                    if !k.is_empty() {
                        self.keywords.push(k);
                        added += 1;
                    }
                }
            }
            if let Some(arr) = obj.get("domain_regex").and_then(|a| a.as_array()) {
                for r in arr.iter().filter_map(|d| d.as_str()) {
                    match Regex::new(r) {
                        Ok(re) => {
                            self.regexes.push(re);
                            added += 1;
                        }
                        Err(_) => {
                            self.skipped += 1;
                            self.skipped_other += 1;
                        }
                    }
                }
            }
        }
        self.lines += added;
        if skipped_rules > 0 {
            logging::warn(
                "filter",
                format!("sing-box source 跳过 {} 条含不支持条件的规则（端口/取反/进程等）", skipped_rules),
            );
        }
        logging::info("filter", format!("sing-box source 规则生效 {} 条", added));
    }

    pub fn load_text(&mut self, text: &str) {
        for line in text.lines() {
            self.add_line(line);
        }
    }

    pub fn add_line(&mut self, raw: &str) {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('!')
            || line.starts_with('[')
            || line.starts_with("# ")
        {
            return;
        }
        // 元素隐藏/脚本注入等规则不是 DNS 层能表达的，直接跳过，绝不能被截成主域名。
        if line.contains("##") || line.contains("#@#") || line.contains("#$#")
            || line.contains("#%#") || line.contains("#?#")
        {
            self.skipped += 1;
            self.skipped_cosmetic += 1;
            return;
        }
        // 带 $ 条件（$third-party、$document、$important 等）的规则无法在 DNS 层判断。
        // 例外规则按放宽处理，允许整域；拦截规则跳过，避免误杀。
        if !line.starts_with('/') {
            if let Some(i) = line.find('$') {
                let mods = &line[i + 1..];
                let important = mods.split(',').any(|m| m.trim() == "important");
                if line.starts_with("@@") {
                    self.add_allow(&line[..i]);
                } else if important {
                    self.add_important(&line[..i]);
                } else {
                    self.skipped += 1;
                    self.skipped_conditional += 1;
                }
                return;
            }
        }
        // 去掉注释（# 之前的规则部分）
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            return;
        }
        if let Some(rest) = line.strip_prefix("@@") {
            self.add_allow(rest);
            return;
        }
        // hosts 格式
        let mut parts = line.split_whitespace();
        if let (Some(first), Some(second)) = (parts.next(), parts.next()) {
            if (first == "0.0.0.0" || first == "127.0.0.1" || first == "::1")
                && valid_host(&strip_adblock(second))
            {
                self.block.insert_exact(&strip_adblock(second));
                self.lines += 1;
                return;
            }
        }
        // URL/域名正则不是 DNS 层能可靠表达的规则，跳过，避免把路径匹配误当成域名拦截。
        if line.starts_with('/') && line.ends_with('/') && line.len() > 2 {
            self.skipped += 1;
            self.skipped_path += 1;
            return;
        }
        // 通配符域名无法可靠映射为 DNS 规则
        if line.contains('*') {
            self.skipped += 1;
            self.skipped_path += 1;
            return;
        }
        if let Some(rest) = line.strip_prefix("||") {
            let host = rest.trim_end_matches('^').trim_end_matches('|').trim();
            if valid_host(host) {
                self.block.insert_suffix(host);
                self.lines += 1;
            } else {
                self.skip_invalid(host);
            }
            return;
        }
        if line.starts_with('|') {
            let host = line.trim_matches('|').trim_end_matches('^').trim();
            if valid_host(host) {
                self.block.insert_exact(host);
                self.lines += 1;
            } else {
                self.skip_invalid(host);
            }
            return;
        }
        let host = strip_adblock(line);
        if valid_host(&host) {
            self.block.insert_exact(&host);
            self.lines += 1;
        } else if host.contains('.') {
            self.skip_invalid(&host);
        } else {
            // 纯关键词规则（如 ad-banner）在 DNS 层容易误杀，跳过。
            self.skipped += 1;
            self.skipped_other += 1;
        }
    }

    fn skip_invalid(&mut self, host: &str) {
        self.skipped += 1;
        if host.contains('/') || host.contains('?') || host.contains('*') || host.contains('^') {
            self.skipped_path += 1;
        } else {
            self.skipped_other += 1;
        }
    }

    /// $important 拦截：即使被 @@ 例外也仍然拦截（AdGuard Home 优先级语义）。
    fn add_important(&mut self, rest: &str) {
        let rest = rest.trim();
        let host = if let Some(r) = rest.strip_prefix("||") {
            r.trim_end_matches('^').trim_end_matches('|')
        } else {
            rest.trim_matches('|')
        };
        let host = host.trim();
        if valid_host(host) {
            if rest.starts_with("||") {
                self.important.insert_suffix(host);
            } else {
                self.important.insert_exact(host);
            }
        } else {
            self.skipped += 1;
            self.skipped_other += 1;
        }
    }

    pub fn is_allowed(&self, domain: &str) -> bool {
        self.allow.contains(&normalize_domain(domain))
    }

    fn add_allow(&mut self, rest: &str) {
        let rest = rest.trim().trim_start_matches("@@");
        let host = if let Some(r) = rest.strip_prefix("||") {
            r.trim_end_matches('^').trim_end_matches('|')
        } else if rest.starts_with('|') {
            rest.trim_matches('|')
        } else {
            rest
        };
        let host = host.trim();
        if valid_host(host) {
            if rest.starts_with("||") {
                self.allow.insert_suffix(host);
            } else if rest.starts_with('|') {
                self.allow.insert_exact(host);
            } else {
                self.allow.insert_exact(host);
            }
        } else {
            self.skip_invalid(host);
        }
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return false;
        }
        if self.important.contains(&domain) {
            return true;
        }
        if self.allow.contains(&domain) {
            return false;
        }
        if self.block.contains(&domain) {
            return true;
        }
        if !self.keywords.is_empty() {
            let ac = self.keywords_ac.get_or_init(|| {
                match aho_corasick::AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&self.keywords)
                {
                    Ok(ac) => Some(ac),
                    Err(e) => {
                        logging::warn("filter", format!("关键词自动机构造失败，回退逐条匹配: {}", e));
                        None
                    }
                }
            });
            let hit = match ac {
                Some(ac) => ac.is_match(domain.as_bytes()),
                None => self.keywords.iter().any(|k| domain.contains(k.as_str())),
            };
            if hit {
                return true;
            }
        }
        if self.regexes.iter().any(|r| r.is_match(&domain)) {
            return true;
        }
        false
    }

    pub fn rule_count(&self) -> usize {
        self.block.len() + self.allow.len()
    }
}

fn valid_host(s: &str) -> bool {
    let s = s.trim().trim_matches('.');
    if s.is_empty() || !s.contains('.') || s.len() > 253 {
        return false;
    }
    if s.contains('/') || s.contains('?') || s.contains('*') || s.contains(':') || s.contains(' ') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn strip_adblock(s: &str) -> String {
    let s = s.trim().trim_end_matches('^').trim_end_matches('|');
    let s = s.trim_start_matches('|');
    normalize_domain(s)
}

fn short_path(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
}

// ---------------- 规则分流 ----------------

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Direct,
    Proxy,
    Block,
    Node(String),
    /// 规则直接引用策略组；由内核策略解析器展开成最终节点。
    Group(String),
    /// 规则引用的节点/组已不存在。运行时明确报错，不回落到当前选中节点。
    Missing(String),
}

impl Action {
    /// 无配置上下文时的语法解析；带组/节点清单的规则应使用 [classify_action]。
    pub fn parse(s: &str) -> Action {
        let t = s.trim();
        let lower = t.to_ascii_lowercase();
        match lower.as_str() {
            "direct" | "dir" => Action::Direct,
            "proxy" | "proxies" => Action::Proxy,
            "block" | "reject" | "deny" => Action::Block,
            _ => {
                if let Some(name) = t.strip_prefix("node:") {
                    Action::Node(name.trim().to_string())
                } else {
                    Action::Node(t.to_string())
                }
            }
        }
    }
}

/// 规则动作分类：策略组名优先于节点名；`node:` 强制按节点解析。
/// 找不到任何对象的动作变成 Missing，运行时会报“引用已失效”，不再静默回落。
pub fn classify_action(raw: &str, group_names: &HashSet<String>, node_names: &HashSet<String>) -> Action {
    let t = raw.trim();
    let lower = t.to_ascii_lowercase();
    match lower.as_str() {
        "direct" | "dir" => return Action::Direct,
        "proxy" | "proxies" => return Action::Proxy,
        "block" | "reject" | "deny" => return Action::Block,
        _ => {}
    }
    if let Some(name) = t.strip_prefix("node:") {
        let name = name.trim();
        return if node_names.contains(name) {
            Action::Node(name.to_string())
        } else {
            Action::Missing(name.to_string())
        };
    }
    if group_names.contains(t) {
        Action::Group(t.to_string())
    } else if node_names.contains(t) {
        Action::Node(t.to_string())
    } else {
        Action::Missing(t.to_string())
    }
}

#[derive(Debug, Clone)]
enum RuleKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex(Regex),
    DomainWildcard(Regex),
    GeoIp(String),
    IpCidr(IpNet),
    Port(u16),
    Final,
}

#[derive(Debug, Clone)]
struct RouteRule {
    kind: RuleKind,
    value: String,
    action: Action,
    source: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ConnKind {
    Tcp,
    Udp,
}

pub struct RuleEngine {
    rules: Vec<RouteRule>,
    final_action: Action,
    cn_direct: bool,
    cn_domains: DomainSet,
    cn_ips: Vec<(u32, u32)>,
    pub rule_count: usize,
}

impl RuleEngine {
    pub fn from_config(cfg: &Config) -> Self {
        let group_names: HashSet<String> = cfg
            .proxy_groups
            .iter()
            .map(|g| g.name.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect();
        let node_names: HashSet<String> = cfg
            .nodes
            .iter()
            .map(|n| n.name.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect();
        let mut rules = Vec::new();
        for rc in &cfg.rules {
            // 规则值在加载期归一化（小写/去前导点），判定热路径不再重复分配。
            let kind = match rc.kind.to_ascii_uppercase().as_str() {
                "DOMAIN" => RuleKind::Domain,
                "DOMAIN-SUFFIX" => RuleKind::DomainSuffix,
                "DOMAIN-KEYWORD" => RuleKind::DomainKeyword,
                "DOMAIN-REGEX" => match Regex::new(&rc.value) {
                    Ok(re) => RuleKind::DomainRegex(re),
                    Err(_) => continue,
                },
                "DOMAIN-WILDCARD" => match wildcard_regex(&rc.value) {
                    Ok(re) => RuleKind::DomainWildcard(re),
                    Err(_) => continue,
                },
                "GEOIP" => {
                    let code = rc.value.trim().to_ascii_uppercase();
                    // 当前只带 CN IP 库；没有 GeoIP 数据库时不能把其他地区猜成不匹配。
                    if code != "CN" {
                        logging::warn("rule", format!("跳过未实现 GEOIP {}（仅 CN 可用）", code));
                        continue;
                    }
                    RuleKind::GeoIp(code)
                }
                "IP-CIDR" | "IP-CIDR6" => match rc.value.parse::<IpNet>() {
                    Ok(net) => RuleKind::IpCidr(net),
                    Err(_) => continue,
                },
                "PORT" => match rc.value.parse::<u16>() {
                    Ok(p) => RuleKind::Port(p),
                    Err(_) => continue,
                },
                "FINAL" | "MATCH" => RuleKind::Final,
                // 这些规则依赖 Android 进程/UID 数据源；未实现前明确拒绝，不能静默当成不匹配。
                "PROCESS-NAME" | "PROCESS-PATH" | "UID" | "APP" | "APP-NAME" => {
                    logging::warn(
                        "rule",
                        format!(
                            "拒绝 {} 规则 {}：当前内核没有可靠的 Android UID/进程名数据源",
                            rc.kind, rc.value
                        ),
                    );
                    continue;
                }
                _ => {
                    logging::warn("rule", format!("拒绝未实现规则类型 {}（值 {}）", rc.kind, rc.value));
                    continue;
                }
            };
            let value = match kind {
                RuleKind::Domain => normalize_domain(&rc.value),
                RuleKind::DomainSuffix => rc.value.trim().trim_start_matches('.').to_ascii_lowercase(),
                RuleKind::DomainKeyword => rc.value.trim().to_ascii_lowercase(),
                _ => rc.value.clone(),
            };
            rules.push(RouteRule {
                kind,
                value,
                action: classify_action(&rc.action, &group_names, &node_names),
                source: rc.source.clone(),
            });
        }
        let final_action = classify_action(&cfg.final_policy, &group_names, &node_names);
        if !rules.iter().any(|r| matches!(r.kind, RuleKind::Final)) {
            rules.push(RouteRule {
                kind: RuleKind::Final,
                value: String::new(),
                action: final_action.clone(),
                source: None,
            });
        }

        let mut cn_domains = DomainSet::default();
        if cfg.cn_direct {
            if let Some(path) = &cfg.cn_domains_file {
                if let Ok(text) = std::fs::read_to_string(path) {
                    for line in text.lines() {
                        let l = line.trim();
                        if l.is_empty() || l.starts_with('#') || l.starts_with('!') {
                            continue;
                        }
                        let l = l.trim_start_matches('.');
                        if let Some(r) = l.strip_prefix("||") {
                            cn_domains.insert_suffix(r.trim_end_matches('^'));
                        } else if l.contains('.') {
                            cn_domains.insert_suffix(l);
                        }
                    }
                }
            }
        }

        // GEOIP 规则即使关闭 cn_direct 也需要 CN IP 库；两者用途不同。
        let cn_ips = cfg
            .cn_ip_file
            .as_ref()
            .map(|p| load_cn_ips(p))
            .unwrap_or_default();

        let rule_count = rules.len() + cn_domains.len();
        Self {
            rules,
            final_action,
            cn_direct: cfg.cn_direct,
            cn_domains,
            cn_ips,
            rule_count,
        }
    }

    pub fn decide(&self, domain: Option<&str>, ip: IpAddr, port: u16, kind: ConnKind) -> Action {
        self.decide_detail(domain, ip, port, kind).0
    }

    /// 与 decide 同一套逻辑，另返回命中说明（供「测试规则」展示，保证单一事实来源）。
    pub fn decide_detail(&self, domain: Option<&str>, ip: IpAddr, _port: u16, _kind: ConnKind) -> (Action, String) {
        let dom = domain.map(normalize_domain);
        // 顺序：自定义规则 -> 国内直连 -> 最终策略。FINAL 不能提前命中。
        for (idx, r) in self.rules.iter().enumerate() {
            if matches!(r.kind, RuleKind::Final) {
                continue;
            }
            let matched = match &r.kind {
                RuleKind::Domain => dom.as_ref().map(|d| d == &r.value).unwrap_or(false),
                RuleKind::DomainSuffix => dom
                    .as_ref()
                    .map(|d| {
                        let suffix = r.value.as_str();
                        !suffix.is_empty()
                            && (d == suffix
                                || (d.len() > suffix.len()
                                    && d.ends_with(suffix)
                                    && d.as_bytes()[d.len() - suffix.len() - 1] == b'.'))
                    })
                    .unwrap_or(false),
                RuleKind::DomainKeyword => dom
                    .as_ref()
                    .map(|d| !r.value.is_empty() && d.contains(r.value.as_str()))
                    .unwrap_or(false),
                RuleKind::DomainRegex(re) => dom.as_ref().map(|d| re.is_match(d)).unwrap_or(false),
                RuleKind::DomainWildcard(re) => dom.as_ref().map(|d| re.is_match(d)).unwrap_or(false),
                RuleKind::GeoIp(code) => {
                    code == "CN" && match ip {
                        IpAddr::V4(v4) => self.cn_ip_contains(v4),
                        IpAddr::V6(_) => false,
                    }
                }
                RuleKind::IpCidr(net) => net.contains(&ip),
                RuleKind::Port(p) => _port == *p,
                RuleKind::Final => false,
            };
            if matched {
                let detail = match &r.source {
                    Some(src) if !src.is_empty() => format!(
                        "命中第 {} 条规则 {} {} → {}\n来源：{}",
                        idx + 1,
                        kind_name(&r.kind),
                        r.value,
                        self.decision_label(&r.action),
                        src
                    ),
                    _ => format!(
                        "命中第 {} 条规则 {} {} → {}\n来源：配置",
                        idx + 1,
                        kind_name(&r.kind),
                        r.value,
                        self.decision_label(&r.action)
                    ),
                };
                return (r.action.clone(), detail);
            }
        }
        if self.cn_direct {
            if let Some(d) = &dom {
                if self.cn_domains.contains(d) {
                    return (Action::Direct, format!("国内直连：域名 {} 命中 CN 域名库", d));
                }
            }
            if let IpAddr::V4(v4) = ip {
                if self.cn_ip_contains(v4) {
                    return (Action::Direct, format!("国内直连：IP {} 命中 CN IP 库", ip));
                }
            }
        }
        for r in &self.rules {
            if matches!(r.kind, RuleKind::Final) {
                let label = self.decision_label(&r.action);
                return (
                    r.action.clone(),
                    format!("未命中任何规则，走最终策略：{}\n来源：final_policy", label),
                );
            }
        }
        let label = self.decision_label(&self.final_action);
        (self.final_action.clone(), format!("未命中任何规则，走最终策略：{}", label))
    }

    fn cn_ip_contains(&self, ip: Ipv4Addr) -> bool {
        let n = u32::from(ip);
        let mut lo = 0usize;
        let mut hi = self.cn_ips.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (start, end) = self.cn_ips[mid];
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

    pub fn decision_label(&self, action: &Action) -> String {
        match action {
            Action::Direct => "DIRECT".into(),
            Action::Proxy => "PROXY".into(),
            Action::Block => "BLOCK".into(),
            Action::Node(n) => n.clone(),
            Action::Group(n) => format!("GROUP:{}", n),
            Action::Missing(n) => format!("MISSING:{}", n),
        }
    }
}

fn kind_name(kind: &RuleKind) -> &'static str {
    match kind {
        RuleKind::Domain => "DOMAIN",
        RuleKind::DomainSuffix => "DOMAIN-SUFFIX",
        RuleKind::DomainKeyword => "DOMAIN-KEYWORD",
        RuleKind::DomainRegex(_) => "DOMAIN-REGEX",
        RuleKind::DomainWildcard(_) => "DOMAIN-WILDCARD",
        RuleKind::GeoIp(_) => "GEOIP",
        RuleKind::IpCidr(_) => "IP-CIDR",
        RuleKind::Port(_) => "PORT",
        RuleKind::Final => "FINAL",
    }
}

fn wildcard_regex(value: &str) -> Result<Regex, regex::Error> {
    let glob = value.trim().trim_start_matches('.');
    let mut pattern = String::from("^");
    for ch in glob.chars() {
        match ch {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            other => pattern.push_str(&regex::escape(&other.to_string())),
        }
    }
    pattern.push('$');
    regex::RegexBuilder::new(&pattern).case_insensitive(true).build()
}

pub(crate) fn load_cn_ips(path: &str) -> Vec<(u32, u32)> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut ranges = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let net: IpNet = match l.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if let IpNet::V4(v4) = net {
            // 用 u64 计算区间：/0 时 1u32 << 32 会溢出（debug panic / release 回绕）。
            let start = u32::from(v4.network()) as u64;
            let size = 1u64 << (32 - v4.prefix_len());
            let end = (start + size - 1).min(u32::MAX as u64) as u32;
            ranges.push((start as u32, end));
        }
    }
    ranges.sort_unstable();
    // 合并重叠/相邻区间：二分查找要求区间互不重叠，用户自更的 IP 库不保证这一点。
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

pub fn build_filter(cfg: &Config) -> FilterEngine {
    let mut filter = FilterEngine::new();
    if !cfg.block_enabled {
        return filter;
    }
    for path in &cfg.ads_files {
        filter.load_file(path);
    }
    if filter.skipped > 0 || filter.rule_count() > 0 {
        logging::info(
            "filter",
            format!(
                "DNS 广告规则生效 {} 条，跳过 {} 条（元素隐藏 {}、条件 {}、路径/通配 {}、非 DNS {}）",
                filter.rule_count(),
                filter.skipped,
                filter.skipped_cosmetic,
                filter.skipped_conditional,
                filter.skipped_path,
                filter.skipped_other
            ),
        );
    }
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singbox_source_rule_set_ingestion() {
        let mut f = FilterEngine::new();
        f.load_singbox_source(
            r#"{"version":3,"rules":[{"domain":["ads.example.com"],"domain_suffix":["tracker.net"],"domain_keyword":["adserv"],"domain_regex":["^ads\\d+\\.foo\\.com$"]}]}"#,
        );
        assert!(f.is_blocked("ads.example.com"));
        assert!(f.is_blocked("x.tracker.net"));
        assert!(f.is_blocked("cdn.adserv.io"));
        assert!(f.is_blocked("ads12.foo.com"));
        assert!(!f.is_blocked("good.com"));
        // 带端口条件的规则整条跳过：不能只保留域名条件造成误拦截。
        f.load_singbox_source(
            r#"{"version":3,"rules":[{"domain":["portonly.example"],"port":[443]}]}"#,
        );
        assert!(!f.is_blocked("portonly.example"));
        assert!(f.skipped_other >= 1);
    }

    #[test]
    fn exact_domain_does_not_match_subdomains() {
        let mut f = FilterEngine::new();
        f.load_singbox_source(r#"{"version":3,"rules":[{"domain":["exact.foo.com"],"domain_suffix":["suffix.foo.com"]}]}"#);
        assert!(f.is_blocked("exact.foo.com"));
        assert!(!f.is_blocked("a.exact.foo.com"), "精确规则不能误伤子域名");
        assert!(f.is_blocked("suffix.foo.com"));
        assert!(f.is_blocked("a.suffix.foo.com"), "后缀规则应该包含子域名");
    }

    #[test]
    fn adblock_syntax_still_works() {
        let mut f = FilterEngine::new();
        f.add_line("||bad.com^");
        assert!(f.is_blocked("x.bad.com"));
        assert!(!f.is_blocked("bad.com.org"));
    }

    #[test]
    fn adblock_single_pipe_exact_and_allow() {
        let mut f = FilterEngine::new();
        f.add_line("||suffix.example.com^");
        f.add_line("|exact.example.net|");
        f.add_line("@@||allowed.example.org^");
        f.add_line("@@|allowed.example.net|");
        assert!(f.is_blocked("suffix.example.com"));
        assert!(f.is_blocked("a.suffix.example.com"));
        assert!(f.is_blocked("exact.example.net"));
        assert!(!f.is_blocked("a.exact.example.net"), "单竖线精确规则不能误伤子域名");
        assert!(!f.is_blocked("allowed.example.org"));
        assert!(!f.is_blocked("a.allowed.example.org"));
        assert!(!f.is_blocked("allowed.example.net"));
    }
}
