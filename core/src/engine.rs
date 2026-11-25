use crate::config::Config;
use crate::logging;
use crate::hits::RuleMeta;
use ipnet::IpNet;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    Important,
    Allow,
    Block,
    None,
}

#[derive(Debug, Clone)]
pub struct FilterMatch {
    pub decision: FilterDecision,
    pub meta: RuleMeta,
}

impl FilterMatch {
    pub fn is_block(&self) -> bool {
        matches!(self.decision, FilterDecision::Important | FilterDecision::Block)
    }
}

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
        self.lookup(domain).is_some()
    }

    /// 返回实际命中的域名键（精确项或后缀项），供归因表反查身份。
    pub fn lookup(&self, domain: &str) -> Option<&String> {
        // 精确集合只匹配完整域名；只有后缀集合才向父域回溯。
        // 原来把 exact 也放进回溯循环，会让 example.com 误伤 a.example.com。
        if let Some(d) = self.exact.get(domain) {
            return Some(d);
        }
        let mut s = domain;
        loop {
            if let Some(d) = self.suffix.get(s) {
                return Some(d);
            }
            match s.find('.') {
                Some(i) => s = &s[i + 1..],
                None => return None,
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
    /// D0：按实际命中键反查规则身份。
    block_meta: HashMap<String, RuleMeta>,
    important_meta: HashMap<String, RuleMeta>,
    allow_meta: HashMap<String, RuleMeta>,
    keyword_meta: Vec<RuleMeta>,
    regex_meta: Vec<RuleMeta>,
    /// 原始规则行 → 身份；模块聚合文件里的行靠它找回模块名。
    line_meta: HashMap<String, RuleMeta>,
    current_meta: Option<RuleMeta>,
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

    pub fn set_line_meta(&mut self, meta: Vec<RuleMeta>) {
        self.line_meta.clear();
        for m in meta {
            if m.section == "dns" && !m.key.trim().is_empty() {
                self.line_meta.insert(m.key.trim().to_string(), m);
            }
        }
    }

    fn meta_for(&self, raw: &str) -> RuleMeta {
        self.current_meta
            .clone()
            .or_else(|| self.line_meta.get(raw.trim()).cloned())
            .unwrap_or_else(|| {
                RuleMeta::config_fallback("dns", raw.trim(), self.lines as i64)
            })
    }

    fn block_exact(&mut self, host: &str, meta: RuleMeta) {
        self.block.insert_exact(host);
        self.block_meta.insert(normalize_domain(host), meta);
    }

    fn block_suffix(&mut self, host: &str, meta: RuleMeta) {
        self.block.insert_suffix(host);
        self.block_meta.insert(normalize_domain(host), meta);
    }

    fn important_exact(&mut self, host: &str, meta: RuleMeta) {
        self.important.insert_exact(host);
        self.important_meta.insert(normalize_domain(host), meta);
    }

    fn important_suffix(&mut self, host: &str, meta: RuleMeta) {
        self.important.insert_suffix(host);
        self.important_meta.insert(normalize_domain(host), meta);
    }

    fn allow_exact(&mut self, host: &str, meta: RuleMeta) {
        self.allow.insert_exact(host);
        self.allow_meta.insert(normalize_domain(host), meta);
    }

    fn allow_suffix(&mut self, host: &str, meta: RuleMeta) {
        self.allow.insert_suffix(host);
        self.allow_meta.insert(normalize_domain(host), meta);
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
            Err(e) => logging::warn(
                "filter",
                format!("读取规则失败 {}: {}", short_path(path), e),
            ),
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
            let Some(obj) = rule.as_object() else {
                continue;
            };
            if obj.keys().any(|k| !supported_keys.contains(&k.as_str())) {
                skipped_rules += 1;
                self.skipped += 1;
                self.skipped_other += 1;
                continue;
            }
            for key in ["domain", "domain_suffix"] {
                if let Some(arr) = obj.get(key).and_then(|a| a.as_array()) {
                    for d in arr.iter().filter_map(|d| d.as_str()) {
                        let meta = self.meta_for(&format!("singbox:{}:{}", key, d));
                        if key == "domain" {
                            self.block_exact(d, meta);
                        } else {
                            self.block_suffix(d, meta);
                        }
                        added += 1;
                    }
                }
            }
            if let Some(arr) = obj.get("domain_keyword").and_then(|a| a.as_array()) {
                for k in arr.iter().filter_map(|d| d.as_str()) {
                    let k = k.trim().to_ascii_lowercase();
                    if !k.is_empty() {
                        self.keywords.push(k.clone());
                        let meta = self.meta_for(&format!("singbox:domain_keyword:{}", k));
                        self.keyword_meta.push(meta);
                        added += 1;
                    }
                }
            }
            if let Some(arr) = obj.get("domain_regex").and_then(|a| a.as_array()) {
                for r in arr.iter().filter_map(|d| d.as_str()) {
                    match Regex::new(r) {
                        Ok(re) => {
                            self.regexes.push(re);
                            let meta = self.meta_for(&format!("singbox:domain_regex:{}", r));
                            self.regex_meta.push(meta);
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
                format!(
                    "sing-box source 跳过 {} 条含不支持条件的规则（端口/取反/进程等）",
                    skipped_rules
                ),
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
        let meta = self.meta_for(raw);
        // 元素隐藏/脚本注入等规则不是 DNS 层能表达的，直接跳过，绝不能被截成主域名。
        if line.contains("##")
            || line.contains("#@#")
            || line.contains("#$#")
            || line.contains("#%#")
            || line.contains("#?#")
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
                    self.add_allow(&line[..i], &meta);
                } else if important {
                    self.add_important(&line[..i], &meta);
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
            self.add_allow(rest, &meta);
            return;
        }
        // hosts 格式
        let mut parts = line.split_whitespace();
        if let (Some(first), Some(second)) = (parts.next(), parts.next()) {
            if (first == "0.0.0.0" || first == "127.0.0.1" || first == "::1")
                && valid_host(&strip_adblock(second))
            {
                let host = strip_adblock(second);
                self.block_exact(&host, meta);
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
                self.block_suffix(host, meta);
                self.lines += 1;
            } else {
                self.skip_invalid(host);
            }
            return;
        }
        if line.starts_with('|') {
            let host = line.trim_matches('|').trim_end_matches('^').trim();
            if valid_host(host) {
                self.block_exact(host, meta);
                self.lines += 1;
            } else {
                self.skip_invalid(host);
            }
            return;
        }
        let host = strip_adblock(line);
        if valid_host(&host) {
            self.block_exact(&host, meta);
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
    fn add_important(&mut self, rest: &str, meta: &RuleMeta) {
        let rest = rest.trim();
        let host = if let Some(r) = rest.strip_prefix("||") {
            r.trim_end_matches('^').trim_end_matches('|')
        } else {
            rest.trim_matches('|')
        };
        let host = host.trim();
        if valid_host(host) {
            if rest.starts_with("||") {
                self.important_suffix(host, meta.clone());
            } else {
                self.important_exact(host, meta.clone());
            }
        } else {
            self.skipped += 1;
            self.skipped_other += 1;
        }
    }

    pub fn is_allowed(&self, domain: &str) -> bool {
        self.allow.contains(&normalize_domain(domain))
    }

    /// 把分流规则里的 REJECT 域名规则并入 DNS 过滤。
    ///
    /// 为什么必须并入：DNS-only 模式下连接层对所有非 DNS 连接直接直连，
    /// route 层永远不会有 REJECT 的机会——用户在配置里写的 `DOMAIN,...,REJECT`
    /// 会「导入成功但实际不拦截」。只有放进 DNS 过滤，拦截才真正生效。
    ///
    /// 优先级用 `important`：手写的 REJECT 是明确指令，应该压过订阅广告源里
    /// 的 `@@` 例外，否则会出现「规则明明写了却拦不住」的困惑。
    pub fn add_route_block(&mut self, kind: &str, value: &str, meta: Option<&RuleMeta>) -> bool {
        let k = kind.trim().to_ascii_uppercase();
        let v = value.trim();
        match k.as_str() {
            "DOMAIN" => {
                let d = normalize_domain(v);
                if valid_host(&d) {
                    self.important_exact(&d, meta.cloned().unwrap_or_else(|| RuleMeta::config_fallback("route", kind, self.lines as i64)));
                    self.lines += 1;
                    true
                } else {
                    false
                }
            }
            "DOMAIN-SUFFIX" => {
                let d = v.trim_start_matches('.').to_ascii_lowercase();
                if valid_host(&d) {
                    self.important_suffix(&d, meta.cloned().unwrap_or_else(|| RuleMeta::config_fallback("route", kind, self.lines as i64)));
                    self.lines += 1;
                    true
                } else {
                    false
                }
            }
            "DOMAIN-KEYWORD" => {
                let kw = v.to_ascii_lowercase();
                if kw.is_empty() {
                    false
                } else {
                    self.keywords.push(kw);
                    self.keyword_meta.push(meta.cloned().unwrap_or_else(|| RuleMeta::config_fallback("route", kind, self.lines as i64)));
                    // OnceCell 可能已在之前的判定里初始化，重置它让新关键词进入自动机。
                    self.keywords_ac = once_cell::sync::OnceCell::new();
                    self.lines += 1;
                    true
                }
            }
            "DOMAIN-REGEX" => match Regex::new(v) {
                Ok(re) => {
                    self.regexes.push(re);
                    self.regex_meta.push(meta.cloned().unwrap_or_else(|| RuleMeta::config_fallback("route", kind, self.lines as i64)));
                    self.lines += 1;
                    true
                }
                Err(e) => {
                    logging::warn("filter", format!("分流 REJECT 正则无效已跳过 {}: {}", v, e));
                    false
                }
            },
            "DOMAIN-WILDCARD" => match wildcard_regex(v) {
                Ok(re) => {
                    self.regexes.push(re);
                    self.regex_meta.push(meta.cloned().unwrap_or_else(|| RuleMeta::config_fallback("route", kind, self.lines as i64)));
                    self.lines += 1;
                    true
                }
                Err(_) => false,
            },
            _ => false,
        }
    }

    fn add_allow(&mut self, rest: &str, meta: &RuleMeta) {
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
                self.allow_suffix(host, meta.clone());
            } else {
                self.allow_exact(host, meta.clone());
            }
        } else {
            self.skip_invalid(host);
        }
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        self.match_detail(domain).is_block()
    }

    /// D0：返回实际生效的规则（important > allow > block > keyword/regex）。
    /// allow 与无命中都计入「不计数」，由调用方区分展示。
    pub fn match_detail(&self, domain: &str) -> FilterMatch {
        let domain = normalize_domain(domain);
        let none = FilterMatch {
            decision: FilterDecision::None,
            meta: RuleMeta::config_fallback("dns", "", -1),
        };
        if domain.is_empty() {
            return none;
        }
        if let Some(key) = self.important.lookup(&domain) {
            let meta = self.important_meta.get(key).cloned().unwrap_or_else(|| {
                RuleMeta::config_fallback("dns", key, -1)
            });
            return FilterMatch {
                decision: FilterDecision::Important,
                meta,
            };
        }
        if let Some(key) = self.allow.lookup(&domain) {
            let meta = self.allow_meta.get(key).cloned().unwrap_or_else(|| {
                RuleMeta::config_fallback("dns", key, -1)
            });
            return FilterMatch {
                decision: FilterDecision::Allow,
                meta,
            };
        }
        if let Some(key) = self.block.lookup(&domain) {
            let meta = self.block_meta.get(key).cloned().unwrap_or_else(|| {
                RuleMeta::config_fallback("dns", key, -1)
            });
            return FilterMatch {
                decision: FilterDecision::Block,
                meta,
            };
        }
        if !self.keywords.is_empty() {
            let ac = self.keywords_ac.get_or_init(|| {
                match aho_corasick::AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&self.keywords)
                {
                    Ok(ac) => Some(ac),
                    Err(e) => {
                        logging::warn(
                            "filter",
                            format!("关键词自动机构造失败，回退逐条匹配: {}", e),
                        );
                        None
                    }
                }
            });
            let idx = match ac {
                Some(ac) => ac.find(domain.as_bytes()).map(|_| {
                    self.keywords
                        .iter()
                        .position(|k| domain.contains(k.as_str()))
                        .unwrap_or(0)
                }),
                None => self
                    .keywords
                    .iter()
                    .position(|k| domain.contains(k.as_str())),
            };
            if let Some(i) = idx {
                let meta = self.keyword_meta.get(i).cloned().unwrap_or_else(|| {
                    RuleMeta::config_fallback("dns", &self.keywords[i], i as i64)
                });
                return FilterMatch {
                    decision: FilterDecision::Block,
                    meta,
                };
            }
        }
        if let Some(i) = self.regexes.iter().position(|r| r.is_match(&domain)) {
            let meta = self.regex_meta.get(i).cloned().unwrap_or_else(|| {
                RuleMeta::config_fallback("dns", self.regexes[i].as_str(), i as i64)
            });
            return FilterMatch {
                decision: FilterDecision::Block,
                meta,
            };
        }
        none
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
pub fn classify_action(
    raw: &str,
    group_names: &HashSet<String>,
    node_names: &HashSet<String>,
) -> Action {
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
    /// PROTOCOL：按连接类型匹配（TCP/UDP）。
    Protocol(ConnKind),
    /// UID：按 Android 应用 UID 匹配。包名/进程名规则由壳层先解析成 UID 再下发，
    /// 内核不持有包名表——包名到 UID 的映射随应用安装/卸载变化，属于壳层职责。
    Uid(u32),
    Final,
}

/// 一条连接进入规则匹配时需要知道的全部信息。
/// `uid` 为 None 表示「归属未知」（没有 root、或表里还没这个 socket），
/// 此时 UID 规则一律不命中，绝不退化成匹配 UID 0。
pub struct MatchInput<'a> {
    pub domain: Option<&'a str>,
    pub ip: IpAddr,
    pub port: u16,
    pub kind: ConnKind,
    pub uid: Option<u32>,
}

#[derive(Debug, Clone)]
struct RouteRule {
    kind: RuleKind,
    value: String,
    action: Action,
    extended_match: bool,
    pre_match: bool,
    source: Option<String>,
    meta: Option<crate::hits::RuleMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnKind {
    Tcp,
    Udp,
}

pub struct RuleEngine {
    rules: Vec<RouteRule>,
    final_action: Action,
    cn_direct: bool,
    cn_domains: DomainSet,
    skip_proxy: DomainSet,
    cn_ips: Vec<(u32, u32)>,
    pub rule_count: usize,
    /// 配置里是否存在 UID 规则。用于「没 root 时提醒规则不生效」的统计与界面提示。
    has_uid: bool,
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
        // 纯过滤模式：全量 TUN、不使用任何节点。代理类动作全部降级为直连，
        // 否则 final=proxy 或引用了不存在节点的规则会命中「无节点兜底拦截」直接断网。
        let filter_only = cfg.mode.eq_ignore_ascii_case("filter_only");
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
                "PORT" | "DST-PORT" => match rc.value.parse::<u16>() {
                    Ok(p) => RuleKind::Port(p),
                    Err(_) => continue,
                },
                "PROTOCOL" => match rc.value.trim().to_ascii_uppercase().as_str() {
                    "TCP" => RuleKind::Protocol(ConnKind::Tcp),
                    "UDP" => RuleKind::Protocol(ConnKind::Udp),
                    other => {
                        logging::warn(
                            "rule",
                            format!("拒绝 PROTOCOL 值 {}（仅支持 TCP/UDP）", other),
                        );
                        continue;
                    }
                },
                "FINAL" | "MATCH" => RuleKind::Final,
                // 这些规则依赖 Android 进程/UID 数据源。UID 数值规则可直接用；
                // 包名类规则由壳层解析成 UID 后再下发，内核侧不再重复实现一套包名表。
                "UID" => match rc.value.trim().parse::<u32>() {
                    Ok(u) => RuleKind::Uid(u),
                    Err(_) => {
                        logging::warn(
                            "rule",
                            format!("拒绝 UID 规则值 {}：不是合法整数", rc.value),
                        );
                        continue;
                    }
                },
                "PROCESS-NAME" | "PROCESS-PATH" | "APP" | "APP-NAME" => {
                    logging::warn(
                        "rule",
                        format!(
                            "拒绝 {} 规则 {}：包名类规则需先由壳层解析成 UID 规则",
                            rc.kind, rc.value
                        ),
                    );
                    continue;
                }
                _ => {
                    logging::warn(
                        "rule",
                        format!("拒绝未实现规则类型 {}（值 {}）", rc.kind, rc.value),
                    );
                    continue;
                }
            };
            let value = match kind {
                RuleKind::Domain => normalize_domain(&rc.value),
                RuleKind::DomainSuffix => {
                    rc.value.trim().trim_start_matches('.').to_ascii_lowercase()
                }
                RuleKind::DomainKeyword => rc.value.trim().to_ascii_lowercase(),
                RuleKind::Protocol(_) => rc.value.trim().to_ascii_uppercase(),
                _ => rc.value.clone(),
            };
            let action_name = rc.action.split(',').next().unwrap_or("").trim();
            let extended_match = rc.action.split(',').any(|v| v.trim().eq_ignore_ascii_case("extended-matching"));
            let pre_match = rc.action.split(',').any(|v| v.trim().eq_ignore_ascii_case("pre-matching"));
            let action = classify_action(action_name, &group_names, &node_names);
            let action = if filter_only {
                proxy_to_direct(action)
            } else {
                action
            };
            let pre_match = pre_match && matches!(action, Action::Block);
            rules.push(RouteRule {
                kind,
                value,
                action,
                extended_match,
                pre_match,
                source: rc.source.clone(),
                meta: rc.meta.clone(),
            });
        }
        let final_action = classify_action(&cfg.final_policy, &group_names, &node_names);
        let final_action = if filter_only {
            proxy_to_direct(final_action)
        } else {
            final_action
        };
        if !rules.iter().any(|r| matches!(r.kind, RuleKind::Final)) {
            rules.push(RouteRule {
                kind: RuleKind::Final,
                value: String::new(),
                action: final_action.clone(),
                extended_match: false,
                pre_match: false,
                source: None,
                meta: None,
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

        let mut skip_proxy = DomainSet::default();
        for domain in &cfg.skip_proxy {
            skip_proxy.insert_suffix(domain);
        }

        // GEOIP 规则即使关闭 cn_direct 也需要 CN IP 库；两者用途不同。
        let cn_ips = cfg
            .cn_ip_file
            .as_ref()
            .map(|p| load_cn_ips(p))
            .unwrap_or_default();

        let rule_count = rules.len() + cn_domains.len();
        let has_uid = rules.iter().any(|r| matches!(r.kind, RuleKind::Uid(_)));
        Self {
            rules,
            final_action,
            cn_direct: cfg.cn_direct,
            cn_domains,
            skip_proxy,
            cn_ips,
            rule_count,
            has_uid,
        }
    }

    /// 配置是否引用了 UID 规则（决定是否需要 UID 表、以及无 root 时是否提示）。
    pub fn has_uid_rules(&self) -> bool {
        self.has_uid
    }

    pub fn decide(&self, domain: Option<&str>, ip: IpAddr, port: u16, kind: ConnKind) -> Action {
        self.decide_detail(domain, ip, port, kind).0
    }

    /// 与 decide 同一套逻辑，另返回命中说明（供「测试规则」展示，保证单一事实来源）。
    pub fn decide_detail(
        &self,
        domain: Option<&str>,
        ip: IpAddr,
        port: u16,
        kind: ConnKind,
    ) -> (Action, String) {
        // 没有 UID 数据源的调用方（测试规则、UDP 早期路径）按「归属未知」处理。
        self.decide_input(&MatchInput {
            domain,
            ip,
            port,
            kind,
            uid: None,
        })
    }

    /// 带 App 归属的连接判定。UID 规则只在 `input.uid` 有值时才参与匹配。
    pub fn decide_input(&self, input: &MatchInput<'_>) -> (Action, String) {
        let (a, d, _) = self.decide_input_attributed(input);
        (a, d)
    }

    /// D0：同一套判定，额外返回首条生效规则的稳定身份。
    /// CN 直连 / final_policy / 无规则 都返回 None（bypass 不计命中）。
    pub fn decide_input_attributed(
        &self,
        input: &MatchInput<'_>,
    ) -> (Action, String, Option<crate::hits::RuleIdentity>) {
        self.decide_input_attributed_with_sniff(input, false)
    }

    /// `sniffed_domain` 表示域名来自 TLS SNI / HTTP Host；仅扩展匹配规则消费该来源。
    pub fn decide_input_attributed_with_sniff(
        &self,
        input: &MatchInput<'_>,
        sniffed_domain: bool,
    ) -> (Action, String, Option<crate::hits::RuleIdentity>) {
        self.decide_input_attributed_with_sources(input, sniffed_domain, None)
    }

    /// 同时保留 DNS 反查域名与嗅探域名；普通规则消费前者，扩展规则还可消费后者。
    pub fn decide_input_attributed_with_sources(
        &self,
        input: &MatchInput<'_>,
        sniffed_domain: bool,
        base_domain: Option<&str>,
    ) -> (Action, String, Option<crate::hits::RuleIdentity>) {
        let dom = input.domain.map(normalize_domain);
        let base_dom = base_domain.map(normalize_domain);
        if let Some(domain) = &dom {
            if self.skip_proxy.contains(domain) {
                return (Action::Direct, format!("跳过代理：域名 {} 命中直连列表", domain), None);
            }
        }
        if let Some(domain) = &base_dom {
            if self.skip_proxy.contains(domain) {
                return (Action::Direct, format!("跳过代理：域名 {} 命中直连列表", domain), None);
            }
        }
        // 预匹配拦截规则先于普通顺序规则，其余规则保持配置顺序。
        for (idx, r) in self.rules.iter().enumerate()
            .filter(|(_, r)| r.pre_match && matches!(r.action, Action::Block))
            .chain(self.rules.iter().enumerate().filter(|(_, r)| !(r.pre_match && matches!(r.action, Action::Block)))) {
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
                RuleKind::DomainWildcard(re) => {
                    dom.as_ref().map(|d| re.is_match(d)).unwrap_or(false)
                }
                RuleKind::GeoIp(code) => {
                    code == "CN"
                        && match input.ip {
                            IpAddr::V4(v4) => self.cn_ip_contains(v4),
                            IpAddr::V6(_) => false,
                        }
                }
                RuleKind::IpCidr(net) => net.contains(&input.ip),
                RuleKind::Port(p) => input.port == *p,
                RuleKind::Protocol(k) => input.kind == *k,
                // 归属未知时 UID 规则不命中：不能把 None 当成 0（0 是 root）去比。
                RuleKind::Uid(u) => input.uid.map(|v| v == *u).unwrap_or(false),
                RuleKind::Final => false,
            };
            let domain_rule = matches!(
                &r.kind,
                RuleKind::Domain | RuleKind::DomainSuffix | RuleKind::DomainKeyword |
                    RuleKind::DomainRegex(_) | RuleKind::DomainWildcard(_)
            );
            let matched = if sniffed_domain && domain_rule {
                let base_match = match &r.kind {
                    RuleKind::Domain => base_dom.as_ref().map(|d| d == &r.value).unwrap_or(false),
                    RuleKind::DomainSuffix => base_dom.as_ref().map(|d| {
                        let suffix = r.value.as_str();
                        !suffix.is_empty() && (d == suffix || (d.len() > suffix.len()
                            && d.ends_with(suffix) && d.as_bytes()[d.len() - suffix.len() - 1] == b'.'))
                    }).unwrap_or(false),
                    RuleKind::DomainKeyword => base_dom.as_ref().map(|d| !r.value.is_empty() && d.contains(r.value.as_str())).unwrap_or(false),
                    RuleKind::DomainRegex(re) | RuleKind::DomainWildcard(re) => base_dom.as_ref().map(|d| re.is_match(d)).unwrap_or(false),
                    _ => false,
                };
                (r.extended_match && matched) || base_match
            } else {
                matched
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
                let identity = r
                    .meta
                    .as_ref()
                    .map(|m| m.identity())
                    .unwrap_or_else(|| crate::hits::RuleIdentity {
                        rule_id: crate::hits::short_rule_id(
                            "config",
                            "route",
                            &format!("{}|{}|{}", kind_name(&r.kind), r.value, idx),
                        ),
                        source_type: "route".into(),
                        source_id: "config".into(),
                        source_name: r.source.clone().unwrap_or_else(|| "当前配置".into()),
                        order: idx as i64,
                    });
                return (r.action.clone(), detail, Some(identity));
            }
        }
        if self.cn_direct {
            if let Some(d) = &dom {
                if self.cn_domains.contains(d) {
                    return (
                        Action::Direct,
                        format!("国内直连：域名 {} 命中 CN 域名库", d),
                        None,
                    );
                }
            }
            if let IpAddr::V4(v4) = input.ip {
                if self.cn_ip_contains(v4) {
                    return (
                        Action::Direct,
                        format!("国内直连：IP {} 命中 CN IP 库", input.ip),
                        None,
                    );
                }
            }
        }
        for r in &self.rules {
            if matches!(r.kind, RuleKind::Final) {
                let label = self.decision_label(&r.action);
                return (
                    r.action.clone(),
                    format!("未命中任何规则，走最终策略：{}\n来源：final_policy", label),
                    None,
                );
            }
        }
        let label = self.decision_label(&self.final_action);
        (
            self.final_action.clone(),
            format!("未命中任何规则，走最终策略：{}", label),
            None,
        )
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
        RuleKind::Protocol(_) => "PROTOCOL",
        RuleKind::Uid(_) => "UID",
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
    regex::RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
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

/// 规则动作是否是「拦截」。只认字面值：`block` / `reject` / `reject-drop`。
/// 组名间接指向拦截的情况不在这里展开——build_filter 拿不到节点/组表，
/// 那种规则仍会在连接层生效（仅 rule/global 全量 TUN 模式）。
/// 纯过滤模式的动作降级：没有节点时，任何"走代理"的意图都落空，
/// 与其让它命中无节点兜底拦截（用户会以为 App 坏了），不如直连。
fn proxy_to_direct(a: Action) -> Action {
    match a {
        Action::Proxy | Action::Node(_) | Action::Group(_) | Action::Missing(_) => Action::Direct,
        other => other,
    }
}

fn action_is_block(action: &str) -> bool {
    let a = action.trim();
    a.eq_ignore_ascii_case("block")
        || a.eq_ignore_ascii_case("reject")
        || a.eq_ignore_ascii_case("reject-drop")
}

pub fn build_filter(cfg: &Config) -> FilterEngine {
    let mut filter = FilterEngine::new();
    filter.set_line_meta(cfg.rule_meta.clone());
    // 分流里的 REJECT 域名规则先并入 DNS 过滤，且**不受 block_enabled 影响**：
    // 它是分流语义（用户明确要求拦截），不是广告过滤。DNS-only 模式下连接层
    // 对所有非 DNS 连接直接直连，route 层没有机会拦截，只有 DNS 层能兜住。
    let mut route_blocked = 0usize;
    for rc in &cfg.rules {
        if action_is_block(&rc.action) && filter.add_route_block(&rc.kind, &rc.value, rc.meta.as_ref()) {
            route_blocked += 1;
        }
    }
    if route_blocked > 0 {
        logging::info(
            "filter",
            format!("分流 REJECT 已并入 DNS 拦截 {} 条", route_blocked),
        );
    }
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
        assert!(
            !f.is_blocked("a.exact.example.net"),
            "单竖线精确规则不能误伤子域名"
        );
        assert!(!f.is_blocked("allowed.example.org"));
        assert!(!f.is_blocked("a.allowed.example.org"));
        assert!(!f.is_blocked("allowed.example.net"));
    }

    fn uid_cfg() -> Config {
        let mut cfg = Config::default();
        // 场景：只对 B 站（uid 10100）拦 ads.bilibili.com，微信（uid 10200）照常走。
        cfg.rules = vec![
            crate::config::RuleConf {
                kind: "UID".into(),
                value: "10100".into(),
                action: "BLOCK".into(),
                source: None,
                meta: None,
            },
            crate::config::RuleConf {
                kind: "DOMAIN-SUFFIX".into(),
                value: "ads.bilibili.com".into(),
                action: "BLOCK".into(),
                source: None,
                meta: None,
            },
        ];
        cfg
    }

    #[test]
    fn uid_rule_participates_in_matching() {
        let cfg = uid_cfg();
        let engine = RuleEngine::from_config(&cfg);
        assert!(engine.has_uid_rules());
        assert_eq!(
            engine.rule_count, 3,
            "两条配置规则 + 自动补的 FINAL，UID 规则不能被丢弃"
        );
    }

    #[test]
    fn uid_rule_only_hits_the_named_app() {
        let cfg = uid_cfg();
        let engine = RuleEngine::from_config(&cfg);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // B 站命中 BLOCK
        let (a, why) = engine.decide_input(&MatchInput {
            domain: Some("www.bilibili.com"),
            ip,
            port: 443,
            kind: ConnKind::Tcp,
            uid: Some(10100),
        });
        assert!(
            matches!(a, Action::Block),
            "uid 10100 应命中 BLOCK，实际 {:?}",
            a
        );
        assert!(why.contains("UID"), "命中说明应标明来源规则：{}", why);
        // 微信同域名不受影响
        let (a2, _) = engine.decide_input(&MatchInput {
            domain: Some("www.bilibili.com"),
            ip,
            port: 443,
            kind: ConnKind::Tcp,
            uid: Some(10200),
        });
        assert!(
            !matches!(a2, Action::Block),
            "uid 10200 不应被 B 站规则影响，实际 {:?}",
            a2
        );
    }

    #[test]
    fn uid_rule_does_not_match_when_uid_unknown() {
        let cfg = uid_cfg();
        let engine = RuleEngine::from_config(&cfg);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // 归属未知（无 root / 表里没这条）时不能命中，更不能退化成 uid 0
        let (a, _) = engine.decide_input(&MatchInput {
            domain: Some("www.bilibili.com"),
            ip,
            port: 443,
            kind: ConnKind::Tcp,
            uid: None,
        });
        assert!(
            matches!(a, Action::Proxy),
            "归属未知时应回落到最终策略(proxy)，实际 {:?}",
            a
        );
    }

    #[test]
    fn invalid_uid_value_is_rejected_not_silently_kept() {
        let mut cfg = Config::default();
        cfg.rules = vec![crate::config::RuleConf {
            kind: "UID".into(),
            value: "com.bilibili.app".into(),
            action: "BLOCK".into(),
            source: None,
                meta: None,
            }];
        let engine = RuleEngine::from_config(&cfg);
        // 包名误写成 UID 时该条规则必须被丢弃，否则会匹配不到任何连接却让人以为生效
        assert_eq!(engine.rule_count, 1, "只剩自动补的 FINAL");
        assert!(!engine.has_uid_rules());
    }

    #[test]
    fn filter_only_mode_degrades_proxy_to_direct() {
        let mut cfg = Config::default();
        cfg.mode = "filter_only".into();
        cfg.final_policy = "proxy".into();
        cfg.rules = vec![
            crate::config::RuleConf {
                kind: "DOMAIN-SUFFIX".into(),
                value: "via-proxy.example".into(),
                action: "proxy".into(),
                source: None,
                meta: None,
            },
            crate::config::RuleConf {
                kind: "DOMAIN-SUFFIX".into(),
                value: "blocked.example".into(),
                action: "block".into(),
                source: None,
                meta: None,
            },
        ];
        let engine = RuleEngine::from_config(&cfg);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // 没有节点也不打算代理：代理意图降级直连，不能命中「无节点兜底拦截」断网。
        let (a, _) = engine.decide_input(&MatchInput {
            domain: Some("cdn.via-proxy.example"),
            ip,
            port: 443,
            kind: ConnKind::Tcp,
            uid: None,
        });
        assert!(
            matches!(a, Action::Direct),
            "代理规则应降级为直连，实际 {:?}",
            a
        );
        // FINAL 也降级
        let (f, _) = engine.decide_input(&MatchInput {
            domain: Some("unknown.example"),
            ip,
            port: 443,
            kind: ConnKind::Tcp,
            uid: None,
        });
        assert!(
            matches!(f, Action::Direct),
            "final=proxy 应降级为直连，实际 {:?}",
            f
        );
        // 拦截规则必须原样保留
        let (b, why) = engine.decide_input(&MatchInput {
            domain: Some("x.blocked.example"),
            ip,
            port: 443,
            kind: ConnKind::Tcp,
            uid: None,
        });
        assert!(matches!(b, Action::Block), "拦截不能被降级，实际 {:?}", b);
        assert!(why.contains("DOMAIN-SUFFIX"));
    }

    #[test]
    fn rule_mode_keeps_proxy_intent() {
        let mut cfg = Config::default();
        cfg.mode = "rule".into();
        cfg.final_policy = "proxy".into();
        let engine = RuleEngine::from_config(&cfg);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let (a, _) = engine.decide_input(&MatchInput {
            domain: Some("example.com"),
            ip,
            port: 443,
            kind: ConnKind::Tcp,
            uid: None,
        });
        // 对照：普通规则模式下 final=proxy 保持原样，由运行时无节点兜底处理。
        assert!(matches!(a, Action::Proxy), "实际 {:?}", a);
    }

    #[test]
    fn route_reject_rules_feed_dns_filter() {
        let mut cfg = Config::default();
        cfg.rules = vec![
            crate::config::RuleConf {
                kind: "DOMAIN".into(),
                value: "ad.example.com".into(),
                action: "block".into(),
                source: None,
                meta: None,
            },
            crate::config::RuleConf {
                kind: "DOMAIN-SUFFIX".into(),
                value: "tracker.example".into(),
                action: "BLOCK".into(),
                source: None,
                meta: None,
            },
            crate::config::RuleConf {
                kind: "DOMAIN-KEYWORD".into(),
                value: "adserv".into(),
                action: "reject".into(),
                source: None,
                meta: None,
            },
            crate::config::RuleConf {
                kind: "DOMAIN-REGEX".into(),
                value: "^ads\\d+\\.foo\\.com$".into(),
                action: "block".into(),
                source: None,
                meta: None,
            },
            crate::config::RuleConf {
                kind: "DOMAIN-WILDCARD".into(),
                value: "*.banner.example".into(),
                action: "block".into(),
                source: None,
                meta: None,
            },
            crate::config::RuleConf {
                kind: "DOMAIN".into(),
                value: "allow.example.com".into(),
                action: "direct".into(),
                source: None,
                meta: None,
            },
        ];
        let f = build_filter(&cfg);
        // DNS-only 下连接层不会执行 REJECT，这五类拦截必须在 DNS 层生效。
        assert!(f.is_blocked("ad.example.com"), "DOMAIN 精确");
        assert!(
            !f.is_blocked("sub.ad.example.com"),
            "精确规则不能误伤子域名"
        );
        assert!(f.is_blocked("x.tracker.example"), "DOMAIN-SUFFIX");
        assert!(f.is_blocked("cdn.adserv.io"), "DOMAIN-KEYWORD");
        assert!(f.is_blocked("ads12.foo.com"), "DOMAIN-REGEX");
        assert!(f.is_blocked("a.banner.example"), "DOMAIN-WILDCARD");
        assert!(
            !f.is_blocked("allow.example.com"),
            "DIRECT 规则不能被当成拦截"
        );
    }

    #[test]
    fn route_reject_applies_even_when_ads_block_disabled() {
        let mut cfg = Config::default();
        cfg.block_enabled = false;
        cfg.rules = vec![crate::config::RuleConf {
            kind: "DOMAIN-SUFFIX".into(),
            value: "tracker.example".into(),
            action: "block".into(),
            source: None,
                meta: None,
            }];
        let f = build_filter(&cfg);
        // 分流拦截是用户明确指令，不能被广告过滤总开关一起关掉。
        assert!(f.is_blocked("x.tracker.example"));
    }

    #[test]
    fn invalid_route_reject_regex_is_skipped() {
        let mut cfg = Config::default();
        cfg.rules = vec![crate::config::RuleConf {
            kind: "DOMAIN-REGEX".into(),
            value: "([".into(),
            action: "block".into(),
            source: None,
                meta: None,
            }];
        let f = build_filter(&cfg);
        // 非法正则不能让内核 panic 或误匹配任何域名
        assert!(!f.is_blocked("anything.example"));
    }

    #[test]
    fn package_name_rules_still_rejected_with_explicit_reason() {
        let mut cfg = Config::default();
        cfg.rules = vec![crate::config::RuleConf {
            kind: "PROCESS-NAME".into(),
            value: "com.bilibili.app".into(),
            action: "BLOCK".into(),
            source: None,
                meta: None,
            }];
        let engine = RuleEngine::from_config(&cfg);
        // 包名类规则由壳层展开成 UID 后下发；内核直接收到时应拒绝而不是误匹配
        assert_eq!(engine.rule_count, 1, "只剩自动补的 FINAL");
    }

    fn flagged_rule(value: &str, action: &str) -> crate::config::RuleConf {
        crate::config::RuleConf {
            kind: "DOMAIN-SUFFIX".into(), value: value.into(), action: action.into(), source: None, meta: None,
        }
    }

    fn flagged_input<'a>(domain: &'a str) -> MatchInput<'a> {
        MatchInput { domain: Some(domain), ip: "203.0.113.9".parse().unwrap(), port: 443, kind: ConnKind::Tcp, uid: None }
    }

    #[test]
    fn extended_matching_consumes_sniffed_domain_only_when_enabled() {
        let mut cfg = Config::default();
        cfg.rules = vec![flagged_rule("example.com", "direct"), flagged_rule("example.com", "block,extended-matching")];
        let engine = RuleEngine::from_config(&cfg);
        assert!(matches!(engine.decide_input(&flagged_input("a.example.com")).0, Action::Direct));
        assert!(matches!(engine.decide_input_attributed_with_sniff(&flagged_input("a.example.com"), true).0, Action::Block));
        assert!(matches!(engine.decide_input_attributed_with_sources(&flagged_input("a.example.com"), true, Some("example.com")).0, Action::Direct));
    }

    #[test]
    fn pre_matching_block_precedes_normal_rule_order() {
        let mut cfg = Config::default();
        cfg.rules = vec![flagged_rule("example.com", "direct"), flagged_rule("example.com", "block,pre-matching")];
        let engine = RuleEngine::from_config(&cfg);
        let (action, detail) = engine.decide_input(&flagged_input("a.example.com"));
        assert!(matches!(action, Action::Block));
        assert!(detail.contains("第 2 条规则"));
    }

    #[test]
    fn skip_proxy_bypasses_block_rules() {
        let mut cfg = Config::default();
        cfg.skip_proxy = vec!["example.com".into()];
        cfg.rules = vec![flagged_rule("example.com", "block")];
        let engine = RuleEngine::from_config(&cfg);
        assert!(matches!(engine.decide_input(&flagged_input("a.example.com")).0, Action::Direct));
    }
}
