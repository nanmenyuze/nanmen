//! MITM 去广告规则：Surge 模块兼容的 hostname 匹配 + URL Rewrite。
//!
//! 支持动作：
//! - reject / reject-200 / reject-tinygif（reject-img 同义）：按 URL 拒绝广告请求
//! - body：对响应体做正则替换（删 JSON 广告字段等），可多条叠加
//! - header：改写发往服务器的请求头
//!
//! hostname 语义与 Surge 一致：`*.example.com` 匹配 example.com 及其全部子域，
//! 裸域名只精确匹配。握手失败的域名进入临时放行名单（fail-open），不断网。

use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::mitm::loon::LoonRule;
use crate::script::{ScriptEngine, ScriptRuleConf};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn default_body_limit() -> usize {
    2 * 1024 * 1024
}
fn default_fail_open_ttl() -> u64 {
    300
}

/// 单条 URL Rewrite 规则（配置/模块合并后的中间表示）。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MitmRuleConf {
    /// 匹配完整 URL（https://host/path?query）的正则。
    pub pattern: String,
    /// reject | reject-200 | reject-tinygif | body | header
    pub action: String,
    /// body 动作：响应体正则（空 = 整体替换）。
    #[serde(default)]
    pub body_pattern: String,
    /// body/header 动作的替换内容（支持 $1 捕获组）。
    #[serde(default)]
    pub replacement: String,
    /// header 动作：要改写的请求头字段名。
    #[serde(default)]
    pub header_field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// MITM 配置块（config.rs 的 `mitm` 字段），默认关闭。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MitmConfig {
    #[serde(default)]
    pub enabled: bool,
    /// CA 证书+私钥落盘路径（PEM，两段拼接）；空 = 不启用。
    #[serde(default)]
    pub ca_file: String,
    /// MITM 域名列表：精确域名或 *.suffix。
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// 用户显式跳过的域名（永不 MITM）。
    /// 1.33 壳层使用 `skip_hostnames` 键，这里做别名兼容。
    #[serde(default, alias = "skip_hostnames")]
    pub skip: Vec<String>,
    #[serde(default)]
    pub rules: Vec<MitmRuleConf>,
    /// 1.33 壳层（M1）下发的原始 [URL Rewrite] 行，由内核解析成 rules。
    #[serde(default)]
    pub url_rewrites: Vec<String>,
    /// 1.33 壳层（M1）下发的原始 [Header Rewrite] 行，由内核解析成 rules。
    #[serde(default)]
    pub header_rewrites: Vec<String>,
    /// Loon `[Rewrite]` 原始行（旧版与新版语法混排），由 loon 解析器编译。
    #[serde(default)]
    pub loon_rewrites: Vec<String>,
    /// 请求/响应脚本；正文由外壳下载后写入，内核用 QuickJS 执行。
    #[serde(default)]
    pub scripts: Vec<ScriptRuleConf>,
    /// `$persistentStore` 落盘路径；空 = 仅在进程内保存。
    #[serde(default)]
    pub script_store_file: String,
    /// 响应体改写上限（字节），超过则原样透传，防内存失控。
    #[serde(default = "default_body_limit")]
    pub body_limit: usize,
    /// 握手失败域名的临时放行时长（秒）。
    #[serde(default = "default_fail_open_ttl")]
    pub fail_open_ttl: u64,
    /// 调试用：跳过对真实服务器的证书校验。正常使用必须为 false。
    #[serde(default)]
    pub upstream_insecure: bool,
    /// 按 App MITM：`all`（全部应用）/ `allow`（仅 app_uids 内）/ `deny`（app_uids 内跳过）。
    #[serde(default)]
    pub app_mode: String,
    /// app_mode 使用的 UID 列表；壳层把用户选的包名解析成 UID 后下发。
    #[serde(default)]
    pub app_uids: Vec<u32>,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ca_file: String::new(),
            hostnames: Vec::new(),
            skip: Vec::new(),
            rules: Vec::new(),
            url_rewrites: Vec::new(),
            header_rewrites: Vec::new(),
            loon_rewrites: Vec::new(),
            scripts: Vec::new(),
            script_store_file: String::new(),
            body_limit: default_body_limit(),
            fail_open_ttl: default_fail_open_ttl(),
            upstream_insecure: false,
            app_mode: String::new(),
            app_uids: Vec::new(),
        }
    }
}

/// MITM 的 App 生效范围。UID 未知时按最保守的一侧处理：
/// - `Allow`：不解密，避免把银行/支付这类证书固定应用误伤；
/// - `Deny`：仍解密（列表外的应用本来就要处理），保持与全局模式一致。
#[derive(Debug, Clone, Default, PartialEq)]
pub enum AppScope {
    #[default]
    All,
    Allow(HashSet<u32>),
    Deny(HashSet<u32>),
}

impl AppScope {
    pub fn parse(mode: &str, uids: &[u32]) -> Self {
        let set: HashSet<u32> = uids.iter().copied().collect();
        if set.is_empty() {
            return AppScope::All;
        }
        match mode.trim().to_ascii_lowercase().as_str() {
            "allow" | "only" => AppScope::Allow(set),
            "deny" | "skip" | "bypass" => AppScope::Deny(set),
            _ => AppScope::All,
        }
    }

    pub fn allows(&self, uid: Option<u32>) -> bool {
        match self {
            AppScope::All => true,
            AppScope::Allow(set) => uid.is_some_and(|u| set.contains(&u)),
            AppScope::Deny(set) => uid.is_none_or(|u| !set.contains(&u)),
        }
    }

    pub fn is_all(&self) -> bool {
        matches!(self, AppScope::All)
    }

    pub fn mode_name(&self) -> &'static str {
        match self {
            AppScope::All => "all",
            AppScope::Allow(_) => "allow",
            AppScope::Deny(_) => "deny",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RewriteAction {
    Reject,
    Reject200,
    RejectTinyGif,
    Body,
    Header,
}

impl RewriteAction {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "reject" | "reject-drop" => Some(Self::Reject),
            "reject-200" => Some(Self::Reject200),
            "reject-tinygif" | "reject-img" => Some(Self::RejectTinyGif),
            "body" => Some(Self::Body),
            "header" => Some(Self::Header),
            _ => None,
        }
    }
}

pub struct RewriteRule {
    pub url: Regex,
    pub action: RewriteAction,
    pub body: Option<regex::bytes::Regex>,
    pub replacement: String,
    pub header_field: String,
}

/// hostname 匹配器：精确集合 + 后缀列表。
pub struct HostMatcher {
    exact: HashSet<String>,
    suffix: Vec<String>,
    /// 中段通配（m*.maps.example.com / img*.shop.example.com）：按 glob 整串锚定，
    /// `*` 匹配任意串、`?` 匹配单字符，避免后缀伪装误命中。
    globs: Vec<regex::Regex>,
}

impl HostMatcher {
    pub fn new(patterns: &[String]) -> Self {
        let mut exact = HashSet::new();
        let mut suffix = Vec::new();
        let mut globs = Vec::new();
        for p in patterns {
            let p = p.trim().trim_end_matches('.').to_ascii_lowercase();
            if p.is_empty() {
                continue;
            }
            if let Some(s) = p.strip_prefix("*.") {
                if !s.is_empty() {
                    suffix.push(s.to_string());
                }
            } else if p.contains('*') || p.contains('?') {
                let mut re = String::from("^");
                for c in p.chars() {
                    match c {
                        '*' => re.push_str(".*"),
                        '?' => re.push('.'),
                        _ => re.push_str(&regex::escape(&c.to_string())),
                    }
                }
                re.push('$');
                if let Ok(r) = regex::Regex::new(&re) {
                    globs.push(r);
                }
            } else {
                exact.insert(p);
            }
        }
        Self { exact, suffix, globs }
    }

    pub fn matches(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if self.exact.contains(&h) {
            return true;
        }
        for s in &self.suffix {
            // 热路径不分配：h == s，或去掉 s 后的前缀以 '.' 结尾。
            if h == *s
                || h.strip_suffix(s.as_str())
                    .map(|prefix| prefix.ends_with('.'))
                    .unwrap_or(false)
            {
                return true;
            }
        }
        if self.globs.iter().any(|g| g.is_match(&h)) {
            return true;
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffix.is_empty() && self.globs.is_empty()
    }
}

pub struct MitmEngine {
    pub enabled: bool,
    pub hosts: HostMatcher,
    pub skip: HostMatcher,
    pub rules: Vec<RewriteRule>,
    /// Loon [Rewrite] 规则（与 Surge [URL Rewrite] 分开，避免语法互相推导）。
    pub loon_rules: Vec<LoonRule>,
    pub loon_unsupported: Vec<String>,
    /// 脚本规则（QuickJS）。脚本执行失败只回退该脚本，不影响隧道。
    pub scripts: ScriptEngine,
    pub body_limit: usize,
    pub upstream_insecure: bool,
    /// 该配置对哪些应用生效；all 时与旧行为完全一致。
    pub app_scope: AppScope,
    /// 编译失败被跳过的规则数（模块预览/日志用）。
    pub skipped_rules: usize,
    fail_open_ttl: Duration,
    bypass: Mutex<HashMap<String, Instant>>,
}

impl MitmEngine {
    pub fn from_config(cfg: &MitmConfig) -> Self {
        let mut rules = Vec::new();
        let mut skipped = 0usize;
        // 兼容 1.33 壳层的原始规则行：拼成模块文本后复用同一套 Surge 解析器。
        let mut source_rules = cfg.rules.clone();
        let mut extra_loon: Vec<String> = Vec::new();
        if !cfg.url_rewrites.is_empty() || !cfg.header_rewrites.is_empty() {
            let mut module = String::new();
            if !cfg.url_rewrites.is_empty() {
                module.push_str("[URL Rewrite]\n");
                for line in &cfg.url_rewrites {
                    module.push_str(line);
                    module.push('\n');
                }
            }
            if !cfg.header_rewrites.is_empty() {
                module.push_str("[Header Rewrite]\n");
                for line in &cfg.header_rewrites {
                    module.push_str(line);
                    module.push('\n');
                }
            }
            let surge = parse_surge_module(&module);
            source_rules.extend(surge.rules);
            // 302/307/3 段 header/mock 翻译成了 Loon 行，跟 cfg.loon_rewrites 合并解析。
            extra_loon = surge.loon;
        }
        for r in &source_rules {
            let Some(action) = RewriteAction::parse(&r.action) else {
                skipped += 1;
                continue;
            };
            let Ok(url) = Regex::new(&r.pattern) else {
                skipped += 1;
                continue;
            };
            let body = if action == RewriteAction::Body {
                let pat = if r.body_pattern.trim().is_empty() {
                    "(?s)^.*$"
                } else {
                    &r.body_pattern
                };
                match regex::bytes::Regex::new(pat) {
                    Ok(b) => Some(b),
                    Err(_) => {
                        skipped += 1;
                        continue;
                    }
                }
            } else {
                None
            };
            if action == RewriteAction::Header && r.header_field.trim().is_empty() {
                skipped += 1;
                continue;
            }
            rules.push(RewriteRule {
                url,
                action,
                body,
                replacement: r.replacement.clone(),
                header_field: r.header_field.trim().to_string(),
            });
        }
        let mut loon_lines = cfg.loon_rewrites.clone();
        loon_lines.extend(extra_loon);
        let loon = crate::mitm::loon::parse_loon_rewrites(&loon_lines);
        let scripts = ScriptEngine::from_config(&cfg.scripts, &cfg.script_store_file);
        Self {
            enabled: cfg.enabled,
            hosts: HostMatcher::new(&cfg.hostnames),
            skip: HostMatcher::new(&cfg.skip),
            rules,
            loon_rules: loon.rules,
            loon_unsupported: loon.unsupported,
            scripts,
            body_limit: cfg.body_limit.max(4096),
            upstream_insecure: cfg.upstream_insecure,
            skipped_rules: skipped,
            fail_open_ttl: Duration::from_secs(cfg.fail_open_ttl.max(1)),
            app_scope: AppScope::parse(&cfg.app_mode, &cfg.app_uids),
            bypass: Mutex::new(HashMap::new()),
        }
    }

    /// 是否应该对该域名做 MITM（启用 + 命中列表 + 未跳过 + 未在放行期）。
    /// 归属未知（如 UDP/QUIC 拿不到 socket 表）时按 [AppScope] 的保守分支处理。
    pub fn should_mitm(&self, host: &str) -> bool {
        self.should_mitm_uid(host, None)
    }

    /// 带 App 归属的判定：先过 App 范围，再过域名规则。
    pub fn should_mitm_uid(&self, host: &str, uid: Option<u32>) -> bool {
        self.app_scope.allows(uid) && self.should_mitm_host(host)
    }

    /// App 范围是否放行该 UID（不做域名判定，供壳层统计“因按 App 跳过”）。
    pub fn app_allows(&self, uid: Option<u32>) -> bool {
        self.app_scope.allows(uid)
    }

    fn should_mitm_host(&self, host: &str) -> bool {
        if !self.enabled || self.hosts.is_empty() || self.skip.matches(host) {
            return false;
        }
        if !self.hosts.matches(host) {
            return false;
        }
        let mut g = match self.bypass.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(until) = g.get(&host.to_ascii_lowercase()) {
            if Instant::now() < *until {
                return false;
            }
            g.remove(&host.to_ascii_lowercase());
        }
        true
    }

    /// TLS 握手失败（cert pinning / 只支持 h2 等）：临时放行，App 重试即恢复透明转发。
    pub fn mark_bypass(&self, host: &str) {
        let mut g = match self.bypass.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        g.retain(|_, until| *until > now);
        g.insert(host.to_ascii_lowercase(), now + self.fail_open_ttl);
    }

    /// 命中该 URL 的全部规则（reject 优先判断，body 可叠加）。
    pub fn rules_for(&self, url: &str) -> Vec<&RewriteRule> {
        self.rules.iter().filter(|r| r.url.is_match(url)).collect()
    }

    /// 命中该 URL 的 Loon 规则；按声明顺序执行，不把 Surge 规则混进来。
    pub fn loon_rules_for(&self, url: &str) -> Vec<&LoonRule> {
        self.loon_rules.iter().filter(|r| r.url.is_match(url)).collect()
    }
}

/// 按上限执行一次正则替换；返回 None 表示结果会超过 limit。
fn replace_limited(
    re: &regex::bytes::Regex,
    input: &[u8],
    replacement: &[u8],
    limit: usize,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut last = 0usize;
    for caps in re.captures_iter(input) {
        let Some(m) = caps.get(0) else { continue };
        let gap = &input[last..m.start()];
        if out.len().saturating_add(gap.len()) > limit {
            return None;
        }
        out.extend_from_slice(gap);
        let mut repl = Vec::new();
        caps.expand(replacement, &mut repl);
        if out.len().saturating_add(repl.len()) > limit {
            return None;
        }
        out.extend_from_slice(&repl);
        last = m.end();
    }
    let tail = &input[last..];
    if out.len().saturating_add(tail.len()) > limit {
        return None;
    }
    out.extend_from_slice(tail);
    Some(out)
}

/// 按顺序应用全部 body 改写规则；输出超过 limit 时返回 None，调用方应原样透传。
pub fn apply_body_rules_limited(
    body: &[u8],
    rules: &[&RewriteRule],
    limit: usize,
) -> Option<(Vec<u8>, bool)> {
    let mut cur = body.to_vec();
    let mut changed = false;
    for r in rules {
        if r.action != RewriteAction::Body {
            continue;
        }
        if let Some(re) = &r.body {
            let out = replace_limited(re, &cur, r.replacement.as_bytes(), limit)?;
            if out.as_slice() != cur.as_slice() {
                changed = true;
            }
            cur = out;
        }
    }
    Some((cur, changed))
}

/// 按顺序应用全部 body 改写规则。
pub fn apply_body_rules(body: &[u8], rules: &[&RewriteRule]) -> (Vec<u8>, bool) {
    let mut cur = body.to_vec();
    let mut changed = false;
    for r in rules {
        if r.action != RewriteAction::Body {
            continue;
        }
        if let Some(re) = &r.body {
            let out = re.replace_all(&cur, r.replacement.as_bytes());
            if out.as_ref() != cur.as_slice() {
                changed = true;
            }
            cur = out.into_owned();
        }
    }
    (cur, changed)
}

// ---------------- Surge 模块文本解析 ----------------

pub struct SurgeMitm {
    pub hostnames: Vec<String>,
    pub rules: Vec<MitmRuleConf>,
    /// Surge [URL Rewrite] 里 302/307/3 段 header/mock 的等价 Loon 行。
    /// 这些动作在 Surge 语义里没有对应的 RewriteAction，但 Loon 执行器已实现，
    /// 翻译后交给同一个执行器，避免两套实现漂移。
    pub loon: Vec<String>,
    pub ignored: usize,
}

/// 引号感知的分词：Surge 规则里带空格的正则/替换串用双引号包裹。
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut in_q = false;
    let mut esc = false;
    for c in line.chars() {
        if esc {
            // 引号内只把 \" 和 \\ 当转义；正则里的 \[ \] 必须留给 regex 引擎。
            if c != '"' && c != '\\' {
                cur.push('\\');
            }
            cur.push(c);
            esc = false;
            continue;
        }
        match c {
            '\\' if in_q => {
                esc = true;
                has = true;
            }
            '"' => {
                in_q = !in_q;
                has = true;
            }
            c if c.is_whitespace() && !in_q => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        out.push(cur);
    }
    out
}

fn valid_host_pattern(p: &str) -> bool {
    let body = p.strip_prefix("*.").unwrap_or(p);
    !body.is_empty()
        && body.len() <= 253
        && body.contains('.')
        && !body.contains(['/', ':', ' '])
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// 把 Surge [URL Rewrite] 里 Loon 已支持、Surge 侧没有 RewriteAction 的动作翻译成 Loon 行。
///
/// - `^url https://new 302|307` → 原样交给 Loon（redirect）
/// - `^url https://new header`（3 段）→ Loon `url new header`（URL 替换）
/// - `^url mock|mock-request-body|mock-response-body <body>` → Loon mock 参数形式
/// 已经是 Loon 参数形式（第三段带 `=`）时原样透传，避免二次包装。
fn surge_rewrite_to_loon(t: &[String], _last: &str, raw: &str) -> Option<String> {
    if t.len() < 3 {
        return None;
    }
    // Surge 的动作在 t[1]（mock 的 body 在 t[2..]），302/307/header 则在 t[2]。
    let action = t[1].to_ascii_lowercase();
    // 302/307、3 段 header：动作在末位（`url new-url 302`）。
    if t.len() == 3 {
        let tail = t[2].to_ascii_lowercase();
        if tail == "302" || tail == "307" {
            return Some(format!("{} {} {}", t[0], t[1], tail));
        }
        if tail == "header" {
            return Some(format!("{} {} header", t[0], t[1]));
        }
    }
    // mock 族：动作在 t[1]，body 在 t[2..]。
    if !matches!(action.as_str(), "mock" | "mock-request-body" | "mock-response-body") {
        return None;
    }
    let dir = if action == "mock-request-body" {
        "mock-request-body"
    } else {
        "mock-response-body"
    };
    // 已经是 Loon 的 `data-type=json data="..."` 写法，直接透传整行。
    if t[2].contains('=') {
        return Some(raw.trim().to_string());
    }
    // body 必须从原始行截取：tokenize 会把 JSON 里的引号当字符串边界剥掉，
    // `mock {"code":0}` 重建成 `{code:0}` 后返回给 App 就不是合法 JSON。
    let lower = raw.to_ascii_lowercase();
    let body = match lower.rfind(action.as_str()) {
        Some(pos) => raw[pos + action.len()..].trim().to_string(),
        None => t[2..].join(" "),
    };
    let trimmed = body.trim_start();
    let data_type = if trimmed.starts_with('{') || trimmed.starts_with('[') {
        "json"
    } else {
        "text"
    };
    let escaped = body.replace('\\', "\\\\").replace('"', "\\\"");
    Some(format!("{} {} data-type={} data=\"{}\"", t[0], dir, data_type, escaped))
}

/// 解析 .sgmodule 中的 [MITM] / [URL Rewrite] / [Header Rewrite] 段。
/// 其余段由调用方（DNS 规则解析）处理；这里只统计本能力范围内的不支持行。
pub fn parse_surge_module(text: &str) -> SurgeMitm {
    let mut hostnames: Vec<String> = Vec::new();
    let mut rules: Vec<MitmRuleConf> = Vec::new();
    let mut loon: Vec<String> = Vec::new();
    let mut ignored = 0usize;
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        match section.as_str() {
            "mitm" => {
                let value = match line.split_once('=') {
                    Some((k, v)) if k.trim().eq_ignore_ascii_case("hostname") => v,
                    // 宽容：裸域名行也按 hostname 处理
                    _ => line,
                };
                for part in value.split(',') {
                    let p = part.trim().trim_end_matches('.').to_ascii_lowercase();
                    if p.is_empty() {
                        continue;
                    }
                    if valid_host_pattern(&p) {
                        hostnames.push(p);
                    } else {
                        ignored += 1;
                    }
                }
            }
            "url rewrite" => {
                let t = tokenize(line);
                if t.len() < 2 {
                    ignored += 1;
                    continue;
                }
                let last = t[t.len() - 1].to_ascii_lowercase();
                // 先走 Surge→Loon 翻译：302/307、3 段 header、mock 在 Surge 里
                // 没有对应的 RewriteAction，硬塞进 reject/body/header 会静默丢规则。
                if let Some(line2) = surge_rewrite_to_loon(&t, &last, line) {
                    loon.push(line2);
                    continue;
                }
                if let Some(action) = RewriteAction::parse(&last) {
                    match action {
                        RewriteAction::Reject | RewriteAction::Reject200 | RewriteAction::RejectTinyGif => {
                            rules.push(MitmRuleConf {
                                pattern: t[0].clone(),
                                action: last.clone(),
                                body_pattern: String::new(),
                                replacement: String::new(),
                                header_field: String::new(),
                                source: None,
                            });
                        }
                        RewriteAction::Body => {
                            // Surge 标准 4 段：url body-regex replacement body
                            // 宽容 3 段：url replacement body（整体替换）
                            let (bp, rep) = match t.len() {
                                4 => (t[1].clone(), t[2].clone()),
                                3 => (String::new(), t[1].clone()),
                                _ => {
                                    ignored += 1;
                                    continue;
                                }
                            };
                            rules.push(MitmRuleConf {
                                pattern: t[0].clone(),
                                action: "body".into(),
                                body_pattern: bp,
                                replacement: rep,
                                header_field: String::new(),
                                source: None,
                            });
                        }
                        RewriteAction::Header => {
                            // url field value header
                            if t.len() == 4 {
                                rules.push(MitmRuleConf {
                                    pattern: t[0].clone(),
                                    action: "header".into(),
                                    body_pattern: String::new(),
                                    replacement: t[2].clone(),
                                    header_field: t[1].clone(),
                                    source: None,
                                });
                            } else {
                                ignored += 1;
                            }
                        }
                    }
                } else {
                    // 302/307/transparent/mock 等：去广告用不到，计入不支持
                    ignored += 1;
                }
            }
            "header rewrite" => {
                let t = tokenize(line);
                // url header-replace|header-add field value
                if t.len() == 4
                    && matches!(t[1].to_ascii_lowercase().as_str(), "header-replace" | "header-add")
                {
                    rules.push(MitmRuleConf {
                        pattern: t[0].clone(),
                        action: "header".into(),
                        body_pattern: String::new(),
                        replacement: t[3].clone(),
                        header_field: t[2].clone(),
                        source: None,
                    });
                } else {
                    ignored += 1;
                }
            }
            _ => {}
        }
    }
    hostnames.sort();
    hostnames.dedup();
    SurgeMitm { hostnames, rules, loon, ignored }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(pattern: &str, action: &str) -> MitmRuleConf {
        MitmRuleConf {
            pattern: pattern.into(),
            action: action.into(),
            body_pattern: String::new(),
            replacement: String::new(),
            header_field: String::new(),
            source: None,
        }
    }

    #[test]
    fn surge_302_header_mock_translate_to_loon() {
        let p = parse_surge_module(
            "[URL Rewrite]\n\
             ^https://api.a.com/v1 https://api.b.com/v1 302\n\
             ^https://api.a.com/old https://api.a.com/new header\n\
             ^https://api.a.com/ad mock {\"code\":0}\n\
             ^https://api.a.com/r mock-request-body data-type=json data=\"{}\"",
        );
        assert_eq!(p.loon.len(), 4, "{:?}", p.loon);
        let set = crate::mitm::loon::parse_loon_rewrites(&p.loon);
        assert_eq!(set.rules.len(), 4, "unsupported={:?}", set.unsupported);
        assert!(matches!(
            set.rules[0].action,
            crate::mitm::loon::LoonAction::Redirect { status: 302, .. }
        ));
        assert!(matches!(set.rules[1].action, crate::mitm::loon::LoonAction::UrlReplace(_)));
        match &set.rules[2].action {
            crate::mitm::loon::LoonAction::ResponseMock(m) => {
                assert_eq!(m.body, b"{\"code\":0}".to_vec());
            }
            other => panic!("期望响应 mock，实际 {:?}", other),
        }
        assert!(matches!(
            set.rules[3].action,
            crate::mitm::loon::LoonAction::RequestMock(_)
        ));
    }

    #[test]
    fn host_matcher_wildcard_and_exact() {
        let m = HostMatcher::new(&["*.example.com".into(), "api.foo.cn".into()]);
        assert!(m.matches("example.com"));
        assert!(m.matches("a.example.com"));
        assert!(m.matches("A.B.Example.Com"));
        assert!(!m.matches("notexample.com"));
        assert!(!m.matches("example.com.evil.cn"));
        assert!(m.matches("api.foo.cn"));
        assert!(!m.matches("x.api.foo.cn")); // 裸域名只精确匹配
    }

    #[test]
    fn engine_reject_and_bypass() {
        let cfg = MitmConfig {
            enabled: true,
            hostnames: vec!["*.ads.com".into()],
            rules: vec![conf(r"^https://.*\.ads\.com/ad", "reject")],
            fail_open_ttl: 300,
            ..Default::default()
        };
        let e = MitmEngine::from_config(&cfg);
        assert!(e.should_mitm("x.ads.com"));
        let hits = e.rules_for("https://x.ads.com/ad?id=1");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].action, RewriteAction::Reject);
        assert!(e.rules_for("https://x.ads.com/content").is_empty());
        // 握手失败 → 临时放行
        e.mark_bypass("x.ads.com");
        assert!(!e.should_mitm("x.ads.com"));
        assert!(e.should_mitm("y.ads.com"));
    }

    fn app_conf(mode: &str, uids: &[u32]) -> MitmConfig {
        MitmConfig {
            enabled: true,
            hostnames: vec!["*.ads.com".into()],
            app_mode: mode.into(),
            app_uids: uids.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn app_scope_allow_only_selected_uid() {
        let e = MitmEngine::from_config(&app_conf("allow", &[10086]));
        assert!(e.should_mitm_uid("x.ads.com", Some(10086)));
        assert!(!e.should_mitm_uid("x.ads.com", Some(10010)));
        // 归属未知时不解密：宁可漏抓，不可误解银行/支付。
        assert!(!e.should_mitm_uid("x.ads.com", None));

    }

    #[test]
    fn app_scope_deny_skips_selected_uid() {
        let e = MitmEngine::from_config(&app_conf("deny", &[10086]));
        // 银行/支付在这份名单里：无论域名是否命中都不解密。
        assert!(!e.should_mitm_uid("x.ads.com", Some(10086)));
        assert!(e.should_mitm_uid("x.ads.com", Some(10010)));
        // 未知归属保持旧行为（照常解密），否则等于把全局 MITM 悄悄关掉。
        assert!(e.should_mitm_uid("x.ads.com", None));
    }

    #[test]
    fn app_scope_all_and_empty_fall_back_to_global() {
        let all = MitmEngine::from_config(&app_conf("all", &[1, 2]));
        assert!(all.should_mitm_uid("x.ads.com", None));
        assert!(all.should_mitm_uid("x.ads.com", Some(999)));
        // 模式写 allow 但列表为空：退化为全局，避免一条规则配错就静默全关。
        let empty = MitmEngine::from_config(&app_conf("allow", &[]));
        assert!(empty.should_mitm_uid("x.ads.com", None));
        assert!(empty.should_mitm_uid("x.ads.com", Some(7)));
        assert_eq!(empty.app_scope.mode_name(), "all");
    }

    #[test]
    fn app_scope_keeps_domain_skip_priority() {
        let mut cfg = app_conf("deny", &[10086]);
        cfg.skip = vec!["pin.ads.com".into()];
        let e = MitmEngine::from_config(&cfg);
        assert!(!e.should_mitm_uid("pin.ads.com", Some(10010)));
        assert!(e.should_mitm_uid("x.ads.com", Some(10010)));
    }

    #[test]
    fn engine_disabled_or_skip() {
        let cfg = MitmConfig {
            enabled: false,
            hostnames: vec!["*.ads.com".into()],
            ..Default::default()
        };
        assert!(!MitmEngine::from_config(&cfg).should_mitm("x.ads.com"));
        let cfg = MitmConfig {
            enabled: true,
            hostnames: vec!["*.ads.com".into()],
            skip: vec!["pin.ads.com".into()],
            ..Default::default()
        };
        let e = MitmEngine::from_config(&cfg);
        assert!(!e.should_mitm("pin.ads.com"));
        assert!(e.should_mitm("x.ads.com"));
    }

    #[test]
    fn body_rewrite_json_ads() {
        let mut r = conf(r"^https://api\.x\.com/feed", "body");
        r.body_pattern = r#""ad_items":\[[^\]]*\],"#.into();
        r.replacement = String::new();
        let cfg = MitmConfig {
            enabled: true,
            hostnames: vec!["api.x.com".into()],
            rules: vec![r],
            ..Default::default()
        };
        let e = MitmEngine::from_config(&cfg);
        let hits = e.rules_for("https://api.x.com/feed?page=1");
        let body = br#"{"items":[1,2],"ad_items":[{"id":9}],"tail":1}"#;
        let (out, changed) = apply_body_rules(body, &hits);
        assert!(changed);
        assert_eq!(out, br#"{"items":[1,2],"tail":1}"#);
    }

    #[test]
    fn body_rewrite_limit_returns_none() {
        let mut r = conf("^https://api.x.com/feed", "body");
        r.replacement = "A".repeat(64);
        let cfg = MitmConfig {
            enabled: true,
            hostnames: vec!["api.x.com".into()],
            rules: vec![r],
            ..Default::default()
        };
        let e = MitmEngine::from_config(&cfg);
        let hits = e.rules_for("https://api.x.com/feed");
        assert!(apply_body_rules_limited(b"small", &hits, 16).is_none());
    }

    #[test]
    fn invalid_regex_skipped_not_fatal() {
        let cfg = MitmConfig {
            enabled: true,
            hostnames: vec!["x.com".into()],
            rules: vec![conf("(unclosed", "reject"), conf("^https://x.com/ok", "reject")],
            ..Default::default()
        };
        let e = MitmEngine::from_config(&cfg);
        assert_eq!(e.skipped_rules, 1);
        assert_eq!(e.rules.len(), 1);
    }

    #[test]
    fn surge_module_parse() {
        let text = r#"#!name=测试模块
[MITM]
hostname = *.example.com, api.foo.cn

[URL Rewrite]
^https://api\.foo\.cn/ad reject
^https://api\.foo\.cn/splash reject-tinygif
^https://api\.foo\.cn/feed "(?s)\"ads\":\[.*?\]," "" body
^https://api\.foo\.cn/req User-Agent "MyApp/1.0" header
^https://api\.foo\.cn/x https://elsewhere 302

[Header Rewrite]
^https://api\.foo\.cn/h header-replace X-Token abc

[Rule]
DOMAIN-SUFFIX,ads.example.com,REJECT
"#;
        let p = parse_surge_module(text);
        assert_eq!(p.hostnames, vec!["*.example.com".to_string(), "api.foo.cn".to_string()]);
        assert_eq!(p.rules.len(), 5);
        // 302 现在翻译成 Loon redirect，不再计入不支持
        assert_eq!(p.ignored, 0);
        assert_eq!(p.loon.len(), 1);
        assert!(p.loon[0].ends_with(" 302"));
        assert_eq!(p.rules[0].action, "reject");
        assert_eq!(p.rules[2].action, "body");
        assert_eq!(p.rules[2].replacement, "");
        assert_eq!(p.rules[3].header_field, "User-Agent");
        assert_eq!(p.rules[4].header_field, "X-Token");
        assert_eq!(p.rules[4].replacement, "abc");
        // 解析结果能直接编译成引擎
        let cfg = MitmConfig {
            enabled: true,
            hostnames: p.hostnames,
            rules: p.rules,
            ..Default::default()
        };
        let e = MitmEngine::from_config(&cfg);
        assert_eq!(e.skipped_rules, 0);
        assert_eq!(e.rules.len(), 5);
    }

    #[test]
    fn tokenize_quoted_spaces() {
        let t = tokenize(r#"^https://x/a "has space" "rep \"q\"" body"#);
        assert_eq!(t.len(), 4);
        assert_eq!(t[1], "has space");
        assert_eq!(t[2], "rep \"q\"");
    }

    #[test]
    fn accepts_shell_m1_raw_lines_and_skip_alias() {
        // 1.33 壳层（M1）下发的 JSON：mitm 分区只有 enabled/hostnames/skip_hostnames/
        // url_rewrites/header_rewrites，没有结构化 rules；内核必须自行解析。
        let json = r#"{
            "enabled": true,
            "hostnames": ["*.ads.com"],
            "skip_hostnames": ["bank.example.com"],
            "url_rewrites": ["^https://x\\.ads\\.com/ad reject"],
            "header_rewrites": ["^https://x\\.ads\\.com/api header-replace User-Agent Namu"]
        }"#;
        let cfg: MitmConfig = serde_json::from_str(json).expect("M1 配置应能反序列化");
        assert_eq!(cfg.skip, vec!["bank.example.com".to_string()]);
        let engine = MitmEngine::from_config(&cfg);
        assert_eq!(engine.rules_for("https://x.ads.com/ad").len(), 1);
        assert_eq!(engine.rules_for("https://x.ads.com/api").len(), 1);
        assert!(engine.should_mitm("x.ads.com"));
        assert!(!engine.should_mitm("bank.example.com"));
    }
}
