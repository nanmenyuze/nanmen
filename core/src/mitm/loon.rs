//! Loon `[Rewrite]` 解析与执行。
//!
//! 同时支持两条语法线：
//! - 旧版（Loon 3.5.1 之前）：`^https://... header-add X Y` 这种空格分隔写法；
//! - 新版：`request if ${url} ~= /regex/i then request.header.add("X", "Y")`。
//!
//! 这里刻意不做“看起来像就执行”的猜测：无法安全实现的 jq、data-path 文件、
//! 脚本、复杂条件会进入 `unsupported`，由界面展示成功能缺口。

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoonPhase {
    Request,
    Response,
}

#[derive(Debug, Clone)]
pub enum RejectKind {
    Drop,
    Status200,
    TinyGif,
    JsonObject,
    JsonArray,
}

#[derive(Debug, Clone)]
pub enum HeaderOp {
    Add { name: String, value: String },
    Del { name: String },
    Replace { name: String, value: String },
    ReplaceRegex { name: String, re: Regex, replacement: String },
}

#[derive(Debug, Clone)]
pub enum JsonKind {
    Add,
    Replace,
    Delete,
}

#[derive(Debug, Clone)]
pub struct JsonOp {
    pub kind: JsonKind,
    pub path: String,
    /// add/replace 的 JSON/字面量值；delete 为 None。
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub enum BodyOp {
    ReplaceRegex { re: regex::bytes::Regex, replacement: String },
    Json(JsonOp),
}

#[derive(Debug, Clone)]
pub struct MockSpec {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum LoonAction {
    UrlReplace(String),
    Redirect { status: u16, url: String },
    Reject(RejectKind),
    RequestHeader(HeaderOp),
    ResponseHeader(HeaderOp),
    RequestBody(BodyOp),
    ResponseBody(BodyOp),
    RequestMock(MockSpec),
    ResponseMock(MockSpec),
}

/// Loon 新版 `request/response if ...` 的条件树。
/// 旧语法规则的条件为 None，行为与原来完全一致。
#[derive(Debug, Clone)]
pub enum LoonCond {
    /// `${url} ~= /re/`
    Url(Regex),
    /// `${request.header['X']} == value`；None 表示与 null 比较（头不存在）
    HeaderEq { name: String, value: Option<String> },
    /// `${request.header['X']} ~= /re/`
    HeaderRegex { name: String, re: Regex },
    /// 参数展开后的布尔常量（`${enabled} == true` → `true == true`）
    Bool(bool),
    And(Vec<LoonCond>),
    Or(Vec<LoonCond>),
    Not(Box<LoonCond>),
}

impl LoonCond {
    pub fn matches(&self, url: &str, headers: &[(String, String)]) -> bool {
        match self {
            LoonCond::Url(re) => re.is_match(url),
            LoonCond::HeaderEq { name, value } => {
                let got = header_values(headers, name);
                match value {
                    None => got.is_empty(),
                    Some(v) => got.iter().any(|g| g == v),
                }
            }
            LoonCond::HeaderRegex { name, re } => {
                header_values(headers, name).iter().any(|g| re.is_match(g))
            }
            LoonCond::Bool(b) => *b,
            LoonCond::And(v) => v.iter().all(|c| c.matches(url, headers)),
            LoonCond::Or(v) => v.iter().any(|c| c.matches(url, headers)),
            LoonCond::Not(c) => !c.matches(url, headers),
        }
    }

    /// 预筛 URL 正则：And 取任一 URL 条件（都命中才真匹配），Or 取并集，
    /// 其余没有 URL 条件时用 `.*`，由条件树在求值时兜底。
    fn prefilter(&self) -> Option<String> {
        match self {
            LoonCond::Url(re) => Some(re.as_str().to_string()),
            LoonCond::And(v) => v.iter().filter_map(|c| c.prefilter()).next(),
            LoonCond::Or(v) => {
                // 任一分支没有 URL 条件（如纯 header/参数条件）时可匹配任意 URL，
                // 预筛必须放宽到 .*，否则会把该分支整体漏掉。
                let mut parts = Vec::new();
                for c in v {
                    match c.prefilter() {
                        Some(p) => parts.push(p),
                        None => return None,
                    }
                }
                if parts.is_empty() { None } else { Some(format!("(?:{})", parts.join(")|(?:"))) }
            }
            LoonCond::Not(_) | LoonCond::Bool(_) | LoonCond::HeaderEq { .. } | LoonCond::HeaderRegex { .. } => None,
        }
    }
}

fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

#[derive(Debug, Clone)]
pub struct LoonRule {
    pub phase: LoonPhase,
    /// 预筛 URL 正则；复合条件还会在 plan 阶段用 [LoonCond] 精确求值。
    pub url: Regex,
    pub cond: Option<LoonCond>,
    pub action: LoonAction,
    pub raw: String,
}

impl LoonRule {
    pub fn applies(&self, url: &str, headers: &[(String, String)]) -> bool {
        self.url.is_match(url)
            && self.cond.as_ref().map(|c| c.matches(url, headers)).unwrap_or(true)
    }
}

#[derive(Debug, Default)]
pub struct LoonSet {
    pub rules: Vec<LoonRule>,
    pub unsupported: Vec<String>,
}

/// 与 http1::tokenize 同样的引号感知分词；这里复制一份避免模块反向依赖。
pub fn tokenize(line: &str) -> Vec<String> {
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

fn ctype_for(data_type: &str) -> String {
    match data_type.to_ascii_lowercase().as_str() {
        "json" => "application/json",
        "text" | "plain" => "text/plain",
        "html" => "text/html",
        "css" => "text/css",
        "javascript" | "js" => "application/javascript",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "gif" => "image/gif",
        "jpeg" | "jpg" => "image/jpeg",
        "tiff" => "image/tiff",
        "mp4" => "video/mp4",
        "text-event-stream" => "text/event-stream",
        "form-data" => "multipart/form-data",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn rejects(action: &str) -> Option<RejectKind> {
    match action {
        "reject" | "reject-drop" => Some(RejectKind::Drop),
        "reject-200" => Some(RejectKind::Status200),
        "reject-img" | "reject-tinygif" => Some(RejectKind::TinyGif),
        "reject-dict" => Some(RejectKind::JsonObject),
        "reject-array" => Some(RejectKind::JsonArray),
        _ => None,
    }
}

fn parse_mock(tokens: &[String], response: bool) -> Option<MockSpec> {
    let mut data_type = "text".to_string();
    let mut data = String::new();
    let mut status = 200u16;
    let mut base64_data = false;
    let mut has_data = false;
    let mut unsupported_file = false;
    for t in tokens {
        let Some((k, v)) = t.split_once('=') else { continue };
        match k.to_ascii_lowercase().as_str() {
            "data-type" => data_type = v.trim_matches('"').to_string(),
            "data" => {
                data = v.trim_matches('"').to_string();
                has_data = true;
            }
            "status-code" if response => status = v.parse().unwrap_or(200),
            "mock-data-is-base64" => base64_data = v.eq_ignore_ascii_case("true"),
            "data-path" => unsupported_file = true,
            _ => {}
        }
    }
    if unsupported_file || !has_data {
        return None;
    }
    let body = if base64_data {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(data.as_bytes()).ok()?
    } else {
        data.into_bytes()
    };
    Some(MockSpec { status, content_type: ctype_for(&data_type), body })
}

fn header_ops(action: &str, params: &[String]) -> Option<(bool, Vec<HeaderOp>)> {
    let response = action.starts_with("response-");
    let is_request = action.starts_with("request-") || !response;
    let base = action
        .strip_prefix("request-")
        .or_else(|| action.strip_prefix("response-"))
        .unwrap_or(action);
    let mut out = Vec::new();
    match base {
        "header-add" => {
            if params.len() < 2 || params.len() % 2 != 0 {
                return None;
            }
            for pair in params.chunks(2) {
                out.push(HeaderOp::Add { name: pair[0].clone(), value: pair[1].clone() });
            }
        }
        "header-del" => {
            if params.is_empty() {
                return None;
            }
            for name in params {
                out.push(HeaderOp::Del { name: name.clone() });
            }
        }
        "header-replace" => {
            if params.len() < 2 || params.len() % 2 != 0 {
                return None;
            }
            for pair in params.chunks(2) {
                out.push(HeaderOp::Replace { name: pair[0].clone(), value: pair[1].clone() });
            }
        }
        "header-replace-regex" => {
            if params.len() < 3 || params.len() % 3 != 0 {
                return None;
            }
            for triple in params.chunks(3) {
                let re = Regex::new(&triple[1]).ok()?;
                out.push(HeaderOp::ReplaceRegex {
                    name: triple[0].clone(),
                    re,
                    replacement: triple[2].clone(),
                });
            }
        }
        _ => return None,
    }
    Some((is_request, out))
}

fn body_ops(action: &str, params: &[String]) -> Option<(bool, Vec<BodyOp>)> {
    let response = action.starts_with("response-");
    let is_request = action.starts_with("request-") || !response;
    let base = action
        .strip_prefix("request-")
        .or_else(|| action.strip_prefix("response-"))
        .unwrap_or(action);
    let mut out = Vec::new();
    match base {
        "body-replace-regex" => {
            if params.len() < 2 || params.len() % 2 != 0 {
                return None;
            }
            for pair in params.chunks(2) {
                let re = regex::bytes::Regex::new(&pair[0]).ok()?;
                out.push(BodyOp::ReplaceRegex { re, replacement: pair[1].clone() });
            }
        }
        "body-json-add" | "body-json-replace" => {
            if params.len() < 2 || params.len() % 2 != 0 {
                return None;
            }
            let kind = if base.ends_with("add") { JsonKind::Add } else { JsonKind::Replace };
            for pair in params.chunks(2) {
                out.push(BodyOp::Json(JsonOp {
                    kind: kind.clone(),
                    path: pair[0].clone(),
                    value: Some(pair[1].clone()),
                }));
            }
        }
        "body-json-del" | "body-json-delete" => {
            if params.is_empty() {
                return None;
            }
            for path in params {
                out.push(BodyOp::Json(JsonOp { kind: JsonKind::Delete, path: path.clone(), value: None }));
            }
        }
        _ => return None,
    }
    Some((is_request, out))
}

/// 解析一条旧版 `[Rewrite]` 行。
///
/// 两种顺序都要认：
/// - `url action [params]` —— reject-dict、mock-response-body data=...
/// - `url target action`   —— header / 302 / 307（Loon 官方写法，动作在末位）
///
/// 之前只按第一种解析，导致社区模块里最常见的 `^url https://new 302` 与
/// `^url https://new header` 全部被判不支持。
fn parse_old(line: &str) -> Option<Vec<LoonRule>> {
    let mut t = tokenize(line);
    // 旧版 Loon 允许 `url - action` 的写法。分隔符本身不是动作，
    // 剥掉后再统一处理，否则整行会被判为不支持。
    if t.len() >= 3 && t[1] == "-" {
        t.remove(1);
    }
    if t.len() < 2 {
        return None;
    }
    let url = Regex::new(&t[0]).ok()?;
    // 先按官方写法试末位动作：`url target header|302`。
    if t.len() >= 3 {
        let tail = t[t.len() - 1].to_ascii_lowercase();
        let params: Vec<String> = t[1..t.len() - 1].to_vec();
        if let Some(r) = build_old_rule(&url, &tail, &params, line) {
            return Some(r);
        }
    }
    build_old_rule(&url, &t[1].to_ascii_lowercase(), &t[2..], line)
}

/// 按 `url action params` 构造规则；动作不认识就返回 None，由调用方换另一种顺序重试。
fn build_old_rule(url: &Regex, action: &str, params: &[String], line: &str) -> Option<Vec<LoonRule>> {
    let req = |a: LoonAction| {
        Some(vec![LoonRule { phase: LoonPhase::Request, url: url.clone(), cond: None, action: a, raw: line.into() }])
    };
    if action == "header" {
        return req(LoonAction::UrlReplace(params.first()?.clone()));
    }
    if action == "302" || action == "307" {
        return req(LoonAction::Redirect {
            status: action.parse().ok()?,
            url: params.first()?.clone(),
        });
    }
    if let Some(kind) = rejects(&action) {
        return req(LoonAction::Reject(kind));
    }
    if action == "mock-request-body" {
        return req(LoonAction::RequestMock(parse_mock(params, false)?));
    }
    if action == "mock-response-body" {
        return req(LoonAction::ResponseMock(parse_mock(params, true)?));
    }
    if let Some((is_request, ops)) = header_ops(&action, params) {
        let phase = if is_request { LoonPhase::Request } else { LoonPhase::Response };
        return Some(ops.into_iter().map(|op| LoonRule {
            phase,
            url: url.clone(),
            cond: None,
            action: if is_request { LoonAction::RequestHeader(op) } else { LoonAction::ResponseHeader(op) },
            raw: line.into(),
        }).collect());
    }
    if let Some((is_request, ops)) = body_ops(&action, params) {
        let phase = if is_request { LoonPhase::Request } else { LoonPhase::Response };
        return Some(ops.into_iter().map(|op| LoonRule {
            phase,
            url: url.clone(),
            cond: None,
            action: if is_request { LoonAction::RequestBody(op) } else { LoonAction::ResponseBody(op) },
            raw: line.into(),
        }).collect());
    }
    None
}

// ---------------- 新版语法 ----------------

fn split_args(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut in_str = false;
    let mut in_re = false;
    let mut depth = 0usize;
    let mut esc = false;
    for c in s.chars() {
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
            '\\' if in_str || in_re => {
                cur.push(c);
                esc = true;
            }
            '"' if depth == 0 => {
                in_str = !in_str;
                has = true;
            }
            '/' if depth == 0 && !in_str => {
                in_re = !in_re;
                cur.push(c);
                has = true;
            }
            '(' | '[' | '{' if !in_str && !in_re => {
                depth += 1;
                cur.push(c);
                has = true;
            }
            ')' | ']' | '}' if !in_str && !in_re => {
                depth = depth.saturating_sub(1);
                cur.push(c);
                has = true;
            }
            ',' if !in_str && !in_re && depth == 0 => {
                if has {
                    out.push(cur.trim().to_string());
                    cur = String::new();
                    has = false;
                }
            }
            c if c.is_whitespace() && !in_str && !in_re && depth == 0 => {
                if has {
                    out.push(cur.trim().to_string());
                    cur = String::new();
                    has = false;
                }
            }
            c => {
                cur.push(c);
                has = true;
            }
        }
    }
    if in_str || in_re || depth != 0 {
        return None;
    }
    if has {
        out.push(cur.trim().to_string());
    }
    Some(out)
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\")
    } else {
        t.to_string()
    }
}

fn parse_regex_literal(s: &str) -> Option<(Regex, bool)> {
    let t = s.trim();
    if !t.starts_with('/') {
        return None;
    }
    let end = t.rfind('/')?;
    if end == 0 {
        return None;
    }
    let body = &t[1..end];
    let flags = &t[end + 1..];
    let mut pattern = body.to_string();
    if flags.contains('i') {
        pattern = format!("(?i){}", pattern);
    }
    Some((Regex::new(&pattern).ok()?, flags.contains('i')))
}

fn parse_bytes_regex_literal(s: &str) -> Option<regex::bytes::Regex> {
    let t = s.trim();
    if !t.starts_with('/') {
        return None;
    }
    let end = t.rfind('/')?;
    if end == 0 {
        return None;
    }
    let body = &t[1..end];
    let flags = &t[end + 1..];
    let pattern = if flags.contains('i') { format!("(?i){}", body) } else { body.to_string() };
    regex::bytes::Regex::new(&pattern).ok()
}

fn json_value_expr(s: &str) -> String {
    let t = s.trim();
    if t.starts_with('"') && t.ends_with('"') {
        // 已经是 JSON 字符串，保留转义
        return t.to_string();
    }
    if t == "true" || t == "false" || t == "null" || t.starts_with('{') || t.starts_with('[') || t.parse::<f64>().is_ok() {
        return t.to_string();
    }
    serde_json::to_string(t).unwrap_or_else(|_| "\"\"".into())
}

/// 解析新版动作函数调用；返回 (phase, action)。
fn parse_new_action(call: &str, default_phase: LoonPhase) -> Option<(LoonPhase, LoonAction)> {
    let t = call.trim();
    let open = t.find('(')?;
    if !t.ends_with(')') {
        return None;
    }
    let name = t[..open].trim().to_ascii_lowercase();
    let args = split_args(&t[open + 1..t.len() - 1])?;
    let _ = default_phase;
    match name.as_str() {
        "url.replace" | "url.rewrite" => {
            Some((LoonPhase::Request, LoonAction::UrlReplace(unquote(args.first()?))))
        }
        "redirect" => {
            let status: u16 = args.first()?.trim().parse().ok()?;
            Some((LoonPhase::Request, LoonAction::Redirect { status, url: unquote(args.get(1)?) }))
        }
        "request.header.add" => Some((
            LoonPhase::Request,
            LoonAction::RequestHeader(HeaderOp::Add { name: unquote(args.first()?), value: unquote(args.get(1)?) }),
        )),
        "request.header.del" | "request.header.delete" => Some((
            LoonPhase::Request,
            LoonAction::RequestHeader(HeaderOp::Del { name: unquote(args.first()?) }),
        )),
        "request.header.replace" | "request.header.replace_regex" => {
            if args.len() >= 3 {
                let (re, _) = parse_regex_literal(&args[1])?;
                Some((LoonPhase::Request, LoonAction::RequestHeader(HeaderOp::ReplaceRegex {
                    name: unquote(&args[0]),
                    re,
                    replacement: unquote(&args[2]),
                })))
            } else {
                Some((
                    LoonPhase::Request,
                    LoonAction::RequestHeader(HeaderOp::Replace {
                        name: unquote(args.first()?),
                        value: unquote(args.get(1)?),
                    }),
                ))
            }
        }
        "response.header.add" => Some((
            LoonPhase::Response,
            LoonAction::ResponseHeader(HeaderOp::Add { name: unquote(args.first()?), value: unquote(args.get(1)?) }),
        )),
        "response.header.del" | "response.header.delete" => Some((
            LoonPhase::Response,
            LoonAction::ResponseHeader(HeaderOp::Del { name: unquote(args.first()?) }),
        )),
        "response.header.replace" | "response.header.replace_regex" => {
            if args.len() >= 3 {
                let (re, _) = parse_regex_literal(&args[1])?;
                Some((LoonPhase::Response, LoonAction::ResponseHeader(HeaderOp::ReplaceRegex {
                    name: unquote(&args[0]),
                    re,
                    replacement: unquote(&args[2]),
                })))
            } else {
                Some((
                    LoonPhase::Response,
                    LoonAction::ResponseHeader(HeaderOp::Replace {
                        name: unquote(args.first()?),
                        value: unquote(args.get(1)?),
                    }),
                ))
            }
        }
        "request.body.replace_regex" | "request.body.replace" => {
            let first = args.first()?;
            let re = if name.ends_with("replace") {
                regex::bytes::Regex::new(&regex::escape(&unquote(first))).ok()?
            } else {
                parse_bytes_regex_literal(first)?
            };
            Some((LoonPhase::Request, LoonAction::RequestBody(BodyOp::ReplaceRegex {
                re,
                replacement: unquote(args.get(1)?),
            })))
        }
        "response.body.replace_regex" | "response.body.replace" => {
            let first = args.first()?;
            let re = if name.ends_with("replace") {
                regex::bytes::Regex::new(&regex::escape(&unquote(first))).ok()?
            } else {
                parse_bytes_regex_literal(first)?
            };
            Some((LoonPhase::Response, LoonAction::ResponseBody(BodyOp::ReplaceRegex {
                re,
                replacement: unquote(args.get(1)?),
            })))
        }
        "request.json.add" | "response.json.add" => {
            let is_req = name.starts_with("request");
            Some((if is_req { LoonPhase::Request } else { LoonPhase::Response }, if is_req {
                LoonAction::RequestBody(BodyOp::Json(JsonOp {
                    kind: JsonKind::Add,
                    path: unquote(args.first()?),
                    value: Some(json_value_expr(args.get(1)?)),
                }))
            } else {
                LoonAction::ResponseBody(BodyOp::Json(JsonOp {
                    kind: JsonKind::Add,
                    path: unquote(args.first()?),
                    value: Some(json_value_expr(args.get(1)?)),
                }))
            }))
        }
        "request.json.replace" | "response.json.replace" => {
            let is_req = name.starts_with("request");
            Some((if is_req { LoonPhase::Request } else { LoonPhase::Response }, if is_req {
                LoonAction::RequestBody(BodyOp::Json(JsonOp {
                    kind: JsonKind::Replace,
                    path: unquote(args.first()?),
                    value: Some(json_value_expr(args.get(1)?)),
                }))
            } else {
                LoonAction::ResponseBody(BodyOp::Json(JsonOp {
                    kind: JsonKind::Replace,
                    path: unquote(args.first()?),
                    value: Some(json_value_expr(args.get(1)?)),
                }))
            }))
        }
        "request.json.delete" | "request.json.del" | "response.json.delete" | "response.json.del" => {
            let is_req = name.starts_with("request");
            Some((if is_req { LoonPhase::Request } else { LoonPhase::Response }, if is_req {
                LoonAction::RequestBody(BodyOp::Json(JsonOp {
                    kind: JsonKind::Delete,
                    path: unquote(args.first()?),
                    value: None,
                }))
            } else {
                LoonAction::ResponseBody(BodyOp::Json(JsonOp {
                    kind: JsonKind::Delete,
                    path: unquote(args.first()?),
                    value: None,
                }))
            }))
        }
        _ => None,
    }
}


/// 顶层运算符切分：跳过引号、括号与 `/regex/` 内的 `&&`/`||`。
fn split_top<'a>(s: &'a str, op: &str) -> Vec<&'a str> {
    let b = s.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut quote = 0u8;
    let mut depth = 0i32;
    let mut in_re = false;
    let mut esc = false;
    let mut expect_re = false;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if quote != 0 {
            if esc { esc = false; }
            else if c == b'\\' { esc = true; }
            else if c == quote { quote = 0; }
            i += 1;
            continue;
        }
        if in_re {
            if esc { esc = false; }
            else if c == b'\\' { esc = true; }
            else if c == b'/' { in_re = false; }
            i += 1;
            continue;
        }
        match c {
            b'\'' | b'"' => quote = c,
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'/' if expect_re => { in_re = true; expect_re = false; }
            b'=' if i > 0 && b[i - 1] == b'~' => expect_re = true,
            b'~' if i > 0 && b[i - 1] == b'!' => expect_re = true,
            _ => {}
        }
        if depth == 0 && quote == 0 && !in_re && b[i..].starts_with(op.as_bytes()) {
            let part = s[start..i].trim();
            if !part.is_empty() { parts.push(part); }
            start = i + op.len();
            i = start;
            continue;
        }
        i += 1;
    }
    let tail = s[start..].trim();
    if !tail.is_empty() { parts.push(tail); }
    parts
}

fn strip_outer_parens(s: &str) -> &str {
    let t = s.trim();
    if !t.starts_with('(') || !t.ends_with(')') { return t; }
    let b = t.as_bytes();
    let mut quote = 0u8;
    let mut depth = 0i32;
    let mut in_re = false;
    let mut esc = false;
    let mut expect_re = false;
    for (i, &c) in b.iter().enumerate() {
        if quote != 0 {
            if esc { esc = false; }
            else if c == b'\\' { esc = true; }
            else if c == quote { quote = 0; }
            continue;
        }
        if in_re {
            if esc { esc = false; }
            else if c == b'\\' { esc = true; }
            else if c == b'/' { in_re = false; }
            continue;
        }
        match c {
            b'\'' | b'"' => quote = c,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 && i != b.len() - 1 { return t; }
            }
            b'/' if expect_re => { in_re = true; expect_re = false; }
            b'=' if i > 0 && b[i - 1] == b'~' => expect_re = true,
            b'~' if i > 0 && b[i - 1] == b'!' => expect_re = true,
            _ => {}
        }
    }
    if depth == 0 { &t[1..t.len() - 1] } else { t }
}

fn parse_bool_literal(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// 解析新版条件表达式；不支持的形式返回 None，由调用方整条报 unsupported。
fn parse_condition(s: &str) -> Option<LoonCond> {
    let t = strip_outer_parens(s.trim());
    if t.is_empty() { return None; }
    if t != s.trim() { return parse_condition(t); }
    let ors = split_top(t, "||");
    if ors.len() > 1 {
        let mut v = Vec::new();
        for p in ors { v.push(parse_condition(p)?); }
        return Some(LoonCond::Or(v));
    }
    let ands = split_top(t, "&&");
    if ands.len() > 1 {
        let mut v = Vec::new();
        for p in ands { v.push(parse_condition(p)?); }
        return Some(LoonCond::And(v));
    }
    parse_condition_atom(t)
}

fn parse_condition_atom(t: &str) -> Option<LoonCond> {
    let t = t.trim();
    if let Some(rest) = t.strip_prefix("${url}") {
        let rest = rest.trim();
        let (neg, lit) = if let Some(r) = rest.strip_prefix("~=") {
            (false, r.trim())
        } else if let Some(r) = rest.strip_prefix("!~") {
            (true, r.trim())
        } else {
            return None;
        };
        let lit = lit.split(" as ").next().unwrap_or(lit).trim();
        let (re, _) = parse_regex_literal(lit)?;
        let c = LoonCond::Url(re);
        return Some(if neg { LoonCond::Not(Box::new(c)) } else { c });
    }
    // ${request.header['X']} / ${request.headers['X']}
    let header_prefix = t
        .strip_prefix("${request.header[")
        .or_else(|| t.strip_prefix("${request.headers["));
    if let Some(rest) = header_prefix {
        let close = rest.find(']')?;
        let name = rest[..close].trim().trim_matches(|c| c == '\'' || c == '"').to_string();
        if name.is_empty() { return None; }
        // rest 以 `]}` 收尾：跳过 ] 后再去掉 }，才是运算符起点。
        let tail = rest[close + 1..].trim().trim_start_matches('}').trim();
        if let Some(r) = tail.strip_prefix("~=") {
            let (re, _) = parse_regex_literal(r.trim())?;
            return Some(LoonCond::HeaderRegex { name, re });
        }
        if let Some(r) = tail.strip_prefix("!~") {
            let (re, _) = parse_regex_literal(r.trim())?;
            return Some(LoonCond::Not(Box::new(LoonCond::HeaderRegex { name, re })));
        }
        if let Some(r) = tail.strip_prefix("!=") {
            let value = r.trim();
            let eq = if value.eq_ignore_ascii_case("null") {
                None
            } else {
                Some(value.trim_matches(|c| c == '\'' || c == '"').to_string())
            };
            return Some(LoonCond::Not(Box::new(LoonCond::HeaderEq { name, value: eq })));
        }
        if let Some(r) = tail.strip_prefix("==") {
            let value = r.trim();
            let eq = if value.eq_ignore_ascii_case("null") {
                None
            } else {
                Some(value.trim_matches(|c| c == '\'' || c == '"').to_string())
            };
            return Some(LoonCond::HeaderEq { name, value: eq });
        }
        return None;
    }
    // 参数展开后可能剩下 `true == true` / `false == true`，直接算常量。
    if let Some((a, b)) = t.split_once("==") {
        if let (Some(x), Some(y)) = (parse_bool_literal(a), parse_bool_literal(b)) {
            return Some(LoonCond::Bool(x == y));
        }
    }
    if let Some((a, b)) = t.split_once("!=") {
        if let (Some(x), Some(y)) = (parse_bool_literal(a), parse_bool_literal(b)) {
            return Some(LoonCond::Bool(x != y));
        }
    }
    parse_bool_literal(t).map(LoonCond::Bool)
}

fn parse_new(line: &str) -> Option<Vec<LoonRule>> {
    let lower = line.to_ascii_lowercase();
    let phase = if lower.starts_with("request if ") {
        LoonPhase::Request
    } else if lower.starts_with("response if ") {
        LoonPhase::Response
    } else {
        return None;
    };
    let then = lower.find(" then ")?;
    let condition = line[..then].trim();
    let actions = line[then + 6..].trim();
    let cond = condition
        .strip_prefix("request if ")
        .or_else(|| condition.strip_prefix("response if "))
        .or_else(|| condition.strip_prefix("request IF "))
        .unwrap_or(condition)
        .trim();
    let cond_ast = parse_condition(cond)?;
    let prefilter = cond_ast.prefilter().unwrap_or_else(|| ".*".to_string());
    let url = Regex::new(&prefilter).ok()?;
    let mut rules = Vec::new();
    for call in actions.split(';') {
        let call = call.trim();
        if call.is_empty() {
            continue;
        }
        let (p, a) = parse_new_action(call, phase)?;
        rules.push(LoonRule {
            phase: p,
            url: url.clone(),
            cond: Some(cond_ast.clone()),
            action: a,
            raw: line.into(),
        });
    }
    if rules.is_empty() {
        return None;
    }
    Some(rules)
}

pub fn parse_loon_rewrites(lines: &[String]) -> LoonSet {
    let mut set = LoonSet::default();
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') || line.starts_with(';') {
            continue;
        }
        let parsed = if line.to_ascii_lowercase().starts_with("request if ")
            || line.to_ascii_lowercase().starts_with("response if ")
        {
            parse_new(line)
        } else {
            parse_old(line)
        };
        match parsed {
            Some(mut rules) => set.rules.append(&mut rules),
            None => set.unsupported.push(line.to_string()),
        }
    }
    set
}

pub fn apply_header_ops(headers: &mut Vec<(String, String)>, ops: &[&HeaderOp]) {
    for op in ops {
        match op {
            HeaderOp::Add { name, value } => {
                headers.push((name.clone(), value.clone()));
            }
            HeaderOp::Del { name } => {
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
            }
            HeaderOp::Replace { name, value } => {
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
                headers.push((name.clone(), value.clone()));
            }
            HeaderOp::ReplaceRegex { name, re, replacement } => {
                for (k, v) in headers.iter_mut() {
                    if k.eq_ignore_ascii_case(name) {
                        *v = re.replace_all(v, replacement.as_str()).into_owned();
                    }
                }
            }
        }
    }
}

pub fn expand_url_template(template: &str, caps: &regex::Captures<'_>) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 {
                if let Ok(n) = template[i + 1..j].parse::<usize>() {
                    if let Some(m) = caps.get(n) {
                        out.push_str(m.as_str());
                        i = j;
                        continue;
                    }
                }
            }
            // ${urlMatch.N} / ${urlMatch.N} 形式
            if template[i..].starts_with("${urlMatch.") {
                if let Some(close) = template[i..].find('}') {
                    let n = &template[i + 11..i + close];
                    if let Ok(n) = n.parse::<usize>() {
                        if let Some(m) = caps.get(n) {
                            out.push_str(m.as_str());
                            i += close + 1;
                            continue;
                        }
                    }
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// 把 JSON 路径拆成 key / index。支持 `data.apps[0].name`。
fn json_path(path: &str) -> Option<Vec<PathSeg>> {
    let mut segs = Vec::new();
    for part in path.split('.') {
        if part.is_empty() {
            return None;
        }
        let mut rest = part;
        while !rest.is_empty() {
            if let Some(open) = rest.find('[') {
                let key = &rest[..open];
                if !key.is_empty() {
                    segs.push(PathSeg::Key(key.to_string()));
                }
                let close = rest[open..].find(']')? + open;
                let idx = &rest[open + 1..close];
                if idx.is_empty() {
                    // `[]` 追加语义太接近 jq，明确不支持
                    return None;
                }
                segs.push(PathSeg::Index(idx.parse().ok()?));
                rest = &rest[close + 1..];
            } else {
                segs.push(PathSeg::Key(rest.to_string()));
                rest = "";
            }
        }
    }
    if segs.is_empty() {
        None
    } else {
        Some(segs)
    }
}

#[derive(Debug, Clone)]
enum PathSeg {
    Key(String),
    Index(usize),
}

fn set_json(value: &mut serde_json::Value, path: &[PathSeg], new: serde_json::Value, add: bool) -> bool {
    if path.is_empty() {
        return false;
    }
    let mut cur = value;
    for (i, seg) in path.iter().enumerate() {
        let last = i + 1 == path.len();
        match seg {
            PathSeg::Key(k) => {
                if !cur.is_object() {
                    if add {
                        *cur = serde_json::Value::Object(Default::default());
                    } else {
                        return false;
                    }
                }
                let obj = cur.as_object_mut().unwrap();
                if last {
                    if !add && !obj.contains_key(k) {
                        return false;
                    }
                    obj.insert(k.clone(), new);
                    return true;
                }
                if !obj.contains_key(k) {
                    if !add {
                        return false;
                    }
                    let next_is_index = matches!(path.get(i + 1), Some(PathSeg::Index(_)));
                    obj.insert(
                        k.clone(),
                        if next_is_index { serde_json::Value::Array(Default::default()) } else { serde_json::Value::Object(Default::default()) },
                    );
                }
                cur = obj.get_mut(k).unwrap();
            }
            PathSeg::Index(n) => {
                if !cur.is_array() {
                    if add {
                        *cur = serde_json::Value::Array(Default::default());
                    } else {
                        return false;
                    }
                }
                let arr = cur.as_array_mut().unwrap();
                while arr.len() <= *n {
                    if !add {
                        return false;
                    }
                    arr.push(serde_json::Value::Null);
                }
                if last {
                    arr[*n] = new;
                    return true;
                }
                cur = &mut arr[*n];
            }
        }
    }
    false
}

fn del_json(value: &mut serde_json::Value, path: &[PathSeg]) -> bool {
    if path.is_empty() {
        return false;
    }
    let mut cur = value;
    for (i, seg) in path.iter().enumerate() {
        let last = i + 1 == path.len();
        match seg {
            PathSeg::Key(k) => {
                let Some(obj) = cur.as_object_mut() else { return false };
                if last {
                    return obj.remove(k).is_some();
                }
                let Some(next) = obj.get_mut(k) else { return false };
                cur = next;
            }
            PathSeg::Index(n) => {
                let Some(arr) = cur.as_array_mut() else { return false };
                if *n >= arr.len() {
                    return false;
                }
                if last {
                    arr.remove(*n);
                    return true;
                }
                cur = &mut arr[*n];
            }
        }
    }
    false
}

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

/// 依次执行 Loon 正文动作；输出超过 limit 返回 None，调用方原样透传。
pub fn apply_body_ops(body: &[u8], ops: &[&BodyOp], limit: usize) -> Option<(Vec<u8>, bool)> {
    let mut cur = body.to_vec();
    let mut changed = false;
    for op in ops {
        match op {
            BodyOp::ReplaceRegex { re, replacement } => {
                let out = replace_limited(re, &cur, replacement.as_bytes(), limit)?;
                if out != cur {
                    changed = true;
                }
                cur = out;
            }
            BodyOp::Json(j) => {
                let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&cur) else { continue };
                let Some(path) = json_path(&j.path) else { continue };
                let did = match j.kind {
                    JsonKind::Delete => del_json(&mut v, &path),
                    JsonKind::Add | JsonKind::Replace => {
                        let Some(raw) = &j.value else { continue };
                        let parsed = serde_json::from_str::<serde_json::Value>(raw)
                            .unwrap_or_else(|_| serde_json::Value::String(raw.clone()));
                        set_json(&mut v, &path, parsed, matches!(j.kind, JsonKind::Add))
                    }
                };
                if did {
                    let out = serde_json::to_vec(&v).ok()?;
                    if out.len() > limit {
                        return None;
                    }
                    if out != cur {
                        changed = true;
                    }
                    cur = out;
                }
            }
        }
    }
    Some((cur, changed))
}

/// 按头部动作取 value；用于测试与 mock 组装。
pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// 预留：把 Loon 动作名映射成界面显示用的能力标签。
pub fn action_label(action: &LoonAction) -> &'static str {
    match action {
        LoonAction::UrlReplace(_) => "URL 替换",
        LoonAction::Redirect { .. } => "重定向",
        LoonAction::Reject(_) => "拒绝",
        LoonAction::RequestHeader(_) => "请求头",
        LoonAction::ResponseHeader(_) => "响应头",
        LoonAction::RequestBody(_) => "请求体/JSON",
        LoonAction::ResponseBody(_) => "响应体/JSON",
        LoonAction::RequestMock(_) => "请求体 mock",
        LoonAction::ResponseMock(_) => "响应 mock",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_old_common_actions() {
        let lines = vec![
            r"^https://api\.x\.com/ad reject".to_string(),
            r"^https://old\.x\.com/p header https://new.x.com/q".to_string(),
            r"^https://api\.x\.com/a 302 https://x.com/new".to_string(),
            r"^https://api\.x\.com/h header-add X-A 1 X-B 2".to_string(),
            r"^https://api\.x\.com/h response-header-del Cookie Set-Cookie".to_string(),
            r#"^https://api\.x\.com/feed response-body-replace-regex "ads":\[.*?\] ""#.to_string(),
            r#"^https://api\.x\.com/j response-body-json-del data.ads "#.to_string(),
            r#"^https://api\.x\.com/j response-body-json-add data.apps[0].name "x""#.to_string(),
        ];
        let set = parse_loon_rewrites(&lines);
        assert_eq!(set.unsupported.len(), 0);
        // header-add / header-del 的多组参数拆成独立动作，共 10 条。
        assert_eq!(set.rules.len(), 10);
        assert!(matches!(set.rules[0].action, LoonAction::Reject(RejectKind::Drop)));
        assert!(matches!(set.rules[1].action, LoonAction::UrlReplace(_)));
        assert!(matches!(set.rules[2].action, LoonAction::Redirect { status: 302, .. }));
    }

    #[test]
    fn parses_dash_separated_old_syntax() {
        // 社区模块最常见的写法：`url - reject-dict`。分隔符不能当成动作名。
        let lines = vec![
            r"^https://app\.x\.com/x/v2/splash/list - reject-dict".to_string(),
            r"^https://acs\.x\.com/gw/mtop\.a\.getadv - reject-dict".to_string(),
            r"^https://api\.x\.com/ad - reject".to_string(),
            r"^https://api\.x\.com/j - response-body-json-del data.ads".to_string(),
        ];
        let set = parse_loon_rewrites(&lines);
        assert_eq!(set.unsupported.len(), 0);
        assert!(matches!(set.rules[0].action, LoonAction::Reject(RejectKind::JsonObject)));
        assert!(matches!(set.rules[1].action, LoonAction::Reject(RejectKind::JsonObject)));
        assert!(matches!(set.rules[2].action, LoonAction::Reject(RejectKind::Drop)));
    }

    #[test]
    fn parses_new_syntax_and_rejects_complex_conditions() {
        let lines = vec![
            r#"request if ${url} ~= /^https:\/\/old\.x\.com\/(.*)$/i as urlMatch then url.replace("https://new.x.com/${urlMatch.1}")"#.to_string(),
            r#"response if ${url} ~= /^https:\/\/api\.x\.com/ then response.body.replace("ad-banner", "")"#.to_string(),
            r#"request if ${url} ~= /^https:\/\/api\.x\.com/ && ${enabled} then request.header.add("X", "1")"#.to_string(),
        ];
        let set = parse_loon_rewrites(&lines);
        assert_eq!(set.rules.len(), 2);
        assert_eq!(set.unsupported.len(), 1);
        assert!(matches!(set.rules[0].action, LoonAction::UrlReplace(_)));
        assert!(matches!(set.rules[1].action, LoonAction::ResponseBody(BodyOp::ReplaceRegex { .. })));
    }

    #[test]
    fn json_add_replace_delete() {
        let (json, _) = {
            let mut ops = Vec::new();
            ops.push(BodyOp::Json(JsonOp { kind: JsonKind::Delete, path: "data.ads".into(), value: None }));
            ops.push(BodyOp::Json(JsonOp { kind: JsonKind::Add, path: "data.apps[0].name".into(), value: Some("\"x\"".into()) }));
            ops.push(BodyOp::Json(JsonOp { kind: JsonKind::Replace, path: "data.price".into(), value: Some("1".into()) }));
            let refs: Vec<&BodyOp> = ops.iter().collect();
            apply_body_ops(br#"{"data":{"ads":[1],"price":9}}"#, &refs, 1 << 20).unwrap()
        };
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert!(v["data"]["ads"].is_null());
        assert_eq!(v["data"]["apps"][0]["name"], "x");
        assert_eq!(v["data"]["price"], 1);
    }

    #[test]
    fn url_template_expands_capture() {
        let re = Regex::new(r"^https://old\.x\.com/(.*)$").unwrap();
        let caps = re.captures("https://old.x.com/a/b").unwrap();
        assert_eq!(expand_url_template("https://new.x.com/$1", &caps), "https://new.x.com/a/b");
        assert_eq!(expand_url_template("https://new.x.com/${urlMatch.1}", &caps), "https://new.x.com/a/b");
    }

    #[test]
    fn mock_inline_and_data_path() {
        let t = tokenize(r#"mock-response-body data-type=json data="{\"ok\":1}" status-code=201"#);
        let m = parse_mock(&t, true).unwrap();
        assert_eq!(m.status, 201);
        assert_eq!(m.content_type, "application/json");
        assert_eq!(m.body, br#"{"ok":1}"#);
        let t = tokenize(r#"mock-response-body data-type=json data-path=response_body.json"#);
        assert!(parse_mock(&t, true).is_none());
    }

    #[test]
    fn new_syntax_compound_conditions_are_evaluated() {
        let lines = vec![
            r#"request if ${url} ~= /^https:\/\/api\.x\.com\/feed/ && ${request.header['X-Test']} == "yes" then request.header.add("X-A", "1")"#.to_string(),
        ];
        let set = parse_loon_rewrites(&lines);
        assert_eq!(set.unsupported.len(), 0, "{:?}", set.unsupported);
        assert_eq!(set.rules.len(), 1);
        let rule = &set.rules[0];
        let h = vec![("X-Test".to_string(), "yes".to_string())];
        assert!(rule.applies("https://api.x.com/feed/index", &h));
        assert!(!rule.applies("https://api.x.com/feed/index", &[("X-Test".into(), "no".into())]));
        assert!(!rule.applies("https://api.x.com/other", &h));
    }

    #[test]
    fn new_syntax_header_regex_and_or() {
        let lines = vec![
            r#"response if ${request.header['Content-Type']} ~= /json/ || ${request.header['X-Mode']} == "legacy" then response.header.add("X-R", "1")"#.to_string(),
        ];
        let set = parse_loon_rewrites(&lines);
        assert_eq!(set.unsupported.len(), 0, "{:?}", set.unsupported);
        let rule = &set.rules[0];
        assert!(rule.applies("https://x.com/a", &[("Content-Type".into(), "application/json".into())]));
        assert!(rule.applies("https://x.com/a", &[("X-Mode".into(), "legacy".into())]));
        assert!(!rule.applies("https://x.com/a", &[("Content-Type".into(), "text/html".into())]));
    }

    #[test]
    fn new_syntax_boolean_argument_constant() {
        let lines = vec![
            r#"request if false == true then request.header.add("X-Never", "1")"#.to_string(),
        ];
        let set = parse_loon_rewrites(&lines);
        assert_eq!(set.unsupported.len(), 0, "{:?}", set.unsupported);
        assert!(!set.rules[0].applies("https://x.com/a", &[]));
    }

    #[test]
    fn unsupported_new_condition_is_reported_not_executed() {
        let lines = vec![
            r#"request if ${request.header['X']} > 3 then request.header.add("X-A", "1")"#.to_string(),
        ];
        let set = parse_loon_rewrites(&lines);
        assert_eq!(set.rules.len(), 0);
        assert_eq!(set.unsupported.len(), 1);
    }
}
