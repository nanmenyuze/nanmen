//! MITM 去广告：SNI 命中列表的 TLS 连接在本地终止，按 URL 规则拒绝广告请求、
//! 改写响应体，其余请求经现有直连/代理出站重新加密转发。
//!
//! 兜底策略（不断网优先）：
//! - 本地 TLS 握手失败（cert pinning / 只支持 h2）→ 域名临时放行，App 重试走透明转发；
//! - 响应体超过改写上限 / br 等无法解码 → 原样透传；
//! - 上游连接失败 → 回 502，只影响这一条请求。

pub mod ca;
pub mod grpc;
pub mod h2;
pub mod host_stats;
pub mod http1;
pub mod jq;
pub mod loon;
pub mod pool;
pub mod rewrite;
pub mod ws;

pub use crate::script::{
    ScriptBatchResult, ScriptMessage, ScriptPhase, ScriptPoolHealth, ScriptWorkerPool,
};
pub use loon::{LoonAction, LoonPhase, LoonRule};
pub use rewrite::{MitmConfig, MitmEngine, MitmRuleConf, RewriteAction, RewriteRule};

use crate::config::Target;
use crate::engine::Action;
use crate::logging;
use crate::netstack::Ctx;
use crate::outbound;
use ca::MitmCa;
use http1::{Buffered, Framing, Headers, RequestHead, TINY_GIF};
use loon::{BodyOp, HeaderOp, MockSpec, RejectKind};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// 同时参与 h2 正文改写的内存预算。
///
/// 一条响应在改写期间至少同时持有「原始字节 + 解压结果 + 改写结果」三份，
/// 因此每条流按 `body_limit * 3` 预留；总量只允许 2 条流并发改写，
/// 其余流在额度不足时直接原样流式转发，避免多流叠加把 PSS 推高。
pub const REWRITE_BUFFER_COPIES: usize = 3;
pub const MAX_CONCURRENT_REWRITE_STREAMS: usize = 2;
/// 脚本配额排队的额外余量：在单脚本超时之上再等这么久才判排队失败。
const SCRIPT_SLOT_QUEUE_GRACE_MS: u64 = 250;
/// 正文直通硬上限：超过 2 MiB 的响应绝不进改写缓冲，哪怕 body_limit 配得更大。
pub const BODY_PASSTHROUGH_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyBypass {
    NonText,
    TooLarge,
}

/// 大响应提前直通判定（纯函数，便于单测）。
/// 只有本来会命中正文规则时才调用；`binary_response_scripts` 存在时允许二进制
/// 正文进入脚本路径，否则 video/audio/octet-stream 等直接透传。
pub fn body_bypass_reason(
    text_like: bool,
    binary_response_scripts: bool,
    content_length: Option<usize>,
    body_limit: usize,
) -> Option<BodyBypass> {
    if let Some(n) = content_length {
        if n > BODY_PASSTHROUGH_LIMIT.min(body_limit) {
            return Some(BodyBypass::TooLarge);
        }
    }
    if !text_like && !binary_response_scripts {
        return Some(BodyBypass::NonText);
    }
    None
}

/// 单条 MITM 连接的观测计数：请求数 / 无规则命中数 / 是否已记录过首条无规则请求。
/// h2 与 h1 共用同一份，连接结束时汇总一条日志，避免逐请求刷屏。
#[derive(Default)]
pub struct ConnTrace {
    pub reqs: AtomicU64,
    pub no_rule: AtomicU64,
    pub noted: AtomicBool,
}

pub struct RewriteBudget {
    total: usize,
    used: AtomicUsize,
}

impl RewriteBudget {
    pub fn new(total: usize) -> Arc<Self> {
        Arc::new(Self {
            total,
            used: AtomicUsize::new(0),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, amount: usize) -> Option<RewritePermit> {
        if amount == 0 || amount > self.total {
            return None;
        }
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let next = used.checked_add(amount)?;
            if next > self.total {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => {
                    return Some(RewritePermit {
                        budget: self.clone(),
                        amount,
                    })
                }
                Err(current) => used = current,
            }
        }
    }
}

pub struct RewritePermit {
    budget: Arc<RewriteBudget>,
    amount: usize,
}

impl Drop for RewritePermit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.amount, Ordering::Relaxed);
    }
}

pub struct MitmState {
    pub engine: Arc<MitmEngine>,
    pub ca: Option<Arc<MitmCa>>,
    pub rewrite_budget: Arc<RewriteBudget>,
    /// 限制并发脚本数：拿不到许可时排队等待（有上限），不跳过脚本。
    /// 并发是内部实现细节，不能改变模块应得的改写结果。
    pub script_slots: Arc<tokio::sync::Semaphore>,
    /// WebSocket 帧改写独立并发闸，不与 h2 短正文改写共享预算。
    pub ws_slots: Arc<tokio::sync::Semaphore>,
    /// 专用脚本工作线程池；每个线程独立持有 QuickJS Runtime。
    pub script_pool: Arc<ScriptWorkerPool>,
    /// 上游连接池：灰度开关关闭时所有 acquire 都 miss，不改变原路径。
    pub pool: Arc<pool::MitmPool>,
}

impl MitmState {
    pub fn build(cfg: &MitmConfig) -> Self {
        Self::build_with_stats(cfg, None)
    }

    pub fn build_with_stats(cfg: &MitmConfig, stats: Option<Arc<crate::stats::Stats>>) -> Self {
        let mut engine_built = MitmEngine::from_config(cfg);
        engine_built.stats = stats.clone();
        let engine = Arc::new(engine_built);
        let ca = if cfg.enabled && !cfg.ca_file.trim().is_empty() && !engine.hosts.is_empty() {
            match MitmCa::load_or_generate(&cfg.ca_file) {
                Ok(c) => {
                    logging::info(
                        "mitm",
                        format!(
                            "MITM 就绪：{} 个域名模式，{} 条 Surge 改写规则，{} 条 Loon 重写（Loon 不支持 {} 条，脚本不支持 {} 条，跳过 {} 条非法规则）",
                            cfg.hostnames.len(),
                            engine.rules.len(),
                            engine.loon_rules.len(),
                            engine.loon_unsupported.len(),
                            engine.scripts.unsupported.len(),
                            engine.skipped_rules
                        ),
                    );
                    let c = Arc::new(c);
                    if let Some(st) = stats.clone() {
                        c.set_stats(st);
                    }
                    Some(c)
                }
                Err(e) => {
                    logging::warn("mitm", format!("CA 加载/生成失败，MITM 不生效: {}", e));
                    None
                }
            }
        } else {
            None
        };
        let rewrite_budget = RewriteBudget::new(
            engine
                .body_limit
                .saturating_mul(REWRITE_BUFFER_COPIES)
                .saturating_mul(MAX_CONCURRENT_REWRITE_STREAMS),
        );
        Self {
            engine,
            ca,
            rewrite_budget,
            script_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            ws_slots: Arc::new(tokio::sync::Semaphore::new(8)),
            script_pool: Arc::new(ScriptWorkerPool::new(4)),
            pool: Arc::new(pool::MitmPool::new(
                cfg.pool_enabled,
                cfg.pool_idle_secs,
                stats,
            )),
        }
    }

    pub fn active(&self) -> bool {
        self.engine.enabled && self.ca.is_some()
    }

    /// 定时/事件触发脚本：只执行指定规则，不走 URL `hits`，避免把其它
    /// `.*` 脚本在同一时刻重复跑一遍。阻塞调用，调度器放在 spawn_blocking 中。
    pub fn run_trigger_rule(&self, rule: &crate::script::CompiledScriptRule) -> Vec<String> {
        let mut msg = crate::script::ScriptMessage::default();
        msg.url = format!("cron://{}", rule.name);
        msg.method = "CRON".to_string();
        let opts = crate::script::ScriptOptions {
            timeout_ms: rule.timeout_ms,
            allow_private_network: false,
            arguments: rule.arguments.clone(),
            argument_types: rule.argument_types.clone(),
            argument_values: self.engine.scripts.effective_argument_values(rule),
            argument_text: rule.argument_text.clone(),
            store: Some(self.engine.scripts.store.clone()),
            script_name: rule.name.clone(),
            binary_body_mode: rule.binary_body_mode,
            environment: self.engine.environment.clone(),
            notification_file: self.engine.notification_file.clone(),
        };
        let out = self.script_pool.run(&rule.source, rule.phase, &msg, &opts);
        let mut errors = Vec::new();
        if let Some(e) = out.error {
            errors.push(format!("{}: {}", rule.name, e));
        }
        for n in out.notifications {
            logging::info("cron", format!("{}: {}", rule.name, n));
        }
        errors
    }

    pub fn script_health(&self) -> ScriptPoolHealth {
        self.script_pool.health()
    }

    pub fn should_mitm(&self, host: &str) -> bool {
        self.active() && self.engine.should_mitm(host)
    }

    /// 带 App 归属的判定（TCP 443 有 socket 表时可精确到 UID）。
    pub fn should_mitm_uid(&self, host: &str, uid: Option<u32>) -> bool {
        self.active() && self.engine.should_mitm_uid(host, uid)
    }

    pub fn app_allows(&self, uid: Option<u32>) -> bool {
        self.engine.app_allows(uid)
    }

    /// 依次执行命中的脚本。QuickJS 固定在专用工作线程上，MITM 路径同步等待；
    /// 外层用 blocking 线程池和信号量限制并发，避免拖住 tokio worker。
    pub async fn run_scripts(
        &self,
        phase: ScriptPhase,
        url: &str,
        message: &ScriptMessage,
    ) -> ScriptBatchResult {
        let mut hits: Vec<_> = self
            .engine
            .scripts
            .hits_with_message(url, phase, message)
            .into_iter()
            .cloned()
            .map(|mut r| {
                r.argument_values = self.engine.scripts.effective_argument_values(&r);
                r
            })
            .collect();
        if hits.is_empty() {
            return ScriptBatchResult {
                message: message.clone(),
                ..Default::default()
            };
        }
        // Loon 语义：每阶段至多执行首条最终条件为 true 的脚本。
        // 只有模块显式打开 legacy-chain 时才沿用 2.8 的多脚本链式执行。
        hits = crate::script::select_phase_hits(hits);
        if let Some(rule) = hits.first() {
            if let Some(identity) = rule.meta.as_ref().map(|m| m.identity()) {
                if let Some(stats) = self.engine.stats.as_ref() {
                    let host = url::Url::parse(url)
                        .ok()
                        .and_then(|u| u.host_str().map(|h| h.to_string()))
                        .unwrap_or_else(|| url.to_string());
                    stats.hits.record_hit(&identity, &host, "rewrite");
                }
            }
        }
        // 配额满时排队等待，不再静默透传：内部排队/限流是实现细节，
        // 不能改变模块应得的结果。排队上限跟随本次命中的脚本超时，
        // 超时后明确失败（既不改写，也不假装成功）。
        let queue_timeout_ms = hits
            .iter()
            .map(|r| r.timeout_ms.max(50).min(crate::script::MAX_TIMEOUT_MS))
            .max()
            .unwrap_or(0)
            + SCRIPT_SLOT_QUEUE_GRACE_MS;
        let _permit = match tokio::time::timeout(
            std::time::Duration::from_millis(queue_timeout_ms),
            self.script_slots.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                self.script_pool.note_failed();
                return ScriptBatchResult {
                    message: message.clone(),
                    matched: hits.len(),
                    errors: vec!["脚本配额已关闭，本次改写未执行".into()],
                    ..Default::default()
                };
            }
            Err(_) => {
                self.script_pool.note_failed();
                return ScriptBatchResult {
                    message: message.clone(),
                    matched: hits.len(),
                    errors: vec![format!("脚本排队超时（{queue_timeout_ms}ms），本次改写未执行")],
                    ..Default::default()
                };
            }
        };
        let base = message.clone();
        let body_limit = self.engine.body_limit;
        let store = self.engine.scripts.store.clone();
        let environment = self.engine.environment.clone();
        let notification_file = self.engine.notification_file.clone();
        let pool = self.script_pool.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut out = ScriptBatchResult {
                message: base.clone(),
                ..Default::default()
            };
            let mut current = base;
            for (idx, rule) in hits.iter().enumerate() {
                out.matched += 1;
                let opts = crate::script::ScriptOptions {
                    timeout_ms: rule.timeout_ms,
                    allow_private_network: false,
                    arguments: rule.arguments.clone(),
                    argument_types: rule.argument_types.clone(),
                    argument_values: rule.argument_values.clone(),
                    argument_text: rule.argument_text.clone(),
                    store: Some(store.clone()),
                    script_name: rule.name.clone(),
                    binary_body_mode: rule.binary_body_mode,
                    environment: environment.clone(),
                    notification_file: notification_file.clone(),
                };
                let r = pool.run(&rule.source, phase, &current, &opts);
                out.done_calls += r.done_calls;
                out.http_calls += r.http_calls;
                out.logs.extend(r.logs.iter().cloned());
                out.notifications.extend(r.notifications.iter().cloned());
                out.notification_items
                    .extend(r.notification_items.iter().cloned());
                out.timed_out |= r.timed_out;
                if let Some(e) = &r.error {
                    out.errors.push(format!("{}: {}", rule.name, e));
                }
                // 即使脚本报错/超时，只要它已经调用过 $done，就按首次完成结果继续。
                if r.done_calls == 0 && r.error.is_some() {
                    continue;
                }
                if r.message.body_len() > rule.max_size.min(body_limit) {
                    out.errors
                        .push(format!("{}: 输出正文超过上限，已丢弃该脚本结果", rule.name));
                    continue;
                }
                current = r.message;
                if r.aborted {
                    out.aborted = true;
                    out.message = current.clone();
                    out.matched = idx + 1;
                    return out;
                }
                if phase == ScriptPhase::Request && r.short_circuit_response {
                    out.short_circuit = true;
                    out.message = current.clone();
                    out.matched = idx + 1;
                    return out;
                }
                out.message = current.clone();
            }
            out
        })
        .await
        .unwrap_or_else(|e| ScriptBatchResult {
            message: message.clone(),
            errors: vec![format!("脚本任务异常: {e}")],
            ..Default::default()
        });
        if !result.errors.is_empty() || result.timed_out {
            let h = self.script_health();
            logging::warn(
                "mitm.script",
                format!(
                    "脚本诊断：命中 {}，错误 {}，累计完成 {}、失败 {}、超时 {}、跳过 {}",
                    result.matched,
                    result.errors.len(),
                    h.completed,
                    h.failed,
                    h.timed_out,
                    h.skipped
                ),
            );
        }
        result
    }
}

#[derive(Clone, Debug)]
enum Terminal {
    Reject(RejectKind),
    Redirect { status: u16, url: String },
    Mock(MockSpec),
}

struct LoonRequestPlan {
    host: String,
    target: Target,
    terminal: Option<Terminal>,
    request_mock: Option<MockSpec>,
    request_body_ops: Vec<BodyOp>,
    response_headers: Vec<HeaderOp>,
    response_body_ops: Vec<BodyOp>,
}

fn parse_rewrite_url(url: &str) -> Option<(String, String, u16)> {
    let u = url::Url::parse(url).ok()?;
    let host = u.host_str()?.to_string();
    let port = u.port_or_known_default().unwrap_or(443);
    let path = if u.query().is_some() {
        format!("{}?{}", u.path(), u.query().unwrap())
    } else {
        u.path().to_string()
    };
    Some((host, path, port))
}

/// D5 Rewrite↔Script disable 表：
/// - 请求阶段终止响应（reject/mock）→ 禁请求脚本 + 禁响应脚本；
/// - 请求体改写/mock → 禁请求脚本；
/// - 响应体改写 → 禁响应脚本；
/// - 仅改头 → 不禁。
pub fn script_disable_flags(
    terminal: bool,
    request_mock: bool,
    request_body_rewrite: bool,
    response_body_rewrite: bool,
) -> (bool, bool) {
    let request = terminal || request_mock || request_body_rewrite;
    let response = terminal || request_mock || response_body_rewrite;
    (request, response)
}

/// 只对请求阶段执行 URL/头/mock 动作；响应动作收集起来等上游响应回来再应用。
fn plan_loon_request(
    hits: &[&LoonRule],
    host: &str,
    target: &Target,
    req: &mut RequestHead,
) -> LoonRequestPlan {
    let mut host_now = host.to_string();
    let mut target_now = target.clone();
    let mut url_now = format!("https://{}{}", host_now, req.path);
    let mut plan = LoonRequestPlan {
        host: host_now.clone(),
        target: target_now.clone(),
        terminal: None,
        request_mock: None,
        request_body_ops: Vec::new(),
        response_headers: Vec::new(),
        response_body_ops: Vec::new(),
    };
    for rule in hits {
        // 新版 Loon 条件可引用请求头/参数；旧规则 cond=None，行为不变。
        // URL 可能被前一条 url.replace 改写，所以每条都用当前 url 重新求值。
        if !rule.applies(&url_now, &req.headers) {
            continue;
        }
        match &rule.action {
            LoonAction::UrlReplace(template) => {
                let Some(caps) = rule.url.captures(&url_now) else {
                    continue;
                };
                let new_url = loon::expand_url_template(template, &caps);
                if let Some((new_host, new_path, new_port)) = parse_rewrite_url(&new_url) {
                    req.path = new_path;
                    if !new_host.eq_ignore_ascii_case(&host_now) || new_port != 443 {
                        // 跨域改写：直连用 198.18.0.1 占位，让 outbound 按新域名解析；
                        // 代理节点直接拿域名，无需本地解析。
                        target_now = Target {
                            ip: "198.18.0.1".parse().unwrap(),
                            port: new_port,
                            domain: Some(new_host.clone()),
                        };
                        host_now = new_host;
                    }
                } else if new_url.starts_with('/') {
                    req.path = new_url;
                }
                url_now = format!("https://{}{}", host_now, req.path);
            }
            LoonAction::Redirect { status, url } => {
                plan.terminal = Some(Terminal::Redirect {
                    status: *status,
                    url: url.clone(),
                });
                break;
            }
            LoonAction::Reject(kind) => {
                plan.terminal = Some(Terminal::Reject(kind.clone()));
                break;
            }
            LoonAction::ResponseMock(spec) => {
                plan.terminal = Some(Terminal::Mock(spec.clone()));
                break;
            }
            LoonAction::RequestMock(spec) => plan.request_mock = Some(spec.clone()),
            LoonAction::RequestHeader(op) => loon::apply_header_ops(&mut req.headers, &[op]),
            LoonAction::RequestBody(op) => plan.request_body_ops.push(op.clone()),
            LoonAction::ResponseHeader(op) => plan.response_headers.push(op.clone()),
            LoonAction::ResponseBody(op) => plan.response_body_ops.push(op.clone()),
        }
        if rule.phase == LoonPhase::Response {
            // 响应阶段规则不应在请求阶段修改请求；上面只处理了请求动作。
            continue;
        }
    }
    plan.host = host_now;
    plan.target = target_now;
    plan
}

fn request_script_message(url: &str, req: &RequestHead, body: &[u8]) -> ScriptMessage {
    ScriptMessage {
        url: url.to_string(),
        method: req.method.clone(),
        status: 0,
        headers: req.headers.clone(),
        body: String::from_utf8_lossy(body).into_owned(),
        body_bytes: Some(body.to_vec()),
    }
}

fn response_script_message(
    url: &str,
    status: u16,
    headers: &Headers,
    body: &[u8],
) -> ScriptMessage {
    ScriptMessage {
        url: url.to_string(),
        method: "GET".into(),
        status,
        headers: headers.clone(),
        body: String::from_utf8_lossy(body).into_owned(),
        body_bytes: Some(body.to_vec()),
    }
}

/// 把脚本结果写回请求。只允许同 host 的 URL 变化；跨域脚本改写不支持，
/// 避免脚本悄悄把流量导向另一个域名而外壳看不到。
fn apply_request_script(
    req: &mut RequestHead,
    msg: &ScriptMessage,
    host: &str,
    base_url: &str,
) -> Result<bool, String> {
    let mut changed = false;
    if !msg.method.trim().is_empty() && msg.method != req.method {
        let m = msg.method.trim();
        if !m
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!("脚本返回非法 method: {m}"));
        }
        req.method = m.to_string();
        changed = true;
    }
    if !msg.url.is_empty() && msg.url != base_url {
        let u = url::Url::parse(&msg.url).map_err(|e| format!("脚本返回 URL 非法: {e}"))?;
        if u.scheme() != "https" && u.scheme() != "http" {
            return Err("脚本只能返回 http/https URL".into());
        }
        let new_host = u.host_str().unwrap_or("");
        if !new_host.eq_ignore_ascii_case(host) {
            return Err(format!("脚本跨域改写不支持: {host} -> {new_host}"));
        }
        let path = if u.query().is_some() {
            format!("{}?{}", u.path(), u.query().unwrap())
        } else {
            u.path().to_string()
        };
        if path != req.path {
            req.path = path;
            changed = true;
        }
    }
    let mut headers = Vec::new();
    for (k, v) in &msg.headers {
        let name = k.trim();
        if name.is_empty() || name.starts_with(':') || name.contains('\r') || name.contains('\n') {
            continue;
        }
        if v.contains('\r') || v.contains('\n') {
            continue;
        }
        headers.push((name.to_string(), v.clone()));
    }
    if headers != req.headers {
        req.headers = headers;
        changed = true;
    }
    let desired = msg.body_bytes();
    let is_no_body = desired.is_empty() && req.body == http1::BodyKind::None;
    if !is_no_body {
        http1::remove_header(&mut req.headers, "content-encoding");
        http1::remove_header(&mut req.headers, "transfer-encoding");
        http1::set_header(
            &mut req.headers,
            "Content-Length",
            &desired.len().to_string(),
        );
        req.body = if desired.is_empty() {
            http1::BodyKind::Length(0)
        } else {
            http1::BodyKind::Length(desired.len() as u64)
        };
        changed = true;
    }
    Ok(changed)
}

async fn send_script_response<S>(
    cio: &mut Buffered<S>,
    msg: &ScriptMessage,
    keep_alive: bool,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let status = if msg.status == 0 { 200 } else { msg.status };
    let reason = match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    };
    let mut headers: Headers = msg
        .headers
        .iter()
        .filter(|(k, _)| {
            !k.eq_ignore_ascii_case("content-length")
                && !k.eq_ignore_ascii_case("transfer-encoding")
                && !k.eq_ignore_ascii_case("connection")
        })
        .cloned()
        .collect();
    headers.push(("Content-Length".into(), msg.body_len().to_string()));
    headers.push((
        "Connection".into(),
        if keep_alive {
            "keep-alive".into()
        } else {
            "close".into()
        },
    ));
    cio.stream
        .write_all(&http1::serialize_response(
            status,
            reason,
            &headers,
            msg.body_bytes(),
        ))
        .await
}

fn read_mock_file(spec: &loon::MockSpec, base_dir: &str) -> Result<Vec<u8>, String> {
    let Some(path) = spec.data_path.as_deref() else {
        return Ok(spec.body.clone());
    };
    let p = std::path::Path::new(path);
    let full = if p.is_absolute() || base_dir.trim().is_empty() {
        p.to_path_buf()
    } else {
        std::path::Path::new(base_dir).join(p)
    };
    let meta = std::fs::metadata(&full).map_err(|e| format!("{}: {e}", full.display()))?;
    if meta.len() > 4 * 1024 * 1024 {
        return Err(format!("{}: 文件超过 4 MiB", full.display()));
    }
    std::fs::read(&full).map_err(|e| format!("{}: {e}", full.display()))
}

fn terminal_response(
    term: &Terminal,
    header_ops: &[HeaderOp],
    keep_alive: bool,
    mock_base_dir: &str,
) -> (u16, String, Headers, Vec<u8>) {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let mut headers: Headers = vec![
        ("Connection".into(), conn.into()),
        ("Cache-Control".into(), "no-store".into()),
    ];
    let (status, reason, body): (u16, &str, Vec<u8>) = match term {
        Terminal::Reject(kind) => match kind {
            RejectKind::Drop => (204, "No Content", Vec::new()),
            RejectKind::Status200 => (200, "OK", Vec::new()),
            RejectKind::TinyGif => (200, "OK", TINY_GIF.to_vec()),
            RejectKind::JsonObject => (200, "OK", b"{}".to_vec()),
            RejectKind::JsonArray => (200, "OK", b"[]".to_vec()),
        },
        Terminal::Redirect { status, url } => {
            headers.push(("Location".into(), url.clone()));
            (
                *status,
                if *status == 307 {
                    "Temporary Redirect"
                } else {
                    "Found"
                },
                Vec::new(),
            )
        }
        Terminal::Mock(spec) => {
            headers.push(("Content-Type".into(), spec.content_type.clone()));
            for (name, value) in &spec.headers {
                http1::set_header(&mut headers, name, value);
            }
            match read_mock_file(spec, mock_base_dir) {
                Ok(body) => (spec.status, "OK", body),
                Err(e) => {
                    logging::warn("mitm", format!("Map Local 文件读取失败: {e}"));
                    (
                        404,
                        "Not Found",
                        format!("Map Local 文件不可读: {e}").into_bytes(),
                    )
                }
            }
        }
    };
    if matches!(term, Terminal::Reject(RejectKind::TinyGif)) {
        headers.push(("Content-Type".into(), "image/gif".into()));
    }
    if matches!(
        term,
        Terminal::Reject(RejectKind::JsonObject | RejectKind::JsonArray)
    ) {
        headers.push(("Content-Type".into(), "application/json".into()));
    }
    loon::apply_header_ops(&mut headers, &header_ops.iter().collect::<Vec<_>>());
    if status != 204 {
        // 用户规则可能删掉 Content-Length；本地响应必须有确定长度，最后补回。
        http1::set_header(&mut headers, "Content-Length", &body.len().to_string());
    }
    (status, reason.to_string(), headers, body)
}

fn reject_response(action: &RewriteAction, keep_alive: bool) -> Vec<u8> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let mut headers: Headers = vec![
        ("Connection".into(), conn.into()),
        ("Cache-Control".into(), "no-store".into()),
    ];
    let (status, reason, body): (u16, &str, &[u8]) = match action {
        RewriteAction::Reject => (204, "No Content", &[]),
        RewriteAction::Reject200 => (200, "OK", &[]),
        RewriteAction::RejectTinyGif => (200, "OK", TINY_GIF),
        _ => (204, "No Content", &[]),
    };
    if matches!(action, RewriteAction::RejectTinyGif) {
        headers.push(("Content-Type".into(), "image/gif".into()));
    }
    if status != 204 {
        headers.push(("Content-Length".into(), body.len().to_string()));
    }
    http1::serialize_response(status, reason, &headers, body)
}

/// 请求体规则命中时先缓冲请求体；返回 Some(缓冲后的正文) 表示上游必须写这份字节，
/// 不能再从客户端流式读取。返回 Err 表示超过上限，调用方应回 413 并断开。
async fn prepare_request_body<S>(
    cio: &mut Buffered<S>,
    req: &mut RequestHead,
    plan: &LoonRequestPlan,
    limit: usize,
    force: bool,
) -> io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if plan.request_mock.is_none() && plan.request_body_ops.is_empty() && !force {
        return Ok(None);
    }
    if req.body == http1::BodyKind::None && plan.request_mock.is_none() {
        return Ok(None);
    }
    let expect = http1::get_header(&req.headers, "expect")
        .map(|v| v.eq_ignore_ascii_case("100-continue"))
        .unwrap_or(false);
    if expect {
        cio.stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await?;
        cio.stream.flush().await?;
        http1::remove_header(&mut req.headers, "expect");
    }
    // 压缩请求体不猜测语义：保留原样，跳过正文改写。
    let enc = http1::get_header(&req.headers, "content-encoding")
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let encoded = !enc.is_empty() && enc != "identity";
    let original_kind = req.body;
    let original = match original_kind {
        http1::BodyKind::None => Vec::new(),
        http1::BodyKind::Length(n) if n > limit as u64 || encoded => {
            logging::info(
                "mitm",
                format!("请求体 {} 字节超过上限或带编码，跳过 Loon 请求体改写", n),
            );
            return Ok(None);
        }
        _ => http1::read_body_limited(cio, original_kind, limit).await?,
    };
    let (body, changed) = if let Some(mock) = &plan.request_mock {
        http1::set_header(&mut req.headers, "Content-Type", &mock.content_type);
        (mock.body.clone(), true)
    } else {
        let refs: Vec<&BodyOp> = plan.request_body_ops.iter().collect();
        match loon::apply_body_ops(&original, &refs, limit) {
            Some((new, changed)) => (new, changed),
            None => (original.clone(), false),
        }
    };
    http1::remove_header(&mut req.headers, "transfer-encoding");
    if changed {
        http1::remove_header(&mut req.headers, "content-encoding");
    }
    http1::set_header(&mut req.headers, "Content-Length", &body.len().to_string());
    req.body = http1::BodyKind::Length(body.len() as u64);
    Ok(Some(body))
}

/// 本地 TLS 握手错误是否只是客户端提前断开（cronet 等连接池预热后弃用）。
/// 这类断开绝不能触发 mark_bypass：一次弃连会让整个域名在 fail_open_ttl 内
/// 完全不解密，正是「B 站首页改写有时失效」的成因。证书/告警类失败优先判定，
/// 保留真正的证书绑定兜底放行语义。
fn is_client_tls_abort(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    const CERT: [&str; 6] = [
        "certificate",
        "unknown ca",
        "unknownissuer",
        "handshake failure",
        "alert",
        "decrypt",
    ];
    if CERT.iter().any(|k| m.contains(k)) {
        return false;
    }
    const ABORT: [&str; 10] = [
        "close_notify",
        "unexpected eof",
        "unexpected-eof",
        "connection reset",
        "broken pipe",
        "connection aborted",
        "connection closed",
        "not connected",
        "early eof",
        "stream closed",
    ];
    ABORT.iter().any(|k| m.contains(k))
}

fn log_conn_summary(conn_id: u64, host: &str, trace: &ConnTrace, t0: Instant) {
    let reqs = trace.reqs.load(Ordering::Relaxed);
    if reqs == 0 {
        return;
    }
    let no_rule = trace.no_rule.load(Ordering::Relaxed);
    logging::info(
        "mitm",
        format!(
            "#{} {} MITM 结束：请求 {}，无规则 {}，耗时 {}s",
            conn_id,
            host,
            reqs,
            no_rule,
            t0.elapsed().as_secs()
        ),
    );
}

/// 单条 MITM 连接的生命周期。client 是来自 TUN 协议栈的字节流（含原始 ClientHello）。
pub async fn handle<S>(
    client: S,
    host: String,
    target: Target,
    action: Action,
    ctx: Arc<Ctx>,
    state: Arc<MitmState>,
    conn_id: u64,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(ca) = state.ca.clone() else { return };
    let server_cfg = match ca.server_config_async(&host).await {
        Ok(c) => c,
        Err(e) => {
            logging::warn("mitm", format!("#{} {} 签证失败: {}", conn_id, host, e));
            return;
        }
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(client)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            // 客户端在本地 TLS 握手中途直接断开：cronet 等连接池会大量预热后弃用，
            // 这类断开与证书绑定无关。绝不能据此拉黑整个域名——否则一次弃连就让
            // 该域名在 fail_open_ttl（默认 300s）内完全不解密，表现为「改写有时失效」。
            let msg = e.to_string();
            if is_client_tls_abort(&msg) {
                ctx.stats.mitm_tls_aborted.fetch_add(1, Ordering::Relaxed);
                host_stats::record(&host, host_stats::Metric::Canceled);
                logging::info(
                    "mitm",
                    format!(
                        "#{} {} 客户端 TLS 握手中途断开（连接池弃连），按回收处理",
                        conn_id, host
                    ),
                );
                return;
            }
            state.engine.mark_bypass(&host);
            ctx.stats.mitm_failed.fetch_add(1, Ordering::Relaxed);
            host_stats::record(&host, host_stats::Metric::Failed);
            logging::warn(
                "mitm",
                format!(
                    "#{} {} 本地 TLS 握手失败（可能证书绑定），临时放行: {}",
                    conn_id, host, e
                ),
            );
            return;
        }
        Err(_) => {
            // 完成 TCP 但迟迟不做 TLS：同样多为预热/备用连接。真正的证书绑定会
            // 明确回 alert，不会静默挂死，所以超时也不拉黑域名。
            ctx.stats.mitm_tls_aborted.fetch_add(1, Ordering::Relaxed);
            host_stats::record(&host, host_stats::Metric::Canceled);
            logging::info(
                "mitm",
                format!("#{} {} TLS 握手未开始，空闲连接回收", conn_id, host),
            );
            return;
        }
    };
    ctx.stats.mitm_conns.fetch_add(1, Ordering::Relaxed);
    host_stats::record(&host, host_stats::Metric::Conn);
    let t0 = Instant::now();
    let trace = Arc::new(ConnTrace::default());
    // ALPN 协商到 h2 时走 HTTP/2 分流；HTTP/1.1 继续走原有解析/改写路径。
    if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
        let h2_res = h2::serve(
            tls,
            host.clone(),
            target,
            action,
            ctx.clone(),
            state,
            conn_id,
            trace.clone(),
        )
        .await;
        if let Err(e) = h2_res {
            ctx.stats.mitm_h2_failed.fetch_add(1, Ordering::Relaxed);
            logging::warn(
                "mitm",
                format!("#{} {} h2 连接处理失败: {}", conn_id, host, e),
            );
        }
        log_conn_summary(conn_id, &host, &trace, t0);
        return;
    }
    let mut cio = Buffered::new(tls);
    loop {
        let req =
            match tokio::time::timeout(Duration::from_secs(60), http1::read_request_head(&mut cio))
                .await
            {
                Ok(Ok(Some(r))) => r,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => {
                    logging::warn("mitm", format!("#{} {} 请求解析失败: {}", conn_id, host, e));
                    break;
                }
                Err(_) => break, // 空闲超时
            };
        let url = format!("https://{}{}", host, req.path);
        let hits = state.engine.rules_for(&url);
        if let Some(r) = hits.iter().find(|r| {
            matches!(
                r.action,
                RewriteAction::Reject | RewriteAction::Reject200 | RewriteAction::RejectTinyGif
            )
        }) {
            // 有请求体时直接关闭：不在拒绝路径上读入大上传，也避免把残留正文
            // 当成下一个请求继续解析。
            let keep_alive = req.keep_alive && req.body == http1::BodyKind::None;
            let resp = reject_response(&r.action, keep_alive);
            if cio.stream.write_all(&resp).await.is_err() {
                break;
            }
            let _ = cio.stream.flush().await;
            ctx.stats.mitm_rejected.fetch_add(1, Ordering::Relaxed);
            logging::info(
                "mitm",
                format!(
                    "#{} MITM {} {} -> REJECT",
                    conn_id,
                    host,
                    http1::redact_path(&req.path)
                ),
            );
            if !keep_alive {
                break;
            }
            continue;
        }
        let mut req = req;
        for r in hits.iter().filter(|r| r.action == RewriteAction::Header) {
            http1::set_header(&mut req.headers, &r.header_field, &r.replacement);
        }
        let body_rules: Vec<&RewriteRule> = hits
            .iter()
            .filter(|r| r.action == RewriteAction::Body)
            .copied()
            .collect();
        let loon_hits = state.engine.loon_rules_for(&url);
        let mut plan = plan_loon_request(&loon_hits, &host, &target, &mut req);
        // Surge [Header Rewrite] 默认语义是响应头；请求侧 set_header 已执行，
        // 这里再把同一条规则追加到响应侧，保持现有模块靠它改请求头的兼容行为。
        for r in hits.iter().filter(|r| r.action == RewriteAction::Header) {
            plan.response_headers.push(HeaderOp::Replace {
                name: r.header_field.clone(),
                value: r.replacement.clone(),
            });
        }
        let script_url = format!("https://{}{}", plan.host, req.path);
        let (script_disabled_req, script_disabled_resp) = script_disable_flags(
            plan.terminal.is_some(),
            plan.request_mock.is_some(),
            !plan.request_body_ops.is_empty(),
            !plan.response_body_ops.is_empty() || !body_rules.is_empty(),
        );
        let request_scripts = !script_disabled_req
            && state
                .engine
                .scripts
                .has_phase(&script_url, ScriptPhase::Request);
        let script_needs_body =
            request_scripts && state.engine.scripts.needs_request_body(&script_url);
        trace.reqs.fetch_add(1, Ordering::Relaxed);
        ctx.stats.mitm_reqs.fetch_add(1, Ordering::Relaxed);
        host_stats::record(&host, host_stats::Metric::Request);
        // 与 h2 路径一致：响应阶段规则/脚本也算命中，避免把响应体改写误报为无规则。
        let response_scripts = !script_disabled_resp
            && state
                .engine
                .scripts
                .has_phase(&script_url, ScriptPhase::Response);
        let matched = !hits.is_empty()
            || !loon_hits.is_empty()
            || request_scripts
            || response_scripts
            || !plan.response_headers.is_empty()
            || !plan.response_body_ops.is_empty()
            || plan.request_mock.is_some()
            || plan.terminal.is_some();
        if !matched {
            trace.no_rule.fetch_add(1, Ordering::Relaxed);
            ctx.stats.mitm_no_rule.fetch_add(1, Ordering::Relaxed);
            host_stats::record(&host, host_stats::Metric::NoRule);
            if !trace.noted.swap(true, Ordering::Relaxed) {
                logging::info(
                    "mitm",
                    format!(
                        "#{} {} 请求与响应均未命中规则: {}",
                        conn_id,
                        host,
                        http1::redact_path(&req.path)
                    ),
                );
            }
        }
        if let Some(term) = &plan.terminal {
            // Loon `reject` 是直接断开连接，不是返回 204；不能给客户端伪造响应。
            if matches!(term, Terminal::Reject(RejectKind::Drop)) {
                ctx.stats.mitm_rejected.fetch_add(1, Ordering::Relaxed);
                logging::info(
                    "mitm",
                    format!(
                        "#{} MITM {} {} -> Loon reject（断开）",
                        conn_id,
                        host,
                        http1::redact_path(&req.path)
                    ),
                );
                break;
            }
            // 请求可能还在上传：终端响应后不复用连接，避免残留正文污染下一请求。
            let keep_alive = req.keep_alive && req.body == http1::BodyKind::None;
            let (status, reason, headers, body) = terminal_response(
                term,
                &plan.response_headers,
                keep_alive,
                &state.engine.mock_base_dir,
            );
            if cio
                .stream
                .write_all(&http1::serialize_response(status, &reason, &headers, &body))
                .await
                .is_err()
            {
                break;
            }
            let _ = cio.stream.flush().await;
            ctx.stats.mitm_rejected.fetch_add(1, Ordering::Relaxed);
            logging::info(
                "mitm",
                format!(
                    "#{} MITM {} {} -> Loon 本地响应 {}",
                    conn_id,
                    host,
                    http1::redact_path(&req.path),
                    status
                ),
            );
            if !keep_alive {
                break;
            }
            continue;
        }
        let mut buffered_body = match prepare_request_body(
            &mut cio,
            &mut req,
            &plan,
            state.engine.body_limit,
            script_needs_body,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                logging::warn("mitm", format!("#{} 请求体改写失败: {}", conn_id, e));
                let headers: Headers = vec![
                    ("Connection".into(), "close".into()),
                    ("Content-Type".into(), "text/plain; charset=utf-8".into()),
                    ("Content-Length".into(), "22".into()),
                ];
                let _ = cio
                    .stream
                    .write_all(&http1::serialize_response(
                        413,
                        "Payload Too Large",
                        &headers,
                        b"request body too large",
                    ))
                    .await;
                let _ = cio.stream.flush().await;
                break;
            }
        };
        if request_scripts {
            if script_needs_body && buffered_body.is_none() {
                logging::info(
                    "mitm",
                    format!(
                        "#{} MITM {} {} 脚本需要正文但正文超限/带编码，跳过请求脚本",
                        conn_id,
                        host,
                        http1::redact_path(&req.path)
                    ),
                );
            } else {
                let body_now = buffered_body.as_deref().unwrap_or(&[]);
                let msg_in = request_script_message(&script_url, &req, body_now);
                let batch = state
                    .run_scripts(ScriptPhase::Request, &script_url, &msg_in)
                    .await;
                if !batch.errors.is_empty() {
                    logging::warn(
                        "mitm",
                        format!(
                            "#{} 请求脚本 {} 条，问题: {}",
                            conn_id,
                            batch.matched,
                            batch.errors.join("; ")
                        ),
                    );
                }
                if batch.aborted {
                    logging::info(
                        "mitm",
                        format!(
                            "#{} MITM {} {} -> 脚本 $done() 放弃请求并断开",
                            conn_id,
                            host,
                            http1::redact_path(&req.path)
                        ),
                    );
                    break;
                }
                if batch.short_circuit {
                    let keep_alive = req.keep_alive
                        && (req.body == http1::BodyKind::None || buffered_body.is_some());
                    if send_script_response(&mut cio, &batch.message, keep_alive)
                        .await
                        .is_ok()
                    {
                        let _ = cio.stream.flush().await;
                    }
                    ctx.stats.mitm_rewritten.fetch_add(1, Ordering::Relaxed);
                    host_stats::record(&host, host_stats::Metric::Rewritten);
                    logging::info(
                        "mitm",
                        format!(
                            "#{} MITM {} {} -> 脚本本地响应 {}",
                            conn_id,
                            host,
                            http1::redact_path(&req.path),
                            batch.message.status
                        ),
                    );
                    if !keep_alive {
                        break;
                    }
                    continue;
                }
                let mut req_try = req.clone();
                match apply_request_script(&mut req_try, &batch.message, &plan.host, &script_url) {
                    Ok(changed) => {
                        req = req_try;
                        if changed {
                            buffered_body = Some(batch.message.body_bytes().to_vec());
                            ctx.stats.mitm_rewritten.fetch_add(1, Ordering::Relaxed);
                            host_stats::record(&host, host_stats::Metric::Rewritten);
                            logging::info(
                                "mitm",
                                format!(
                                    "#{} MITM {} {} -> 请求脚本已修改",
                                    conn_id,
                                    host,
                                    http1::redact_path(&req.path)
                                ),
                            );
                        }
                    }
                    Err(e) => {
                        logging::warn("mitm", format!("#{} 请求脚本结果丢弃: {}", conn_id, e));
                    }
                }
            }
        }
        let keep = match forward(
            &mut cio,
            &plan.host,
            &plan.target,
            &action,
            &ctx,
            &state,
            &mut req,
            &body_rules,
            buffered_body.as_deref(),
            &plan.response_headers,
            &plan.response_body_ops,
            conn_id,
        )
        .await
        {
            Ok(k) => k,
            Err(e) => {
                logging::warn(
                    "mitm",
                    format!(
                        "#{} MITM {} {} 转发失败: {}",
                        conn_id,
                        host,
                        http1::redact_path(&req.path),
                        e
                    ),
                );
                let headers: Headers = vec![
                    ("Connection".into(), "close".into()),
                    ("Content-Length".into(), "0".into()),
                ];
                let _ = cio
                    .stream
                    .write_all(&http1::serialize_response(
                        502,
                        "Bad Gateway",
                        &headers,
                        &[],
                    ))
                    .await;
                let _ = cio.stream.flush().await;
                break;
            }
        };
        if !keep || !req.keep_alive {
            break;
        }
    }
    let _ = cio.stream.shutdown().await;
    log_conn_summary(conn_id, &host, &trace, t0);
}

/// 转发单个请求并按需改写响应。返回客户端连接是否可继续复用。
async fn forward<S>(
    cio: &mut Buffered<S>,
    host: &str,
    target: &Target,
    action: &Action,
    ctx: &Arc<Ctx>,
    state: &Arc<MitmState>,
    req: &mut RequestHead,
    body_rules: &[&RewriteRule],
    buffered_body: Option<&[u8]>,
    response_headers: &[HeaderOp],
    response_body_ops: &[BodyOp],
    conn_id: u64,
) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let nodes = ctx.nodes_snapshot();
    let selected = ctx.selected_snapshot();
    let dns = ctx.dns();
    let websocket = http1::is_upgrade_request(&req.headers);
    let pool_key = pool::h1_key(host, target, action, state.engine.upstream_insecure);
    let pooled = state.pool.take_h1(&pool_key);
    let conn = match pooled {
        Some(conn) => conn,
        None => {
            let raw = outbound::connect(
                action,
                &nodes,
                selected.as_deref(),
                target.clone(),
                Some(&dns),
            )
            .await?;
            let tls = outbound::tls_wrap(raw, host, state.engine.upstream_insecure).await?;
            pool::H1Conn::new(Buffered::new(Box::new(tls) as outbound::BoxStream))
        }
    };
    let mut lease = pool::H1Lease::new(state.pool.clone(), pool_key, conn);
    let up = lease.up();
    let ws_plan = if websocket {
        state.engine.ws_rules.plan(host, &req.path)
    } else {
        ws::WsPlan::default()
    };
    if ws_plan.active {
        let probe = format!("https://{}{}", host, req.path);
        if let Some(rule) = state
            .engine
            .ws_rules
            .rules
            .iter()
            .find(|r| r.url.is_match(probe.as_bytes()))
        {
            if let Some(identity) = state.engine.identity_for("ws", &rule.raw) {
                if let Some(stats) = state.engine.stats.as_ref() {
                    stats.hits.record_hit(
                        &identity,
                        host,
                        if ws_plan.block { "block" } else { "rewrite" },
                    );
                }
            }
        }
    }
    let expect_continue = http1::get_header(&req.headers, "expect")
        .map(|v| v.eq_ignore_ascii_case("100-continue"))
        .unwrap_or(false);

    // 组装上游请求：普通请求每请求独立连接（connection: close）；WebSocket
    // 保留 Upgrade 语义，101 后切换成双向透传。
    let mut headers = req.headers.clone();
    for h in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "content-length",
        "expect",
    ] {
        http1::remove_header(&mut headers, h);
    }
    http1::set_header(&mut headers, "Host", host);
    let upstream_pool = state.pool.enabled() && !websocket;
    http1::set_header(
        &mut headers,
        "Connection",
        if websocket {
            "Upgrade"
        } else if upstream_pool {
            "keep-alive"
        } else {
            "close"
        },
    );
    if ws_plan.active {
        // 帧改写只实现未压缩文本；剥掉扩展，拒绝 permessage-deflate 等协商。
        http1::remove_header(&mut headers, "sec-websocket-extensions");
        logging::info(
            "mitm",
            format!(
                "#{} WebSocket 帧改写启用，已剥离 Sec-WebSocket-Extensions（压缩/扩展降级）",
                conn_id
            ),
        );
    }
    let has_body_rewrite = !body_rules.is_empty() || !response_body_ops.is_empty();
    if has_body_rewrite && !websocket {
        // 改写路径只要可解码的编码，避免 br
        http1::set_header(&mut headers, "Accept-Encoding", "gzip, deflate, identity");
    }
    // 请求体流式转发：只保留原始组帧，不再把 8MB 以上上传读进内存。
    match req.body {
        http1::BodyKind::None => {}
        http1::BodyKind::Length(n) => {
            http1::set_header(&mut headers, "Content-Length", &n.to_string());
        }
        http1::BodyKind::Chunked => {
            http1::set_header(&mut headers, "Transfer-Encoding", "chunked");
        }
    }
    let up_req = RequestHead {
        method: req.method.clone(),
        path: req.path.clone(),
        headers,
        keep_alive: upstream_pool,
        body: req.body,
    };
    up.stream
        .write_all(&http1::serialize_request_head(&up_req))
        .await?;
    if expect_continue {
        // 客户端在等 100；先本地应答，避免它一直不发送大请求体。
        cio.stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await?;
        cio.stream.flush().await?;
    }
    if let Some(body) = buffered_body {
        up.stream.write_all(body).await?;
    } else {
        tokio::time::timeout(
            Duration::from_secs(300),
            http1::forward_request_body(cio, &mut up.stream, req.body),
        )
        .await
        .map_err(|_| outbound::io_err("上游请求体转发超时"))??;
    }
    up.stream.flush().await?;

    let head = tokio::time::timeout(Duration::from_secs(30), http1::read_response_head(up))
        .await
        .map_err(|_| outbound::io_err("上游响应头超时"))??;

    // WebSocket/HTTP Upgrade：101 后不再按 HTTP 解析，客户端与上游双向搬运。
    if head.status == 101 && http1::is_upgrade_response(&head.headers) {
        let mut h = head.headers.clone();
        http1::set_header(&mut h, "Connection", "Upgrade");
        cio.stream
            .write_all(&http1::serialize_response(
                head.status,
                &head.reason,
                &h,
                &[],
            ))
            .await?;
        // read_request_head/read_response_head 可能已把早期帧读进残留缓冲，
        // 先按方向补写，再进入纯字节双向复制。
        let client_early = std::mem::take(&mut cio.buf);
        let upstream_early = std::mem::take(&mut up.buf);
        if ws_plan.active {
            // WebSocket 长连接有独立并发闸，不占 h2 短正文改写的 2 条预算。
            let permit = state.ws_slots.clone().try_acquire_owned().ok();
            if let Some(_permit) = permit {
                logging::info(
                    "mitm",
                    format!(
                        "#{} MITM {} {} -> WebSocket 帧改写",
                        conn_id,
                        host,
                        http1::redact_path(&req.path)
                    ),
                );
                ws::relay(
                    &mut cio.stream,
                    &mut up.stream,
                    &client_early,
                    &upstream_early,
                    ws_plan,
                )
                .await?;
                return Ok(false);
            }
            logging::warn(
                "mitm",
                format!("#{} WebSocket 帧改写并发已满，本次降级为纯透传", conn_id),
            );
        }
        if !upstream_early.is_empty() {
            cio.stream.write_all(&upstream_early).await?;
        }
        if !client_early.is_empty() {
            up.stream.write_all(&client_early).await?;
        }
        cio.stream.flush().await?;
        up.stream.flush().await?;
        logging::info(
            "mitm",
            format!(
                "#{} MITM {} {} -> WebSocket 隧道",
                conn_id,
                host,
                http1::redact_path(&req.path)
            ),
        );
        let _ = tokio::io::copy_bidirectional(&mut cio.stream, &mut up.stream).await;
        return Ok(false);
    }

    let framing = http1::response_framing(&head, &req.method);
    let upstream_keep = state.pool.enabled()
        && framing != Framing::Eof
        && !http1::get_header(&head.headers, "connection")
            .map(|v| v.to_ascii_lowercase().contains("close"))
            .unwrap_or(false);
    let mut resp_headers = head.headers.clone();
    {
        let refs: Vec<&HeaderOp> = response_headers.iter().collect();
        loon::apply_header_ops(&mut resp_headers, &refs);
    }
    let limit = state.engine.body_limit;
    let ctype = http1::get_header(&resp_headers, "content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    let text_like = ctype.is_empty()
        || ["json", "text", "html", "xml", "javascript"]
            .iter()
            .any(|t| ctype.contains(t));
    let script_url = format!("https://{}{}", host, req.path);
    let binary_response_scripts = state
        .engine
        .scripts
        .has_binary_phase(&script_url, ScriptPhase::Response);
    let response_scripts = state
        .engine
        .scripts
        .has_phase(&script_url, ScriptPhase::Response);
    let has_body_work = !body_rules.is_empty() || !response_body_ops.is_empty() || response_scripts;
    let content_length = match framing {
        Framing::Length(n) => Some(n as usize),
        _ => None,
    };
    // 响应头已经改写，正文不必进缓冲：非文本大响应/超过 2 MiB 的正文直接透传。
    // 先 flush 已写出的头，再 pipe 剩余字节，保证 chunked 前缀不丢。
    let early_bypass = if has_body_work && framing != Framing::None {
        body_bypass_reason(text_like, binary_response_scripts, content_length, limit)
    } else {
        None
    };
    if let Some(reason) = early_bypass {
        ctx.stats.mitm_body_bypassed.fetch_add(1, Ordering::Relaxed);
        logging::info(
            "mitm",
            format!(
                "#{} {} {} 正文提前直通（{}，{} 字节）",
                conn_id,
                host,
                http1::redact_path(&req.path),
                match reason {
                    BodyBypass::NonText => "非文本",
                    BodyBypass::TooLarge => "超过 2MiB",
                },
                content_length
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "chunked".into())
            ),
        );
        let mut h = resp_headers.clone();
        match framing {
            Framing::Length(n) => http1::set_header(&mut h, "Content-Length", &n.to_string()),
            Framing::Chunked => http1::set_header(&mut h, "Transfer-Encoding", "chunked"),
            _ => {}
        }
        let keep = framing != Framing::Eof;
        http1::set_header(
            &mut h,
            "Connection",
            if keep && req.keep_alive {
                "keep-alive"
            } else {
                "close"
            },
        );
        cio.stream
            .write_all(&http1::serialize_response(
                head.status,
                &head.reason,
                &h,
                &[],
            ))
            .await?;
        cio.stream.flush().await?;
        match framing {
            Framing::Length(n) => up.pipe_n(&mut cio.stream, n).await?,
            Framing::Chunked => up.pipe_chunked(&mut cio.stream).await?,
            Framing::Eof => up.pipe_rest(&mut cio.stream).await?,
            Framing::None => {}
        }
        if upstream_keep {
            lease.mark_reusable();
        }
        return Ok(keep);
    }
    let can_rewrite =
        has_body_work && framing != Framing::None && (text_like || binary_response_scripts);

    if can_rewrite {
        // 先按原始组帧收字节（不解码），超限可无缝转透传。
        let (raw_body, exceeded) = match framing {
            Framing::Length(n) if n <= limit as u64 => {
                let b = tokio::time::timeout(Duration::from_secs(120), up.read_n(n as usize))
                    .await
                    .map_err(|_| outbound::io_err("上游响应体超时"))??;
                (b, false)
            }
            Framing::Chunked => {
                let (b, exceeded) = tokio::time::timeout(
                    Duration::from_secs(120),
                    up.read_chunked_raw_limit(limit),
                )
                .await
                .map_err(|_| outbound::io_err("上游响应体超时"))??;
                (b, exceeded)
            }
            _ => tokio::time::timeout(Duration::from_secs(120), up.read_to_end_limit(limit))
                .await
                .map_err(|_| outbound::io_err("上游响应体超时"))??,
        };
        if exceeded {
            // 超过改写上限：原样透传剩余字节，保持原始组帧
            let mut h = resp_headers.clone();
            http1::set_header(&mut h, "Connection", "close");
            ctx.stats.mitm_body_bypassed.fetch_add(1, Ordering::Relaxed);
            cio.stream
                .write_all(&http1::serialize_response(
                    head.status,
                    &head.reason,
                    &h,
                    &[],
                ))
                .await?;
            cio.stream.write_all(&raw_body).await?;
            cio.stream.flush().await?;
            up.pipe_rest(&mut cio.stream).await?;
            return Ok(false);
        }
        let decoded = if framing == Framing::Chunked {
            match http1::decode_chunked(&raw_body) {
                Some(d) => d,
                None => {
                    // chunked 不完整：原样透传
                    ctx.stats.mitm_body_bypassed.fetch_add(1, Ordering::Relaxed);
                    let mut h = resp_headers.clone();
                    http1::set_header(&mut h, "Connection", "close");
                    cio.stream
                        .write_all(&http1::serialize_response(
                            head.status,
                            &head.reason,
                            &h,
                            &raw_body,
                        ))
                        .await?;
                    cio.stream.flush().await?;
                    return Ok(false);
                }
            }
        } else {
            raw_body.clone()
        };
        let enc = http1::get_header(&head.headers, "content-encoding").unwrap_or("");
        match http1::decode_content_limited(&decoded, enc, limit) {
            Some(plain) => {
                // Surge [URL Rewrite] 与 Loon [Rewrite] 分开执行，互不推断语法。
                let surge_out = if body_rules.is_empty() {
                    Some((plain.clone(), false))
                } else {
                    rewrite::apply_body_rules_limited(&plain, body_rules, limit)
                };
                let loon_ops: Vec<&BodyOp> = response_body_ops.iter().collect();
                let loon_out = if loon_ops.is_empty() {
                    Some((
                        surge_out
                            .as_ref()
                            .map(|(b, _)| b.clone())
                            .unwrap_or_default(),
                        false,
                    ))
                } else {
                    let base = surge_out
                        .as_ref()
                        .map(|(b, _)| b.as_slice())
                        .unwrap_or(&plain);
                    loon::apply_body_ops(base, &loon_ops, limit)
                };
                let Some((new_body, loon_changed)) = loon_out else {
                    // 改写后超过上限：不能把放大后的正文发给客户端，回退原始响应。
                    ctx.stats.mitm_body_bypassed.fetch_add(1, Ordering::Relaxed);
                    let mut h = resp_headers.clone();
                    let keep = framing != Framing::Eof;
                    http1::set_header(
                        &mut h,
                        "Connection",
                        if keep && req.keep_alive {
                            "keep-alive"
                        } else {
                            "close"
                        },
                    );
                    cio.stream
                        .write_all(&http1::serialize_response(
                            head.status,
                            &head.reason,
                            &h,
                            &raw_body,
                        ))
                        .await?;
                    cio.stream.flush().await?;
                    return Ok(keep);
                };
                let surge_changed = surge_out.map(|(_, c)| c).unwrap_or(false);
                let mut status_out = head.status;
                let mut headers_out = resp_headers.clone();
                let mut body_out = new_body;
                let mut script_changed = false;
                if response_scripts {
                    let msg_in =
                        response_script_message(&script_url, status_out, &headers_out, &body_out);
                    let batch = state
                        .run_scripts(ScriptPhase::Response, &script_url, &msg_in)
                        .await;
                    if !batch.errors.is_empty() {
                        logging::warn(
                            "mitm",
                            format!(
                                "#{} 响应脚本 {} 条，问题: {}",
                                conn_id,
                                batch.matched,
                                batch.errors.join("; ")
                            ),
                        );
                    }
                    if batch.matched > 0 {
                        if batch.message.body_len() > limit {
                            logging::warn(
                                "mitm",
                                format!(
                                    "#{} 响应脚本输出 {} 字节超过上限，丢弃脚本结果",
                                    conn_id,
                                    batch.message.body_len()
                                ),
                            );
                        } else {
                            let body_bytes = batch.message.body_bytes().to_vec();
                            script_changed = body_bytes != body_out
                                || batch.message.status != status_out
                                || batch.message.headers != headers_out;
                            body_out = body_bytes;
                            if batch.message.status >= 100 && batch.message.status <= 599 {
                                status_out = batch.message.status;
                            }
                            headers_out = batch.message.headers.clone();
                        }
                    }
                }
                let changed = surge_changed || loon_changed || script_changed;
                let mut h = headers_out;
                for k in ["transfer-encoding", "content-encoding", "content-length"] {
                    http1::remove_header(&mut h, k);
                }
                http1::set_header(&mut h, "Content-Length", &body_out.len().to_string());
                let keep = framing != Framing::Eof;
                http1::set_header(
                    &mut h,
                    "Connection",
                    if keep && req.keep_alive {
                        "keep-alive"
                    } else {
                        "close"
                    },
                );
                let reason = if status_out == head.status {
                    head.reason.clone()
                } else {
                    "OK".to_string()
                };
                cio.stream
                    .write_all(&http1::serialize_response(
                        status_out, &reason, &h, &body_out,
                    ))
                    .await?;
                cio.stream.flush().await?;
                if changed {
                    ctx.stats.mitm_rewritten.fetch_add(1, Ordering::Relaxed);
                    host_stats::record(&host, host_stats::Metric::Rewritten);
                    logging::info(
                        "mitm",
                        format!(
                            "#{} MITM {} {} -> {} 改写 {}→{} 字节",
                            conn_id,
                            host,
                            http1::redact_path(&req.path),
                            status_out,
                            plain.len(),
                            body_out.len()
                        ),
                    );
                }
                if upstream_keep {
                    lease.mark_reusable();
                }
                return Ok(keep);
            }
            None => {
                // br 等无法解码，或解压后超过上限：原样透传（完整收到的原始字节）
                ctx.stats.mitm_body_bypassed.fetch_add(1, Ordering::Relaxed);
                let mut h = resp_headers.clone();
                let keep = framing != Framing::Eof;
                http1::set_header(
                    &mut h,
                    "Connection",
                    if keep && req.keep_alive {
                        "keep-alive"
                    } else {
                        "close"
                    },
                );
                cio.stream
                    .write_all(&http1::serialize_response(
                        head.status,
                        &head.reason,
                        &h,
                        &raw_body,
                    ))
                    .await?;
                cio.stream.flush().await?;
                if upstream_keep {
                    lease.mark_reusable();
                }
                return Ok(keep);
            }
        }
    }

    // 透传路径：不碰正文，按原始组帧搬运。
    // 用户响应头动作可能删掉 Content-Length/Transfer-Encoding；协议组帧头必须补回，
    // 否则 keep-alive 客户端无法判断正文结束。
    let mut h = resp_headers.clone();
    match framing {
        Framing::Length(n) => http1::set_header(&mut h, "Content-Length", &n.to_string()),
        Framing::Chunked => http1::set_header(&mut h, "Transfer-Encoding", "chunked"),
        _ => {}
    }
    let keep = framing != Framing::Eof;
    http1::set_header(
        &mut h,
        "Connection",
        if keep && req.keep_alive {
            "keep-alive"
        } else {
            "close"
        },
    );
    cio.stream
        .write_all(&http1::serialize_response(
            head.status,
            &head.reason,
            &h,
            &[],
        ))
        .await?;
    match framing {
        Framing::Length(n) => up.pipe_n(&mut cio.stream, n).await?,
        Framing::Chunked => up.pipe_chunked(&mut cio.stream).await?,
        Framing::Eof => up.pipe_rest(&mut cio.stream).await?,
        Framing::None => {
            cio.stream.flush().await?;
        }
    }
    if upstream_keep {
        lease.mark_reusable();
    }
    Ok(keep)
}

#[cfg(test)]
mod tls_abort_tests {
    use super::is_client_tls_abort;

    /// cronet 连接池预热后弃连：绝不能据此拉黑整个域名。
    #[test]
    fn pool_abort_is_not_cert_failure() {
        for m in [
            "peer closed connection without sending TLS close_notify: https://docs.rs/rustls",
            "unexpected eof while reading",
            "Connection reset by peer (os error 104)",
            "Broken pipe (os error 32)",
            "connection aborted",
            "connection closed",
        ] {
            assert!(is_client_tls_abort(m), "应判为弃连: {}", m);
        }
    }

    /// 真正的证书绑定/告警失败仍要保留临时放行兜底。
    #[test]
    fn real_cert_failure_keeps_bypass() {
        for m in [
            "invalid peer certificate: UnknownIssuer",
            "peer sent fatal alert: bad_certificate",
            "received fatal alert: handshake_failure",
            "decrypt error",
        ] {
            assert!(!is_client_tls_abort(m), "应判为真失败: {}", m);
        }
    }

    /// 未知错误保守起见按真失败处理，不放宽拉黑条件。
    #[test]
    fn unknown_error_is_not_abort() {
        assert!(!is_client_tls_abort("some other failure"));
    }
}

#[cfg(test)]
mod body_bypass_tests {
    use super::{body_bypass_reason, script_disable_flags, BodyBypass, BODY_PASSTHROUGH_LIMIT};

    #[test]
    fn small_text_is_buffered() {
        assert_eq!(
            body_bypass_reason(true, false, Some(64 * 1024), 8 * 1024 * 1024),
            None
        );
        assert_eq!(body_bypass_reason(true, false, None, 8 * 1024 * 1024), None);
    }

    #[test]
    fn video_is_passed_through() {
        assert_eq!(
            body_bypass_reason(false, false, Some(1024), 8 * 1024 * 1024),
            Some(BodyBypass::NonText)
        );
        assert_eq!(
            body_bypass_reason(false, false, None, 8 * 1024 * 1024),
            Some(BodyBypass::NonText)
        );
    }

    #[test]
    fn binary_script_may_consume_small_binary() {
        assert_eq!(
            body_bypass_reason(false, true, Some(1024), 8 * 1024 * 1024),
            None
        );
    }

    #[test]
    fn over_two_mib_is_passed_through_even_for_text() {
        assert_eq!(
            body_bypass_reason(
                true,
                false,
                Some(BODY_PASSTHROUGH_LIMIT + 1),
                8 * 1024 * 1024
            ),
            Some(BodyBypass::TooLarge)
        );
        assert_eq!(
            body_bypass_reason(true, false, Some(BODY_PASSTHROUGH_LIMIT), 8 * 1024 * 1024),
            None
        );
    }

    #[test]
    fn configured_smaller_limit_wins() {
        assert_eq!(
            body_bypass_reason(true, false, Some(512 * 1024 + 1), 512 * 1024),
            Some(BodyBypass::TooLarge)
        );
    }
    #[test]
    fn script_disable_table_matches_contract() {
        assert_eq!(script_disable_flags(true, false, false, false), (true, true));
        assert_eq!(script_disable_flags(false, true, false, false), (true, true));
        assert_eq!(script_disable_flags(false, false, true, false), (true, false));
        assert_eq!(script_disable_flags(false, false, false, true), (false, true));
        assert_eq!(script_disable_flags(false, false, false, false), (false, false));
    }

}
