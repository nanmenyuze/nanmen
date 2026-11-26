//! Loon / Shadowrocket 脚本运行时（QuickJS）。
//!
//! 本模块只负责“给定脚本源码和一次请求/响应，返回修改结果”。
//! MITM 接入、HTTP/1.1 与 h2 的缓冲、回退由上层负责。
//!
//! 安全边界：
//! - 专用工作线程长期持有 Runtime；每次执行只新建 Context，内存上限 32 MiB、栈上限 512 KiB；
//! - QuickJS 中断回调按墙钟超时终止死循环；
//! - `$httpClient` 只允许 http/https，默认拒绝私网/环回地址；
//! - `$persistentStore` 是进程内存储，不伪装成系统级持久化；
//! - 脚本异常/超时/多次 `$done` 都不会让隧道崩溃，调用方按失败回退。

use regex::Regex;
use rquickjs::function::Func;
use rquickjs::prelude::*;
use rquickjs::{
    ArrayBuffer, Context, Function, Null, Object, Persistent, Runtime, TypedArray, Undefined, Value,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;
pub const MAX_TIMEOUT_MS: u64 = 10_000;
pub const MEMORY_LIMIT: usize = 32 * 1024 * 1024;
pub const STACK_LIMIT: usize = 512 * 1024;
pub const HTTP_LIMIT: usize = 1024 * 1024;
pub const STORE_LIMIT: usize = 1024 * 1024;
pub const STORE_MAX_KEYS: usize = 256;
pub const MAX_HTTP_CALLS: usize = 32;
pub const MAX_LOGS: usize = 64;
pub const MAX_NOTIFICATIONS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptPhase {
    Request,
    Response,
    /// 定时/事件触发：只注入 `$request` 风格宿主对象，不需要真实 HTTP 事务。
    Cron,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptMessage {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// UTF-8 文本镜像；文本脚本读写这里。
    pub body: String,
    /// 原始正文字节；二进制脚本读写这里，文本脚本为 None。
    pub body_bytes: Option<Vec<u8>>,
}

impl ScriptMessage {
    /// 优先返回原始字节，避免二进制正文被 lossy 字符串截断。
    pub fn body_bytes(&self) -> &[u8] {
        self.body_bytes.as_deref().unwrap_or(self.body.as_bytes())
    }

    pub fn body_len(&self) -> usize {
        self.body_bytes
            .as_ref()
            .map(|b| b.len())
            .unwrap_or(self.body.len())
    }

    pub fn set_body_bytes(&mut self, bytes: Vec<u8>) {
        self.body = String::from_utf8_lossy(&bytes).into_owned();
        self.body_bytes = Some(bytes);
    }
}

fn default_script_timeout() -> u64 {
    DEFAULT_TIMEOUT_MS
}
fn default_true() -> bool {
    true
}
/// 手写 Default：derive 会把 `enable` 置成 false，等于让所有老配置脚本静默停摆。
/// 其余字段沿用 derive 口径（timeout/max_size 为 0，编译期再 clamp）。
impl Default for ScriptRuleConf {
    fn default() -> Self {
        Self {
            name: String::new(),
            phase: String::new(),
            pattern: String::new(),
            condition: String::new(),
            source: String::new(),
            arguments: HashMap::new(),
            argument_types: HashMap::new(),
            argument_values: HashMap::new(),
            cron: String::new(),
            trigger: String::new(),
            argument_text: None,
            timeout_ms: 0,
            max_size: 0,
            requires_body: false,
            binary_body_mode: false,
            meta: None,
            legacy_chain: false,
            enable: true,
            enable_param: String::new(),
        }
    }
}
fn default_script_max_size() -> usize {
    2 * 1024 * 1024
}

/// 一条脚本规则（配置/模块合并后的中间表示）。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptRuleConf {
    #[serde(default)]
    pub name: String,
    /// request | response
    #[serde(default)]
    pub phase: String,
    /// 预筛 URL 正则；空 = 不匹配（避免误执行全部流量）。
    /// 有 `condition` 时由条件树的 URL 分支重算，缺失 URL 分支时放宽为 `.*`。
    #[serde(default)]
    pub pattern: String,
    /// Loon Script v2 条件表达式（`${url} ~= /x/ && ${request.header['X']} == "1"`）。
    /// 空 = 仅按 pattern 预筛，行为与旧版一致。
    #[serde(default)]
    pub condition: String,
    /// JavaScript 正文；由外壳下载 script-path 后写入。
    #[serde(default)]
    pub source: String,
    /// `$argument` 键值（插件 [Argument] 形式）。
    #[serde(default)]
    pub arguments: HashMap<String, String>,
    /// 参数声明类型（string / number / boolean）；缺省按 string。
    #[serde(default)]
    pub argument_types: HashMap<String, String>,
    /// 运行期当前值，覆盖 `arguments` 里的默认值；改值不触发脚本重编译。
    #[serde(default)]
    pub argument_values: HashMap<String, String>,
    /// 5 段 cron 表达式；非空时 phase 由调度器置为 cron。
    #[serde(default)]
    pub cron: String,
    /// cron / network-changed / generic；空值由 cron 字段推导。
    #[serde(default)]
    pub trigger: String,
    /// Loon 单条 `argument=` 的原始字符串；非空且无 arguments 时 `$argument` 为字符串。
    #[serde(default)]
    pub argument_text: Option<String>,
    #[serde(default = "default_script_timeout", alias = "timeout_ms")]
    pub timeout_ms: u64,
    /// 单条脚本允许读写的正文上限。
    #[serde(default = "default_script_max_size", alias = "max_size")]
    pub max_size: usize,
    /// 是否必须有正文才执行（Loon `requires-body=true`）。
    #[serde(default, alias = "requires_body")]
    pub requires_body: bool,
    /// `binary-body-mode=true`：`$request/$response.body` 以 Uint8Array 暴露。
    #[serde(default, alias = "binary_body_mode")]
    pub binary_body_mode: bool,
    /// D0：稳定规则身份；缺省时由脚本名/阶段兜底。
    #[serde(default)]
    pub meta: Option<crate::hits::RuleMeta>,
    /// 模块 legacy-chain：true 时沿用 2.8 的多脚本链式执行；默认 false = Loon 首条语义。
    #[serde(default, alias = "legacy_chain")]
    pub legacy_chain: bool,
    /// Loon `enable`（缺省 true）。false 时条目仍保留在配置里供界面显示，
    /// 但不进编译结果、不参与执行，也不计"不支持"。
    #[serde(default = "default_true", alias = "enabled")]
    pub enable: bool,
    /// `enable=${name}`：启用状态由插件 [Argument] 的开关决定。编译期只记参数名，
    /// 运行时按当前值求值——用户拨开关立即生效，不必重新解析整个模块。
    #[serde(default)]
    pub enable_param: String,
}

#[derive(Clone)]
pub struct CompiledScriptRule {
    /// 运行期参数覆盖的稳定键：phase|原始 pattern|name。
    pub key: String,
    pub name: String,
    pub phase: ScriptPhase,
    /// 预筛 URL 正则；精确判定由 `cond` 完成。
    pub url: Regex,
    /// Script v2 条件树；None = 旧版仅 URL 预筛。
    pub cond: Option<crate::mitm::loon::LoonCond>,
    pub source: String,
    pub arguments: HashMap<String, String>,
    pub argument_types: HashMap<String, String>,
    pub argument_values: HashMap<String, String>,
    pub argument_text: Option<String>,
    pub cron: String,
    /// 编译期解析好的 5 段表达式；空 cron 为 None，调度器不再每轮 parse。
    pub cron_spec: Option<crate::cron::CronSpec>,
    pub trigger: String,
    pub timeout_ms: u64,
    pub max_size: usize,
    pub requires_body: bool,
    pub binary_body_mode: bool,
    pub meta: Option<crate::hits::RuleMeta>,
    pub legacy_chain: bool,
    /// `enable=${name}` 的参数名；空 = 不看参数（静态启用）。
    pub enable_param: String,
    /// 规则驱动的 MITM 作用域推导用：原始 pattern + 条件表达式全文。
    /// 条件树里常写着真正的域名，而预筛正则被放宽成 `.*`，只看正则推不出域名。
    pub scope_text: String,
}

/// 已编译脚本集合；非法正则/阶段/空源码不会进入执行列表。
#[derive(Default)]
pub struct ScriptEngine {
    pub rules: Vec<CompiledScriptRule>,
    pub unsupported: Vec<String>,
    /// Loon `disable=1` 的条目名；保留是为了让界面能显示"已禁用"，
    /// 且不与 `unsupported`（语法/能力不支持）混为一谈。
    pub disabled: Vec<String>,
    pub store: Arc<ScriptStore>,
    /// script key → 运行期当前值；只影响 `$argument` 注入，不重编译脚本。
    argument_overrides: Arc<Mutex<HashMap<String, HashMap<String, String>>>>,
}

fn script_key(phase: &str, pattern: &str, name: &str) -> String {
    format!("{}|{}|{}", phase.trim().to_ascii_lowercase(), pattern, name)
}

/// D5：Loon 默认每阶段只执行首条条件为 true 的脚本；
/// 仅当首条脚本所属模块显式开启 legacy-chain 时保留 2.8 的链式集合。
pub fn select_phase_hits(mut hits: Vec<CompiledScriptRule>) -> Vec<CompiledScriptRule> {
    if !hits.first().map(|r| r.legacy_chain).unwrap_or(false) {
        hits.truncate(1);
    }
    hits
}

impl CompiledScriptRule {
    /// 调度表键必须包含 cron 表达式：只改执行时间、不改脚本名时，旧触发时间
    /// 不能继续命中。参数覆盖仍用稳定的 `key`，不受影响。
    pub fn schedule_key(&self) -> String {
        format!("{}|cron={}", self.key, self.cron)
    }
}

impl ScriptEngine {
    pub fn from_config(confs: &[ScriptRuleConf], store_file: &str) -> Self {
        let mut rules = Vec::new();
        let mut unsupported = Vec::new();
        let mut disabled = Vec::new();
        for c in confs {
            if !c.enable {
                // Loon enable=false：脚本完全不执行。放在所有校验之前，
                // 保持"禁用优先于其他错误"的口径——一条关掉的坏脚本不该报错。
                disabled.push(if c.name.trim().is_empty() {
                    c.pattern.trim().to_string()
                } else {
                    c.name.clone()
                });
                continue;
            }
            let phase = match c.phase.trim().to_ascii_lowercase().as_str() {
                "request" => ScriptPhase::Request,
                "response" => ScriptPhase::Response,
                "cron" => ScriptPhase::Cron,
                other => {
                    unsupported.push(format!("{}: 未知阶段 {}", c.name, other));
                    continue;
                }
            };
            // cron 只在编译期解析一次，调度循环每秒复用同一份 CronSpec；否则每轮
            // 都对 `2 月 30 日` 这类无解表达式重扫 527040 分钟。
            let cron_spec = if c.cron.trim().is_empty() {
                None
            } else {
                match crate::cron::CronSpec::parse(c.cron.trim()) {
                    Some(v) => Some(v),
                    None => {
                        unsupported.push(format!("{}: cron 表达式非法: {}", c.name, c.cron));
                        continue;
                    }
                }
            };
            let cond = if c.condition.trim().is_empty() {
                None
            } else {
                match crate::mitm::loon::parse_condition(&c.condition) {
                    Some(v) => Some(v),
                    None => {
                        unsupported.push(format!(
                            "{}: Script v2 条件无法解析: {}",
                            c.name, c.condition
                        ));
                        continue;
                    }
                }
            };
            // 条件树自己给出 URL 预筛：无 URL 分支 / 顶层 || 时用 `.*` 兜底，
            // 具体是否执行交给 hits_with_headers() 的 LoonCond 求值。
            let pattern = if phase == ScriptPhase::Cron {
                ".*".to_string()
            } else {
                match &cond {
                    Some(v) => v.prefilter().unwrap_or_else(|| ".*".to_string()),
                    None => c.pattern.trim().to_string(),
                }
            };
            if pattern.is_empty() {
                unsupported.push(format!("{}: 缺少 URL 匹配正则", c.name));
                continue;
            }
            let Ok(url) = Regex::new(&pattern) else {
                unsupported.push(format!("{}: URL 正则非法", c.name));
                continue;
            };
            if c.source.trim().is_empty() {
                unsupported.push(format!("{}: 脚本正文为空", c.name));
                continue;
            }
            if c.source.len() > 4 * 1024 * 1024 {
                unsupported.push(format!("{}: 脚本正文超过 4 MiB", c.name));
                continue;
            }
            let name = if c.name.trim().is_empty() {
                pattern.clone()
            } else {
                c.name.clone()
            };
            rules.push(CompiledScriptRule {
                key: script_key(&c.phase, c.pattern.trim(), &name),
                name,
                phase,
                url,
                cond,
                source: c.source.clone(),
                arguments: c.arguments.clone(),
                argument_types: c.argument_types.clone(),
                argument_values: c.argument_values.clone(),
                argument_text: c.argument_text.clone(),
                cron: c.cron.trim().to_string(),
                cron_spec,
                trigger: c.trigger.trim().to_ascii_lowercase(),
                timeout_ms: c.timeout_ms.max(50).min(MAX_TIMEOUT_MS),
                max_size: c.max_size.clamp(4096, 8 * 1024 * 1024),
                requires_body: c.requires_body,
                binary_body_mode: c.binary_body_mode,
                meta: c.meta.clone(),
                legacy_chain: c.legacy_chain,
                enable_param: c.enable_param.trim().to_string(),
                scope_text: format!("{} {}", c.pattern.trim(), c.condition.trim()),
            });
        }
        let mut overrides = HashMap::new();
        for r in &rules {
            if !r.argument_values.is_empty() {
                overrides.insert(r.key.clone(), r.argument_values.clone());
            }
        }
        Self {
            rules,
            unsupported,
            disabled,
            store: Arc::new(ScriptStore::new(store_file)),
            argument_overrides: Arc::new(Mutex::new(overrides)),
        }
    }

    /// 更新某个脚本的运行期参数值。只换 Map，不重新解析/编译脚本；
    /// 已进入 `run_scripts` 的批次持有自己的快照，不受影响。
    pub fn set_argument_values(&self, key: &str, values: HashMap<String, String>) {
        self.argument_overrides
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key.to_string(), values);
    }

    pub fn effective_argument_values(&self, rule: &CompiledScriptRule) -> HashMap<String, String> {
        let guard = self
            .argument_overrides
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.get(&rule.key).cloned().unwrap_or_else(|| {
            let mut base = rule.arguments.clone();
            base.extend(rule.argument_values.clone());
            base
        })
    }

    /// 脚本当前是否启用。静态 `enable=false` 编译期已剔除，这里只处理
    /// `enable=${name}`：按运行期参数值求值，拨开关后下一次请求即生效。
    fn rule_enabled(&self, rule: &CompiledScriptRule) -> bool {
        if rule.enable_param.is_empty() {
            return true;
        }
        let values = self.effective_argument_values(rule);
        match values.get(&rule.enable_param).map(|v| v.trim().to_ascii_lowercase()) {
            // 参数缺失/空值时沿用默认开关，不静默停掉脚本。
            None => true,
            Some(v) => !matches!(v.as_str(), "0" | "false" | "no" | "off"),
        }
    }

    /// 预筛命中（只看 URL pattern）；has_phase/正文预算等早期判断使用。
    pub fn hits(&self, url: &str, phase: ScriptPhase) -> Vec<&CompiledScriptRule> {
        self.rules
            .iter()
            .filter(|r| r.phase == phase && r.url.is_match(url) && self.rule_enabled(r))
            .collect()
    }

    /// 精确命中：URL 预筛 + Script v2 条件树按实际请求/响应头求值。
    /// 条件为 None 时与 hits() 等价，保持旧脚本行为。
    pub fn hits_with_headers(
        &self,
        url: &str,
        phase: ScriptPhase,
        headers: &[(String, String)],
    ) -> Vec<&CompiledScriptRule> {
        self.rules
            .iter()
            .filter(|r| {
                r.phase == phase
                    && r.url.is_match(url)
                    && r.cond.as_ref().map_or(true, |c| c.matches(url, headers))
                    && self.rule_enabled(r)
            })
            .collect()
    }

    /// 按真实请求/响应求值 Script v2 条件：URL、method、status、header、body、Argument。
    pub fn hits_with_message(
        &self,
        url: &str,
        phase: ScriptPhase,
        message: &ScriptMessage,
    ) -> Vec<&CompiledScriptRule> {
        self.rules
            .iter()
            .filter(|r| {
                if r.phase != phase || !r.url.is_match(url) || !self.rule_enabled(r) {
                    return false;
                }
                let Some(cond) = &r.cond else { return true };
                let mut args = r.arguments.clone();
                for (k, v) in &r.argument_values {
                    if args.contains_key(k) || r.argument_types.contains_key(k) {
                        args.insert(k.clone(), v.clone());
                    }
                }
                let empty: [(String, String); 0] = [];
                let ctx = crate::mitm::loon::LoonMatch {
                    url,
                    method: &message.method,
                    status: message.status,
                    request_headers: if phase == ScriptPhase::Request {
                        &message.headers
                    } else {
                        &empty
                    },
                    response_headers: if phase == ScriptPhase::Response {
                        &message.headers
                    } else {
                        &empty
                    },
                    request_body: if phase == ScriptPhase::Request {
                        message.body.as_bytes()
                    } else {
                        &[]
                    },
                    response_body: if phase == ScriptPhase::Response {
                        message.body.as_bytes()
                    } else {
                        &[]
                    },
                    arguments: &args,
                };
                cond.matches_ctx(&ctx)
            })
            .collect()
    }

    pub fn needs_request_body(&self, url: &str) -> bool {
        self.hits(url, ScriptPhase::Request).iter().any(|r| {
            r.requires_body
                || r.binary_body_mode
                || r.cond
                    .as_ref()
                    .map(|c| c.needs_request_body())
                    .unwrap_or(false)
        })
    }

    pub fn has_phase(&self, url: &str, phase: ScriptPhase) -> bool {
        !self.hits(url, phase).is_empty()
    }

    /// 该 URL/阶段是否有二进制正文脚本；MITM 据此放行 gRPC/非文本正文。
    pub fn has_binary_phase(&self, url: &str, phase: ScriptPhase) -> bool {
        self.hits(url, phase).iter().any(|r| r.binary_body_mode)
    }
}

#[derive(Clone, Default)]
pub struct ScriptOptions {
    pub timeout_ms: u64,
    pub allow_private_network: bool,
    pub arguments: HashMap<String, String>,
    pub argument_types: HashMap<String, String>,
    /// 运行期覆盖值；只与 argument_types 声明的键合并，不做源码字符串替换。
    pub argument_values: HashMap<String, String>,
    pub argument_text: Option<String>,
    pub store: Option<Arc<ScriptStore>>,
    /// 当前脚本名，供 `$script.name` 和默认存储 key 使用。
    pub script_name: String,
    /// 二进制正文模式：`$request/$response.body` 以 Uint8Array 暴露。
    pub binary_body_mode: bool,
    /// `$environment` 字段：app/appVersion/system/device/language/timezone 等。
    pub environment: HashMap<String, String>,
    /// `$notification` 系统通知队列（JSONL）；空 = 只保留诊断。
    pub notification_file: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptNotification {
    pub title: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub script: String,
}

#[derive(Debug, Clone, Default)]
pub struct ScriptBatchResult {
    pub message: ScriptMessage,
    pub matched: usize,
    pub skipped: bool,
    pub short_circuit: bool,
    /// Loon `$done()`：放弃请求并断开；仅 http 阶段。
    pub aborted: bool,
    pub done_calls: usize,
    pub http_calls: usize,
    pub timed_out: bool,
    pub errors: Vec<String>,
    pub logs: Vec<String>,
    pub notifications: Vec<String>,
    pub notification_items: Vec<ScriptNotification>,
}

#[derive(Debug, Clone, Default)]
pub struct ScriptOutcome {
    pub message: ScriptMessage,
    pub short_circuit_response: bool,
    /// `$done()` 无参数：放弃请求并断开。
    pub aborted: bool,
    pub done_calls: usize,
    pub http_calls: usize,
    pub notifications: Vec<String>,
    pub notification_items: Vec<ScriptNotification>,
    pub logs: Vec<String>,
    pub error: Option<String>,
    pub timed_out: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum DoneKind {
    #[default]
    None,
    /// `$done()` / `$done(undefined)`：放弃请求断开（cron/generic 为正常结束）。
    Abort,
    /// `$done({})`：透传。
    Pass,
    /// `$done({response: ...})`：请求阶段终止响应。
    Response,
    /// `$done({url/headers/body/status...})`：改包后继续。
    Modified,
}

#[derive(Debug, Clone)]
struct DoneState {
    called: bool,
    kind: DoneKind,
    calls: usize,
    url: Option<String>,
    method: Option<String>,
    status: Option<u16>,
    headers: Option<Vec<(String, String)>>,
    body: Option<String>,
    body_bytes: Option<Vec<u8>>,
    nested_response: bool,
}

impl Default for DoneState {
    fn default() -> Self {
        Self {
            called: false,
            kind: DoneKind::None,
            calls: 0,
            url: None,
            method: None,
            status: None,
            headers: None,
            body: None,
            body_bytes: None,
            nested_response: false,
        }
    }
}

struct TimerEntry {
    at: Instant,
    cb: Persistent<Function<'static>>,
}

struct HttpOutcome {
    id: u64,
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    error: Option<String>,
}

struct HttpQueue {
    tx: std::sync::mpsc::Sender<HttpOutcome>,
    rx: Mutex<std::sync::mpsc::Receiver<HttpOutcome>>,
}

impl HttpQueue {
    fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            tx,
            rx: Mutex::new(rx),
        }
    }
}

struct RuntimeStats {
    http_calls: AtomicUsize,
    http_queue: HttpQueue,
    pending_http: Mutex<HashMap<u64, Persistent<Function<'static>>>>,
    next_http_id: std::sync::atomic::AtomicU64,
    notifications: Mutex<Vec<String>>,
    notification_items: Mutex<Vec<ScriptNotification>>,
    logs: Mutex<Vec<String>>,
}

impl RuntimeStats {
    fn new() -> Self {
        Self {
            http_calls: AtomicUsize::new(0),
            http_queue: HttpQueue::new(),
            pending_http: Mutex::new(HashMap::new()),
            next_http_id: std::sync::atomic::AtomicU64::new(0),
            notifications: Mutex::new(Vec::new()),
            notification_items: Mutex::new(Vec::new()),
            logs: Mutex::new(Vec::new()),
        }
    }
}

/// 进程内 + 可选文件落盘的脚本存储。每个 MitmEngine 持有独立实例，
/// 避免测试/多实例互相污染；写入后立即原子落盘。
pub struct ScriptStore {
    file: Option<PathBuf>,
    map: Mutex<HashMap<String, String>>,
}

impl Default for ScriptStore {
    fn default() -> Self {
        Self::new("")
    }
}

impl ScriptStore {
    pub fn new(path: &str) -> Self {
        let file = if path.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(path.trim()))
        };
        let map = file
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self {
            file,
            map: Mutex::new(map),
        }
    }

    pub fn read(&self, key: &str) -> Option<String> {
        self.map.lock().unwrap().get(key).cloned()
    }

    pub fn remove(&self, key: &str) -> bool {
        let removed = self.map.lock().unwrap().remove(key).is_some();
        if removed {
            self.persist();
        }
        removed
    }

    pub fn clear(&self) -> bool {
        self.map.lock().unwrap().clear();
        self.persist();
        true
    }

    pub fn write(&self, value: String, key: String) -> bool {
        let previous;
        {
            let mut map = self.map.lock().unwrap();
            if !map.contains_key(&key) && map.len() >= STORE_MAX_KEYS {
                return false;
            }
            previous = map.insert(key.clone(), value);
            let over = serde_json::to_string(&*map)
                .map(|t| t.len() > STORE_LIMIT)
                .unwrap_or(true);
            if over {
                match previous {
                    Some(v) => {
                        map.insert(key, v);
                    }
                    None => {
                        map.remove(&key);
                    }
                }
                return false;
            }
        }
        self.persist();
        true
    }

    fn persist(&self) {
        let Some(path) = &self.file else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let Ok(text) = serde_json::to_string(&*self.map.lock().unwrap()) else {
            return;
        };
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn md5_hex(s: &str) -> String {
    use md5::{Digest, Md5};
    hex_digest(&Md5::digest(s.as_bytes()))
}

fn sha1_hex(s: &str) -> String {
    use sha1::{Digest, Sha1};
    hex_digest(&Sha1::digest(s.as_bytes()))
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex_digest(&Sha256::digest(s.as_bytes()))
}

fn hmac_sha256_hex(key: &str, msg: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    hex_digest(&mac.finalize().into_bytes())
}

fn b64_encode(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn b64_decode(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn append_notification_queue(options: &ScriptOptions, items: &[ScriptNotification]) {
    let path = options.notification_file.trim();
    if path.is_empty() || items.is_empty() {
        return;
    }
    use std::io::Write as _;
    let p = std::path::Path::new(path);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let rotate = std::fs::metadata(p)
        .map(|m| m.len() > 256 * 1024)
        .unwrap_or(false);
    let mut f = if rotate {
        std::fs::File::create(p)
    } else {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
    }
    .ok()
    .unwrap_or_else(|| std::fs::File::create(p).expect("notification queue path"));
    for item in items {
        let mut item = item.clone();
        if item.script.is_empty() {
            item.script = options.script_name.clone();
        }
        if let Ok(line) = serde_json::to_string(&item) {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn value_string(v: &Value<'_>) -> Option<String> {
    if v.is_undefined() || v.is_null() {
        return None;
    }
    v.as_string().and_then(|s| s.to_string().ok())
}

fn object_headers(obj: &Object<'_>) -> Vec<(String, String)> {
    obj.props::<String, String>()
        .filter_map(|p| p.ok())
        .collect()
}

fn object_string(obj: &Object<'_>, key: &str) -> Option<String> {
    obj.get::<_, Value>(key).ok().and_then(|v| value_string(&v))
}

fn object_u16(obj: &Object<'_>, key: &str) -> Option<u16> {
    obj.get::<_, Value>(key)
        .ok()
        .and_then(|v| v.as_int().or_else(|| v.as_float().map(|f| f as i32)))
        .and_then(|n| u16::try_from(n).ok())
}

fn object_u64(obj: &Object<'_>, key: &str) -> Option<u64> {
    obj.get::<_, Value>(key).ok().and_then(|v| {
        v.as_int()
            .map(|n| n as u64)
            .or_else(|| v.as_float().map(|f| f as u64))
    })
}

fn object_headers_value(obj: &Object<'_>, key: &str) -> Option<Vec<(String, String)>> {
    let v = obj.get::<_, Value>(key).ok()?;
    // Loon/小火箭也接受 [["name","value"], ...] 或 [{name,value}, ...] 数组形式。
    // 必须先判断数组：JS 数组也是 object，不能先走 object_headers。
    if let Some(arr) = v.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr.iter::<Value>() {
            let Ok(item) = item else { continue };
            if let Some(pair) = item.as_array() {
                let k = pair.get::<Value>(0).ok().and_then(|v| value_string(&v));
                let val = pair.get::<Value>(1).ok().and_then(|v| value_string(&v));
                if let (Some(k), Some(val)) = (k, val) {
                    out.push((k, val));
                }
            } else if let Some(o) = item.as_object() {
                let k = object_string(o, "name").or_else(|| object_string(o, "key"));
                let val = object_string(o, "value");
                if let (Some(k), Some(val)) = (k, val) {
                    out.push((k, val));
                }
            }
        }
        return Some(out);
    }
    if let Some(h) = v.as_object() {
        return Some(object_headers(h));
    }
    None
}

fn value_bytes(v: &Value<'_>) -> Option<Vec<u8>> {
    if let Some(s) = value_string(v) {
        return Some(s.into_bytes());
    }
    if let Some(ta) = TypedArray::<u8>::from_value(v.clone()).ok() {
        let bytes: &[u8] = ta.as_ref();
        return Some(bytes.to_vec());
    }
    if let Some(ab) = ArrayBuffer::from_value(v.clone()) {
        if let Ok(slice) = ab.as_slice::<u8>() {
            return Some(slice.to_vec());
        }
    }
    if let Some(arr) = v.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr.iter::<Value>() {
            let Ok(item) = item else { return None };
            let n = item.as_int()?;
            if !(0..=255).contains(&n) {
                return None;
            }
            out.push(n as u8);
        }
        return Some(out);
    }
    None
}

fn abort_done_state() -> DoneState {
    DoneState {
        called: true,
        kind: DoneKind::Abort,
        calls: 1,
        ..Default::default()
    }
}

fn parse_done_value(value: &Value<'_>) -> DoneState {
    let mut d = DoneState {
        called: true,
        calls: 1,
        ..Default::default()
    };
    if value.is_undefined() || value.is_null() {
        d.kind = DoneKind::Abort;
        return d;
    }
    let Some(obj) = value.as_object() else {
        // 非对象参数按 Loon 的口径视为放弃请求，避免把 `$done("x")` 当成透传。
        d.kind = DoneKind::Abort;
        return d;
    };
    d.kind = DoneKind::Pass;
    d.url = object_string(obj, "url");
    d.method = object_string(obj, "method");
    d.status = object_u16(obj, "status").or_else(|| object_u16(obj, "statusCode"));
    d.headers = object_headers_value(obj, "headers");
    if let Ok(v) = obj.get::<_, Value>("body") {
        d.body = value_string(&v);
        d.body_bytes = value_bytes(&v);
    }
    if let Ok(v) = obj.get::<_, Value>("bodyBytes") {
        if let Some(bytes) = value_bytes(&v) {
            d.body_bytes = Some(bytes);
        }
    }
    if let Ok(v) = obj.get::<_, Value>("response") {
        if let Some(resp) = v.as_object() {
            d.kind = DoneKind::Response;
            d.nested_response = true;
            d.status = object_u16(resp, "status").or_else(|| object_u16(resp, "statusCode"));
            d.headers = object_headers_value(resp, "headers");
            if let Ok(v) = resp.get::<_, Value>("body") {
                d.body = value_string(&v);
                d.body_bytes = value_bytes(&v);
            }
            if let Ok(v) = resp.get::<_, Value>("bodyBytes") {
                if let Some(bytes) = value_bytes(&v) {
                    d.body_bytes = Some(bytes);
                }
            }
        }
    }
    if d.kind == DoneKind::Pass
        && (d.url.is_some()
            || d.method.is_some()
            || d.status.is_some()
            || d.headers.is_some()
            || d.body.is_some()
            || d.body_bytes.is_some())
    {
        d.kind = DoneKind::Modified;
    }
    d
}

fn js_request<'js>(
    ctx: &rquickjs::Ctx<'js>,
    msg: &ScriptMessage,
    binary: bool,
) -> rquickjs::Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("url", msg.url.clone())?;
    obj.set("method", msg.method.clone())?;
    if binary {
        obj.set(
            "body",
            TypedArray::<u8>::new(ctx.clone(), msg.body_bytes().to_vec())?,
        )?;
    } else {
        obj.set("body", msg.body.clone())?;
    }
    let headers = Object::new(ctx.clone())?;
    for (k, v) in &msg.headers {
        headers.set(k.as_str(), v.as_str())?;
    }
    obj.set("headers", headers)?;
    Ok(obj)
}

fn js_response<'js>(
    ctx: &rquickjs::Ctx<'js>,
    msg: &ScriptMessage,
    binary: bool,
) -> rquickjs::Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("status", msg.status)?;
    obj.set("statusCode", msg.status)?;
    if binary {
        obj.set(
            "body",
            TypedArray::<u8>::new(ctx.clone(), msg.body_bytes().to_vec())?,
        )?;
    } else {
        obj.set("body", msg.body.clone())?;
    }
    let headers = Object::new(ctx.clone())?;
    for (k, v) in &msg.headers {
        headers.set(k.as_str(), v.as_str())?;
    }
    obj.set("headers", headers)?;
    Ok(obj)
}

fn read_message(obj: &Object<'_>, base: &ScriptMessage, phase: ScriptPhase) -> ScriptMessage {
    let mut m = base.clone();
    if let Some(v) = object_string(obj, "url") {
        m.url = v;
    }
    if let Some(v) = object_string(obj, "method") {
        m.method = v;
    }
    if let Ok(v) = obj.get::<_, Value>("body") {
        if v.is_string() {
            if let Some(s) = value_string(&v) {
                if s != m.body {
                    m.body = s;
                    m.body_bytes = None;
                }
            }
        } else if let Some(bytes) = value_bytes(&v) {
            m.set_body_bytes(bytes);
        }
    }
    if let Some(h) = object_headers_value(obj, "headers") {
        m.headers = h;
    }
    if phase == ScriptPhase::Response {
        if let Some(s) = object_u16(obj, "status").or_else(|| object_u16(obj, "statusCode")) {
            m.status = s;
        }
    }
    m
}

fn apply_done(base: &ScriptMessage, done: &DoneState, phase: ScriptPhase) -> ScriptMessage {
    let mut m = base.clone();
    if let Some(v) = &done.url {
        m.url = v.clone();
    }
    if let Some(v) = &done.method {
        m.method = v.clone();
    }
    if let Some(bytes) = &done.body_bytes {
        m.set_body_bytes(bytes.clone());
    } else if let Some(v) = &done.body {
        if v != &m.body {
            m.body = v.clone();
            m.body_bytes = None;
        }
    }
    if let Some(h) = &done.headers {
        m.headers = h.clone();
    }
    if phase == ScriptPhase::Response {
        if let Some(s) = done.status {
            m.status = s;
        }
    }
    m
}

fn private_host(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h == "::1" {
        return true;
    }
    let Ok(ip) = h.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

const DEFAULT_HTTP_TIMEOUT_MS: u64 = 4_000;
const MAX_HTTP_TIMEOUT_MS: u64 = 10_000;

/// 独立的短任务 runtime：$httpClient 走真正的异步 reqwest，
/// 不占 MITM 的 tokio worker；脚本线程只在完成队列上等待。
fn http_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("namu-script-http")
            .enable_all()
            .build()
            .expect("创建脚本 HTTP runtime 失败")
    })
}

fn http_client(allow_private: bool) -> &'static reqwest::Client {
    static PUBLIC: OnceLock<reqwest::Client> = OnceLock::new();
    static PRIVATE: OnceLock<reqwest::Client> = OnceLock::new();
    let make = || {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 3 {
                    attempt.stop()
                } else if !allow_private
                    && attempt.url().host_str().map(private_host).unwrap_or(true)
                {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .expect("创建脚本 HTTP client 失败")
    };
    if allow_private {
        PRIVATE.get_or_init(make)
    } else {
        PUBLIC.get_or_init(make)
    }
}

async fn http_get_async(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    allow_private: bool,
    timeout: Duration,
) -> Result<(u16, Vec<(String, String)>, String), String> {
    let u = url::Url::parse(url).map_err(|e| format!("URL 无效: {e}"))?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err("只允许 http/https".into());
    }
    let host = u.host_str().ok_or("URL 缺少 host")?;
    if !allow_private && private_host(host) {
        return Err("默认禁止访问私网/环回地址".into());
    }
    let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
    let mut req = http_client(allow_private).request(m, u).timeout(timeout);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    if let Some(b) = body {
        req = req.body(b.to_string());
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let hs = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > HTTP_LIMIT {
        return Err("响应超过 1 MiB".into());
    }
    Ok((status, hs, String::from_utf8_lossy(&bytes).into_owned()))
}

fn make_http_function<'js>(
    ctx: &rquickjs::Ctx<'js>,
    method: &'static str,
    allow_private: bool,
    stats: Arc<RuntimeStats>,
) -> rquickjs::Result<Function<'js>> {
    let f = Function::new(
        ctx.clone(),
        move |ctx: rquickjs::Ctx<'js>, a: Value<'js>, b: Opt<Value<'js>>, c: Opt<Value<'js>>| {
            let mut url = String::new();
            let mut headers: Vec<(String, String)> = Vec::new();
            let mut body: Option<String> = None;
            let mut cb: Option<Function<'js>> = None;
            let mut timeout_ms = DEFAULT_HTTP_TIMEOUT_MS;
            let first = &a;
            if let Some(obj) = first.as_object() {
                url = object_string(obj, "url").unwrap_or_default();
                headers = object_headers_value(obj, "headers").unwrap_or_default();
                body = object_string(obj, "body");
                if let Some(n) = object_u64(obj, "timeout").or_else(|| object_u64(obj, "timeoutMs"))
                {
                    // Loon 的 timeout 通常是秒；大于 60 的值按毫秒处理。
                    timeout_ms = if n <= 60 { n.saturating_mul(1000) } else { n };
                }
            } else if let Some(s) = value_string(first) {
                url = s;
            }
            let mut candidates = Vec::new();
            if let Some(v) = b.0 {
                candidates.push(v);
            }
            if let Some(v) = c.0 {
                candidates.push(v);
            }
            for v in candidates {
                if let Some(f) = v.as_function() {
                    cb = Some(f.clone());
                } else if body.is_none() {
                    body = value_string(&v);
                }
            }
            let calls = stats.http_calls.fetch_add(1, Ordering::Relaxed);
            if calls >= MAX_HTTP_CALLS {
                if let Some(cb) = cb {
                    let _ = cb.call::<_, ()>((
                        format!("单次脚本 $httpClient 调用超过 {MAX_HTTP_CALLS} 次"),
                        Undefined,
                        Undefined,
                    ));
                }
                return;
            }
            let timeout = Duration::from_millis(timeout_ms.clamp(50, MAX_HTTP_TIMEOUT_MS));
            let id = stats.next_http_id.fetch_add(1, Ordering::Relaxed);
            let tx = stats.http_queue.tx.clone();
            let method_owned = method.to_string();
            http_runtime().spawn(async move {
                let outcome = match http_get_async(
                    &method_owned,
                    &url,
                    &headers,
                    body.as_deref(),
                    allow_private,
                    timeout,
                )
                .await
                {
                    Ok((status, headers, body)) => HttpOutcome {
                        id,
                        status,
                        headers,
                        body,
                        error: None,
                    },
                    Err(e) => HttpOutcome {
                        id,
                        status: 0,
                        headers: Vec::new(),
                        body: String::new(),
                        error: Some(e),
                    },
                };
                let _ = tx.send(outcome);
            });
            if let Some(cb) = cb {
                let saved = Persistent::save(&ctx, cb);
                stats.pending_http.lock().unwrap().insert(id, saved);
            }
        },
    )?;
    Ok(f)
}

/// 等待异步 HTTP 完成并在脚本上下文里调用回调。每次回调后继续驱动微任务，
/// 允许回调里再发请求或 Promise 续体继续执行。
fn drain_http(
    context: &Context,
    rt: &Runtime,
    stats: &RuntimeStats,
    deadline: Instant,
) -> Option<String> {
    loop {
        drain_jobs(rt, deadline);
        if stats.pending_http.lock().unwrap().is_empty() {
            return None;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Some("脚本等待 $httpClient 回调超时".into());
        }
        let outcome = {
            let rx = stats.http_queue.rx.lock().unwrap();
            rx.recv_timeout(remaining)
        };
        let outcome = match outcome {
            Ok(v) => v,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Some("脚本等待 $httpClient 回调超时".into())
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Some("脚本 HTTP 完成队列已断开".into())
            }
        };
        let cb = stats.pending_http.lock().unwrap().remove(&outcome.id);
        let Some(cb) = cb else { continue };
        let call_res = context.with(|ctx| {
            let cb = cb.restore(&ctx).map_err(|_| rquickjs::Error::Unknown)?;
            if let Some(e) = &outcome.error {
                cb.call::<_, ()>((e.as_str(), Undefined, Undefined))
            } else {
                let resp = Object::new(ctx.clone())?;
                resp.set("status", outcome.status)?;
                resp.set("statusCode", outcome.status)?;
                let hobj = Object::new(ctx.clone())?;
                for (k, v) in &outcome.headers {
                    hobj.set(k.as_str(), v.as_str())?;
                }
                resp.set("headers", hobj)?;
                cb.call::<_, ()>((Null, resp, outcome.body.as_str()))
            }
        });
        if let Err(e) = call_res {
            return Some(format!("$httpClient 回调失败: {e}"));
        }
        drain_jobs(rt, deadline);
    }
}

/// 执行一次请求或响应脚本。
///
/// `message` 是进入脚本时的请求/响应快照；`phase` 决定 `$request` 与 `$response`
/// 哪个对象可写。返回的 `message` 是脚本完成后的结果；`short_circuit_response`
pub fn run_script(
    source: &str,
    phase: ScriptPhase,
    message: &ScriptMessage,
    options: &ScriptOptions,
) -> ScriptOutcome {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return ScriptOutcome {
                message: message.clone(),
                error: Some(format!("QuickJS Runtime 创建失败: {e}")),
                ..Default::default()
            };
        }
    };
    run_script_with_runtime(&rt, source, phase, message, options)
}

/// 在 ctx.with 之外驱动 QuickJS 微任务队列（Promise/async 续体）。
/// 受墙钟 deadline 约束；超时由中断回调兜底，异常或队列清空即停。
fn drain_jobs(rt: &Runtime, deadline: Instant) {
    while rt.is_job_pending() && Instant::now() < deadline {
        match rt.execute_pending_job() {
            Ok(true) => {}
            _ => break,
        }
    }
}

/// 在调用线程已有的 Runtime 上执行一次脚本。
///
/// `rquickjs::Runtime` 不能跨线程使用；专用工作线程创建并长期持有它，
/// 每次执行只新建 Context，避免重复初始化 Runtime。
fn run_script_with_runtime(
    rt: &Runtime,
    source: &str,
    phase: ScriptPhase,
    message: &ScriptMessage,
    options: &ScriptOptions,
) -> ScriptOutcome {
    let mut out = ScriptOutcome {
        message: message.clone(),
        ..Default::default()
    };
    let timeout = Duration::from_millis(options.timeout_ms.max(50).min(MAX_TIMEOUT_MS));
    let started = Instant::now();
    rt.set_memory_limit(MEMORY_LIMIT);
    rt.set_max_stack_size(STACK_LIMIT);
    let timers: Arc<Mutex<Vec<TimerEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let deadline = started + timeout;
    let finished = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    let finished_flag = finished.clone();
    let interrupted_flag = interrupted.clone();
    rt.set_interrupt_handler(Some(Box::new(move || {
        if !finished_flag.load(Ordering::Relaxed) && Instant::now() >= deadline {
            interrupted_flag.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    })));

    let done = Arc::new(Mutex::new(DoneState::default()));
    let stats = Arc::new(RuntimeStats::new());
    let mut evaluated = message.clone();
    let mut short_circuit = false;
    let mut aborted = false;
    let mut eval_error: Option<String> = None;
    let context = match Context::full(rt) {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(format!("脚本执行失败: {e}"));
            return out;
        }
    };
    let mut req_p: Option<Persistent<Object<'static>>> = None;
    let mut resp_p: Option<Persistent<Object<'static>>> = None;
    // 阶段1：注入宿主对象并求值。微任务驱动必须在 ctx.with 之外
    // （rquickjs 的 Runtime 与 Context 共享 safe_ref，闭包内调 rt 方法会重复借用 panic）。
    let setup_res = context.with(|ctx| {
        let globals = ctx.globals();
        let req_obj = js_request(&ctx, message, options.binary_body_mode)?;
        let resp_obj = if phase == ScriptPhase::Response {
            Some(js_response(&ctx, message, options.binary_body_mode)?)
        } else {
            None
        };
        req_p = Some(Persistent::save(&ctx, req_obj.clone()));
        if let Some(r) = &resp_obj {
            resp_p = Some(Persistent::save(&ctx, r.clone()));
        }
        globals.set("$request", req_obj.clone())?;
        if let Some(r) = &resp_obj {
            globals.set("$response", r.clone())?;
        }
        let mut effective = options.arguments.clone();
        for (k, v) in &options.argument_values {
            if effective.contains_key(k) || options.argument_types.contains_key(k) {
                effective.insert(k.clone(), v.clone());
            }
        }
        if effective.is_empty() {
            match options.argument_text.as_deref() {
                Some(text) if !text.is_empty() => globals.set("$argument", text)?,
                _ => globals.set("$argument", Undefined)?,
            }
        } else {
            let args = Object::new(ctx.clone())?;
            for (k, v) in &effective {
                // Loon [Argument] 声明类型：number/boolean 必须按真类型注入，
                // 否则脚本里 `$argument.price > 5`、`$argument.enabled === true` 全部失效。
                match options
                    .argument_types
                    .get(k)
                    .map(|t| t.as_str())
                    .unwrap_or("string")
                {
                    "number" => match v.trim().parse::<f64>() {
                        Ok(n) => args.set(k.as_str(), n)?,
                        Err(_) => args.set(k.as_str(), v.as_str())?,
                    },
                    "boolean" => {
                        let b = matches!(
                            v.trim().to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes" | "on"
                        );
                        args.set(k.as_str(), b)?
                    }
                    _ => args.set(k.as_str(), v.as_str())?,
                }
            }
            globals.set("$argument", args)?;
        }
        let script_obj = Object::new(ctx.clone())?;
        script_obj.set("name", options.script_name.clone())?;
        globals.set("$script", script_obj)?;
        let env_obj = Object::new(ctx.clone())?;
        for (k, v) in &options.environment {
            env_obj.set(k.as_str(), v.as_str())?;
        }
        globals.set("$environment", env_obj)?;
        let utils = Object::new(ctx.clone())?;
        utils.set(
            "getByteLength",
            Func::from(|s: String| s.as_bytes().len() as u32),
        )?;
        utils.set("base64Encode", Func::from(|s: String| b64_encode(&s)))?;
        utils.set("base64Decode", Func::from(|s: String| b64_decode(&s)))?;
        utils.set("md5", Func::from(|s: String| md5_hex(&s)))?;
        utils.set("sha1", Func::from(|s: String| sha1_hex(&s)))?;
        utils.set("sha256", Func::from(|s: String| sha256_hex(&s)))?;
        utils.set(
            "hmacSha256",
            Func::from(|key: String, msg: String| hmac_sha256_hex(&key, &msg)),
        )?;
        utils.set(
            "unescape",
            Func::from(|s: String| {
                percent_encoding::percent_decode_str(&s)
                    .decode_utf8_lossy()
                    .into_owned()
            }),
        )?;
        utils.set(
            "escape",
            Func::from(|s: String| {
                percent_encoding::utf8_percent_encode(&s, percent_encoding::NON_ALPHANUMERIC)
                    .to_string()
            }),
        )?;
        globals.set("$utils", utils)?;
        ctx.eval::<(), _>(
            r#"
                $utils.geoLookup = function(ip) {
                  return {ip: String(ip || ""), country: "", province: "", city: "", isp: ""};
                };
                $utils.getNetworkInfo = function() {
                  return {type: "unknown", cellular: {}, wifi: {}};
                };
            "#,
        )?;
        // require 只暴露内置纯函数模块，不开放文件系统/网络/进程能力。
        let modules = Object::new(ctx.clone())?;
        let crypto = Object::new(ctx.clone())?;
        crypto.set("md5", Func::from(|s: String| md5_hex(&s)))?;
        crypto.set("sha1", Func::from(|s: String| sha1_hex(&s)))?;
        crypto.set("sha256", Func::from(|s: String| sha256_hex(&s)))?;
        crypto.set(
            "hmacSha256",
            Func::from(|key: String, msg: String| hmac_sha256_hex(&key, &msg)),
        )?;
        modules.set("crypto", crypto)?;
        let b64 = Object::new(ctx.clone())?;
        b64.set("encode", Func::from(|s: String| b64_encode(&s)))?;
        b64.set("decode", Func::from(|s: String| b64_decode(&s)))?;
        modules.set("base64", b64)?;
        let util = Object::new(ctx.clone())?;
        util.set(
            "getByteLength",
            Func::from(|s: String| s.as_bytes().len() as u32),
        )?;
        util.set("base64Encode", Func::from(|s: String| b64_encode(&s)))?;
        util.set("base64Decode", Func::from(|s: String| b64_decode(&s)))?;
        util.set("md5", Func::from(|s: String| md5_hex(&s)))?;
        util.set("sha256", Func::from(|s: String| sha256_hex(&s)))?;
        modules.set("util", util)?;
        globals.set("__namuModules", modules)?;
        ctx.eval::<(), _>(
            r#"
                globalThis.require = (function(mods) {
                  return function(name) {
                    name = String(name || "").replace(/^node:/, "");
                    const m = mods[name];
                    if (!m) throw new Error("require: 不支持的内置模块 " + name);
                    return m;
                  };
                })(__namuModules);
                delete globalThis.__namuModules;
            "#,
        )?;
        // 不可信第三方脚本：默认不给动态求值入口，能力只走白名单宿主函数。
        globals.set("eval", Undefined)?;
        globals.set("Function", Undefined)?;
        let ps = Object::new(ctx.clone())?;
        let store = options
            .store
            .clone()
            .unwrap_or_else(|| Arc::new(ScriptStore::new("")));
        let default_key = if options.script_name.trim().is_empty() {
            "default".to_string()
        } else {
            options.script_name.clone()
        };
        let st_read = store.clone();
        let key_read = default_key.clone();
        ps.set(
            "read",
            Func::from(move |key: Opt<String>| st_read.read(key.0.as_deref().unwrap_or(&key_read))),
        )?;
        let st_write = store.clone();
        let key_write = default_key.clone();
        ps.set(
            "write",
            Func::from(move |value: Value, key: Opt<String>| {
                let k = key.0.clone().unwrap_or_else(|| key_write.clone());
                if value.is_undefined() || value.is_null() {
                    st_write.remove(&k)
                } else if let Some(v) = value_string(&value) {
                    st_write.write(v, k)
                } else {
                    false
                }
            }),
        )?;
        let st_remove = store.clone();
        ps.set(
            "remove",
            Func::from(move |key: Opt<String>| match key.0 {
                Some(k) => st_remove.remove(&k),
                None => st_remove.clear(),
            }),
        )?;
        let st_clear = store.clone();
        ps.set("removeAll", Func::from(move || st_clear.clear()))?;
        globals.set("$persistentStore", ps)?;
        let timer_q = timers.clone();
        let set_timer = Function::new(ctx.clone(), move |cb: Function, delay: Opt<u32>| {
            let delay = delay.0.unwrap_or(0).min(10_000);
            let tctx = cb.ctx().clone();
            let saved = Persistent::save(&tctx, cb);
            timer_q.lock().unwrap().push(TimerEntry {
                at: Instant::now() + Duration::from_millis(delay as u64),
                cb: saved,
            });
        })?;
        globals.set("setTimeout", set_timer.clone())?;
        // Loon 的 setInterval 当前也只执行一次；保持一致，避免无限循环。
        globals.set("setInterval", set_timer)?;
        let done2 = done.clone();
        let done_fn = Function::new(ctx.clone(), move |v: Opt<Value>| {
            let mut d = match v.0 {
                Some(value) => parse_done_value(&value),
                None => abort_done_state(),
            };
            let mut state = done2.lock().unwrap();
            state.calls += d.calls;
            if !state.called {
                d.calls = state.calls;
                *state = d;
            }
        })?;
        globals.set("$done", done_fn)?;
        let http = Object::new(ctx.clone())?;
        for (name, method) in [
            ("get", "GET"),
            ("post", "POST"),
            ("put", "PUT"),
            ("delete", "DELETE"),
            ("head", "HEAD"),
            ("options", "OPTIONS"),
            ("patch", "PATCH"),
        ] {
            http.set(
                name,
                make_http_function(&ctx, method, options.allow_private_network, stats.clone())?,
            )?;
        }
        globals.set("$httpClient", http)?;
        let notif = Object::new(ctx.clone())?;
        let st = stats.clone();
        notif.set(
            "post",
            Func::from(
                move |title: String, subtitle: Opt<String>, body: Opt<String>| {
                    let subtitle = subtitle.0.unwrap_or_default();
                    let body = body.0.unwrap_or_default();
                    let text = format!("{}{}{}", title, subtitle, body);
                    let mut list = st.notifications.lock().unwrap();
                    if list.len() < MAX_NOTIFICATIONS {
                        list.push(text.chars().take(512).collect());
                    }
                    drop(list);
                    let mut items = st.notification_items.lock().unwrap();
                    if items.len() < MAX_NOTIFICATIONS {
                        items.push(ScriptNotification {
                            title: title.chars().take(128).collect(),
                            subtitle: subtitle.chars().take(128).collect(),
                            body: body.chars().take(512).collect(),
                            script: String::new(),
                        });
                    }
                },
            ),
        )?;
        globals.set("$notification", notif)?;
        let st2 = stats.clone();
        let con = Object::new(ctx.clone())?;
        con.set(
            "log",
            Func::from(move |msg: String| {
                let mut logs = st2.logs.lock().unwrap();
                if logs.len() < MAX_LOGS {
                    logs.push(msg.chars().take(512).collect());
                }
            }),
        )?;
        globals.set("console", con)?;
        if let Err(e) = ctx.eval::<Value, _>(source) {
            eval_error = Some(format!("脚本执行失败: {e}"));
        }
        Ok::<(), rquickjs::Error>(())
    });
    if let Err(e) = setup_res {
        out.error = Some(format!("脚本执行失败: {e}"));
    }
    drain_jobs(rt, deadline);
    // 阶段2：定时器回调；每次回调后在外部驱动其 resolve 的 Promise 续体。
    loop {
        if Instant::now() >= deadline {
            break;
        }
        let next = {
            let mut q = timers.lock().unwrap();
            if q.is_empty() {
                break;
            }
            let idx = q
                .iter()
                .enumerate()
                .min_by_key(|(_, t)| t.at)
                .map(|(i, _)| i)
                .unwrap();
            Some(q.remove(idx))
        };
        let Some(entry) = next else { break };
        if entry.at > deadline {
            break;
        }
        if entry.at > Instant::now() {
            std::thread::sleep(entry.at - Instant::now());
        }
        let cb_res = context.with(|ctx| {
            let cb = entry
                .cb
                .restore(&ctx)
                .map_err(|_| rquickjs::Error::Unknown)?;
            cb.call::<_, ()>(())
        });
        if let Err(e) = cb_res {
            eval_error.get_or_insert_with(|| format!("定时器回调失败: {e}"));
            break;
        }
        drain_jobs(rt, deadline);
    }
    // 阶段2b：等待异步 HTTP 完成；回调仍在本脚本上下文里执行，但网络 I/O
    // 在独立 runtime 上，不占用脚本工作线程。
    if eval_error.is_none() {
        if let Some(e) = drain_http(&context, rt, &stats, deadline) {
            eval_error.get_or_insert(e);
        }
    }
    // 阶段3：停表后再回读 JS 对象；否则超时脚本的后续属性访问会立刻再次触发中断。
    finished.store(true, Ordering::Relaxed);
    let host_objects_ready =
        req_p.is_some() && (phase != ScriptPhase::Response || resp_p.is_some());
    let read_res = if host_objects_ready {
        context.with(|ctx| {
            let phase_base = message;
            let done_now = done.lock().unwrap().clone();
            if phase == ScriptPhase::Response {
                let r = resp_p.take().expect("response object").restore(&ctx)?;
                evaluated = read_message(&r, phase_base, phase);
            } else {
                let rq = req_p.take().expect("request object").restore(&ctx)?;
                evaluated = read_message(&rq, phase_base, phase);
            }
            if done_now.called {
                match done_now.kind {
                    DoneKind::Abort => {
                        if phase != ScriptPhase::Cron {
                            aborted = true;
                        }
                    }
                    DoneKind::Response => {
                        evaluated = apply_done(phase_base, &done_now, ScriptPhase::Response);
                        if phase == ScriptPhase::Request {
                            short_circuit = true;
                        }
                    }
                    DoneKind::Pass | DoneKind::Modified | DoneKind::None => {
                        evaluated = apply_done(&evaluated, &done_now, phase);
                    }
                }
            }
            Ok::<(), rquickjs::Error>(())
        })
    } else {
        // 宿主对象注入失败（如 OOM/引擎错误）：保留原文，不再 expect 回读。
        Ok(())
    };
    if let Err(e) = read_res {
        out.error = Some(format!("脚本执行失败: {e}"));
    }

    out.error = out.error.or(eval_error);
    let elapsed = started.elapsed();
    out.timed_out = interrupted.load(Ordering::Relaxed)
        || (elapsed >= timeout
            && out
                .error
                .as_deref()
                .map(|e| e.contains("interrupt") || e.contains("interrupted"))
                .unwrap_or(false));
    if out.timed_out {
        out.error.get_or_insert_with(|| "脚本超时".into());
    }
    out.done_calls = done.lock().unwrap().calls;
    out.http_calls = stats.http_calls.load(Ordering::Relaxed);
    out.notifications = stats.notifications.lock().unwrap().clone();
    out.notification_items = stats.notification_items.lock().unwrap().clone();
    append_notification_queue(options, &out.notification_items);
    out.logs = stats.logs.lock().unwrap().clone();
    if !out.timed_out
        && out
            .error
            .as_deref()
            .map(|e| e.contains("interrupted"))
            .unwrap_or(false)
    {
        out.timed_out = true;
        out.error = Some("脚本超时".into());
    }

    if out.error.is_some() {
        stats.pending_http.lock().unwrap().clear();
    }
    out.message = evaluated;
    out.short_circuit_response = short_circuit;
    out.aborted = aborted;
    out
}

struct ScriptJob {
    source: String,
    phase: ScriptPhase,
    message: ScriptMessage,
    options: ScriptOptions,
    reply: std::sync::mpsc::SyncSender<ScriptOutcome>,
}

#[derive(Debug, Default)]
pub struct ScriptWorkerStats {
    completed: std::sync::atomic::AtomicU64,
    failed: std::sync::atomic::AtomicU64,
    timed_out: std::sync::atomic::AtomicU64,
    skipped: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptPoolHealth {
    pub completed: u64,
    pub failed: u64,
    pub timed_out: u64,
    pub skipped: u64,
}

/// 专用脚本工作线程池。每个线程创建一次 QuickJS Runtime，之后只处理
/// 「执行请求」通道消息；MITM 路径同步等待结果并带超时。
///
/// `rquickjs::Runtime` 不能跨线程，因此不能在 tokio worker 上直接复用它。
pub struct ScriptWorkerPool {
    senders: Vec<std::sync::mpsc::Sender<ScriptJob>>,
    next: AtomicUsize,
    stats: Arc<ScriptWorkerStats>,
}

impl ScriptWorkerPool {
    pub fn new(workers: usize) -> Self {
        let count = workers.min(8);
        let mut senders = Vec::with_capacity(count);
        let stats = Arc::new(ScriptWorkerStats::default());
        for index in 0..count {
            let (tx, rx) = std::sync::mpsc::channel::<ScriptJob>();
            let _ = std::thread::Builder::new()
                .name(format!("namu-script-{index}"))
                .spawn(move || {
                    let rt = Runtime::new();
                    for job in rx {
                        let out = match &rt {
                            Ok(rt) => run_script_with_runtime(
                                rt,
                                &job.source,
                                job.phase,
                                &job.message,
                                &job.options,
                            ),
                            Err(e) => ScriptOutcome {
                                message: job.message.clone(),
                                error: Some(format!("QuickJS Runtime 创建失败: {e}")),
                                ..Default::default()
                            },
                        };
                        let _ = job.reply.send(out);
                    }
                });
            senders.push(tx);
        }
        Self {
            senders,
            next: AtomicUsize::new(0),
            stats,
        }
    }

    /// 发送一个脚本执行请求并同步等待；等待上限为脚本超时 + 250 ms。
    pub fn run(
        &self,
        source: &str,
        phase: ScriptPhase,
        message: &ScriptMessage,
        options: &ScriptOptions,
    ) -> ScriptOutcome {
        if self.senders.is_empty() {
            self.stats.skipped.fetch_add(1, Ordering::Relaxed);
            return ScriptOutcome {
                message: message.clone(),
                error: Some("脚本工作线程不可用".into()),
                ..Default::default()
            };
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let job = ScriptJob {
            source: source.to_string(),
            phase,
            message: message.clone(),
            options: options.clone(),
            reply: tx,
        };
        if let Err(e) = self.senders[idx].send(job) {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
            return ScriptOutcome {
                message: message.clone(),
                error: Some(format!("脚本工作线程已退出: {e}")),
                ..Default::default()
            };
        }
        let timeout_ms = options.timeout_ms.max(50).min(MAX_TIMEOUT_MS);
        match rx.recv_timeout(Duration::from_millis(timeout_ms + 250)) {
            Ok(out) => {
                if out.timed_out {
                    self.stats.timed_out.fetch_add(1, Ordering::Relaxed);
                } else if out.error.is_some() {
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.completed.fetch_add(1, Ordering::Relaxed);
                }
                out
            }
            Err(_) => {
                self.stats.timed_out.fetch_add(1, Ordering::Relaxed);
                ScriptOutcome {
                    message: message.clone(),
                    error: Some("脚本工作线程响应超时（已放弃本次结果）".into()),
                    timed_out: true,
                    ..Default::default()
                }
            }
        }
    }

    pub fn note_skipped(&self) {
        self.stats.skipped.fetch_add(1, Ordering::Relaxed);
    }

    /// 排队超时等「已命中但没能执行」的情形计入失败，不计跳过：
    /// 跳过只应表示脚本自身不适用，不得用来掩盖并发限流造成的结果丢失。
    pub fn note_failed(&self) {
        self.stats.failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn health(&self) -> ScriptPoolHealth {
        ScriptPoolHealth {
            completed: self.stats.completed.load(Ordering::Relaxed),
            failed: self.stats.failed.load(Ordering::Relaxed),
            timed_out: self.stats.timed_out.load(Ordering::Relaxed),
            skipped: self.stats.skipped.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> ScriptMessage {
        ScriptMessage {
            url: "https://api.example.com/v1".into(),
            method: "GET".into(),
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: "{\"a\":1}".into(),
            body_bytes: None,
        }
    }

    #[test]
    fn cron_spec_is_compiled_into_rule_and_schedule_key_tracks_expression() {
        let base = ScriptRuleConf {
            name: "定时".into(),
            phase: "cron".into(),
            cron: "0 9 * * *".into(),
            source: "$done({});".into(),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[base.clone()], "/tmp/namu-cron-test.json");
        assert_eq!(1, engine.rules.len());
        let rule = &engine.rules[0];
        assert!(rule.cron_spec.is_some());
        assert!(rule.schedule_key().contains("0 9 * * *"));

        let changed = ScriptRuleConf { cron: "0 10 * * *".into(), ..base };
        let engine = ScriptEngine::from_config(&[changed], "/tmp/namu-cron-test-2.json");
        let new_rule = &engine.rules[0];
        assert_eq!(rule.key, new_rule.key);
        assert_ne!(rule.schedule_key(), new_rule.schedule_key());
    }

    #[test]
    fn async_await_script_completes_via_done() {
        let src = r#"
            (async function () {
                const data = await Promise.resolve(JSON.stringify({ ok: 1 }));
                const obj = JSON.parse(data);
                obj.added = 2;
                $done({ body: JSON.stringify(obj) });
            })();
        "#;
        let out = run_script(
            src,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions::default(),
        );
        assert!(out.error.is_none(), "async 脚本出错: {:?}", out.error);
        assert_eq!(out.done_calls, 1, "async 续体应调用 $done");
        let v: serde_json::Value = serde_json::from_str(&out.message.body).unwrap();
        assert_eq!(v["added"], 2);
        assert_eq!(v["ok"], 1);
    }

    #[test]
    fn promise_chain_with_timer_completes() {
        let src = r#"
            new Promise(function (resolve) { setTimeout(function () { resolve("x"); }, 10); })
                .then(function (v) { return v + "y"; })
                .then(function (v) { $done({ body: v }); });
        "#;
        let out = run_script(
            src,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions::default(),
        );
        assert!(out.error.is_none(), "Promise 链出错: {:?}", out.error);
        assert_eq!(out.message.body, "xy");
        assert_eq!(out.done_calls, 1);
    }

    #[test]
    fn async_await_rejection_is_caught_and_done_still_fires() {
        let src = r#"
            (async function () {
                try {
                    await Promise.reject(new Error("boom"));
                } catch (e) {
                    $done({ body: "caught:" + e.message });
                }
            })();
        "#;
        let out = run_script(
            src,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions::default(),
        );
        assert!(
            out.error.is_none(),
            "未捕获 rejection 不应成脚本错误: {:?}",
            out.error
        );
        assert_eq!(out.message.body, "caught:boom");
    }

    #[test]
    fn done_body_mutates_response_and_multiple_done_is_first_wins() {
        let out = run_script(
            r#"$done({body:"first"}); $done({body:"second"});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions::default(),
        );
        assert_eq!(out.message.body, "first");
        assert_eq!(out.done_calls, 2);
        assert!(out.error.is_none());
    }

    #[test]
    fn direct_request_object_mutation_is_read_back() {
        let out = run_script(
            r#"$request.headers["x-test"]="1"; $request.body="changed";"#,
            ScriptPhase::Request,
            &req(),
            &ScriptOptions::default(),
        );
        assert_eq!(out.message.body, "changed");
        assert!(out
            .message
            .headers
            .iter()
            .any(|(k, v)| k == "x-test" && v == "1"));
    }

    #[test]
    fn infinite_loop_is_interrupted_and_does_not_panic() {
        let out = run_script(
            "while (true) { }",
            ScriptPhase::Request,
            &req(),
            &ScriptOptions {
                timeout_ms: 100,
                ..Default::default()
            },
        );
        assert!(out.timed_out || out.error.is_some());
        assert_eq!(out.message.body, "{\"a\":1}");
    }

    #[test]
    fn persistent_store_undefined_deletes_key() {
        let out = run_script(
            r#"$persistentStore.write("v","k"); $persistentStore.write(undefined,"k"); $done({body:$persistentStore.read("k") || "deleted"});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions::default(),
        );
        assert_eq!(out.message.body, "deleted");
        assert!(out.error.is_none());
    }

    #[test]
    fn set_timeout_callback_can_complete_the_script() {
        let out = run_script(
            r#"setTimeout(function(){ $done({body:"later"}); }, 20);"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions {
                timeout_ms: 1000,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body, "later");
        assert_eq!(out.done_calls, 1);
        assert!(out.error.is_none());
    }

    #[test]
    fn persistent_store_roundtrips() {
        let source =
            r#"$persistentStore.write("v1","k1"); $done({body:$persistentStore.read("k1")});"#;
        let out = run_script(
            source,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions::default(),
        );
        assert_eq!(out.message.body, "v1");
        assert!(out.error.is_none());
    }

    #[test]
    fn persistent_store_survives_process_restart_when_file_is_configured() {
        let dir = std::env::temp_dir().join(format!("namu_store_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("store.json");
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(ScriptStore::new(path.to_string_lossy().as_ref()));
        store.write("persisted".into(), "k".into());
        drop(store);
        let reopened = ScriptStore::new(path.to_string_lossy().as_ref());
        assert_eq!(reopened.read("k"), Some("persisted".into()));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn argument_object_is_available() {
        let mut args = HashMap::new();
        args.insert("region".into(), "cn".into());
        let out = run_script(
            r#"$done({body:$argument.region});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions {
                arguments: args,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body, "cn");
    }

    #[test]
    fn argument_object_keeps_declared_types() {
        let mut args = HashMap::new();
        args.insert("price".into(), "9.99".into());
        args.insert("enabled".into(), "true".into());
        args.insert("region".into(), "CN".into());
        let mut types = HashMap::new();
        types.insert("price".into(), "number".into());
        types.insert("enabled".into(), "boolean".into());
        types.insert("region".into(), "string".into());
        let out = run_script(
            r#"$done({body:[typeof $argument.price, typeof $argument.enabled, typeof $argument.region, $argument.price, $argument.enabled, $argument.region].join("|")});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions {
                arguments: args,
                argument_types: types,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body, "number|boolean|string|9.99|true|CN");
        assert!(out.error.is_none(), "{:?}", out.error);
    }

    #[test]
    fn argument_object_json_roundtrip_preserves_types() {
        let mut args = HashMap::new();
        args.insert("level".into(), "2".into());
        args.insert("enabled".into(), "false".into());
        let mut types = HashMap::new();
        types.insert("level".into(), "number".into());
        types.insert("enabled".into(), "boolean".into());
        let out = run_script(
            r#"$done({body:($argument.level > 1 && $argument.enabled === false) ? "ok" : "bad"});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions {
                arguments: args,
                argument_types: types,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body, "ok");
    }

    #[test]
    fn argument_values_override_defaults_with_declared_coercion() {
        let mut args = HashMap::new();
        args.insert("price".into(), "9.99".into());
        args.insert("region".into(), "CN".into());
        let mut types = HashMap::new();
        types.insert("price".into(), "number".into());
        types.insert("region".into(), "string".into());
        let mut values = HashMap::new();
        values.insert("price".into(), "12.5".into());
        values.insert("region".into(), "US".into());
        let out = run_script(
            r#"$done({body:[typeof $argument.price, $argument.price, $argument.region].join("|")});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions {
                arguments: args,
                argument_types: types,
                argument_values: values,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body, "number|12.5|US");
    }

    #[test]
    fn runtime_argument_override_does_not_recompile_script() {
        let conf = ScriptRuleConf {
            name: "args".into(),
            phase: "response".into(),
            pattern: "^https://x/".into(),
            source: r#"$done({body:$argument.region});"#.into(),
            arguments: HashMap::from([("region".to_string(), "CN".to_string())]),
            argument_types: HashMap::from([("region".to_string(), "string".to_string())]),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[conf], "");
        let rule = &engine.rules[0];
        assert_eq!(
            engine
                .effective_argument_values(rule)
                .get("region")
                .unwrap(),
            "CN"
        );
        engine.set_argument_values(
            &rule.key,
            HashMap::from([("region".to_string(), "US".to_string())]),
        );
        assert_eq!(
            engine
                .effective_argument_values(rule)
                .get("region")
                .unwrap(),
            "US"
        );
        assert_eq!(
            engine.rules[0].source, rule.source,
            "source 不因参数值变化而重写"
        );
    }

    #[test]
    fn cron_rule_compiles_and_rejects_bad_expression() {
        let ok = ScriptRuleConf {
            name: "每日签到".into(),
            phase: "cron".into(),
            pattern: "".into(),
            cron: "0 9 * * *".into(),
            source: "$done({});".into(),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[ok], "");
        assert_eq!(engine.unsupported.len(), 0, "{:?}", engine.unsupported);
        assert_eq!(engine.rules[0].phase, ScriptPhase::Cron);
        assert_eq!(engine.rules[0].url.as_str(), ".*");
        assert_eq!(engine.rules[0].cron, "0 9 * * *");
        let bad = ScriptRuleConf {
            name: "bad".into(),
            phase: "cron".into(),
            cron: "61 * * * *".into(),
            source: "$done({});".into(),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[bad], "");
        assert_eq!(engine.rules.len(), 0);
        assert!(engine.unsupported[0].contains("cron 表达式非法"));
    }

    #[test]
    fn argument_text_is_passed_as_a_string() {
        let out = run_script(
            r#"$done({body:$argument});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions {
                argument_text: Some("region=cn".into()),
                ..Default::default()
            },
        );
        assert_eq!(out.message.body, "region=cn");
    }

    #[test]
    fn environment_utils_and_require_are_available() {
        let mut env = HashMap::new();
        env.insert("app".into(), "南门DNS".into());
        env.insert("system".into(), "Android".into());
        env.insert("appVersion".into(), "2.8.1".into());
        let out = run_script(
            r#"const c = require("crypto");
               $done({body:[
                 $environment.app,
                 $environment.system,
                 $environment.appVersion,
                 $utils.getByteLength("中文"),
                 $utils.md5("abc"),
                 $utils.base64Decode($utils.base64Encode("ok")),
                 c.sha256("abc"),
                 typeof require
               ].join("|")});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions {
                environment: env,
                ..Default::default()
            },
        );
        assert!(out.error.is_none(), "{:?}", out.error);
        assert_eq!(
            out.message.body,
            "南门DNS|Android|2.8.1|6|900150983cd24fb0d6963f7d28e17f72|ok|ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad|function"
        );
    }

    #[test]
    fn notification_queue_is_exported_as_jsonl() {
        let dir = std::env::temp_dir().join(format!("namu_notif_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("notifications.jsonl");
        let _ = std::fs::remove_file(&path);
        let out = run_script(
            r#"$notification.post("构建完成","任务","正文"); $done({});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions {
                script_name: "demo".into(),
                notification_file: path.to_string_lossy().to_string(),
                ..Default::default()
            },
        );
        assert_eq!(out.notification_items.len(), 1);
        let text = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["title"], "构建完成");
        assert_eq!(v["body"], "正文");
        assert_eq!(v["script"], "demo");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn notification_and_console_are_recorded() {
        let out = run_script(
            r#"$notification.post("t","s","b"); console.log("hello"); $done({});"#,
            ScriptPhase::Request,
            &req(),
            &ScriptOptions::default(),
        );
        assert_eq!(out.notifications.len(), 1);
        assert_eq!(out.logs, vec!["hello".to_string()]);
    }

    #[test]
    fn script_engine_compiles_filters_and_reports_gaps() {
        let confs = vec![
            ScriptRuleConf {
                name: "ok".into(),
                phase: "request".into(),
                pattern: r"^https://api\.example\.com/".into(),
                source: "$done({});".into(),
                ..Default::default()
            },
            ScriptRuleConf {
                name: "bad-phase".into(),
                phase: "stream".into(),
                pattern: r"^https://".into(),
                source: "x".into(),
                ..Default::default()
            },
            ScriptRuleConf {
                name: "bad-regex".into(),
                phase: "response".into(),
                pattern: "(".into(),
                source: "x".into(),
                ..Default::default()
            },
            ScriptRuleConf {
                name: "empty".into(),
                phase: "response".into(),
                pattern: r"^https://".into(),
                source: String::new(),
                ..Default::default()
            },
        ];
        let engine = ScriptEngine::from_config(&confs, "");
        assert_eq!(engine.rules.len(), 1);
        assert_eq!(engine.unsupported.len(), 3);
        assert_eq!(
            engine
                .hits("https://api.example.com/v1", ScriptPhase::Request)
                .len(),
            1
        );
        assert!(engine
            .hits("https://other.example.com/v1", ScriptPhase::Request)
            .is_empty());
    }

    #[test]
    fn disabled_script_is_reported_but_never_compiled_or_hit() {
        let confs = vec![
            ScriptRuleConf {
                name: "off".into(),
                phase: "request".into(),
                pattern: r"^https://api\.example\.com/".into(),
                source: "$done({});".into(),
                enable: false,
                ..Default::default()
            },
            // 关掉的坏脚本不该报 unsupported：enable 优先级高于语法校验，
            // 否则界面会把「用户主动关掉」误显示成「语法不支持」。
            ScriptRuleConf {
                name: "off-broken".into(),
                phase: "stream".into(),
                pattern: "(".into(),
                source: String::new(),
                enable: false,
                ..Default::default()
            },
            ScriptRuleConf {
                name: "on".into(),
                phase: "request".into(),
                pattern: r"^https://api\.example\.com/".into(),
                source: "$done({});".into(),
                ..Default::default()
            },
        ];
        let engine = ScriptEngine::from_config(&confs, "");
        assert_eq!(engine.rules.len(), 1, "禁用条目不进执行列表");
        assert_eq!(engine.rules[0].name, "on");
        assert!(
            engine.unsupported.is_empty(),
            "禁用优先，不该报不支持: {:?}",
            engine.unsupported
        );
        assert_eq!(engine.disabled, vec!["off".to_string(), "off-broken".to_string()]);
        assert_eq!(
            engine
                .hits("https://api.example.com/v1", ScriptPhase::Request)
                .len(),
            1,
            "禁用条目不参与命中"
        );
    }

    #[test]
    fn script_conf_reads_enable_flag_from_kernel_json() {
        // 外壳按 camelCase 下发；`enabled` 作为别名兜住手写配置。
        let c: ScriptRuleConf =
            serde_json::from_str(r#"{"name":"a","phase":"request","source":"$done({})","enable":false}"#)
                .unwrap();
        assert!(!c.enable);
        let c2: ScriptRuleConf = serde_json::from_str(r#"{"enabled":false}"#).unwrap();
        assert!(!c2.enable);
        let c3: ScriptRuleConf = serde_json::from_str(r#"{"name":"b"}"#).unwrap();
        assert!(c3.enable, "缺省必须是启用，不能把老配置变成禁用");
    }

    #[test]
    fn enable_param_follows_argument_switch_without_recompiling() {
        let mut args = HashMap::new();
        args.insert("enabled".to_string(), "false".to_string());
        let conf = ScriptRuleConf {
            name: "switch".into(),
            phase: "request".into(),
            pattern: r"^https://api\.example\.com/".into(),
            source: r#"$done({body:"hit"});"#.into(),
            arguments: args,
            enable_param: "enabled".into(),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[conf], "");
        assert_eq!(engine.rules.len(), 1, "参数驱动的条目要编译，只是运行时判启用");
        assert!(
            engine
                .hits("https://api.example.com/v1", ScriptPhase::Request)
                .is_empty(),
            "开关是 false 时不得命中"
        );
        // 拨开关：只改运行期值，不重解析模块。
        let mut on = HashMap::new();
        on.insert("enabled".to_string(), "true".to_string());
        engine.set_argument_values(&engine.rules[0].key, on);
        assert_eq!(
            engine
                .hits("https://api.example.com/v1", ScriptPhase::Request)
                .len(),
            1,
            "开关拨到 true 后立刻生效"
        );
    }

    #[test]
    fn enable_param_without_value_stays_enabled() {
        // Loon：参数缺失时沿用默认开关，不能静默把脚本停掉。
        let mut args = HashMap::new();
        args.insert("enabled".to_string(), String::new());
        let conf = ScriptRuleConf {
            name: "switch".into(),
            phase: "request".into(),
            pattern: r"^https://api\.example\.com/".into(),
            source: "$done({});".into(),
            arguments: args,
            enable_param: "enabled".into(),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[conf], "");
        assert_eq!(
            engine
                .hits("https://api.example.com/v1", ScriptPhase::Request)
                .len(),
            1
        );
    }

    #[test]
    fn script_condition_tree_matches_method_body_status_and_argument() {
        let mut args = HashMap::new();
        args.insert("region".to_string(), "CN".to_string());
        let conf = ScriptRuleConf {
            name: "v2-complex".into(),
            phase: "request".into(),
            pattern: r"^https://api\.example\.com/".into(),
            condition:
                "${request.method} == POST && ${request.body} ~= /needle/ && ${region} == CN".into(),
            source: r#"$done({body:"hit"});"#.into(),
            arguments: args,
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[conf], "");
        assert_eq!(engine.rules.len(), 1, "{:?}", engine.unsupported);
        let mut msg = req();
        msg.url = "https://api.example.com/v1".into();
        msg.method = "POST".into();
        msg.body = "has needle inside".into();
        assert_eq!(
            engine
                .hits_with_message(&msg.url, ScriptPhase::Request, &msg)
                .len(),
            1
        );
        assert!(engine.needs_request_body(&msg.url));
        msg.method = "GET".into();
        assert!(engine
            .hits_with_message(&msg.url, ScriptPhase::Request, &msg)
            .is_empty());
        msg.method = "POST".into();
        msg.body = "nothing".into();
        assert!(engine
            .hits_with_message(&msg.url, ScriptPhase::Request, &msg)
            .is_empty());
    }

    #[test]
    fn script_condition_tree_matches_response_status_and_header() {
        let conf = ScriptRuleConf {
            name: "resp-status".into(),
            phase: "response".into(),
            pattern: r"^https://api\.example\.com/".into(),
            condition: "${response.status} == 201 && ${response.header['X-Ok']} == \"1\"".into(),
            source: r#"$done({body:"ok"});"#.into(),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[conf], "");
        assert_eq!(engine.rules.len(), 1, "{:?}", engine.unsupported);
        let mut msg = req();
        msg.url = "https://api.example.com/v1".into();
        msg.status = 201;
        msg.headers = vec![("X-Ok".into(), "1".into())];
        assert_eq!(
            engine
                .hits_with_message(&msg.url, ScriptPhase::Response, &msg)
                .len(),
            1
        );
        msg.status = 200;
        assert!(engine
            .hits_with_message(&msg.url, ScriptPhase::Response, &msg)
            .is_empty());
    }

    #[test]
    fn script_condition_tree_filters_by_actual_headers() {
        let conf = ScriptRuleConf {
            name: "cond".into(),
            phase: "request".into(),
            pattern: String::new(),
            condition:
                r#"${url} ~= /^https://api\.example\.com/ && ${request.header['X-Ad']} == "1""#
                    .into(),
            source: "$done({});".into(),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[conf.clone()], "");
        assert_eq!(
            engine.rules.len(),
            1,
            "unsupported={:?}",
            engine.unsupported
        );
        // pattern 只是预筛；真正是否执行由条件树按实际头决定。
        assert_eq!(
            engine
                .hits("https://api.example.com/v1", ScriptPhase::Request)
                .len(),
            1
        );
        assert_eq!(
            engine
                .hits_with_headers(
                    "https://api.example.com/v1",
                    ScriptPhase::Request,
                    &[("X-Ad".into(), "1".into())],
                )
                .len(),
            1,
        );
        assert!(engine
            .hits_with_headers(
                "https://api.example.com/v1",
                ScriptPhase::Request,
                &[("X-Ad".into(), "0".into())],
            )
            .is_empty());

        let bad = ScriptRuleConf {
            name: "bad-cond".into(),
            phase: "request".into(),
            pattern: r"^https://".into(),
            condition: "${url} == not-a-loon-condition".into(),
            source: "$done({});".into(),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[bad], "");
        assert!(engine.rules.is_empty());
        assert!(engine
            .unsupported
            .iter()
            .any(|e| e.contains("Script v2 条件无法解析")));
    }

    #[test]
    fn script_engine_needs_body_only_when_declared() {
        let mut conf = ScriptRuleConf {
            name: "body".into(),
            phase: "request".into(),
            pattern: r"^https://api\.example\.com/".into(),
            source: "$done({});".into(),
            ..Default::default()
        };
        let engine = ScriptEngine::from_config(&[conf.clone()], "");
        assert!(!engine.needs_request_body("https://api.example.com/v1"));
        conf.requires_body = true;
        let engine = ScriptEngine::from_config(&[conf], "");
        assert!(engine.needs_request_body("https://api.example.com/v1"));
    }

    #[test]
    fn binary_body_mode_exposes_uint8array_and_returns_bytes() {
        let mut msg = req();
        msg.body = "\u{1}\u{2}\u{3}".into();
        msg.body_bytes = Some(vec![1, 2, 3]);
        let out = run_script(
            "const b = $response.body; $done({ body: new Uint8Array([b[0] + 1, b[1], b[2]]) });",
            ScriptPhase::Response,
            &msg,
            &ScriptOptions {
                binary_body_mode: true,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body_bytes.as_deref(), Some(&[2u8, 2, 3][..]));
        assert!(out.error.is_none(), "{:?}", out.error);
    }

    #[test]
    fn binary_body_mode_accepts_arraybuffer_and_plain_byte_array() {
        let mut msg = req();
        msg.body_bytes = Some(vec![7, 8]);
        let out = run_script(
            "const a = $response.body; $done({ body: Array.from(a).map(x => x + 1) });",
            ScriptPhase::Response,
            &msg,
            &ScriptOptions {
                binary_body_mode: true,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body_bytes.as_deref(), Some(&[8u8, 9][..]));
        assert!(out.error.is_none(), "{:?}", out.error);
    }

    #[test]
    fn http_client_fetches_local_test_server() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nnetwork",
            );
        });
        let source = format!(
            r#"$httpClient.get("http://{addr}/x", function(err, resp, data) {{ $done({{body: data}}); }});"#
        );
        let out = run_script(
            &source,
            ScriptPhase::Request,
            &req(),
            &ScriptOptions {
                allow_private_network: true,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body, "network");
        assert_eq!(out.http_calls, 1);
    }

    #[test]
    fn http_client_honors_headers_array_and_timeout_option() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
            let body = if req.contains("x-test: one") {
                "header-ok"
            } else {
                "header-missing"
            };
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            );
        });
        let source = format!(
            r#"$httpClient.get({{url:"http://{addr}/x", headers:[{{name:"X-Test", value:"one"}}], timeout:1}}, function(err, resp, data) {{ $done({{body: err ? "err:" + err : data}}); }});"#
        );
        let out = run_script(
            &source,
            ScriptPhase::Request,
            &req(),
            &ScriptOptions {
                allow_private_network: true,
                timeout_ms: 10_000,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body, "header-ok");
        assert!(out.error.is_none(), "{:?}", out.error);
    }

    #[test]
    fn http_client_timeout_is_not_fixed_at_four_seconds() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            std::thread::sleep(std::time::Duration::from_millis(1500));
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        });
        let source = format!(
            r#"$httpClient.get({{url:"http://{addr}/slow", timeout:1}}, function(err, resp, data) {{ $done({{body: err ? "timeout" : data}}); }});"#
        );
        let started = Instant::now();
        let out = run_script(
            &source,
            ScriptPhase::Request,
            &req(),
            &ScriptOptions {
                allow_private_network: true,
                timeout_ms: 10_000,
                ..Default::default()
            },
        );
        assert_eq!(out.message.body, "timeout");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(1400),
            "elapsed {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn sandbox_exposes_only_whitelisted_host_capabilities() {
        let out = run_script(
            r#"$done({body:[typeof require, typeof fetch, typeof process, typeof eval, typeof Function, typeof WebAssembly].join(",")});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions::default(),
        );
        assert_eq!(
            out.message.body,
            "function,undefined,undefined,undefined,undefined,undefined"
        );
        assert!(out.error.is_none());
    }

    #[test]
    fn memory_limit_fails_gracefully() {
        let out = run_script(
            "let a=[]; while(true){ a.push(new Array(4096).fill(1)); }",
            ScriptPhase::Request,
            &req(),
            &ScriptOptions {
                timeout_ms: 5000,
                ..Default::default()
            },
        );
        assert!(out.error.is_some());
        assert_eq!(out.message.body, "{\"a\":1}");
    }

    #[test]
    fn worker_pool_recovers_after_timeout() {
        let pool = ScriptWorkerPool::new(1);
        let out = pool.run(
            r#"$done({body:"pool-ok"});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions::default(),
        );
        assert_eq!(out.message.body, "pool-ok");
        assert!(out.error.is_none());

        let out = pool.run(
            "while(true){}",
            ScriptPhase::Request,
            &req(),
            &ScriptOptions {
                timeout_ms: 100,
                ..Default::default()
            },
        );
        assert!(out.timed_out);

        let out = pool.run(
            r#"$done({body:"after-timeout"});"#,
            ScriptPhase::Response,
            &req(),
            &ScriptOptions::default(),
        );
        assert_eq!(out.message.body, "after-timeout");
        assert!(out.error.is_none());
        let health = pool.health();
        assert_eq!(health.completed, 2);
        assert_eq!(health.timed_out, 1);
    }
    #[test]
    fn loon_done_empty_aborts_and_empty_object_passes() {
        let out = run_script(
            "$done();",
            ScriptPhase::Request,
            &req(),
            &ScriptOptions::default(),
        );
        assert!(out.error.is_none());
        assert!(out.aborted, "$done() 应放弃请求并断开");
        assert!(!out.short_circuit_response);

        let out = run_script(
            "$done({});",
            ScriptPhase::Request,
            &req(),
            &ScriptOptions::default(),
        );
        assert!(out.error.is_none());
        assert!(!out.aborted, "$done({{}}) 应透传");
        assert_eq!(out.message.body, req().body);
    }

    #[test]
    fn loon_done_nested_response_short_circuits_request() {
        let out = run_script(
            r#"$done({response:{status:403,headers:{"content-type":"text/plain"},body:"blocked"}});"#,
            ScriptPhase::Request,
            &req(),
            &ScriptOptions::default(),
        );
        assert!(out.error.is_none());
        assert!(out.short_circuit_response, "$done({{response}}) 应终止请求");
        assert_eq!(out.message.status, 403);
        assert_eq!(out.message.body, "blocked");
    }

    #[test]
    fn loon_done_modified_keeps_request_going() {
        let out = run_script(
            r#"$done({url:"https://api.example.com/v2",headers:[["x-a","1"]],body:"patched"});"#,
            ScriptPhase::Request,
            &req(),
            &ScriptOptions::default(),
        );
        assert!(out.error.is_none());
        assert!(!out.aborted);
        assert!(!out.short_circuit_response);
        assert_eq!(out.message.url, "https://api.example.com/v2");
        assert_eq!(out.message.body, "patched");
    }

    #[test]
    fn cron_done_empty_is_normal_end() {
        let out = run_script(
            "$done();",
            ScriptPhase::Cron,
            &req(),
            &ScriptOptions::default(),
        );
        assert!(out.error.is_none());
        assert!(!out.aborted, "cron/generic 的 $done() 是正常结束");
    }

    #[test]
    fn loon_default_selects_first_script_and_legacy_chain_keeps_all() {
        let base = ScriptRuleConf {
            phase: "request".into(),
            pattern: "^https://api\\.example\\.com/".into(),
            source: "$done({});".into(),
            ..Default::default()
        };
        let a = ScriptRuleConf { name: "a".into(), ..base.clone() };
        let b = ScriptRuleConf { name: "b".into(), ..base.clone() };
        let engine = ScriptEngine::from_config(&[a, b], "/tmp/namu-script-select.json");
        let hits = engine.hits("https://api.example.com/v1", ScriptPhase::Request)
            .into_iter().cloned().collect::<Vec<_>>();
        assert_eq!(hits.len(), 2);
        assert_eq!(select_phase_hits(hits).len(), 1, "Loon 每阶段只跑首条");

        let legacy_a = ScriptRuleConf { name: "a".into(), legacy_chain: true, ..base.clone() };
        let legacy_b = ScriptRuleConf { name: "b".into(), legacy_chain: true, ..base };
        let engine = ScriptEngine::from_config(&[legacy_a, legacy_b], "/tmp/namu-script-select2.json");
        let hits = engine.hits("https://api.example.com/v1", ScriptPhase::Request)
            .into_iter().cloned().collect::<Vec<_>>();
        assert_eq!(select_phase_hits(hits).len(), 2, "legacy-chain 保留旧链式行为");
    }

}
