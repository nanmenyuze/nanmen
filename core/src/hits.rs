//! 命中归因与观测数据（D0–D3）。
//!
//! 口径：
//! - 一次请求只记一条生效规则（调用方保证传入选中的最小 order）；
//! - bypass / 无规则不进入这里；
//! - 今日计数按设备本地时区自然日清零，累计计数不清；
//! - 最近命中内存 200 条、落盘 50 条，只含域名/模块/时间/动作；
//! - 小时桶保留 168 + 当前，原子写；损坏后重建并在快照里暴露 error。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const RING_CAP: usize = 200;
pub const RING_PERSIST: usize = 50;
pub const HOUR_KEEP: usize = 168;

/// 配置下发的稳定规则身份。section/key 只用于编译期查找，不进入最近命中。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleMeta {
    #[serde(default)]
    pub section: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub source_type: String,
    #[serde(default)]
    pub source_id: String,
    #[serde(default)]
    pub source_name: String,
    #[serde(default)]
    pub order: i64,
}

impl RuleMeta {
    pub fn identity(&self) -> RuleIdentity {
        RuleIdentity {
            rule_id: self.rule_id.clone(),
            source_type: self.source_type.clone(),
            source_id: self.source_id.clone(),
            source_name: self.source_name.clone(),
            order: self.order,
        }
    }

    /// 配置里没有显式 meta 时的兜底：仍能归到「当前配置」，但不伪造 rule id。
    pub fn config_fallback(section: &str, key: &str, order: i64) -> Self {
        Self {
            section: section.to_string(),
            key: key.to_string(),
            rule_id: short_rule_id("config", section, key),
            source_type: section.to_string(),
            source_id: "config".to_string(),
            source_name: "当前配置".to_string(),
            order,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleIdentity {
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub source_type: String,
    #[serde(default)]
    pub source_id: String,
    #[serde(default)]
    pub source_name: String,
    #[serde(default)]
    pub order: i64,
}

impl RuleIdentity {
    pub fn unknown(order: i64) -> Self {
        Self {
            rule_id: "unknown".into(),
            source_type: "unknown".into(),
            source_id: "unknown".into(),
            source_name: "未归因".into(),
            order,
        }
    }

    pub fn is_unknown(&self) -> bool {
        self.source_type.trim().is_empty()
            || self.source_type.eq_ignore_ascii_case("unknown")
            || self.source_id.trim().is_empty()
    }

    fn source_key(&self) -> String {
        if self.is_unknown() {
            "unknown|unknown".into()
        } else {
            format!(
                "{}|{}",
                self.source_type.trim().to_ascii_lowercase(),
                self.source_id.trim()
            )
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HitEvent {
    pub seq: u64,
    pub ts: u64,
    pub domain: String,
    pub action: String,
    pub rule_id: String,
    pub source_type: String,
    pub source_id: String,
    pub source_name: String,
    pub order: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HourBucket {
    pub hour_ts: i64,
    pub queries: u64,
    pub blocked: u64,
    pub cache_lookups: u64,
    pub cache_hit: u64,
    pub per_source_hits: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HistoryFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    buckets: Vec<HourBucket>,
    #[serde(default)]
    ring: Vec<HitEvent>,
}

#[derive(Debug, Clone, Default)]
struct SourceCounter {
    hits_today: u64,
    hits_total: u64,
    source_name: String,
    order: i64,
}

struct SourceStore {
    day: i64,
    sources: HashMap<String, SourceCounter>,
    /// 同一 source 下首次见到的 ruleId，仅用于诊断展示。
    rules: HashMap<String, String>,
}

impl Default for SourceStore {
    fn default() -> Self {
        Self {
            day: local_day_key(),
            sources: HashMap::new(),
            rules: HashMap::new(),
        }
    }
}

pub struct HitStore {
    inner: Mutex<SourceStore>,
    ring: Mutex<VecDeque<HitEvent>>,
    history: Mutex<Vec<HourBucket>>,
    seq: AtomicU64,
    total_hits: AtomicU64,
    history_path: Mutex<Option<PathBuf>>,
    history_dirty: AtomicBool,
    history_error: AtomicBool,
    last_error: Mutex<String>,
    /// D2 关闭后不写盘；内存仍可查看，重新打开后的首个 dirty 周期补写。
    persist_enabled: AtomicBool,
}

impl Default for HitStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(SourceStore::default()),
            ring: Mutex::new(VecDeque::new()),
            history: Mutex::new(Vec::new()),
            seq: AtomicU64::new(0),
            total_hits: AtomicU64::new(0),
            history_path: Mutex::new(None),
            history_dirty: AtomicBool::new(false),
            history_error: AtomicBool::new(false),
            last_error: Mutex::new(String::new()),
            persist_enabled: AtomicBool::new(true),
        }
    }
}

impl HitStore {
    pub fn set_persist_enabled(&self, enabled: bool) {
        self.persist_enabled.store(enabled, Ordering::Relaxed);
        if enabled && self.history_dirty.load(Ordering::Relaxed) {
            let _ = self.persist();
        }
    }

    pub fn persist_enabled(&self) -> bool {
        self.persist_enabled.load(Ordering::Relaxed)
    }

    pub fn set_history_path(&self, path: Option<String>) {
        let p = path.map(PathBuf::from).filter(|p| !p.as_os_str().is_empty());
        *self.history_path.lock().unwrap_or_else(|p| p.into_inner()) = p.clone();
        if let Some(p) = p {
            self.load_history(&p);
        }
    }

    fn load_history(&self, path: &Path) {
        let Ok(text) = fs::read_to_string(path) else {
            return;
        };
        match serde_json::from_str::<HistoryFile>(&text) {
            Ok(v) => {
                let mut buckets = v.buckets;
                // 2.9.2 早期测试包用本地小时写盘；v3 起改存 UTC。
                // 读完立刻按当前偏移校正，并在下面落盘为 v3；否则用户在写盘前改时区会二次校正。
                let migrated_v2 = v.version < 3;
                if migrated_v2 {
                    let offset = utc_offset_secs();
                    for b in &mut buckets {
                        b.hour_ts -= offset;
                    }
                }
                buckets.sort_by_key(|b| b.hour_ts);
                buckets.retain(|b| b.hour_ts >= 0);
                let now_hour = utc_hour_ts();
                buckets.retain(|b| b.hour_ts >= now_hour - (HOUR_KEEP as i64) * 3600);
                while buckets.len() > HOUR_KEEP + 1 {
                    buckets.remove(0);
                }
                *self.history.lock().unwrap_or_else(|p| p.into_inner()) = buckets;
                {
                    let mut ring = self.ring.lock().unwrap_or_else(|p| p.into_inner());
                    ring.clear();
                    for mut e in v.ring.into_iter().rev().take(RING_PERSIST).rev() {
                        if e.source_type.trim().is_empty() {
                            e.source_type = "unknown".into();
                            e.source_id = "unknown".into();
                            e.source_name = "未归因".into();
                        }
                        ring.push_back(e);
                    }
                }
                // v2→v3 的校正必须在本次加载内落盘，避免下次启动再用新时区偏移校一次。
                // 这是一次性迁移，不受运行期“关闭摘要停写盘”门控；否则用户关闭摘要后
                // 每次启动都会重复校正（v2 文件一直升不到 v3）。
                if migrated_v2 {
                    let _ = self.persist_inner();
                }
                self.history_error.store(false, Ordering::Relaxed);
                self.last_error
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clear();
            }
            Err(e) => {
                self.history_error.store(true, Ordering::Relaxed);
                *self.last_error.lock().unwrap_or_else(|p| p.into_inner()) =
                    format!("历史文件损坏，已重建：{e}");
                *self.history.lock().unwrap_or_else(|p| p.into_inner()) = Vec::new();
                self.ring
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clear();
                // 立即用空历史覆盖坏文件，避免每次启动都报同一个错。
                let _ = self.persist();
            }
        }
    }

    /// 把计数、ring 与历史一起落盘；临时文件 + rename 原子替换。
    pub fn persist(&self) -> bool {
        if !self.persist_enabled.load(Ordering::Relaxed) {
            return false;
        }
        self.persist_inner()
    }

    fn persist_inner(&self) -> bool {
        let path = self
            .history_path
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let Some(path) = path else { return false };
        let buckets = self.history.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let ring = self
            .ring
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .rev()
            .take(RING_PERSIST)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        let body = HistoryFile {
            version: 3,
            buckets,
            ring,
        };
        let Ok(text) = serde_json::to_string(&body) else {
            return false;
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, text).is_err() {
            return false;
        }
        match fs::rename(&tmp, &path) {
            Ok(()) => {
                self.history_dirty.store(false, Ordering::Relaxed);
                true
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                self.note_error(format!("历史写入失败：{e}"));
                false
            }
        }
    }

    pub fn flush_if_dirty(&self) {
        if self.history_dirty.load(Ordering::Relaxed) {
            let _ = self.persist();
        }
    }

    /// 用户点「重试」：清掉损坏标记并重建空历史，下一次统计继续写盘。
    pub fn repair(&self) -> bool {
        self.history_error.store(false, Ordering::Relaxed);
        self.last_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        self.history.lock().unwrap_or_else(|p| p.into_inner()).clear();
        self.ring.lock().unwrap_or_else(|p| p.into_inner()).clear();
        self.persist()
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.sources.clear();
        inner.rules.clear();
        inner.day = local_day_key();
        drop(inner);
        self.ring.lock().unwrap_or_else(|p| p.into_inner()).clear();
        self.history.lock().unwrap_or_else(|p| p.into_inner()).clear();
        self.total_hits.store(0, Ordering::Relaxed);
        self.seq.store(0, Ordering::Relaxed);
        self.history_error.store(false, Ordering::Relaxed);
        let _ = self.persist_inner();
    }

    fn note_error(&self, message: String) {
        self.history_error.store(true, Ordering::Relaxed);
        *self.last_error.lock().unwrap_or_else(|p| p.into_inner()) = message;
    }

    fn ensure_day(inner: &mut SourceStore) {
        let today = local_day_key();
        if inner.day != today {
            inner.day = today;
            for v in inner.sources.values_mut() {
                v.hits_today = 0;
            }
        }
    }

    /// 记录一次生效规则命中。`action` 取 block / rewrite / route。
    pub fn record_hit(&self, identity: &RuleIdentity, domain: &str, action: &str) {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return;
        }
        let key = identity.source_key();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::ensure_day(&mut inner);
        let order = identity.order.max(-1);
        let entry = inner.sources.entry(key.clone()).or_insert_with(|| SourceCounter {
            order,
            ..Default::default()
        });
        entry.hits_today = entry.hits_today.saturating_add(1);
        entry.hits_total = entry.hits_total.saturating_add(1);
        if entry.source_name.is_empty() || identity.is_unknown() {
            entry.source_name = if identity.is_unknown() {
                "未归因".into()
            } else {
                identity.source_name.clone()
            };
        }
        if entry.order < 0 || (order >= 0 && order < entry.order) {
            entry.order = order;
        }
        inner
            .rules
            .entry(key.clone())
            .or_insert_with(|| identity.rule_id.clone());
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        self.total_hits.fetch_add(1, Ordering::Relaxed);
        drop(inner);

        let ev = HitEvent {
            seq,
            ts: now_ms(),
            domain,
            action: action.to_string(),
            rule_id: identity.rule_id.clone(),
            source_type: if identity.is_unknown() {
                "unknown".into()
            } else {
                identity.source_type.clone()
            },
            source_id: if identity.is_unknown() {
                "unknown".into()
            } else {
                identity.source_id.clone()
            },
            source_name: if identity.is_unknown() {
                "未归因".into()
            } else {
                identity.source_name.clone()
            },
            order,
        };
        {
            let mut ring = self.ring.lock().unwrap_or_else(|p| p.into_inner());
            if ring.len() >= RING_CAP {
                ring.pop_front();
            }
            ring.push_back(ev);
        }
        self.bucket_mut(|b| {
            *b.per_source_hits.entry(key).or_insert(0) += 1;
        });
        self.history_dirty.store(true, Ordering::Relaxed);
    }

    /// 一次 DNS 查询（含被拦截、缓存、上游）。
    pub fn record_query(&self, blocked: bool) {
        self.bucket_mut(|b| {
            b.queries = b.queries.saturating_add(1);
            if blocked {
                b.blocked = b.blocked.saturating_add(1);
            }
        });
    }

    /// 已由 record_query 计过 queries 时，只补 blocked 桶。
    pub fn record_blocked(&self) {
        self.bucket_mut(|b| b.blocked = b.blocked.saturating_add(1));
    }

    /// 进入缓存查询路径：lookups 必加，命中时再记 cache_hit。
    pub fn record_cache_lookup(&self, hit: bool) {
        self.bucket_mut(|b| {
            b.cache_lookups = b.cache_lookups.saturating_add(1);
            if hit {
                b.cache_hit = b.cache_hit.saturating_add(1);
            }
        });
    }

    fn bucket_mut(&self, f: impl FnOnce(&mut HourBucket)) {
        let hour = utc_hour_ts();
        let mut buckets = self.history.lock().unwrap_or_else(|p| p.into_inner());
        if buckets.last().map(|b| b.hour_ts) != Some(hour) {
            buckets.push(HourBucket {
                hour_ts: hour,
                ..Default::default()
            });
            let cutoff = hour - (HOUR_KEEP as i64) * 3600;
            buckets.retain(|b| b.hour_ts >= cutoff);
            while buckets.len() > HOUR_KEEP + 1 {
                buckets.remove(0);
            }
        }
        if let Some(b) = buckets.last_mut() {
            f(b);
        }
        self.history_dirty.store(true, Ordering::Relaxed);
    }

    pub fn snapshot_json(&self, since_seq: i64) -> String {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::ensure_day(&mut inner);
        let sources = inner
            .sources
            .iter()
            .map(|(key, v)| {
                let (source_type, source_id) = key.split_once('|').unwrap_or((key, ""));
                json!({
                    "sourceType": source_type,
                    "sourceId": source_id,
                    "sourceName": if v.source_name.is_empty() { "未归因" } else { v.source_name.as_str() },
                    "hitsToday": v.hits_today,
                    "hitsTotal": v.hits_total,
                    "order": v.order,
                    "ruleId": inner.rules.get(key).cloned().unwrap_or_default(),
                })
            })
            .collect::<Vec<Value>>();
        let day = inner.day;
        drop(inner);
        let ring = self
            .ring
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|e| since_seq < 0 || e.seq > since_seq as u64)
            .cloned()
            .collect::<Vec<_>>();
        let buckets = self.history.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let err = self.history_error.load(Ordering::Relaxed);
        let msg = self.last_error.lock().unwrap_or_else(|p| p.into_inner()).clone();
        json!({
            "available": true,
            "seq": self.seq.load(Ordering::Relaxed),
            "day": day,
            "dayStartMs": local_day_start_ms(),
            "hitsTotal": self.total_hits.load(Ordering::Relaxed),
            "sources": sources,
            "ring": ring,
            "ringCapacity": RING_CAP,
            "ringPersisted": RING_PERSIST,
            "history": {
                "buckets": buckets,
                "retainedHours": HOUR_KEEP,
                "error": err,
                "message": msg,
            },
            "serverNowMs": now_ms(),
        })
        .to_string()
    }
}

pub fn empty_snapshot() -> String {
    json!({
        "available": false,
        "seq": 0,
        "day": local_day_key(),
        "dayStartMs": local_day_start_ms(),
        "hitsTotal": 0,
        "sources": [],
        "ring": [],
        "ringCapacity": RING_CAP,
        "ringPersisted": RING_PERSIST,
        "history": { "buckets": [], "retainedHours": HOUR_KEEP, "error": false, "message": "" },
        "serverNowMs": now_ms(),
    })
    .to_string()
}

pub fn short_rule_id(source_id: &str, section: &str, key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(source_id.as_bytes());
    h.update(b"|");
    h.update(section.as_bytes());
    h.update(b"|");
    h.update(key.as_bytes());
    let d = h.finalize();
    d[..6].iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 设备本地自然日 key：YYYYMMDD，用于跨日清零。
pub fn local_day_key() -> i64 {
    let tm = local_tm();
    (tm.tm_year as i64 + 1900) * 10000 + (tm.tm_mon as i64 + 1) * 100 + tm.tm_mday as i64
}

pub fn local_day_start_ms() -> i64 {
    let mut tm = local_tm();
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    unsafe { (libc::mktime(&mut tm) as i64) * 1000 }
}

/// D3 冻结口径：小时桶一律 UTC 整点对齐，显示层再按设备时区转换。
/// 这样跨时区旅行不会改变桶边界，也不会出现同一小时重复/漏记。
pub fn utc_hour_ts() -> i64 {
    (now_ms() / 1000 / 3600) as i64 * 3600
}

/// 设备当前相对 UTC 的偏移秒数（东区为正）；仅用于迁移旧本地小时桶。
fn utc_offset_secs() -> i64 {
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        tm.tm_gmtoff as i64
    }
}

fn local_tm() -> libc::tm {
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        tm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(id: &str, order: i64, name: &str) -> RuleIdentity {
        RuleIdentity {
            rule_id: format!("r{id}"),
            source_type: "dns".into(),
            source_id: id.into(),
            source_name: name.into(),
            order,
        }
    }

    #[test]
    fn hour_bucket_is_utc_aligned() {
        let hour = utc_hour_ts();
        assert_eq!(hour % 3600, 0);
        let now = (now_ms() / 1000) as i64;
        assert!((now - hour).abs() < 3600, "桶必须是当前 UTC 整点");
        assert!((now - hour) >= 0);
    }

    #[test]
    fn counts_per_source_and_ring_cap() {
        let s = HitStore::default();
        for i in 0..(RING_CAP + 5) {
            s.record_hit(&identity(if i % 2 == 0 { "a" } else { "b" }, i as i64, "模块"), "x.test", "block");
        }
        let v: Value = serde_json::from_str(&s.snapshot_json(-1)).unwrap();
        assert_eq!(v["ring"].as_array().unwrap().len(), RING_CAP);
        assert_eq!(v["ring"][0]["seq"], 6);
        let sources = v["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(v["hitsTotal"], RING_CAP + 5);
    }

    #[test]
    fn since_seq_returns_increment_only() {
        let s = HitStore::default();
        s.record_hit(&identity("a", 1, "A"), "a.test", "block");
        s.record_hit(&identity("a", 1, "A"), "b.test", "block");
        let v: Value = serde_json::from_str(&s.snapshot_json(1)).unwrap();
        assert_eq!(v["ring"].as_array().unwrap().len(), 1);
        assert_eq!(v["ring"][0]["domain"], "b.test");
    }

    #[test]
    fn history_atomic_write_and_corrupt_rebuild() {
        let dir = std::env::temp_dir().join(format!("namu-hits-{}", now_ms()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        let s = HitStore::default();
        s.set_history_path(Some(path.to_string_lossy().into_owned()));
        s.record_query(true);
        s.record_query(false);
        s.record_cache_lookup(true);
        s.record_hit(&identity("a", 1, "A"), "a.test", "block");
        assert!(s.persist());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"queries\":2"));
        assert!(!path.with_extension("json.tmp").exists());
        fs::write(&path, "{bad").unwrap();
        let s2 = HitStore::default();
        s2.set_history_path(Some(path.to_string_lossy().into_owned()));
        let v: Value = serde_json::from_str(&s2.snapshot_json(-1)).unwrap();
        assert_eq!(v["history"]["error"], true);
        assert!(s2.repair());
        let v2: Value = serde_json::from_str(&s2.snapshot_json(-1)).unwrap();
        assert_eq!(v2["history"]["error"], false);
    }

    #[test]
    fn v2_local_buckets_are_upgraded_once_and_rewritten_as_v3() {
        let dir = std::env::temp_dir().join(format!("namu-hits-v2-{}", now_ms()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        let local_hour = utc_hour_ts() + utc_offset_secs();
        let file = serde_json::json!({
            "version": 2,
            "buckets": [{
                "hourTs": local_hour,
                "queries": 3,
                "blocked": 1,
                "cacheLookups": 0,
                "cacheHit": 0,
                "perSourceHits": {}
            }],
            "ring": []
        });
        fs::write(&path, file.to_string()).unwrap();
        let s = HitStore::default();
        s.set_history_path(Some(path.to_string_lossy().into_owned()));
        let rewritten: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(rewritten["version"], 3);
        assert_eq!(rewritten["buckets"][0]["hourTs"], local_hour - utc_offset_secs());
        // 再加载一次不能再减偏移。
        let again = HitStore::default();
        again.set_history_path(Some(path.to_string_lossy().into_owned()));
        let v: Value = serde_json::from_str(&again.snapshot_json(-1)).unwrap();
        assert_eq!(v["history"]["buckets"][0]["hourTs"], local_hour - utc_offset_secs());
    }

    #[test]
    fn v2_local_buckets_are_upgraded_even_when_persist_disabled() {
        let dir = std::env::temp_dir().join(format!("namu-hits-v2-nop-{}", now_ms()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        let local_hour = utc_hour_ts() + utc_offset_secs();
        let file = serde_json::json!({
            "version": 2,
            "buckets": [{
                "hourTs": local_hour,
                "queries": 1,
                "blocked": 0,
                "cacheLookups": 0,
                "cacheHit": 0,
                "perSourceHits": {}
            }],
            "ring": []
        });
        fs::write(&path, file.to_string()).unwrap();
        let s = HitStore::default();
        // 用户关闭轻量摘要时运行期不写盘，但 v2→v3 是一次性迁移，必须写回，
        // 否则每次启动都会拿新时区偏移再校一次。
        s.set_persist_enabled(false);
        s.set_history_path(Some(path.to_string_lossy().into_owned()));
        let rewritten: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(rewritten["version"], 3);
        assert_eq!(rewritten["buckets"][0]["hourTs"], local_hour - utc_offset_secs());
    }

    #[test]
    fn empty_identity_goes_unknown() {
        let s = HitStore::default();
        s.record_hit(&RuleIdentity::default(), "x.test", "block");
        let v: Value = serde_json::from_str(&s.snapshot_json(-1)).unwrap();
        assert_eq!(v["sources"][0]["sourceType"], "unknown");
    }
}
