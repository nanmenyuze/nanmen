use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Serialize)]
pub struct DnsLogItem {
    pub id: u64,
    pub ts: u64,
    pub domain: String,
    pub qtype: String,
    pub action: String,
    pub detail: String,
    pub ms: u64,
    /// 时间窗口内同一域名/动作的合并次数；1 表示单条。
    pub count: u64,
}

struct Pending {
    domain: String,
    qtype: String,
    action: String,
    detail: String,
    first: Instant,
    count: u64,
    ms_sum: u64,
    ts: u64,
}

struct Inner {
    seq: u64,
    items: VecDeque<DnsLogItem>,
    pending: HashMap<String, Pending>,
}

const WINDOW: Duration = Duration::from_secs(5);

static LOG: Lazy<Mutex<Inner>> = Lazy::new(|| {
    Mutex::new(Inner {
        seq: 0,
        items: VecDeque::with_capacity(500),
        pending: HashMap::new(),
    })
});

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn key(domain: &str, qtype: &str, action: &str, detail: &str) -> String {
    format!("{}|{}|{}|{}", domain, qtype, action, detail)
}

fn push_item(inner: &mut Inner, p: Pending) {
    inner.seq += 1;
    let id = inner.seq;
    if inner.items.len() >= 500 {
        inner.items.pop_front();
    }
    let ms = if p.count == 0 { 0 } else { p.ms_sum / p.count };
    inner.items.push_back(DnsLogItem {
        id,
        ts: p.ts,
        domain: p.domain,
        qtype: p.qtype,
        action: p.action,
        detail: p.detail,
        ms,
        count: p.count,
    });
}

/// 合并 5 秒窗口内同一域名/类型/动作/原因的重复查询：
/// - 窗口未结束时只累计 count，不写新日志；
/// - 窗口到期（或被下一次查询/快照触发）时写一条汇总，count 保留准确次数。
fn flush_due(inner: &mut Inner, now: Instant, force: bool) {
    let mut keys: Vec<(String, Instant)> = inner
        .pending
        .iter()
        .filter(|(_, p)| force || now.duration_since(p.first) >= WINDOW)
        .map(|(k, p)| (k.clone(), p.first))
        .collect();
    // 首次全量落盘时 HashMap 顺序是乱的；按窗口起点排序，保证日志时间顺序。
    keys.sort_by_key(|(_, first)| *first);
    for (k, _) in keys {
        if let Some(p) = inner.pending.remove(&k) {
            push_item(inner, p);
        }
    }
}

/// A lightweight, bounded DNS query log. It is deliberately separate from the
/// general run log so a busy resolver cannot evict connection diagnostics.
pub fn add(domain: &str, qtype: &str, action: &str, detail: &str, ms: u64) {
    let mut inner = match LOG.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    // 先把到期的窗口落盘，保证日志按时间顺序输出。
    flush_due(&mut inner, now, false);
    let k = key(domain, qtype, action, detail);
    if let Some(p) = inner.pending.get_mut(&k) {
        if now.duration_since(p.first) < WINDOW {
            p.count += 1;
            p.ms_sum += ms;
            return;
        }
    }
    if let Some(p) = inner.pending.remove(&k) {
        push_item(&mut inner, p);
    }
    // 极端情况下防止 pending 无界增长：直接落盘最老的一半。
    if inner.pending.len() >= 1024 {
        flush_due(&mut inner, now, true);
    }
    inner.pending.insert(
        k,
        Pending {
            domain: domain.to_string(),
            qtype: qtype.to_string(),
            action: action.to_string(),
            detail: detail.to_string(),
            first: now,
            count: 1,
            ms_sum: ms,
            ts: now_ms(),
        },
    );
}

pub fn json_since(since: u64) -> String {
    let mut inner = match LOG.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    // UI 每秒拉取一次；没有新查询时也要把到期窗口落盘，避免最后一条永远不出现。
    // since=0 是首次加载/导出全量，先把还没到 5 秒的窗口也落盘，避免页面上暂时空白。
    flush_due(&mut inner, Instant::now(), since == 0);
    let items: Vec<&DnsLogItem> = inner.items.iter().filter(|it| it.id > since).collect();
    serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
}

pub fn clear() {
    let mut inner = match LOG.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    inner.items.clear();
    inner.pending.clear();
}
