//! MITM 按 host 观测：连接 / 失败 / 取消 / 无规则 / 改写。
//!
//! 热路径只做一次短临界区查表拿到 `Arc`，计数全在原子量上完成；
//! 榜单排序和字符串格式化在锁外做，避免把统计变成转发瓶颈。
//! 表最多 256 条，按最近访问时间近似 LRU 淘汰。数据只在本机内存，不上报。

use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub const MAX_HOSTS: usize = 256;

#[derive(Clone, Copy, Debug)]
pub enum Metric {
    Conn,
    Request,
    Failed,
    Canceled,
    NoRule,
    Rewritten,
}

#[derive(Default)]
pub struct HostCounters {
    pub conns: AtomicU64,
    pub reqs: AtomicU64,
    pub failed: AtomicU64,
    pub canceled: AtomicU64,
    pub no_rule: AtomicU64,
    pub rewritten: AtomicU64,
    last_seen: AtomicU64,
}

impl HostCounters {
    fn bump(&self, metric: Metric) {
        match metric {
            Metric::Conn => self.conns.fetch_add(1, Ordering::Relaxed),
            Metric::Request => self.reqs.fetch_add(1, Ordering::Relaxed),
            Metric::Failed => self.failed.fetch_add(1, Ordering::Relaxed),
            Metric::Canceled => self.canceled.fetch_add(1, Ordering::Relaxed),
            Metric::NoRule => self.no_rule.fetch_add(1, Ordering::Relaxed),
            Metric::Rewritten => self.rewritten.fetch_add(1, Ordering::Relaxed),
        };
    }
}

struct Table {
    entries: HashMap<String, Arc<HostCounters>>,
    tick: u64,
}

pub struct HostStats {
    table: Mutex<Table>,
}

pub static HOST_STATS: Lazy<HostStats> = Lazy::new(|| HostStats {
    table: Mutex::new(Table {
        entries: HashMap::new(),
        tick: 0,
    }),
});

impl HostStats {
    /// 记录一次事件。host 先归一化（去端口、小写、去尾点）。
    pub fn record(&self, host: &str, metric: Metric) {
        let key = normalize_host(host);
        if key.is_empty() {
            return;
        }
        let mut table = match self.table.lock() {
            Ok(t) => t,
            Err(p) => p.into_inner(),
        };
        table.tick = table.tick.wrapping_add(1);
        let tick = table.tick;
        let entry = if let Some(e) = table.entries.get(&key) {
            e.clone()
        } else {
            if table.entries.len() >= MAX_HOSTS {
                evict_oldest(&mut table.entries);
            }
            let e = Arc::new(HostCounters::default());
            table.entries.insert(key, e.clone());
            e
        };
        // 锁只包住查表/插入；计数和 last_seen 更新都在锁外完成。
        drop(table);
        entry.last_seen.store(tick, Ordering::Relaxed);
        entry.bump(metric);
    }

    /// 失败 top N：失败次数降序，同次数按连接数降序。
    pub fn top_failed(&self, n: usize) -> Vec<HostRow> {
        self.top(n, |c| c.failed.load(Ordering::Relaxed))
    }

    /// 无规则 top N：请求与响应两阶段都没命中的次数降序。
    pub fn top_no_rule(&self, n: usize) -> Vec<HostRow> {
        self.top(n, |c| c.no_rule.load(Ordering::Relaxed))
    }

    fn top<F>(&self, n: usize, pick: F) -> Vec<HostRow>
    where
        F: Fn(&HostCounters) -> u64,
    {
        let snapshot: Vec<(String, Arc<HostCounters>)> = {
            let table = match self.table.lock() {
                Ok(t) => t,
                Err(p) => p.into_inner(),
            };
            table
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let mut rows: Vec<HostRow> = snapshot
            .into_iter()
            .map(|(host, c)| HostRow {
                host,
                conns: c.conns.load(Ordering::Relaxed),
                reqs: c.reqs.load(Ordering::Relaxed),
                failed: c.failed.load(Ordering::Relaxed),
                canceled: c.canceled.load(Ordering::Relaxed),
                no_rule: c.no_rule.load(Ordering::Relaxed),
                rewritten: c.rewritten.load(Ordering::Relaxed),
                selected: pick(&c),
            })
            .filter(|r| r.selected > 0)
            .collect();
        rows.sort_by(|a, b| {
            b.selected
                .cmp(&a.selected)
                .then_with(|| b.conns.cmp(&a.conns))
                .then_with(|| a.host.cmp(&b.host))
        });
        rows.truncate(n);
        rows
    }

    pub fn len(&self) -> usize {
        let table = match self.table.lock() {
            Ok(t) => t,
            Err(p) => p.into_inner(),
        };
        table.entries.len()
    }

    pub fn contains(&self, host: &str) -> bool {
        let key = normalize_host(host);
        let table = match self.table.lock() {
            Ok(t) => t,
            Err(p) => p.into_inner(),
        };
        table.entries.contains_key(&key)
    }

    pub fn snapshot_json(&self) -> Value {
        json!({
            "failedTop": self.top_failed(10),
            "noRuleTop": self.top_no_rule(10),
            "hosts": self.len(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct HostRow {
    pub host: String,
    pub conns: u64,
    pub reqs: u64,
    pub failed: u64,
    pub canceled: u64,
    pub no_rule: u64,
    pub rewritten: u64,
    selected: u64,
}

impl serde::Serialize for HostRow {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("HostRow", 7)?;
        st.serialize_field("host", &self.host)?;
        st.serialize_field("conns", &self.conns)?;
        st.serialize_field("reqs", &self.reqs)?;
        st.serialize_field("failed", &self.failed)?;
        st.serialize_field("canceled", &self.canceled)?;
        st.serialize_field("noRule", &self.no_rule)?;
        st.serialize_field("rewritten", &self.rewritten)?;
        st.end()
    }
}

fn evict_oldest(entries: &mut HashMap<String, Arc<HostCounters>>) {
    let Some(oldest) = entries
        .iter()
        .min_by_key(|(_, c)| c.last_seen.load(Ordering::Relaxed))
        .map(|(k, _)| k.clone())
    else {
        return;
    };
    entries.remove(&oldest);
}

pub fn record(host: &str, metric: Metric) {
    HOST_STATS.record(host, metric);
}

/// SNI/host 归一化：去掉端口、尾点，转小写；IPv6 保留方括号内内容。
pub fn normalize_host(host: &str) -> String {
    let h = host.trim();
    if h.is_empty() {
        return String::new();
    }
    let no_port = if h.starts_with('[') {
        h.split(']')
            .next()
            .map(|s| s.trim_start_matches('['))
            .unwrap_or(h)
    } else {
        h.rsplit_once(':')
            .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
            .map(|(host, _)| host)
            .unwrap_or(h)
    };
    no_port.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_port_and_dot() {
        assert_eq!(normalize_host("Ads.Example.COM.:443"), "ads.example.com");
        assert_eq!(normalize_host("example.com"), "example.com");
        assert_eq!(normalize_host("[::1]:443"), "::1");
        assert_eq!(normalize_host(""), "");
    }

    #[test]
    fn table_is_bounded_at_256() {
        let stats = HostStats {
            table: Mutex::new(Table {
                entries: HashMap::new(),
                tick: 0,
            }),
        };
        for i in 0..300 {
            stats.record(&format!("h{}.example.com", i), Metric::Conn);
        }
        assert_eq!(stats.len(), MAX_HOSTS);
    }

    #[test]
    fn top_orders_by_selected_metric() {
        let stats = HostStats {
            table: Mutex::new(Table {
                entries: HashMap::new(),
                tick: 0,
            }),
        };
        stats.record("a.example.com", Metric::NoRule);
        stats.record("b.example.com", Metric::NoRule);
        stats.record("b.example.com", Metric::NoRule);
        let top = stats.top_no_rule(10);
        assert_eq!(top.first().map(|r| r.host.as_str()), Some("b.example.com"));
        assert_eq!(top.first().map(|r| r.no_rule), Some(2));
    }

    #[test]
    fn lru_keeps_recently_touched_host() {
        let stats = HostStats {
            table: Mutex::new(Table {
                entries: HashMap::new(),
                tick: 0,
            }),
        };
        for i in 0..MAX_HOSTS {
            stats.record(&format!("h{}.example.com", i), Metric::Conn);
        }
        // 再触一次最老的第 0 条，然后插入新 host 触发淘汰。
        stats.record("h0.example.com", Metric::Conn);
        stats.record("new.example.com", Metric::Conn);
        assert!(!stats.contains("h1.example.com"));
        assert!(stats.contains("h0.example.com"));
        assert!(stats.contains("new.example.com"));
    }
}
