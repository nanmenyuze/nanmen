//! 活跃连接快照：给壳层「实时连接」页用。
//!
//! 只记录判断连接所需的元数据（归属 UID、目标、域名、动作、命中规则），
//! 不做字节计数——那需要改中继路径，代价远大于收益。连接关闭时整条移除，
//! 表本身有上限，漏删的条目会被最旧淘汰兜住，不会无界增长。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// 与 TUN 连接上限一致：活跃连接最多 1024 条，快照表不需要比它大。
const MAX_ENTRIES: usize = 1024;

/// 每连接流量计：主循环只做原子累加（无锁），快照时读一次交给壳层算速率。
#[derive(Debug, Default)]
pub struct ConnMeter {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub id: u64,
    pub uid: Option<u32>,
    pub domain: Option<String>,
    pub dst_ip: String,
    pub dst_port: u16,
    pub action: String,
    pub rule: String,
    pub mitm: bool,
    pub started: Instant,
    pub meter: Arc<ConnMeter>,
    /// 内核 10s 采样算出的速率（B/s），壳层直接显示，不再自己做差分。
    pub up_bps: u64,
    pub down_bps: u64,
}

/// 输出给 JNI 的扁平结构，`age_ms` 在取快照时计算，避免壳层处理 Instant。
#[derive(Debug, Clone)]
pub struct ConnOut {
    pub id: u64,
    pub uid: Option<u32>,
    pub domain: Option<String>,
    pub dst_ip: String,
    pub dst_port: u16,
    pub action: String,
    pub rule: String,
    pub mitm: bool,
    pub age_ms: u64,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub up_bps: u64,
    pub down_bps: u64,
}

#[derive(Debug, Default)]
pub struct ConnTable {
    next_id: u64,
    items: HashMap<u64, ConnInfo>,
}

impl ConnTable {
    pub fn new() -> Self {
        Self { next_id: 1, items: HashMap::new() }
    }

    /// 插入一条连接，返回快照 id；满时先淘汰开始时间最早的一条。
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        uid: Option<u32>,
        domain: Option<String>,
        dst_ip: String,
        dst_port: u16,
        action: String,
        rule: String,
        mitm: bool,
    ) -> (u64, Arc<ConnMeter>) {
        if self.items.len() >= MAX_ENTRIES {
            if let Some(oldest) = self
                .items
                .iter()
                .min_by_key(|(_, v)| v.started)
                .map(|(k, _)| *k)
            {
                self.items.remove(&oldest);
            }
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let meter = Arc::new(ConnMeter::default());
        self.items.insert(
            id,
            ConnInfo {
                id,
                uid,
                domain,
                dst_ip,
                dst_port,
                action,
                rule,
                mitm,
                started: Instant::now(),
                meter: meter.clone(),
                up_bps: 0,
                down_bps: 0,
            },
        );
        (id, meter)
    }

    /// 写入内核采样出的每连接速率（10s 一次，主循环持有写锁时调用）。
    pub fn set_rates(&mut self, id: u64, up_bps: u64, down_bps: u64) {
        if let Some(c) = self.items.get_mut(&id) {
            c.up_bps = up_bps;
            c.down_bps = down_bps;
        }
    }

    pub fn remove(&mut self, id: Option<u64>) {
        if let Some(id) = id {
            self.items.remove(&id);
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 最近的 `max` 条，按开始时间倒序（最新在前）。
    pub fn snapshot(&self, max: usize) -> Vec<ConnOut> {
        let now = Instant::now();
        let mut rows: Vec<ConnOut> = self
            .items
            .values()
            .map(|c| ConnOut {
                id: c.id,
                uid: c.uid,
                domain: c.domain.clone(),
                dst_ip: c.dst_ip.clone(),
                dst_port: c.dst_port,
                action: c.action.clone(),
                rule: c.rule.clone(),
                mitm: c.mitm,
                age_ms: now.duration_since(c.started).as_millis() as u64,
                up_bytes: c.meter.up.load(Ordering::Relaxed),
                down_bytes: c.meter.down.load(Ordering::Relaxed),
                up_bps: c.up_bps,
                down_bps: c.down_bps,
            })
            .collect();
        // 用 id 倒序而不是 age_ms：同一毫秒内建立的连接 age_ms 相等，排序会不稳定。
        rows.sort_by(|a, b| b.id.cmp(&a.id));
        rows.truncate(max);
        rows
    }

    /// 增量快照：只返回 id > `since` 的记录，按 id 升序，并给出总条数与游标。
    /// 壳层第一次传 0 拿到全表，之后用返回的 last 续取，避免每秒重传整表。
    pub fn json_since(&self, since: u64) -> String {
        let now = Instant::now();
        let mut rows: Vec<ConnOut> = self
            .items
            .values()
            .filter(|c| c.id > since)
            .map(|c| ConnOut {
                id: c.id,
                uid: c.uid,
                domain: c.domain.clone(),
                dst_ip: c.dst_ip.clone(),
                dst_port: c.dst_port,
                action: c.action.clone(),
                rule: c.rule.clone(),
                mitm: c.mitm,
                age_ms: now.duration_since(c.started).as_millis() as u64,
                up_bytes: c.meter.up.load(Ordering::Relaxed),
                down_bytes: c.meter.down.load(Ordering::Relaxed),
                up_bps: c.up_bps,
                down_bps: c.down_bps,
            })
            .collect();
        rows.sort_by_key(|r| r.id);
        let last = rows.last().map(|r| r.id).unwrap_or(since);
        format!(
            "{{\"items\":{},\"last\":{},\"total\":{}}}",
            to_json_array(&rows),
            last,
            self.items.len()
        )
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push(' '),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

impl ConnOut {
    fn to_json(&self) -> String {
        let domain = match &self.domain {
            Some(d) if !d.is_empty() => format!("\"{}\"", escape(d)),
            _ => "null".to_string(),
        };
        let uid = match self.uid {
            Some(u) => u.to_string(),
            None => "null".to_string(),
        };
        format!(
            "{{\"id\":{},\"uid\":{},\"domain\":{},\"ip\":\"{}\",\"port\":{},\"action\":\"{}\",\"rule\":\"{}\",\"mitm\":{},\"ageMs\":{},\"up\":{},\"down\":{},\"upBps\":{},\"downBps\":{}}}",
            self.id,
            uid,
            domain,
            escape(&self.dst_ip),
            self.dst_port,
            escape(&self.action),
            escape(&self.rule),
            self.mitm,
            self.age_ms,
            self.up_bytes,
            self.down_bytes,
            self.up_bps,
            self.down_bps
        )
    }
}

/// 整表序列化成 JSON 数组；壳层按数组解析，不需要知道内部结构。
pub fn to_json_array(rows: &[ConnOut]) -> String {
    let body = rows
        .iter()
        .map(|r| r.to_json())
        .collect::<Vec<_>>()
        .join(",");
    format!("[{}]", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(t: &mut ConnTable, uid: u32, domain: &str, action: &str) -> u64 {
        t.insert(
            Some(uid),
            Some(domain.to_string()),
            "1.1.1.1".into(),
            443,
            action.into(),
            "命中第 3 条规则 DOMAIN-SUFFIX ads.com → 拦截".into(),
            false,
        )
        .0
    }

    #[test]
    fn insert_snapshot_and_remove() {
        let mut t = ConnTable::new();
        let a = add(&mut t, 10086, "api.bilibili.com", "直连");
        let b = add(&mut t, 10010, "ads.example.com", "拦截");
        assert_eq!(t.len(), 2);
        let rows = t.snapshot(10);
        assert_eq!(rows.len(), 2);
        // 最新在前
        assert_eq!(rows[0].id, b);
        assert_eq!(rows[1].id, a);
        assert_eq!(rows[0].uid, Some(10010));
        assert_eq!(rows[0].action, "拦截");
        t.remove(Some(a));
        assert_eq!(t.len(), 1);
        assert_eq!(t.snapshot(10)[0].id, b);
        // None 不应 panic，也不应误删
        t.remove(None);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn unknown_uid_and_domain_render_null() {
        let mut t = ConnTable::new();
        t.insert(None, None, "10.0.0.1".into(), 80, "直连".into(), String::new(), false);
        let json = to_json_array(&t.snapshot(10));
        assert!(json.contains("\"uid\":null"));
        assert!(json.contains("\"domain\":null"));
        assert!(json.contains("\"ip\":\"10.0.0.1\""));
    }

    #[test]
    fn table_is_bounded_by_oldest_eviction() {
        let mut t = ConnTable::new();
        for i in 0..(MAX_ENTRIES + 3) {
            add(&mut t, 10000 + i as u32, "a.example.com", "直连");
        }
        assert_eq!(t.len(), MAX_ENTRIES);
        // 最新插入的一定在快照里
        let rows = t.snapshot(MAX_ENTRIES);
        assert_eq!(rows.len(), MAX_ENTRIES);
    }

    #[test]
    fn json_since_only_returns_new_rows() {
        let mut t = ConnTable::new();
        let a = add(&mut t, 1, "a.example.com", "直连");
        let first = t.json_since(0);
        assert!(first.contains("\"last\":1"));
        assert!(first.contains("\"total\":1"));
        assert!(first.contains("a.example.com"));
        let b = add(&mut t, 2, "b.example.com", "直连");
        let second = t.json_since(a);
        assert!(second.contains("\"last\":2"));
        assert!(second.contains("b.example.com"));
        assert!(!second.contains("a.example.com"));
        // 没有新记录时 last 保持游标
        assert!(t.json_since(b).contains("\"last\":2"));
    }

    #[test]
    fn json_escapes_quotes_and_newlines() {
        let mut t = ConnTable::new();
        t.insert(
            Some(42),
            Some("quo\"te.example.com".into()),
            "1.2.3.4".into(),
            443,
            "直连\n换行".into(),
            "来源：\"模块\"".into(),
            true,
        );
        let json = to_json_array(&t.snapshot(10));
        assert!(json.contains("quo\\\"te"));
        assert!(!json.contains('\n'));
    }
}
