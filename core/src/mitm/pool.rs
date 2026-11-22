//! MITM 上游连接池（灰度，默认关闭）。
//!
//! h1：每条池化连接是独占租约，借用期间不能被第二个请求复用；响应完整读完后
//! 才按 keep-alive 条件放回。连接键包含 host/port/scheme/ALPN/SNI/insecure 与
//! 已解析的 target/action，避免配置热更后把请求复用到错误的线路。
//!
//! h2：同键连接可被多条下游流共享；容量由对端 SETTINGS_MAX_CONCURRENT_STREAMS
//! 决定（见 `h2.rs` 的池化入口），GOAWAY/发送失败时立即从池中摘除。
//! 只有显式打开 `mitm.poolEnabled` 才启用，关闭时行为与 2.9 之前一致。

use crate::config::Target;
use crate::engine::Action;
use crate::mitm::http1::Buffered;
use crate::outbound::BoxStream;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_H1_IDLE: usize = 64;
/// h2 全池条目上限：单键 4 条只限同域，跨域仍可能累积；全池按最旧空闲淘汰。
const MAX_H2_IDLE: usize = 128;

/// 池键：host+port+scheme+ALPN+SNI+insecure，再带 target/线路，
/// 防止配置热更或策略切换后把请求复用到错误的节点。
pub fn h1_key(host: &str, target: &Target, action: &Action, insecure: bool) -> String {
    let route = match action {
        Action::Direct => "direct".to_string(),
        Action::Proxy => "proxy".to_string(),
        Action::Block => "block".to_string(),
        Action::Node(n) => format!("node:{}", n),
        Action::Group(g) => format!("group:{}", g),
        Action::Missing(m) => format!("missing:{}", m),
    };
    format!(
        "h1|{}|{}|{}|{}|{}|{}|{}",
        host.trim_end_matches('.').to_ascii_lowercase(),
        target.port,
        target.domain.as_deref().unwrap_or(""),
        target.ip,
        route,
        insecure,
        "https+http/1.1"
    )
}

pub struct H1Conn {
    pub up: Buffered<BoxStream>,
    last_used: Instant,
}

impl H1Conn {
    pub fn new(up: Buffered<BoxStream>) -> Self {
        Self {
            up,
            last_used: Instant::now(),
        }
    }
}

pub struct MitmPool {
    enabled: bool,
    idle_secs: u64,
    h1: Mutex<HashMap<String, Vec<H1Conn>>>,
    h2: Mutex<HashMap<String, Vec<Arc<H2Entry>>>>,
    stats: Option<Arc<crate::stats::Stats>>,
}

impl MitmPool {
    pub fn new(enabled: bool, idle_secs: u64, stats: Option<Arc<crate::stats::Stats>>) -> Self {
        Self {
            enabled,
            idle_secs: idle_secs.max(5),
            h1: Mutex::new(HashMap::new()),
            h2: Mutex::new(HashMap::new()),
            stats,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn idle(&self) -> Duration {
        Duration::from_secs(self.idle_secs)
    }

    /// 取一条可复用的 h1 连接；取不到返回 None，由调用方新建并走 miss 计数。
    pub fn take_h1(&self, key: &str) -> Option<H1Conn> {
        if !self.enabled {
            return None;
        }
        let mut g = self.h1.lock().unwrap_or_else(|p| p.into_inner());
        let Some(list) = g.get_mut(key) else {
            self.bump_miss();
            return None;
        };
        while let Some(conn) = list.pop() {
            if conn.last_used.elapsed() <= self.idle() {
                if let Some(st) = &self.stats {
                    st.mitm_pool_h1_hit.fetch_add(1, Ordering::Relaxed);
                }
                return Some(conn);
            }
            self.bump_evict();
        }
        g.remove(key);
        self.bump_miss();
        None
    }

    /// 完整消费响应后放回；调用方必须在确认可复用时才调用。
    pub fn release_h1(&self, key: String, up: Buffered<BoxStream>) {
        if !self.enabled {
            return;
        }
        let mut g = self.h1.lock().unwrap_or_else(|p| p.into_inner());
        let exists = g.contains_key(&key);
        if g.len() >= MAX_H1_IDLE && !exists {
            if let Some(old) = g.keys().next().cloned() {
                g.remove(&old);
                self.bump_evict();
            }
        }
        let list = g.entry(key).or_default();
        if !list.is_empty() {
            list.clear();
            self.bump_evict();
        }
        if let Some(st) = &self.stats {
            st.mitm_pool_h1_reuse.fetch_add(1, Ordering::Relaxed);
        }
        list.push(H1Conn {
            up,
            last_used: Instant::now(),
        });
    }

    fn bump_miss(&self) {
        if let Some(st) = &self.stats {
            st.mitm_pool_h1_miss.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn bump_evict(&self) {
        if let Some(st) = &self.stats {
            st.mitm_pool_h1_evict.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub struct H2Entry {
    pub send: ::h2::client::SendRequest<Bytes>,
    max_streams: usize,
    active: AtomicUsize,
    closed: AtomicBool,
    last_used: Mutex<Instant>,
}

impl H2Entry {
    pub fn new(send: ::h2::client::SendRequest<Bytes>, max_streams: usize) -> Self {
        Self {
            send,
            max_streams: max_streams.max(1),
            active: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            last_used: Mutex::new(Instant::now()),
        }
    }

    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    pub fn reserve_unbounded(self: &Arc<Self>) -> Option<H2Lease> {
        if self.closed.load(Ordering::Relaxed) {
            return None;
        }
        self.active.fetch_add(1, Ordering::Relaxed);
        Some(H2Lease {
            entry: self.clone(),
        })
    }

    pub fn reserve(self: &Arc<Self>) -> Option<H2Lease> {
        if self.closed.load(Ordering::Relaxed) {
            return None;
        }
        loop {
            let active = self.active.load(Ordering::Relaxed);
            if active >= self.max_streams {
                return None;
            }
            if self
                .active
                .compare_exchange(active, active + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                if let Ok(mut t) = self.last_used.lock() {
                    *t = Instant::now();
                }
                return Some(H2Lease {
                    entry: self.clone(),
                });
            }
        }
    }
}

pub struct H2Lease {
    pub entry: Arc<H2Entry>,
}

impl H2Lease {
    pub fn send(&self) -> ::h2::client::SendRequest<Bytes> {
        self.entry.send.clone()
    }
}

impl Drop for H2Lease {
    fn drop(&mut self) {
        self.entry.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl MitmPool {
    /// 取一条有 SETTINGS 容量的 h2 连接；返回的 lease 在请求结束前持有流配额。
    pub fn take_h2(&self, key: &str) -> Option<H2Lease> {
        if !self.enabled {
            return None;
        }
        let mut g = self.h2.lock().unwrap_or_else(|p| p.into_inner());
        let Some(list) = g.get_mut(key) else {
            self.bump_h2_miss();
            return None;
        };
        // 不能只看列表尾：尾连接满了不代表同键前面的连接也满。全部扫一遍，
        // 满的连接留在池里继续服务已有流，只有真的没有一条能 reserve 才新建。
        let mut entries = std::mem::take(list);
        let mut kept = Vec::with_capacity(entries.len());
        let mut lease = None;
        for entry in entries.drain(..) {
            if entry.closed.load(Ordering::Relaxed) {
                self.bump_h2_evict();
                continue;
            }
            let idle = entry
                .last_used
                .lock()
                .map(|t| t.elapsed())
                .unwrap_or_default();
            if idle > self.idle() {
                entry.mark_closed();
                self.bump_h2_evict();
                continue;
            }
            if lease.is_none() {
                if let Some(l) = entry.reserve() {
                    lease = Some(l);
                    kept.push(entry);
                    continue;
                }
            }
            kept.push(entry);
        }
        let empty = kept.is_empty();
        *list = kept;
        if empty {
            g.remove(key);
        }
        if let Some(lease) = lease {
            if let Some(st) = &self.stats {
                st.mitm_pool_h2_hit.fetch_add(1, Ordering::Relaxed);
            }
            return Some(lease);
        }
        self.bump_h2_miss();
        None
    }

    pub fn offer_h2(&self, key: String, entry: Arc<H2Entry>) {
        if !self.enabled {
            return;
        }
        let mut g = self.h2.lock().unwrap_or_else(|p| p.into_inner());
        // 全池上限：先腾位置。淘汰只从池中摘除并 mark_closed，已有流的 lease 仍持有 Arc，
        // 会继续收尾；当前请求刚拿到的 lease 也不受影响。
        while h2_total(&g) >= MAX_H2_IDLE {
            if !evict_oldest_h2(&mut g, self.stats.as_ref()) {
                return;
            }
        }
        let list = g.entry(key).or_default();
        if let Some(st) = &self.stats {
            st.mitm_pool_h2_reuse.fetch_add(1, Ordering::Relaxed);
        }
        list.push(entry);
        while list.len() > 4 {
            list.remove(0);
            self.bump_h2_evict();
        }
    }

    pub fn evict_h2(&self, entry: &Arc<H2Entry>) {
        entry.mark_closed();
        if self.enabled {
            if let Some(st) = &self.stats {
                st.mitm_pool_h2_evict.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn bump_h2_miss(&self) {
        if let Some(st) = &self.stats {
            st.mitm_pool_h2_miss.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn bump_h2_evict(&self) {
        if let Some(st) = &self.stats {
            st.mitm_pool_h2_evict.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn h2_total(g: &HashMap<String, Vec<Arc<H2Entry>>>) -> usize {
    g.values().map(Vec::len).sum()
}

/// 跨键淘汰最久未使用的 h2 条目；只 mark_closed，已有流继续收尾。
fn evict_oldest_h2(
    g: &mut HashMap<String, Vec<Arc<H2Entry>>>,
    stats: Option<&Arc<crate::stats::Stats>>,
) -> bool {
    let mut victim: Option<(String, usize, Instant)> = None;
    for (key, list) in g.iter() {
        for (idx, entry) in list.iter().enumerate() {
            let used = entry
                .last_used
                .lock()
                .map(|t| *t)
                .unwrap_or_else(|p| *p.into_inner());
            if victim
                .as_ref()
                .map(|(_, _, oldest)| used < *oldest)
                .unwrap_or(true)
            {
                victim = Some((key.clone(), idx, used));
            }
        }
    }
    let Some((key, idx, _)) = victim else {
        return false;
    };
    let Some(list) = g.get_mut(&key) else {
        return false;
    };
    if idx >= list.len() {
        return false;
    }
    let entry = list.remove(idx);
    entry.mark_closed();
    if let Some(st) = stats {
        st.mitm_pool_h2_evict.fetch_add(1, Ordering::Relaxed);
    }
    true
}

pub fn h2_key(host: &str, target: &Target, action: &Action, insecure: bool) -> String {
    h1_key(host, target, action, insecure)
        .replacen("h1|", "h2|", 1)
        .replace("https+http/1.1", "https+h2")
}

/// 独占 h1 租约：Drop 时把完整消费且声明可复用的连接放回池。
pub struct H1Lease {
    pool: Arc<MitmPool>,
    key: String,
    up: Option<H1Conn>,
    reusable: bool,
}

impl H1Lease {
    pub fn new(pool: Arc<MitmPool>, key: String, conn: H1Conn) -> Self {
        Self {
            pool,
            key,
            up: Some(conn),
            reusable: false,
        }
    }

    pub fn up(&mut self) -> &mut Buffered<BoxStream> {
        &mut self.up.as_mut().expect("h1 lease 已释放").up
    }

    pub fn mark_reusable(&mut self) {
        self.reusable = true;
    }
}

impl Drop for H1Lease {
    fn drop(&mut self) {
        if self.reusable {
            if let Some(conn) = self.up.take() {
                self.pool.release_h1(std::mem::take(&mut self.key), conn.up);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Action;

    fn target() -> Target {
        Target {
            ip: "127.0.0.1".parse().unwrap(),
            port: 443,
            domain: Some("api.example.com".into()),
        }
    }

    #[test]
    fn pool_key_separates_route_and_security() {
        let a = h1_key("api.example.com", &target(), &Action::Direct, false);
        let b = h1_key(
            "api.example.com",
            &target(),
            &Action::Node("hk".into()),
            false,
        );
        let c = h1_key("api.example.com", &target(), &Action::Direct, true);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(
            a,
            h1_key("API.EXAMPLE.COM.", &target(), &Action::Direct, false)
        );
    }

    #[tokio::test]
    async fn disabled_pool_never_reuses_h1() {
        let pool = MitmPool::new(false, 30, None);
        let stream = Box::new(tokio::io::duplex(16).0) as BoxStream;
        pool.release_h1("k".into(), Buffered::new(stream));
        assert!(pool.take_h1("k").is_none());
    }

    #[tokio::test]
    async fn enabled_pool_reuses_h1_once() {
        let stats = Arc::new(crate::stats::Stats::new());
        let pool = MitmPool::new(true, 30, Some(stats.clone()));
        let stream = Box::new(tokio::io::duplex(16).0) as BoxStream;
        pool.release_h1("k".into(), Buffered::new(stream));
        assert!(pool.take_h1("k").is_some());
        assert_eq!(stats.mitm_pool_h1_reuse.load(Ordering::Relaxed), 1);
        assert_eq!(stats.mitm_pool_h1_hit.load(Ordering::Relaxed), 1);
        assert!(pool.take_h1("k").is_none());
    }
}
