use serde_json::json;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use once_cell::sync::Lazy;

/// UDP 截断转 TCP 次数（无引擎上下文的全局计数）
pub static STATS_TCP: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));

#[derive(Default)]
pub struct Stats {
    pub started_at: AtomicI64,
    /// 停止时点（0 = 仍在运行）：停止后 uptime 冻结，不再随墙钟增长。
    pub stopped_at: AtomicI64,
    pub up_bytes: AtomicU64,
    pub down_bytes: AtomicU64,
    pub dns_queries: AtomicU64,
    /// 被内核拒绝的 DoT/DoQ（853）连接数。
    pub dot_blocked: AtomicU64,
    pub dns_blocked: AtomicU64,
    pub active_conns: AtomicI64,
    pub total_conns: AtomicU64,
    pub tcp_packets: AtomicU64,
    pub filter_rules: AtomicU64,
    pub filter_skipped: AtomicU64,
    pub dns_cached: AtomicU64,
    /// 进入缓存查询路径的次数（不含本地拦截/AAAA 过滤/DoT 阻断），
    /// 用于计算真实缓存命中率，避免被大量本地拦截拉低。
    pub dns_cache_lookups: AtomicU64,
    pub dns_stale: AtomicU64,
    pub dns_negative: AtomicU64,
    pub dns_coalesced: AtomicU64,
    pub dns_rebind: AtomicU64,
    pub dns_fallback: AtomicU64,
    /// 备用查询按原因拆分：主上游失败 / 熔断 / 竞速胜出 / 策略复核。
    pub dns_fallback_fail: AtomicU64,
    pub dns_fallback_breaker: AtomicU64,
    pub dns_fallback_race: AtomicU64,
    pub dns_fallback_review: AtomicU64,
    pub dns_aaaa_blocked: AtomicU64,
    pub dns_ms_sum: AtomicU64,
    pub dns_ms_count: AtomicU64,
    /// 本地拦截/缓存/过滤应答耗时，和上游往返分开统计。
    pub dns_local_ms_sum: AtomicU64,
    pub dns_local_ms_count: AtomicU64,
    /// 连接序号：失败日志用它和并发连接一一对应。
    pub conn_seq: AtomicU64,
    /// DNS 上游耗时分布：<10ms / <50 / <100 / <300 / <1000 / >=1000。
    pub dns_lat_lt10: AtomicU64,
    pub dns_lat_lt50: AtomicU64,
    pub dns_lat_lt100: AtomicU64,
    pub dns_lat_lt300: AtomicU64,
    pub dns_lat_lt1000: AtomicU64,
    pub dns_lat_ge1000: AtomicU64,
    /// MITM：成功解密的连接数 / 拒绝的广告请求 / 改写的响应 / 握手失败放行 / 拒绝的 QUIC。
    pub mitm_conns: AtomicU64,
    pub mitm_rejected: AtomicU64,
    pub mitm_rewritten: AtomicU64,
    pub mitm_failed: AtomicU64,
    pub mitm_quic_blocked: AtomicU64,
}

impl Stats {
    /// 记录一次上游往返耗时，用于界面显示平均 DNS 延迟。
    pub fn record_dns_ms(&self, ms: u64) {
        self.dns_ms_sum.fetch_add(ms, Ordering::Relaxed);
        self.dns_ms_count.fetch_add(1, Ordering::Relaxed);
        let bucket = if ms < 10 {
            &self.dns_lat_lt10
        } else if ms < 50 {
            &self.dns_lat_lt50
        } else if ms < 100 {
            &self.dns_lat_lt100
        } else if ms < 300 {
            &self.dns_lat_lt300
        } else if ms < 1000 {
            &self.dns_lat_lt1000
        } else {
            &self.dns_lat_ge1000
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录一次本地路径（拦截/缓存/过滤）的应答耗时。
    pub fn record_local_ms(&self, ms: u64) {
        self.dns_local_ms_sum.fetch_add(ms, Ordering::Relaxed);
        self.dns_local_ms_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录一次「备用查询被采用」，并按原因拆分。
    pub fn record_fallback(&self, reason: FallbackReason) {
        self.dns_fallback.fetch_add(1, Ordering::Relaxed);
        match reason {
            FallbackReason::PrimaryFailure => self.dns_fallback_fail.fetch_add(1, Ordering::Relaxed),
            FallbackReason::Breaker => self.dns_fallback_breaker.fetch_add(1, Ordering::Relaxed),
            FallbackReason::Race => self.dns_fallback_race.fetch_add(1, Ordering::Relaxed),
            FallbackReason::Review => self.dns_fallback_review.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn new_conn_id(&self) -> u64 {
        self.conn_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn new() -> Self {
        let s = Self::default();
        s.started_at.store(now_ms() as i64, Ordering::Relaxed);
        s
    }
    pub fn to_json(&self) -> String {
        let start = self.started_at.load(Ordering::Relaxed);
        let stopped = self.stopped_at.load(Ordering::Relaxed);
        let end = if stopped > 0 { stopped } else { now_ms() as i64 };
        let uptime = (end - start).max(0) as u64;
        let n = self.dns_ms_count.load(Ordering::Relaxed);
        let avg = if n == 0 { 0 } else { self.dns_ms_sum.load(Ordering::Relaxed) / n };
        let local_n = self.dns_local_ms_count.load(Ordering::Relaxed);
        let local_avg = if local_n == 0 { 0 } else { self.dns_local_ms_sum.load(Ordering::Relaxed) / local_n };
        json!({
            "up": self.up_bytes.load(Ordering::Relaxed),
            "down": self.down_bytes.load(Ordering::Relaxed),
            "dnsQueries": self.dns_queries.load(Ordering::Relaxed),
            "dotBlocked": self.dot_blocked.load(Ordering::Relaxed),
            "dnsBlocked": self.dns_blocked.load(Ordering::Relaxed),
            "activeConns": self.active_conns.load(Ordering::Relaxed),
            "totalConns": self.total_conns.load(Ordering::Relaxed),
            "filterRules": self.filter_rules.load(Ordering::Relaxed),
            "filterSkipped": self.filter_skipped.load(Ordering::Relaxed),
            "dnsCached": self.dns_cached.load(Ordering::Relaxed),
            "dnsCacheLookups": self.dns_cache_lookups.load(Ordering::Relaxed),
            "dnsStale": self.dns_stale.load(Ordering::Relaxed),
            "dnsNegative": self.dns_negative.load(Ordering::Relaxed),
            "dnsCoalesced": self.dns_coalesced.load(Ordering::Relaxed),
            "dnsRebind": self.dns_rebind.load(Ordering::Relaxed),
            "dnsFallback": self.dns_fallback.load(Ordering::Relaxed),
            "dnsFallbackFail": self.dns_fallback_fail.load(Ordering::Relaxed),
            "dnsFallbackBreaker": self.dns_fallback_breaker.load(Ordering::Relaxed),
            "dnsFallbackRace": self.dns_fallback_race.load(Ordering::Relaxed),
            "dnsFallbackReview": self.dns_fallback_review.load(Ordering::Relaxed),
            "dnsTcpRetry": STATS_TCP.load(Ordering::Relaxed),
            "dnsAaaaBlocked": self.dns_aaaa_blocked.load(Ordering::Relaxed),
            "dnsAvgMs": avg,
            "dnsLocalAvgMs": local_avg,
            "dnsLatency": {
                "lt10": self.dns_lat_lt10.load(Ordering::Relaxed),
                "lt50": self.dns_lat_lt50.load(Ordering::Relaxed),
                "lt100": self.dns_lat_lt100.load(Ordering::Relaxed),
                "lt300": self.dns_lat_lt300.load(Ordering::Relaxed),
                "lt1000": self.dns_lat_lt1000.load(Ordering::Relaxed),
                "ge1000": self.dns_lat_ge1000.load(Ordering::Relaxed),
            },
            "mitmConns": self.mitm_conns.load(Ordering::Relaxed),
            "mitmRejected": self.mitm_rejected.load(Ordering::Relaxed),
            "mitmRewritten": self.mitm_rewritten.load(Ordering::Relaxed),
            "mitmFailed": self.mitm_failed.load(Ordering::Relaxed),
            "mitmQuicBlocked": self.mitm_quic_blocked.load(Ordering::Relaxed),
            "uptime": uptime,
        })
        .to_string()
    }
}

#[derive(Clone, Copy)]
pub enum FallbackReason {
    PrimaryFailure,
    Breaker,
    Race,
    Review,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
