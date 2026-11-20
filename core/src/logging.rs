use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Clone, Serialize)]
pub struct LogItem {
    pub id: u64,
    pub ts: u64,
    pub level: String,
    pub tag: String,
    pub msg: String,
}

struct Inner {
    seq: u64,
    items: VecDeque<LogItem>,
}

static LOG: Lazy<Mutex<Inner>> = Lazy::new(|| {
    Mutex::new(Inner {
        seq: 0,
        items: VecDeque::with_capacity(600),
    })
});

static LAST_TS: AtomicU64 = AtomicU64::new(0);

pub fn log(level: &str, tag: &str, msg: impl AsRef<str>) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    LAST_TS.store(ts, Ordering::Relaxed);
    let mut inner = match LOG.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    inner.seq += 1;
    let id = inner.seq;
    if inner.items.len() >= 600 {
        inner.items.pop_front();
    }
    // 单条日志限长：异常/上游报错可能带整段报文，不截断会让 600 条环形缓冲吃掉几十 MB。
    let text = msg.as_ref();
    let msg = if text.len() > 1024 {
        format!("{}…[截断 {} 字节]", &text[..text.char_indices().take_while(|(i, _)| *i <= 1024).last().map(|(i, _)| i).unwrap_or(0)], text.len())
    } else {
        text.to_string()
    };
    inner.items.push_back(LogItem {
        id,
        ts,
        level: level.to_string(),
        tag: tag.to_string(),
        msg,
    });
}

pub fn info(tag: &str, msg: impl AsRef<str>) {
    log("I", tag, msg)
}

pub fn warn(tag: &str, msg: impl AsRef<str>) {
    log("W", tag, msg)
}

pub fn error(tag: &str, msg: impl AsRef<str>) {
    log("E", tag, msg)
}

pub fn dump_since(since: u64) -> Vec<LogItem> {
    let inner = match LOG.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    inner
        .items
        .iter()
        .filter(|it| it.id > since)
        .cloned()
        .collect()
}

pub fn clear() {
    let mut inner = match LOG.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    inner.items.clear();
}

pub fn json_since(since: u64) -> String {
    serde_json::to_string(&dump_since(since)).unwrap_or_else(|_| "[]".into())
}
