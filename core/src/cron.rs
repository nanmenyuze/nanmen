//! 5 段 cron 解析与本地时区下次触发计算。
//!
//! 只做调度，不执行脚本；执行由 mitm 脚本引擎承担。支持 `*`、`*/n`、
//! `a-b`、`a-b/n`、逗号列表；DOW 允许 0-7（0/7 都是周日）。不支持秒级、
//! `@reboot`、时区后缀、L/W/# 等扩展。

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

/// cron 与 network-changed/generic 共用的串行闸：同一脚本上一轮未完成时跳过。
static INFLIGHT: Lazy<Mutex<std::collections::HashSet<String>>> =
    Lazy::new(|| Mutex::new(std::collections::HashSet::new()));

/// 无解 cron 表达式的复查间隔；表达式本身不会变，复查只是给系统时区/时钟调整留余地。
const UNSOLVABLE_RECHECK_SECS: u64 = 6 * 60 * 60;

/// 由 nativeStart 启动、nativeStop 取消的定时/事件调度循环。
/// 不注册系统服务、不持 WakeLock/AlarmManager：VPN 关闭即随 tokio runtime 退出。
pub async fn run_cron_loop(
    shutdown: Arc<AtomicBool>,
    mitm: Arc<RwLock<Arc<crate::mitm::MitmState>>>,
) {
    let mut next: HashMap<String, u64> = HashMap::new();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let state = mitm.read().unwrap_or_else(|p| p.into_inner()).clone();
        let rules: Vec<_> = state
            .engine
            .scripts
            .rules
            .iter()
            .filter(|r| r.cron_spec.is_some())
            .cloned()
            .collect();
        let now = now_secs();
        // cron 表达式变更后 schedule_key 会变；清掉不再对应任何规则的旧键，
        // 避免旧时间在下一轮继续命中。
        next.retain(|key, _| rules.iter().any(|r| r.schedule_key() == *key));
        for rule in rules {
            let Some(spec) = rule.cron_spec.as_ref() else {
                continue;
            };
            let schedule_key = rule.schedule_key();
            let due_at = match next.get(&schedule_key) {
                Some(v) => *v,
                None => match spec.next_after(now) {
                    Some(v) => {
                        next.insert(schedule_key, v);
                        continue;
                    }
                    None => {
                        // 2 月 30 日这类无解表达式：记下复查时间，别每秒重扫 527040 分钟。
                        next.insert(schedule_key, now + UNSOLVABLE_RECHECK_SECS);
                        continue;
                    }
                },
            };
            if due_at > now {
                continue;
            }
            // 同一脚本串行：上一轮还没跑完就跳过本次。
            let mut following = spec.next_after(now).unwrap_or(now + 60);
            if following < now + 30 {
                following = now + 30;
            }
            next.insert(schedule_key, following);
            let jitter = 5 + (now % 26);
            spawn_trigger(
                rule,
                shutdown.clone(),
                jitter as u64,
                mitm.clone(),
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// network-changed / generic 共用入口：选择 trigger 匹配的脚本，串行执行。
pub fn trigger_scripts(
    kind: &str,
    mitm: &Arc<RwLock<Arc<crate::mitm::MitmState>>>,
    shutdown: &Arc<AtomicBool>,
    debounce_secs: u64,
) -> usize {
    let state = mitm.read().unwrap_or_else(|p| p.into_inner()).clone();
    let rules: Vec<_> = state
        .engine
        .scripts
        .rules
        .iter()
        .filter(|r| {
            let t = if r.trigger.is_empty() {
                if !r.cron.is_empty() {
                    "cron"
                } else {
                    "generic"
                }
            } else {
                r.trigger.as_str()
            };
            t.eq_ignore_ascii_case(kind)
        })
        .cloned()
        .collect();
    let mut started = 0;
    for rule in rules {
        if INFLIGHT
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(rule.key.clone())
        {
            spawn_trigger_inner(
                rule,
                shutdown.clone(),
                debounce_secs,
                mitm.clone(),
            );
            started += 1;
        }
    }
    started
}

fn spawn_trigger(
    rule: crate::script::CompiledScriptRule,
    shutdown: Arc<AtomicBool>,
    delay_secs: u64,
    mitm: Arc<RwLock<Arc<crate::mitm::MitmState>>>,
) {
    if !INFLIGHT
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(rule.key.clone())
    {
        return;
    }
    spawn_trigger_inner(rule, shutdown, delay_secs, mitm);
}

fn spawn_trigger_inner(
    rule: crate::script::CompiledScriptRule,
    shutdown: Arc<AtomicBool>,
    delay_secs: u64,
    mitm: Arc<RwLock<Arc<crate::mitm::MitmState>>>,
) {
    let key = rule.key.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(delay_secs.max(1))).await;
        if shutdown.load(Ordering::Relaxed) {
            INFLIGHT
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&key);
            return;
        }
        // 延迟队列里持有的是入队时的脚本快照。执行前必须回到当前脚本表校验：
        // 脚本被删除/停用、cron 改写或正文被热替换时，旧任务不能按旧时间再跑一次。
        let latest = mitm.read().unwrap_or_else(|p| p.into_inner()).clone();
        let Some(current) = latest
            .engine
            .scripts
            .rules
            .iter()
            .find(|r| {
                r.key == rule.key
                    && r.cron == rule.cron
                    && r.trigger == rule.trigger
                    && r.source == rule.source
            })
            .cloned()
        else {
            crate::logging::warn(
                "cron",
                format!("触发任务已过期，跳过: {} ({})", rule.name, rule.key),
            );
            INFLIGHT
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&key);
            return;
        };
        let state2 = latest;
        let rule2 = current;
        let result = tokio::task::spawn_blocking(move || state2.run_trigger_rule(&rule2)).await;
        match result {
            Ok(errors) => {
                for e in errors {
                    crate::logging::warn("cron", e);
                }
            }
            Err(e) => crate::logging::warn("cron", format!("触发任务 join 失败: {}", e)),
        }
        INFLIGHT
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key);
    });
}

#[derive(Clone, Debug)]
pub struct CronSpec {
    minute: [bool; 60],
    hour: [bool; 24],
    dom: [bool; 32],
    month: [bool; 13],
    dow: [bool; 7],
    dom_wildcard: bool,
    dow_wildcard: bool,
    source: String,
}

fn parse_field(raw: &str, min: u32, max: u32, wildcard: bool) -> Option<(Vec<u32>, bool)> {
    let mut out = Vec::new();
    let mut any_wildcard = wildcard;
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => {
                let step = s.parse::<u32>().ok()?;
                if step == 0 {
                    return None;
                }
                (r, step)
            }
            None => (part, 1),
        };
        let (start, end) = if range == "*" {
            any_wildcard = true;
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (a.parse().ok()?, b.parse().ok()?)
        } else {
            let v = range.parse::<u32>().ok()?;
            (v, v)
        };
        if start < min || end > max || start > end {
            return None;
        }
        let mut v = start;
        while v <= end {
            out.push(v);
            v += step;
        }
    }
    out.sort_unstable();
    out.dedup();
    Some((out, any_wildcard))
}

impl CronSpec {
    pub fn parse(expr: &str) -> Option<Self> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return None;
        }
        let (minutes, _) = parse_field(fields[0], 0, 59, false)?;
        let (hours, _) = parse_field(fields[1], 0, 23, false)?;
        let (doms, dom_wildcard) = parse_field(fields[2], 1, 31, fields[2].trim() == "*")?;
        let (months, _) = parse_field(fields[3], 1, 12, false)?;
        let (dows, dow_wildcard) = parse_field(fields[4], 0, 7, fields[4].trim() == "*")?;
        let mut minute = [false; 60];
        for v in minutes {
            minute[v as usize] = true;
        }
        let mut hour = [false; 24];
        for v in hours {
            hour[v as usize] = true;
        }
        let mut dom = [false; 32];
        for v in doms {
            dom[v as usize] = true;
        }
        let mut month = [false; 13];
        for v in months {
            month[v as usize] = true;
        }
        let mut dow = [false; 7];
        for v in dows {
            dow[(v % 7) as usize] = true;
        }
        Some(Self {
            minute,
            hour,
            dom,
            month,
            dow,
            dom_wildcard,
            dow_wildcard,
            source: expr.trim().to_string(),
        })
    }

    pub fn matches_local(&self, secs: u64) -> bool {
        let Some(t) = local_fields(secs) else {
            return false;
        };
        if !self.minute[t.minute as usize]
            || !self.hour[t.hour as usize]
            || !self.month[t.month as usize]
        {
            return false;
        }
        let dom_ok = self.dom[t.day as usize];
        let dow_ok = self.dow[t.wday as usize];
        if self.dom_wildcard && self.dow_wildcard {
            true
        } else if self.dom_wildcard {
            dow_ok
        } else if self.dow_wildcard {
            dom_ok
        } else {
            // Vixie cron：DOM/DOW 同时受限时取并集。
            dom_ok || dow_ok
        }
    }

    /// 下一次触发（严格晚于 from），按本地时区计算；无解时返回 None。
    pub fn next_after(&self, from: u64) -> Option<u64> {
        let mut t = from.saturating_sub(from % 60) + 60;
        // 上限 366 天，避免 2 月 30 日这类表达式空转。
        for _ in 0..(366 * 24 * 60) {
            if self.matches_local(t) {
                return Some(t);
            }
            t += 60;
        }
        None
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}

#[derive(Clone, Copy, Debug)]
struct LocalTime {
    minute: u32,
    hour: u32,
    day: u32,
    month: u32,
    wday: u32,
}

fn local_fields(secs: u64) -> Option<LocalTime> {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let raw = secs as libc::time_t;
    let ok = unsafe { libc::localtime_r(&raw, &mut tm) };
    if ok.is_null() {
        return None;
    }
    Some(LocalTime {
        minute: tm.tm_min as u32,
        hour: tm.tm_hour as u32,
        day: tm.tm_mday as u32,
        month: (tm.tm_mon + 1) as u32,
        wday: tm.tm_wday as u32,
    })
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_five_fields_and_rejects_invalid() {
        assert!(CronSpec::parse("* * * * *").is_some());
        assert!(CronSpec::parse("*/5 0-6 1,15 * 1-5").is_some());
        assert!(CronSpec::parse("0 9 * * * *").is_none());
        assert!(CronSpec::parse("60 * * * *").is_none());
        assert!(CronSpec::parse("* 24 * * *").is_none());
        assert!(CronSpec::parse("* * 0 * *").is_none());
        assert!(CronSpec::parse("* * * 13 *").is_none());
        assert!(CronSpec::parse("* * * * 8").is_none());
        assert!(CronSpec::parse("* * * *").is_none());
        assert!(CronSpec::parse("@reboot").is_none());
        assert!(CronSpec::parse("* * * * * Asia/Shanghai").is_none());
    }

    #[test]
    fn every_minute_is_exactly_one_minute_later() {
        let spec = CronSpec::parse("* * * * *").unwrap();
        let from = 1_700_000_040;
        assert_eq!(spec.next_after(from), Some(from + 60));
        assert!(spec.matches_local(from + 60));
    }

    #[test]
    fn rejects_unsatisfiable_calendar_date() {
        // 2 月 30 日永远不会到来；扫描一年后返回 None，而不是死循环。
        let spec = CronSpec::parse("0 0 30 2 *").unwrap();
        assert_eq!(spec.next_after(now_secs()), None);
    }
}
