#![recursion_limit = "512"]

pub mod config;
pub mod conns;
pub mod cron;
pub mod dns;
pub mod dns_log;
pub mod engine;
pub mod finance;
pub mod hits;
pub mod logging;
pub mod mitm;
pub mod netstack;
pub mod outbound;
pub mod proto;
pub mod quic;
pub mod script;
pub mod sniff;
pub mod stats;
pub mod strategy;
pub mod subscribe;
pub mod udp;
pub mod uidmap;

use crate::config::Config;
use crate::dns::DnsEngine;
use crate::engine::{build_filter, load_cn_ips, Action, ConnKind, FilterEngine, RuleEngine};
use crate::netstack::Ctx;
use crate::stats::Stats;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::JNIEnv;
use once_cell::sync::Lazy;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Engine {
    rt: tokio::runtime::Runtime,
    shutdown: Arc<AtomicBool>,
    stats: Arc<Stats>,
    ctx: Arc<Ctx>,
}

static ENGINE: Lazy<Mutex<Option<Engine>>> = Lazy::new(|| Mutex::new(None));

fn stop_engine() {
    let mut guard = match ENGINE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(engine) = guard.take() {
        logging::info("core", "正在停止：通知协议栈释放 TUN");
        engine.shutdown.store(true, Ordering::Relaxed);
        engine
            .ctx
            .dns
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .save_state();
        engine.stats.hits.persist();
        // 冻结统计时点：停止后 nativeStats 仍返回本次会话的汇总，uptime 不再增长。
        engine
            .stats
            .stopped_at
            .store(crate::stats::now_ms() as i64, Ordering::Relaxed);
        ENGINE_STATS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone_from(&engine.stats);
        engine.rt.shutdown_timeout(Duration::from_secs(3));
        logging::info("core", "已停止：运行时与 TUN 资源已释放");
    }
}

static ENGINE_STATS: Lazy<Mutex<Arc<Stats>>> = Lazy::new(|| Mutex::new(Arc::new(Stats::new())));

/// 壳层最近一次下发的 UID 表（紧凑 JSON）。nativeSetUidMap 在没有运行中的
/// 内核时先存这里，等 nativeStart 建好会话再应用，避免启动窗口期丢规则。
static UID_TABLE_PENDING: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

fn read_string(env: &mut JNIEnv, s: &JString) -> Option<String> {
    let js = env.get_string(s).ok()?;
    Some(String::from(js))
}

/// fallback 污染复核用的 CN IP 段，与分流共用同一份 cnip.txt。
fn cn_ips_for(cfg: &Config) -> Vec<(u32, u32)> {
    cfg.cn_ip_file
        .as_ref()
        .map(|p| load_cn_ips(p))
        .unwrap_or_default()
}

fn to_jstring(env: &mut JNIEnv, text: String) -> jstring {
    match env.new_string(text) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Validate the same payload accepted by nativeStart without changing the running engine.
#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeValidateConfig<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(json) = read_string(&mut env, &config_json) else {
            return false;
        };
        match config::parse_lenient(&json) {
            Ok(_) => true,
            Err(e) => {
                logging::error(
                    "core",
                    format!(
                        "配置校验失败: {} {}",
                        e,
                        config::error_context(&json, &e)
                    ),
                );
                false
            }
        }
    }));
    matches!(result, Ok(true)) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
    config_json: JString<'local>,
) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(|| -> bool {
        let json = match read_string(&mut env, &config_json) {
            Some(s) => s,
            None => return false,
        };
        let cfg: Config = match config::parse_lenient(&json) {
            Ok(c) => c,
            Err(e) => {
                logging::error(
                    "core",
                    format!(
                        "配置解析失败: {} {}",
                        e,
                        config::error_context(&json, &e)
                    ),
                );
                return false;
            }
        };
        if fd <= 0 {
            logging::error("core", "无效的 TUN fd");
            return false;
        }
        stop_engine();

        let filter: Arc<FilterEngine> = Arc::new(build_filter(&cfg));
        let rules: Arc<RuleEngine> = Arc::new(RuleEngine::from_config(&cfg));
        let strategy = Arc::new(strategy::StrategySet::from_config(&cfg));
        if strategy.has_errors() {
            for issue in strategy.issues() {
                logging::warn(
                    "strategy",
                    format!(
                        "策略诊断 {}{}：{}",
                        if issue.group.is_empty() {
                            "全局".to_string()
                        } else {
                            issue.group.clone()
                        },
                        if issue.code.is_empty() {
                            "".to_string()
                        } else {
                            format!("/{}", issue.code)
                        },
                        issue.message
                    ),
                );
            }
        }
        let stats: Arc<Stats> = Arc::new(Stats::new());
        stats
            .hits
            .set_history_path(cfg.hit_history_file.clone());
        stats.hits.set_persist_enabled(cfg.hit_history_enabled);
        crate::outbound::set_tuning(cfg.bbr, stats.clone());
        stats
            .filter_rules
            .store(filter.rule_count() as u64, Ordering::Relaxed);
        stats
            .filter_skipped
            .store(filter.skipped as u64, Ordering::Relaxed);
        let mut dns_cfg = cfg.dns.clone();
        dns_cfg.block_aaaa = cfg.dns.block_aaaa || !cfg.ipv6;
        let mut dns = DnsEngine::new(
            &dns_cfg,
            filter.clone(),
            stats.clone(),
            &cfg.block_mode,
            cfg.block_enabled,
            cfg.fake_ip && cfg.mode != "dns_only" && cfg.mode != "filter_only",
            cfg.dns.query_log,
        );
        dns.set_prefer_ipv6(cfg.prefer_ipv6);
        dns.set_fake_path(if cfg.fake_ip && cfg.mode != "dns_only" {
            cfg.fake_ip_file.clone()
        } else {
            None
        });
        dns.set_cache_path(if cfg.dns.cache_file.trim().is_empty() {
            None
        } else {
            Some(cfg.dns.cache_file.clone())
        });
        dns.set_cn_ips(cn_ips_for(&cfg));
        let dns: Arc<DnsEngine> = Arc::new(dns);
        logging::info(
            "core",
            format!(
                "启动 mode={} 广告规则={} 分流规则={} 节点={} DNS={}",
                cfg.mode,
                filter.rule_count(),
                rules.rule_count,
                cfg.nodes.len(),
                cfg.dns.upstream
            ),
        );
        let shutdown = Arc::new(AtomicBool::new(false));
        let nodes = cfg.nodes.clone();
        let selected = cfg.selected.clone();
        let health = Arc::new(strategy::HealthRegistry::new());
        let mitm_state = Arc::new(std::sync::RwLock::new(Arc::new(
            mitm::MitmState::build_with_stats(&cfg.mitm, Some(stats.clone())),
        )));
        // 壳层可能在 nativeStart 之前就下发过 UID 表（服务启动顺序不保证），
        // 这里把最后一份 pending 表应用到新会话，避免刚启动的窗口期 UID 规则失效。
        let uid_map = Arc::new(std::sync::RwLock::new(crate::uidmap::UidMap::default()));
        if let Some(text) = UID_TABLE_PENDING
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        {
            let (rows, bad) = crate::uidmap::UidMap::parse_json(&text);
            if bad > 0 {
                logging::warn("uid", format!("UID 表启动应用：{} 条无效已跳过", bad));
            }
            uid_map
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .replace(rows);
        }
        let ctx = Arc::new(Ctx {
            cfg: std::sync::RwLock::new(cfg),
            filter,
            rules: Arc::new(std::sync::RwLock::new(rules)),
            dns: Arc::new(std::sync::RwLock::new(dns)),
            stats: stats.clone(),
            shutdown: shutdown.clone(),
            nodes: Arc::new(std::sync::RwLock::new(Arc::new(nodes))),
            selected: Arc::new(std::sync::RwLock::new(selected)),
            strategy: Arc::new(std::sync::RwLock::new(strategy)),
            health: health.clone(),
            decision: Arc::new(std::sync::RwLock::new(())),
            mitm: mitm_state,
            uid_map: uid_map.clone(),
            conns: Arc::new(std::sync::RwLock::new(crate::conns::ConnTable::new())),
            quic_clear: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });

        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(3)
            .enable_all()
            .thread_name("namu-core")
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                logging::error("core", format!("运行时创建失败: {}", e));
                return false;
            }
        };
        let ctx2 = ctx.clone();
        let health_ctx = ctx.clone();
        netstack::STACK_READY.store(false, Ordering::Release);
        rt.spawn(async move {
            if let Err(e) = netstack::run(fd as i32, ctx2).await {
                logging::error("tun", format!("协议栈异常退出: {}", e));
            }
        });
        let hs = health_ctx.shutdown.clone();
        let hstrat = health_ctx.strategy.clone();
        let hnodes = health_ctx.nodes.clone();
        let hhealth = health.clone();
        rt.spawn(async move {
            strategy::run_health_loop(hs, hstrat, hnodes, hhealth).await;
        });
        // cron / network-changed / generic 共用同一个随 VPN 生命周期存活的调度循环。
        let cron_shutdown = ctx.shutdown.clone();
        let cron_mitm = ctx.mitm.clone();
        rt.spawn(async move {
            cron::run_cron_loop(cron_shutdown, cron_mitm).await;
        });
        // 等协议栈真正就绪再返回 true，避免界面先显示「已连接」但流量还没人接。
        let mut waited = 0u32;
        while !netstack::STACK_READY.load(Ordering::Acquire) && waited < 300 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            waited += 10;
        }
        if waited >= 300 {
            logging::warn("core", "协议栈 300ms 内未就绪，继续启动");
        }
        // Fake-IP 映射定期落盘（mihomo/sing-box cache_file 同款）
        let ctx_flush = ctx.clone();
        let shut_flush = shutdown.clone();
        rt.spawn(async move {
            // 30s 一落盘：重启用到的映射窗口从 60s 缩到 30s（停止/热重载另有即时落盘）。
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                if shut_flush.load(Ordering::Relaxed) {
                    break;
                }
                ctx_flush
                    .dns
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .save_state();
                ctx_flush.stats.hits.flush_if_dirty();
            }
        });

        let mut guard = match ENGINE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *guard = Some(Engine {
            rt,
            shutdown,
            stats: stats.clone(),
            ctx: ctx.clone(),
        });
        *ENGINE_STATS.lock().unwrap_or_else(|p| p.into_inner()) = stats;
        logging::info("core", "服务已启动");
        true
    }));
    match result {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => {
            logging::error("core", "启动时发生内部错误");
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeStop<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| stop_engine()));
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeStats<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let json = {
        let guard = match ENGINE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match guard.as_ref() {
            Some(engine) => {
                let snapshot = engine.ctx.mitm().engine.bypass_snapshot();
                let stats_json = engine.stats.to_json_with(&snapshot);
                let groups = engine
                    .ctx
                    .strategy_snapshot()
                    .health_json(&engine.ctx.health);
                match serde_json::from_str::<serde_json::Value>(&stats_json) {
                    Ok(mut value) => {
                        if let Some(obj) = value.as_object_mut() {
                            obj.insert("groups".to_string(), groups);
                        }
                        serde_json::to_string(&value).unwrap_or(stats_json)
                    }
                    Err(_) => stats_json,
                }
            }
            // 停止后返回本次会话的最终统计（uptime 已冻结），不再清空。
            None => ENGINE_STATS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .to_json(),
        }
    };
    to_jstring(&mut env, json)
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeHits<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    since: jlong,
) -> jstring {
    let json = {
        let guard = match ENGINE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let stats = match guard.as_ref() {
            Some(engine) => engine.stats.clone(),
            None => ENGINE_STATS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
        };
        stats.hits.snapshot_json(since)
    };
    to_jstring(&mut env, json)
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeHitsRepair<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jboolean {
    let stats = ENGINE_STATS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    if stats.hits.repair() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeSetHitHistoryEnabled<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    enabled: jboolean,
) -> jboolean {
    let on = enabled != 0;
    let stats = ENGINE_STATS.lock().unwrap_or_else(|p| p.into_inner());
    stats.hits.set_persist_enabled(on);
    on as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeClearHits<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    ENGINE_STATS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .hits
        .clear();
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeLogs<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    since: jlong,
) -> jstring {
    let json = logging::json_since(since.max(0) as u64);
    to_jstring(&mut env, json)
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeDnsLogs<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    since: jlong,
) -> jstring {
    let json = dns_log::json_since(since.max(0) as u64);
    to_jstring(&mut env, json)
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeClearDnsLogs<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    dns_log::clear();
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeClearLogs<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    logging::clear();
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeParseSubscription<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    text: JString<'local>,
) -> jstring {
    let json = catch_unwind(AssertUnwindSafe(|| {
        let raw = read_string(&mut env, &text).unwrap_or_default();
        subscribe::parse_to_json(&raw)
    }))
    .unwrap_or_else(|_| "{\"nodes\":[],\"rules\":[],\"groups\":[],\"unsupported\":0}".into());
    to_jstring(&mut env, json)
}

/// 端到端节点测速：经真实代理协议转发一个测速 URL 的 GET，量到首个响应字节。
/// 壳层旧测速只对入口做 TCP/TLS 握手——入口快但转发不通的节点会被误选。
/// 入参 {"nodes":[Node...],"url":"...","timeoutMs":5000}；
/// 出参 {"results":[{"name","ok","ms","error"}]}。并发上限 6，独立小运行时，
/// 不依赖 VPN 是否已启动。
#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeProbeNodes<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    payload: JString<'local>,
) -> jstring {
    let json = catch_unwind(AssertUnwindSafe(
        || -> Result<String, Box<dyn std::error::Error>> {
            let raw = read_string(&mut env, &payload).unwrap_or_default();
            let v: serde_json::Value = serde_json::from_str(&raw)?;
            let nodes: Vec<config::Node> = serde_json::from_value(v["nodes"].clone())?;
            let url = v["url"]
                .as_str()
                .unwrap_or("https://www.gstatic.com/generate_204")
                .to_string();
            let timeout_ms = v["timeoutMs"].as_u64().unwrap_or(5000).clamp(500, 15000);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?;
            let results = rt.block_on(async move {
                let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(6));
                let mut set = tokio::task::JoinSet::new();
                for node in nodes {
                    let sem = sem.clone();
                    let url = url.clone();
                    set.spawn(async move {
                        let _permit = sem.acquire().await.ok();
                        let start = std::time::Instant::now();
                        let r = outbound::probe_node(
                            &node,
                            &url,
                            std::time::Duration::from_millis(timeout_ms),
                        )
                        .await;
                        let ms = start.elapsed().as_millis() as u64;
                        match r {
                            Ok(_) => serde_json::json!({
                                "name": node.name, "ok": true, "ms": ms, "error": "",
                            }),
                            Err(e) => serde_json::json!({
                                "name": node.name, "ok": false, "ms": ms, "error": e.to_string(),
                            }),
                        }
                    });
                }
                let mut out = Vec::new();
                while let Some(joined) = set.join_next().await {
                    if let Ok(v) = joined {
                        out.push(v);
                    }
                }
                out
            });
            Ok(serde_json::json!({ "results": results }).to_string())
        },
    ))
    .unwrap_or_else(|_| Ok("{\"results\":[]}".to_string()))
    .unwrap_or_else(|_| "{\"results\":[]}".to_string());
    to_jstring(&mut env, json)
}

/// 壳层下发「五元组 → 归属 UID」整表。返回接受的条数，-1 表示参数错误。
/// 无 root 时壳层下发空表，等价于关闭 UID 规则（不会退化成按 UID 0 匹配）。
#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeSetUidMap<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    table_json: JString<'local>,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| -> i32 {
        let json = match read_string(&mut env, &table_json) {
            Some(s) => s,
            None => return -1,
        };
        let (rows, bad) = crate::uidmap::UidMap::parse_json(&json);
        let count = rows.len() as i32;
        // 没有运行中的内核时先缓存，等 nativeStart 建好会话再应用。
        *UID_TABLE_PENDING.lock().unwrap_or_else(|p| p.into_inner()) = Some(json);
        let guard = match ENGINE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(engine) = guard.as_ref() {
            engine
                .ctx
                .uid_map
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .replace(rows);
        }
        if bad > 0 {
            logging::warn(
                "uid",
                format!("UID 表下发：{} 条无效已跳过，接受 {} 条", bad, count),
            );
        }
        count
    }))
    .unwrap_or(-1)
}

/// 连接列表增量快照：`since` 是上次拿到的游标，首次传 0。
/// 返回 `{"items":[...],"last":n,"total":n}`；内核未运行时给空表。
#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeConnections<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    since: jlong,
) -> jstring {
    let json = catch_unwind(AssertUnwindSafe(|| {
        let guard = match ENGINE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match guard.as_ref() {
            Some(engine) => engine
                .ctx
                .conns
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .json_since(since.max(0) as u64),
            None => "{\"items\":[],\"last\":0,\"total\":0}".to_string(),
        }
    }))
    .unwrap_or_else(|_| "{\"items\":[],\"last\":0,\"total\":0}".to_string());
    to_jstring(&mut env, json)
}

/// 壳层切网后调用：置位后主循环在下一轮清空 QUIC 黑洞判定（旧网络结论作废）。
#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeClearQuicBlackhole(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    let guard = match ENGINE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(engine) = guard.as_ref() {
        engine
            .ctx
            .quic_clear
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// 规则热重载（sing-box serviceReload 同款）：只换过滤/分流引擎，TUN 与连接不中断。
#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeReloadRules<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jint {
    let result = catch_unwind(AssertUnwindSafe(|| -> jint {
        let json = match read_string(&mut env, &config_json) {
            Some(s) => s,
            None => return 0,
        };
        let cfg: Config = match config::parse_lenient(&json) {
            Ok(c) => c,
            Err(e) => {
                logging::error(
                    "core",
                    format!(
                        "热重载配置解析失败: {} {}",
                        e,
                        config::error_context(&json, &e)
                    ),
                );
                return -2;
            }
        };
        let guard = match ENGINE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(engine) = guard.as_ref() else {
            return 0;
        };
        let old_mitm = engine.ctx.mitm();
        let reuse_mitm = {
            let previous = engine.ctx.cfg.read().unwrap_or_else(|p| p.into_inner());
            old_mitm.can_reuse(&cfg.mitm, &previous.mitm)
        };
        let new_mitm = if reuse_mitm {
            old_mitm
        } else {
            let candidate = mitm::MitmState::build_with_stats(&cfg.mitm, Some(engine.stats.clone()));
            if candidate.ca_unavailable() {
                logging::warn("mitm", "热重载未应用：无法加载 MITM CA，继续使用原配置");
                return -1;
            }
            Arc::new(candidate)
        };
        let filter = Arc::new(build_filter(&cfg));
        let rules = Arc::new(RuleEngine::from_config(&cfg));
        let strategy = Arc::new(strategy::StrategySet::from_config(&cfg));
        if strategy.has_errors() {
            for issue in strategy.issues() {
                logging::warn(
                    "strategy",
                    format!("热重载策略诊断 {}：{}", issue.group, issue.message),
                );
            }
        }
        // 旧引擎状态先落盘，新引擎从盘加载，Fake-IP 与缓存都不丢
        engine
            .ctx
            .dns
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .save_state();
        let mut new_dns_cfg = cfg.dns.clone();
        new_dns_cfg.block_aaaa = cfg.dns.block_aaaa || !cfg.ipv6;
        let mut new_dns = DnsEngine::new(
            &new_dns_cfg,
            filter.clone(),
            engine.stats.clone(),
            &cfg.block_mode,
            cfg.block_enabled,
            cfg.fake_ip && cfg.mode != "dns_only" && cfg.mode != "filter_only",
            cfg.dns.query_log,
        );
        new_dns.set_prefer_ipv6(cfg.prefer_ipv6);
        new_dns.set_fake_path(if cfg.fake_ip && cfg.mode != "dns_only" {
            cfg.fake_ip_file.clone()
        } else {
            None
        });
        new_dns.set_cache_path(if cfg.dns.cache_file.trim().is_empty() {
            None
        } else {
            Some(cfg.dns.cache_file.clone())
        });
        new_dns.set_cn_ips(cn_ips_for(&cfg));
        // 与 netstack 的新连接决策读锁配对：新连接要么看到旧快照，要么看到新快照。
        // 已有连接不参与该锁，热更新不会中断它们。
        let _decision_guard = engine
            .ctx
            .decision
            .write()
            .unwrap_or_else(|p| p.into_inner());
        crate::outbound::set_tuning(cfg.bbr, engine.stats.clone());
        engine
            .stats
            .filter_rules
            .store(filter.rule_count() as u64, Ordering::Relaxed);
        engine
            .stats
            .filter_skipped
            .store(filter.skipped as u64, Ordering::Relaxed);
        if let Ok(mut d) = engine.ctx.dns.write() {
            *d = Arc::new(new_dns);
        }
        if let Ok(mut r) = engine.ctx.rules.write() {
            *r = rules;
        }
        if let Ok(mut st) = engine.ctx.strategy.write() {
            *st = strategy;
        }
        // 运行配置/节点/选中线路一并热更：sniff、无节点策略、节点参数修改
        // 都走热重载路径，只换 DNS/规则引擎会让这些改动静默失效。
        if let Ok(mut n) = engine.ctx.nodes.write() {
            *n = Arc::new(cfg.nodes.clone());
        }
        if let Ok(mut s) = engine.ctx.selected.write() {
            *s = cfg.selected.clone();
        }
        // MITM 引擎与 CA 一并热更：规则/域名列表改动不中断现有连接。
        if let Ok(mut m) = engine.ctx.mitm.write() {
            *m = new_mitm;
        }
        if let Ok(mut c) = engine.ctx.cfg.write() {
            *c = cfg;
        }
        logging::info("core", "配置热重载完成，TUN 与连接未中断");
        1
    }));
    result.unwrap_or(0)
}

/// 脚本参数运行期热更新：只替换 `$argument` 注入值，不重编译脚本，
/// 也不替换 MITM 引擎；已进入执行队列的脚本持有自己的参数快照。
#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeSetScriptArguments<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    payload_json: JString<'local>,
) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(|| -> bool {
        let Some(json) = read_string(&mut env, &payload_json) else {
            return false;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else {
            logging::warn("script", "参数热更新 JSON 解析失败");
            return false;
        };
        let Some(key) = v.get("key").and_then(|x| x.as_str()) else {
            return false;
        };
        let Some(values) = v.get("values").and_then(|x| x.as_object()) else {
            return false;
        };
        let map: std::collections::HashMap<String, String> = values
            .iter()
            .filter_map(|(k, x)| x.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        let guard = match ENGINE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(engine) = guard.as_ref() else {
            return false;
        };
        let mitm = engine.ctx.mitm();
        mitm.engine.scripts.set_argument_values(key, map);
        logging::info("script", format!("脚本参数已热更新: {}", key));
        true
    }));
    match result {
        Ok(true) => 1,
        _ => 0,
    }
}

/// network-changed / generic 手动触发：与 cron 共用同一套串行执行设施。
/// network-changed 由壳层在网络稳定后调用；这里再做 4 秒去抖兜底。
#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeTriggerScripts<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    kind: JString<'local>,
) -> jint {
    let result = catch_unwind(AssertUnwindSafe(|| -> i32 {
        let Some(kind) = read_string(&mut env, &kind) else {
            return -1;
        };
        let debounce = if kind.eq_ignore_ascii_case("network-changed") {
            4
        } else {
            1
        };
        let guard = match ENGINE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(engine) = guard.as_ref() else {
            return -1;
        };
        let started =
            cron::trigger_scripts(&kind, &engine.ctx.mitm, &engine.ctx.shutdown, debounce);
        logging::info("cron", format!("触发 {}：启动 {} 条脚本", kind, started));
        started as i32
    }));
    match result {
        Ok(v) => v,
        _ => -1,
    }
}

/// 规则测试：与运行时完全同一套判定（含模块合并规则、CN 直连、模式覆盖、
/// 无节点策略），由内核算出结果，避免 Kotlin 侧另写一套匹配逻辑产生偏差。
struct RuleTransportResult {
    label: String,
    node: String,
    chain: Vec<String>,
    note: String,
}

fn node_udp_supported(cfg: &Config, name: &str) -> Option<bool> {
    cfg.nodes
        .iter()
        .find(|n| n.name == name)
        .map(|n| n.udp_supported())
}

/// 规则测试按传输层分别展开；TCP 的结果不会替 UDP 背书。
fn resolve_rule_transport(
    action: &Action,
    transport: strategy::Transport,
    cfg: &Config,
    strategy: &strategy::StrategySet,
    health: &strategy::HealthRegistry,
    rules: &RuleEngine,
) -> RuleTransportResult {
    let mut action = action.clone();
    let mut chain: Vec<String> = Vec::new();
    let mut note = String::new();
    if let Action::Group(name) = &action {
        match strategy.resolve_group(name, transport, health) {
            Ok(r) => {
                chain = r.chain.clone();
                note = format!("策略组解析：{} → {}", r.chain.join(" → "), r.node);
                action = Action::Node(r.node);
            }
            Err(e) => {
                chain = e.chain.clone();
                let policy = e.policy.chosen(cfg.block_when_no_node);
                let final_label = match policy {
                    strategy::NoNodePolicy::Direct => "DIRECT",
                    _ => "BLOCK",
                };
                note = format!(
                    "策略组解析失败：{}（链：{}）；无可用节点 → {}",
                    e.message,
                    if e.chain.is_empty() {
                        "无".to_string()
                    } else {
                        e.chain.join(" → ")
                    },
                    final_label
                );
                action = match policy {
                    strategy::NoNodePolicy::Direct => Action::Direct,
                    _ => Action::Block,
                };
            }
        }
    }
    if let Action::Missing(name) = &action {
        note = format!(
            "引用失效：{} 不存在；运行时不回落到当前选中节点，按 BLOCK 处理",
            name
        );
        chain.push(format!("MISSING:{}", name));
        action = Action::Block;
    }
    if matches!(action, Action::Proxy) {
        let selected = cfg
            .selected
            .as_ref()
            .filter(|name| cfg.nodes.iter().any(|n| n.name == **name))
            .cloned()
            .or_else(|| cfg.nodes.first().map(|n| n.name.clone()));
        match selected {
            Some(node) => {
                if transport == strategy::Transport::Udp
                    && node_udp_supported(cfg, &node) == Some(false)
                {
                    let kind = cfg
                        .nodes
                        .iter()
                        .find(|n| n.name == node)
                        .map(|n| n.kind.as_str())
                        .unwrap_or("unknown");
                    note = format!("节点 {}（{}）不支持 UDP，UDP 流量不会发给它", node, kind);
                    return RuleTransportResult {
                        label: "UDP_UNSUPPORTED".to_string(),
                        node,
                        chain: vec![],
                        note,
                    };
                }
                action = Action::Node(node);
            }
            None => {
                action = if cfg.block_when_no_node {
                    Action::Block
                } else {
                    Action::Direct
                };
                note = if cfg.block_when_no_node {
                    "没有可用节点，按无节点策略拦截".to_string()
                } else {
                    "没有可用节点，回落直连".to_string()
                };
            }
        }
    }
    if let Action::Node(node) = &action {
        if transport == strategy::Transport::Udp && node_udp_supported(cfg, node) == Some(false) {
            let kind = cfg
                .nodes
                .iter()
                .find(|n| n.name == *node)
                .map(|n| n.kind.as_str())
                .unwrap_or("unknown");
            return RuleTransportResult {
                label: "UDP_UNSUPPORTED".to_string(),
                node: node.clone(),
                chain,
                note: format!("节点 {}（{}）不支持 UDP，UDP 流量不会发给它", node, kind),
            };
        }
        if chain.is_empty() {
            chain.push(node.clone());
        }
    }
    RuleTransportResult {
        label: rules.decision_label(&action),
        node: match &action {
            Action::Node(n) => n.clone(),
            Action::Direct => "DIRECT".to_string(),
            Action::Block => "BLOCK".to_string(),
            Action::Proxy => cfg.selected.clone().unwrap_or_default(),
            Action::Group(n) => format!("GROUP:{}", n),
            Action::Missing(n) => format!("MISSING:{}", n),
        },
        chain,
        note,
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeTestRule<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
    input: JString<'local>,
) -> jstring {
    let json = catch_unwind(AssertUnwindSafe(|| {
        let (Some(cfg_text), Some(raw_input)) =
            (read_string(&mut env, &config_json), read_string(&mut env, &input))
        else {
            return r#"{"action":"错误","detail":"读取参数失败"}"#.to_string();
        };
        let cfg: Config = match config::parse_lenient(&cfg_text) {
            Ok(c) => c,
            Err(e) => {
                return serde_json::json!({"action": "错误", "detail": format!("配置解析失败: {}", e)}).to_string();
            }
        };
        let input = raw_input.trim().to_ascii_lowercase();
        if input.is_empty() {
            return r#"{"action":"错误","detail":"输入为空"}"#.to_string();
        }
        let rules = RuleEngine::from_config(&cfg);
        let strategy = strategy::StrategySet::from_config(&cfg);
        let health = strategy::HealthRegistry::new();
        let (domain, ip) = match input.parse::<std::net::IpAddr>() {
            Ok(ip) => (None, ip),
            Err(_) => (Some(input.as_str()), std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        };
        let (action, mut detail) = match cfg.mode.as_str() {
            "global" => (Action::Proxy, "全局模式：全部走代理".to_string()),
            "dns_only" => (Action::Direct, "仅 DNS 模式：全部直连".to_string()),
            _ => rules.decide_detail(domain, ip, 0, ConnKind::Tcp),
        };
        let rule_action = rules.decision_label(&action);
        let tcp = resolve_rule_transport(
            &action,
            strategy::Transport::Tcp,
            &cfg,
            &strategy,
            &health,
            &rules,
        );
        let udp = resolve_rule_transport(
            &action,
            strategy::Transport::Udp,
            &cfg,
            &strategy,
            &health,
            &rules,
        );
        if !tcp.note.is_empty() {
            detail.push_str(&format!("\nTCP：{}", tcp.note));
        }
        if !udp.note.is_empty() {
            detail.push_str(&format!("\nUDP：{}", udp.note));
        }
        let issues: Vec<String> = strategy
            .issues()
            .iter()
            .filter(|i| {
                i.group.is_empty()
                    || tcp.chain.iter().any(|c| c == &i.group)
                    || udp.chain.iter().any(|c| c == &i.group)
            })
            .map(|i| format!("{}：{}", if i.group.is_empty() { "全局" } else { i.group.as_str() }, i.message))
            .collect();
        serde_json::json!({
            "source": "kernel",
            "order": "预匹配拦截 → 普通规则 → 国内直连 → FINAL",
            "action": tcp.label,
            "ruleAction": rule_action,
            "detail": detail,
            "node": tcp.node,
            "chain": tcp.chain,
            "tcpAction": tcp.label,
            "tcpNote": tcp.note,
            "udpAction": udp.label,
            "udpNode": udp.node,
            "udpChain": udp.chain,
            "udpNote": udp.note,
            "issues": issues
        })
        .to_string()
    }))
    .unwrap_or_else(|_| r#"{"action":"错误","detail":"内部错误"}"#.to_string());
    to_jstring(&mut env, json)
}

/// 导出 MITM CA 证书（未连接也可用）：生成/加载 ca_file，
/// 在 out_dir 写 namu-ca.pem 与 namu-ca.crt（DER，供系统安装意图使用）。
#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeMitmExportCa<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    ca_file: JString<'local>,
    out_dir: JString<'local>,
) -> jstring {
    let json = catch_unwind(AssertUnwindSafe(|| {
        let (Some(ca_path), Some(out)) = (
            read_string(&mut env, &ca_file),
            read_string(&mut env, &out_dir),
        ) else {
            return r#"{"ok":false,"error":"读取参数失败"}"#.to_string();
        };
        match mitm::ca::export_ca(&ca_path, &out) {
            Ok((pem, der, name)) => {
                serde_json::json!({"ok": true, "pem": pem, "der": der, "system_name": name})
                    .to_string()
            }
            Err(e) => serde_json::json!({"ok": false, "error": e}).to_string(),
        }
    }))
    .unwrap_or_else(|_| r#"{"ok":false,"error":"内部错误"}"#.to_string());
    to_jstring(&mut env, json)
}

#[no_mangle]
pub extern "system" fn Java_com_namu_dns_NativeCore_nativeVersion<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    to_jstring(&mut env, "1.13.38".into())
}

/// 给发布产物做独立校验用：即使 JNI 入口被裁剪，`llvm-strings` 仍能在
/// libnanmen_core.so 里读到 `nanmen_core-1.13.38`，不必只信清单文件。
#[no_mangle]
pub static NAMU_CORE_VERSION: [u8; 19] = *b"nanmen_core-1.13.38";

#[cfg(test)]
mod rule_test_transport_tests {
    use super::*;

    #[test]
    fn rule_test_reports_udp_unsupported_without_claiming_tcp_node() {
        let cfg: Config = serde_json::from_str(
            r#"{
                "nodes":[{"name":"仅TCP","type":"trojan","udp":false}],
                "proxy_groups":[{
                    "name":"分组","type":"fallback","members":["仅TCP"],
                    "no_node_action":"block"
                }]
            }"#,
        )
        .unwrap();
        let rules = RuleEngine::from_config(&cfg);
        let strategy = strategy::StrategySet::from_config(&cfg);
        let health = strategy::HealthRegistry::new();
        let action = Action::Group("分组".to_string());
        let tcp = resolve_rule_transport(
            &action,
            strategy::Transport::Tcp,
            &cfg,
            &strategy,
            &health,
            &rules,
        );
        let udp = resolve_rule_transport(
            &action,
            strategy::Transport::Udp,
            &cfg,
            &strategy,
            &health,
            &rules,
        );
        assert_eq!(tcp.label, "仅TCP");
        assert!(tcp.chain.contains(&"仅TCP".to_string()));
        assert_eq!(udp.label, "BLOCK");
        assert!(udp.note.contains("不支持 UDP"));
    }
}
