//! MITM CA：生成/加载自签根证书，按域名动态签发叶子证书。
//!
//! CA 以「证书 PEM + PKCS8 私钥 PEM」拼接落盘（ca_file），重启/热重载复用同一 CA，
//! 用户只需安装一次证书。叶子证书带 128 条上限的 FIFO ServerConfig 缓存。
//! 同 host 并发首连走 single-flight：只签一次，其余等待复用；签发放到阻塞线程池，
//! 不把 rcgen 的同步 CPU 工作压回 async worker。等待有界、超时/打满时再直签兜底。
//! 链里始终携带磁盘上的原始 CA DER，保证与用户已安装的证书完全一致。

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::Notify;

const LEAF_CACHE_CAP: usize = 128;
const MAX_LEAF_WAITERS: usize = 128;
const LEAF_WAIT_TIMEOUT: Duration = Duration::from_secs(4);
const CERT_MARK: &str = "-----BEGIN CERTIFICATE-----";
const CERT_END: &str = "-----END CERTIFICATE-----";
const KEY_MARK: &str = "-----BEGIN PRIVATE KEY-----";
const KEY_END: &str = "-----END PRIVATE KEY-----";
static NEXT_CA_TEMP: AtomicUsize = AtomicUsize::new(0);

fn io_err(msg: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.to_string())
}

fn pem_section(pem: &str, begin: &str, end: &str) -> Option<String> {
    let s = pem.find(begin)?;
    let body = s + begin.len();
    let e = body + pem[body..].find(end)? + end.len();
    Some(pem[s..e].to_string())
}

fn publish_ca(path: &Path, pem: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    // 所有生成者共用同一把锁。保留锁文件，文件描述符关闭时由内核释放锁。
    let mut lock_options = OpenOptions::new();
    lock_options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600);
    }
    let lock = lock_options.open(parent.join(".namu-ca.lock"))?;
    lock.lock()?;
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let (temp, mut file) = loop {
        let id = NEXT_CA_TEMP.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".namu-ca-{}-{id}.tmp", std::process::id()));
        match options.open(&temp) {
            Ok(file) => break (temp, file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        file.write_all(pem)?;
        file.sync_all()?;
        drop(file);
        // 私钥完整写入后再发布，兼容禁止创建硬链接的 Android 环境。
        fs::rename(&temp, path)
    })();
    let _ = fs::remove_file(temp);
    result
}

fn pem_to_der(pem: &str) -> io::Result<Vec<u8>> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| io_err(format!("PEM 解码失败: {}", e)))
}

fn der_to_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from(CERT_MARK);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(CERT_END);
    out.push('\n');
    out
}

pub struct MitmCa {
    key: KeyPair,
    /// 用落盘 CA 参数重建的签发者对象（仅用于 signed_by 的 subject/key）。
    issuer: rcgen::Certificate,
    /// 磁盘上的原始 CA DER：进证书链、导出安装都用它。
    ca_der: CertificateDer<'static>,
    cache: Mutex<LeafCache>,
    /// host -> 正在签发的通知；等待者不持锁、不阻塞 runtime worker。
    inflight: Mutex<HashMap<String, Arc<Flight>>>,
    pending_waiters: AtomicUsize,
    stats: RwLock<Option<Arc<crate::stats::Stats>>>,
}

#[derive(Default)]
struct Flight {
    notify: Notify,
    waiters: AtomicUsize,
}

/// 叶子证书缓存：HashMap + FIFO 淘汰队列。满 128 条只淘汰最老的一条，
/// 不再整表清空，避免热门域名在同一时刻全部重新签发。
struct LeafCache {
    map: HashMap<String, Arc<rustls::ServerConfig>>,
    order: VecDeque<String>,
}

impl LeafCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&self, host: &str) -> Option<Arc<rustls::ServerConfig>> {
        self.map.get(host).cloned()
    }

    fn insert(&mut self, host: String, cfg: Arc<rustls::ServerConfig>) {
        if self.map.contains_key(&host) {
            self.map.insert(host, cfg);
            return;
        }
        while self.order.len() >= LEAF_CACHE_CAP {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            } else {
                break;
            }
        }
        self.order.push_back(host.clone());
        self.map.insert(host, cfg);
    }
}

impl MitmCa {
    pub fn load_or_generate(path: &str) -> io::Result<Self> {
        if path.trim().is_empty() {
            return Err(io_err("未配置 CA 文件路径"));
        }
        match fs::read_to_string(path) {
            Ok(pem) => return Self::load_pem(&pem),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Self::generate(Path::new(path))
    }

    fn load_pem(pem: &str) -> io::Result<Self> {
        let cert_pem = pem_section(pem, CERT_MARK, CERT_END)
            .ok_or_else(|| io_err("CA 文件缺少证书段"))?;
        let key_pem =
            pem_section(pem, KEY_MARK, KEY_END).ok_or_else(|| io_err("CA 文件缺少私钥段"))?;
        let key = KeyPair::from_pem(&key_pem)
            .map_err(|e| io_err(format!("CA 私钥解析失败: {}", e)))?;
        let ca_der = CertificateDer::from(pem_to_der(&cert_pem)?);
        let (_, parsed) = x509_parser::parse_x509_certificate(ca_der.as_ref())
            .map_err(|e| io_err(format!("CA 证书解析失败: {}", e)))?;
        if parsed.public_key().raw != key.public_key_der().as_slice() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "CA 证书与私钥不匹配"));
        }
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)
            .map_err(|e| io_err(format!("CA 证书解析失败: {}", e)))?;
        let issuer = params
            .self_signed(&key)
            .map_err(|e| io_err(format!("CA 重建失败: {}", e)))?;
        Ok(Self {
            key,
            issuer,
            ca_der,
            cache: Mutex::new(LeafCache::new()),
            inflight: Mutex::new(HashMap::new()),
            pending_waiters: AtomicUsize::new(0),
            stats: RwLock::new(None),
        })
    }

    fn generate(path: &Path) -> io::Result<Self> {
        let key = KeyPair::generate().map_err(|e| io_err(format!("生成 CA 私钥失败: {}", e)))?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "Namu DNS MITM CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Namu DNS");
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2044, 1, 1);
        let cert = params
            .self_signed(&key)
            .map_err(|e| io_err(format!("自签 CA 失败: {}", e)))?;
        let ca_der = cert.der().clone();
        let mut blob = cert.pem();
        blob.push_str(&key.serialize_pem());
        if let Err(e) = publish_ca(path, blob.as_bytes()) {
            if e.kind() == io::ErrorKind::AlreadyExists {
                return Self::load_pem(&fs::read_to_string(path)?);
            }
            return Err(e);
        }
        Ok(Self {
            key,
            issuer: cert,
            ca_der,
            cache: Mutex::new(LeafCache::new()),
            inflight: Mutex::new(HashMap::new()),
            pending_waiters: AtomicUsize::new(0),
            stats: RwLock::new(None),
        })
    }

    pub fn ca_der(&self) -> &[u8] {
        &self.ca_der
    }

    pub fn ca_pem(&self) -> String {
        der_to_pem(&self.ca_der)
    }

    pub fn set_stats(&self, stats: Arc<crate::stats::Stats>) {
        if let Ok(mut g) = self.stats.write() {
            *g = Some(stats);
        }
    }

    fn stat(&self, f: impl FnOnce(&crate::stats::Stats)) {
        if let Some(s) = self.stats.read().ok().and_then(|g| g.clone()) {
            f(&s);
        }
    }

    fn cached(&self, host: &str) -> Option<Arc<rustls::ServerConfig>> {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(host)
    }

    /// 同 host 并发首连只签一次。缓存命中直接返回；未命中的首个调用成为 leader，
    /// 其余等待 Notify；等待超时或全局等待数打满时直接走阻塞线程池签发兜底。
    pub async fn server_config_async(
        self: &Arc<Self>,
        host: &str,
    ) -> io::Result<Arc<rustls::ServerConfig>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(c) = self.cached(&host) {
            self.stat(|s| {
                s.mitm_leaf_hit.fetch_add(1, Ordering::Relaxed);
            });
            return Ok(c);
        }
        self.stat(|s| {
            s.mitm_leaf_miss.fetch_add(1, Ordering::Relaxed);
        });

        enum Slot {
            Leader(Arc<Flight>),
            Follower(Arc<Flight>),
            Full,
        }
        let slot = {
            let mut g = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(f) = g.get(&host).cloned() {
                if self.pending_waiters.load(Ordering::Relaxed) >= MAX_LEAF_WAITERS {
                    self.stat(|s| {
                        s.mitm_leaf_pending_full.fetch_add(1, Ordering::Relaxed);
                    });
                    Slot::Full
                } else {
                    self.pending_waiters.fetch_add(1, Ordering::Relaxed);
                    f.waiters.fetch_add(1, Ordering::Relaxed);
                    Slot::Follower(f)
                }
            } else {
                let f = Arc::new(Flight::default());
                g.insert(host.clone(), f.clone());
                Slot::Leader(f)
            }
        };

        let flight = match slot {
            Slot::Full => return self.sign_blocking(host).await,
            Slot::Leader(f) => {
                let guard = FlightGuard {
                    ca: self.clone(),
                    host: host.clone(),
                    flight: f,
                };
                let r = self.sign_blocking(host).await;
                drop(guard);
                return r;
            }
            Slot::Follower(f) => f,
        };
        self.stat(|s| {
            s.mitm_leaf_wait.fetch_add(1, Ordering::Relaxed);
        });
        let wait_guard = WaiterGuard {
            ca: self.clone(),
            flight: flight.clone(),
        };
        // 先注册 notified，再复查缓存：避免 leader 在「查缓存」和「await」之间完成导致丢唤醒。
        let notified = flight.notify.notified();
        tokio::pin!(notified);
        if let Some(c) = self.cached(&host) {
            drop(wait_guard);
            self.stat(|s| {
                s.mitm_leaf_hit.fetch_add(1, Ordering::Relaxed);
            });
            return Ok(c);
        }
        let timed_out = tokio::time::timeout(LEAF_WAIT_TIMEOUT, notified)
            .await
            .is_err();
        drop(wait_guard);
        if let Some(c) = self.cached(&host) {
            self.stat(|s| {
                s.mitm_leaf_hit.fetch_add(1, Ordering::Relaxed);
            });
            return Ok(c);
        }
        if timed_out {
            self.stat(|s| {
                s.mitm_leaf_wait_timeout.fetch_add(1, Ordering::Relaxed);
            });
        }
        // 超时/leader 失败：不继续排队，直接走阻塞线程池补签。
        self.sign_blocking(host).await
    }

    async fn sign_blocking(
        self: &Arc<Self>,
        host: String,
    ) -> io::Result<Arc<rustls::ServerConfig>> {
        let ca = self.clone();
        tokio::task::spawn_blocking(move || ca.server_config(&host))
            .await
            .map_err(|e| io_err(format!("证书签发任务失败: {}", e)))?
    }

    /// 为指定域名构建服务端 TLS 配置（叶子证书 + 原始 CA 链，ALPN 仅 http/1.1）。
    pub fn server_config(&self, host: &str) -> io::Result<Arc<rustls::ServerConfig>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        {
            let g = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(c) = g.get(&host) {
                return Ok(c);
            }
        }
        let leaf_key =
            KeyPair::generate().map_err(|e| io_err(format!("生成叶子私钥失败: {}", e)))?;
        let mut params = CertificateParams::new(vec![host.clone()])
            .map_err(|e| io_err(format!("非法域名 {}: {}", host, e)))?;
        params.distinguished_name.push(DnType::CommonName, &host);
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2040, 1, 1);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(&leaf_key, &self.issuer, &self.key)
            .map_err(|e| io_err(format!("签发 {} 证书失败: {}", host, e)))?;
        let chain = vec![leaf.der().clone(), self.ca_der.clone()];
        let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der.into())
            .map_err(|e| io_err(format!("TLS 服务端配置失败: {}", e)))?;
        // 先 h2 再 http/1.1：客户端按顺序协商，gRPC 等 HTTP/2 请求
        // 不再被降级成 HTTP/1.1；不支持 h2 的客户端仍回落到 HTTP/1.1。
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.stat(|s| {
            s.mitm_leaf_sign.fetch_add(1, Ordering::Relaxed);
        });
        let mut g = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        g.insert(host, cfg.clone());
        Ok(cfg)
    }
}

/// Android 系统证书区文件名：<subject_hash_old>.0。
/// 算法 = 证书 subject DER 的 MD5 前 4 字节小端。本 CA 的 subject 全部为
/// PrintableString 且无多余空白，与 OpenSSL 规范化编码一致。
pub fn system_cert_name(ca_file: &str) -> Result<String, String> {
    let ca = MitmCa::load_or_generate(ca_file).map_err(|e| e.to_string())?;
    let (_, cert) = x509_parser::parse_x509_certificate(ca.ca_der())
        .map_err(|e| format!("解析 CA 证书失败: {}", e))?;
    use md5::{Digest, Md5};
    let digest = Md5::digest(cert.subject.as_raw());
    let hash = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    Ok(format!("{:08x}.0", hash))
}

/// 导出 CA 供安装：out_dir 下写 namu-ca.pem（证书）与 namu-ca.crt（DER），
/// 并返回系统证书区文件名。独立于运行中的引擎，未连接时也能生成/导出。
pub fn export_ca(ca_file: &str, out_dir: &str) -> Result<(String, String, String), String> {
    let ca = MitmCa::load_or_generate(ca_file).map_err(|e| format!("读取或生成 CA：{e}"))?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("创建证书导出目录：{e}"))?;
    let pem_path = Path::new(out_dir).join("namu-ca.pem");
    let der_path = Path::new(out_dir).join("namu-ca.crt");
    std::fs::write(&pem_path, ca.ca_pem()).map_err(|e| format!("写入 PEM 证书：{e}"))?;
    std::fs::write(&der_path, ca.ca_der()).map_err(|e| format!("写入 DER 证书：{e}"))?;
    let name = system_cert_name(ca_file)?;
    Ok((
        pem_path.to_string_lossy().to_string(),
        der_path.to_string_lossy().to_string(),
        name,
    ))
}

struct FlightGuard {
    ca: Arc<MitmCa>,
    host: String,
    flight: Arc<Flight>,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        let mut g = self.ca.inflight.lock().unwrap_or_else(|p| p.into_inner());
        // 只有当前 leader 自己的 entry 才删；若 map 已被别的 leader 替换则不动。
        if let Some(cur) = g.get(&self.host) {
            if Arc::ptr_eq(cur, &self.flight) {
                g.remove(&self.host);
            }
        }
        drop(g);
        // 唤醒所有等待者，让它们复查缓存（成功则复用，失败则兜底补签）。
        self.flight.notify.notify_waiters();
    }
}

struct WaiterGuard {
    ca: Arc<MitmCa>,
    flight: Arc<Flight>,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.ca.pending_waiters.fetch_sub(1, Ordering::Relaxed);
        self.flight.waiters.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("namu_mitm_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name).to_string_lossy().to_string()
    }

    #[test]
    fn generate_reload_same_ca() {
        let path = tmp_path("ca.pem");
        let _ = std::fs::remove_file(&path);
        let ca1 = MitmCa::load_or_generate(&path).unwrap();
        let der1 = ca1.ca_der().to_vec();
        let ca2 = MitmCa::load_or_generate(&path).unwrap();
        assert_eq!(der1, ca2.ca_der(), "重载必须复用同一 CA");
        // 两个实例签出的叶子证书都能被原始 CA 验证（同 key）
        let _c1 = ca1.server_config("a.example.com").unwrap();
        let _c2 = ca2.server_config("a.example.com").unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mismatched_disk_ca_is_rejected_without_overwriting() {
        let path = tmp_path("mixed-ca.pem");
        let key_a = KeyPair::generate().unwrap();
        let cert_a = CertificateParams::default().self_signed(&key_a).unwrap();
        let key_b = KeyPair::generate().unwrap();
        let pem = cert_a.pem() + &key_b.serialize_pem();
        fs::write(&path, &pem).unwrap();
        let err = MitmCa::load_or_generate(&path)
            .err()
            .expect("must reject mixed CA");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read_to_string(&path).unwrap(), pem);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn publication_preserves_an_existing_file() {
        let path = tmp_path("existing-ca.pem");
        fs::write(&path, b"existing CA").unwrap();
        let err = publish_ca(Path::new(&path), b"new CA").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"existing CA");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn concurrent_first_generation_publishes_one_ca() {
        let path = tmp_path("concurrent-ca.pem");
        let _ = fs::remove_file(&path);
        let start = Arc::new(std::sync::Barrier::new(6));
        let workers: Vec<_> = (0..6)
            .map(|_| {
                let start = Arc::clone(&start);
                let path = path.clone();
                std::thread::spawn(move || {
                    start.wait();
                    MitmCa::load_or_generate(&path).unwrap().ca_der().to_vec()
                })
            })
            .collect();
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        let saved = MitmCa::load_or_generate(&path).unwrap();
        for der in results {
            assert_eq!(der, saved.ca_der());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn leaf_cache_evicts_oldest_instead_of_clearing_whole_table() {
        let path = tmp_path("ca_fifo.pem");
        let _ = std::fs::remove_file(&path);
        let ca = MitmCa::load_or_generate(&path).unwrap();
        let seed = ca.server_config("seed.example.com").unwrap();
        {
            let mut g = ca.cache.lock().unwrap();
            for i in 0..129 {
                g.insert(format!("h{i}.example.com"), seed.clone());
            }
            assert_eq!(g.map.len(), 128);
            assert!(!g.map.contains_key("h0.example.com"));
            assert!(g.map.contains_key("h1.example.com"));
            assert!(g.map.contains_key("h128.example.com"));
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_connections_sign_leaf_once() {
        let path = tmp_path("ca_singleflight.pem");
        let _ = std::fs::remove_file(&path);
        let ca = Arc::new(MitmCa::load_or_generate(&path).unwrap());
        let stats = Arc::new(crate::stats::Stats::new());
        ca.set_stats(stats.clone());
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let ca = ca.clone();
            tasks.push(tokio::spawn(async move {
                ca.server_config_async("burst.example.com").await.unwrap()
            }));
        }
        let mut configs = Vec::new();
        for t in tasks {
            configs.push(t.await.unwrap());
        }
        for c in &configs[1..] {
            assert!(
                Arc::ptr_eq(&configs[0], c),
                "同 host 并发首连必须复用同一 ServerConfig"
            );
        }
        assert_eq!(
            stats.mitm_leaf_sign.load(Ordering::Relaxed),
            1,
            "并发首连只允许签发一次"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn leaf_cert_verifies_against_ca() {
        use rustls::client::danger::ServerCertVerifier;
        let path = tmp_path("ca_verify.pem");
        let _ = std::fs::remove_file(&path);
        let ca = MitmCa::load_or_generate(&path).unwrap();
        let cfg = ca.server_config("test.example.com").unwrap();
        // 从 ServerConfig 拿不到链，直接用签发参数再签一张做 webpki 验证
        let leaf_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2040, 1, 1);
        let leaf = params.signed_by(&leaf_key, &ca.issuer, &ca.key).unwrap();
        let anchors = vec![rustls::RootCertStore::empty()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_der.clone()).unwrap();
        let _ = anchors;
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let now = rustls::pki_types::UnixTime::now();
        let name = rustls::pki_types::ServerName::try_from("test.example.com").unwrap();
        let result = verifier.verify_server_cert(leaf.der(), &[ca.ca_der.clone()], &name, &[], now);
        assert!(
            result.is_ok(),
            "叶子证书必须能通过 CA 验证: {:?}",
            result.err()
        );
        let _ = std::fs::remove_file(&path);
        // cfg 构建成功即 ALPN/链装配无误
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn export_writes_pem_and_der() {
        let path = tmp_path("ca_export.pem");
        let out = tmp_path("export_out");
        let _ = std::fs::remove_file(&path);
        let (pem, der, name) = export_ca(&path, &out).unwrap();
        assert!(std::fs::read_to_string(&pem).unwrap().contains(CERT_MARK));
        assert!(!std::fs::read(&der).unwrap().is_empty());
        assert!(name.ends_with(".0") && name.len() == 10);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&out);
    }
}
