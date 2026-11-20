use crate::config::{Node, Target};
use crate::outbound::{encode_socks_addr, io_err, BoxStream};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::RngCore;
use sha1::Sha1;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

enum AeadCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

fn key_len_for(method: &str) -> io::Result<usize> {
    match method.to_ascii_lowercase().as_str() {
        "aes-128-gcm" | "aes128-gcm" => Ok(16),
        "aes-256-gcm" | "aes256-gcm" => Ok(32),
        "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(32),
        other => Err(io_err(format!("不支持的加密方式: {}", other))),
    }
}

fn cipher_new(method: &str, key: &[u8]) -> io::Result<AeadCipher> {
    match method.to_ascii_lowercase().as_str() {
        "aes-128-gcm" | "aes128-gcm" => Aes128Gcm::new_from_slice(key)
            .map(AeadCipher::Aes128)
            .map_err(|_| io_err("AES-128 密钥错误")),
        "aes-256-gcm" | "aes256-gcm" => Aes256Gcm::new_from_slice(key)
            .map(AeadCipher::Aes256)
            .map_err(|_| io_err("AES-256 密钥错误")),
        "chacha20-ietf-poly1305" | "chacha20-poly1305" => ChaCha20Poly1305::new_from_slice(key)
            .map(AeadCipher::ChaCha)
            .map_err(|_| io_err("ChaCha20 密钥错误")),
        other => Err(io_err(format!("不支持的加密方式: {}", other))),
    }
}

impl AeadCipher {
    fn encrypt(&self, nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
        let n = aes_gcm::Nonce::from_slice(nonce);
        let r = match self {
            AeadCipher::Aes128(c) => c.encrypt(n, plain),
            AeadCipher::Aes256(c) => c.encrypt(n, plain),
            AeadCipher::ChaCha(c) => c.encrypt(n, plain),
        };
        r.unwrap_or_default()
    }
    fn decrypt(&self, nonce: &[u8; 12], ct: &[u8]) -> Option<Vec<u8>> {
        let n = aes_gcm::Nonce::from_slice(nonce);
        match self {
            AeadCipher::Aes128(c) => c.decrypt(n, ct).ok(),
            AeadCipher::Aes256(c) => c.decrypt(n, ct).ok(),
            AeadCipher::ChaCha(c) => c.decrypt(n, ct).ok(),
        }
    }
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut md5 = Md5::new();
        if !prev.is_empty() {
            md5.update(&prev);
        }
        md5.update(password);
        prev = md5.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

fn hkdf_subkey(master: &[u8], salt: &[u8]) -> io::Result<Vec<u8>> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master);
    let mut okm = vec![0u8; master.len()];
    hk.expand(b"ss-subkey", &mut okm).map_err(|_| io_err("HKDF 派生失败"))?;
    Ok(okm)
}

fn inc_nonce(nonce: &mut [u8; 12]) {
    for i in 0..12 {
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            break;
        }
    }
}

async fn write_chunk<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cipher: &AeadCipher,
    nonce: &mut [u8; 12],
    data: &[u8],
) -> io::Result<()> {
    let mut len_plain = [0u8; 2];
    len_plain.copy_from_slice(&(data.len() as u16).to_be_bytes());
    let enc_len = cipher.encrypt(nonce, &len_plain);
    inc_nonce(nonce);
    let enc_data = cipher.encrypt(nonce, data);
    inc_nonce(nonce);
    w.write_all(&enc_len).await?;
    w.write_all(&enc_data).await?;
    Ok(())
}

async fn read_chunk<R: AsyncReadExt + Unpin>(
    r: &mut R,
    cipher: &AeadCipher,
    nonce: &mut [u8; 12],
) -> io::Result<Option<Vec<u8>>> {
    let mut len_ct = [0u8; 2 + 16];
    match r.read_exact(&mut len_ct).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len_plain = cipher
        .decrypt(nonce, &len_ct)
        .ok_or_else(|| io_err("SS 长度解密失败"))?;
    inc_nonce(nonce);
    if len_plain.len() != 2 {
        return Err(io_err("SS 长度格式错误"));
    }
    let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    if len > 0x3FFF {
        return Err(io_err("SS 分块过大"));
    }
    // AEAD 密文 = 明文长度 + 16 字节认证标签，必须完整读入才能解密。
    let mut data_ct = vec![0u8; len + 16];
    r.read_exact(&mut data_ct).await?;
    let data = cipher
        .decrypt(nonce, &data_ct)
        .ok_or_else(|| io_err("SS 数据解密失败"))?;
    inc_nonce(nonce);
    Ok(Some(data))
}

async fn pump(
    mut sr: tokio::net::tcp::OwnedReadHalf,
    mut sw: tokio::net::tcp::OwnedWriteHalf,
    master: Vec<u8>,
    method: String,
    key_len: usize,
    write_cipher: AeadCipher,
    mut write_nonce: [u8; 12],
    pipe: DuplexStream,
) {
    let (mut pr, mut pw) = tokio::io::split(pipe);

    let write_loop = async {
        loop {
            let mut buf = vec![0u8; 8192];
            let n = pr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            for chunk in buf[..n].chunks(0x3FFF) {
                write_chunk(&mut sw, &write_cipher, &mut write_nonce, chunk).await?;
            }
        }
        Ok::<(), io::Error>(())
    };

    let read_loop = async {
        // 服务端 salt 与首个响应数据可能一直等到应用真正发出请求后才返回，
        // 所以读握手必须和写循环并发，不能阻塞 connect() 返回。
        let mut server_salt = vec![0u8; key_len];
        tokio::time::timeout(std::time::Duration::from_secs(8), sr.read_exact(&mut server_salt))
            .await
            .map_err(|_| io_err("等待 SS 服务端 salt 超时"))??;
        let read_key = hkdf_subkey(&master, &server_salt)?;
        let read_cipher = cipher_new(&method, &read_key)?;
        let mut read_nonce = [0u8; 12];
        loop {
            match read_chunk(&mut sr, &read_cipher, &mut read_nonce).await {
                Ok(Some(data)) => {
                    if !data.is_empty() {
                        pw.write_all(&data).await?;
                    }
                }
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        Ok::<(), io::Error>(())
    };

    tokio::pin!(read_loop);
    tokio::pin!(write_loop);
    // 半关闭语义：写侧先结束（客户端 FIN）时不能丢弃读侧——
    // 服务端响应可能还在路上，必须继续读到 EOF。
    tokio::select! {
        r = &mut read_loop => { if let Err(e) = r { crate::logging::warn("ss", format!("读失败: {}", e)); } }
        r = &mut write_loop => {
            if let Err(e) = r { crate::logging::warn("ss", format!("写失败: {}", e)); }
            if let Err(e) = read_loop.await { crate::logging::warn("ss", format!("读失败: {}", e)); }
        }
    }
}

/// Shadowsocks AEAD UDP（SIP003）：每个报文独立 salt + 全零 nonce，明文为 SOCKS 地址 + 负载。
pub struct SsUdpCipher {
    method: String,
    master: Vec<u8>,
    key_len: usize,
    /// 重放防护：记录近期见过的 salt，重复 salt 直接丢弃。
    /// 容量有界，满了整体轮换（窗口重置，可接受）。
    seen_salts: std::sync::Mutex<std::collections::HashSet<Vec<u8>>>,
}

impl SsUdpCipher {
    pub fn new(node: &Node) -> io::Result<Self> {
        let method = node.method.clone().unwrap_or_else(|| "aes-256-gcm".into());
        let password = node.password.clone().unwrap_or_default();
        let key_len = key_len_for(&method)?;
        let master = evp_bytes_to_key(password.as_bytes(), key_len);
        Ok(Self {
            method,
            master,
            key_len,
            seen_salts: std::sync::Mutex::new(std::collections::HashSet::new()),
        })
    }

    pub fn seal(&self, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut salt = vec![0u8; self.key_len];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = hkdf_subkey(&self.master, &salt)?;
        let cipher = cipher_new(&self.method, &key)?;
        let mut plain = Vec::new();
        encode_socks_addr(&mut plain, target)?;
        plain.extend_from_slice(payload);
        let nonce = [0u8; 12];
        let encrypted = cipher.encrypt(&nonce, &plain);
        if encrypted.is_empty() {
            return Err(io_err("SS UDP 加密失败"));
        }
        let mut out = salt;
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    pub fn open(&self, packet: &[u8]) -> io::Result<(Target, Vec<u8>)> {
        if packet.len() <= self.key_len {
            return Err(io_err("SS UDP 报文过短"));
        }
        let salt = &packet[..self.key_len];
        {
            let mut seen = self.seen_salts.lock().unwrap_or_else(|p| p.into_inner());
            if seen.len() >= 8192 {
                seen.clear();
            }
            if !seen.insert(salt.to_vec()) {
                return Err(io_err("SS UDP 重放报文"));
            }
        }
        let key = hkdf_subkey(&self.master, salt)?;
        let cipher = cipher_new(&self.method, &key)?;
        let nonce = [0u8; 12];
        let plain = cipher
            .decrypt(&nonce, &packet[self.key_len..])
            .ok_or_else(|| io_err("SS UDP 解密失败"))?;
        let (domain, ip, port, offset) = crate::outbound::parse_socks_addr_bytes(&plain, 0)?;
        let payload = plain[offset..].to_vec();
        Ok((
            Target {
                ip,
                port,
                domain,
            },
            payload,
        ))
    }
}

pub async fn connect(node: &Node, target: Target) -> io::Result<BoxStream> {
    let method = node.method.clone().unwrap_or_else(|| "aes-256-gcm".into());
    let password = node.password.clone().unwrap_or_default();
    let key_len = key_len_for(&method)?;
    let master = evp_bytes_to_key(password.as_bytes(), key_len);
    let sock = crate::outbound::tcp_connect(&node.server, node.port).await?;
    let (sr, mut sw) = sock.into_split();

    let mut salt = vec![0u8; key_len];
    rand::thread_rng().fill_bytes(&mut salt);
    sw.write_all(&salt).await?;
    let write_key = hkdf_subkey(&master, &salt)?;
    let write_cipher = cipher_new(&method, &write_key)?;

    // Shadowsocks AEAD 的服务端 salt 是在收到首个客户端分块后才返回的。
    // 必须先发送目标地址（首个加密分块），不能先阻塞等待服务端数据。
    let mut first = Vec::new();
    encode_socks_addr(&mut first, &target)?;
    let mut write_nonce = [0u8; 12];
    write_chunk(&mut sw, &write_cipher, &mut write_nonce, &first).await?;

    let log_method = method.clone();
    let (pipe_a, pipe_b) = tokio::io::duplex(128 * 1024);
    // connect 立即返回；应用请求由 write_loop 转发，服务端 salt 在后台读取。
    tokio::spawn(pump(sr, sw, master, method, key_len, write_cipher, write_nonce, pipe_a));
    crate::logging::info("ss", format!("已连接 {} ({})", node.label(), log_method));
    Ok(Box::new(pipe_b))
}

