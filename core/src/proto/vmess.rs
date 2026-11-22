//! VMess AEAD 客户端（TCP / TLS / WebSocket）。
//!
//! 仅实现 alterId=0 的 AEAD 认证与标准分块数据段；不做 MD5 旧认证、mux、UDP、gRPC。
//! 协议常量与密钥派生顺序依据 V2Fly VMess 规范 / Xray-core 实现。

use crate::config::{Node, Target};
use crate::logging;
use crate::outbound::{encode_vless_addr, io_err, tls_connect, BoxStream};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use md5::{Digest, Md5};
use rand::RngCore;
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const CMD_TCP: u8 = 0x01;
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const SEC_AES128_GCM: u8 = 0x03;
const SEC_CHACHA20_POLY1305: u8 = 0x04;
const CHUNK_LIMIT: usize = 16384;
const WRITE_CHUNK: usize = 16000;
const KDF_SALT: &[u8] = b"VMess AEAD KDF";
const AUTH_ID_SALT: &str = "AES Auth ID Encryption";

/// SHAKE128：VMess 的长度掩码是 SHAKE128(bodyIV) 的连续两字节流。
/// 项目没有 sha3 依赖，这里实现最小 Keccak-f[1600] + SHAKE128 sponge。
struct Shake128 {
    state: [u64; 25],
    pos: usize,
}

const KECCAK_RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const KECCAK_ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const KECCAK_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f1600(st: &mut [u64; 25]) {
    for round in 0..24 {
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }
        let mut t = st[1];
        for i in 0..24 {
            let j = KECCAK_PILN[i];
            let tmp = st[j];
            st[j] = t.rotate_left(KECCAK_ROTC[i]);
            t = tmp;
        }
        for j in (0..25).step_by(5) {
            let mut row = [0u64; 5];
            row.copy_from_slice(&st[j..j + 5]);
            for i in 0..5 {
                st[j + i] ^= (!row[(i + 1) % 5]) & row[(i + 2) % 5];
            }
        }
        st[0] ^= KECCAK_RC[round];
    }
}

impl Shake128 {
    fn new(seed: &[u8]) -> Self {
        let mut state = [0u64; 25];
        let rate = 168usize;
        for chunk in seed.chunks(rate) {
            for (i, b) in chunk.iter().enumerate() {
                state[i / 8] ^= (*b as u64) << (8 * (i % 8));
            }
            if chunk.len() == rate {
                keccak_f1600(&mut state);
            }
        }
        let pos = seed.len() % rate;
        state[pos / 8] ^= 0x1f << (8 * (pos % 8));
        state[(rate - 1) / 8] ^= 0x80 << (8 * ((rate - 1) % 8));
        keccak_f1600(&mut state);
        Self { state, pos: 0 }
    }

    fn next_u16(&mut self) -> u16 {
        let hi = self.next_byte() as u16;
        let lo = self.next_byte() as u16;
        (hi << 8) | lo
    }

    fn next_byte(&mut self) -> u8 {
        const RATE: usize = 168;
        if self.pos == RATE {
            keccak_f1600(&mut self.state);
            self.pos = 0;
        }
        let b = ((self.state[self.pos / 8] >> (8 * (self.pos % 8))) & 0xff) as u8;
        self.pos += 1;
        b
    }
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC 接受任意 key");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// VMess 的 KDF 是「把上一层 HMAC 当作下一层的哈希函数」的嵌套 HMAC，
/// 不能退化成 HMAC(key, salt || path)。
fn nested_hmac(keys: &[&[u8]], data: &[u8]) -> [u8; 32] {
    if keys.len() == 1 {
        return hmac_sha256(keys[0], data);
    }
    let parent = &keys[..keys.len() - 1];
    let key = keys[keys.len() - 1];
    let block = 64usize;
    let mut k = key.to_vec();
    if k.len() > block {
        k = hmac_sha256(&[], &k).to_vec();
    }
    let mut ipad = vec![0x36u8; block];
    let mut opad = vec![0x5cu8; block];
    for i in 0..k.len() {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner_msg = ipad;
    inner_msg.extend_from_slice(data);
    let inner = nested_hmac(parent, &inner_msg);
    let mut outer_msg = opad;
    outer_msg.extend_from_slice(&inner);
    nested_hmac(parent, &outer_msg)
}

fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = Vec::with_capacity(2 + path.len());
    keys.push(KDF_SALT);
    keys.push(salt.as_bytes());
    keys.extend_from_slice(path);
    nested_hmac(&keys, key)
}

fn kdf16(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, salt, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

fn md5_bytes(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    let out = h.finalize();
    let mut v = [0u8; 16];
    v.copy_from_slice(&out);
    v
}

fn sha256_16(data: &[u8]) -> [u8; 16] {
    let out = Sha256::digest(data);
    let mut v = [0u8; 16];
    v.copy_from_slice(&out[..16]);
    v
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut h = 0x811c9dc5u32;
    for b in data {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn aes_ecb_encrypt(key: &[u8; 16], plain: &[u8; 16]) -> io::Result<[u8; 16]> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(plain);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

fn gcm_seal(key: &[u8], nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| io_err("VMess AES-GCM key 无效"))?;
    cipher
        .encrypt(AesNonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| io_err("VMess 头部加密失败"))
}

fn gcm_open(key: &[u8], nonce: &[u8; 12], data: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| io_err("VMess AES-GCM key 无效"))?;
    cipher
        .decrypt(AesNonce::from_slice(nonce), Payload { msg: data, aad })
        .map_err(|_| io_err("VMess 响应头认证失败"))
}

fn chunk_nonce(iv: &[u8; 16], count: u16) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..2].copy_from_slice(&count.to_be_bytes());
    n[2..].copy_from_slice(&iv[2..12]);
    n
}

fn chacha_key(body_key: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let first = md5_bytes(body_key);
    out[..16].copy_from_slice(&first);
    let second = md5_bytes(&first);
    out[16..].copy_from_slice(&second);
    out
}

enum BodyAead {
    Aes(Aes128Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl BodyAead {
    fn new(security: u8, body_key: &[u8; 16]) -> io::Result<Self> {
        match security {
            SEC_AES128_GCM => Ok(Self::Aes(
                Aes128Gcm::new_from_slice(body_key)
                    .map_err(|_| io_err("VMess AES-GCM key 无效"))?,
            )),
            SEC_CHACHA20_POLY1305 => {
                let key = chacha_key(body_key);
                Ok(Self::ChaCha(
                    ChaCha20Poly1305::new_from_slice(&key)
                        .map_err(|_| io_err("VMess ChaCha20 key 无效"))?,
                ))
            }
            other => Err(io_err(format!("VMess 不支持的加密方式: {}", other))),
        }
    }

    fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload {
            msg: plain,
            aad: &[],
        };
        match self {
            Self::Aes(c) => c
                .encrypt(AesNonce::from_slice(nonce), payload)
                .map_err(|_| io_err("VMess 数据加密失败")),
            Self::ChaCha(c) => c
                .encrypt(ChaChaNonce::from_slice(nonce), payload)
                .map_err(|_| io_err("VMess 数据加密失败")),
        }
    }

    fn open(&self, nonce: &[u8; 12], data: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload {
            msg: data,
            aad: &[],
        };
        match self {
            Self::Aes(c) => c
                .decrypt(AesNonce::from_slice(nonce), payload)
                .map_err(|_| io_err("VMess 数据认证失败")),
            Self::ChaCha(c) => c
                .decrypt(ChaChaNonce::from_slice(nonce), payload)
                .map_err(|_| io_err("VMess 数据认证失败")),
        }
    }
}

struct BodyCipher {
    aead: BodyAead,
    iv: [u8; 16],
    count: u16,
    mask: Shake128,
}

impl BodyCipher {
    fn new(security: u8, body_key: &[u8; 16], body_iv: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            aead: BodyAead::new(security, body_key)?,
            iv: *body_iv,
            count: 0,
            mask: Shake128::new(body_iv),
        })
    }

    fn seal_chunk(&mut self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = chunk_nonce(&self.iv, self.count);
        self.count = self.count.wrapping_add(1);
        let cipher = self.aead.seal(&nonce, plain)?;
        let mut wire = Vec::with_capacity(2 + cipher.len());
        let len = (cipher.len() as u16) ^ self.mask.next_u16();
        wire.extend_from_slice(&len.to_be_bytes());
        wire.extend_from_slice(&cipher);
        Ok(wire)
    }

    fn open_chunk(&mut self, _wire_len: u16, cipher: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = chunk_nonce(&self.iv, self.count);
        self.count = self.count.wrapping_add(1);
        self.aead.open(&nonce, cipher)
    }

    fn unmask_len(&mut self, wire: u16) -> u16 {
        wire ^ self.mask.next_u16()
    }
}

fn security_of(node: &Node) -> io::Result<u8> {
    match node
        .method
        .as_deref()
        .unwrap_or("auto")
        .to_ascii_lowercase()
        .as_str()
    {
        "auto" | "" | "aes-128-gcm" | "aes128-gcm" => Ok(SEC_AES128_GCM),
        "chacha20-poly1305" | "chacha20" | "chacha20-ietf-poly1305" => Ok(SEC_CHACHA20_POLY1305),
        other => Err(io_err(format!(
            "VMess 不支持加密方式 {}（仅 auto/aes-128-gcm/chacha20-poly1305）",
            other
        ))),
    }
}

async fn open_stream(node: &Node) -> io::Result<BoxStream> {
    let host = node.server.clone();
    let port = node.port;
    let sni = node.sni.clone().unwrap_or_else(|| host.clone());
    let insecure = node.insecure.unwrap_or(false);
    let use_tls = node.tls.unwrap_or(false);
    let mut stream: BoxStream = if use_tls {
        Box::new(tls_connect(&host, port, &sni, insecure).await?)
    } else {
        Box::new(crate::outbound::tcp_connect(&host, port).await?)
    };
    if node.ws_path.is_some() {
        let path = node.ws_path.clone().unwrap_or_else(|| "/".into());
        let ws_host = node.ws_host.clone().unwrap_or_else(|| sni.clone());
        stream = crate::proto::ws::wrap(stream, &path, &ws_host).await?;
    }
    Ok(stream)
}

struct RequestState {
    response_auth: u8,
    security: u8,
    body_key: [u8; 16],
    body_iv: [u8; 16],
}

fn build_request_header(node: &Node, target: &Target) -> io::Result<(Vec<u8>, RequestState)> {
    let uuid = crate::proto::vless::parse_uuid(node.uuid.as_deref().unwrap_or(""))?;
    let security = security_of(node)?;
    let mut rng = rand::thread_rng();
    let mut body_key = [0u8; 16];
    let mut body_iv = [0u8; 16];
    let mut response_auth = [0u8; 1];
    rng.fill_bytes(&mut body_key);
    rng.fill_bytes(&mut body_iv);
    rng.fill_bytes(&mut response_auth);

    let mut header = Vec::with_capacity(64);
    header.push(1u8); // version
    header.extend_from_slice(&body_iv);
    header.extend_from_slice(&body_key);
    header.push(response_auth[0]);
    header.push(OPT_CHUNK_STREAM | OPT_CHUNK_MASKING);
    header.push(security);
    header.push(0u8); // reserved
    header.push(CMD_TCP);
    encode_vless_addr(&mut header, target)?; // VMess 与 VLESS 一样是 port-then-address
                                             // padding 长度写在 security 字节高 4 位；这里固定 0，避免无意义负载。
    let hash = fnv1a(&header);
    header.extend_from_slice(&hash.to_be_bytes());

    let cmd_key = md5_bytes(&[uuid.as_slice(), b"c48619fe-8f02-49e0-b9e9-edf763e17e21"].concat());
    let auth_key = kdf16(&cmd_key, AUTH_ID_SALT, &[]);
    let mut auth_plain = [0u8; 16];
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    auth_plain[..8].copy_from_slice(&ts.to_be_bytes());
    let mut rand4 = [0u8; 4];
    rng.fill_bytes(&mut rand4);
    auth_plain[8..12].copy_from_slice(&rand4);
    let crc = crc32fast::hash(&auth_plain[..12]);
    auth_plain[12..].copy_from_slice(&crc.to_be_bytes());
    let auth_id = aes_ecb_encrypt(&auth_key, &auth_plain)?;

    let mut conn_nonce = [0u8; 8];
    rng.fill_bytes(&mut conn_nonce);

    let len_key = kdf16(
        &cmd_key,
        "VMess Header AEAD Key_Length",
        &[&auth_id, &conn_nonce],
    );
    let len_nonce = kdf(
        &cmd_key,
        "VMess Header AEAD Nonce_Length",
        &[&auth_id, &conn_nonce],
    );
    let a_len = gcm_seal(
        &len_key,
        &nonce12(&len_nonce),
        &(header.len() as u16).to_be_bytes(),
        &auth_id,
    )?;

    let hdr_key = kdf16(&cmd_key, "VMess Header AEAD Key", &[&auth_id, &conn_nonce]);
    let hdr_nonce = kdf(
        &cmd_key,
        "VMess Header AEAD Nonce",
        &[&auth_id, &conn_nonce],
    );
    let a_header = gcm_seal(&hdr_key, &nonce12(&hdr_nonce), &header, &auth_id)?;

    let mut out = Vec::with_capacity(16 + 18 + 8 + a_header.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&a_len);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&a_header);

    Ok((
        out,
        RequestState {
            response_auth: response_auth[0],
            security,
            body_key,
            body_iv,
        },
    ))
}

fn nonce12(full: &[u8; 32]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(&full[..12]);
    n
}

async fn read_response_header<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    state: &RequestState,
) -> io::Result<BodyCipher> {
    let resp_key = sha256_16(&state.body_key);
    let resp_iv = sha256_16(&state.body_iv);
    let fut = async {
        let mut len_buf = [0u8; 18];
        stream.read_exact(&mut len_buf).await?;
        let len_key = kdf16(&resp_key, "AEAD Resp Header Len Key", &[]);
        let len_nonce = nonce12(&kdf(&resp_iv, "AEAD Resp Header Len IV", &[]));
        let plain_len = gcm_open(&len_key, &len_nonce, &len_buf, &[])?;
        if plain_len.len() != 2 {
            return Err(io_err("VMess 响应头长度无效"));
        }
        let len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
        if len == 0 || len > 4096 {
            return Err(io_err("VMess 响应头长度越界"));
        }
        let mut payload = vec![0u8; len + 16];
        stream.read_exact(&mut payload).await?;
        let key = kdf16(&resp_key, "AEAD Resp Header Key", &[]);
        let nonce = nonce12(&kdf(&resp_iv, "AEAD Resp Header IV", &[]));
        let header = gcm_open(&key, &nonce, &payload, &[])?;
        if header.len() < 2 || header[0] != state.response_auth {
            return Err(io_err("VMess 响应头认证值不匹配"));
        }
        BodyCipher::new(state.security, &resp_key, &resp_iv)
    };
    tokio::time::timeout(std::time::Duration::from_secs(8), fut)
        .await
        .map_err(|_| io_err("VMess 响应头超时"))?
}

/// VMess AEAD TCP 连接。返回一个明文双向管道；请求头/响应头在后台完成。
///
/// 关键点：VMess 服务端通常要等第一个请求分块才回响应头，所以请求体写循环
/// 必须和响应头读取并行启动，不能先等响应头再写 body，否则会互相等待。
pub async fn connect(node: &Node, target: Target) -> io::Result<BoxStream> {
    let mut stream = open_stream(node).await?;
    let (header, state) = build_request_header(node, &target)?;
    stream.write_all(&header).await?;

    let request = BodyCipher::new(state.security, &state.body_key, &state.body_iv)?;
    let (pipe_a, pipe_b) = tokio::io::duplex(128 * 1024);
    let (sr, sw) = tokio::io::split(stream);
    let (pr, pw) = tokio::io::split(pipe_a);
    let label = node.label();
    tokio::spawn(async move {
        let mut request = request;
        let write_loop = async {
            let mut sw = sw;
            let mut pr = pr;
            let mut buf = vec![0u8; WRITE_CHUNK];
            loop {
                let n = pr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let frame = request.seal_chunk(&buf[..n])?;
                sw.write_all(&frame).await?;
            }
            let end = request.seal_chunk(&[])?;
            sw.write_all(&end).await?;
            sw.shutdown().await?;
            Ok::<(), io::Error>(())
        };
        tokio::pin!(write_loop);

        let mut sr = sr;
        let response = {
            let response_fut = read_response_header(&mut sr, &state);
            tokio::pin!(response_fut);
            tokio::select! {
                r = &mut response_fut => match r {
                    Ok(r) => r,
                    Err(e) => {
                        logging::warn("vmess", format!("{} 响应头握手失败: {}", label, e));
                        return;
                    }
                },
                r = &mut write_loop => {
                    if let Err(e) = r { logging::warn("vmess", format!("{} 写失败 {}", label, e)); }
                    return;
                }
            }
        };

        let read_loop = async {
            let mut pw = pw;
            let mut response = response;
            read_response_body(&mut sr, &mut pw, &mut response).await
        };
        tokio::pin!(read_loop);
        tokio::select! {
            r = &mut read_loop => {
                if let Err(e) = r { logging::warn("vmess", format!("{} 读失败 {}", label, e)); }
            }
            r = &mut write_loop => {
                if let Err(e) = r { logging::warn("vmess", format!("{} 写失败 {}", label, e)); }
                if let Err(e) = read_loop.await { logging::warn("vmess", format!("{} 读失败 {}", label, e)); }
            }
        }
    });

    logging::info(
        "vmess",
        format!(
            "已连接 {} -> {}",
            node.label(),
            crate::outbound::display_target(&target)
        ),
    );
    Ok(Box::new(pipe_b))
}

async fn read_response_body<R: AsyncReadExt + Unpin>(
    sr: &mut R,
    pw: &mut tokio::io::WriteHalf<DuplexStream>,
    response: &mut BodyCipher,
) -> io::Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        sr.read_exact(&mut len_buf).await?;
        let wire = u16::from_be_bytes(len_buf);
        let len = response.unmask_len(wire) as usize;
        if len == 0 {
            break;
        }
        if len < 16 || len > CHUNK_LIMIT {
            return Err(io_err("VMess 响应分块长度越界"));
        }
        let mut cipher = vec![0u8; len];
        sr.read_exact(&mut cipher).await?;
        let plain = response.open_chunk(wire, &cipher)?;
        if plain.is_empty() {
            break;
        }
        pw.write_all(&plain).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_matches_v2fly_nested_hmac_vector() {
        // 向量由 Go 的 hMacCreator 实现生成，用于防止把嵌套 HMAC 简化成普通 HMAC。
        let key = b"0123456789abcdef";
        let out = kdf(
            key,
            "VMess Header AEAD Key",
            &[b"authid0123456789", b"nonce123"],
        );
        assert_eq!(
            hex(&out),
            "b6baaa564ea7f248d826c62bbba333b74dfbf06ddf345b194a071a1f53283413"
        );
        let auth = kdf16(key, AUTH_ID_SALT, &[]);
        assert_eq!(hex(&auth), "ebde3a0b17bf94c86fa140917ec6a0c9");
    }

    #[test]
    fn shake128_matches_go_nonempty_vector() {
        let seed: Vec<u8> = (0..16).collect();
        let mut s = Shake128::new(&seed);
        let mut got = Vec::new();
        for _ in 0..16 {
            got.push(s.next_byte());
        }
        assert_eq!(hex(&got), "98481946de85c670a7a84432ab4091a8");
    }

    #[test]
    fn shake128_matches_empty_vector() {
        let mut s = Shake128::new(b"");
        assert_eq!(s.next_byte(), 0x7f);
        assert_eq!(s.next_byte(), 0x9c);
    }

    #[test]
    fn body_chunk_roundtrip_aes() {
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let mut w = BodyCipher::new(SEC_AES128_GCM, &key, &iv).unwrap();
        let mut r = BodyCipher::new(SEC_AES128_GCM, &key, &iv).unwrap();
        let frame = w.seal_chunk(b"hello vmess").unwrap();
        let wire = u16::from_be_bytes([frame[0], frame[1]]);
        let len = r.unmask_len(wire) as usize;
        let plain = r.open_chunk(wire, &frame[2..2 + len]).unwrap();
        assert_eq!(plain, b"hello vmess");
    }

    #[test]
    fn body_chunk_roundtrip_chacha() {
        let key = [3u8; 16];
        let iv = [5u8; 16];
        let mut w = BodyCipher::new(SEC_CHACHA20_POLY1305, &key, &iv).unwrap();
        let mut r = BodyCipher::new(SEC_CHACHA20_POLY1305, &key, &iv).unwrap();
        let frame = w.seal_chunk(b"chacha").unwrap();
        let wire = u16::from_be_bytes([frame[0], frame[1]]);
        let len = r.unmask_len(wire) as usize;
        assert_eq!(r.open_chunk(wire, &frame[2..2 + len]).unwrap(), b"chacha");
    }

    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
