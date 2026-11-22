//! QUIC Initial 包的 SNI 嗅探。
//!
//! 背景：UDP 路径原本靠 DNS 反向映射「唯一」才敢丢 QUIC（怕共享 CDN IP 连坐）。
//! 实测 B 站 api/app 共用同一批 CDN IP，反查永远 ambiguous，迫降门从不打开，
//! App 走 HTTP/3 时整条连接绕过 MITM，改写间歇性失效。
//!
//! 这里直接在客户端 Initial 包里解出 TLS ClientHello 的 SNI：QUIC v1 的 Initial
//! 密钥由 DCID + 固定 salt 派生（RFC 9001 §5.2），无需要证书/会话即可解密。
//! 只对「SNI 命中 MITM 清单」的 Initial 丢包，共享 IP 上的其他域名不受影响；
//! 客户端 Initial 收不到回应会按 Happy Eyeballs 回落 TCP，改写恢复。
//!
//! 只支持 v1（版本号 1）；v2/0-RTT/分片 ClientHello 返回 None，走原有路径，
//! 不会误伤：宁可不迫降，也不猜错域名。

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// RFC 9001 §5.2 规定的 QUIC v1 Initial salt。
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// 从 UDP 载荷里取 QUIC Initial 的 SNI；不是可解的 v1 Initial 就返回 None。
pub fn initial_sni(payload: &[u8]) -> Option<String> {
    // 长包头 + 固定位；type bits（0x30）=0 才是 Initial。
    let b0 = *payload.first()?;
    if b0 & 0x80 == 0 || b0 & 0x30 != 0x00 {
        return None;
    }
    let version = u32::from_be_bytes([
        *payload.get(1)?,
        *payload.get(2)?,
        *payload.get(3)?,
        *payload.get(4)?,
    ]);
    if version != 1 {
        return None;
    }
    let mut pos = 5usize;
    let dcid_len = *payload.get(pos)? as usize;
    pos += 1;
    let dcid = payload.get(pos..pos + dcid_len)?;
    pos += dcid_len;
    let scid_len = *payload.get(pos)? as usize;
    pos += 1;
    let _scid = payload.get(pos..pos + scid_len)?;
    pos += scid_len;
    // Initial 有 token 长度字段（通常 0）。
    let token_len = read_varint(payload, &mut pos)? as usize;
    let _token = payload.get(pos..pos.checked_add(token_len)?)?;
    pos += token_len;
    let length = read_varint(payload, &mut pos)? as usize;
    let pn_offset = pos;

    // 头部保护采样：PN 偏移后 4 字节起取 16 字节（RFC 9001 §5.4.2）。
    let sample_off = pn_offset.checked_add(4)?;
    let sample = payload.get(sample_off..sample_off.checked_add(16)?)?;

    let hk = Hkdf::<Sha256>::new(Some(&SALT_V1), dcid);
    let mut key = [0u8; 16];
    hk.expand(b"quic key", &mut key).ok()?;
    let mut iv = [0u8; 12];
    hk.expand(b"quic iv", &mut iv).ok()?;
    let mut hp = [0u8; 16];
    hk.expand(b"quic hp", &mut hp).ok()?;

    // 头部保护：AES-128-ECB(hp_key, sample) 前 5 字节做掩码。
    let hp_cipher = aes::Aes128::new_from_slice(&hp).ok()?;
    let mut block = aes::Block::clone_from_slice(sample);
    hp_cipher.encrypt_block(&mut block);
    let mask = block;

    // 长包头第一字节只掩 0x0f；PN 长度在低 2 位。
    let first = b0 ^ (mask[0] & 0x0f);
    let pn_len = (first & 0x03) as usize + 1;
    if pn_len > 4 {
        return None;
    }
    let header_end = pn_offset.checked_add(pn_len)?;
    if header_end > payload.len() {
        return None;
    }
    let mut header: Vec<u8> = payload[..header_end].to_vec();
    header[0] = first;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        let v = payload[pn_offset + i] ^ mask[1 + i];
        header[pn_offset + i] = v;
        pn = (pn << 8) | v as u64;
    }

    // Length 覆盖「PN + 密文」，从 PN 起点算起。
    let packet_end = pn_offset.checked_add(length)?;
    let ct = payload.get(header_end..packet_end)?;

    let mut nonce = iv;
    for i in 0..pn_len {
        nonce[12 - pn_len + i] ^= header[pn_offset + i];
    }
    let cipher = Aes128Gcm::new_from_slice(&key).ok()?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ct,
                aad: &header,
            },
        )
        .ok()?;
    parse_frames(&plain)
}

/// 解析 Initial 明文里的帧，找 CRYPTO 帧并抽 ClientHello 的 SNI。
fn parse_frames(plain: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos < plain.len() {
        let ty = plain[pos];
        pos += 1;
        match ty {
            // padding / ping：无长度字段。
            0x00 | 0x01 => continue,
            // CRYPTO：长度 varint + 数据（可能包含多个握手记录）。
            0x06 => {
                let len = read_varint(plain, &mut pos)? as usize;
                let data = plain.get(pos..pos.checked_add(len)?)?;
                pos += len;
                if let Some(sni) = hello_sni(data) {
                    return Some(sni);
                }
            }
            // 其余帧格式不确定，停止解析，避免误读。
            _ => return None,
        }
    }
    None
}

/// 从 CRYPTO 帧数据里找 TLS ClientHello（可能有多条记录）并抽 SNI。
fn hello_sni(data: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos + 5 <= data.len() {
        // TLS handshake record：0x16 + legacy version + 2 字节长度。
        if data[pos] != 0x16 {
            pos += 1;
            continue;
        }
        let rec_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        let start = pos + 5;
        let end = start.checked_add(rec_len)?;
        let rec = data.get(start..end)?;
        if let Some(sni) = client_hello_sni(rec) {
            return Some(sni);
        }
        pos = end;
    }
    None
}

/// 解析 ClientHello（不含记录头）的 extensions，取 server_name。
fn client_hello_sni(hs: &[u8]) -> Option<String> {
    if hs.first().copied()? != 0x01 {
        return None;
    }
    let hs_len = u24(hs.get(1..4)?) as usize;
    let body = hs.get(4..4usize.checked_add(hs_len)?)?;
    let mut pos = 0usize;
    // legacy_version(2) + random(32)
    pos = pos.checked_add(34)?;
    // session_id
    let sid_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + sid_len)?;
    // cipher_suites
    let cs_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2 + cs_len)?;
    // compression_methods
    let comp_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + comp_len)?;
    // extensions
    let ext_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_len)?;
    let mut p = pos;
    while p + 4 <= ext_end {
        let ty = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]);
        let len = u16::from_be_bytes([*body.get(p + 2)?, *body.get(p + 3)?]) as usize;
        p += 4;
        let end = p.checked_add(len)?;
        let ext = body.get(p..end)?;
        p = end;
        if ty == 0x0000 {
            // server_name_list：长度(2) + 条目(类型1 + 长度2 + 名字)
            let list_len = u16::from_be_bytes([*ext.first()?, *ext.get(1)?]) as usize;
            let list = ext.get(2..2usize.checked_add(list_len)?)?;
            let name_type = *list.first()?;
            let name_len = u16::from_be_bytes([*list.get(1)?, *list.get(2)?]) as usize;
            let name = list.get(3..3usize.checked_add(name_len)?)?;
            if name_type != 0 {
                return None;
            }
            let host = std::str::from_utf8(name).ok()?.trim().to_ascii_lowercase();
            if host.is_empty() || host.len() > 253 {
                return None;
            }
            return Some(host);
        }
    }
    None
}

fn u24(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32
}

/// QUIC varint（RFC 9000 §4.1）：2 位长度前缀，支持 1/2/4/8 字节。
fn read_varint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *b.get(*pos)?;
    let len = 1usize << (first >> 6);
    if *pos + len > b.len() {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for i in 1..len {
        v = (v << 8) | b[*pos + i] as u64;
    }
    *pos += len;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(sni: &str) -> Vec<u8> {
        // extensions: server_name(0x0000)
        let mut entry = Vec::new();
        entry.push(0u8); // host_name
        entry.extend((sni.len() as u16).to_be_bytes());
        entry.extend(sni.as_bytes());
        let mut name_list = Vec::new();
        name_list.extend((entry.len() as u16).to_be_bytes());
        name_list.extend(&entry);
        let mut ext = Vec::new();
        ext.extend(0u16.to_be_bytes());
        ext.extend((name_list.len() as u16).to_be_bytes());
        ext.extend(&name_list);

        let mut hello = Vec::new();
        hello.extend([0x03, 0x03]); // legacy version
        hello.extend([0u8; 32]); // random
        hello.push(0); // session id len
        hello.extend((2u16).to_be_bytes());
        hello.extend([0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello.push(1);
        hello.push(0); // null compression
        hello.extend((ext.len() as u16).to_be_bytes());
        hello.extend(&ext);

        let mut hs = Vec::new();
        hs.push(0x01);
        hs.extend([
            ((hello.len() >> 16) & 0xff) as u8,
            ((hello.len() >> 8) & 0xff) as u8,
            (hello.len() & 0xff) as u8,
        ]);
        hs.extend(&hello);

        let mut rec = Vec::new();
        rec.extend([0x16, 0x03, 0x01]);
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(&hs);
        rec
    }

    fn put_varint(out: &mut Vec<u8>, v: usize) {
        if v < 0x40 {
            out.push(v as u8);
        } else if v < 0x4000 {
            out.push(0x40 | ((v >> 8) as u8));
            out.push((v & 0xff) as u8);
        } else {
            out.push(0x80 | ((v >> 24) as u8));
            out.push(((v >> 16) & 0xff) as u8);
            out.push(((v >> 8) & 0xff) as u8);
            out.push((v & 0xff) as u8);
        }
    }

    /// 用与解析侧相同的 RFC 9001 派生，构造一个真实的 v1 Initial 包。
    fn build_initial(sni: &str, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let hello = build_client_hello(sni);
        let mut frames = Vec::new();
        frames.push(0x06); // CRYPTO
        put_varint(&mut frames, hello.len());
        frames.extend(&hello);

        let pn_len = 2usize;
        let pn = [0x00u8, 0x07];
        let mut header = Vec::new();
        header.push(0xC0 | ((pn_len - 1) as u8)); // long header, fixed bit, Initial
        header.extend((1u32).to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend(dcid);
        header.push(scid.len() as u8);
        header.extend(scid);
        put_varint(&mut header, 0); // token length
        put_varint(&mut header, pn_len + frames.len() + 16); // length = PN + 密文（含 16 字节 tag）
        header.extend(pn);
        let hk = Hkdf::<Sha256>::new(Some(&SALT_V1), dcid);
        let mut key = [0u8; 16];
        hk.expand(b"quic key", &mut key).unwrap();
        let mut iv = [0u8; 12];
        hk.expand(b"quic iv", &mut iv).unwrap();
        let mut hp = [0u8; 16];
        hk.expand(b"quic hp", &mut hp).unwrap();
        let mut nonce = iv;
        nonce[12 - pn_len] ^= pn[0];
        nonce[12 - pn_len + 1] ^= pn[1];
        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let mut ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &frames,
                    aad: &header,
                },
            )
            .unwrap();

        let mut packet = header;
        packet.append(&mut ct);
        let pn_offset = packet.len() - frames.len() - 16 - pn_len;
        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let hp_cipher = aes::Aes128::new_from_slice(&hp).unwrap();
        let mut block = aes::Block::clone_from_slice(sample);
        hp_cipher.encrypt_block(&mut block);
        packet[0] ^= block[0] & 0x0f;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= block[1 + i];
        }
        packet
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let rec = build_client_hello("app.bilibili.com");
        assert_eq!(hello_sni(&rec).as_deref(), Some("app.bilibili.com"));
    }

    #[test]
    fn extracts_sni_from_quic_initial() {
        let dcid = [0x11u8; 8];
        let scid = [0x22u8; 4];
        let pkt = build_initial("app.bilibili.com", &dcid, &scid);
        assert_eq!(initial_sni(&pkt).as_deref(), Some("app.bilibili.com"));
    }

    #[test]
    fn ignores_non_initial_and_truncated() {
        assert!(initial_sni(&[]).is_none());
        // 短包头（1-RTT）不是长包头。
        assert!(initial_sni(&[0x40, 0, 0, 0]).is_none());
        // 截断包不能 panic。
        let dcid = [0x33u8; 8];
        let mut pkt = build_initial("a.test", &dcid, &[0x44u8; 4]);
        pkt.truncate(30);
        assert!(initial_sni(&pkt).is_none());
    }
}
