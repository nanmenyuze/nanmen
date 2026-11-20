//! 从首包提取 TLS SNI / HTTP Host，补足没有经过本地 DNS 的连接域名。

use std::net::IpAddr;

pub fn sniff_domain(data: &[u8]) -> Option<String> {
    tls_sni(data).or_else(|| http_host(data))
}

fn clean_host(host: &str) -> Option<String> {
    let mut h = host.trim();
    if h.starts_with('[') {
        // 这里只返回域名；IPv6 字面量不参与域名分流。
        return None;
    }
    if h.matches(':').count() == 1 {
        h = h.split(':').next()?;
    }
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.len() > 253 || h.parse::<IpAddr>().is_ok() || !h.contains('.') {
        return None;
    }
    if !h.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
        return None;
    }
    Some(h)
}

fn tls_sni(d: &[u8]) -> Option<String> {
    // TLS record(5) + handshake header(4) + ClientHello version/random(34)
    if d.len() < 43 || d[0] != 0x16 || d[5] != 0x01 {
        return None;
    }
    let hs_len = ((d[6] as usize) << 16) | ((d[7] as usize) << 8) | d[8] as usize;
    let end = (9usize + hs_len).min(d.len());
    let mut p = 9usize;
    if p + 34 > end {
        return None;
    }
    p += 34;

    let session_len = *d.get(p)? as usize;
    p += 1;
    if p + session_len > end {
        return None;
    }
    p += session_len;

    if p + 2 > end {
        return None;
    }
    let cipher_len = u16::from_be_bytes([d[p], d[p + 1]]) as usize;
    p += 2;
    if p + cipher_len > end {
        return None;
    }
    p += cipher_len;

    let comp_len = *d.get(p)? as usize;
    p += 1;
    if p + comp_len > end {
        return None;
    }
    p += comp_len;

    if p + 2 > end {
        return None;
    }
    let ext_total = u16::from_be_bytes([d[p], d[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(end);

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([d[p], d[p + 1]]);
        let ext_len = u16::from_be_bytes([d[p + 2], d[p + 3]]) as usize;
        p += 4;
        if p + ext_len > ext_end {
            return None;
        }
        if ext_type == 0 {
            let ext = &d[p..p + ext_len];
            if ext.len() < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
            let list_end = (2 + list_len).min(ext.len());
            let mut q = 2usize;
            while q + 3 <= list_end {
                let name_type = ext[q];
                let name_len = u16::from_be_bytes([ext[q + 1], ext[q + 2]]) as usize;
                q += 3;
                if q + name_len > list_end {
                    return None;
                }
                if name_type == 0 {
                    return clean_host(std::str::from_utf8(&ext[q..q + name_len]).ok()?);
                }
                q += name_len;
            }
            return None;
        }
        p += ext_len;
    }
    None
}

fn http_host(d: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(d).ok()?;
    let mut lines = text.split("\r\n");
    let request = lines.next()?;
    let mut parts = request.split_whitespace();
    let method = parts.next()?;
    if !matches!(method, "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "PATCH" | "CONNECT") {
        return None;
    }
    let authority = parts.next();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.len() >= 5 && line.as_bytes()[..5].eq_ignore_ascii_case(b"host:") {
            return clean_host(line[5..].trim());
        }
    }
    if method == "CONNECT" {
        return clean_host(authority?);
    }
    None
}
