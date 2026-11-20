//! gRPC protobuf 字段级正文改写。
//!
//! gRPC 正文由若干「5 字节帧头 + protobuf 消息」组成：
//! `[compressed flag u8][message length u32 BE][payload]`。
//! 这里不依赖具体 proto schema，按 protobuf wire format 递归解析：
//! - length-delimited 字段若可读为文本，直接套用现有 body 正则规则；
//! - 否则尝试按嵌套消息递归，改写其中的字符串字段；
//! - varint/fixed/未知结构原样保留，压缩消息（flag=1）不碰，避免破坏编码。
//!
//! 这是「字段值级」改写，不改变字段号、wire type、字段顺序或帧边界；
//! 解析失败/输出超限时由调用方回退原始正文。

use super::rewrite::apply_body_rules_limited;
use super::RewriteRule;

const MAX_DEPTH: usize = 24;

/// 改写 gRPC 正文。返回 `(新正文, 是否有改动)`；
/// 帧结构非法、protobuf 解析失败或输出超过 `limit` 时返回 `None`。
pub fn rewrite_grpc_body(
    body: &[u8],
    rules: &[&RewriteRule],
    limit: usize,
) -> Option<(Vec<u8>, bool)> {
    if body.is_empty() {
        return Some((Vec::new(), false));
    }
    let mut out = Vec::with_capacity(body.len());
    let mut changed = false;
    let mut pos = 0usize;
    while pos < body.len() {
        if body.len() - pos < 5 {
            return None;
        }
        let flags = body[pos];
        let len = u32::from_be_bytes([
            body[pos + 1],
            body[pos + 2],
            body[pos + 3],
            body[pos + 4],
        ]) as usize;
        pos += 5;
        if len > body.len() - pos {
            return None;
        }
        let payload = &body[pos..pos + len];
        pos += len;

        // 压缩帧不解析；flag 原样保留，避免误改压缩流。
        let (new_payload, payload_changed) = if flags & 1 != 0 {
            (payload.to_vec(), false)
        } else {
            rewrite_message(payload, rules, limit, 0)?
        };
        changed |= payload_changed;
        out.push(flags);
        out.extend_from_slice(&(new_payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&new_payload);
        if out.len() > limit {
            return None;
        }
    }
    if changed {
        Some((out, true))
    } else {
        Some((body.to_vec(), false))
    }
}

struct Field<'a> {
    raw: &'a [u8],
    prefix: Option<&'a [u8]>,
    payload: &'a [u8],
}

/// 解析一条 protobuf 消息；只接受 varint/fixed32/fixed64/length-delimited。
/// group（wire 3/4）或非法 wire type 直接判失败，由上层回退原文。
fn parse_message(data: &[u8]) -> Option<Vec<Field<'_>>> {
    let mut fields = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let start = pos;
        let (tag, tag_len) = read_varint(data, pos)?;
        pos += tag_len;
        if tag >> 3 == 0 {
            return None;
        }
        match tag & 0x07 {
            0 => {
                let (_, n) = read_varint(data, pos)?;
                pos += n;
                fields.push(Field {
                    raw: &data[start..pos],
                    prefix: None,
                    payload: &[],
                });
            }
            1 => {
                if data.len() - pos < 8 {
                    return None;
                }
                pos += 8;
                fields.push(Field {
                    raw: &data[start..pos],
                    prefix: None,
                    payload: &[],
                });
            }
            2 => {
                let tag_end = pos;
                let (len, n) = read_varint(data, pos)?;
                pos += n;
                let len = usize::try_from(len).ok()?;
                if len > data.len() - pos {
                    return None;
                }
                let payload = &data[pos..pos + len];
                pos += len;
                fields.push(Field {
                    raw: &data[start..pos],
                    // prefix 只含字段 tag；长度在改写后重新编码，不能带旧 length。
                    prefix: Some(&data[start..tag_end]),
                    payload,
                });
            }
            5 => {
                if data.len() - pos < 4 {
                    return None;
                }
                pos += 4;
                fields.push(Field {
                    raw: &data[start..pos],
                    prefix: None,
                    payload: &[],
                });
            }
            _ => return None,
        }
    }
    Some(fields)
}

fn rewrite_message(
    data: &[u8],
    rules: &[&RewriteRule],
    limit: usize,
    depth: usize,
) -> Option<(Vec<u8>, bool)> {
    if depth > MAX_DEPTH {
        return Some((data.to_vec(), false));
    }
    let fields = parse_message(data)?;
    let mut out = Vec::with_capacity(data.len());
    let mut changed = false;
    for field in fields {
        let (prefix, payload) = match (field.prefix, field.payload.is_empty()) {
            (Some(prefix), _) => (prefix, field.payload),
            _ => {
                out.extend_from_slice(field.raw);
                continue;
            }
        };
        let (new_payload, payload_changed) = rewrite_length_payload(payload, rules, limit, depth)?;
        if payload_changed {
            changed = true;
            out.extend_from_slice(prefix);
            write_varint(new_payload.len() as u64, &mut out);
            out.extend_from_slice(&new_payload);
        } else {
            out.extend_from_slice(field.raw);
        }
        if out.len() > limit {
            return None;
        }
    }
    if changed {
        Some((out, true))
    } else {
        Some((data.to_vec(), false))
    }
}

/// length-delimited 字段内容：优先当文本套规则，其次当嵌套消息递归。
fn rewrite_length_payload(
    payload: &[u8],
    rules: &[&RewriteRule],
    limit: usize,
    depth: usize,
) -> Option<(Vec<u8>, bool)> {
    if depth >= MAX_DEPTH || payload.is_empty() {
        return Some((payload.to_vec(), false));
    }
    if let Ok(text) = std::str::from_utf8(payload) {
        if is_textual(text) {
            return match apply_body_rules_limited(text.as_bytes(), rules, limit) {
                Some(v) => Some(v),
                // 规则替换后超限，按未改处理，由整体路径决定是否回退。
                None => Some((payload.to_vec(), false)),
            };
        }
    }
    match rewrite_message(payload, rules, limit, depth + 1) {
        Some(v) => Some(v),
        None => Some((payload.to_vec(), false)),
    }
}

fn is_textual(text: &str) -> bool {
    text.chars()
        .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
}

fn read_varint(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let start = pos;
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *data.get(pos)?;
        pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, pos - start));
        }
        if shift == 63 {
            return None;
        }
    }
    None
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::{RewriteAction, RewriteRule};
    use regex::Regex;

    fn body_rule(pattern: &str, replacement: &str) -> RewriteRule {
        RewriteRule {
            url: Regex::new(r"^https://grpc\.test\.local/ads").unwrap(),
            action: RewriteAction::Body,
            body: Some(regex::bytes::Regex::new(pattern).unwrap()),
            replacement: replacement.to_string(),
            header_field: String::new(),
        }
    }

    fn varint(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        write_varint(v, &mut out);
        out
    }

    fn field_str(num: u8, text: &str) -> Vec<u8> {
        let mut out = varint((u64::from(num) << 3) | 2);
        out.extend_from_slice(&varint(text.len() as u64));
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn field_varint(num: u8, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(num) << 3);
        out.extend_from_slice(&varint(value));
        out
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn decode_str_fields(data: &[u8]) -> Vec<String> {
        let fields = parse_message(data).unwrap();
        let mut out = Vec::new();
        for f in fields {
            if f.prefix.is_some() {
                if let Some(value) = rewrite_length_payload(f.payload, &[], 4096, 0)
                    .and_then(|(v, _)| String::from_utf8(v).ok())
                    .filter(|s| is_textual(s))
                {
                    out.push(value);
                }
            }
        }
        out
    }

    #[test]
    fn rewrites_string_fields_and_nested_messages() {
        let mut inner = Vec::new();
        inner.extend_from_slice(&field_str(1, "inner ad"));
        inner.extend_from_slice(&field_varint(2, 7));
        let mut msg = Vec::new();
        msg.extend_from_slice(&field_str(1, "top ad"));
        let mut nested_field = varint(2u64 << 3 | 2);
        nested_field.extend_from_slice(&varint(inner.len() as u64));
        nested_field.extend_from_slice(&inner);
        msg.extend_from_slice(&nested_field);
        msg.extend_from_slice(&field_varint(3, 42));

        let rule = body_rule("ad", "x");
        let rules = [&rule];
        let body = frame(&msg);
        let (out, changed) = rewrite_grpc_body(&body, &rules, 4096).unwrap();
        assert!(changed);
        let payload = &out[5..];
        let fields = parse_message(payload).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(decode_str_fields(payload), vec!["top x"]);
        assert_eq!(
            decode_str_fields(fields[1].payload),
            vec!["inner x"],
            "嵌套消息里的字符串也应被改写"
        );
    }

    #[test]
    fn preserves_compressed_frames_and_lengths() {
        let raw = frame(&field_str(1, "ad"));
        let mut body = vec![1u8];
        body.extend_from_slice(&raw[1..]);
        let rule = body_rule("ad", "x");
        let rules = [&rule];
        let (out, changed) = rewrite_grpc_body(&body, &rules, 4096).unwrap();
        assert!(!changed);
        assert_eq!(out, body);
    }

    #[test]
    fn malformed_frame_falls_back() {
        let rule = body_rule("ad", "x");
        let rules = [&rule];
        let bad = vec![0u8, 0, 0, 0, 9, 1];
        assert!(rewrite_grpc_body(&bad, &rules, 4096).is_none());
        let mut body = frame(&field_str(1, "ad"));
        body.truncate(body.len() - 1);
        assert!(rewrite_grpc_body(&body, &rules, 4096).is_none());
    }

    #[test]
    fn multiple_messages_keep_frame_boundaries() {
        let rule = body_rule("ad", "x");
        let rules = [&rule];
        let mut body = frame(&field_str(1, "ad1"));
        body.extend_from_slice(&frame(&field_str(1, "ad2")));
        let (out, changed) = rewrite_grpc_body(&body, &rules, 4096).unwrap();
        assert!(changed);
        assert_eq!(out.len(), 18);
        let mut pos = 0;
        for i in 0..2u8 {
            assert_eq!(out[pos], 0);
            let len = u32::from_be_bytes([out[pos + 1], out[pos + 2], out[pos + 3], out[pos + 4]])
                as usize;
            assert_eq!(
                &out[pos + 5..pos + 5 + len],
                &[10, 2, b'x', b'1' + i],
                "帧边界应保留，字段值应依次改成 x1/x2"
            );
            pos += 5 + len;
        }
        assert_eq!(pos, out.len());
    }

    #[test]
    fn rejects_output_over_limit() {
        let rule = body_rule("ad", "a much longer replacement");
        let rules = [&rule];
        assert!(rewrite_grpc_body(&frame(&field_str(1, "ad")), &rules, 8).is_none());
    }
}
