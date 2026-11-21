//! 五元组 → 归属 UID 映射。
//!
//! Android 的 VpnService 只拿到 TUN 里的 IP 包，内核看不到「这条连接属于哪个 App」。
//! 唯一可靠的来源是系统 socket 表：`/proc/net/tcp`、`/proc/net/tcp6` 的 uid 列。
//! 那张表只能由有 root 的壳进程读取，因此由 Kotlin 侧轮询后整表下发到这里。
//!
//! 设计取舍：
//! - **整表替换**而不是增量合并。socket 表本来就有消失的连接，增量合并会留下幽灵条目，
//!   误判比漏判更危险（会把 B 站流量当成微信放行）。
//! - **不缓存过期时间**。表的新鲜度由壳侧轮询间隔决定，内核只负责按现状匹配；
//!   未知 UID 一律返回 None，让规则层显式处理「不知道」而不是猜一个 0（0 是 root）。

use std::collections::HashMap;
use std::net::IpAddr;

/// (客户端地址, 客户端端口, 目标地址, 目标端口)
pub type FlowKey = (IpAddr, u16, IpAddr, u16);

/// 条目上限。正常设备并发 socket 顶多几百条，8192 已远超；
/// 超出直接截断，避免异常数据把内存顶穿。
pub const MAX_FLOWS: usize = 8192;

#[derive(Default)]
pub struct UidMap {
    /// 精确五元组索引。源地址对得上时优先用它，准确度最高。
    exact: HashMap<FlowKey, u32>,
    /// 退化索引：源端口 + 目标地址 + 目标端口。
    ///
    /// 为什么必须有它：TUN 里看到的源地址是 VPN 接口地址（如 10.10.10.1），
    /// 而 `/proc/net/tcp` 里 App socket 的 local 地址是物理网卡地址（蜂窝 10.x 或
    /// Wi-Fi 192.168.x）。两者天然不一致，只做精确匹配会一条都命中不了。
    /// 源端口由内核分配，同一时刻在同一目标上不会重复，配合目标地址足以定位。
    by_port: HashMap<(u16, IpAddr, u16), u32>,
}

impl UidMap {
    pub fn replace(&mut self, entries: Vec<(FlowKey, u32)>) {
        self.exact.clear();
        self.by_port.clear();
        self.exact.reserve(entries.len().min(MAX_FLOWS));
        self.by_port.reserve(entries.len().min(MAX_FLOWS));
        for (key, uid) in entries.into_iter().take(MAX_FLOWS) {
            self.exact.insert(key, uid);
            self.by_port
                .insert((key.1, key.2, key.3), uid);
        }
    }

    pub fn clear(&mut self) {
        self.exact.clear();
        self.by_port.clear();
    }

    pub fn lookup(&self, key: &FlowKey) -> Option<u32> {
        self.exact.get(key).copied()
    }

    /// 连接判定用的双级查找：精确五元组 → 源端口+目标。
    pub fn lookup_flow(
        &self,
        client_ip: IpAddr,
        client_port: u16,
        server_ip: IpAddr,
        server_port: u16,
    ) -> Option<u32> {
        self.exact
            .get(&(client_ip, client_port, server_ip, server_port))
            .copied()
            .or_else(|| self.by_port.get(&(client_port, server_ip, server_port)).copied())
    }

    pub fn len(&self) -> usize {
        self.exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }

    /// 解析壳侧下发的紧凑数组：
    /// `[["10.10.10.1",54321,"1.2.3.4",443,10200], ...]`
    ///
    /// 单条格式错误只跳过该条并计入 `bad`，不整体失败——一张表里出现
    /// 个别坏行（比如 IPv6 文本不规范）不该让全部 App 规则失效。
    pub fn parse_json(text: &str) -> (Vec<(FlowKey, u32)>, usize) {
        let mut out = Vec::new();
        let mut bad = 0usize;
        let arr: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => return (out, 1),
        };
        let Some(items) = arr.as_array() else {
            return (out, 1);
        };
        for item in items {
            let Some(row) = item.as_array() else {
                bad += 1;
                continue;
            };
            if row.len() != 5 {
                bad += 1;
                continue;
            }
            let lip = row[0].as_str().and_then(|s| s.parse::<IpAddr>().ok());
            let lp = row[1].as_u64().and_then(|n| u16::try_from(n).ok());
            let rip = row[2].as_str().and_then(|s| s.parse::<IpAddr>().ok());
            let rp = row[3].as_u64().and_then(|n| u16::try_from(n).ok());
            let uid = row[4].as_u64().and_then(|n| u32::try_from(n).ok());
            match (lip, lp, rip, rp, uid) {
                (Some(lip), Some(lp), Some(rip), Some(rp), Some(uid)) => {
                    out.push(((lip, lp, rip, rp), uid));
                }
                _ => bad += 1,
            }
        }
        (out, bad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(a: &str, ap: u16, b: &str, bp: u16) -> FlowKey {
        (
            IpAddr::V4(a.parse::<Ipv4Addr>().unwrap()),
            ap,
            IpAddr::V4(b.parse::<Ipv4Addr>().unwrap()),
            bp,
        )
    }

    #[test]
    fn replace_is_whole_table_not_incremental() {
        let mut m = UidMap::default();
        m.replace(vec![
            (key("10.10.10.1", 5001, "1.1.1.1", 443), 10100),
            (key("10.10.10.1", 5002, "2.2.2.2", 443), 10200),
        ]);
        assert_eq!(m.len(), 2);
        // 第二次只带一条：旧条目必须消失，否则关掉的连接会留下幽灵归属。
        m.replace(vec![(key("10.10.10.1", 5001, "1.1.1.1", 443), 10300)]);
        assert_eq!(m.len(), 1);
        assert_eq!(m.lookup(&key("10.10.10.1", 5001, "1.1.1.1", 443)), Some(10300));
        assert_eq!(m.lookup(&key("10.10.10.1", 5002, "2.2.2.2", 443)), None);
    }

    #[test]
    fn unknown_flow_is_none_not_zero() {
        let m = UidMap::default();
        // 0 是 root 的 UID：把未知当成 0 会让「只拦某 App」的规则误伤 root 流量。
        assert_eq!(m.lookup(&key("10.10.10.1", 1, "1.1.1.1", 443)), None);
    }

    #[test]
    fn lookup_flow_falls_back_to_port_when_source_ip_differs() {
        let mut m = UidMap::default();
        // socket 表里源地址是物理网卡，TUN 里看到的是 VPN 地址。
        m.replace(vec![(
            key("192.168.1.20", 54321, "1.2.3.4", 443),
            10200,
        )]);
        // 精确命中
        assert_eq!(
            m.lookup_flow(
                "192.168.1.20".parse().unwrap(),
                54321,
                "1.2.3.4".parse().unwrap(),
                443
            ),
            Some(10200)
        );
        // 源 IP 换成 VPN 地址，仍应命中
        assert_eq!(
            m.lookup_flow(
                "10.10.10.1".parse().unwrap(),
                54321,
                "1.2.3.4".parse().unwrap(),
                443
            ),
            Some(10200)
        );
        // 端口或目标不同则不得误命中
        assert_eq!(
            m.lookup_flow(
                "10.10.10.1".parse().unwrap(),
                54322,
                "1.2.3.4".parse().unwrap(),
                443
            ),
            None
        );
        assert_eq!(
            m.lookup_flow(
                "10.10.10.1".parse().unwrap(),
                54321,
                "5.6.7.8".parse().unwrap(),
                443
            ),
            None
        );
    }

    #[test]
    fn parse_compact_array() {
        let text = r#"[
            ["10.10.10.1",54321,"1.2.3.4",443,10200],
            ["fd00:1::5",5000,"2606:4700::1111",443,10101]
        ]"#;
        let (rows, bad) = UidMap::parse_json(text);
        assert_eq!(bad, 0);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1, 10200);
        assert_eq!(rows[1].1, 10101);
    }

    #[test]
    fn parse_skips_bad_rows_but_keeps_good_ones() {
        let text = r#"[
            ["10.10.10.1",54321,"1.2.3.4",443,10200],
            ["nonsense",1,"1.2.3.4",443,1],
            ["10.10.10.1",70000,"1.2.3.4",443,1],
            ["10.10.10.1",5000,"1.2.3.4",443]
        ]"#;
        let (rows, bad) = UidMap::parse_json(text);
        assert_eq!(rows.len(), 1);
        assert_eq!(bad, 3);
    }

    #[test]
    fn parse_tolerates_malformed_json() {
        let (rows, bad) = UidMap::parse_json("not json");
        assert!(rows.is_empty());
        assert_eq!(bad, 1);
        let (rows2, bad2) = UidMap::parse_json(r#"{"flows":[]}"#);
        assert!(rows2.is_empty());
        assert_eq!(bad2, 1);
    }

    #[test]
    fn replace_caps_at_max_flows() {
        let mut m = UidMap::default();
        let entries: Vec<(FlowKey, u32)> = (0..(MAX_FLOWS + 100))
            .map(|i| (key("10.10.10.1", (i % 60000) as u16, "1.1.1.1", 443), i as u32))
            .collect();
        m.replace(entries);
        assert!(m.len() <= MAX_FLOWS);
    }
}
