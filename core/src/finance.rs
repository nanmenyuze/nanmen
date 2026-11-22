//! 金融连接保护：支付、银行、账号安全类连接永不进入 MITM。
//!
//! 为什么不能依赖「这些 App 有证书固定」：证书固定不会让流量自动绕过 MITM，
//! 只会让被劫持的连接校验失败——表现为断开、重试、转圈甚至闪退。
//! 因此必须在劫持判定之前显式排除，且排除优先级高于一切域名命中。
//!
//! 判定顺序（命中任一即排除）：
//! 1. UID 命中金融整包清单（银行/证券/云闪付等独立 App）；
//! 2. 域名命中内置/配置的硬排除后缀（全局生效，不限 App）；
//! 3. UID 命中混合 App（微信/支付宝/QQ）且域名分词含金融关键字；
//! 4. `allow_hosts` 只能豁免第 3 条关键字启发，不能覆盖前两条——防止误把支付域名加回来。
//!
//! 无域名（SNI 与反向映射都未知）时调用方本来就不会 MITM，这里不重复处理。

use std::collections::HashSet;

/// 内置金融域名硬排除后缀。
///
/// 只收「支付/商户网关/账号安全」用途明确的域名，不做整域排除：
/// 整域排除会把微信、支付宝里的内容与广告接口也一起放掉，失去改写空间。
/// 清单允许不全——混合 App 的关键字启发和整包 UID 排除在后面兜底。
pub const BUILTIN_HOSTS: &[&str] = &[
    // 微信支付 / 财付通
    "tenpay.com",
    "pay.weixin.qq.com",
    "payapp.weixin.qq.com",
    "mch.weixin.qq.com",
    "pay.qq.com",
    // 微信支付新版网关（支付 DNS/收银台走 *.wechatpay.cn / *.wechatpay.com）
    "wechatpay.cn",
    "wechatpay.com",
    // 支付宝：支付、商户网关、账号
    "openapi.alipay.com",
    "mapi.alipay.com",
    "mobilegw.alipay.com",
    "mclient.alipay.com",
    "cashier.alipay.com",
    "pay.alipay.com",
    "passport.alipay.com",
    "login.alipay.com",
    "auth.alipay.com",
    // 云闪付 / 银联
    "unionpay.com",
    "95516.com",
];

/// 混合 App 内域名分词命中即排除的关键字。
/// 按 `.`、`-`、`/` 之外还以 `_` 切分后整词比较，避免 `author` 误中 `auth`、
/// `payload` 误中 `pay` 这类子串误判。
pub const FINANCE_KEYWORDS: &[&str] = &[
    "pay", "payment", "cashier", "trade", "trading", "finance", "bank", "banking",
    "passport", "login", "auth", "security", "wallet", "fund", "invest", "loan",
];

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FinanceConf {
    /// 总开关，默认开启。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 整包排除的 UID（银行、证券、云闪付等独立金融 App）。
    #[serde(default)]
    pub uids: Vec<u32>,
    /// 混合 App 的 UID（微信、支付宝、QQ）：整包不排除，仅关键字启发。
    #[serde(default)]
    pub mixed_uids: Vec<u32>,
    /// 追加的硬排除域名后缀，与内置清单合并。
    #[serde(default)]
    pub hosts: Vec<String>,
    /// 混合 App 的关键字启发开关，默认开启。
    #[serde(default = "default_true")]
    pub keyword_skip: bool,
    /// 用户自定义硬排除（等价于追加 hosts）。
    #[serde(default)]
    pub extra_hosts: Vec<String>,
    /// 用户自定义放行：只豁免关键字启发，不能覆盖整包 UID 与硬排除。
    #[serde(default)]
    pub allow_hosts: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for FinanceConf {
    fn default() -> Self {
        Self {
            enabled: true,
            uids: Vec::new(),
            mixed_uids: Vec::new(),
            hosts: Vec::new(),
            keyword_skip: true,
            extra_hosts: Vec::new(),
            allow_hosts: Vec::new(),
        }
    }
}

pub struct FinanceProtect {
    enabled: bool,
    keyword_skip: bool,
    uids: HashSet<u32>,
    mixed_uids: HashSet<u32>,
    blocked: Vec<String>,
    allowed: Vec<String>,
}

/// 归一化成后缀匹配形式：小写、去首尾空白、去结尾点、去 `*.` 前缀。
fn normalize(pattern: &str) -> Option<String> {
    let mut p = pattern.trim().to_ascii_lowercase();
    while let Some(rest) = p.strip_suffix('.') {
        p = rest.to_string();
    }
    if let Some(rest) = p.strip_prefix("*.") {
        p = rest.to_string();
    }
    if p.is_empty() {
        None
    } else {
        Some(p)
    }
}

fn suffix_matches(patterns: &[String], host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    patterns.iter().any(|p| h == *p || h.ends_with(&format!(".{}", p)))
}

/// 域名分词：点、横线、下划线都视为分隔，整词命中关键字才算。
fn has_finance_keyword(host: &str) -> bool {
    host.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .any(|t| FINANCE_KEYWORDS.contains(&t))
}

impl FinanceProtect {
    pub fn from_config(cfg: &FinanceConf) -> Self {
        let mut blocked: Vec<String> = BUILTIN_HOSTS.iter().filter_map(|s| normalize(s)).collect();
        for p in cfg.hosts.iter().chain(cfg.extra_hosts.iter()) {
            if let Some(n) = normalize(p) {
                if !blocked.contains(&n) {
                    blocked.push(n);
                }
            }
        }
        Self {
            enabled: cfg.enabled,
            keyword_skip: cfg.keyword_skip,
            uids: cfg.uids.iter().copied().collect(),
            mixed_uids: cfg.mixed_uids.iter().copied().collect(),
            blocked,
            allowed: cfg.allow_hosts.iter().filter_map(|s| normalize(s)).collect(),
        }
    }

    /// 返回排除原因；None 表示可以正常参与 MITM 判定。
    pub fn bypass_reason(&self, uid: Option<u32>, host: Option<&str>) -> Option<&'static str> {
        if !self.enabled {
            return None;
        }
        if let Some(u) = uid {
            if self.uids.contains(&u) {
                return Some("金融App整包排除");
            }
        }
        let h = host?;
        if suffix_matches(&self.blocked, h) {
            return Some("金融域名硬排除");
        }
        if self.keyword_skip {
            if let Some(u) = uid {
                if self.mixed_uids.contains(&u)
                    && has_finance_keyword(h)
                    && !suffix_matches(&self.allowed, h)
                {
                    return Some("金融关键字排除");
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protect() -> FinanceProtect {
        FinanceProtect::from_config(&FinanceConf {
            uids: vec![10123],
            mixed_uids: vec![10234],
            ..Default::default()
        })
    }

    #[test]
    fn finance_uid_is_fully_excluded() {
        let p = protect();
        assert_eq!(
            p.bypass_reason(Some(10123), Some("ads.example.com")),
            Some("金融App整包排除")
        );
        // 整包排除与域名无关，甚至没有域名也排除。
        assert_eq!(p.bypass_reason(Some(10123), None), Some("金融App整包排除"));
        assert_eq!(p.bypass_reason(Some(10123), Some("mp.weixin.qq.com")), Some("金融App整包排除"));
    }

    #[test]
    fn builtin_payment_domains_blocked_for_any_app() {
        let p = protect();
        for h in [
            "pay.weixin.qq.com",
            "api.mch.weixin.qq.com",
            "wx.tenpay.com",
            "openapi.alipay.com",
            "cashier.alipay.com",
        ] {
            assert_eq!(p.bypass_reason(Some(9999), Some(h)), Some("金融域名硬排除"), "{}", h);
        }
        // 大小写与结尾点不影响判定。
        assert_eq!(p.bypass_reason(None, Some("PAY.Weixin.QQ.com.")), Some("金融域名硬排除"));
    }

    #[test]
    fn mini_program_domains_stay_mitmable() {
        let p = protect();
        // 小程序第三方业务域名：既不在硬排除，也无金融关键字。
        assert_eq!(p.bypass_reason(Some(10234), Some("api.shop-example.com")), None);
        // 公众号等内容域名不受影响。
        assert_eq!(p.bypass_reason(Some(10234), Some("mp.weixin.qq.com")), None);
    }

    #[test]
    fn keyword_only_applies_to_mixed_apps() {
        let p = protect();
        assert_eq!(
            p.bypass_reason(Some(10234), Some("login.weixin.qq.com")),
            Some("金融关键字排除")
        );
        // 同样域名在普通 App 上不做关键字排除，避免误伤正常改写。
        assert_eq!(p.bypass_reason(Some(9999), Some("login.weixin.qq.com")), None);
        // 子串不算命中：author 不是 auth，payload 不是 pay。
        assert_eq!(p.bypass_reason(Some(10234), Some("author.example.com")), None);
        assert_eq!(p.bypass_reason(Some(10234), Some("payload.example.com")), None);
    }

    #[test]
    fn allow_list_only_overrides_keyword() {
        let p = FinanceProtect::from_config(&FinanceConf {
            mixed_uids: vec![10234],
            uids: vec![10123],
            allow_hosts: vec!["login.weixin.qq.com".into()],
            ..Default::default()
        });
        assert_eq!(p.bypass_reason(Some(10234), Some("login.weixin.qq.com")), None);
        // 但不能放行硬排除域名，也不能放行整包 UID。
        assert_eq!(p.bypass_reason(Some(10234), Some("pay.weixin.qq.com")), Some("金融域名硬排除"));
        assert_eq!(p.bypass_reason(Some(10123), Some("login.weixin.qq.com")), Some("金融App整包排除"));
    }

    #[test]
    fn disabled_means_no_bypass() {
        let p = FinanceProtect::from_config(&FinanceConf {
            enabled: false,
            uids: vec![10123],
            ..Default::default()
        });
        assert_eq!(p.bypass_reason(Some(10123), Some("pay.weixin.qq.com")), None);
    }
}
