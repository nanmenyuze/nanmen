use crate::config::{Config, Node};
use crate::outbound;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// 策略组解析的传输层。TCP 与 UDP 必须分开判断：TCP 探测成功不代表节点的 UDP 可用。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoNodePolicy {
    Global,
    Block,
    Direct,
}

impl NoNodePolicy {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "global" => Some(Self::Global),
            "block" | "reject" => Some(Self::Block),
            "direct" => Some(Self::Direct),
            _ => None,
        }
    }

    pub fn chosen(self, global_block: bool) -> Self {
        match self {
            Self::Global => {
                if global_block {
                    Self::Block
                } else {
                    Self::Direct
                }
            }
            other => other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroupType {
    Select,
    UrlTest,
    Fallback,
}

impl GroupType {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "select" => Some(Self::Select),
            "url-test" | "urltest" => Some(Self::UrlTest),
            "fallback" => Some(Self::Fallback),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct GroupDef {
    name: String,
    kind: GroupType,
    members: Vec<String>,
    test_url: String,
    interval: Duration,
    timeout: Duration,
    tolerance_ms: u64,
    failure_threshold: u32,
    recovery_threshold: u32,
    no_node_action: NoNodePolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupIssue {
    /// 空字符串表示全局问题（例如重复节点名）。
    pub group: String,
    pub code: String,
    pub message: String,
}

impl GroupIssue {
    fn new(group: &str, code: &str, message: String) -> Self {
        Self {
            group: group.to_string(),
            code: code.to_string(),
            message,
        }
    }
}

/// 不可变策略快照。热重载时整体替换；已有连接持有旧的解析结果，不受新快照影响。
#[derive(Debug, Clone, Default)]
pub struct StrategySet {
    groups: Vec<GroupDef>,
    by_name: HashMap<String, usize>,
    node_types: HashMap<String, String>,
    selections: BTreeMap<String, String>,
    issues: Vec<GroupIssue>,
    disabled: HashSet<String>,
    duplicate_nodes: Vec<String>,
}

impl StrategySet {
    pub fn from_config(cfg: &Config) -> Self {
        let mut issues = Vec::new();
        let mut node_types = HashMap::new();
        let mut node_counts: HashMap<String, usize> = HashMap::new();
        for node in &cfg.nodes {
            let name = node.name.trim();
            if name.is_empty() {
                continue;
            }
            *node_counts.entry(name.to_string()).or_insert(0) += 1;
            node_types.insert(name.to_string(), node.kind.clone());
        }
        let duplicate_nodes: Vec<String> = node_counts
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(name, _)| name.clone())
            .collect();
        for name in &duplicate_nodes {
            issues.push(GroupIssue::new(
                "",
                "duplicate_node",
                format!("节点名重复：{}；策略组引用无法唯一解析", name),
            ));
        }

        let mut group_counts: HashMap<String, usize> = HashMap::new();
        for g in &cfg.proxy_groups {
            let name = g.name.trim();
            if !name.is_empty() {
                *group_counts.entry(name.to_string()).or_insert(0) += 1;
            }
        }

        let mut groups = Vec::new();
        let mut by_name = HashMap::new();
        let mut disabled = HashSet::new();
        for raw in &cfg.proxy_groups {
            let name = raw.name.trim().to_string();
            if name.is_empty() {
                issues.push(GroupIssue::new(
                    "",
                    "empty_group_name",
                    "策略组名称为空，已禁用".to_string(),
                ));
                continue;
            }
            let kind = match GroupType::parse(&raw.kind) {
                Some(k) => k,
                None => {
                    issues.push(GroupIssue::new(
                        &name,
                        "unknown_type",
                        format!("未知策略组类型：{}（仅支持 select / url-test / fallback）", raw.kind),
                    ));
                    disabled.insert(name.clone());
                    GroupType::Select
                }
            };
            let no_node_action = match NoNodePolicy::parse(&raw.no_node_action) {
                Some(p) => p,
                None => {
                    issues.push(GroupIssue::new(
                        &name,
                        "bad_no_node_action",
                        format!("未知无可用节点策略：{}（global / block / direct）", raw.no_node_action),
                    ));
                    disabled.insert(name.clone());
                    NoNodePolicy::Global
                }
            };
            let members: Vec<String> = raw
                .members
                .iter()
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty())
                .collect();
            if members.is_empty() {
                issues.push(GroupIssue::new(&name, "empty_group", "策略组没有成员，已禁用".to_string()));
                disabled.insert(name.clone());
            }
            if members.iter().any(|m| m == &name) {
                issues.push(GroupIssue::new(
                    &name,
                    "self_reference",
                    "策略组不能直接引用自身，已禁用".to_string(),
                ));
                disabled.insert(name.clone());
            }
            let mut seen = HashSet::new();
            for m in &members {
                if !seen.insert(m.clone()) {
                    issues.push(GroupIssue::new(
                        &name,
                        "duplicate_member",
                        format!("成员重复：{}", m),
                    ));
                    disabled.insert(name.clone());
                }
            }

            let idx = groups.len();
            if group_counts.get(&name).copied().unwrap_or(0) > 1 {
                disabled.insert(name.clone());
                if !issues.iter().any(|i| i.group == name && i.code == "duplicate_group") {
                    issues.push(GroupIssue::new(
                        &name,
                        "duplicate_group",
                        format!("策略组名重复：{}，引用存在歧义，已禁用", name),
                    ));
                }
            }
            by_name.entry(name.clone()).or_insert(idx);
            groups.push(GroupDef {
                name,
                kind,
                members,
                test_url: if raw.test_url.trim().is_empty() {
                    "http://www.gstatic.com/generate_204".to_string()
                } else {
                    raw.test_url.trim().to_string()
                },
                interval: Duration::from_secs(raw.interval.clamp(5, 86_400)),
                timeout: Duration::from_millis(raw.timeout.clamp(500, 30_000)),
                tolerance_ms: raw.tolerance.min(30_000),
                failure_threshold: raw.failure_threshold.max(1),
                recovery_threshold: raw.recovery_threshold.max(1),
                no_node_action,
            });
        }

        // 引用完整性：成员必须唯一地指向一个节点或一个组。
        for g in &groups {
            for m in &g.members {
                let is_node = node_types.contains_key(m);
                let is_group = by_name.contains_key(m);
                let node_dup = node_counts.get(m).copied().unwrap_or(0) > 1;
                let group_dup = group_counts.get(m).copied().unwrap_or(0) > 1;
                if !is_node && !is_group {
                    issues.push(GroupIssue::new(
                        &g.name,
                        "missing_reference",
                        format!("成员不存在：{}（节点已删除或名称已变更）", m),
                    ));
                    disabled.insert(g.name.clone());
                } else if is_node && is_group {
                    issues.push(GroupIssue::new(
                        &g.name,
                        "ambiguous_member",
                        format!("成员 {} 同时是节点和策略组，引用存在歧义", m),
                    ));
                    disabled.insert(g.name.clone());
                } else if is_node && node_dup {
                    issues.push(GroupIssue::new(
                        &g.name,
                        "duplicate_node_reference",
                        format!("成员 {} 指向重复节点名，无法唯一解析", m),
                    ));
                    disabled.insert(g.name.clone());
                } else if is_group && group_dup {
                    issues.push(GroupIssue::new(
                        &g.name,
                        "duplicate_group_reference",
                        format!("成员 {} 指向重复策略组名，无法唯一解析", m),
                    ));
                    disabled.insert(g.name.clone());
                }
            }
        }

        // 选中状态必须指向当前组成员；节点更新后残留的选择要明确报错，不能静默换节点。
        for (group, selected) in &cfg.group_selections {
            let Some(idx) = by_name.get(group) else {
                continue;
            };
            let g = &groups[*idx];
            let trimmed = selected.trim();
            if !g.members.iter().any(|m| m == trimmed) {
                issues.push(GroupIssue::new(
                    group,
                    "stale_selection",
                    format!("已选成员 {} 不在当前组中（节点更新或配置已变更）", selected),
                ));
                disabled.insert(group.clone());
            }
        }

        // 环检测：DFS 三色标记，环上所有组都禁用。
        let mut color = vec![0u8; groups.len()];
        let mut stack: Vec<usize> = Vec::new();
        let mut reported: HashSet<String> = HashSet::new();
        for i in 0..groups.len() {
            if color[i] == 0 {
                dfs_cycle(i, &groups, &by_name, &mut color, &mut stack, &mut reported, &mut issues, &mut disabled);
            }
        }

        // 依赖传播：引用了已禁用组的组也不能启用。
        let mut changed = true;
        while changed {
            changed = false;
            for g in &groups {
                if disabled.contains(&g.name) {
                    continue;
                }
                if g.members.iter().any(|m| by_name.contains_key(m) && disabled.contains(m)) {
                    disabled.insert(g.name.clone());
                    issues.push(GroupIssue::new(
                        &g.name,
                        "disabled_reference",
                        "成员引用了已禁用的策略组，本组一并禁用".to_string(),
                    ));
                    changed = true;
                }
            }
        }

        Self {
            groups,
            by_name,
            node_types,
            selections: cfg.group_selections.clone(),
            issues,
            disabled,
            duplicate_nodes,
        }
    }

    pub fn issues(&self) -> &[GroupIssue] {
        &self.issues
    }

    pub fn duplicate_nodes(&self) -> &[String] {
        &self.duplicate_nodes
    }

    pub fn has_errors(&self) -> bool {
        !self.disabled.is_empty() || !self.duplicate_nodes.is_empty()
    }

    pub fn is_group(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    pub fn is_usable(&self, name: &str) -> bool {
        self.by_name.contains_key(name) && !self.disabled.contains(name)
    }

    pub fn group_names(&self) -> Vec<String> {
        self.groups.iter().map(|g| g.name.clone()).collect()
    }

    pub fn selection(&self, group: &str) -> Option<&str> {
        self.selections.get(group).map(|s| s.as_str())
    }

    pub fn set_selection(&mut self, group: &str, member: &str) {
        self.selections.insert(group.to_string(), member.to_string());
    }

    /// 解析一个组到最终节点。chain 从顶层组到叶子节点，供规则测试和日志展示。
    pub fn resolve_group(
        &self,
        name: &str,
        transport: Transport,
        health: &HealthRegistry,
    ) -> Result<Resolved, ResolveFailure> {
        let mut visiting = HashSet::new();
        self.resolve_group_inner(name, transport, health, &mut Vec::new(), &mut visiting)
    }

    fn resolve_group_inner(
        &self,
        name: &str,
        transport: Transport,
        health: &HealthRegistry,
        chain: &mut Vec<String>,
        visiting: &mut HashSet<String>,
    ) -> Result<Resolved, ResolveFailure> {
        let Some(idx) = self.by_name.get(name).copied() else {
            return Err(ResolveFailure::new(
                "missing_group",
                format!("策略组不存在：{}", name),
                chain.clone(),
                NoNodePolicy::Global,
            ));
        };
        let group = &self.groups[idx];
        if self.disabled.contains(&group.name) {
            let why = self
                .issues
                .iter()
                .filter(|i| i.group == group.name)
                .map(|i| i.message.clone())
                .collect::<Vec<_>>()
                .join("；");
            return Err(ResolveFailure::new(
                "disabled_group",
                format!("策略组 {} 已禁用：{}", group.name, why),
                chain.clone(),
                group.no_node_action,
            ));
        }
        if !visiting.insert(group.name.clone()) {
            return Err(ResolveFailure::new(
                "cycle",
                format!("策略组嵌套循环：{}", chain.join(" -> ")),
                chain.clone(),
                group.no_node_action,
            ));
        }
        chain.push(group.name.clone());

        let result = match group.kind {
            GroupType::Select => self.resolve_select(group, transport, health, chain, visiting),
            GroupType::Fallback => self.resolve_fallback(group, transport, health, chain, visiting),
            GroupType::UrlTest => self.resolve_url_test(group, transport, health, chain, visiting),
        };
        visiting.remove(&group.name);
        if result.is_err() {
            chain.pop();
        }
        result
    }

    fn resolve_select(
        &self,
        group: &GroupDef,
        transport: Transport,
        health: &HealthRegistry,
        chain: &mut Vec<String>,
        visiting: &mut HashSet<String>,
    ) -> Result<Resolved, ResolveFailure> {
        let chosen = self
            .selections
            .get(&group.name)
            .map(|s| s.trim().to_string())
            .filter(|s| group.members.iter().any(|m| m == s))
            .or_else(|| group.members.first().cloned());
        let Some(member) = chosen else {
            return Err(self.no_member(group, "空组", chain));
        };
        self.resolve_member(
            &group.name,
            &member,
            transport,
            health,
            chain,
            visiting,
            group.failure_threshold,
            group.recovery_threshold,
        )
    }

    fn resolve_fallback(
        &self,
        group: &GroupDef,
        transport: Transport,
        health: &HealthRegistry,
        chain: &mut Vec<String>,
        visiting: &mut HashSet<String>,
    ) -> Result<Resolved, ResolveFailure> {
        let mut last_error: Option<ResolveFailure> = None;
        for member in &group.members {
            let base = chain.len();
            match self.resolve_member(
                &group.name,
                member,
                transport,
                health,
                chain,
                visiting,
                group.failure_threshold,
                group.recovery_threshold,
            ) {
                Ok(resolved) => {
                    if resolved.leaf_available {
                        return Ok(resolved);
                    }
                    chain.truncate(base);
                }
                Err(e) => {
                    chain.truncate(base);
                    last_error = Some(e);
                }
            }
        }
        let reason = last_error
            .map(|e| e.message)
            .unwrap_or_else(|| "没有健康成员".to_string());
        Err(self.no_member(group, &reason, chain))
    }

    fn resolve_url_test(
        &self,
        group: &GroupDef,
        transport: Transport,
        health: &HealthRegistry,
        chain: &mut Vec<String>,
        visiting: &mut HashSet<String>,
    ) -> Result<Resolved, ResolveFailure> {
        let mut candidates: Vec<Resolved> = Vec::new();
        let mut last_error: Option<ResolveFailure> = None;
        for member in &group.members {
            let base = chain.len();
            match self.resolve_member(
                &group.name,
                member,
                transport,
                health,
                chain,
                visiting,
                group.failure_threshold,
                group.recovery_threshold,
            ) {
                Ok(resolved) => {
                    if resolved.leaf_available {
                        candidates.push(resolved);
                    }
                    chain.truncate(base);
                }
                Err(e) => {
                    chain.truncate(base);
                    last_error = Some(e);
                }
            }
        }
        if candidates.is_empty() {
            let reason = last_error
                .map(|e| e.message)
                .unwrap_or_else(|| "没有可测速成员".to_string());
            return Err(self.no_member(group, &reason, chain));
        }
        let best_latency = candidates
            .iter()
            .map(|c| c.latency_ms.unwrap_or(u64::MAX))
            .min()
            .unwrap_or(u64::MAX);
        // 容差内保持当前选择，避免每次探测都在两个相近节点之间来回切。
        if let Some(current) = self.selections.get(&group.name) {
            if let Some(c) = candidates.iter().find(|c| {
                c.node == *current
                    && c.latency_ms.unwrap_or(u64::MAX)
                        <= best_latency.saturating_add(group.tolerance_ms)
            }) {
                return Ok(c.clone());
            }
        }
        Ok(candidates
            .into_iter()
            .min_by_key(|c| c.latency_ms.unwrap_or(u64::MAX))
            .unwrap_or_else(|| Resolved::new(chain.clone(), "", None, transport)))
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_member(
        &self,
        group: &str,
        member: &str,
        transport: Transport,
        health: &HealthRegistry,
        chain: &mut Vec<String>,
        visiting: &mut HashSet<String>,
        failure_threshold: u32,
        recovery_threshold: u32,
    ) -> Result<Resolved, ResolveFailure> {
        if let Some(idx) = self.by_name.get(member).copied() {
            return self.resolve_group_inner(
                &self.groups[idx].name,
                transport,
                health,
                chain,
                visiting,
            );
        }
        let Some(kind) = self.node_types.get(member) else {
            return Err(ResolveFailure::new(
                "missing_reference",
                format!("策略组 {} 引用的成员不存在：{}", group, member),
                chain.clone(),
                NoNodePolicy::Global,
            ));
        };
        if transport == Transport::Udp && !supports_udp(kind) {
            return Err(ResolveFailure::new(
                "udp_unsupported",
                format!("节点 {}（{}）不支持 UDP，不能作为 UDP 策略成员", member, kind),
                chain.clone(),
                NoNodePolicy::Global,
            ));
        }
        // 阈值来自当前组配置；TCP 与 UDP 各自维护健康状态，互不背书。
        let availability = health.availability(member, transport, failure_threshold, recovery_threshold);
        chain.push(member.to_string());
        let latency_ms = health.latency(member, transport);
        Ok(Resolved {
            node: member.to_string(),
            chain: chain.clone(),
            latency_ms,
            transport,
            leaf_available: availability != Availability::Unhealthy,
        })
    }

    fn no_member(&self, group: &GroupDef, reason: &str, chain: &[String]) -> ResolveFailure {
        ResolveFailure::new(
            "no_available_member",
            format!("策略组 {} 没有可用成员：{}", group.name, reason),
            chain.to_vec(),
            group.no_node_action,
        )
    }

    /// 健康检查目标：仅 url-test / fallback 需要主动探测；select 不做自动切换。
    pub fn health_targets(&self) -> Vec<HealthTarget> {
        self.groups
            .iter()
            .filter(|g| !self.disabled.contains(&g.name))
            .filter(|g| matches!(g.kind, GroupType::UrlTest | GroupType::Fallback))
            .map(|g| HealthTarget {
                group: g.name.clone(),
                test_url: g.test_url.clone(),
                interval: g.interval,
                timeout: g.timeout,
                failure_threshold: g.failure_threshold,
                recovery_threshold: g.recovery_threshold,
            })
            .collect()
    }

    /// 一个组可达的所有叶子节点（嵌套组会展开，去重）。
    pub fn leaf_nodes(&self, group: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen_groups = HashSet::new();
        self.collect_leaves(group, &mut out, &mut seen_groups);
        out
    }

    fn collect_leaves(&self, name: &str, out: &mut Vec<String>, seen: &mut HashSet<String>) {
        let Some(idx) = self.by_name.get(name).copied() else { return };
        if !seen.insert(name.to_string()) {
            return;
        }
        let g = &self.groups[idx];
        for m in &g.members {
            if self.by_name.contains_key(m) {
                self.collect_leaves(m, out, seen);
            } else if self.node_types.contains_key(m) && !out.iter().any(|x| x == m) {
                out.push(m.clone());
            }
        }
    }
}

fn dfs_cycle(
    idx: usize,
    groups: &[GroupDef],
    by_name: &HashMap<String, usize>,
    color: &mut [u8],
    stack: &mut Vec<usize>,
    reported: &mut HashSet<String>,
    issues: &mut Vec<GroupIssue>,
    disabled: &mut HashSet<String>,
) {
    color[idx] = 1;
    stack.push(idx);
    for member in &groups[idx].members {
        let Some(next) = by_name.get(member).copied() else { continue };
        if color[next] == 1 {
            if let Some(pos) = stack.iter().position(|i| *i == next) {
                let path: Vec<String> = stack[pos..]
                    .iter()
                    .map(|i| groups[*i].name.clone())
                    .chain(std::iter::once(groups[next].name.clone()))
                    .collect();
                let key = path.join("\u{0}");
                if reported.insert(key) {
                    for i in &stack[pos..] {
                        disabled.insert(groups[*i].name.clone());
                    }
                    disabled.insert(groups[next].name.clone());
                    issues.push(GroupIssue::new(
                        &groups[next].name,
                        "cycle",
                        format!("策略组嵌套循环不能启用：{}", path.join(" -> ")),
                    ));
                }
            }
        } else if color[next] == 0 {
            dfs_cycle(next, groups, by_name, color, stack, reported, issues, disabled);
        }
    }
    stack.pop();
    color[idx] = 2;
}

fn supports_udp(kind: &str) -> bool {
    matches!(kind, "ss" | "socks5")
}

#[derive(Clone, Debug)]
pub struct Resolved {
    pub node: String,
    /// 顶层组 ... 叶子节点；select 组也包含组名。
    pub chain: Vec<String>,
    pub latency_ms: Option<u64>,
    pub transport: Transport,
    pub leaf_available: bool,
}

impl Resolved {
    fn new(chain: Vec<String>, node: &str, latency_ms: Option<u64>, transport: Transport) -> Self {
        let mut chain = chain;
        if !node.is_empty() {
            chain.push(node.to_string());
        }
        Self {
            node: node.to_string(),
            chain,
            latency_ms,
            transport,
            leaf_available: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolveFailure {
    pub code: String,
    pub message: String,
    pub chain: Vec<String>,
    pub policy: NoNodePolicy,
}

impl ResolveFailure {
    fn new(code: &str, message: String, chain: Vec<String>, policy: NoNodePolicy) -> Self {
        Self {
            code: code.to_string(),
            message,
            chain,
            policy,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Unknown,
    Healthy,
    Unhealthy,
}

#[derive(Clone, Debug, Default)]
pub struct NodeHealth {
    pub tcp: TransportHealth,
    pub udp: TransportHealth,
}

#[derive(Clone, Debug, Default)]
pub struct TransportHealth {
    /// None = 尚未探测；true/false = 已达到恢复/失败阈值后的稳定状态。
    pub healthy: Option<bool>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub latency_ms: Option<u64>,
    pub last_check_ms: u64,
}

#[derive(Default)]
pub struct HealthRegistry {
    inner: RwLock<HashMap<String, NodeHealth>>,
}

impl HealthRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &self,
        node: &str,
        transport: Transport,
        ok: bool,
        latency_ms: Option<u64>,
        failure_threshold: u32,
        recovery_threshold: u32,
        now_ms: u64,
    ) {
        let mut guard = self.inner.write().unwrap_or_else(|p| p.into_inner());
        let entry = guard.entry(node.to_string()).or_default();
        let state = match transport {
            Transport::Tcp => &mut entry.tcp,
            Transport::Udp => &mut entry.udp,
        };
        state.last_check_ms = now_ms;
        if ok {
            state.consecutive_successes = state.consecutive_successes.saturating_add(1);
            state.consecutive_failures = 0;
            if latency_ms.is_some() {
                state.latency_ms = latency_ms;
            }
            if state.healthy != Some(true)
                && state.consecutive_successes >= recovery_threshold.max(1)
            {
                state.healthy = Some(true);
            }
        } else {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.consecutive_successes = 0;
            if state.healthy != Some(false)
                && state.consecutive_failures >= failure_threshold.max(1)
            {
                state.healthy = Some(false);
            }
        }
    }

    pub fn availability_with_defaults(&self, node: &str, transport: Transport) -> Availability {
        self.availability(node, transport, 3, 2)
    }

    pub fn availability(
        &self,
        node: &str,
        transport: Transport,
        failure_threshold: u32,
        recovery_threshold: u32,
    ) -> Availability {
        let guard = self.inner.read().unwrap_or_else(|p| p.into_inner());
        let Some(h) = guard.get(node) else {
            return Availability::Unknown;
        };
        let s = match transport {
            Transport::Tcp => &h.tcp,
            Transport::Udp => &h.udp,
        };
        match s.healthy {
            Some(true) => Availability::Healthy,
            Some(false) => {
                // 已达到恢复阈值后 health 会变 true；这里保持 false。
                let _ = recovery_threshold;
                Availability::Unhealthy
            }
            None => {
                if s.consecutive_failures >= failure_threshold.max(1) {
                    Availability::Unhealthy
                } else {
                    Availability::Unknown
                }
            }
        }
    }

    pub fn latency(&self, node: &str, transport: Transport) -> Option<u64> {
        let guard = self.inner.read().unwrap_or_else(|p| p.into_inner());
        let h = guard.get(node)?;
        match transport {
            Transport::Tcp => h.tcp.latency_ms,
            Transport::Udp => h.udp.latency_ms,
        }
    }

    pub fn snapshot(&self) -> HashMap<String, NodeHealth> {
        self.inner.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

#[derive(Clone, Debug)]
pub struct HealthTarget {
    pub group: String,
    pub test_url: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
}

/// 后台健康检查。仅探测 url-test / fallback 的叶子节点；select 不做自动切换。
/// 探测走真实节点到测速 URL 的 TCP/HTTP 路径，结果只写入 TCP 健康状态，
/// 绝不把 TCP 结果写入 UDP，避免「TCP 通就宣称 UDP 可用」。
pub async fn run_health_loop(
    shutdown: Arc<AtomicBool>,
    strategy: Arc<RwLock<Arc<StrategySet>>>,
    nodes: Arc<RwLock<Arc<Vec<Node>>>>,
    health: Arc<HealthRegistry>,
) {
    let mut last_run: HashMap<String, Instant> = HashMap::new();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let set = strategy.read().unwrap_or_else(|p| p.into_inner()).clone();
        let node_list = nodes.read().unwrap_or_else(|p| p.into_inner()).clone();
        for target in set.health_targets() {
            let due = last_run
                .get(&target.group)
                .map(|t| t.elapsed() >= target.interval)
                .unwrap_or(true);
            if !due {
                continue;
            }
            last_run.insert(target.group.clone(), Instant::now());
            let leaves = set.leaf_nodes(&target.group);
            if leaves.is_empty() {
                continue;
            }
            let nodes_for_group = node_list.clone();
            let health_for_group = health.clone();
            let target_for_group = target.clone();
            tokio::spawn(async move {
                for name in leaves {
                    let Some(node) = nodes_for_group.iter().find(|n| n.name == name).cloned() else {
                        continue;
                    };
                    let started = Instant::now();
                    let ok = outbound::probe_node(&node, &target_for_group.test_url, target_for_group.timeout).await.is_ok();
                    let latency = if ok { Some(started.elapsed().as_millis() as u64) } else { None };
                    health_for_group.record(
                        &name,
                        Transport::Tcp,
                        ok,
                        latency,
                        target_for_group.failure_threshold,
                        target_for_group.recovery_threshold,
                        crate::stats::now_ms(),
                    );
                    if !ok {
                        crate::logging::warn(
                            "strategy",
                            format!(
                                "策略组 {} 健康检查失败：{}（{}）",
                                target_for_group.group, name, target_for_group.test_url
                            ),
                        );
                    }
                }
            });
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyGroup, RuleConf};
    use crate::engine::{Action, ConnKind, RuleEngine};
    use serde_json::json;

    fn node(name: &str, kind: &str) -> Node {
        serde_json::from_value(json!({
            "name": name,
            "type": kind,
            "server": "127.0.0.1",
            "port": 1080,
            "password": "x"
        }))
        .unwrap()
    }

    fn group(name: &str, kind: &str, members: &[&str]) -> ProxyGroup {
        ProxyGroup {
            name: name.into(),
            kind: kind.into(),
            members: members.iter().map(|m| m.to_string()).collect(),
            ..Default::default()
        }
    }

    fn config(nodes: Vec<Node>, groups: Vec<ProxyGroup>, selections: &[(&str, &str)]) -> Config {
        let mut cfg = Config::default();
        cfg.nodes = nodes;
        cfg.proxy_groups = groups;
        cfg.group_selections = selections
            .iter()
            .map(|(g, m)| (g.to_string(), m.to_string()))
            .collect();
        cfg
    }

    fn health_ok(health: &HealthRegistry, name: &str, latency: u64, ft: u32, rt: u32) {
        health.record(name, Transport::Tcp, true, Some(latency), ft, rt, 1);
    }

    fn health_fail(health: &HealthRegistry, name: &str, times: u32, ft: u32, rt: u32) {
        for i in 0..times {
            health.record(name, Transport::Tcp, false, None, ft, rt, i as u64 + 1);
        }
    }

    #[test]
    fn select_group_uses_persisted_selection() {
        let cfg = config(
            vec![node("n1", "ss"), node("n2", "ss")],
            vec![group("G", "select", &["n1", "n2"])],
            &[("G", "n2")],
        );
        let set = StrategySet::from_config(&cfg);
        let h = HealthRegistry::new();
        let r = set.resolve_group("G", Transport::Tcp, &h).unwrap();
        assert_eq!(r.node, "n2");
        assert_eq!(r.chain, vec!["G", "n2"]);
    }

    #[test]
    fn select_group_without_selection_uses_first_member() {
        let cfg = config(
            vec![node("n1", "ss"), node("n2", "ss")],
            vec![group("G", "select", &["n1", "n2"])],
            &[],
        );
        let set = StrategySet::from_config(&cfg);
        let r = set.resolve_group("G", Transport::Tcp, &HealthRegistry::new()).unwrap();
        assert_eq!(r.node, "n1");
    }

    #[test]
    fn fallback_switches_after_failure_threshold_and_recovers() {
        let mut g = group("F", "fallback", &["n1", "n2"]);
        g.failure_threshold = 2;
        g.recovery_threshold = 2;
        let cfg = config(vec![node("n1", "ss"), node("n2", "ss")], vec![g], &[]);
        let set = StrategySet::from_config(&cfg);
        let h = HealthRegistry::new();

        assert_eq!(set.resolve_group("F", Transport::Tcp, &h).unwrap().node, "n1");
        health_fail(&h, "n1", 1, 2, 2);
        assert_eq!(set.resolve_group("F", Transport::Tcp, &h).unwrap().node, "n1");
        health_fail(&h, "n1", 1, 2, 2);
        assert_eq!(set.resolve_group("F", Transport::Tcp, &h).unwrap().node, "n2");

        health_ok(&h, "n1", 1, 2, 2);
        assert_eq!(set.resolve_group("F", Transport::Tcp, &h).unwrap().node, "n2");
        health_ok(&h, "n1", 1, 2, 2);
        assert_eq!(set.resolve_group("F", Transport::Tcp, &h).unwrap().node, "n1");
    }

    #[test]
    fn url_test_picks_lowest_latency_and_respects_tolerance() {
        let mut g = group("U", "url-test", &["n1", "n2"]);
        g.tolerance = 50;
        let cfg = config(
            vec![node("n1", "ss"), node("n2", "ss")],
            vec![g.clone(), group("V", "url-test", &["n1", "n2"])],
            &[("U", "n1")],
        );
        let set = StrategySet::from_config(&cfg);
        let h = HealthRegistry::new();
        health_ok(&h, "n1", 100, 1, 1);
        health_ok(&h, "n2", 80, 1, 1);
        // U 保留当前选择：100 <= 80 + 50。
        assert_eq!(set.resolve_group("U", Transport::Tcp, &h).unwrap().node, "n1");
        // V 没有当前选择，选最低延迟。
        assert_eq!(set.resolve_group("V", Transport::Tcp, &h).unwrap().node, "n2");
    }

    #[test]
    fn udp_never_uses_tcp_probe_or_trojan_node() {
        let cfg = config(
            vec![node("tj", "trojan"), node("ss", "ss")],
            vec![group("F", "fallback", &["tj", "ss"])],
            &[],
        );
        let set = StrategySet::from_config(&cfg);
        let h = HealthRegistry::new();
        health_ok(&h, "tj", 1, 1, 1);
        // TCP 仍可以走 trojan 的首选。
        assert_eq!(set.resolve_group("F", Transport::Tcp, &h).unwrap().node, "tj");
        // UDP 必须跳过不支持 UDP 的 trojan，不能拿 TCP 健康当 UDP 可用。
        assert_eq!(set.resolve_group("F", Transport::Udp, &h).unwrap().node, "ss");

        let only_tj = config(
            vec![node("tj", "trojan")],
            vec![group("F", "fallback", &["tj"])],
            &[],
        );
        let set = StrategySet::from_config(&only_tj);
        let err = set.resolve_group("F", Transport::Udp, &HealthRegistry::new()).unwrap_err();
        assert_eq!(err.code, "no_available_member");
        assert!(err.message.contains("不支持 UDP"));
    }

    #[test]
    fn nested_groups_resolve_through_chain() {
        let cfg = config(
            vec![node("n1", "ss")],
            vec![
                group("inner", "select", &["n1"]),
                group("outer", "select", &["inner"]),
            ],
            &[],
        );
        let set = StrategySet::from_config(&cfg);
        let r = set.resolve_group("outer", Transport::Tcp, &HealthRegistry::new()).unwrap();
        assert_eq!(r.chain, vec!["outer", "inner", "n1"]);
    }

    #[test]
    fn cycle_is_reported_and_cannot_be_enabled() {
        let cfg = config(
            vec![node("n1", "ss")],
            vec![
                group("A", "select", &["B"]),
                group("B", "select", &["A"]),
            ],
            &[],
        );
        let set = StrategySet::from_config(&cfg);
        assert!(!set.is_usable("A"));
        assert!(!set.is_usable("B"));
        assert!(set.issues().iter().any(|i| i.code == "cycle"));
        assert_eq!(
            set.resolve_group("A", Transport::Tcp, &HealthRegistry::new())
                .unwrap_err()
                .code,
            "disabled_group"
        );
    }

    #[test]
    fn empty_group_missing_reference_and_duplicate_node_are_detected() {
        let cfg = config(
            vec![node("n1", "ss"), node("n1", "ss")],
            vec![
                group("empty", "select", &[]),
                group("missing", "select", &["ghost"]),
                group("dup", "select", &["n1"]),
            ],
            &[],
        );
        let set = StrategySet::from_config(&cfg);
        assert!(set.issues().iter().any(|i| i.code == "empty_group"));
        assert!(set.issues().iter().any(|i| i.code == "missing_reference"));
        assert!(set.issues().iter().any(|i| i.code == "duplicate_node"));
        assert!(set.issues().iter().any(|i| i.code == "duplicate_node_reference"));
        assert!(!set.is_usable("dup"));
    }

    #[test]
    fn stale_selection_is_explicit_error() {
        let cfg = config(
            vec![node("n1", "ss")],
            vec![group("G", "select", &["n1"])],
            &[("G", "removed-node")],
        );
        let set = StrategySet::from_config(&cfg);
        assert!(!set.is_usable("G"));
        assert!(set.issues().iter().any(|i| i.code == "stale_selection"));
    }

    #[test]
    fn two_rules_can_hit_two_independent_groups() {
        let mut cfg = config(
            vec![node("n1", "ss"), node("n2", "ss")],
            vec![
                group("组A", "select", &["n1"]),
                group("组B", "select", &["n2"]),
            ],
            &[],
        );
        cfg.rules = vec![
            RuleConf {
                kind: "DOMAIN".into(),
                value: "a.example".into(),
                action: "组A".into(),
                source: Some("测试".into()),
            },
            RuleConf {
                kind: "DOMAIN".into(),
                value: "b.example".into(),
                action: "组B".into(),
                source: Some("测试".into()),
            },
        ];
        let engine = RuleEngine::from_config(&cfg);
        let set = StrategySet::from_config(&cfg);
        let h = HealthRegistry::new();
        let (a, _) = engine.decide_detail(Some("a.example"), std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 443, ConnKind::Tcp);
        let (b, _) = engine.decide_detail(Some("b.example"), std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 443, ConnKind::Tcp);
        assert_eq!(a, Action::Group("组A".into()));
        assert_eq!(b, Action::Group("组B".into()));
        assert_eq!(set.resolve_group("组A", Transport::Tcp, &h).unwrap().node, "n1");
        assert_eq!(set.resolve_group("组B", Transport::Tcp, &h).unwrap().node, "n2");
    }
}
