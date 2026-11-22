use crate::config::{Config, Node};
use crate::outbound;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    LoadBalance,
}

impl GroupType {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "select" => Some(Self::Select),
            "url-test" | "urltest" => Some(Self::UrlTest),
            "fallback" => Some(Self::Fallback),
            "load-balance" | "loadbalance" | "balance" => Some(Self::LoadBalance),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::UrlTest => "url-test",
            Self::Fallback => "fallback",
            Self::LoadBalance => "load-balance",
        }
    }
}

/// load-balance 的选路方式。默认一致性哈希，只有显式配置 round-robin 才轮询。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LbMode {
    ConsistentHash,
    RoundRobin,
}

impl LbMode {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "" | "consistent" | "consistent-hash" | "consistent-hashing" | "hash" => {
                Some(Self::ConsistentHash)
            }
            "round-robin" | "roundrobin" | "rr" | "polling" => Some(Self::RoundRobin),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ConsistentHash => "consistent-hash",
            Self::RoundRobin => "round-robin",
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
    lb_mode: LbMode,
    /// 自动切换最短间隔；当前节点不可用时不受此限。
    switch_interval: Duration,
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

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

fn default_clock() -> Clock {
    Arc::new(Instant::now)
}

/// 策略组的可变运行时状态。快照本身保持不可变，这里只放会随解析变化的小状态：
/// 上次切换时间、当前自动命中、load-balance 轮询计数。
struct GroupState {
    clock: Clock,
    last_switch: RwLock<Instant>,
    current: RwLock<Option<String>>,
    rr: AtomicUsize,
}

impl GroupState {
    fn new(clock: Clock) -> Self {
        let now = clock();
        let last_switch = now.checked_sub(Duration::from_secs(3_600)).unwrap_or(now);
        Self {
            clock,
            last_switch: RwLock::new(last_switch),
            current: RwLock::new(None),
            rr: AtomicUsize::new(0),
        }
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    fn current(&self) -> Option<String> {
        self.current
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn switch_allowed(&self, interval: Duration) -> bool {
        let last = *self.last_switch.read().unwrap_or_else(|p| p.into_inner());
        self.now().duration_since(last) >= interval
    }

    fn set_current(&self, member: &str) {
        *self.current.write().unwrap_or_else(|p| p.into_inner()) = Some(member.to_string());
    }

    fn mark_switch(&self, member: &str) {
        *self.last_switch.write().unwrap_or_else(|p| p.into_inner()) = self.now();
        *self.current.write().unwrap_or_else(|p| p.into_inner()) = Some(member.to_string());
    }

    fn next_rr(&self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            self.rr.fetch_add(1, Ordering::Relaxed) % len
        }
    }
}

/// 不可变策略快照。热重载时整体替换；已有连接持有旧的解析结果，不受新快照影响。
#[derive(Clone)]
pub struct StrategySet {
    groups: Vec<GroupDef>,
    by_name: HashMap<String, usize>,
    node_types: HashMap<String, String>,
    /// 节点是否真的能转发 UDP（协议能力 + 节点级 udp 开关）。
    /// 策略组按 UDP 解析时只认这张表，不能拿 TCP 探测成功来背书。
    node_udp: HashMap<String, bool>,
    selections: BTreeMap<String, String>,
    issues: Vec<GroupIssue>,
    disabled: HashSet<String>,
    duplicate_nodes: Vec<String>,
    states: HashMap<String, Arc<GroupState>>,
}

impl Default for StrategySet {
    fn default() -> Self {
        Self {
            groups: Vec::new(),
            by_name: HashMap::new(),
            node_types: HashMap::new(),
            node_udp: HashMap::new(),
            selections: BTreeMap::new(),
            issues: Vec::new(),
            disabled: HashSet::new(),
            duplicate_nodes: Vec::new(),
            states: HashMap::new(),
        }
    }
}

impl std::fmt::Debug for StrategySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrategySet")
            .field("groups", &self.groups)
            .field("selections", &self.selections)
            .field("issues", &self.issues)
            .field("disabled", &self.disabled)
            .field("duplicate_nodes", &self.duplicate_nodes)
            .finish()
    }
}

impl StrategySet {
    pub fn from_config(cfg: &Config) -> Self {
        Self::from_config_with_clock(cfg, default_clock())
    }

    /// 测试可注入时钟；生产走 [`from_config`]。
    pub fn from_config_with_clock(cfg: &Config, clock: Clock) -> Self {
        let mut issues = Vec::new();
        let mut node_types = HashMap::new();
        let mut node_udp = HashMap::new();
        let mut node_counts: HashMap<String, usize> = HashMap::new();
        for node in &cfg.nodes {
            let name = node.name.trim();
            if name.is_empty() {
                continue;
            }
            *node_counts.entry(name.to_string()).or_insert(0) += 1;
            node_types.insert(name.to_string(), node.kind.clone());
            node_udp.insert(name.to_string(), node.udp_supported());
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
                        format!(
                            "未知策略组类型：{}（支持 select / url-test / fallback / load-balance）",
                            raw.kind
                        ),
                    ));
                    disabled.insert(name.clone());
                    GroupType::Select
                }
            };
            let lb_mode = if kind == GroupType::LoadBalance {
                match LbMode::parse(&raw.lb_mode) {
                    Some(m) => m,
                    None => {
                        issues.push(GroupIssue::new(
                            &name,
                            "bad_lb_mode",
                            format!(
                                "未知 load-balance 选路方式：{}（consistent-hash / round-robin）",
                                raw.lb_mode
                            ),
                        ));
                        disabled.insert(name.clone());
                        LbMode::ConsistentHash
                    }
                }
            } else {
                LbMode::ConsistentHash
            };
            let no_node_action = match NoNodePolicy::parse(&raw.no_node_action) {
                Some(p) => p,
                None => {
                    issues.push(GroupIssue::new(
                        &name,
                        "bad_no_node_action",
                        format!(
                            "未知无可用节点策略：{}（global / block / direct）",
                            raw.no_node_action
                        ),
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
                issues.push(GroupIssue::new(
                    &name,
                    "empty_group",
                    "策略组没有成员，已禁用".to_string(),
                ));
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
                if !issues
                    .iter()
                    .any(|i| i.group == name && i.code == "duplicate_group")
                {
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
                lb_mode,
                switch_interval: Duration::from_secs(raw.switch_interval.clamp(1, 86_400)),
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
                dfs_cycle(
                    i,
                    &groups,
                    &by_name,
                    &mut color,
                    &mut stack,
                    &mut reported,
                    &mut issues,
                    &mut disabled,
                );
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
                if g.members
                    .iter()
                    .any(|m| by_name.contains_key(m) && disabled.contains(m))
                {
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

        let mut states: HashMap<String, Arc<GroupState>> = HashMap::new();
        for g in &groups {
            states
                .entry(g.name.clone())
                .or_insert_with(|| Arc::new(GroupState::new(clock.clone())));
        }

        Self {
            groups,
            by_name,
            node_types,
            node_udp,
            selections: cfg.group_selections.clone(),
            issues,
            disabled,
            duplicate_nodes,
            states,
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
        self.selections
            .insert(group.to_string(), member.to_string());
    }

    /// 解析一个组到最终节点。chain 从顶层组到叶子节点，供规则测试和日志展示。
    pub fn resolve_group(
        &self,
        name: &str,
        transport: Transport,
        health: &HealthRegistry,
    ) -> Result<Resolved, ResolveFailure> {
        self.resolve_group_with_target(name, transport, health, None)
    }

    /// 带目标键的解析。load-balance 的一致性哈希需要「域名(无则 IP):目的端口」；
    /// 其他组类型忽略该参数。
    pub fn resolve_group_with_target(
        &self,
        name: &str,
        transport: Transport,
        health: &HealthRegistry,
        target: Option<&str>,
    ) -> Result<Resolved, ResolveFailure> {
        let mut visiting = HashSet::new();
        self.resolve_group_inner(
            name,
            transport,
            health,
            target,
            &mut Vec::new(),
            &mut visiting,
        )
    }

    fn resolve_group_inner(
        &self,
        name: &str,
        transport: Transport,
        health: &HealthRegistry,
        target: Option<&str>,
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
            GroupType::Select => {
                self.resolve_select(group, transport, health, target, chain, visiting)
            }
            GroupType::Fallback => {
                self.resolve_fallback(group, transport, health, target, chain, visiting)
            }
            GroupType::UrlTest => {
                self.resolve_url_test(group, transport, health, target, chain, visiting)
            }
            GroupType::LoadBalance => {
                self.resolve_load_balance(group, transport, health, target, chain, visiting)
            }
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
        target: Option<&str>,
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
            target,
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
        target: Option<&str>,
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
                target,
                chain,
                visiting,
                group.failure_threshold,
                group.recovery_threshold,
            ) {
                Ok(resolved) => {
                    if resolved.leaf_available {
                        if let Some(st) = self.states.get(&group.name) {
                            st.mark_switch(member);
                        }
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
        target: Option<&str>,
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
                target,
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
        let best = candidates
            .iter()
            .min_by_key(|c| c.latency_ms.unwrap_or(u64::MAX))
            .cloned()
            .unwrap_or_else(|| Resolved::new(chain.clone(), "", None, transport));
        let best_latency = best.latency_ms.unwrap_or(u64::MAX);
        let state = self.states.get(&group.name);
        // 首次解析可以沿用旧的 groupSelections 作为起点；之后以运行时 current 为准。
        let current = state
            .and_then(|s| s.current())
            .or_else(|| self.selections.get(&group.name).cloned());
        if let Some(current) = current {
            if let Some(cur) = candidates.iter().find(|c| {
                c.node == current || c.chain.get(1).map(|m| m == &current).unwrap_or(false)
            }) {
                let cur_latency = cur.latency_ms.unwrap_or(u64::MAX);
                // 容差内保持当前，避免来回切。
                if cur_latency <= best_latency.saturating_add(group.tolerance_ms) {
                    return Ok(cur.clone());
                }
                // 更优且超过容差：只有距上次切换满 switch_interval 才允许自动切。
                let allowed = state
                    .map(|s| s.switch_allowed(group.switch_interval))
                    .unwrap_or(true);
                if allowed {
                    if let Some(st) = state {
                        st.mark_switch(&best.node);
                    }
                    return Ok(best);
                }
                return Ok(cur.clone());
            }
            // 当前节点已不可用：立即切换，不受切换闸限制。
        }
        if let Some(st) = state {
            st.mark_switch(&best.node);
        }
        Ok(best)
    }

    fn resolve_load_balance(
        &self,
        group: &GroupDef,
        transport: Transport,
        health: &HealthRegistry,
        target: Option<&str>,
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
                target,
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
                .unwrap_or_else(|| "没有健康成员".to_string());
            return Err(self.no_member(group, &reason, chain));
        }
        let state = self.states.get(&group.name);
        let index = match group.lb_mode {
            LbMode::RoundRobin => state.map(|s| s.next_rr(candidates.len())).unwrap_or(0),
            LbMode::ConsistentHash => {
                let key = target.unwrap_or(group.name.as_str());
                let mut hasher = DefaultHasher::new();
                key.hash(&mut hasher);
                group.name.hash(&mut hasher);
                (hasher.finish() as usize) % candidates.len()
            }
        };
        let chosen = candidates[index].clone();
        // 只记录「最近命中」，不刷新 last_switch：load-balance 每条连接都可能换节点。
        if let Some(st) = state {
            st.set_current(&chosen.node);
        }
        Ok(chosen)
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_member(
        &self,
        group: &str,
        member: &str,
        transport: Transport,
        health: &HealthRegistry,
        target: Option<&str>,
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
                target,
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
        if transport == Transport::Udp && !self.node_udp.get(member).copied().unwrap_or(false) {
            return Err(ResolveFailure::new(
                "udp_unsupported",
                format!(
                    "节点 {}（{}）不支持 UDP，不能作为 UDP 策略成员",
                    member, kind
                ),
                chain.clone(),
                NoNodePolicy::Global,
            ));
        }
        // 阈值来自当前组配置；TCP 与 UDP 各自维护健康状态，互不背书。
        let availability =
            health.availability(member, transport, failure_threshold, recovery_threshold);
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

    /// 策略组健康快照，供统计接口的 groups 字段导出。只读，不建立常驻通道。
    pub fn health_json(&self, health: &HealthRegistry) -> serde_json::Value {
        let snapshot = health.snapshot();
        let groups: Vec<serde_json::Value> = self
            .groups
            .iter()
            .filter(|g| !self.disabled.contains(&g.name))
            .map(|g| {
                let current = self
                    .states
                    .get(&g.name)
                    .and_then(|s| s.current())
                    .or_else(|| self.selections.get(&g.name).cloned());
                let members: Vec<serde_json::Value> = g
                    .members
                    .iter()
                    .map(|m| {
                        let node = self.node_types.contains_key(m);
                        let health_json = if node {
                            snapshot.get(m).map(|h| {
                                serde_json::json!({
                                    "tcp": transport_health_json(&h.tcp),
                                    "udp": transport_health_json(&h.udp),
                                })
                            })
                        } else {
                            None
                        };
                        serde_json::json!({
                            "name": m,
                            "node": node,
                            "health": health_json,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "name": g.name,
                    "type": g.kind.as_str(),
                    "lbMode": g.lb_mode.as_str(),
                    "switchInterval": g.switch_interval.as_secs(),
                    "current": current,
                    "members": members,
                })
            })
            .collect();
        serde_json::Value::Array(groups)
    }

    /// 健康检查目标：url-test / fallback / load-balance 需要主动探测；
    /// select 不做自动切换，也不因健康状态剔除成员。
    pub fn health_targets(&self) -> Vec<HealthTarget> {
        self.groups
            .iter()
            .filter(|g| !self.disabled.contains(&g.name))
            .filter(|g| {
                matches!(
                    g.kind,
                    GroupType::UrlTest | GroupType::Fallback | GroupType::LoadBalance
                )
            })
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
        let Some(idx) = self.by_name.get(name).copied() else {
            return;
        };
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
        let Some(next) = by_name.get(member).copied() else {
            continue;
        };
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
            dfs_cycle(
                next, groups, by_name, color, stack, reported, issues, disabled,
            );
        }
    }
    stack.pop();
    color[idx] = 2;
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

fn transport_health_json(h: &TransportHealth) -> serde_json::Value {
    let status = match h.healthy {
        Some(true) => "healthy",
        Some(false) => "unhealthy",
        None => {
            if h.consecutive_failures > 0 {
                "failing"
            } else {
                "unknown"
            }
        }
    };
    serde_json::json!({
        "status": status,
        "latencyMs": h.latency_ms,
        "lastCheckMs": h.last_check_ms,
    })
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
                    let Some(node) = nodes_for_group.iter().find(|n| n.name == name).cloned()
                    else {
                        continue;
                    };
                    let started = Instant::now();
                    let ok = outbound::probe_node(
                        &node,
                        &target_for_group.test_url,
                        target_for_group.timeout,
                    )
                    .await
                    .is_ok();
                    let latency = if ok {
                        Some(started.elapsed().as_millis() as u64)
                    } else {
                        None
                    };
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
        let r = set
            .resolve_group("G", Transport::Tcp, &HealthRegistry::new())
            .unwrap();
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

        assert_eq!(
            set.resolve_group("F", Transport::Tcp, &h).unwrap().node,
            "n1"
        );
        health_fail(&h, "n1", 1, 2, 2);
        assert_eq!(
            set.resolve_group("F", Transport::Tcp, &h).unwrap().node,
            "n1"
        );
        health_fail(&h, "n1", 1, 2, 2);
        assert_eq!(
            set.resolve_group("F", Transport::Tcp, &h).unwrap().node,
            "n2"
        );

        health_ok(&h, "n1", 1, 2, 2);
        assert_eq!(
            set.resolve_group("F", Transport::Tcp, &h).unwrap().node,
            "n2"
        );
        health_ok(&h, "n1", 1, 2, 2);
        assert_eq!(
            set.resolve_group("F", Transport::Tcp, &h).unwrap().node,
            "n1"
        );
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
        assert_eq!(
            set.resolve_group("U", Transport::Tcp, &h).unwrap().node,
            "n1"
        );
        // V 没有当前选择，选最低延迟。
        assert_eq!(
            set.resolve_group("V", Transport::Tcp, &h).unwrap().node,
            "n2"
        );
    }

    #[test]
    fn load_balance_hashes_target_and_round_robin_alternates() {
        let mut lb = group("LB", "load-balance", &["n1", "n2"]);
        lb.lb_mode = "consistent-hash".into();
        let cfg = config(vec![node("n1", "ss"), node("n2", "ss")], vec![lb], &[]);
        let set = StrategySet::from_config(&cfg);
        let h = HealthRegistry::new();
        health_ok(&h, "n1", 10, 1, 1);
        health_ok(&h, "n2", 20, 1, 1);
        let a = set
            .resolve_group_with_target("LB", Transport::Tcp, &h, Some("example.com:443"))
            .unwrap()
            .node;
        let b = set
            .resolve_group_with_target("LB", Transport::Tcp, &h, Some("example.com:443"))
            .unwrap()
            .node;
        assert_eq!(a, b, "同一目标键必须落同一节点");
        // 至少验证不同目标键不会因为轮询计数而漂移：连续同一 key 仍是同一节点。
        let _ = set
            .resolve_group_with_target("LB", Transport::Tcp, &h, Some("other.com:443"))
            .unwrap();

        let mut rr = group("RR", "load-balance", &["n1", "n2"]);
        rr.lb_mode = "round-robin".into();
        let cfg = config(vec![node("n1", "ss"), node("n2", "ss")], vec![rr], &[]);
        let set = StrategySet::from_config(&cfg);
        let h = HealthRegistry::new();
        let first = set.resolve_group("RR", Transport::Tcp, &h).unwrap().node;
        let second = set.resolve_group("RR", Transport::Tcp, &h).unwrap().node;
        assert_ne!(first, second, "round-robin 必须轮询");
    }

    #[test]
    fn url_test_switch_gate_waits_30s_but_unhealthy_switches_immediately() {
        let now = Arc::new(std::sync::Mutex::new(Instant::now()));
        let clock_now = now.clone();
        let clock: Clock = Arc::new(move || *clock_now.lock().unwrap());
        let mut g = group("U", "url-test", &["n1", "n2"]);
        g.tolerance = 0;
        g.switch_interval = 30;
        let cfg = config(vec![node("n1", "ss"), node("n2", "ss")], vec![g], &[]);
        let set = StrategySet::from_config_with_clock(&cfg, clock);
        let h = HealthRegistry::new();
        health_ok(&h, "n1", 100, 1, 1);
        health_ok(&h, "n2", 50, 1, 1);
        // 首次解析没有 current，直接命中最低延迟 n2，并记录切换时刻。
        assert_eq!(
            set.resolve_group("U", Transport::Tcp, &h).unwrap().node,
            "n2"
        );
        // n1 变快，但 30s 闸未到，保持 n2。
        health_ok(&h, "n1", 5, 1, 1);
        assert_eq!(
            set.resolve_group("U", Transport::Tcp, &h).unwrap().node,
            "n2"
        );
        // 时钟前进 31s，允许切到更优 n1。
        *now.lock().unwrap() += Duration::from_secs(31);
        assert_eq!(
            set.resolve_group("U", Transport::Tcp, &h).unwrap().node,
            "n1"
        );
        // n1 被判定不可用：即使闸未到也立即切回 n2。
        health_fail(&h, "n1", 1, 1, 1);
        assert_eq!(
            set.resolve_group("U", Transport::Tcp, &h).unwrap().node,
            "n2"
        );
    }

    #[test]
    fn health_json_exports_groups_and_members() {
        let cfg = config(
            vec![node("n1", "ss"), node("n2", "ss")],
            vec![group("LB", "load-balance", &["n1", "n2"])],
            &[],
        );
        let set = StrategySet::from_config(&cfg);
        let h = HealthRegistry::new();
        health_ok(&h, "n1", 42, 1, 1);
        let v = set.health_json(&h);
        let groups = v.as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["name"], "LB");
        assert_eq!(groups[0]["type"], "load-balance");
        assert_eq!(groups[0]["lbMode"], "consistent-hash");
        assert_eq!(groups[0]["members"][0]["health"]["tcp"]["latencyMs"], 42);
        assert_eq!(groups[0]["members"][1]["health"], serde_json::Value::Null);
    }

    #[test]
    fn udp_never_uses_tcp_probe_or_trojan_node() {
        // trojan 本身已支持 UDP；这里显式 udp:false，验证「TCP 健康不能给 UDP 背书」。
        let mut tj = node("tj", "trojan");
        tj.udp = Some(false);
        let cfg = config(
            vec![tj, node("ss", "ss")],
            vec![group("F", "fallback", &["tj", "ss"])],
            &[],
        );
        let set = StrategySet::from_config(&cfg);
        let h = HealthRegistry::new();
        health_ok(&h, "tj", 1, 1, 1);
        // TCP 仍可以走 trojan 的首选。
        assert_eq!(
            set.resolve_group("F", Transport::Tcp, &h).unwrap().node,
            "tj"
        );
        // UDP 必须跳过不支持 UDP 的 trojan，不能拿 TCP 健康当 UDP 可用。
        assert_eq!(
            set.resolve_group("F", Transport::Udp, &h).unwrap().node,
            "ss"
        );

        let mut only_tj_node = node("tj", "trojan");
        only_tj_node.udp = Some(false);
        let only_tj = config(
            vec![only_tj_node],
            vec![group("F", "fallback", &["tj"])],
            &[],
        );
        let set = StrategySet::from_config(&only_tj);
        let err = set
            .resolve_group("F", Transport::Udp, &HealthRegistry::new())
            .unwrap_err();
        assert_eq!(err.code, "no_available_member");
        assert!(err.message.contains("不支持 UDP"));
    }

    #[test]
    fn trojan_and_vless_support_udp_by_default() {
        for kind in ["trojan", "vless"] {
            let cfg = config(
                vec![node("n", kind)],
                vec![group("F", "fallback", &["n"])],
                &[],
            );
            let set = StrategySet::from_config(&cfg);
            let r = set
                .resolve_group("F", Transport::Udp, &HealthRegistry::new())
                .unwrap();
            assert_eq!(r.node, "n", "{} 默认应可用于 UDP", kind);
        }
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
        let r = set
            .resolve_group("outer", Transport::Tcp, &HealthRegistry::new())
            .unwrap();
        assert_eq!(r.chain, vec!["outer", "inner", "n1"]);
    }

    #[test]
    fn cycle_is_reported_and_cannot_be_enabled() {
        let cfg = config(
            vec![node("n1", "ss")],
            vec![group("A", "select", &["B"]), group("B", "select", &["A"])],
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
        assert!(set
            .issues()
            .iter()
            .any(|i| i.code == "duplicate_node_reference"));
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
        let (a, _) = engine.decide_detail(
            Some("a.example"),
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            443,
            ConnKind::Tcp,
        );
        let (b, _) = engine.decide_detail(
            Some("b.example"),
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            443,
            ConnKind::Tcp,
        );
        assert_eq!(a, Action::Group("组A".into()));
        assert_eq!(b, Action::Group("组B".into()));
        assert_eq!(
            set.resolve_group("组A", Transport::Tcp, &h).unwrap().node,
            "n1"
        );
        assert_eq!(
            set.resolve_group("组B", Transport::Tcp, &h).unwrap().node,
            "n2"
        );
    }
}
