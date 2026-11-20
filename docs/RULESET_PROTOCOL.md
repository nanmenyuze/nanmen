# 规则集与 PROTOCOL（2.3.8 增量）

版本：南门DNS 2.3.8 / versionCode 82 / 内核 1.12.5
范围：`RULE-SET` / `DOMAIN-SET` 规则集引用，以及 `PROTOCOL`（TCP/UDP）规则。
本轮不升版本号，作为 2.3.8 的增量能力。

## RULE-SET

```ini
[Rule]
RULE-SET,https://example.com/rules.txt,PROXY
```

- 导入/同步模块时拉取 URL，缓存到 `files/ruleset_<url哈希前16位>.txt`，上限 8 MiB。
- `ConfigStore.rebuildModules` 把缓存内容展开成普通 `RuleItem`，与手写规则走同一套 RuleEngine。
- 集合策略覆盖列表行内策略（Surge 语义）；`PROXY` / `DIRECT` / `REJECT*` 分别映射为 `proxy` / `direct` / `block`。
- 列表支持 `DOMAIN* / IP-CIDR* / GEOIP(CN) / PORT / PROTOCOL`；`USER-AGENT` 等未支持类型跳过。
- 拉取失败保留旧缓存继续使用；没有缓存时该规则集不生效，不会伪装成命中。
- 纯规则集模块（没有其他规则）也可以导入。

## DOMAIN-SET

```ini
DOMAIN-SET,https://example.com/domains.txt,REJECT
```

- `.example.com` → `DOMAIN-SUFFIX,example.com`（含 apex）
- `*.example.com` → `DOMAIN-WILDCARD,*.example.com`（仅子域）
- `example.com` → `DOMAIN,example.com`（精确）

## PROTOCOL

```ini
PROTOCOL,UDP,REJECT
PROTOCOL,TCP,DIRECT
```

- 内核按连接类型匹配；只接受 `TCP` / `UDP`。
- 其他值在加载期拒绝并写告警，不会被当作“永不匹配”静默吞掉。
- 同步支持 `RULE-SET` 列表里的 `PROTOCOL` 行。

## 未实现边界

- `USER-AGENT`：需要 MITM 重决策，未实现。
- `IP-ASN` / 完整 GEOIP：需要 MaxMind 数据库，未实现。
- 逻辑规则（`AND` / `OR` / `NOT`）：需要解析器与求值器，未实现。
- 策略组名作为规则目标仍未接入；按现有模块规则记入 `lostRouteTargets`。

## 验证

- Rust：184/184（含新增 2 项 PROTOCOL）。
- Kotlin：118/118、24 suites（含新增 5 项规则集回归）。
- Lint：0 error / 38 warning / 3 information。
- 无 Android 真机；规则集实际拉取和网络切换未做设备实测。
