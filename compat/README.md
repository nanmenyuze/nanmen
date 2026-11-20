# compat/：Loon / 小火箭兼容性基线

这个目录不是功能实现，而是**固定样本 + 预期结果 + 回归测试**，用于后续逐项做 Loon 兼容时避免“改坏旧行为”。

## 目录

- `fixtures/nodes/`：17 个节点 URI 样本（SS/SSR/VMess/VLESS/Trojan/Hysteria2/TUIC/WireGuard/SOCKS5/HTTP/HTTPS/AnyTLS）。
- `fixtures/subscriptions/`：Base64 订阅、Clash YAML、Loon `.conf`、Shadowrocket `.conf`。
- `fixtures/modules/`：Surge `.sgmodule`、Loon `.plugin`。
- `fixtures/rulesets/`：AdBlock 列表、sing-box source JSON。
- `fixtures/scripts/`：Loon `$request` / `$response` / `$httpClient` API 样本。
- `fixtures/configs/`：南门 DNS 2.x JSON、旧版扁平 JSON。
- `fixtures/headers/`：`Subscription-Userinfo` 响应头。
- `expected/cases.json`：52 条机器可读预期（导入结果、计数、命中规则、出站、脚本输出）。
- `expected/coverage.json`：每条 case 是否被测试直接消费，区分解析断言/运行断言。
- `expected/baseline.json`：M0 基线汇总（版本、测试、lint、APK、清洁构建）。
- `targets.json`：Loon/Shadowrocket 目标版本、样本授权、设备状态。
- `matrix.json`：80 行机读兼容矩阵。

## 运行

```bash
cd ..                 # 到 work/v134
cd core && cargo test --test compat_fixtures -- --nocapture
cd ..
./gradlew :app:testDebugUnitTest --tests 'com.namu.dns.CompatFixtureTest'
```

完整基线：

```bash
cd core && cargo test
cd ..
./gradlew :app:testDebugUnitTest :app:lintDebug :app:verifyKernel :app:assembleDebug
```

## 约定

- 样本全部为合成数据，不含真实服务器、密码、UUID 或订阅地址。
- `expected/cases.json` 中的 `expected.import` 表示**当前基线行为**，不是目标能力。实现某项能力后，必须同步更新 `cases.json` 和对应测试断言。
- 未支持项不要通过改测试“变绿”；先加实现，再加断言。
- 新增样本后，`CompatFixtureTest` / `compat_fixtures.rs` 的文件路径断言需要同步；目录层级保持 `fixtures/<category>/<file>`。

## 已知基线缺陷

1. `ssr://`、`wireguard://`、`anytls://` 等未识别 scheme 静默丢弃，不进入 `unsupported` 计数。
2. AdBlock `|exact.example.net|` 单竖线精确域名没有解析；`fixtures/rulesets/ads.txt` 当前只得到 2 条 block。
3. Loon `.conf`、Shadowrocket `.conf` 不能导入，`parse_subscription` 返回空。
4. `.sgmodule` 的 `[Body Rewrite]`、`[Script]`、`[Host]` 被计入 `ignored`。
5. `.plugin` 的 `[Argument]`、`[General]`、`[Rewrite]`、`[Host]`、`[Script]` 被计入 `ignored`。
6. `DOMAIN-REGEX` / `PORT` 在 kernel 可用，但模块解析器和手动规则 UI 不完整。
