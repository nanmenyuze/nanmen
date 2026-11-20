# 基础配置 DNS 改为手机默认解析

版本：南门DNS 2.3.8 / versionCode 82
日期：2026-11-20

## 1. 改动

- 「基础配置」的 DNS 上游由阿里 DoH（`https://dns.alidns.com/dns-query`）改为 `system`，表示**跟随手机当前 Wi‑Fi / 移动数据 / 以太网下发的 DNS**。
- 备用 DNS 默认也改为 `system`，取系统下发的第二个 DNS；没有第二个时为空，不补第三方地址。
- DNS 设置页新增「跟随手机默认 DNS」选项；仍保留阿里、DNSPod、Cloudflare、Google 和手动 DoH/DoT/UDP，供用户主动选择。
- 内核未改动，仍为 `nanmen_core 1.12.5`；系统 DNS 在 Kotlin 壳层下发配置时转成 `udp://<server>:53`。

## 2. 系统 DNS 选择规则

`SystemDns` 只从**非 VPN** 的底层网络读取 `LinkProperties.dnsServers`：

1. 排除 VPN 自身，避免读到 TUN 的 `10.10.10.53`。
2. 优先已验证（VALIDATED）的网络，再按 Wi‑Fi > 移动数据 > 以太网排序。
3. DNS 服务器优先 IPv4，其次 IPv6；第一个作为主上游，第二个作为备用。
4. 过滤 loopback、link-local、any-local 地址。
5. 如果系统没有下发任何 DNS，主上游写 `udp://127.0.0.1:9`（不可达），**fail-closed，不回落第三方**；页面会提示未获取到系统 DNS。

## 3. 旧基础配置迁移

新增一次性迁移 `DnsDefaultsMigration`，只在以下条件全部满足时替换：

- `dnsUpstream == https://dns.alidns.com/dns-query`
- `dnsFallback == 223.5.5.5`
- 没有 Bootstrap、DoH Header、远端配置名/URL

满足时把当前 `default.conf`（以及非 active 时的 `default.conf`、`files/default.json` 兜底）改为 `system`。用户手动改过 DNS、配置了 Header/Bootstrap 或使用远端配置的，不会被覆盖。迁移幂等，只执行一次。

## 4. 生效方式

- 新安装：`assets/default.json`、`AppConfig`、`ConfigFile.GeneralConfig` 默认均为 `system`。
- 旧安装升级：启动时迁移基础配置；如果 VPN 已连接，保存 DNS 设置会触发重载/重建。
- 手动切换：策略 → 当前配置 → DNS 上游 → 跟随手机默认 DNS。
- 网络切换：`NamuVpnService` 原有的 NetworkCallback 会重建 TUN，重建时重新读取当前底层 DNS。

## 5. 边界

- **Private DNS**：系统 Private DNS 的 strict DoT 可能绕过 LinkProperties 的 UDP DNS；本改动读取的是系统下发的 DNS 服务器，不解析 Private DNS 主机名。需要绝对避免第三方时，建议同时关闭 Private DNS。
- **无系统 DNS**：按第 2 节 fail-closed，不自动使用阿里/腾讯/Cloudflare/Google。
- **备份**：备份中的 `dnsUpstream`/`dnsFallback` 原样保存 `system`，换机恢复后仍跟随新机网络。
- **无设备**：本轮仍没有 Android 真机/模拟器，真实 Wi‑Fi/蜂窝 DNS 读取只做了编译与静态逻辑验证，未做设备实测。

## 6. 验证

- `:app:compileDebugKotlin` 通过。
- `:app:testDebugUnitTest`：23 个 suite、113 个测试，0 failure / 0 error / 0 skip。
- 新增 `DnsDefaultsMigrationTest`：默认 `system`、旧默认识别、自定义 DoH 不覆盖、远端配置不覆盖。
- `:app:lintDebug`：0 error（warning 为项目既有 deprecated API）。
- 清洁构建与 APK 校验结果见交付记录。
