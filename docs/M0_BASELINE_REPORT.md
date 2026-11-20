# M0 复现 2.0 基线与锁定兼容对象

> 状态：**PASS_WITH_BLOCKERS（构建/单测基线通过，端到端兼容基线未通过）**  
> 日期：2026-11-19  
> 版本：南门DNS 2.0 / versionCode 69 / 内核 1.11.5  
> 原则：不把解析通过写成运行通过；没有设备/样本的项一律标阻塞。

## 1. 结论

- 2.0 源码可取得；版本号、`kernel_version.txt`、两个 ABI 的 `.so` 摘要一致。
- 在**清洁解压目录**中完成 Rust、Kotlin、lint、`verifyKernel`、`assembleDebug`，无构建失败。
- 固定兼容对象：Loon 3.5.3（App Store 页面）；Shadowrocket 2.2.66（七麦版本记录，官方页面待复核）。
- 样本 31 个、case 52 条、机读矩阵 80 行、逐 case 覆盖审计 52 条。
- **52 条 case 中 35 条被测试直接消费**：29 条解析断言 + 6 条运行行为断言；17 条未直接消费，原因逐条记录在 `compat/expected/coverage.json`。
- **端到端兼容未验收**：没有 Android 设备、没有 iOS/Loon/Shadowrocket 设备、没有真实节点/真实 HTTPS 代理，因此不能宣称“Loon 兼容通过”。

## 2. 环境记录

| 项 | 值 |
|---|---|
| OS | Ubuntu 22.04（云主机） |
| JDK | Temurin 17.0.21（`/home/user/jdk17`） |
| Gradle | 8.14 |
| Rust | 1.100.0 |
| Cargo | 1.100.0 |
| Android SDK | compileSdk 36；build-tools 34/36/37 可用 |
| NDK | 28.2.13676358 |
| 设备 | `adb devices` 无设备；无 iOS 设备 |
| 网络 | 清洁构建使用本机 Gradle/Cargo 缓存；未验证完全离线 |

> 说明：`java -version` 默认是 JDK 11；构建必须显式使用 `JAVA_HOME=/home/user/jdk17`。文档命令已固定这一点。

## 3. 源码与版本事实

| 项 | 值 |
|---|---|
| 源码树 | `work/v134` |
| Git commit | 无 Git 仓库，使用源码摘要替代 |
| `versionName` | `2.0` |
| `versionCode` | `69` |
| 内核源码版本 | `1.11.5`（`core/src/lib.rs`） |
| `kernel_version.txt` 版本 | `1.11.5` |
| 内核源码摘要 | `eb3f98a59bd5bbf3860c871d210acdae0529155e3e45bf8f3b414e9290176409` |
| Cargo 摘要 | `56100cb9b85b36b564a0d92e280faa61cdfe1799d0677b54b7ede4cbb376ddf3` |
| arm64 `.so` | `198ddddc4a57fae26233ca08e936abf8242d084a35744598815be9fd569f53e2` |
| armv7 `.so` | `a82294a8f1e2c4e2fd69b0c96727f5d60914a3fcdd42389bb265d940c17d164f` |
| 代码树摘要 | `29c3a56521c62df0581cdc12eb23fbda373c81829be7bc392b3214cec1d07f60` |
| 源码包 | `南门DNS-2.0-自研内核-完整源码.zip` |
| 源码包 SHA-256 | 见交付目录 `SHA256SUMS.txt`（避免包内自引用） |
| APK（清洁构建） | `app-debug.apk`，41,741,767 字节，versionCode 69/versionName 2.0，minSdk 31 |
| APK SHA-256 | `f720b5345cd1900188235df6888ca80b1e165429e52eb647498abf99808dfa11` |

代码树摘要算法：对 `app/src`、`core/src`、`core/tests`、Gradle 配置、`core/Cargo.*`、`compat/fixtures`、`compat/expected/cases.json` 中所有文件，按相对路径排序，逐个写入 `path\0sha256(file)\0` 后取 SHA-256。`docs/` 不参与，因此写报告不会改变代码摘要。

## 4. 兼容对象锁定

| 对象 | 目标版本 | 来源 | 置信度 | 备注 |
|---|---|---|---|---|
| Loon | 3.5.3 | <https://apps.apple.com/cm/app/loon/id1373567447> | App Store 页面 | 官方文档 Node/Rule/Rewrite/Script/Plugin 作为目标语义 |
| Shadowrocket | 2.2.66 | <https://www.aso100.com/app/version/appid/932747118/country/gh> | 二手版本记录 | 官方 App Store 页面未直接读取；需 iOS 设备复核 |

- Loon 官方文档抓取日期：2026-11-19。
- Shadowrocket 没有同等完整的公开规范；矩阵中“小火箭目标”按常见订阅/配置形态标注，不声称逐字段等价。
- 目标版本锁定记录见 `compat/targets.json`。

## 5. 样本来源与授权

- 全部 31 个 fixture 为**本项目自建合成样本**：`example.com`、`203.0.113.0/24`、`198.51.100.0/24`、占位 UUID/密码。
- 不含真实节点、真实订阅 URL、真实账号、真实 UUID、真实密码。
- 无第三方素材/插件文本复制，因此不依赖第三方授权。
- 样本来源、授权、设备状态见 `compat/targets.json`。

## 6. 执行与结果

### 6.1 原地基线（当前工作树）

```bash
cd work/v134/core
cargo test

cd work/v134
export JAVA_HOME=/home/user/jdk17
export ANDROID_HOME=/home/user/Android/Sdk
./gradlew --no-daemon :app:testDebugUnitTest :app:lintDebug :app:verifyKernel :app:assembleDebug
```

> 新增测试后，原地只做了定向冒烟；以下权威数字来自 6.2 清洁构建。

| 检查 | 结果 |
|---|---|
| Rust | 118 / 118 通过 |
| Kotlin | 72 / 72 通过（18 suites） |
| Lint | 0 errors / 38 warnings |
| 内核校验 | 通过 |
| Debug APK | 41,741,767 字节，minSdk 31 |

### 6.2 清洁解压构建

- 清洁目录：`work/a12-clean/南门DNS-2.0-自研内核-完整源码`，由源码 zip 解压，`app/build`、`core/target`、`.gradle`、`.kotlin` 均不存在。
- 命令：`M0_LOG_DIR=work/a12-clean-logs bash scripts/m0_clean_build.sh`
- 首次失败：Gradle wrapper 指向 8.9，缓存缺失且下载遇 PKIX 证书错误；**不是代码失败**。已将 wrapper 对齐到本地 8.14 后重跑。
- 最终结果：**BUILD SUCCESSFUL in 3m 44s**；54 tasks executed。
- 依赖说明：构建使用本机 Gradle/Cargo/Android SDK 缓存；验证的是“源码树清洁”，不是“完全离线环境”。

## 7. 文档与实测差异

| 项 | 文档旧值 | 实测/当前值 | 说明 |
|---|---|---|---|
| Rust 测试数 | 116 | 118 | 新增 TUIC/AnyTLS 解析测试（11 项 compat_fixtures）与规则运行测试（1 项） |
| Kotlin 测试数 | 70 | 72 | 新增订阅用量与配置 fixture 测试（CompatFixtureTest 5 项） |
| Lint | 41 warnings | 38 warnings | Android 12+ 壳清洁构建权威口径；minSdk 31 新增 ObsoleteSdkInt |
| 直接消费 case | 未统计 | 35 / 52 | `coverage.json` |
| 解析断言 | 未统计 | 29 | 节点/订阅/配置/部分模块 |
| 运行断言 | 未统计 | 6 | 规则运行矩阵 |
| Shadowrocket 版本 | 未固定 | 2.2.66 | 二手来源，待官方复核 |
| APK 字节 | 1a8e63a9…（旧 2.0 包） | f720b534…（Android 12+ 清洁包） | 同版本/同调试签名；换壳后重新构建 |
| 端到端兼容 | 未声明 | 阻塞 | 无设备/真实服务 |

## 8. 逐 case 消费审计

- 机器可读：`compat/expected/coverage.json`
- 汇总：52 条；直接消费 35；未直接消费 17。
- 按类别：

| 类别 | 总数 | 直接消费 | 未消费原因 |
|---|---:|---:|---|
| 节点 | 17 | 17 | 已覆盖解析断言 |
| 订阅 | 8 | 8 | 已覆盖解析断言 |
| 规则 | 10 | 6 | R05-R08 只有模块 ignored 聚合解析，无逐条运行断言 |
| 重写 | 10 | 0 | 2 条有等价行为测试但未消费 case；8 条无逐 case 断言 |
| 脚本 | 3 | 0 | 无脚本运行时 |
| 配置 | 4 | 4 | C03/C04 复用订阅 conf 测试 |

> “解析断言”只证明解析器当前行为；不等于“规则实际命中/重写出站/脚本执行”。端到端运行断言仍缺设备与服务。

## 9. 阻塞与未决

1. **设备阻塞**：`adb devices` 为空；没有 Android 真机，四页 UI、Root 证书信任、真实出站未验收。
2. **iOS 阻塞**：无 iOS 设备、无 Loon/Shadowrocket 安装，无法做两端行为对照。
3. **真实服务阻塞**：无真实 VLESS/Trojan/HTTPS 代理、无真实 视频类 App gRPC 请求，HTTPS 代理与 gRPC 只到单测级。
4. **Shadowrocket 版本**：2.2.66 来自二手版本记录，官方页面待复核。
5. **样本范围**：全部合成，不覆盖真实厂商插件/私有协议样本；Snell/ShadowTLS 无 fixture。

## 10. M0 验收清单

| 验收项 | 状态 | 证据 |
|---|---|---|
| 取得 2.0 完整源码与 fixtures | 通过 | 源码包 196 文件；31 fixtures |
| 验证 versionName/versionCode | 通过 | 2.0 / 69 |
| 验证 kernel_version.txt 与 .so | 通过 | `scripts/m0_validate.py`；`verifyKernel` |
| 执行 Rust/Kotlin/lint/kernel/debug | 通过 | 清洁构建记录 |
| 记录环境/源码摘要/失败原因 | 通过 | 本文第 2、3、9 节 |
| 固定 Loon/小火箭版本 | Loon 通过；Shadowrocket 待复核 | `targets.json` |
| 样本来源/授权 | 通过（自建合成） | `targets.json` |
| 设备记录 | 阻塞 | 无 Android/iOS 设备 |
| 机读逐项矩阵 | 通过 | `compat/matrix.json`（80 行） |
| 每条 case 是否被测试消费 | 通过（35/52，其余列明） | `coverage.json` |
| 从清洁环境重复构建 | 通过（源码清洁；依赖缓存共享） | 下节 |

## 11. 清洁构建记录

### 11.1 首次尝试

- 现象：`./gradlew` 试图下载 `gradle-8.9-bin.zip`，报 `SSLHandshakeException / PKIX path building failed`。
- 判定：环境/工具链阻塞，不是源码编译失败。未把它写成“基线通过”。
- 处理：`gradle/wrapper/gradle-wrapper.properties` 对齐到本机已缓存的 Gradle 8.14；清洁脚本优先使用 `./gradlew`。

### 11.2 第二次尝试

```text
clean dir: work/a12-clean/南门DNS-2.0-自研内核-完整源码
Rust:      118 / 118 (65 lib + 1 cert + 11 compat_fixtures + 1 compat_rules + 26 core + 14 mitm)
Kotlin:    72 / 72 (18 suites, 0 failure / 0 error / 0 skipped)
Lint:      0 errors / 38 warnings
Kernel:    verifyKernel passed
APK:       41,741,767 bytes
APK SHA:   f720b5345cd1900188235df6888ca80b1e165429e52eb647498abf99808dfa11
Gradle:    BUILD SUCCESSFUL in 3m 44s, 54 tasks executed
```

### 11.3 复现结论

- 清洁源码树可以完整构建；构建结果与版本号、内核摘要一致。
- 本次 Android 12+ 壳清洁 APK 与旧 2.0 包 **不是字节一致**（旧包 41,880,342 / `1a8e63a9…`），但同 versionCode、同 versionName、同调试证书；这是换壳后的重新构建，不是功能回退。
- 未执行“完全离线 + 空缓存”的环境；Gradle/Cargo/Android SDK 依赖来自本机缓存，需在报告中如实标注。
