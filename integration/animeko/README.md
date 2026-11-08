# Animeko × Lanerc 集成工程

目标：在 Animeko 内保留原生数据源体系，增加独立的 Lanerc 动态源模式；两者支持各自使用和并行搜索，逐步接入原版弹幕与评论。Android 修改版使用自己的发布签名，不依赖原 Lanerc APK 的发布私钥。

## 基线与工程布局

- 上游：`open-ani/animeko`，固定 commit `6d79729a135cee6af861a7a095d3880d1b452260`。
- `upstream.json` 保存 commit、固定下载地址与 ZIP SHA-256。
- `overlay/` 是实际 Kotlin 源码，路径与上游工程对应；不是 Dart cleanroom 的拷贝。
- `core-checks/` 编译、测试同一份 Kotlin 源码，不是另外重写一个测试实现。
- 保留上游 AGPL-3.0 许可，见 `LICENSE.txt`。发布修改版时须提供对应源代码和许可。
- 上游包含较大的桌面原生库。使用固定基线 + 小型源码 overlay，避免把这些二进制再次提交本仓库。可重复还原完整源码，不依赖临时目录内容。

```sh
python scripts/prepare_animeko_lanerc.py
# 生成 .local/animeko/worktree；执行任何 Gradle 构建前请先检查该目录。
cd integration/animeko/core-checks
bash gradlew test
```

本地需要 JDK 21；依赖下载与编译在 GitHub Actions 中实际运行。没有把私密恢复材料交给构建 runner。

## 已实现的基础代码

### Kotlin 协议核心

- 请求 MD5 签名，要求传入**添加 sign 前的准确 Dio 规范化 URI**。Kotlin URI 桥已对 7 组 Dart/Dio fixture 与 Ktor URLBuilder roundtrip 做一致性验证。
- 三套独立密钥的用途隔离：播放 GCM、普通响应 ECB、公开 TXT ECB。
- GCM `nonce[12] || ciphertext || tag[16]` 认证解密；普通响应按顺序字符替换、Base64、ECB/PKCS7 解码。
- 限长 Protobuf wire 解码、未知字段与不匹配 wire type 跳过、重复字段最后值生效、int32 符号处理、非 200/空 URL 拒绝。
- 私密材料与导出的源定义分离；密钥防御性复制；敏感对象的 `toString` 脱敏。
- Android/桌面使用 JVM JCE。iOS 加密实现尚未接入。

### 动态内置源发现

`LanercBootstrapPlan.builtIn()` 内置原 APK 的 TXT 域名池与 DoH provider，不把当前 `v3.yyghk.com` 固定成源地址。发现引擎接收注入的 HTTP transport，按原版 TXT ECB 逻辑解码、检查 HTTPS URL，并按 DNS TTL 缓存；失效后失败不会返回演示数据或无限复用旧地址。同一源的并发发现去重，不同源不共享缓存。

Android 已连接独立 HTTP transport、本机 KeyStore 材料加载、源工厂/codec 注册、设置 UI 和三模式过滤；用户可添加动态内置源。加密 TXT 本身不等于 DNSSEC 或后端来源认证；后续凭据必须绑定源与后端 origin，不能跨源转发。

### 并行搜索执行器

- `ANIMEKO / LANERC / BOTH` 三种模式。
- 默认最多 4 个源并发，单源超时隔离，增量返回结果。
- 查询取消传播到底层，不吞掉协程取消。
- 按源族、源 ID 保留结果归属；同名不同源不互相覆盖；不接受一个源冒充另一个源返回结果。
- 大小写、全角与标点/空格归一化、别名精确匹配优先；保留季度数字，不把第二季当第一季。
- 该执行器尚未连接 Animeko 页面或替换其自动匹配器。没有证据证明应全面替换 Animeko 的搜索，所以保留其匹配、剧集过滤和偏好选择逻辑。

## 原版格式兼容：证据边界

用户选择兼容**Lanerc 原版**，而非 cleanroom `DynamicSourceManifest`。当前没有原版导出的源文件样本，也没有已经证实的完整导入文件 schema；这里不会凭空设计一种 JSON，再称其兼容原版。

静态证据：

- 原版后备配置读取 `domain` 字段：ARM64 `0x96cfd8`，pool `0x11b48`。
- 后备地址存在 `Ahttps://` / `Ahttp://` 特殊前缀处理，且有后续签名探测逻辑；不能只去掉字母 A 就认定全部协议已经复现。
- 原版评论读取路径是 `app/chat/comment`，不是 cleanroom 的 `app/chat/comments`。
- `app/v2/guest/captcha`、`app/v2/guest/credential`、`app/v2/guest/play` 与 `playResolveProtobuf` 的已确认部分可复用，验证码提交字段 `challenge_id` / `selected`（字符串）、评论与弹幕只读 DTO 已由静态证据恢复；用户登录与发送仍未接入。
- 2026-11-08 对 APK 中两条公开后备配置地址进行了无凭据 GET，两条均网络失败，**没有取得配置内容**。见 `analysis/lanerc/public-source-config.json`；不能把网络诊断成功运行说成取得真实源文件。

## 未完成的验收项

- [ ] 原版源文件导入/导出兼容、异常格式回归样本。
- [x] Animeko 源注册、独立持久化、设置入口与三模式 UI；已编译，未设备验证。
- [x] Android KeyStore 安全存储、按源与 origin 隔离凭据、URI 规范化桥接；未设备验证。
- [x] 搜索/详情/剧集与 MediaSource/ApiVideoResolver 代码接线；不是生产播放成功。
- [ ] 合法验证码交互、guestCredential 生命周期与生产播放验证。
- [ ] Lanerc 弹幕加载/发送、评论列表/分页/回复及登录要求，与 Animeko 原有服务分开。
- [ ] 可安装 Android APK、UI 自动化、真机播放与回归测试。

当前已生成 Android 集成预览 APK，**不是生产验收完成的版本**。最新执行结果见 `analysis/lanerc/animeko-core-validation.json`；字段明确区分核心测试、Android 构建、UI 集成及原版格式验证。

## 已验证的交付与本轮新增

- Kotlin 核心 42 项测试通过、0 失败/跳过，源码安全准备 4 项通过。
- Android 编译、UI 编译、打包与上传已成功。构建 42443902879 的红色结论来自之后提交报告失败，不是编译失败。
- APK 已实际放入 Code：[`downloads/animeko/`](../../downloads/animeko/)，配套 SHA256SUMS、build.json；本地重新拉取并校验通过。applicationId `me.him188.ani.lanerc`，arm64 debug 签名。
- 当前 Code APK 对应 `2e3cce6`，不包含后续新增的评论页面；后续构建必须分别确认。
- 新增播放器评论页独立 Lanerc 作品评论切换入口，使用选中媒体的原版 `vod_id`，而非 Bangumi ID；仅原生 Lanerc 源可请求。保留 Animeko 评论，支持手动选择、分页、失败重试，切换媒体取消旧请求，不显示敏感后台错误。**此新增代码正在进行 Android 编译验证，未做真机测试。**
- 弹幕目前保留原版字段及接口 DTO；播放器渲染位置枚举与发送尚未接入。评论发送、原版用户登录也未接入。
- 构建不嵌入恢复密钥或生产凭据。现有 APK 不是无需配置即可播放的成品，也没有真实播放成功的证据。
