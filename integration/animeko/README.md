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

- 请求 MD5 签名先计算添加 sign 前的 Dio 规范化 URI，**实际摘要输入为其 `Uri.path`，不是完整 URL**。Kotlin URI 桥已对 7 组 Dart/Dio fixture 与 Ktor URLBuilder roundtrip 做一致性验证。
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

- Kotlin 核心 52 项测试通过、0 失败/跳过，源码安全准备 4 项通过。
- Android 编译、UI 编译、打包与上传已成功。构建 42443902879 的红色结论来自之后提交报告失败，不是编译失败。
- APK 已实际放入 Code：[`downloads/animeko/`](../../downloads/animeko/)，配套 SHA256SUMS、build.json；本地重新拉取并校验通过。基础 applicationId `me.him188.ani.lanerc`，debug 实际安装包名 `me.him188.ani.lanerc.debug2`（已解析 APK 二进制清单核对），最低 Android 8.1 / API 27，arm64 debug 签名。
- Code APK 的实际版本以 `downloads/animeko/build.json` 的 `source_commit` 为准，不能用当前分支 HEAD 替代；`native_comments_ui_in_source` 表示该包对应源码是否含原生评论界面。
- 新增播放器评论页独立 Lanerc 作品评论切换入口，使用选中媒体的原版 `vod_id`，而非 Bangumi ID；仅原生 Lanerc 源可请求。保留 Animeko 评论，支持手动选择、分页、失败重试，切换媒体取消旧请求，不显示敏感后台错误。**桌面宿主编译及 6 项合成回归已通过；Android 新构建、真机与生产后台仍需分别验证。**
- 弹幕新增只读列表，并恢复原版渲染映射：position == 1 为 top，其余为 scroll（0x9231e8..0x923204 和枚举池 0x1ef78/0x1ef80）。已接入播放器原有时间线、源开关、时间偏移、过滤和列表，按选中源/原版媒体 ID 查询，换集取消旧请求，不写进 Bangumi 键控缓存。此桥接已通过桌面宿主编译与时间线回归，Android 新构建仍待验证；发送和原版用户登录未接入。
- 构建不嵌入恢复密钥或生产凭据。现有 APK 不是无需配置即可播放的成品，也没有真实播放成功的证据。

Actions UI 工作流执行 6 项合成回归：保留原评论、显式加载/切源清空、弹幕独立加载、顶部/滚动及时间映射、非原生选择清空、换集请求取消。结果须以实际报告为准，不因提交测试代码就声明通过。

### 最近已确认与正在执行的验证

- 核心 52 项测试：0 failures/errors/skipped，包含按源长度分隔凭据命名空间，防止清除 `source` 时误删 `source.child`；旧凭据仅在源+origin 的 KeyStore AAD 校验通过后兼容读取/清除。
- Actions 42448105586：真实宿主桌面 Compose 编译及 6 项 UI/时间线测试全部通过；工具链按上游要求切换为 JBR/JCEF 21，而非 Temurin 冒充桌面依赖完整。
- Python 源码安全与 APK 交付回归本地共 13 项通过；不等于设备测试。
- Android KeyStore 新增 3 项 API 30 x86_64 模拟器测试：Unicode 往返/随机 IV、源与 origin AAD 隔离、篡改/截断拒绝；已交由独立 Actions，**尚未宣称通过**，不含生产材料。
- 验证码不再默认替用户选择第 1 项，允许按原图实际编号手选；原版编号基数未生产核实，不能把合成测试当作真实验证码成功。

### 签名输入纠正与生产探测边界

进一步核对拦截器发现 `Uri.parse(...).path` 取值此前被误认成完整 URI；健康探测硬编码 `/app/health@` 也与路径输入吻合。旧签名 fixture 的跨语言一致性只能证明大家计算相同输入，不能证明选对了 native 字段。现已修正 Kotlin、Python 与 Dart CLI/fixture 生成器，并交给 Actions 重新验证；之前的成功计数不用于声称此修正已经验证。

通过临时 runner 公钥封装预签名请求，在不把恢复的客户端 MD5/AES 密钥交给 CI 的情况下开始真实接口探测；响应只以分析接收者 CMS 密文保存。首次完整 URL 摘要的 captcha 请求得到 HTTP 404（空 body），不是有效验证码或播放成功。后续按路径签名的探测与新版 APK 必须单独核验。公开元数据不含签名值、challenge/guest credential 或播放 URL。


### 真实接口与设备验证更新

- API30 x86_64 模拟器的 3 项 Android KeyStore 测试现已实际通过（run 42449550833）；这不等于实体设备播放验证。
- run 42450351022：原版 `/app/v2/vod/{id}`、搜索、POST 访客验证码、评论与弹幕全部取得 HTTP200；本地用原版顺序字符替换和 ECB 密钥成功解码，业务 code 为 201。详情为 4 条线路/112 集，评论页含 16 条评论与 2 条回复，弹幕共 5505 条。公开报告仅保留字段、数量和响应 hash，不公开用户内容、挑战 ID、原始明文或恢复密钥。
- 已加入完全脱敏的 schema 回归 fixture 和 3 项 Kotlin 测试，交由 Actions 验证；不冒充完整生产响应测试，也不嵌入真实密钥。
- 之前详情探测器仍允许错误的 `/app/vod/{id}`，虽宿主常量已修成 v2，却未同步探测策略。现已对齐，并加入跨文件路径一致性回归。
- 验证码图像获取成功不等于完成真人验证。没有自动猜解验证码，没有取得 guestCredential，也没有宣称真实播放成功。原发布私钥已从验收阻塞项移除，修改版采用独立签名。

真实详情还发现旧 128 字符资源 ID 上限会拒绝样本全部 112 集（实际令牌长 218～320 字符）。已统一修正详情、媒体创建、社区身份和播放请求为有界 4096 字符 URL-safe opaque token；脱敏样例保留长度而不保留原令牌，加入超长、路径穿越、控制字符及请求 body 隔离回归。新修改等待 Actions，不据此声称生产播放成功。
