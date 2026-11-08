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

- 请求 MD5 签名，要求传入**添加 sign 前的准确 Dio 规范化 URI**。当前不把 Ktor 的 URL 编码冒充已验证的 Dio 行为。
- 三套独立密钥的用途隔离：播放 GCM、普通响应 ECB、公开 TXT ECB。
- GCM `nonce[12] || ciphertext || tag[16]` 认证解密；普通响应按顺序字符替换、Base64、ECB/PKCS7 解码。
- 限长 Protobuf wire 解码、未知字段与不匹配 wire type 跳过、重复字段最后值生效、int32 符号处理、非 200/空 URL 拒绝。
- 私密材料与导出的源定义分离；密钥防御性复制；敏感对象的 `toString` 脱敏。
- Android/桌面使用 JVM JCE。iOS 加密实现尚未接入。

### 动态内置源发现

`LanercBootstrapPlan.builtIn()` 内置原 APK 的 TXT 域名池与 DoH provider，不把当前 `v3.yyghk.com` 固定成源地址。发现引擎接收注入的 HTTP transport，按原版 TXT ECB 逻辑解码、检查 HTTPS URL，并按 DNS TTL 缓存；失效后失败不会返回演示数据或无限复用旧地址。同一源的并发发现去重，不同源不共享缓存。

这是发现逻辑，不是已经接入 APP 的完整“内置源”。HTTP transport、私密材料的本机加载、源注册与 UI 仍需连接。加密 TXT 本身不等于 DNSSEC 或后端来源认证；后续凭据必须绑定源与后端 origin，不能跨源转发。

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
- `app/v2/guest/captcha`、`app/v2/guest/credential`、`app/v2/guest/play` 与 `playResolveProtobuf` 的已确认部分可复用，但验证码提交字段、用户会话、评论/弹幕完整模型仍需还原。
- 2026-11-08 对 APK 中两条公开后备配置地址进行了无凭据 GET，两条均网络失败，**没有取得配置内容**。见 `analysis/lanerc/public-source-config.json`；不能把网络诊断成功运行说成取得真实源文件。

## 未完成的验收项

- [ ] 原版源文件导入/导出兼容、异常格式回归样本。
- [ ] Animeko 的源注册、独立持久化、设置入口与三模式 UI；保留原源设置与订阅。
- [ ] Android 本机密钥加载/安全存储、按源与 origin 隔离凭据、真实 URI 规范化桥接。
- [ ] 搜索/详情/剧集协议适配及现有 MediaSource/ApiVideoResolver 播放链连接。
- [ ] 合法验证码交互、guestCredential 生命周期与生产播放验证。
- [ ] Lanerc 弹幕加载/发送、评论列表/分页/回复及登录要求，与 Animeko 原有服务分开。
- [ ] 可安装 Android APK、UI 自动化、真机播放与回归测试。

当前是可编译并有测试的集成基础层，**不是已完成的 APP 修改版**。最新执行结果见 `analysis/lanerc/animeko-core-validation.json`；字段明确区分核心测试、Android 构建、UI 集成及原版格式验证。

## 本轮实际执行

GitHub Actions [42442665479](https://github.com/13510954098/zawu/actions/runs/42442665479) 已完成：**29 项 Kotlin 测试全部通过、0 跳过**；另执行 4 项源码解包安全测试，并下载、校验、还原固定版本 Animeko 与源码 overlay。未构建 Android APK，未运行 Animeko UI，未接入生产账户或媒体。
