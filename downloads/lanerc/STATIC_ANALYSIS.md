# Lanerc 源码与 APK 初步静态比对

仅静态读取文件，未运行 APK、未调用生产接口、未验证凭据有效性。未提取或公开任何有效私钥/令牌。

## 输入与完整性

- 源码：远程分支 `arena/f32564a0-zawu` 的 `lanerc-source.zip`，99 个条目。
- APK：用户提供直链，105357759 字节。
- APK SHA-256：`4368de63ae2003138dbe63b673422a3b3a5414ab652ffb1feb3424964f88bcfd`，本地合并后与下载报告一致。

## 身份与构建差异

| 项目 | 源码 | APK |
| --- | --- | --- |
| Android 包名 | com.cleanroom.lanerc | com.clggjv.xcjfmd.ffo |
| 版本 | 1.0.8+32 | versionName 1.0.8 / versionCode 32 |
| targetSdk | 35 | 36 |
| 框架 | Flutter / media_kit | 包含 libflutter.so、libapp.so、libmpv.so |
| 存储线索 | sqflite、shared_preferences | 包含 libisar.so（不能仅凭文件断定所有存储用途） |
| 签名 | release 使用 signingConfigs.debug | META-INF/LANERCX3.RSA 公共证书 |

源码 README 和 pubspec 明确标记为 Clean-Room 重建，README 明确声明不包含私有密钥/盐值。不能把该压缩包当作“仅删除密钥的原版完整源码”。

APK application 类为 `off.dmfjcx.vjgglc.moc.StubApp`，仅凭命名不能确定是否加壳或具体保护方案。

## 密钥排查结果

- 源码中未找到 `.jks`、`.keystore`、`.pem`、`.p12`、`.pfx`、`.key`、`key.properties`、`.env` 文件。
- `android/app/build.gradle:31` 使用调试签名，而非原版发布密钥配置。
- `api_service.dart` 未见 Authorization 请求头、HMAC 签名、AES 请求加密实现；存在演示数据和自建服务接口逻辑。
- `doh_bootstrap_resolver.dart` 实现标准 DoH TXT/HTTPS 回退，不包含恢复私有密钥的逻辑。
- `server/server.py` 中的 SHA-256 是密码摘要处理；`local_database.dart` 的 SHA-256 用于文件校验，均不能视作遗失密钥。
- APK ARM64 libapp.so 中存在 AES、HMAC、Authorization、encrypt、token 等关键词；关键词存在不足以确定具体算法、凭据值、有效性或调用位置，不将第三方 SDK 字符串误报为应用密钥。

## 接口字符串对照

源码提取的 17 个接口字符串中，12 个在 ARM64 libapp.so 中按完整字节匹配，包括 `app/config`、`app/home`、`app/v2/play`、`app/chat/barragev2` 等。

未完整匹配：`app/auth/login`、`app/auth/register`、`app/chat/comments`、`app/feedback`、`app/v2/vod/$vodId`。其中最后一项含 Dart 插值表达式，未匹配不能说明运行时接口不存在。字符串匹配不能证明协议或源码完全相同。

## 可恢复的公开签名信息

从 APK v1 签名块读取的 X.509 证书 SHA-256 指纹：

`74:32:2D:4D:62:B9:F4:A9:86:DF:A8:97:3E:E7:0E:BC:03:4E:74:55:1B:87:15:C7:55:ED:D9:ED:18:E6:82:0B`

有效期：2025-07-26 06:02:55 GMT 至 2052-12-11 06:02:55 GMT。

这是公开证书信息，不是私钥；本次未独立验证全部 APK 签名方案，也不能从该证书反推出发布签名私钥。

## 结论与下一步

尚未找回任何经验证的业务密钥、发布签名私钥或生产令牌。主要阻碍是现有源码为净室重建版本，与 APK 存在实质差异。应优先查找原始项目、构建机 keystore、CI Secrets 备份和服务端配置；若目标是 API 签名或数据解密，需要明确相关报错、原始请求/响应的脱敏样例或原始加密模块，才能定位调用链，不能凭关键词猜测密钥。

## 第二轮：三类恢复目标分别排查

### A. 发布签名

检查了当前仓库 4 个 ZIP、源码 ZIP、APK 文件路径，以及当前本地可见 Git 历史中的文件名，均未发现常见 keystore / 私钥扩展名或 key.properties。这个检查不覆盖 GitHub Secrets、其他设备、未获取的历史，也不能排除改名、嵌套归档或加密备份。

目前能恢复的仅有公开签名证书及指纹，不能恢复签名私钥。后续应按上面的证书指纹核对旧构建机/备份里的 keystore；不要把 keystore 或密码提交到公开仓库。若使用 Google Play 应用签名，应区分可申请重置的上传密钥和由 Google 保管的应用签名密钥。

### B. API 请求签名

在 APK `lib/arm64-v8a/libapp.so` 中找到 `buildSignature` 文本，文件偏移为 `0x3ea91` 和 `0x8d5da`。这些是字节位置，不是函数入口地址，也未证明该名称属于业务请求签名（可能存在框架/库同名函数）。同时存在 Authorization 字符串，但没有证据表明它与上述名称相关。

源码中未找到相应业务请求签名实现，不能从净室源码重建原版算法。需要进一步分析 Flutter AOT 的对象池、交叉引用与调用链，确认输入字段、排序/编码、时间戳、摘要算法以及候选常量的使用位置。在调用链确认前，不猜测或宣称任何字符串为有效签名密钥。

### C. 接口数据解密

APK ARM64 库中存在 AES、CBC、GCM、PKCS7、SHA-256 等字节标记，以及 AEAD、Poly1305 等通用加密库错误文本。这证明打包内容包含相关算法线索，但无法证明业务接口使用哪种算法，尤其不能仅凭字符串判断 key / IV 或确认其有效性。

APK 还包含独立广告/设备信息相关 native 库，必须避免把 SDK 自身加密误当作业务协议。下一步需确认网络响应解码调用链中的 base64/解压/加密顺序、模式、填充、IV/nonce 来源、是否使用会话派生密钥及服务端下发参数。Android Keystore 中由设备生成且不可导出的密钥不能仅凭安装包恢复。

### 当前交付边界

- 已完成输入文件完整性校验、身份/构建差异核对、常见密钥文件路径排查、公共证书读取、接口字符串对照和算法标记初筛。
- 未完成 Flutter AOT 反编译/调用链重建；未运行 APK、未抓取网络流量、未尝试访问生产接口。
- 三类目标均已纳入排查，但目前没有任何“已找回且可用”的私钥、API 签名密钥或数据解密密钥。
