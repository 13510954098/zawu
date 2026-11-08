# 本轮恢复结果：已重建响应密钥与请求签名材料

> **后续更新：另已恢复普通响应的独立 AES-256-ECB 密钥/字符替换链，并还原 playResolveProtobuf 消息结构与访客凭证模型。GCM 密钥的准确用途为播放 protobuf 加密 data 字段，不能泛称覆盖全部通信。最新结果与未完成项见 `PROTOCOL_FINDINGS.md`。**

适用输入：APK SHA-256 `4368de63ae2003138dbe63b673422a3b3a5414ab652ffb1feb3424964f88bcfd`。

## 结果概览

| 目标 | 结果 | 验证边界 |
| --- | --- | --- |
| 响应加解密 | 从实际初始化调用链重建 32 字节 AES 密钥；模式定位为 AES-GCM | 静态确认材料来源；未使用生产响应验证 |
| API 请求签名 | 找到 17 字符固定后缀，重建 MD5 签名拼接及 sign 参数格式 | 静态确认拦截器逻辑；未向生产服务发请求 |
| Android 发布签名私钥 | 未找回；只有公开签名证书 | 私钥不能由 APK 的公开证书反推 |

私密值已写入本地 `.local/lanerc/recovered-secrets.json`，权限 `0600`，并受 `.gitignore` 排除。**没有把明文密钥、签名后缀或私密恢复文件提交到 Git。请及时下载并自行安全备份；`.local` 不作为跨会话持久备份。**

## 1. 响应解密密钥：不是关键词猜测

通过修改固定版本分析器，仅补充静态字段初始化入口元数据，定位到：

```text
UQa._AJg（静态 encrypter 字段，偏移 0x121c）
  initializer: 0x60c4d8
    -> 0x63298c（密钥字节重建）
      -> 对象池 0xe238：4 组、每组 16 个半字节
    -> 0x60c548（AES 构造）
      -> 对象池 0xc4c0：AESMode.gcm
```

`0x63298c` 对总共 64 个半字节做结构检查，并在循环中执行高半字节左移 4 位、与低半字节按位 OR，逐字节写入 32 字节缓冲区。已按这段实际代码重建密钥，而非从随机字符串中猜测。

密钥 SHA-256 指纹（不是密钥本身）：

`13be23ee91145831a5167b0035af19efba0215c91703a2830411fc20d401234d`

原始二进制解密入口 `0x9163b4` 先检查至少 28 字节，再拆出前 12 字节作为 nonce，余下数据传给 GCM 解密。按该库默认 128-bit GCM tag，原始封包结构为：

```text
nonce[12] || ciphertext || authentication_tag[16]
```

**这里描述的是已解码的二进制封包**，不是保证可直接输入任何 HTTP 响应 JSON。外层 base64、JSON 字段、压缩以及每个接口的使用范围没有全部重建；不要把任意响应直接当作该封包解密。关联数据按当前调用的空/默认参数重建，仍应使用原项目测试样例确认。

## 2. 请求签名：固定后缀和拼接格式

实际请求拦截器入口：`0x7ee08c`。

主要证据：

- `0x7ee248` 调用 Dio 最终 URI getter（`0x4a979c`），涉及 baseUrl、path、queryParameters 及规范化。
- 时间戳由微秒时间两次除以 1000 得到秒值。
- `0x7ee4a8` 生成 3 个 `a`–`z` 字符组成的 nonce。
- `0x7ee2f4`–`0x7ee348` 拼接 URI、分隔符、秒值、nonce 和固定后缀。
- 固定后缀来自对象池 `0x11b70`，长度 17。
- `0x7ee358` 后经 UTF-8 编码和 digest 转换；对应 sink 初始化包含 MD5 的四个标准状态字，输出转十六进制字符串。
- `0x7ee3b4` 开始构建名为 `sign` 的参数，值以 `-` 分隔。

重建形式：

```text
digest = lower_hex(MD5(UTF8(canonical_uri + "@" + unix_seconds + "@" + nonce + secret_suffix)))
sign = unix_seconds + "-" + nonce + "-" + digest
```

**sign 位于查询参数，不是 Authorization 或自定义请求头。** 签名结果合并回 RequestOptions 的 `queryParameters`（字段偏移 `0x50`）；URI getter 在 `0x4a9930` 读取同一字段用于生成 query。应使用添加新 sign 参数之前的最终 URI；不要重复签入上一次的 sign。

签名后缀 SHA-256 指纹：

`d96c5bea92373a2048144fccb68f96fe8e913b4f992a13b559865f229886a92a`

同一后缀在 APK 的 ARM64、ARMv7、x86_64 三份 `libapp.so` 中均存在，已做离线比对，未公开字面值。

### 修正此前 buildSignature 线索

`buildSignature` 位于 appName、packageName、buildNumber、installerStore 等包信息字段组中，不能当作业务签名算法入口。真正业务签名的证据来自上述请求拦截器、MD5 调用、固定后缀与查询参数合并逻辑，而不是该字段名。

## 3. 本地工具与测试

源码工具不包含恢复出的真实值：

- `scripts/lanerc_recover_material.py`：从私密对象池转储重建材料，默认写入被 Git 忽略的私密文件，不打印值。
- `scripts/lanerc_offline_crypto.py`：离线签名与已解码二进制 AES-GCM 封包解密，无网络请求逻辑。
- `tests/test_lanerc_recovery.py`：6 个测试，使用公开的合成测试密钥/后缀，覆盖半字节重建、异常输入、签名拼接、GCM 往返和篡改拒绝，均通过。

示例（仅离线处理自有测试数据）：

```sh
python scripts/lanerc_offline_crypto.py --secrets .local/lanerc/recovered-secrets.json sign \
  --uri 'https://example.invalid/app/config' --timestamp 1700000000 --nonce abc

# 解密需安装 cryptography；输入应是已解码二进制封包
python scripts/lanerc_offline_crypto.py --secrets .local/lanerc/recovered-secrets.json decrypt \
  --input response-envelope.bin --output plaintext.bin
```

Python 工具不会自动替代 Dart URI 规范化：查询顺序、百分号编码、路径标准化等必须与原客户端一致。测试证明的是重建工具在合成数据上的行为，**不等于已在原 APK 中运行验证或在生产接口验证成功**。

## 4. 私密转储的处理

为在受限网络下私下检查对象池，本轮将原始转储在 GitHub runner 上用本地临时 RSA 公钥加密后取回。仓库中的 `private-bundle.p7m` 是 CMS 加密文件，公开证书 `analysis-recipient.pem` 不含解密私钥。私钥和解密后的转储只放在被忽略的 `.local/lanerc/` 中，不公开。此前 FINDINGS.md 中“原始转储仅在 runner 存在”的说明现已由本处理方式取代。

## 5. 无法完成的一项与安全建议

发布签名私钥仍然需要原 keystore、构建机备份，或发布平台提供的相应密钥管理/上传密钥重置流程。恢复业务签名后缀和响应 AES 密钥，不能生成同一发布者签名，也不能替代 keystore。

建议将已在客户端内置的固定后缀和共享响应密钥视为可提取凭据，恢复业务后轮换并评估协议迁移。此报告不把静态找到的材料描述为已验证有效的生产凭据。
