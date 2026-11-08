# 后续离线协议分析：已确认与仍无法确认的部分

> **最新公开配置验证：2026-11-08 已实际取得并用独立 TXT 密钥解码公开 DoH 记录，得到 `v3.yyghk.com`。这取代下文此前“未查 DNS/未确认关联”的历史状态，但不代表已验证受保护 API 或播放。详见 `PUBLIC_VALIDATION.md`。**

输入仍是用户直链 APK，SHA-256 为 `4368de63ae2003138dbe63b673422a3b3a5414ab652ffb1feb3424964f88bcfd`。仓库未发现另一个名为 sample.apk 的文件，不能假定不同版本结果相同。本轮未访问现网、未请求或伪造 guestCredential、未执行验证码识别或媒体下载。

## 一、重要修正：响应解密有两条不同路径

此前只还原的 AES-GCM 密钥，准确用途是 `playResolveProtobuf` 路径中加密的 `data` 字段，**不能将其称为覆盖所有通信响应的唯一解密密钥**。

本轮确认普通响应还有另一套独立处理：

| 路径 | 静态证据 | 当前结果 |
| --- | --- | --- |
| 普通响应 data 字符串 | `0x957bf8 -> 0x7ed7d8` | 已重建第二个 32 字节密钥、顺序字符替换表、base64/AES-256-ECB/PKCS7 链 |
| `playResolveProtobuf` | `0x95794c -> 0x7ed914` 判断 codec；`0x957960 -> 0x916070` | 已重建外层/内层消息字段及条件 AES-256-GCM 解密链 |

普通响应的处理函数 `0x7ed7d8` 做 10 次顺序字符替换，再用对象池 `0x133a0` 的 UTF-8 字符串构建 32 字节 key；AES 模式对象 `0xc4a0` 是 `ecb`，构造默认 padding 为 PKCS7。随后走 base64 解码、AES 解密、UTF-8 解码。顺序替换不能擅自改成一次并行字符翻译。

第二个密钥的 SHA-256 指纹：

`9c1f3067e0376feb3b407b16118c3a033fbc4f777529724ee9606e9f375cfb3b`

实际值及字符映射已补入 `.local/lanerc/recovered-secrets.json` 的 `json_response_encryption`，不明文提交到 Git。ECB 没有认证能力，padding/UTF-8 检查通过不能证明响应真实。

## 二、guest/captcha 与 guestCredential：已确认真实数据流，未取得有效凭证

不是仅凭错误文案推测：已定位请求、响应模型和播放调用中的使用。

### 1. 挑战响应

- APK 内接口标识：`app/v2/guest/captcha`；请求调用位置 `0x920068`。
- 解码模型：`QRa.cJc`，入口经 `0x660e24 -> 0x660e58`。
- 模型读取字段：`challenge_id`、`image`、`option_count`、`expires_in`。

这里的 `image` 是字符串字段，不能仅凭字段名断言特定图像编码或验证码题型。

### 2. 凭证响应

- APK 内存在 `app/v2/guest/credential` 接口标识。
- 响应模型：`RRa.cJc`，`0x6a2910 -> 0x6a2944`。
- 模型读取 `guest_credential`、`expires_in`、`expires_at`；关键字段缺失/不满足校验时有 FormatException 分支。
- 已确认这些是服务端响应中读取的值；未在本轮获取任何可用的访客凭证。`expires_in` / `expires_at` 的单位和服务器约束未由字段名推定为已验证事实。

### 3. 播放请求使用

- 游客播放标识：`app/v2/guest/play`。
- `0x923978`、`0x92398c` 附近构建请求数据，包含 `resource_id` 和 `guest_credential`。
- `0x923924` 检查凭证字符串非空，空值走 `0x923a40` 的 `guestCredential 不能为空` 错误。
- 请求 extra 中设置 `responseCodec: playResolveProtobuf`，从而选择专用二进制解码路径。

**guestCredential 不是从静态 APK 中找到一个固定常量就可恢复的“主密钥”。** 已还原模型和使用位置，不代表拥有服务器签发的可用值，也没有绕过验证、凭证过期或资源授权。

## 三、playResolveProtobuf：已还原消息字段与解码链

### 外层：PlayResolveResponse

描述符初始化函数 `0x60bf10` 及其辅助函数给出字段号和类型；运行时 PbFieldType 位值对应 int32=`0x800`、string=`0x40`、bool=`0x10`、bytes=`0x20`：

| 字段号 | 名称 | 类型 |
| --- | --- | --- |
| 1 | code | int32 |
| 2 | msg | string |
| 3 | encrypted | bool |
| 4 | data | bytes |

### 内层：PlayResolve

描述符初始化函数 `0x60b630`：

| 字段号 | 名称 | 类型 |
| --- | --- | --- |
| 1 | playUrl | string |

已提供 wire-compatible 的 `reconstructed_play_resolve.proto`。原始 .proto 的 syntax/package/options 没有恢复；文件选择 proto3 以便互操作，不声称是原始源码。

### 已确认调用顺序

```text
responseCodec == playResolveProtobuf
  -> 接收字节数组，解析 PlayResolveResponse
  -> code 必须为 200，否则走错误分支
  -> 读取 data
  -> encrypted == true 时，调用 0x9163b4 做 AES-256-GCM 解密
       nonce[12] || ciphertext || tag[16]
  -> 将明文/未加密 data 解析为 PlayResolve
  -> 读取并 trim playUrl，空值抛错
```

这恢复的是客户端响应消息和解码流程，**不是对服务器签发链接、CDN 鉴权、每条流的可访问性或额外 DRM 的验证**。

## 四、后端发现：确认静态 DoH 引导链，不能声称验证现网后端

- 引导域名列表（对象池 `0x11c30`）：`dohx.lanerc.moe`、`doh.lanercdns1.cc`、`doh.uminadns2.cc`。
- DoH 提供者列表（`0x11c38`）含 doh.pub、dns.alidns.com、doh.360.cn、1.12.12.12、223.5.5.5、dns.google 的 HTTPS 地址。
- `0x96d42c` / `0x96d448` 读取域名列表；查询拼接包含 `&type=txt`，随后读取 DNS JSON 的 `Answer`。
- 此链说明客户端可以运行时发现地址，静态域名池不必等于最终 API 主机。

已将整个 APK 的 ZIP 条目逐个解压，搜索 `v3.yyghk.com` 的 UTF-8/ASCII 和 UTF-16LE 字节，均未匹配。这个结论**不覆盖加密、其他编码、拼接或运行时下发**。没有执行 DNS/HTTP 查询，因此不能确认它是否为当前后端，更不能仅因用户提到该域名就将其写作已验证事实。

## 五、离线工具、验证与私密值

- `scripts/lanerc_play_proto.py`：限长、边界检查的本地消息解析器；支持普通 protobuf wire type 0/1/2/5，拒绝 group；可使用独立提供的密钥解码本地加密样例，输出私密文件，不发请求、不获取媒体。
- `scripts/lanerc_offline_crypto.py`：新增 `decrypt-json-response`，输入应为本地响应的编码 data 字符串，不是整个 HTTP JSON 包。
- `scripts/lanerc_recover_material.py`：可同时恢复签名后缀、GCM 密钥和普通响应 ECB 密钥及替换表。
- `tests/test_lanerc_recovery.py` + `tests/test_lanerc_play_proto.py`：共 13 项合成数据测试通过，含 protobuf 默认值/重复字段/未知字段/截断/超长 varint、两类加密往返和 GCM 篡改拒绝。

示例（仅本地自有测试样例）：

```sh
python scripts/lanerc_play_proto.py --input play-response.bin \
  --secrets .local/lanerc/recovered-secrets.json --output .local/lanerc/play-decoded.json

python scripts/lanerc_offline_crypto.py --secrets .local/lanerc/recovered-secrets.json \
  decrypt-json-response --input encoded-data.txt --output .local/lanerc/plaintext.json
```

**这些测试验证工具实现，不是原应用/现网服务器的端到端兼容性验证。** 没有生产样例的认证解密成功记录，不能把静态重建直接描述成“现网全部打通”。发布 keystore 私钥仍不可由 APK 公共证书恢复。
