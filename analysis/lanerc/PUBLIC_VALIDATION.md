# 实际公开配置核验：DoH TXT 已解码到 v3.yyghk.com

## 本轮实际执行的检查

2026-11-08 UTC，通过 GitHub Actions 取得公开 DNS TXT，并对用户明确指定的两个域名执行不带凭据的 HTTPS `HEAD /`。随后在本地使用静态恢复的 TXT 专用密钥解码保存的公开 TXT 数据。

运行记录：https://github.com/13510954098/zawu/actions/runs/42439813047

没有发送恢复的通信签名，没有请求验证码、访客凭证、播放接口或媒体，没有关闭 TLS 证书校验，也没有跟随重定向。

## 已得到真实数据支持的结论

1. `dohx.lanerc.moe` 的公开 TXT 查询返回一条记录（本次 DNS 状态 0）。TXT-only 域名的 `HEAD /` 因没有可解析的 Web 地址失败，并不与 TXT 可用相矛盾。
2. 进一步沿 APK `0x96d9e8` 的 TXT 解码函数发现独立密钥：对象池 `0x11d00`，32 字节，AES-256-ECB / PKCS7，模式来自 `0xc4a0`。这与普通响应 ECB 密钥、播放 GCM 密钥均不同。
3. 使用该密钥处理**本次实际取得的公开 TXT**：Base64、PKCS7 padding、UTF-8 检查均通过，解码内容的 HTTPS 主机名为 **`v3.yyghk.com`**。
4. 对 `https://v3.yyghk.com/` 的无凭据 HEAD 请求返回 HTTP 404，说明该检查时刻能建立 HTTPS 并获得 HTTP 响应。**根路径 404 不能判定 API 不可用，也不能证明 API/播放可用。**

该 TXT 专用密钥 SHA-256 指纹：

`34dc9de848c3fe72706e4a74a02d4d47596f43c0da78867ab17897f44069f29c`

实际值已补入私密恢复文件的 `bootstrap_txt_encryption` 节，不明文提交 Git。

## 验证边界

这次不再只是“APK 中发现了域名字符串”，而是完成了 **实际公开 TXT -> APK 对应密钥解码 -> 预期主机名** 的配置链验证。

但 AES-ECB 本身不提供认证，公共 DNS 响应没有在本次报告中证明 DNSSEC 身份认证；padding/可读 URL 和主机名匹配不能证明域名所有权或受保护业务授权。因此报告不会将它表述成“整个现网已经打通”。

本次随机诊断子域名 TXT 查询为 NXDOMAIN，不能据此认定客户端所有前缀/回退策略失效；主域 TXT 本次有结果。

## 可复现的文件与工具

- `public-connectivity.json`：DNS/HEAD 观测，仅导出脱敏元数据。
- `bootstrap-validation.json`：实际 TXT 的离线解码检查，仅导出主机名及摘要，不含 URL 路径/查询参数。
- `public-dns-records.p7m`：CMS 加密后的 DNS 原始记录；明文仅在被 Git 忽略的本地 `.local/lanerc/` 中。
- `scripts/lanerc_validate_bootstrap.py`：离线验证器；无网络访问，不请求任何凭证或媒体。

```sh
python scripts/lanerc_validate_bootstrap.py \
  --records .local/lanerc/public-dns-records.json \
  --secrets .local/lanerc/recovered-secrets.json \
  --expected-host v3.yyghk.com \
  --output analysis/lanerc/bootstrap-validation.json
```

公开诊断 runner 没有使用恢复的密钥；密钥只在取回加密记录后于本地使用。`public-connectivity.json` 中 `recovered_keys_used: false` 仅描述 runner 的公开 DNS/HEAD 检查，不描述后续的本地解码步骤。

## 当前能交付什么

- 已静态恢复：请求 MD5 签名后缀、普通响应 ECB 密钥/字符替换链、播放 GCM 密钥、独立 TXT ECB 密钥。
- 已验证：公开后端配置发现链真实解码成功；21 项离线合成测试通过。
- 未验证：现网请求签名是否被服务器接受、真实受保护响应是否与重建工具兼容、有效访客凭证、播放授权或链接可访问性。
- 无法从 APK 推导：发布签名私钥；服务器尚未签发的动态访客凭证。

不能在没有真实受保护响应或可控制的测试后端的情况下，把剩余部分伪装成“已完成”。当前没有启动会无限重试、自动解验证码或获取受保护媒体的后台任务。
