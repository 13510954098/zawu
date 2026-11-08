# 独立库兼容性验证与离线签名工具

## 已取得的结果

2026-11-08，GitHub Actions run [42440460276](https://github.com/13510954098/zawu/actions/runs/42440460276) 实际完成独立参考验证：31 项测试通过、0 失败、0 跳过；本地再次运行也通过。随后 run [42440603608](https://github.com/13510954098/zawu/actions/runs/42440603608) 加入离线签名 CLI 集成检查，最终 **34 项测试全部通过、0 失败、0 跳过**，其中 CLI 对全部 7 组 URI 完成真实进程调用测试，另外检查旧签名拒绝与错误输入不泄露。机器记录见 `reference-validation.json`。本地未安装 Dart，新增 3 项 CLI 测试在本地跳过，已在该 Actions 中实际执行。

- Dart 3.9.2 / encrypt 5.0.3 生成公开合成 AES-GCM、AES-ECB/PKCS7 数据，Python 工具成功解密；包括 GCM 外层响应与内层播放消息。
- Dart Dio 5.9.0 / crypto 3.0.6 生成 7 组 URI 与 MD5 签名，覆盖前导斜线、已有 query、中文、空格、布尔值、列表、null、路径规范化、绝对地址。Python 签名工具使用这些规范化 URI 时全部匹配。
- 官方 protoc 生成类与手工解析器完成 500 组外层、100 组内层消息对照。
- 修复实际发现的差异：已知字段号遇到不匹配的 wire type，应像官方生成类一样作为未知字段跳过。坏 tag、越界长度、截断 varint 和不支持的 groups 仍被拒绝。

重要细节：Dio 将示例 base `https://example.invalid/api/` 与 path `/app/config` 合并为 `/api/app/config`；不能直接用 Python `urljoin` 的前导斜线行为代替。中文、空格及 query 顺序也影响签名。

## 离线签名 CLI

`reference/lanerc/bin/sign_offline.dart` 直接使用上述固定版本的 Dio 规范化，不发送 HTTP 请求。它从本地恢复材料读取 `request_signature.secret_suffix`，不打印密钥；输出的签名和 URL 仍属于敏感请求信息，不要提交仓库或公开日志。

先安装 Dart 3.9.2，在仓库根目录执行依赖安装（仅此步骤需要包下载）：

```sh
cd reference/lanerc
dart pub get
cd ../..
```

请求描述示例（示例地址不会用于真实服务）：

```json
{
  "baseUrl": "https://example.invalid/api/",
  "path": "app/config",
  "queryParameters": {"q": "雪 空"},
  "timestamp": 1700000000,
  "nonce": "abc"
}
```

将自己的请求描述保存为 `.local/lanerc/request.json`，然后从仓库根目录运行：

```sh
umask 077
REQUEST="$PWD/.local/lanerc/request.json"
MATERIAL="$PWD/.local/lanerc/recovered-secrets.json"
OUTPUT="$PWD/.local/lanerc/signed-request.json"
(cd reference/lanerc && dart run bin/sign_offline.dart "$REQUEST" "$MATERIAL") > "$OUTPUT"
```

示例时间戳已过期；实际使用须自行提供当前 Unix 秒和三位小写字母 nonce。已有 `sign` 参数会被拒绝，避免把旧签名再次签入。工具输出签名前的规范化 URI、`sign` 值及添加签名后的 URI；没有自动请求、验证码处理、凭据获取或媒体访问功能。

## 验证范围与剩余缺口

- fixture 只含公开 dummy key、dummy suffix 和 `example.invalid`；不使用私密恢复材料。
- Dart 版本来自 APK 分析；所选 Dio/encrypt/crypto 版本是固定的参考版本，尚未确认等于 APK 的具体依赖版本。
- 这些结果证明恢复工具与固定公开库及重建 wire schema 的互操作，不是运行原 APK，也不是生产服务接受请求的证明。
- 真实公开 TXT 解码到 `v3.yyghk.com` 的结果见 `PUBLIC_VALIDATION.md`，与合成加密测试分开记录。
- 仍未取得有效 `guestCredential` 或生产播放响应；尚无端到端播放成功记录。
- 发布签名私钥仍不能由 APK 公钥证书推导，需要原 keystore 或备份。
