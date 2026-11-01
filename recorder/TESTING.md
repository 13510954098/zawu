# 验证记录（2026-11-01）

## 本次交付

- APK：`delivery/lanerc-local-recorder-debug.apk`（48,992 bytes）
- SHA-256：`6d3aa65e8f9c1d4779f945ddc290e2de1d4a27dbb26d7700ea35d56b308c1df9`
- 源码/测试快照：`b83ce34`；APK 发布提交：`904bba3`
- GitHub Actions：https://github.com/13510954098/zawu/actions/runs/41287107206
- `debug-apk` 和 `android11-smoke` 均成功。Artifact 分别为 `lanerc-local-recorder-debug`、`android-lint-report`、`android11-smoke-results`。

## 已实际通过

- JDK 17 / Gradle 8.9 / Android Gradle Plugin 8.7.3：assembleDebug、lintDebug。
- Android 11 API 30 x86_64 AOSP default 模拟器，不含 Google Play 服务。
- 实际系统 MediaProjection 授权对话框：拒绝后不生成视频，报告标注未授权。
- 拒绝录屏情况下停止会话并创建 ZIP，检查 report.txt、events.jsonl 存在，screen.mp4 不存在。
- 通过系统对话框同意录屏，确认录制启动状态。
- 暂停和继续记录状态切换。
- 通过 AOSP 测试镜像 root shell 的系统 Binder 接口撤销 projection，确认回调停止会话。此 root/shell 只属于 CI 测试，安装后的记录器不需要也不调用 root/ADB。
- 中断后 screen.mp4 文件非空，并出现在 ZIP 中。**这不是视频回放/内容质量验证。**
- 本地静态检查：无 INTERNET/RECORD_AUDIO/READ_PHONE_STATE/MANAGE_EXTERNAL_STORAGE 权限；目标包 queries 配置；无障碍实现无读取文本/描述及执行点击 API；wrapper JAR 和 APK 基础结构；本地重新计算 SHA-256 与交付校验文件相符。

早期模拟器脚本因创建重复 Activity 导致授权结果接收错误，修正后上述最终运行成功。不能把早期失败运行当作最终通过结果，也不能把源码已有实现当成真机验证。

## 尚未验证，需用户在 Android 11 真机执行

1. 安装 Lanerc，启用本记录器无障碍；开始后是否正确拉起目标，实际 Flutter/广告节点能读取多少；未安装时提示的视觉体验。
2. 点击广告并观察权益变化（全由用户完成），在备注中记录次数和重启后状态。记录器不判定或伪造奖励成功。
3. 悬浮窗允许/拒绝两种情况下，分别用悬浮按钮和通知结束。拒绝所有授权时确认无虚假采集声明。
4. 点击“导出 ZIP”，在系统文件选择器选本地 Download 等位置，保存后用文件管理器打开。模拟器脚本只验证 ZIP 生成，不验证 SAF UI 点击和 DocumentProvider 的实际写入。
5. 视频播放完整性、时间与 UI 事件对齐、转屏、Flutter 节点、密码字段过滤、通知敏感画面、安全窗口黑屏。
6. 系统录屏指示器手动停止、厂商后台限制、低空间、进程被杀/强制停止后的恢复导出、长时录制。CI 的系统 Binder 撤销不等价于所有厂商中断场景。
7. 一键删除后应用内记录确实移除；外部保存/分享副本需手动删除。

## 重要边界

无法可靠自动检测第三方安全窗口原因，只能明确报告可能黑屏、请人工核验。录像没有图像脱敏，分享前请检查。无障碍为避免泄漏而完全省略文本，因此报告不能自动从文本提取权益变化。

Debug APK 仅用于测试。不同 CI runner 的临时 debug 签名可能不同；以后升级若提示签名不一致，请先导出重要记录，再卸载旧版安装新版（卸载会清除本地记录）。不要把测试版用于生产分发。
