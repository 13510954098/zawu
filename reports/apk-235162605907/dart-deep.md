# Dart AOT 深度结果（blutter）

- 引擎：Dart version: 3.5.4, Snapshot: 80a49c7111088100a233b2ae788e1f48, Target: android arm64
- 产物：`dart-pp.txt` 51044 行（Object Pool 全量导出）
- 常量字符串：13612 条，唯一 8421 条，其中中文 563 条

## 硬编码域名
| host | 次数 |
|---|---|
| `plugins.flutter.io` | 3 |
| `stackoverflow.com` | 1 |
| `promisesaplus.com` | 1 |
| `dns.alidns.com` | 1 |
| `doh.360.cn` | 1 |
| `admod.lizi.lat` | 1 |
| `adnet.lizimh.com` | 1 |
| `adnet.lizi.lat` | 1 |
| `lz-1382057604.cos.ap-hongkong.myqcloud.com` | 1 |

## 构建环境痕迹

- `file:///`
- `file:///Users/share/manga/.dart_tool/flutter_build/dart_plugin_registrant.dart`

## 明文接口清单（60 个）

```
/app/api/health
app/api/ad/reward/progress
app/api/ad/reward/query
app/api/category/list
app/api/chapter/v3/
app/api/collection/comic/add
app/api/collection/comic/remove
app/api/collection/comic/sort
app/api/collection/create
app/api/collection/delete
app/api/collection/detail?id=
app/api/collection/favorite
app/api/collection/mine/detail?id=
app/api/collection/mine?type=
app/api/collection/unfavorite
app/api/collection/update
app/api/collection/user?user_id=
app/api/comic/report
app/api/community/comment/create
app/api/community/comment/delete
app/api/community/comment/like
app/api/community/comment/unlike
app/api/community/comments
app/api/community/notification/read
app/api/community/notification/read-all
app/api/community/notification/unread-count
app/api/community/notifications
app/api/community/post/create
app/api/community/post/delete
app/api/community/post/detail
app/api/community/post/like
app/api/community/post/unlike
app/api/community/post/view
app/api/community/posts
app/api/community/posts/mine
app/api/community/posts/user
app/api/community/report
app/api/configv2
app/api/health
app/api/home/data
app/api/home/tab/data
app/api/order/create
app/api/order/list
app/api/order/query?order_no=
app/api/rank/list
app/api/search/full?q=
app/api/search/suggest?q=
app/api/user/info
app/api/user/like
app/api/user/likes?sort=
app/api/user/login
app/api/user/refound
app/api/user/register
app/api/user/unlike
app/api/user/update
app/api/v2/detail/
app/api/v2/user/code/refound
app/api/v2/user/code/reg
app/api/v2/user/code/verify
app/api/vip/products
```

## 中文文案（按场景分组）

### 激励广告 / 广告解锁（20 条）
-  个广告
- 》，快下载APP和我一起观看吧～ 官网：
- 享受专属铭牌、尊享线路以及免除广告
- 任务每天按北京时间零点更新。\n完成广告后，进度可能稍有延迟，可下拉刷新查看。
- 保存开屏免广告时间失败：
- 加载激励视频失败，请重试
- 加载激励视频失败：
- 完成广告观看任务
- 开屏广告超时兜底，强制跳转主页
- 未完成当前任务，请完整观看广告
- 本任务还在审核中，您确定要重新观看吗？可能会重置审核进度导致更慢哦？一般情况下只需要等待1-5分钟，期间你可以主动下拉刷新查询状态。
- 检查或展示激励视频失败：
- 激励完成后刷新
- 激励视频可展示状态：
- 登录账号，查看今天的任务进度与阅读奖励。
- 观看广告
- 观看第 
- 重新观看
- 阅读奖励
- 阅读时间不足，请观看广告获取阅读时间

### 会员 / 付费（20 条）
- 会员中心
- 会员权益中心
- 如果点击\"我已支付\"后没反应，请返回上一页点击右上角的客服按钮联系客服处理
- 完成支付后请返回此页点击\"我已支付\"进行确认
- 已支付
- 待支付
- 我已支付
- 我的订单
- 支付方式
- 支付金额
- 暂无可用支付方式
- 暂无订单
- 正在生成订单
- 立即支付
- 订单创建失败，请重试
- 订单号
- 订单号已复制
- 订单详情
- 选择支付方式
- 金额

### 任务 / 签到（15 条）
- 任务中心
- 任务每天按北京时间零点更新。\n完成广告后，进度可能稍有延迟，可下拉刷新查看。
- 刷新任务状态
- 前往任务中心
- 完成广告观看任务
- 已完成当前任务
- 并发任务异常: 
- 暂时无法加载任务
- 未完成当前任务，请完整观看广告
- 本任务还在审核中，您确定要重新观看吗？可能会重置审核进度导致更慢哦？一般情况下只需要等待1-5分钟，期间你可以主动下拉刷新查询状态。
- 查询任务结果失败，请稍后重试
- 登录后查看阅读任务
- 登录账号，查看今天的任务进度与阅读奖励。
- 请完成任务解锁当前章节
- 读取任务进度失败，请重试

### 章节 / 阅读（29 条）
-  分钟阅读
- 【EasyRefresh】onLoad - 加载下一章
- 上拉加载下一章
- 下一章
- 任务每天按北京时间零点更新。\n完成广告后，进度可能稍有延迟，可下拉刷新查看。
- 加载下一章
- 加载章节失败，请重试
- 完成后可阅读至当天结束
- 导出阅读历史失败：
- 开始阅读
- 当前章节
- 我正在栗子漫画阅读《
- 暂无章节数据
- 本任务还在审核中，您确定要重新观看吗？可能会重置审核进度导致更慢哦？一般情况下只需要等待1-5分钟，期间你可以主动下拉刷新查询状态。
- 登录后查看阅读任务
- 登录后继续阅读
- 登录账号，查看今天的任务进度与阅读奖励。
- 目录
- 章节
- 继续阅读
- 继续阅读失败: 
- 请先阅读并同意用户协议和隐私协议
- 请完成任务解锁当前章节
- 读取任务进度失败，请重试
- 释放加载下一章

### 社区 / 互动（16 条）
- TA 还没有发布动态
- 举报
- 全部评论 
- 写评论...
- 加载帖子详情失败: 
- 加载用户帖子失败: 
- 加载社区帖子失败: 
- 加载评论失败: 
- 发布帖子
- 已提交举报，我们会尽快处理
- 帖子加载失败
- 暂无帖子
- 确定要删除这条帖子吗？
- 确定要删除这条评论吗？
- 还没有发布动态
- 还没有评论，来抢沙发吧

### 账号（47 条）
- 修改失败，请检查旧密码是否正确
- 去登录
- 密码
- 密码不能少于6位
- 密码重置成功
- 已有账号？立即登录
- 已登录？点我刷新
- 忘记密码
- 您的账号已被系统标识为风险账号
- 您还未登录哦～
- 新密码不能少于6位
- 新旧密码不能一样
- 昵称
- 未登录
- 欢迎注册栗子漫画
- 欢迎登录栗子漫画
- 注册失败，请重试
- 注册成功
- 登录后查看阅读任务
- 登录后继续阅读
- 登录已过期，请重新登录
- 登录成功
- 登录账号，查看今天的任务进度与阅读奖励。
- 确定要退出登录吗？
- 立即注册

### 其他（432 条）
-  回复 
-  完 —
-  张:
-  张新图片:
-  条历史记录，请在新app导入
-  条回复
-  条回复 >
-  秒
-  秒后重试
-  章
-  第
-  部
- $modalRouteContentName を閉じる
- /10 部漫画
- APP初始化成功
- DoH 全部失败，回落静态列表
- DoH方式异常: 
- DoH获取失败页异常: 
- JS执行错误: 
- JsEngine 未初始化，请先调用 init()
- TA 还没有公开漫单
- TG 群链接未配置
- ]，预加载 
- crypto-js 加载完成
- 《用户协议》
- 《隐私协议》
- 」吗？
- 【EasyRefresh】onRefresh - 加载上一章
- 【滚动预加载】当前: 
- 【翻页预加载】当前: 
