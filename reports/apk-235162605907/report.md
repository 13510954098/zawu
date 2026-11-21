# APK 静态分析报告
> 仅静态读取（解包、读 DEX/so、验签）。未运行、未抓流量、未调用接口。

## 身份
- 包名 `com.hbsclj.uth`，v1.1.7（versionCode 19）
- minSdk 24 / targetSdk 34 / compileSdk 36
- 大小 41.29 MB，SHA-256 `235162605907f6c26c39d3f877af387a915ea8b6f3ca000d358111a0aefa2ab2`

### 签名
- 主体：`C=US, ST=State, L=City, O=MyCompany, CN=Android`
- 证书 SHA-256：`cdd266df8b2399c24da38e408b6d9825c7bd2af073229847f551ea653ea096e1`
- 方案：v2=True、v3=False、v1=False

## 技术栈
- DEX 合计 18.6 MB，类描述符约 19809
- Flutter：是（flutter_assets 8 个，libapp.so 8.3 MB）
- 原生库 10 个：`libflutter.so`(29313KB)、`libapp.so`(26210KB)、`libsqlite3.so`(4467KB)、`libfastdev_quickjs_runtime.so`(3975KB)、`libplt-base.so`(607KB)、`libverbanr.so`(577KB)、`libcommonV2DevInfo.so`(510KB)、`libsgcore.so`(313KB)、`libti-monitor.so`(177KB)、`libdatastore_shared_counter.so`(22KB)

## 第三方 SDK（按类数）
| SDK | 类数 |
|---|---|
| 快手广告 kwad | 4044 |
| smartdigimkt | 2098 |
| 倍孜 Beizi(聚合) | 2030 |
| TopOn AnyThink(聚合) | 1764 |
| Sigmob | 1245 |
| Flutter | 400 |
| TalkingData | 277 |
| 快手 weapon(反作弊) | 180 |
| 腾讯广点通 GDT | 179 |
| Volley | 87 |
| OPPO | 8 |
| 小米 | 2 |
| vivo | 2 |
| Adjust | 2 |
| 字节穿山甲 Pangle | 1 |
| AppsFlyer | 1 |

## 权限（18 条，敏感 11 条）
- `READ_MEDIA_AUDIO` — 读音频媒体
- `READ_MEDIA_VIDEO` — 读视频媒体
- `READ_EXTERNAL_STORAGE` — 读外部存储
- `WRITE_EXTERNAL_STORAGE` — 写外部存储
- `GET_TASKS` — 读运行任务栈
- `READ_PHONE_STATE` — 可读设备/运营商标识
- `ACCESS_COARSE_LOCATION` — 粗略定位
- `ACCESS_FINE_LOCATION` — 精确定位
- `REQUEST_INSTALL_PACKAGES` — 可拉起安装其他 APK
- `AD_ID` — 读广告 ID(GAID)
- `QUERY_ALL_PACKAGES` — 可枚举全部已装应用

## 组件（119 个，对外可见 4 个）
- [activity] `com.hbsclj.uth.MainActivity` filters=1
- [activity] `com.kwad.auth.login.KwadRouteHandlerActivity` filters=0
- [activity-alias] `com.hbsclj.uth.kwad.KwadHandlerActivity` filters=0
- [receiver] `androidx.profileinstaller.ProfileInstallReceiver` filters=4

## 网络端点（45 个唯一 host，Top 30）
| host | 次数 |
|---|---|
| `p1-lm.adkwai.com` | 11 |
| `cn-api.anythinktech.com` | 6 |
| `p2-lm.adkwai.com` | 5 |
| `github.com` | 4 |
| `adx.anythinktech.com` | 3 |
| `cn-tk.anythinktech.com` | 3 |
| `adservice.sigmob.cn` | 3 |
| `issuetracker.google.com` | 2 |
| `cn-api-sec.anythinktech.com` | 2 |
| `play.google.com` | 2 |
| `se.anythinktech.com` | 2 |
| `www.example.com` | 2 |
| `open.e.kuaishou.com` | 2 |
| `static.yximgs.com` | 2 |
| `adx-bj.statisticslinks.com` | 2 |
| `adx-strategy-api-cn.statisticslinks.com` | 2 |
| `api.talkingdata.com` | 2 |
| `api.flutter.dev` | 2 |
| `schemas.android.com` | 1 |
| `adxcn-tk.anythinktech.com` | 1 |
| `cn-da.anythinktech.com` | 1 |
| `ssapi.anythinktech.com` | 1 |
| `apps.samsung.com` | 1 |
| `msg.cmpassport.com` | 1 |
| `p3-lm.adkwai.com` | 1 |
| `p4-lm.adkwai.com` | 1 |
| `p5-lm.adkwai.com` | 1 |
| `style-browse-openapi.test.gifshow.com` | 1 |
| `developer.android.com` | 1 |
| `docs.flutter.dev` | 1 |

## 凭据相关字段
- 字段名出现次数：`placementid`×157、`appid`×99、`placement_id`×46、`app_id`×32、`slot_id`×28、`appkey`×25、`app_key`×8、`secretkey`×6、`slotid`×2、`accesskey`×1、`access_key`×1
- 这些是字段名，不是值；本包未见 appId=xxx 这类相邻字面量，值可能由服务端下发。

## 加固指纹
- 无 apkid 结论

## 局限
- 静态结论；运行期行为需设备或抓包证据。签名未做密码学验证。

## 深挖状态（机器生成）
- jadx: jadx_exit=3
- blutter: blutter_exit=0
- Dart 引擎信息: Dart version: 3.5.4, Snapshot: 80a49c7111088100a233b2ae788e1f48, Target: android arm64
- blutter 产物: pp.txt 51043 行

### blutter 目录
```
asm
blutter_frida.js
ida_script
objs.txt
pp.txt
--- asm 文件数 ---
1383
```

## Dart AOT 侧（libapp.so 8.3 MB，UTF-16LE 快照字符串）

- 可用文案样本 408 条（已用常用字过滤，仍可能残留个别乱码字符）
- 业务关键词命中：重试×32、任务×22、广告×19、收藏×10、章节×7、清理×4、解锁×3、下拉×3、会员×2、排行×2、缓存×2、免广告×1、最后一章×1

### 文案样本（按出现次数）
| 文案 | 次数 |
|---|---|
| 请稍后重试 | 4 |
| 请重试 | 4 |
| 形酀求 | 4 |
| 老菒而 | 3 |
| 漫画 | 2 |
| 至少 | 2 |
| 刷新中 | 2 |
| 预加载 | 2 |
| 当前 | 2 |
| 最多 | 2 |
| 功能 | 2 |
| 諟老锁 | 2 |
| 者节 | 1 |
| 舁脁节老节 | 1 |
| 要许 | 1 |
| 为搜係偮 | 1 |
| 蘰噂蕡动态徖汢 | 1 |
| 鄸标记已读失败 | 1 |
| 证码发送失败 | 1 |
| 攠灸捥整襤操作失败從半 | 1 |
| 到期时间 | 1 |
| 任务说明熄鱘祟摮 | 1 |
| 輰验证并发送中 | 1 |
| 贠选择漫画 | 1 |
| 謸请求已取消 | 1 |
| 潃瑮硥酴注册失败 | 1 |
| 请重试從呆 | 1 |
| 部漫画溆慢 | 1 |
| 加载完成厦獹整乭癡杩瑡牯瀮灯 | 1 |
| 还没阅读过漫画哦 | 1 |
| 还没有创建漫单僄敲獯慴慬猠 | 1 |
| 慍捴卨楴正虹南靨请完成任务解锁当前章节徦慃慰楢楬祴 | 1 |
| 霆确定要删除这条评论吗 | 1 |
| 襡添加漫画炌敲楦虸桴 | 1 |
| 请先调用 | 1 |
| 輠您还未登录哦 | 1 |
| 贌请输入新昵称历楚薥霉 | 1 |
| 謠今日已完成犆捏徜潇 | 1 |
| 正在审核中 | 1 |
| 请耐心等待 | 1 |
| 在获取服务端 | 1 |
| 告尚未准备好 | 1 |
| 搜索漫画 | 1 |
| 可选择最多從剓 | 1 |
| 刷新失败 | 1 |
| 以下为上次获取的进度從 | 1 |
| 鴹网络请求超时 | 1 |
| 请重新获取滑块榎摮硥摥徚灊 | 1 |
| 酰加载漫单失败 | 1 |
| 请先阅读并同意用户协议和隐私协议 | 1 |
| 褌栗子漫画撎牵湩 | 1 |
| 蔰完结抆扪 | 1 |
| 漫画和漫单只能选其一徜灵 | 1 |
| 个标签 | 1 |
| 愠牲扩饡滑块加载失败 | 1 |
| 请重新获取喇 | 1 |
| 行本択慲湩潰汯 | 1 |
| 未获取到广告交易编号 | 1 |
| 暂时无法确认任务结果 | 1 |
| 褠保存失败枤瑥强瑳瑡 | 1 |

### 资源路径
`assets/icons/vip.svg`、`assets/icons/thumb_up.svg`、`assets/images/task_center_mascot.png`、`assets/icons/menu_sort.svg`、`assets/icons/delete.svg`、`assets/images/default_cover.jpg`、`assets/icons/eye.svg`、`assets/images/toolbar_history_bg.png`、`assets/images/toolbar_rank_item.png`、`assets/images/splash.webp`、`assets/icons/right.svg`、`assets/icons/thumb_up_filled.svg`、`assets/images/toolbar_rank_bg.png`、`assets/icons/message_circle.svg`、`assets/icons/clock.svg`、`assets/icons/reader_settings.svg`、`packages/flutter_js/assets/js/fetch.js`、`assets/icons/reader_exchange.svg`、`assets/icons/back.svg`、`assets/icons/edit.svg`

完整 Dart 侧结果见 dart-deep.md 与 dart-hot.md。
