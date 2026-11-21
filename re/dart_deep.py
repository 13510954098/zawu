#!/usr/bin/env python3
# 把 blutter 的 pp.txt 整理成可读的 Dart 侧深度报告
import argparse, os, re
from collections import Counter

API_RE = re.compile(r'(?:app)?/?app/api[A-Za-z0-9_/.\-?=\\]*')
HOST_RE = re.compile(r'[a-z0-9][a-z0-9.\-]{3,40}\.(?:com|cn|net|io|xyz|top|app|site|cc|lat)\b')
ZH_RE = re.compile('[\u4e00-\u9fa5]')
GROUPS = [
    ('激励广告 / 广告解锁', ['广告', '激励', '奖励', '观看', '免广告']),
    ('会员 / 付费', ['会员', '漫币', '支付', '充值', '金额', '订单', '购买']),
    ('任务 / 签到', ['任务', '签到', '积分', '金币', '领取']),
    ('章节 / 阅读', ['章节', '阅读', '进度', '目录', '下一章']),
    ('社区 / 互动', ['评论', '举报', '动态', '帖子', '点赞', '关注']),
    ('账号', ['登录', '注册', '昵称', '密码', '验证码', '账号', '注销']),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pp', required=True)
    ap.add_argument('--blutter-log', default='')
    ap.add_argument('--outdir', default='.')
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    raw = open(a.pp, encoding='utf-8', errors='replace').read()
    lines = raw.split(chr(10))

    strs = []
    for l in lines:
        if 'String: "' in l:
            s = l.split('String: "', 1)[1]
            if s.endswith('"'):
                s = s[:-1]
            strs.append(s)
    uniq = sorted(set(strs))
    zh = [s for s in uniq if ZH_RE.search(s)]
    api = sorted({x.replace(chr(92), '') for x in API_RE.findall(raw)})
    hosts = Counter(HOST_RE.findall(raw))
    dev_paths = sorted({s for s in uniq if '/Users/' in s or 'file:///' in s})

    dartver = ''
    if a.blutter_log and os.path.exists(a.blutter_log):
        for l in open(a.blutter_log, encoding='utf-8', errors='replace'):
            if 'Dart version' in l:
                dartver = l.strip()

    out = ['# Dart AOT 深度结果（blutter）', '']
    out.append('- 引擎：%s' % (dartver or '见 blutter.log'))
    out.append('- 产物：`dart-pp.txt` %d 行（Object Pool 全量导出）' % len(lines))
    out.append('- 常量字符串：%d 条，唯一 %d 条，其中中文 %d 条' % (len(strs), len(uniq), len(zh)))

    if hosts:
        out += ['', '## 硬编码域名', '| host | 次数 |', '|---|---|']
        for h, n in hosts.most_common():
            out.append('| `%s` | %d |' % (h, n))

    if dev_paths:
        out += ['', '## 构建环境痕迹', '']
        for p in dev_paths[:6]:
            out.append('- `%s`' % p)

    if api:
        out += ['', '## 明文接口清单（%d 个）' % len(api), '', '```']
        out += api
        out += ['```']

    if zh:
        out += ['', '## 中文文案（按场景分组）']
        for name, kws in GROUPS:
            hit = [s for s in zh if any(k in s for k in kws)]
            if not hit:
                continue
            out += ['', '### %s（%d 条）' % (name, len(hit))]
            out += ['- ' + s for s in hit[:25]]
        rest = [s for s in zh if not any(k in s for _, kws in GROUPS for k in kws)]
        if rest:
            out += ['', '### 其他（%d 条）' % len(rest)]
            out += ['- ' + s for s in rest[:30]]

    open(os.path.join(a.outdir, 'dart-deep.md'), 'w', encoding='utf-8').write(chr(10).join(out) + chr(10))
    open(os.path.join(a.outdir, 'dart-strings.txt'), 'w', encoding='utf-8').write(chr(10).join(zh) + chr(10))
    print('dart deep: %d api, %d hosts, %d zh strings' % (len(api), len(hosts), len(zh)))


main()
