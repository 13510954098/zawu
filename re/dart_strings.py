#!/usr/bin/env python3
# Dart AOT 文案提取（UTF-16LE 快照字符串 + 常用字过滤，不依赖 blutter）
import argparse, os, re
from collections import Counter

COMMON = set('的一是不了在人有我他这为之大来以个中上们到说国和地也子时道出而要于就下得可你年生自会那后能对着事其里所去行过家十用发天如然作方成者多日都三小军二无同么经法当起与好看学进种将还分此心前面又定见只主没公从现美次总何新己许件最知老门展群解长很必量队走带应打向指接住少完今结提直题清象热病呢达话早吗未先形级至观求页章节漫画会员广告签到收藏充值任务金币免费解锁播放下载分享登录历史搜索分类追更排行缓存刷新加载确定取消返回上一页最新完结审核动态版本重试网络错误成功失败请稍后您')

PAT = re.compile(rb'((?:[\x00-\xff][\x4e-\x9f]){2,})')
CJKSEG = re.compile('[\u4e00-\u9fa5]{2,}')
PATHS = re.compile('(?:assets|packages)/[A-Za-z0-9_./-]{3,60}')
KW = ['会员', '漫币', '充值', '金币', '解锁', '免广告', '广告', '签到', '任务', '积分', '章节',
      '追更', '排行', '收藏', '缓存', '青少年', '最后一章', '清理', '下拉', '重试']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--decoded', required=True)
    ap.add_argument('--outdir', default='.')
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    so = os.path.join(a.decoded, 'lib', 'arm64-v8a', 'libapp.so')
    if not os.path.exists(so):
        print('no libapp.so')
        return
    data = open(so, 'rb').read()
    u = Counter()
    for m in PAT.finditer(data):
        b = m.group()
        if len(b) % 2:
            b = b[:-1]
        s = b.decode('utf-16-le', 'ignore')
        for seg in CJKSEG.findall(s):
            if len(set(seg) & COMMON) >= max(2, len(seg) // 3):
                u[seg] += 1
    paths = Counter(PATHS.findall(data.decode('latin-1', 'ignore')))
    kw = [(k, sum(n for s, n in u.items() if k in s)) for k in KW]
    kw = [x for x in kw if x[1]]

    lines = ['', '## Dart AOT 侧（libapp.so %.1f MB，UTF-16LE 快照字符串）' % (len(data) / 1048576.0), '']
    lines.append('- 可用文案样本 %d 条（已用常用字过滤，仍可能残留个别乱码字符）' % len(u))
    if kw:
        lines.append('- 业务关键词命中：' + '、'.join('%s×%d' % k for k in sorted(kw, key=lambda x: -x[1])))
    lines += ['', '### 文案样本（按出现次数）', '| 文案 | 次数 |', '|---|---|']
    for s, n in u.most_common(60):
        lines.append('| %s | %d |' % (s.replace('|', '/'), n))
    if paths:
        lines += ['', '### 资源路径', '、'.join('`%s`' % p for p, _ in paths.most_common(20))]
    open(os.path.join(a.outdir, 'dart-findings.md'), 'w').write(chr(10).join(lines) + chr(10))
    print('dart strings: %d samples, %d keywords' % (len(u), len(kw)))


main()
