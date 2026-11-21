#!/usr/bin/env python3
# 在 blutter 的 asm 产物里定位敏感逻辑（签名 / 加密 / token / 登录）
import argparse, os, re
from collections import Counter

KW = ['x-sign', 'x_sign', 'sign', 'signature', 'md5', 'sha1', 'sha256', 'hmac', 'aes',
      'encrypt', 'decrypt', 'secret', 'appkey', 'app_key', 'token', 'authorization',
      'app/api/user/login', 'app/api/user/register', 'app/api/chapter/v3', 'nonce', 'timestamp',
      'deviceid', 'device_id', 'oauthid', 'refound']
SKIP = {'pp.txt', 'objs.txt'}
MAXKB = 6000


def walk(root):
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(dp, f)
            if f in SKIP:
                continue
            if os.path.getsize(p) > MAXKB * 1024:
                continue
            yield p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--blutter', required=True)
    ap.add_argument('--outdir', default='.')
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    if not os.path.isdir(a.blutter):
        print('no blutter dir')
        return

    files = list(walk(a.blutter))
    hits = Counter()
    ctx = []
    for p in files:
        rel = os.path.relpath(p, a.blutter)
        try:
            raw = open(p, 'rb').read()
        except Exception:
            continue
        if not raw:
            continue
        probe = raw[:4000]
        if sum(1 for b in probe if b in (9, 10, 13) or 32 <= b < 127) < len(probe) * 0.85:
            continue
        lines = raw.decode('utf-8', errors='replace').split(chr(10))
        for i, l in enumerate(lines):
            low = l.lower()
            k = next((x for x in KW if x in low), None)
            if not k:
                continue
            hits[k] += 1
            if len(ctx) < 150:
                head = ''
                for j in range(i, max(-1, i - 14), -1):
                    if re.search(r'(Function|Proc|func|0x[0-9a-f]{6,})', lines[j]):
                        head = lines[j].strip()
                        break
                ctx.append((rel, k, head[:120], l.strip()[:200]))

    out = ['# Dart 侧敏感逻辑定位（blutter asm 扫描）', '']
    out.append('- 扫描文件 %d 个（跳过 pp.txt / objs.txt 与二进制）' % len(files))
    out.append('- 命中统计：' + '、'.join('`%s`×%d' % (k, n) for k, n in hits.most_common()))
    out += ['', '## 命中位置（函数头 / 命中行）', '| 文件 | 关键词 | 函数 | 命中行 |', '|---|---|---|---|']
    for rel, k, head, l in ctx:
        out.append('| `%s` | `%s` | `%s` | `%s` |' % (rel, k, head.replace('|', '/').replace(chr(96), chr(39)), l.replace('|', '/').replace(chr(96), chr(39))))
    if not ctx:
        out.append('| - | - | 无 | 无 |')
    open(os.path.join(a.outdir, 'dart-hot.md'), 'w', encoding='utf-8').write(chr(10).join(out) + chr(10))
    print('dart hot: %d files, %d hits, %d samples' % (len(files), sum(hits.values()), len(ctx)))


main()
