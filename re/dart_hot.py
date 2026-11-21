#!/usr/bin/env python3
# 在 blutter 的 asm 产物里定位敏感逻辑（签名 / 加密 / token / 登录）
import argparse, os, re
from collections import Counter

PATTERNS = [
    ('x-sign', r'x-sign|x_sign'),
    ('sign', r'(?<![a-z])sign(?![a-z])'),
    ('signature', r'signature'),
    ('md5', r'md5'),
    ('sha1', r'sha1'),
    ('sha256', r'sha256'),
    ('hmac', r'hmac'),
    ('aes', r'(?<![a-z])aes'),
    ('encrypt', r'encrypt'),
    ('decrypt', r'decrypt'),
    ('secret', r'secret'),
    ('appkey', r'appkey|app_key'),
    ('token', r'(?<![a-z])token'),
    ('authorization', r'authorization'),
    ('nonce', r'nonce'),
    ('timestamp', r'timestamp'),
    ('deviceid', r'device[_-]?id'),
    ('refound', r'refound'),
    ('api_login', r'app/api/user/login'),
    ('api_register', r'app/api/user/register'),
    ('api_chapter', r'app/api/chapter/v3'),
]
MAXKB = 8000


def texts(root):
    d = os.path.join(root, 'asm')
    if not os.path.isdir(d):
        return
    for dp, _, fs in os.walk(d):
        for f in fs:
            p = os.path.join(dp, f)
            if os.path.getsize(p) > MAXKB * 1024:
                continue
            yield p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--blutter', required=True)
    ap.add_argument('--outdir', default='.')
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    files = list(texts(a.blutter)) if os.path.isdir(a.blutter) else []
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
            k = next((name for name, pat in PATTERNS if re.search(pat, low)), None)
            if not k:
                continue
            hits[k] += 1
            if len(ctx) < 60:
                head = ''
                for j in range(i, max(-1, i - 20), -1):
                    if re.search(r'(Function|\bProc\b|func\s+0x|0x[0-9a-f]{6,}\s*:)', lines[j]):
                        head = lines[j].strip()
                        break
                ctx.append((rel, k, head[:100], l.strip()[:160]))

    out = ['# Dart 侧敏感逻辑定位（blutter asm 扫描）', '']
    out.append('- 扫描 asm 文件 %d 个' % len(files))
    out.append('- 命中统计：' + ('、'.join('`%s`×%d' % (k, n) for k, n in hits.most_common()) or '无'))
    out += ['', '## 命中位置', '| 文件 | 关键词 | 所属函数 | 命中行 |', '|---|---|---|---|']
    for rel, k, head, l in ctx:
        out.append('| `%s` | `%s` | `%s` | `%s` |' % (rel, k, head.replace('|', '/').replace(chr(96), chr(39)), l.replace('|', '/').replace(chr(96), chr(39))))
    if not ctx:
        out.append('| - | - | 无 | 无 |')
    open(os.path.join(a.outdir, 'dart-hot.md'), 'w', encoding='utf-8').write(chr(10).join(out) + chr(10))
    print('dart hot: %d files, %d hits' % (len(files), sum(hits.values())))


main()
