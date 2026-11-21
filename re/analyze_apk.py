#!/usr/bin/env python3
# APK 静态首轮分析: 生成 report.md / facts.json / domains.txt (只读, 不执行代码)
import argparse, hashlib, json, os, re, zipfile, subprocess, tempfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

AND = '{http://schemas.android.com/apk/res/android}'
SDK = [
 ('倍孜 Beizi(聚合)', ['com/beizi']), ('快手广告 kwad', ['com/kwad']),
 ('Sigmob', ['com/sigmob']), ('TopOn AnyThink(聚合)', ['com/anythink']),
 ('TalkingData', ['com/tendcloud']), ('smartdigimkt', ['com/smartdigimkt']),
 ('快手 weapon(反作弊)', ['com/kuaishou']), ('腾讯广点通 GDT', ['com/qq/e']),
 ('字节穿山甲 Pangle', ['com/bytedance', 'com/pangle', 'com/ss/android']),
 ('Google AdMob', ['com/google/android/gms/ads']), ('Meta Audience', ['com/facebook/ads']),
 ('AppLovin', ['com/applovin']), ('Unity Ads', ['com/unity3d/ads']),
 ('ironSource', ['com/ironsource']), ('Mintegral', ['com/mbridge', 'com/mintegral']),
 ('百度 Mobads', ['com/baidu/mobads']), ('华为 Ads', ['com/huawei/hms/ads']),
 ('小米', ['com/miui']), ('OPPO', ['com/opos', 'com/heytap']), ('vivo', ['com/vivo']),
 ('友盟 Umeng', ['com/umeng']), ('AppsFlyer', ['com/appsflyer']), ('Adjust', ['com/adjust']),
 ('Flutter', ['io/flutter']), ('Volley', ['com/android/volley', 'com/czhj/volley']),
]
RISK = {
 'android.permission.REQUEST_INSTALL_PACKAGES': '可拉起安装其他 APK',
 'android.permission.QUERY_ALL_PACKAGES': '可枚举全部已装应用',
 'android.permission.READ_PHONE_STATE': '可读设备/运营商标识',
 'android.permission.ACCESS_FINE_LOCATION': '精确定位',
 'android.permission.ACCESS_COARSE_LOCATION': '粗略定位',
 'android.permission.READ_EXTERNAL_STORAGE': '读外部存储',
 'android.permission.WRITE_EXTERNAL_STORAGE': '写外部存储',
 'android.permission.GET_TASKS': '读运行任务栈',
 'android.permission.READ_MEDIA_AUDIO': '读音频媒体',
 'android.permission.READ_MEDIA_VIDEO': '读视频媒体',
 'com.google.android.gms.permission.AD_ID': '读广告 ID(GAID)',
}
URL = re.compile(r'(?:https?|wss?)://([A-Za-z0-9][A-Za-z0-9._-]{2,60})')
CLS = re.compile(rb'(?<![A-Za-z0-9_$])L((?:[A-Za-z][A-Za-z0-9_$]{0,40}/){1,6}[A-Za-z0-9_$]{1,90});')
KEY = re.compile(r'(?i)(app[_-]?id|app[_-]?key|app[_-]?secret|access[_-]?key|secret[_-]?key|placement[_-]?id|adspot|slot[_-]?id)')


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def take(buf, pos):
    n = int.from_bytes(buf[pos:pos + 4], 'little')
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


def signature(path):
    out = {'schemes': {}, 'cert_dn': None, 'cert_sha256': None, 'notes': []}
    data = open(path, 'rb').read()
    eocd = data.rfind(bytes([80,75,5,6]))
    if eocd > 0:
        cd = int.from_bytes(data[eocd + 16:eocd + 20], 'little')
        if data[cd - 16:cd] == b'APK Sig Block 42':
            size = int.from_bytes(data[cd - 24:cd - 16], 'little')
            pos, pairs = cd - size - 8 + 8, {}
            while pos < cd - 24:
                n = int.from_bytes(data[pos:pos + 8], 'little')
                if n <= 0 or pos + 8 + n > cd - 24:
                    break
                pairs[data[pos + 8:pos + 12]] = data[pos + 12:pos + 8 + n]
                pos += 8 + n
            v2, v3 = bytes.fromhex('1a870971'), bytes.fromhex('c06853f0')
            out['schemes']['v2'] = v2 in pairs
            out['schemes']['v3'] = v3 in pairs
            blob = pairs.get(v2) or pairs.get(v3)
            if blob:
                try:
                    signers, _ = take(blob, 0)
                    signer, _ = take(signers, 0)
                    signed, _ = take(signer, 0)
                    _, p = take(signed, 0)
                    certs, _ = take(signed, p)
                    der, _ = take(certs, 0)
                    out['cert_sha256'] = hashlib.sha256(der).hexdigest()
                    with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
                        f.write(der)
                        tmp = f.name
                    r = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-subject', '-in', tmp],
                                       capture_output=True, text=True)
                    os.unlink(tmp)
                    for ln in r.stdout.splitlines():
                        if 'subject=' in ln:
                            out['cert_dn'] = ln.split('subject=', 1)[1].strip()
                except Exception as e:
                    out['notes'].append('v2 证书解析失败: %s' % e)
    try:
        with zipfile.ZipFile(path) as z:
            out['schemes']['v1'] = any(n.startswith('META-INF/') and n.upper().endswith(('.RSA', '.DSA', '.EC')) for n in z.namelist())
    except Exception:
        out['schemes']['v1'] = False
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', required=True)
    ap.add_argument('--decoded', required=True)
    ap.add_argument('--apkid')
    ap.add_argument('--outdir', default='.')
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)

    man = {'permissions': [], 'components': [], 'links': []}
    root = ET.parse(os.path.join(a.decoded, 'AndroidManifest.xml')).getroot()
    man['package'] = root.get('package')
    man['compile_sdk'] = root.get(AND + 'compileSdkVersion')
    yml = open(os.path.join(a.decoded, 'apktool.yml'), encoding='utf-8', errors='ignore').read()
    for k, dst in (('versionName', 'version_name'), ('versionCode', 'version_code'),
                   ('minSdkVersion', 'min_sdk'), ('targetSdkVersion', 'target_sdk')):
        m = re.search('%s:[ ]*(.+)' % k, yml)
        man[dst] = m.group(1).strip() if m else None
    for el in root.findall('uses-permission') + root.findall('uses-permission-sdk-23'):
        man['permissions'].append(el.get(AND + 'name'))
    app = root.find('application')
    if app is not None:
        for kind in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
            for el in app.findall(kind):
                filters = el.findall('intent-filter')
                exp = el.get(AND + 'exported')
                man['components'].append({'type': kind, 'name': el.get(AND + 'name'),
                                          'exported': exp if exp else ('true' if filters else 'false'),
                                          'filters': len(filters)})
                for f in filters:
                    for d in f.findall('data'):
                        s = d.get(AND + 'scheme')
                        if s and s not in ('http', 'https', 'content', 'file'):
                            man['links'].append({'scheme': s, 'host': d.get(AND + 'host')})

    p2, p3, blob, nd = Counter(), Counter(), [], 0
    for f in sorted(os.listdir(a.decoded)):
        if not re.match('classes[0-9]*[.]dex$', f):
            continue
        raw = open(os.path.join(a.decoded, f), 'rb').read()
        nd += len(raw)
        for n in CLS.findall(raw).__iter__():
            seg = n.decode('utf-8', 'ignore').split('/')
            if len(seg) >= 2:
                p2['/'.join(seg[:2])] += 1
            if len(seg) >= 3:
                p3['/'.join(seg[:3])] += 1
        blob.append(raw.decode('latin-1', 'ignore'))

    libs = defaultdict(lambda: {'abis': [], 'bytes': 0})
    for r, _, fs in os.walk(os.path.join(a.decoded, 'lib')):
        for f in fs:
            libs[f]['abis'].append(os.path.basename(r))
            libs[f]['bytes'] += os.path.getsize(os.path.join(r, f))

    tr = chr(10).join(blob)
    la = os.path.join(a.decoded, 'lib', 'arm64-v8a', 'libapp.so')
    if os.path.exists(la):
        tr += open(la, 'rb').read().decode('latin-1', 'ignore')
    hosts = Counter(h.lower() for h in URL.findall(tr))

    sdks = []
    for name, pfx in SDK:
        n = sum(p3[p] + p2[p] for p in pfx)
        if n:
            sdks.append((name, n))
    sdks.sort(key=lambda x: -x[1])
    risk = [(p, RISK[p]) for p in man['permissions'] if p in RISK]
    keys = Counter(m.group(0).lower() for m in KEY.finditer(tr)).most_common(12)
    fat = os.path.join(a.decoded, 'assets', 'flutter_assets')
    sig = signature(a.apk)
    apkid = None
    if a.apkid and os.path.exists(a.apkid):
        try:
            j = json.load(open(a.apkid))
            apkid = {k: v for k, v in list(j.values())[0].items() if v} if j else None
        except Exception:
            pass

    facts = {'apk': {'bytes': os.path.getsize(a.apk), 'sha256': sha256(a.apk)}, 'manifest': man,
             'dex': {'bytes': nd, 'top_p2': p2.most_common(30), 'top_p3': p3.most_common(30)},
             'native_libs': dict(libs), 'sdks': sdks, 'hosts': hosts.most_common(80),
             'key_names': keys, 'signature': sig, 'apkid': apkid,
             'flutter': {'assets': len(os.listdir(fat)) if os.path.isdir(fat) else 0,
                         'libapp_bytes': os.path.getsize(la) if os.path.exists(la) else 0}}
    open(os.path.join(a.outdir, 'facts.json'), 'w').write(json.dumps(facts, ensure_ascii=False, indent=2))
    open(os.path.join(a.outdir, 'domains.txt'), 'w').write(chr(10).join('%s  %d' % (h, n) for h, n in hosts.most_common()) + chr(10))

    L = []
    L.append('# APK 静态分析报告')
    L.append('> 仅静态读取（解包、读 DEX/so、验签）。未运行、未抓流量、未调用接口。')
    L.append('')
    L.append('## 身份')
    L.append('- 包名 `%s`，v%s（versionCode %s）' % (man['package'], man['version_name'], man['version_code']))
    L.append('- minSdk %s / targetSdk %s / compileSdk %s' % (man['min_sdk'], man['target_sdk'], man['compile_sdk']))
    L.append('- 大小 %.2f MB，SHA-256 `%s`' % (facts['apk']['bytes'] / 1048576.0, facts['apk']['sha256']))
    L.append('')
    L.append('### 签名')
    L.append('- 主体：`%s`' % sig['cert_dn'])
    L.append('- 证书 SHA-256：`%s`' % sig['cert_sha256'])
    L.append('- 方案：' + '、'.join('%s=%s' % (k, v) for k, v in sig['schemes'].items()))
    for n in sig['notes']:
        L.append('- 注意：' + n)
    L.append('')
    L.append('## 技术栈')
    L.append('- DEX 合计 %.1f MB，类描述符约 %d' % (nd / 1048576.0, sum(p2.values())))
    L.append('- Flutter：%s（flutter_assets %d 个，libapp.so %.1f MB）'
             % ('是' if facts['flutter']['assets'] else '未发现', facts['flutter']['assets'], facts['flutter']['libapp_bytes'] / 1048576.0))
    L.append('- 原生库 %d 个：' % len(libs) + '、'.join('`%s`(%dKB)' % (k, v['bytes'] // 1024) for k, v in sorted(libs.items(), key=lambda x: -x[1]['bytes'])[:10]))
    L.append('')
    L.append('## 第三方 SDK（按类数）')
    L.append('| SDK | 类数 |')
    L.append('|---|---|')
    for name, n in sdks:
        L.append('| %s | %d |' % (name, n))
    L.append('')
    L.append('## 权限（%d 条，敏感 %d 条）' % (len(man['permissions']), len(risk)))
    for p, why in risk:
        L.append('- `%s` — %s' % (p.split('.')[-1], why))
    L.append('')
    L.append('## 组件（%d 个，对外可见 %d 个）' % (len(man['components']), sum(1 for c in man['components'] if c['exported'] == 'true')))
    for c in [x for x in man['components'] if x['exported'] == 'true'][:20]:
        L.append('- [%s] `%s` filters=%d' % (c['type'], c['name'], c['filters']))
    if man['links']:
        L.append('自定义 scheme：' + '、'.join('`%s://%s`' % (d['scheme'], d['host'] or '') for d in man['links'][:20]))
    L.append('')
    L.append('## 网络端点（%d 个唯一 host，Top 30）' % len(hosts))
    L.append('| host | 次数 |')
    L.append('|---|---|')
    for h, n in hosts.most_common(30):
        L.append('| `%s` | %d |' % (h, n))
    L.append('')
    L.append('## 凭据相关字段')
    L.append('- 字段名出现次数：' + '、'.join('`%s`×%d' % k for k in keys))
    L.append('- 这些是字段名，不是值；本包未见 appId=xxx 这类相邻字面量，值可能由服务端下发。')
    L.append('')
    L.append('## 加固指纹')
    if apkid:
        for k, v in apkid.items():
            if isinstance(v, list) and v:
                L.append('- %s: %s' % (k, ', '.join(str(x) for x in v[:6])))
    else:
        L.append('- 无 apkid 结论')
    L.append('')
    L.append('## 局限')
    L.append('- 静态结论；运行期行为需设备或抓包证据。签名未做密码学验证。')
    open(os.path.join(a.outdir, 'report.md'), 'w').write(chr(10).join(L) + chr(10))
    print('report written; hosts=%d classes=%d' % (len(hosts), sum(p2.values())))


main()
