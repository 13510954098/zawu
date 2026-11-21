import base64, yaml, ast

def b64(s): return base64.b64encode(s.encode()).decode()

def step(name, body, cond=None):
    out = ["      - name: " + name]
    if cond: out.append("        if: " + cond)
    out.append("        run: |")
    for ln in body.strip("\n").split("\n"):
        out.append(("          " + ln) if ln.strip() else "")
    return "\n".join(out)

harness = open('/dev/stdin').read() if False else r'''
import frida, sys, time, os, json
pid=int(sys.argv[1]); js_path=sys.argv[2]; out=sys.argv[3]; secs=float(sys.argv[4])
dev=frida.get_usb_device(timeout=40)
session=dev.attach(pid)
js=open(js_path).read()
script=session.create_script(js)
f=open(out,'a',buffering=1)
ctr=[0]
def on_msg(m, data):
    try:
        if m['type']=='send':
            p=m.get('payload',{})
            if isinstance(p,dict) and p.get('t')=='mem' and data:
                idx=os.path.getsize('/tmp/memdump.bin') if os.path.exists('/tmp/memdump.bin') else 0
                with open('/tmp/memdump.bin','ab') as mf: mf.write(data)
                f.write(json.dumps({'t':'memref','base':p.get('base'),'size':len(data),'idx':idx})+'\n')
            else:
                ctr[0]+=1
                if data:
                    with open('/tmp/ctx_%03d.bin'%ctr[0],'wb') as cf: cf.write(data)
                f.write(json.dumps({'msg':p,'dlen':len(data) if data else 0})+'\n')
        elif m['type']=='error':
            f.write(json.dumps({'err':str(m.get('description',''))[:400]})+'\n')
    except Exception as e:
        f.write(json.dumps({'harness_err':str(e)})+'\n')
script.on('message', on_msg)
script.load()
f.write(json.dumps({'t':'collector_start','variant':js_path})+'\n')
t0=time.time(); dumped=False
while time.time()-t0 < secs:
    if os.path.exists('/tmp/go_dump') and not dumped:
        dumped=True
        for meth in ('dump','scan'):
            try:
                ex = getattr(script,'exports_sync',None) or script.exports
                r=getattr(ex,meth,None)
                if r:
                    r(); f.write(json.dumps({'rpc':meth,'ok':True})+'\n'); break
            except Exception as e:
                f.write(json.dumps({'rpc':meth,'err':str(e)[:200]})+'\n')
    time.sleep(1)
try: session.detach()
except Exception: pass
f.write(json.dumps({'t':'collector_done'})+'\n')
'''

glob32 = r'''
rpc.exports = { dump: function () {
  var total = 0;
  var ranges = Process.enumerateRanges('rw-');
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    if (r.size > 96 * 1024 * 1024) continue;
    if (total + r.size > 320 * 1024 * 1024) continue;
    total += r.size;
    try {
      send({ t: 'range', base: r.base.toString(), size: r.size });
      var CH = 4 * 1024 * 1024;
      for (var off = 0; off < r.size; off += CH) {
        var n = Math.min(CH, r.size - off);
        var data = r.base.add(off).readByteArray(n);
        send({ t: 'mem', base: r.base.add(off).toString() }, data);
      }
    } catch (e) { send({ t: 'rangeerr', at: r.base.toString(), e: '' + e }); }
  }
  send({ t: 'dumpdone', total: total });
} };
'''

candctx = r'''
function hexPat(s) { var o = []; for (var i = 0; i < s.length; i++) o.push(('0' + s.charCodeAt(i).toString(16)).slice(-2)); return o.join(' '); }
function scanPat(pat, tag, ctxlen) {
  var n = 0;
  Process.enumerateRanges('rw-').forEach(function (r) {
    if (r.size > 160 * 1024 * 1024) return;
    try {
      Memory.scan(r.base, r.size, pat, { onMatch: function (a, sz) {
        n++;
        try { send({ t: tag, at: a.toString() }, Memory.readByteArray(a.sub(ctxlen / 2), ctxlen)); }
        catch (e) { try { send({ t: tag, at: a.toString() }, Memory.readByteArray(a, ctxlen)); } catch (e2) {} }
      }, onComplete: function () {} });
    } catch (e) {}
  });
  return n;
}
rpc.exports = { scan: function () {
  var r1 = scanPat(hexPat('f8d992c74b29491d8a3e3fd5f07389d8'), 'ctx_f8d9', 8192);
  var r2 = scanPat(hexPat('e4dc85a3ea309e89807e3ecde5022c58'), 'ctx_mpbeiv', 4096);
  var r3 = scanPat(hexPat('ocjket'), 'ctx_doh', 4096);
  send({ t: 'scandone', f8d9: r1, mpbeiv: r2, doh: r3 });
} };
setInterval(function () { try { rpc.exports.scan(); } catch (e) {} }, 20000);
'''

sboxjs = r'''
var SBOX = '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76';
var hits = 0;
function scan() {
  Process.enumerateRanges('rw-').forEach(function (r) {
    if (r.size > 160 * 1024 * 1024) return;
    try {
      Memory.scan(r.base, r.size, SBOX, { onMatch: function (a, sz) {
        hits++;
        try { send({ t: 'sbox', at: a.toString() }, Memory.readByteArray(a.sub(65536), 131072)); }
        catch (e) { try { send({ t: 'sbox', at: a.toString() }, Memory.readByteArray(a, 65536)); } catch (e2) {} }
      }, onComplete: function () {} });
    } catch (e) {}
  });
  if (hits > 0) send({ t: 'sboxdone', hits: hits });
}
rpc.exports = { scan: scan };
setInterval(function () { try { scan(); } catch (e) {} }, 20000);
'''

writehook = r'''
var readlink = new NativeFunction(Module.getExportByName(null, 'readlink'), 'int', ['pointer', 'pointer', 'int']);
var tbuf = Memory.alloc(1024);
globalThis._hit = false;
Interceptor.attach(Module.getExportByName(null, 'write'), {
  onEnter: function (args) { this.fd = args[0].toInt32(); this.p = args[1]; this.n = args[2].toInt32(); },
  onLeave: function (ret) {
    if (this.n > 20000 && !globalThis._hit) {
      try {
        var p1 = Memory.allocUtf8String('/proc/self/fd/' + this.fd);
        var rl = readlink(p1, tbuf, 1023);
        if (rl > 0) {
          var target = tbuf.readUtf8String(rl);
          if (target.indexOf('libCachedImageData') >= 0) {
            globalThis._hit = true;
            send({ t: 'plainwrite', at: this.p.toString(), n: this.n, target: '' + target }, this.p.readByteArray(96));
            send({ t: 'trigger' });
          }
        }
      } catch (e) {}
    }
  }
});
send({ t: 'writehooked' });
'''

sockethook = r'''
function probe(name) {
  try {
    Interceptor.attach(Module.getExportByName(null, name), {
      onEnter: function (args) { this.fd = args[0].toInt32(); this.p = args[1]; },
      onLeave: function (ret) {
        var n = ret.toInt32();
        if (n > 40000) {
          try {
            var head = this.p.readByteArray(96);
            var bl = new Uint8Array(head);
            var magic = bl[0].toString(16) + bl[1].toString(16);
            send({ t: 'bigread', fn: name, fd: this.fd, n: n, at: this.p.toString(), magic: magic }, head);
          } catch (e) {}
        }
      }
    });
    send({ t: name + 'hooked' });
  } catch (e) { send({ t: name + 'err', e: '' + e }); }
}
probe('recv'); probe('read');
'''

javabridge = r'''
Java.perform(function () {
  var hooked = 0;
  try {
    var JN = Java.use('io.flutter.embedding.engine.FlutterJNI');
    try {
      var ov = JN.handlePlatformMessage.overload('java.lang.String', '[B', 'int', 'long');
      ov.implementation = function (ch, msg, rid, ck) {
        try {
          var b64 = '';
          if (msg !== null) { var B64 = Java.use('android.util.Base64'); b64 = B64.encodeToString(msg, 2); }
          send({ t: 'javamsg', ch: '' + ch, b64: ('' + b64).slice(0, 8000) });
        } catch (e) {}
        return ov.call(this, ch, msg, rid, ck);
      };
      hooked++;
    } catch (e) {}
    try {
      var ov2 = JN.handlePlatformMessage.overload('java.lang.String', 'java.nio.ByteBuffer', 'int', 'long');
      ov2.implementation = function (ch, msg, rid, ck) {
        try {
          var b64 = '';
          if (msg !== null) { try { var B64 = Java.use('android.util.Base64'); b64 = B64.encodeToString(msg.array(), 2); } catch (e) {} }
          send({ t: 'javamsg', ch: '' + ch, b64: ('' + b64).slice(0, 8000) });
        } catch (e) {}
        return ov2.call(this, ch, msg, rid, ck);
      };
      hooked++;
    } catch (e) {}
  } catch (e) { send({ t: 'javaerr', e: '' + e }); }
  send({ t: 'javahooked', n: hooked });
});
'''

verify = r'''
import json, os, re, hashlib, base64, urllib.request, sys
from Crypto.Cipher import AES, ChaCha20, ARC4
from Crypto.Util import Counter
from io import BytesIO
from PIL import Image
MAGS = [b'\xff\xd8', b'\x89PNG', b'RIFF', b'WEBP', b'GIF8']
IVC = bytes.fromhex('e4dc85a3ea309e89807e3ecde5022c58')
K = {'lzsign': b'q2sIObYXCp2uBZgCNBlY93J3z67hK0wS',
     'f8d9hex': b'f8d992c74b29491d8a3e3fd5f07389d8',
     'f8d9raw': bytes.fromhex('f8d992c74b29491d8a3e3fd5f07389d8'),
     'salt': bytes.fromhex('bd445ef770867f355489b55277334e54dae0e5d9a9dceb05ca7409b437dd740c'),
     'salthex': b'bd445ef770867f355489b55277334e54dae0e5d9a9dceb05ca7409b437dd740c',
     'iv': IVC, 'ivhex': b'e4dc85a3ea309e89807e3ecde5022c58',
     'doh1raw': base64.b64decode('ocjketotfNqSPDUzH+PaEEnrfi7T9h6fDEZnUp4iPBA='),
     'doh1b64': b'ocjketotfNqSPDUzH+PaEEnrfi7T9h6fDEZnUp4iPBA=',
     'doh2raw': base64.b64decode('QV0678YHdblbICFhjCySqmetZwo2hgrTwHymP2mFRqI='),
     'doh2b64': b'QV0678YHdblbICFhjCySqmetZwo2hgrTwHymP2mFRqI=',
     'pkg': b'com.hbsclj.uth', 'lizimh': b'lizimh', 'mechat': b'mechat.fun'}
def enc(k):
    o = {'raw': k, 'md5': hashlib.md5(k).digest(), 'sha256': hashlib.sha256(k).digest(), 'sha1x16': hashlib.sha1(k).digest()[:16]}
    return {n: v for n, v in o.items() if len(v) in (16, 24, 32)}
def ok(d, off):
    for m in MAGS:
        if d[off:off + len(m)] != m: continue
        try:
            im = Image.open(BytesIO(d)); im.load()
            w, h = im.size
            if 200 < w < 3000 and 200 < h < 3000: return True
        except Exception: return False
    return False
hits = []
hitlog = []
def try_all(key, name, cts):
    for kn, kk in enc(key).items():
        for cf in cts:
            ct = cf['data']
            for ivn, iv in [('iv0', b'\0' * 16), ('ivfile', IVC), ('ivct', ct[:16])]:
                try:
                    body = ct[16:] if ivn == 'ivct' else ct
                    n = len(body) // 16 * 16
                    d = AES.new(kk, AES.MODE_CBC, iv).decrypt(body[:max(n, 16)])[:512]
                    for off in (0, 1, 8, 15, 16):
                        if ok(d, off): hitlog.append((name, kn, 'cbc', ivn)); return
                except Exception: pass
            try:
                d = AES.new(kk, AES.MODE_ECB).decrypt(ct[:max(len(ct) // 16 * 16, 16)])[:512]
                for off in (0, 1, 8, 15, 16):
                    if ok(d, off): hitlog.append((name, kn, 'ecb')); return
            except Exception: pass
            for nn, nv in [('n0', b'\0' * 8), ('nct', ct[:8]), ('niv', IVC[:8])]:
                try:
                    c = Counter.new(64, prefix=nv, initial_value=0)
                    d = AES.new(kk, AES.MODE_CTR, counter=c).decrypt(ct[:512])[:512]
                    for off in (0, 1, 8, 15, 16):
                        if ok(d, off): hitlog.append((name, kn, 'ctr', nn)); return
                except Exception: pass
            for nn, nv in [('n12ct', ct[:12]), ('n12iv', IVC[:12]), ('n12z', b'\0' * 12), ('n8ct', ct[:8] + b'\0' * 4), ('n8iv', IVC[:8] + b'\0' * 4)]:
                try:
                    d = ChaCha20.new(key=kk, nonce=nv).decrypt(ct[:512])[:512]
                    for off in (0, 1, 8, 15, 16):
                        if ok(d, off): hitlog.append((name, kn, 'cha', nn)); return
                except Exception: pass
            try:
                d = ARC4.new(kk).decrypt(ct[:256])[:256]
                for off in (0, 1, 8, 15, 16):
                    if ok(d, off): hitlog.append((name, kn, 'rc4')); return
            except Exception: pass
from collections import Counter
cts = []
for p in (1, 2, 3):
    url = 'http://img2.mechat.fun/3/26824/492177/%d.jpg' % p
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Dart/3.5 (dart:io)'})
        cts.append({'url': url, 'data': urllib.request.urlopen(req, timeout=20).read()})
    except Exception as e:
        print('fetch fail', url, e)
print('corpus:', [(c['url'], len(c['data'])) for c in cts])
if not cts: sys.exit(0)
cand = {}
def addc(s, src):
    if s and len(s) >= 16: cand[s] = src
if os.path.exists('/tmp/cands.jsonl'):
    for ln in open('/tmp/cands.jsonl', errors='replace'):
        try:
            j = json.loads(ln)
            m = j.get('msg', j)
            if isinstance(m, dict):
                if m.get('t') == 'c' and m.get('s'): addc(m['s'], 'c')
                if m.get('t') == 'javamsg' and m.get('b64'):
                    try:
                        raw = base64.b64decode(m['b64'])
                        for s in re.findall(rb'[0-9a-fA-F]{32}', raw[:2048]): addc(s.decode(), 'jav')
                    except Exception: pass
        except Exception: pass
import glob as g
for fp in g.glob('/tmp/ctx_*.bin'):
    try:
        d = open(fp, 'rb').read()
        for s in set(re.findall(rb'[0-9a-fA-F]{32}', d)): addc(s.decode(), 'ctx')
    except Exception: pass
if os.path.exists('/tmp/memdump.bin'):
    data = open('/tmp/memdump.bin', 'rb').read(400 * 1024 * 1024)
    for s in set(re.findall(rb'[0-9a-fA-F]{32}', data)): addc(s.decode(), 'mem')
    print('memdump scanned', len(data))
if os.path.exists('pp.txt'):
    pp = open('pp.txt', errors='replace').read()
    for s in set(re.findall(r'[0-9a-fA-F]{32}', pp)): addc(s, 'pp')
print('total candidates:', len(cand))
for name in list(cand):
    hitlog.clear()
    try_all(name.encode(), name, cts)
    if re.fullmatch(r'[0-9a-fA-F]{32}', name):
        try_all(bytes.fromhex(name), name + '!hex', cts)
    if hitlog:
        c = Counter(h[0] for h in hitlog)
        if max(c.values()) >= 2:
            print('KEYFOUND-CONFIRMED', name, hitlog[:3]); hits.extend(hitlog)
        else:
            print('weak-single', name, hitlog[:1])
print('HITS:', len(hits))
open('/tmp/verify_report.txt', 'w').write(json.dumps({'hits': hits, 'n_cand': len(cand)}, default=str))
if hits:
    os.makedirs('frida-hit', exist_ok=True)
    open('frida-hit/KEY_%s.txt' % os.environ.get('VARIANT', 'x'), 'w').write(json.dumps(hits, default=str, indent=1))
'''

procfs_py = r'''
import re, subprocess, os, sys, json
PID = sys.argv[1]
maps = subprocess.run(['adb', 'shell', 'su', '0', 'cat', '/proc/%s/maps' % PID], capture_output=True, text=True).stdout
regions = []; total = 0
for ln in maps.splitlines():
    m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (rw-p) ', ln)
    if not m: continue
    a, b = int(m.group(1), 16), int(m.group(2), 16)
    sz = b - a
    if sz > 128 * 1024 * 1024: continue
    if total + sz > 350 * 1024 * 1024: continue
    regions.append((a, sz)); total += sz
print('regions:', len(regions), 'total', total)
out = open('/tmp/memdump.bin', 'wb')
for a, sz in regions:
    try:
        r = subprocess.run(['adb', 'exec-out', 'su', '0', 'dd', 'if=/proc/%s/mem' % PID, 'bs=4096', 'skip=%d' % (a // 4096), 'count=%d' % ((sz + 4095) // 4096)], capture_output=True, timeout=180)
        out.write(r.stdout[:sz])
    except Exception as e:
        print('region fail', hex(a), e)
out.close()
data = open('/tmp/memdump.bin', 'rb').read()
cands = set(s.decode() for s in re.findall(rb'[0-9a-fA-F]{32}', data))
print('mem bytes', len(data), 'cands', len(cands))
with open('/tmp/cands.jsonl', 'a') as f:
    for c in cands: f.write(json.dumps({'msg': {'t': 'c', 's': c}}) + '\n')
'''

apk_dl = '''
RC=0
curl -fsSL --retry 3 --max-time 600 -o /tmp/app.apk "$APK_URL" || RC=$?
GOT=$(sha256sum /tmp/app.apk 2>/dev/null | cut -d' ' -f1 || echo none)
echo "curl_exit=$RC sha=$GOT" >> "dyn/$TS/run.log"
if [ "$GOT" != "$APK_SHA" ]; then
  echo "APK_URL 速朽，走 configv2 回落" >> "dyn/$TS/run.log"
  NEW=$(curl -fsSL --max-time 30 -A "Dart/3.5 (dart:io)" "http://cdn.mechat.fun/app/api/configv2" | python3 -c "import sys,re; m=re.findall(r'https?://[^\\"]+\\.apk', sys.stdin.read()); print(m[0] if m else '')")
  echo "new_url=$NEW" >> "dyn/$TS/run.log"
  if [ -n "$NEW" ]; then curl -fsSL --retry 3 --max-time 600 -o /tmp/app.apk "$NEW"; GOT=$(sha256sum /tmp/app.apk | cut -d' ' -f1); fi
  [ "$GOT" = "$APK_SHA" ] || { /tmp/hb.sh "$TS" apk-failed; exit 1; }
fi
/tmp/hb.sh "$TS" downloaded
'''

toolchain = '''
export PATH=/usr/local/lib/android/sdk/cmdline-tools/latest/bin:/usr/local/lib/android/sdk/platform-tools:$PATH
sudo chmod 666 /dev/kvm >> "dyn/$TS/run.log" 2>&1 || true
yes | sdkmanager --licenses >/dev/null 2>&1 || true
sdkmanager --install "emulator" "platform-tools" "system-images;android-$API;google_apis;$ABI" >> "dyn/$TS/sdk.log" 2>&1 || true
ls "/usr/local/lib/android/sdk/system-images/android-$API/google_apis/$ABI" >/dev/null 2>&1 || { /tmp/hb.sh "$TS" sdk-image-missing; exit 1; }
pip3 install -q frida==16.5.9 pycryptodome pillow >> "dyn/$TS/sdk.log" 2>&1 || true
echo "PATH=/usr/local/lib/android/sdk/platform-tools:/usr/local/lib/android/sdk/emulator:$PATH" >> "$GITHUB_ENV"
python3 -c "import frida; print('frida', frida.__version__)" >> "dyn/$TS/run.log" 2>&1 || true
/tmp/hb.sh "$TS" toolchain-ready
'''

avd = '''
export PATH=/usr/local/lib/android/sdk/cmdline-tools/latest/bin:$PATH
unset ANDROID_AVD_HOME ANDROID_SDK_HOME ANDROID_USER_HOME ANDROID_PREFS_ROOT
echo no | avdmanager -v create avd -n "$AVD_NAME" -k "system-images;android-$API;google_apis;$ABI" -d pixel_5 --force >> "dyn/$TS/avd.log" 2>&1 || echo no | avdmanager -v create avd -n "$AVD_NAME" -k "system-images;android-$API;google_apis;$ABI" --force >> "dyn/$TS/avd.log" 2>&1
INI=$(find "$HOME" -maxdepth 4 -name "$AVD_NAME.ini" 2>/dev/null | head -1)
[ -n "$INI" ] || { /tmp/hb.sh "$TS" avd-missing; exit 1; }
AVD_HOME=$(dirname "$INI")
echo "AVD_HOME=$AVD_HOME" >> "$GITHUB_ENV"
/tmp/hb.sh "$TS" avd-ready
'''

emulator = '''
export ANDROID_AVD_HOME="$AVD_HOME"
EMU=/usr/local/lib/android/sdk/emulator/emulator
OPTS="-avd $AVD_NAME -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect -camera-back none -camera-front none -writable-system"
nohup $EMU $OPTS -accel on > "dyn/$TS/emulator.log" 2>&1 & EMU_PID=$!
sleep 20
if ! kill -0 "$EMU_PID" 2>/dev/null; then
  echo "accel on 失败回退 off" >> "dyn/$TS/run.log"
  nohup $EMU $OPTS -accel off > "dyn/$TS/emulator.log" 2>&1 & EMU_PID=$!
  sleep 20
fi
echo "EMU_PID=$EMU_PID" >> "$GITHUB_ENV"
adb start-server >> "dyn/$TS/run.log" 2>&1 || true
BOOTED=0
for i in $(seq 1 60); do
  B=$(timeout 15 adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\\r')
  if [ "$B" = "1" ]; then BOOTED=1; echo "boot_ok_loop=$i" >> "dyn/$TS/run.log"; break; fi
  sleep 10
done
[ "$BOOTED" = "1" ] || { /tmp/hb.sh "$TS" boot-timeout; exit 1; }
timeout 60 adb shell settings put global window_animation_scale 0 || true
timeout 60 adb shell settings put global transition_animation_scale 0 || true
timeout 60 adb shell settings put global animator_duration_scale 0 || true
adb root >> "dyn/$TS/run.log" 2>&1 || true; sleep 3
adb install -r -g /tmp/app.apk >> "dyn/$TS/install.log" 2>&1 || { /tmp/hb.sh "$TS" install-failed; exit 1; }
adb shell am start -n "$PKG/.MainActivity" >> "dyn/$TS/run.log" 2>&1 || true
sleep 30
/tmp/hb.sh "$TS" app-up
'''

frida_setup = '''
curl -fsSL --max-time 300 -o /tmp/fs.xz "https://github.com/frida/frida/releases/download/16.5.9/frida-server-16.5.9-android-x86_64.xz" || { /tmp/hb.sh "$TS" frida-dl-failed; exit 1; }
xz -d -k -f /tmp/fs.xz
adb push /tmp/fs /data/local/tmp/fs >> "dyn/$TS/run.log" 2>&1
adb shell "chmod 755 /data/local/tmp/fs; (su 0 /data/local/tmp/fs >/dev/null 2>&1 &) || (/data/local/tmp/fs >/dev/null 2>&1 &)" || true
sleep 5
adb shell "ps -A | grep fs | head -2" >> "dyn/$TS/run.log" 2>&1 || true
/tmp/hb.sh "$TS" frida-server-up
'''

def collector_body(js):
    return '''
PID=$(adb shell pidof $PKG | tr -d '\\r[:space:]')
echo "PID=$PID" >> "$GITHUB_ENV"
echo "''' + b64(harness) + '''" | base64 -d > /tmp/collector.py
echo "''' + b64(js) + '''" | base64 -d > /tmp/variant.js
nohup python3 /tmp/collector.py "$PID" /tmp/variant.js /tmp/cands.jsonl 900 > /tmp/collector.out 2>&1 &
echo $! > /tmp/col.pid
echo "collector=$VARIANT pid=$PID" >> "dyn/$TS/run.log"
'''

uiflow = '''
A() { timeout 20 adb shell "$@" || true; }
sleep 10
A input tap 925 715; sleep 4; A input tap 925 715; sleep 6
A screencap -p /sdcard/m.png; adb pull /sdcard/m.png "dyn/$TS/inter-modal.png" >/dev/null 2>&1 || true
A input tap 450 730; sleep 4
A input text "928081274@qq.com"; sleep 3
A input keyevent 111; sleep 2
A input tap 78 1015; sleep 2
A input tap 450 890; sleep 4
A input text "Zmh20100227"; sleep 3
A input keyevent 111; sleep 2
A input tap 540 1212; sleep 15
A screencap -p /sdcard/l.png; adb pull /sdcard/l.png "dyn/$TS/inter-loggedin.png" >/dev/null 2>&1 || true
python3 -c "from PIL import Image; im=Image.open('dyn/$TS/inter-loggedin.png').convert('RGB'); w,h=im.size; px=im.getpixel((w//2,int(1212*h//2340))); print('login_check px=%s'%(px,)); open('/tmp/ABORT','w').write('1') if (px[0]>200 and px[1]>150 and px[2]<130 and px[0]-px[2]>80) else print('login_passed')" >> "dyn/$TS/run.log" 2>&1 || true
if [ -f /tmp/ABORT ]; then
  echo "fast-fail: 登录未成，触发dump后提前收尾" >> "dyn/$TS/run.log"; /tmp/hb.sh "$TS" fastfail-login; touch /tmp/go_dump
else
  A input keyevent 4; sleep 3; A input keyevent 4; sleep 3
  A input tap 270 700; sleep 20
  A screencap -p /sdcard/d.png; adb pull /sdcard/d.png "dyn/$TS/inter-detail.png" >/dev/null 2>&1 || true
  A input tap 700 2150; sleep 15
  A screencap -p /sdcard/p0.png; adb pull /sdcard/p0.png "dyn/$TS/inter-page0.png" >/dev/null 2>&1 || true
  touch /tmp/go_dump
  for s in 1 2 3 4 5 6 7 8; do
    A input swipe 540 1800 540 600 400; sleep 10
    A screencap -p /sdcard/pg$s.png; adb pull /sdcard/pg$s.png "dyn/$TS/inter-page$s.png" >/dev/null 2>&1 || true
  done
  sleep 15
  echo "uiflow=done" >> "dyn/$TS/run.log"
fi
/tmp/hb.sh "$TS" uidrive-done
'''

procfs_dump = '''
PID=$(adb shell pidof $PKG | tr -d '\\r[:space:]')
echo "''' + b64(procfs_py) + '''" | base64 -d > /tmp/procfs.py
python3 /tmp/procfs.py "$PID" >> "dyn/$TS/run.log" 2>&1 || true
/tmp/hb.sh "$TS" procfs-done
'''

stop_collector = '''
kill $(cat /tmp/col.pid) 2>/dev/null || true
sleep 2
wc -l /tmp/cands.jsonl >> "dyn/$TS/run.log" 2>&1 || true
ls -la /tmp/memdump.bin >> "dyn/$TS/run.log" 2>&1 || true
ls /tmp/ctx_*.bin >> "dyn/$TS/run.log" 2>&1 | head -20 || true
'''

verify_step = '''
touch /tmp/cands.jsonl 2>/dev/null || true
echo "''' + b64(verify) + '''" | base64 -d > /tmp/verify.py
python3 /tmp/verify.py >> "dyn/$TS/run.log" 2>&1 || true
if grep -qa KEYFOUND-CONFIRMED "dyn/$TS/run.log"; then
  mkdir -p frida-hit
  cp /tmp/verify_report.txt frida-hit/ 2>/dev/null || true
  /tmp/hb.sh "$TS" -a KEYFOUND
fi
cp /tmp/cands.jsonl "dyn/$TS/" 2>/dev/null || true
cp /tmp/verify_report.txt "dyn/$TS/" 2>/dev/null || true
cp /tmp/collector.out "dyn/$TS/" 2>/dev/null || true
if [ -f /tmp/memdump.bin ]; then gzip -1 -c /tmp/memdump.bin > "dyn/$TS/memdump.gz" 2>/dev/null || true; fi
/tmp/hb.sh "$TS" -a done
'''

EMUC = "$" + "{{ matrix.variant != 'offlinebrute' }}"
PROC = "$" + "{{ matrix.variant == 'procfs' }}"
OB = "$" + "{{ matrix.variant == 'offlinebrute' }}"
NEMU = "$" + "{{ matrix.variant != 'procfs' && matrix.variant != 'offlinebrute' }}"
V = "$" + "{{ matrix.variant }}"

boot_body = '''
TS=$(date -u +%Y%m%d-%H%M%S)
echo "TS=$TS" >> "$GITHUB_ENV"
echo "VARIANT=@V@" >> "$GITHUB_ENV"
echo "BR=re/frida-$TS-@V@" >> "$GITHUB_ENV"
git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"
mkdir -p "dyn/$TS"
echo "== start $(date -u) variant=@V@ ==" >> "dyn/$TS/run.log"
cat > /tmp/hb.sh <<'HB'
#!/usr/bin/env bash
cd "$GITHUB_WORKSPACE" || exit 0
FULL=0
if [ "$1" = "-a" ]; then FULL=1; shift; fi
TS="$1"; shift
echo "[$(date -u +%H:%M:%S)] $*" >> "dyn/$TS/run.log"
git add -A "dyn/$TS" 2>/dev/null || true
git add frida-hit 2>/dev/null || true
git commit -q -m "hb: @V@ $*" 2>/dev/null
git push -q origin "HEAD:refs/heads/re/frida-$TS-@V@" 2>/dev/null || true
HB
chmod +x /tmp/hb.sh
/tmp/hb.sh "$TS" init
'''

parts = []
parts.append('name: RE-Frida 密钥猎杀矩阵 v2')
parts.append('')
parts.append('on:')
parts.append('  workflow_dispatch: {}')
parts.append('  push:')
parts.append('    branches:')
parts.append('      - re/frida-*')
parts.append('')
parts.append('permissions:')
parts.append('  contents: write')
parts.append('')
parts.append('env:')
parts.append('  PKG: com.hbsclj.uth')
parts.append("  APK_URL: 'https://alicm.a.etoote.com/bs2/ad-app/YWQtYXBwOmFkX2RzcF9hcHA6NTY1MTEyMTU0NzpNRVJDSEFOVDpbQkA3MzE3MjYyZToyNDE5OTczMjAyMzU0Nw%3D%3D.apk'")
parts.append("  APK_SHA: '235162605907f6c26c39d3f877af387a915ea8b6f3ca000d358111a0aefa2ab2'")
parts.append("  APK_SIZE: '43291746'")
parts.append("  API: '33'")
parts.append("  ABI: 'x86_64'")
parts.append('  AVD_NAME: probe')
parts.append('')
parts.append('jobs:')
parts.append('  hunt:')
parts.append('    runs-on: ubuntu-latest')
parts.append('    timeout-minutes: 40')
parts.append('    strategy:')
parts.append('      fail-fast: false')
parts.append('      matrix:')
parts.append('        variant: [glob32, candctx, sbox, writehook, sockethook, javabridge, procfs, offlinebrute]')
parts.append('    steps:')
parts.append('      - name: Checkout')
parts.append('        uses: actions/checkout@v4')
parts.append('')
parts.append(step('0. Bootstrap', boot_body))
parts.append('')
parts.append(step('1. APK 下载+校验', apk_dl, cond=EMUC))
parts.append('')
parts.append(step('2. 工具链+frida客户端+PATH注入', toolchain, cond=EMUC))
parts.append('')
parts.append(step('3. AVD', avd, cond=EMUC))
parts.append('')
parts.append(step('4. 模拟器+装机+启动App', emulator, cond=EMUC))
parts.append('')
parts.append(step('5. frida-server 部署', frida_setup, cond=NEMU))
parts.append('')
for v, js in [('glob32', glob32), ('candctx', candctx), ('sbox', sboxjs), ('writehook', writehook), ('sockethook', sockethook), ('javabridge', javabridge)]:
    parts.append(step('6c. 采集器[%s]' % v, collector_body(js), cond="$" + "{{ matrix.variant == '%s' }}" % v))
    parts.append('')
parts.append(step('6p. [procfs] 采集器跳过', 'echo "procfs: post-harvest instead" >> "dyn/$TS/run.log"', cond=PROC))
parts.append(step('6o. [offlinebrute] 跳过模拟器', 'echo "offlinebrute: no emulator" >> "dyn/$TS/run.log"', cond=OB))
parts.append('')
parts.append(step('7. UI 驱动（登录+翻页+触发dump）', uiflow, cond=EMUC))
parts.append('')
parts.append(step('7b. procfs 内存收割', procfs_dump, cond=PROC))
parts.append('')
parts.append(step('8. 停止采集器', stop_collector, cond=NEMU))
parts.append('')
parts.append(step('9. 候选验证', verify_step))
parts.append('')
parts.append(step('10. 收尾清单', 'ls -la dyn/$TS >> "dyn/$TS/run.log" 2>&1 || true'))
parts.append('')
parts.append('      - name: 11. Upload artifact')
parts.append('        if: always()')
parts.append('        uses: actions/upload-artifact@v4')
parts.append('        with:')
parts.append('          name: frida-hunt-@V@')
parts.append('          path: dyn/')
parts.append('          if-no-files-found: ignore')
parts.append('          retention-days: 7')
parts.append('')
parts.append('      - name: 11b. Upload hit')
parts.append('        if: always()')
parts.append('        uses: actions/upload-artifact@v4')
parts.append('        with:')
parts.append('          name: frida-hit-@V@')
parts.append('          path: frida-hit/')
parts.append('          if-no-files-found: ignore')
parts.append('          retention-days: 30')

yml = '\n'.join(parts)
yml = yml.replace('@V@', V)
ast.parse(verify); ast.parse(harness); ast.parse(procfs_py)
open('.github/workflows/frida-hunt.yml', 'w').write(yml)
d = yaml.safe_load(open('.github/workflows/frida-hunt.yml'))
print('BUILD OK v2, steps:', len(d['jobs']['hunt']['steps']))
