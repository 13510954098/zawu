#!/usr/bin/env python3
"""Comprehensive black-box Android Emulator dynamic analysis & privacy/network/UI audit."""
import base64
import hashlib
import json
import os
import pathlib
import re
import socket
import struct
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET
from collections import Counter

PKG = "com.clggjv.xcjfmd.ffo"
MAIN_ACTIVITY = "com.clggjv.xcjfmd.ffo/com.clggjv.xcjfmd.ffo.MainActivity"
APK_PATH = pathlib.Path("work/sample.apk")
REPORT_DIR = pathlib.Path("work/deep_dynamic")
STEP_LOG = pathlib.Path("work/step_dynamic.log")

NOISE_IPS = {"168.63.129.16", "169.254.169.254", "127.0.0.1", "10.0.2.2", "10.0.2.3", "10.0.2.15"}
GMS_NOISE_SUFFIXES = (
    "googleapis.com",
    "gstatic.com",
    "google.com",
    "googleadservices.com",
    "doubleclick.net",
    "gvt1.com",
    "gvt2.com",
    "android.com",
)


def log(msg: str):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    STEP_LOG.parent.mkdir(parents=True, exist_ok=True)
    with STEP_LOG.open("a") as f:
        f.write(line + "\n")


def run_cmd(cmd, timeout=120, check=False, text=True):
    try:
        p = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if text else subprocess.PIPE,
            timeout=timeout,
            text=text,
            check=check,
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ("" if text else b"")
        if not text and isinstance(out, str):
            out = out.encode()
        return 124, out


def adb(*args, timeout=60, text=True):
    return run_cmd(["adb", *args], timeout=timeout, text=text)


def is_gms_noise(domain: str) -> bool:
    d = domain.lower().strip(".")
    return any(d == suf or d.endswith("." + suf) for suf in GMS_NOISE_SUFFIXES)


def parse_dns_qname(buf, offset):
    labels = []
    jumped = False
    jumps = 0
    orig_next = offset
    while offset < len(buf):
        length = buf[offset]
        if length == 0:
            if not jumped:
                orig_next = offset + 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                orig_next = offset + 2
            jumped = True
            offset = ptr
            jumps += 1
            if jumps > 10:
                break
            continue
        offset += 1
        if offset + length > len(buf):
            break
        labels.append(buf[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), orig_next


def extract_tls_sni(payload):
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    try:
        pos = 5 + 4 + 2 + 32
        if pos >= len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len
        if pos + 2 > len(payload):
            return None
        cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cs_len
        if pos >= len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            if ext_type == 0x0000 and pos + 2 <= end:
                list_len = struct.unpack("!H", payload[pos:pos + 2])[0]
                spos = pos + 2
                send = min(end, spos + list_len)
                while spos + 3 <= send:
                    name_type = payload[spos]
                    name_len = struct.unpack("!H", payload[spos + 1:spos + 3])[0]
                    spos += 3
                    if name_type == 0 and spos + name_len <= send:
                        return payload[spos:spos + name_len].decode("ascii", "replace")
                    spos += name_len
            pos += ext_len
    except Exception:
        return None
    return None


def parse_pcap(pcap_path: pathlib.Path):
    app_dns = Counter()
    gms_dns = Counter()
    app_sni = Counter()
    gms_sni = Counter()
    http_requests = []
    tcp_endpoints = Counter()

    if not pcap_path.exists() or pcap_path.stat().st_size < 24:
        return {"app_dns": {}, "app_tls_sni": {}, "http_cleartext": [], "tcp_endpoints": {}, "gms_background_dns": {}}

    data = pcap_path.read_bytes()
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    _, _, _, _, _, _, linktype = struct.unpack(endian + "IHHiIII", data[:24])
    lhdr = {1: 14, 113: 16, 276: 20, 101: 0}.get(linktype)
    if lhdr is None:
        return {"error": f"unsupported_linktype_{linktype}"}

    pos = 24
    seen_http = set()
    while pos + 16 <= len(data):
        _, _, incl_len, _ = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        pkt = data[pos:pos + incl_len]
        pos += incl_len
        if len(pkt) < lhdr + 20:
            continue
        if linktype == 1:
            ethertype = struct.unpack("!H", pkt[12:14])[0]
        elif linktype == 113:
            ethertype = struct.unpack("!H", pkt[14:16])[0]
        elif linktype == 276:
            ethertype = struct.unpack("!H", pkt[0:2])[0]
        else:
            ethertype = 0x0800
        if ethertype != 0x0800:
            continue

        ip = pkt[lhdr:]
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl:
            continue
        proto = ip[9]
        src_ip = socket.inet_ntoa(ip[12:16])
        dst_ip = socket.inet_ntoa(ip[16:20])
        if src_ip in NOISE_IPS or dst_ip in NOISE_IPS:
            continue
        l4 = ip[ihl:]

        if proto == 17 and len(l4) >= 8:
            sport, dport = struct.unpack("!HH", l4[:4])
            dns = l4[8:]
            if dport == 53 and len(dns) >= 12:
                qdcount = struct.unpack("!H", dns[4:6])[0]
                off = 12
                for _ in range(min(qdcount, 4)):
                    qname, off = parse_dns_qname(dns, off)
                    if qname:
                        qn = qname.lower()
                        if is_gms_noise(qn):
                            gms_dns[qn] += 1
                        else:
                            app_dns[qn] += 1
                    off += 4
        elif proto == 6 and len(l4) >= 20:
            sport, dport = struct.unpack("!HH", l4[:4])
            flags = l4[13]
            if (flags & 0x02) and not (flags & 0x10):
                if not dst_ip.startswith(("127.", "10.0.2.")):
                    tcp_endpoints[f"{dst_ip}:{dport}"] += 1
            doff = ((l4[12] >> 4) & 0x0F) * 4
            payload = l4[doff:]
            if not payload:
                continue
            sni = extract_tls_sni(payload)
            if sni:
                sn = sni.lower()
                if is_gms_noise(sn):
                    gms_sni[sn] += 1
                else:
                    app_sni[sn] += 1
            elif payload[:5] in (b"GET /", b"POST ", b"HEAD ", b"PUT /"):
                head_txt = payload[:1024].decode("latin1", "replace")
                lines = head_txt.split("\r\n")
                req_line = lines[0][:180]
                host_hdr = ""
                for ln in lines[1:15]:
                    if ln.lower().startswith("host:"):
                        host_hdr = ln.split(":", 1)[1].strip()
                        break
                key = (host_hdr, req_line)
                if key not in seen_http and len(http_requests) < 80:
                    seen_http.add(key)
                    http_requests.append({"host": host_hdr, "request": req_line, "dst": f"{dst_ip}:{dport}"})

    return {
        "app_dns": dict(app_dns.most_common(100)),
        "app_tls_sni": dict(app_sni.most_common(100)),
        "http_cleartext": http_requests,
        "tcp_endpoints": dict(tcp_endpoints.most_common(80)),
        "gms_background_dns": dict(gms_dns.most_common(30)),
        "gms_background_sni": dict(gms_sni.most_common(30)),
    }


class StagePcap:
    def __init__(self, out_dir: pathlib.Path, stage_name: str):
        self.pcap_path = out_dir / f"{stage_name}.pcap"
        self.out_json = out_dir / f"{stage_name}_net.json"
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", "any", "-U", "-s", "1024", "-w", str(self.pcap_path), "udp port 53 or tcp"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.6)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.proc:
            subprocess.run(["sudo", "kill", "-INT", str(self.proc.pid)], stdin=subprocess.DEVNULL, check=False)
            try:
                self.proc.wait(timeout=5)
            except Exception:
                subprocess.run(["sudo", "kill", "-9", str(self.proc.pid)], stdin=subprocess.DEVNULL, check=False)
        parsed = parse_pcap(self.pcap_path)
        self.out_json.write_text(json.dumps(parsed, indent=2, ensure_ascii=False))
        if self.pcap_path.exists():
            self.pcap_path.unlink()


def parse_bounds(bounds_str: str):
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str or "")
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    return (x1, y1, x2, y2, (x1 + x2) // 2, (y1 + y2) // 2)


def snapshot_ui(prefix: str):
    png_path = REPORT_DIR / f"{prefix}.png"
    xml_path = REPORT_DIR / f"{prefix}.xml"
    rc, png_bytes = adb("exec-out", "screencap", "-p", timeout=20, text=False)
    if rc == 0 and png_bytes and png_bytes.startswith(b"\x89PNG"):
        png_path.write_bytes(png_bytes)

    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml", timeout=15)
    rc_x, xml_txt = adb("shell", "cat", "/sdcard/ui.xml", timeout=10)
    nodes = []
    if rc_x == 0 and "<?xml" in xml_txt:
        idx = xml_txt.find("<?xml")
        clean_xml = xml_txt[idx:]
        xml_path.write_text(clean_xml)
        try:
            root = ET.fromstring(clean_xml)
            for el in root.iter("node"):
                txt = (el.attrib.get("text") or "").strip()
                desc = (el.attrib.get("content-desc") or "").strip()
                b = parse_bounds(el.attrib.get("bounds", ""))
                clickable = el.attrib.get("clickable") == "true"
                cls = el.attrib.get("class", "")
                pkg = el.attrib.get("package", "")
                if txt or desc or clickable:
                    nodes.append({
                        "text": txt,
                        "desc": desc,
                        "label": txt or desc,
                        "clickable": clickable,
                        "class": cls,
                        "package": pkg,
                        "bounds": b,
                    })
        except Exception as e:
            log(f"XML parse error on {prefix}: {e}")
    return nodes


def find_node(nodes, keywords, require_clickable=False, min_y=0, max_y=2280):
    if isinstance(keywords, str):
        keywords = [keywords]
    for kw in keywords:
        for n in nodes:
            b = n["bounds"]
            if not b:
                continue
            if not (min_y <= b[5] <= max_y):
                continue
            if require_clickable and not n["clickable"]:
                continue
            if kw in n["label"]:
                return n
    return None


def tap(x: int, y: int, desc: str = ""):
    log(f"TAP ({x}, {y}) {desc}")
    adb("shell", "input", "tap", str(x), str(y), timeout=10)


def ensure_foreground():
    _, resumed = adb("shell", "dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity' || true")
    if PKG not in resumed:
        log("App left foreground; bringing MainActivity back...")
        adb("shell", "am", "start", "-n", MAIN_ACTIVITY, timeout=15)
        time.sleep(3)


def boot_emulator(sdk_root: str):
    emu_bin = str(pathlib.Path(sdk_root) / "emulator" / "emulator")
    emu_log = open("work/emulator.log", "w")
    log("Starting headless KVM emulator...")
    proc = subprocess.Popen(
        [
            emu_bin,
            "-avd", "test_avd",
            "-no-window",
            "-gpu", "swiftshader_indirect",
            "-no-audio",
            "-no-boot-anim",
            "-no-snapshot",
            "-partition-size", "6144",
            "-memory", "4096",
        ],
        stdin=subprocess.DEVNULL,
        stdout=emu_log,
        stderr=subprocess.STDOUT,
    )
    adb("wait-for-device", timeout=60)
    for i in range(120):
        if proc.poll() is not None:
            raise RuntimeError(f"Emulator exited early with code {proc.returncode}")
        rc, out = adb("shell", "getprop", "sys.boot_completed", timeout=10)
        if rc == 0 and out.strip() == "1":
            log(f"Emulator booted in {i * 2}s")
            time.sleep(6)
            return proc, emu_log
        time.sleep(2)
    raise RuntimeError("Emulator boot timeout")


def collect_uid_sockets(uid: int):
    sockets = []
    for proto_name in ("tcp", "tcp6", "udp", "udp6"):
        rc, txt = adb("shell", f"cat /proc/net/{proto_name}", timeout=10)
        if rc != 0:
            continue
        for ln in txt.splitlines()[1:]:
            parts = ln.split()
            if len(parts) >= 8 and parts[7].isdigit() and int(parts[7]) == uid:
                sockets.append({"proto": proto_name, "local": parts[1], "rem": parts[2], "st": parts[3]})
    return sockets


def collect_os_forensics(uid: int):
    forensics = {}
    _, appops = adb("shell", "cmd", "appops", "get", PKG, timeout=15)
    forensics["appops"] = appops.strip()

    _, sensors = adb("shell", "dumpsys", "sensorservice", timeout=15)
    # Extract active sensor connections & recent sensor events
    sensor_lines = []
    in_active = False
    for ln in sensors.splitlines():
        if any(k in ln for k in ("Sensor List", "Active sensors:", "Socket Buffer", "Connection Number:", PKG, "Accelerometer", "Gyroscope", "Linear Acceleration", "Rotation Vector")):
            sensor_lines.append(ln)
    forensics["sensorservice_filtered"] = "\n".join(sensor_lines[:200])
    (REPORT_DIR / "dumpsys_sensorservice.txt").write_text(sensors[:200_000])

    _, services = adb("shell", "dumpsys", "activity", "services", PKG, timeout=15)
    forensics["active_services"] = services.strip()[:10_000]

    _, procs = adb("shell", f"ps -A -o USER,PID,PPID,VSZ,RSS,NAME | grep -E 'clggjv|ffo|kwad|bytedance|webview' || true", timeout=10)
    forensics["processes"] = procs.strip()

    _, jobs = adb("shell", f"dumpsys jobscheduler | grep -E -A 18 '{PKG}' || true", timeout=15)
    forensics["jobscheduler"] = jobs.strip()[:8000]

    _, alarms = adb("shell", f"dumpsys alarm | grep -E -A 8 -B 1 '{PKG}' || true", timeout=15)
    forensics["alarms"] = alarms.strip()[:8000]

    _, media = adb("shell", "dumpsys media.player || true", timeout=10)
    forensics["media_player"] = media.strip()[:6000]

    forensics["uid_sockets_snapshot"] = collect_uid_sockets(uid)

    # Sandbox directory metadata inventory (metadata & non-binary config keys only; NO memory/DEX dumping)
    _, data_tree = adb("shell", f"find /data/data/{PKG} -maxdepth 3 -exec ls -ld {{}} + 2>/dev/null || true", timeout=20)
    (REPORT_DIR / "sandbox_data_tree.txt").write_text(data_tree)

    _, ext_tree = adb("shell", f"find /sdcard/Android/data/{PKG} -maxdepth 3 -exec ls -ld {{}} + 2>/dev/null || true", timeout=15)
    (REPORT_DIR / "sandbox_ext_tree.txt").write_text(ext_tree)

    # Inspect shared_prefs XML key names & types (redact long string values > 48 chars to avoid leaking session tokens)
    _, sp_list = adb("shell", f"ls -1 /data/data/{PKG}/shared_prefs 2>/dev/null || true", timeout=10)
    sp_summary = {}
    for sp_file in [x.strip() for x in sp_list.splitlines() if x.strip().endswith(".xml")]:
        _, sp_xml = adb("shell", f"cat '/data/data/{PKG}/shared_prefs/{sp_file}' 2>/dev/null || true", timeout=10)
        entries = []
        try:
            idx = sp_xml.find("<?xml")
            if idx >= 0:
                root = ET.fromstring(sp_xml[idx:])
                for child in root:
                    k = child.attrib.get("name", "")
                    val = child.attrib.get("value") if "value" in child.attrib else (child.text or "")
                    if val and len(val) > 64:
                        val = val[:32] + f"...(len={len(val)})"
                    entries.append({"tag": child.tag, "name": k, "value": val})
        except Exception as e:
            entries.append({"parse_error": str(e)})
        sp_summary[sp_file] = entries
    (REPORT_DIR / "shared_prefs_summary.json").write_text(json.dumps(sp_summary, indent=2, ensure_ascii=False))

    # Loaded module paths from /proc/<pid>/maps (unique file paths only — zero memory bytes read)
    _, pid_out = adb("shell", "pidof", PKG, timeout=10)
    pids = [p for p in pid_out.strip().split() if p.isdigit()]
    if pids:
        main_pid = pids[0]
        _, maps_paths = adb(
            "shell",
            f"awk '$6 ~ /^\\// {{print $6}}' /proc/{main_pid}/maps | sort -u | grep -vE '^/(system|apex|vendor|product|dev)/' || true",
            timeout=10,
        )
        forensics["loaded_non_system_modules"] = [x.strip() for x in maps_paths.splitlines() if x.strip()]
        _, threads = adb("shell", f"ls /proc/{main_pid}/task | xargs -I{{}} cat /proc/{main_pid}/task/{{}}/comm 2>/dev/null | sort | uniq -c | sort -nr || true", timeout=15)
        forensics["thread_names"] = threads.strip()

    (REPORT_DIR / "os_forensics.json").write_text(json.dumps(forensics, indent=2, ensure_ascii=False))
    return forensics


def upload_report_tarball(tar_path: pathlib.Path):
    repo = os.environ["REPO"]
    commit_sha = os.environ["COMMIT_SHA"]
    data = tar_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    chunk_size = 18 * 1024 * 1024
    blobs = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        payload = pathlib.Path("work/dyn_blob_payload.json")
        payload.write_text(json.dumps({
            "encoding": "base64",
            "content": base64.b64encode(chunk).decode("ascii"),
        }))
        res = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/git/blobs", "--method", "POST", "--input", str(payload)],
            stdin=subprocess.DEVNULL,
            text=True,
        )
        blobs.append({"sha": json.loads(res)["sha"], "size": len(chunk)})

    manifest = {
        "type": "deep_dynamic_report",
        "sha256": sha256,
        "size": len(data),
        "blobs": blobs,
    }
    comment_payload = pathlib.Path("work/dyn_comment.json")
    comment_payload.write_text(json.dumps({"body": json.dumps(manifest)}))
    subprocess.check_call(
        ["gh", "api", f"repos/{repo}/commits/{commit_sha}/comments", "--method", "POST", "--input", str(comment_payload)],
        stdin=subprocess.DEVNULL,
    )


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    sdk_root = os.environ.get("ANDROID_HOME") or "/usr/local/lib/android/sdk"
    emu_proc, emu_log = boot_emulator(sdk_root)
    actions_log = []

    try:
        # Enable root adbd for system diagnostics (appops, sensorservice, sandbox file ls)
        adb("root", timeout=20)
        time.sleep(2)
        adb("wait-for-device", timeout=30)

        adb("shell", "input", "keyevent", "82")
        adb("shell", "wm", "dismiss-keyguard")
        for setting in ("window_animation_scale", "transition_animation_scale", "animator_duration_scale"):
            adb("shell", "settings", "put", "global", setting, "0")
        adb("shell", "am", "broadcast", "-a", "android.intent.action.CLOSE_SYSTEM_DIALOGS")

        rc, out = adb("install", "-r", str(APK_PATH), timeout=120)
        log(f"APK install rc={rc}: {out.strip()}")
        if rc != 0:
            raise RuntimeError(f"Install failed: {out}")

        _, pkg_dump = adb("shell", "dumpsys", "package", PKG, timeout=30)
        (REPORT_DIR / "dumpsys_package.txt").write_text(pkg_dump)
        m_uid = re.search(r"userId=(\d+)", pkg_dump)
        uid = int(m_uid.group(1)) if m_uid else -1
        log(f"Package UID={uid}")

        adb("logcat", "-G", "16M")  # Increase logcat ring buffer to 16MB so zero startup lines roll off!
        adb("logcat", "-c")

        # === STAGE 1: Cold Launch & Announcement Modal -> Home ===
        log("=== STAGE 1: Launch & Dismiss Startup Modal ===")
        with StagePcap(REPORT_DIR, "stage1_launch"):
            adb("shell", "am", "start", "-W", "-n", MAIN_ACTIVITY, timeout=30)
            time.sleep(14)
            nodes_modal = snapshot_ui("01_startup_modal")
            actions_log.append({"stage": "01_startup_modal", "node_count": len(nodes_modal), "labels": [n["label"] for n in nodes_modal if n["label"]][:25]})

            btn = find_node(nodes_modal, ["已知晓", "我知道了", "同意", "关闭", "进入"])
            if btn and btn["bounds"]:
                tap(btn["bounds"][4], btn["bounds"][5], f"modal_btn:{btn['label']}")
            else:
                tap(540, 1558, "modal_btn_fallback")
            time.sleep(4)
            nodes_home = snapshot_ui("02_home_featured")
            actions_log.append({"stage": "02_home_featured", "node_count": len(nodes_home), "labels": [n["label"] for n in nodes_home if n["label"]][:40]})

        # === STAGE 2: Category Tabs & Search ===
        log("=== STAGE 2: Category Tabs & Search ===")
        with StagePcap(REPORT_DIR, "stage2_browse_search"):
            ensure_foreground()
            tab_riman = find_node(nodes_home, ["日漫"], max_y=400)
            if tab_riman:
                tap(tab_riman["bounds"][4], tab_riman["bounds"][5], "tab_riman")
            else:
                tap(245, 250, "tab_riman_fallback")
            time.sleep(4)
            nodes_riman = snapshot_ui("03_tab_riman")
            actions_log.append({"stage": "03_tab_riman", "labels": [n["label"] for n in nodes_riman if n["label"]][:30]})

            tab_movie = find_node(nodes_riman or nodes_home, ["剧场版"], max_y=400)
            if tab_movie:
                tap(tab_movie["bounds"][4], tab_movie["bounds"][5], "tab_movie")
            else:
                tap(415, 250, "tab_movie_fallback")
            time.sleep(4)
            nodes_movie = snapshot_ui("04_tab_movie")
            actions_log.append({"stage": "04_tab_movie", "labels": [n["label"] for n in nodes_movie if n["label"]][:30]})

            # Switch back to 精选
            tab_feat = find_node(nodes_movie or nodes_home, ["精选"], max_y=400)
            if tab_feat:
                tap(tab_feat["bounds"][4], tab_feat["bounds"][5], "tab_featured")
            else:
                tap(80, 250, "tab_featured_fallback")
            time.sleep(3)

            # Tap Search bar
            nodes_curr = snapshot_ui("04b_back_featured")
            search_bar = find_node(nodes_curr, ["今天你想看", "搜索"], max_y=300)
            if search_bar:
                tap(search_bar["bounds"][4], search_bar["bounds"][5], "search_bar")
            else:
                tap(450, 145, "search_bar_fallback")
            time.sleep(4)
            nodes_search = snapshot_ui("05_search_page")
            actions_log.append({"stage": "05_search_page", "labels": [n["label"] for n in nodes_search if n["label"]][:35]})

            # Input query "JOJO" & submit
            adb("shell", "input", "text", "JOJO")
            time.sleep(1.5)
            adb("shell", "input", "keyevent", "66")
            btn_do_search = find_node(nodes_search, ["搜索"], max_y=300)
            if btn_do_search:
                tap(btn_do_search["bounds"][4], btn_do_search["bounds"][5], "search_submit")
            time.sleep(5)
            nodes_sres = snapshot_ui("06_search_results")
            actions_log.append({"stage": "06_search_results", "labels": [n["label"] for n in nodes_sres if n["label"]][:35]})

        # === STAGE 3: Anime Detail & Video Playback (libmpv + Pre-roll Ad Slot Check) ===
        log("=== STAGE 3: Detail & Video Playback ===")
        with StagePcap(REPORT_DIR, "stage3_detail_playback"):
            ensure_foreground()
            # Look for a result card in 06_search_results or navigate back to home and pick a card
            card = None
            for n in nodes_sres:
                if n["bounds"] and 300 <= n["bounds"][5] <= 1850 and len(n["label"]) >= 3 and n["label"] not in ("搜索", "取消", "历史记录", "热门搜索"):
                    card = n
                    break
            if card:
                tap(card["bounds"][4], card["bounds"][5], f"search_card:{card['label'][:24]}")
            else:
                adb("shell", "input", "keyevent", "4")
                time.sleep(2)
                nodes_h2 = snapshot_ui("06b_home_for_card")
                for n in nodes_h2:
                    if n["bounds"] and 850 <= n["bounds"][5] <= 1850 and len(n["label"]) >= 4:
                        card = n
                        break
                if card:
                    tap(card["bounds"][4], card["bounds"][5], f"home_card:{card['label'][:24]}")
                else:
                    tap(190, 1680, "home_card_coords_fallback")

            time.sleep(8)
            nodes_detail = snapshot_ui("07_detail_or_player_8s")
            actions_log.append({"stage": "07_detail_or_player_8s", "labels": [n["label"] for n in nodes_detail if n["label"]][:40]})

            # Try tapping episode 1 / play if visible, and wait 12s to observe video stream / ad SDK behavior
            ep_node = find_node(nodes_detail, ["第01集", "第1集", "01", "立即播放", "播放"], min_y=400, max_y=2000)
            if ep_node:
                tap(ep_node["bounds"][4], ep_node["bounds"][5], f"episode:{ep_node['label'][:20]}")
            time.sleep(12)
            nodes_play = snapshot_ui("08_playback_20s")
            actions_log.append({"stage": "08_playback_20s", "labels": [n["label"] for n in nodes_play if n["label"]][:40]})

        # === STAGE 4: Welfare (福利) & Profile (我的) & Login ===
        log("=== STAGE 4: Welfare, Profile & Login ===")
        with StagePcap(REPORT_DIR, "stage4_welfare_profile"):
            # Navigate back to root tabs
            for _ in range(3):
                ensure_foreground()
                curr_nodes = snapshot_ui("tmp_nav_check")
                if find_node(curr_nodes, ["福利", "我的"], min_y=1900):
                    break
                adb("shell", "input", "keyevent", "4")
                time.sleep(2.5)

            curr_nodes = snapshot_ui("08b_root_tabs")
            welfare_tab = find_node(curr_nodes, ["福利"], min_y=1850)
            if welfare_tab:
                tap(welfare_tab["bounds"][4], welfare_tab["bounds"][5], "tab_welfare")
            else:
                tap(540, 2060, "tab_welfare_fallback")
            time.sleep(5)
            nodes_welfare = snapshot_ui("09_welfare_tab")
            actions_log.append({"stage": "09_welfare_tab", "labels": [n["label"] for n in nodes_welfare if n["label"]][:35]})

            profile_tab = find_node(nodes_welfare or curr_nodes, ["我的"], min_y=1850)
            if profile_tab:
                tap(profile_tab["bounds"][4], profile_tab["bounds"][5], "tab_profile")
            else:
                tap(895, 2060, "tab_profile_fallback")
            time.sleep(5)
            nodes_profile = snapshot_ui("10_profile_tab")
            actions_log.append({"stage": "10_profile_tab", "labels": [n["label"] for n in nodes_profile if n["label"]][:40]})

            login_btn = find_node(nodes_profile, ["登录", "注册", "点击登录"], max_y=1200)
            if login_btn:
                tap(login_btn["bounds"][4], login_btn["bounds"][5], f"login:{login_btn['label'][:20]}")
                time.sleep(4)
                nodes_login = snapshot_ui("11_login_page")
                actions_log.append({"stage": "11_login_page", "labels": [n["label"] for n in nodes_login if n["label"]][:35]})

        # === STAGE 5: OS Forensics, AppOps, Sensors, Services & Logcat ===
        log("=== STAGE 5: Collecting OS Forensics & Full Logcat ===")
        forensics = collect_os_forensics(uid)

        _, logcat_all = adb("logcat", "-d", "-v", "time", timeout=40)
        (REPORT_DIR / "logcat_all.txt").write_text(logcat_all)

        _, crash_log = adb("logcat", "-d", "-b", "crash", "-v", "time", timeout=15)
        (REPORT_DIR / "logcat_crash.txt").write_text(crash_log)

        app_log_re = re.compile(
            r"(flutter|mpv|media_kit|isar|StubApp|jiagu|jgccxf|clggjv|xcjfmd|xinghmob|sigmob|pangle|pangolin|kwad|gdt|beizi|baidu|"
            r"UnsatisfiedLinkError|ClassNotFoundException|FATAL EXCEPTION|AndroidRuntime|MethodChannel|ExoPlayer)",
            re.IGNORECASE,
        )
        filtered = [ln for ln in logcat_all.splitlines() if app_log_re.search(ln)]
        (REPORT_DIR / "logcat_app_filtered.txt").write_text("\n".join(filtered[:4000]))

        (REPORT_DIR / "ui_traversal_summary.json").write_text(json.dumps({
            "uid": uid,
            "actions": actions_log,
            "crash_bytes": len(crash_log.strip()),
            "filtered_log_lines": len(filtered),
            "loaded_modules_count": len(forensics.get("loaded_non_system_modules", [])),
        }, indent=2, ensure_ascii=False))

    finally:
        log("Shutting down emulator...")
        adb("emu", "kill", timeout=10)
        try:
            emu_proc.wait(timeout=10)
        except Exception:
            emu_proc.kill()
        emu_log.close()

    # Remove temporary nav check files
    for tmp in REPORT_DIR.glob("tmp_nav_check*"):
        tmp.unlink()

    tar_path = pathlib.Path("work/deep_dynamic_report.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(REPORT_DIR, arcname="deep_dynamic")

    log(f"Uploading {tar_path} ({tar_path.stat().st_size} bytes)...")
    upload_report_tarball(tar_path)
    log("Deep dynamic observation completed and uploaded!")


if __name__ == "__main__":
    main()
