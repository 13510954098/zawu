#!/usr/bin/env python3
"""Targeted precision dynamic run: Weekly Schedule, Search, Anime Detail, Live MPV Video Playback, CDN PCAP, Watch History (Isar), Cache, Entry Quiz, Theme & Disclaimer."""
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
REPORT_DIR = pathlib.Path("work/precision_dynamic")
STEP_LOG = pathlib.Path("work/step_precision.log")

NOISE_IPS = {"168.63.129.16", "169.254.169.254", "127.0.0.1", "10.0.2.2", "10.0.2.3", "10.0.2.15"}
GMS_NOISE_SUFFIXES = (
    "googleapis.com", "gstatic.com", "google.com", "googleadservices.com",
    "doubleclick.net", "gvt1.com", "gvt2.com", "android.com",
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
    app_sni = Counter()
    http_requests = []
    tcp_endpoints = Counter()
    bytes_by_endpoint = Counter()

    if not pcap_path.exists() or pcap_path.stat().st_size < 24:
        return {"app_dns": {}, "app_tls_sni": {}, "http_cleartext": [], "tcp_endpoints": {}, "bytes_by_endpoint": {}}

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
        _, _, incl_len, orig_len = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        pkt = data[pos:pos + incl_len]
        pos += incl_len
        if len(pkt) < lhdr + 20:
            continue
        ethertype = (
            struct.unpack("!H", pkt[12:14])[0] if linktype == 1 else
            struct.unpack("!H", pkt[14:16])[0] if linktype == 113 else
            struct.unpack("!H", pkt[0:2])[0] if linktype == 276 else 0x0800
        )
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
                    if qname and not is_gms_noise(qname):
                        app_dns[qname.lower()] += 1
                    off += 4
        elif proto == 6 and len(l4) >= 20:
            sport, dport = struct.unpack("!HH", l4[:4])
            flags = l4[13]
            if not dst_ip.startswith(("127.", "10.0.2.")):
                if (flags & 0x02) and not (flags & 0x10):
                    tcp_endpoints[f"{dst_ip}:{dport}"] += 1
                bytes_by_endpoint[f"{dst_ip}:{dport}"] += orig_len
            elif not src_ip.startswith(("127.", "10.0.2.")):
                bytes_by_endpoint[f"{src_ip}:{sport}"] += orig_len
            doff = ((l4[12] >> 4) & 0x0F) * 4
            payload = l4[doff:]
            if not payload:
                continue
            sni = extract_tls_sni(payload)
            if sni and not is_gms_noise(sni):
                app_sni[sni.lower()] += 1
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
        "bytes_by_endpoint": dict(bytes_by_endpoint.most_common(40)),
    }


class StagePcap:
    def __init__(self, out_dir: pathlib.Path, stage_name: str):
        self.pcap_path = out_dir / f"{stage_name}.pcap"
        self.out_json = out_dir / f"{stage_name}_net.json"
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            [
                "sudo", "tcpdump", "-i", "any", "-U", "-s", "1024", "-w", str(self.pcap_path),
                "not host 168.63.129.16 and not host 169.254.169.254 and (udp port 53 or tcp)",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)
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
        clean_xml = xml_txt[xml_txt.find("<?xml"):]
        xml_path.write_text(clean_xml)
        try:
            root = ET.fromstring(clean_xml)
            for el in root.iter("node"):
                txt = (el.attrib.get("text") or "").strip()
                desc = (el.attrib.get("content-desc") or "").strip()
                b = parse_bounds(el.attrib.get("bounds", ""))
                clickable = el.attrib.get("clickable") == "true"
                cls = el.attrib.get("class", "")
                if txt or desc or "EditText" in cls:
                    nodes.append({
                        "text": txt,
                        "desc": desc,
                        "label": (txt or desc).replace("\n", " | "),
                        "clickable": clickable,
                        "class": cls,
                        "bounds": b,
                    })
        except Exception as e:
            log(f"XML parse error on {prefix}: {e}")
    log(f"Snapshot {prefix}: {len(nodes)} labeled/input nodes")
    return nodes


def tap(x: int, y: int, desc: str = ""):
    log(f"TAP ({x}, {y}) {desc}")
    adb("shell", "input", "tap", str(x), str(y), timeout=10)


def back(desc: str = ""):
    log(f"KEYCODE_BACK {desc}")
    adb("shell", "input", "keyevent", "4", timeout=10)


def return_to_home_root(max_backs=5):
    for i in range(max_backs):
        adb("shell", "uiautomator", "dump", "/sdcard/ui_chk.xml", timeout=10)
        _, xml_txt = adb("shell", "cat", "/sdcard/ui_chk.xml", timeout=10)
        if "我的" in xml_txt and "福利" in xml_txt and "首页" in xml_txt:
            return True
        back(f"unwind_{i}")
        time.sleep(1.8)
    adb("shell", "am", "start", "-n", MAIN_ACTIVITY, timeout=15)
    time.sleep(2.5)
    return False


def boot_emulator(sdk_root: str):
    emu_bin = str(pathlib.Path(sdk_root) / "emulator" / "emulator")
    emu_log = open("work/emulator_precision.log", "w")
    log("Starting headless KVM emulator...")
    proc = subprocess.Popen(
        [
            emu_bin, "-avd", "test_avd", "-no-window", "-gpu", "swiftshader_indirect",
            "-no-audio", "-no-boot-anim", "-no-snapshot", "-partition-size", "6144", "-memory", "4096",
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


def upload_report(tar_path: pathlib.Path):
    repo = os.environ["REPO"]
    commit_sha = os.environ["COMMIT_SHA"]
    data = tar_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    chunk_size = 24 * 1024 * 1024
    blobs = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        payload = pathlib.Path("work/prec_blob.json")
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
        "type": "precision_dynamic_report",
        "sha256": sha256,
        "size": len(data),
        "blobs": blobs,
    }
    comment_payload = pathlib.Path("work/prec_comment.json")
    comment_payload.write_text(json.dumps({"body": json.dumps(manifest)}))
    subprocess.check_call(
        ["gh", "api", f"repos/{repo}/commits/{commit_sha}/comments", "--method", "POST", "--input", str(comment_payload)],
        stdin=subprocess.DEVNULL,
    )


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    emu_proc, emu_log = boot_emulator(sdk_root)
    summary = {"stages": []}

    try:
        adb("root", timeout=15)
        time.sleep(1.5)
        adb("logcat", "-G", "16M", timeout=10)
        adb("logcat", "-c", timeout=10)

        log("Installing sample.apk...")
        rc, out = adb("install", "-r", "-g", str(APK_PATH), timeout=90)
        if rc != 0:
            raise RuntimeError(f"adb install failed: {out}")

        log("Launching Lanerc and dismissing startup modal...")
        adb("shell", "am", "start", "-W", "-n", MAIN_ACTIVITY, timeout=30)
        time.sleep(10)
        tap(540, 1468, "dismiss_startup_modal_已知晓")
        time.sleep(4)
        home_nodes = snapshot_ui("00_home_ready")
        summary["stages"].append({"stage": "00_home_ready", "labels": [n["label"] for n in home_nodes[:30]]})

        # STAGE 1: Weekly Broadcast Schedule (番剧排期表) -> PATH: app/week
        with StagePcap(REPORT_DIR, "stageA_week_and_search"):
            tap(802, 928, "open_weekly_schedule_番剧排期表")
            time.sleep(5)
            week_nodes = snapshot_ui("01_weekly_schedule")
            summary["stages"].append({"stage": "01_weekly_schedule", "labels": [n["label"] for n in week_nodes[:40]]})
            # Tap another weekday tab (e.g. 周六 / 周日) if visible
            for n in week_nodes:
                if any(d in n["label"] for d in ("周六", "周日", "周四", "周五")) and n["bounds"]:
                    tap(n["bounds"][4], n["bounds"][5], f"weekday_{n['label']}")
                    time.sleep(2.5)
                    snapshot_ui("01b_weekly_schedule_other_day")
                    break

            back("leave_weekly_schedule")
            time.sleep(2.5)

            # STAGE 2: Search Execution -> PATH: app/vod/search
            tap(550, 160, "open_search_page")
            time.sleep(2.5)
            tap(553, 160, "focus_search_edittext")
            time.sleep(1.2)
            adb("shell", "input", "text", "JOJO", timeout=10)
            time.sleep(1.2)
            tap(1011, 160, "submit_search_搜索")
            time.sleep(6)
            search_nodes = snapshot_ui("02_search_results_jojo")
            summary["stages"].append({"stage": "02_search_results_jojo", "labels": [n["label"] for n in search_nodes[:40]]})

        # STAGE 3: Anime Detail & Live MPV Video Stream Playback -> PATH: app/v2/vod/..., app/v2/guest/play
        with StagePcap(REPORT_DIR, "stageB_video_detail_and_mpv_stream"):
            # Try tapping first search result card below y=220
            tapped_result = False
            for n in search_nodes:
                b = n["bounds"]
                if b and b[1] >= 210 and b[3] <= 1900 and len(n["label"]) >= 3 and n["label"] not in ("搜索",):
                    tap(b[4], b[5], f"tap_search_result_{n['label'][:25]}")
                    tapped_result = True
                    break

            if not tapped_result:
                return_to_home_root()
                tap(187, 1733, "fallback_tap_completed_anime_card")

            time.sleep(8)
            detail_nodes = snapshot_ui("03_video_detail_initial_8s")
            summary["stages"].append({"stage": "03_video_detail_initial_8s", "labels": [n["label"] for n in detail_nodes[:50]]})

            # Check if an episode chip (e.g. "01", "第01集", "第1集", "1", "PV") is visible & tap it to ensure playback starts
            for n in detail_nodes:
                b = n["bounds"]
                lbl = n["label"].strip()
                if b and b[1] >= 650 and (lbl in ("01", "1", "02", "2", "第01集", "第1集", "全集", "正片") or re.match(r"^0?[12]$", lbl)):
                    tap(b[4], b[5], f"select_episode_{lbl}")
                    time.sleep(2)
                    break

            log("Waiting 14s for live MPV video stream & buffering...")
            time.sleep(14)
            play_nodes = snapshot_ui("04_video_mpv_playing_22s")
            summary["stages"].append({"stage": "04_video_mpv_playing_22s", "labels": [n["label"] for n in play_nodes[:50]]})

            # Capture live media/audio/thread/fd forensics WHILE video player is active!
            _, pid_out = adb("shell", f"pidof {PKG} || true", timeout=10)
            pid = pid_out.strip().split()[0] if pid_out.strip() else ""
            live_player_forensics = {"pid": pid}
            if pid:
                _, threads = adb("shell", f"cat /proc/{pid}/task/*/comm 2>/dev/null | sort | uniq -c | sort -rn", timeout=10)
                live_player_forensics["threads_histogram"] = threads.strip()
                _, fds = adb("shell", f"ls -l /proc/{pid}/fd 2>/dev/null | grep -E 'socket|isar|mpv|video|cache|anon' | head -n 80 || true", timeout=10)
                live_player_forensics["interesting_fds"] = fds.strip()
            _, audio_dump = adb("shell", "dumpsys audio | grep -E -A 6 'AudioPlaybackConfiguration|player piid|u0a' || true", timeout=10)
            live_player_forensics["dumpsys_audio_excerpt"] = audio_dump.strip()[:4000]
            _, media_session = adb("shell", "dumpsys media_session || true", timeout=10)
            live_player_forensics["dumpsys_media_session"] = media_session.strip()[:4000]
            (REPORT_DIR / "live_player_forensics.json").write_text(json.dumps(live_player_forensics, indent=2, ensure_ascii=False))

            # Also tap the "评论" tab on the video detail page if present
            for n in play_nodes:
                b = n["bounds"]
                if b and "评论" in n["label"] and 500 <= b[1] <= 1200:
                    tap(b[4], b[5], f"tap_video_comments_tab_{n['label']}")
                    time.sleep(3.5)
                    comm_nodes = snapshot_ui("04b_video_comments_tab")
                    summary["stages"].append({"stage": "04b_video_comments_tab", "labels": [x["label"] for x in comm_nodes[:40]]})
                    break

            # Also test a second completed anime from Home (`魔术士奥芬的无赖之旅 圣域篇`) if first was from search
            return_to_home_root()
            tap(187, 1733, "tap_completed_anime_card_home")
            time.sleep(12)
            second_play_nodes = snapshot_ui("05_second_anime_playback_12s")
            summary["stages"].append({"stage": "05_second_anime_playback_12s", "labels": [n["label"] for n in second_play_nodes[:50]]})

        # STAGE 4: Post-Playback Watch History (Isar), Offline Cache, Entry Quiz, Theme, Disclaimer
        with StagePcap(REPORT_DIR, "stageC_profile_subpages"):
            return_to_home_root()
            tap(900, 2071, "open_profile_tab_我的")
            time.sleep(2.5)

            # 1) Watch History (/history -> IsarHistory)
            tap(416, 457, "open_watch_history_历史记录")
            time.sleep(3.5)
            hist_nodes = snapshot_ui("06_watch_history")
            summary["stages"].append({"stage": "06_watch_history", "labels": [n["label"] for n in hist_nodes[:40]]})
            back("back_from_history")
            time.sleep(2)

            # 2) Offline Cache (/cache -> IsarDownload)
            tap(664, 457, "open_offline_cache_离线缓存")
            time.sleep(3)
            cache_nodes = snapshot_ui("07_offline_cache")
            summary["stages"].append({"stage": "07_offline_cache", "labels": [n["label"] for n in cache_nodes[:40]]})
            back("back_from_cache")
            time.sleep(2)

            # 3) Entry Quiz (/question -> PATH: app/user/question)
            tap(285, 651, "open_entry_quiz_入站问答")
            time.sleep(4)
            quiz_nodes = snapshot_ui("08_entry_quiz")
            summary["stages"].append({"stage": "08_entry_quiz", "labels": [n["label"] for n in quiz_nodes[:40]]})
            back("back_from_quiz")
            time.sleep(2)

            # 4) Disclaimer (免责声明)
            tap(540, 1127, "open_disclaimer_免责声明")
            time.sleep(2.5)
            disc_nodes = snapshot_ui("09_disclaimer")
            summary["stages"].append({"stage": "09_disclaimer", "labels": [n["label"] for n in disc_nodes[:40]]})

        # Inspect Isar DB metadata & printable strings to verify IsarHistory persistence on disk
        _, isar_stat = adb("shell", f"ls -lh /data/data/{PKG}/app_flutter/default.isar* 2>/dev/null || true", timeout=10)
        _, isar_strings = adb("shell", f"strings -n 5 /data/data/{PKG}/app_flutter/default.isar 2>/dev/null | tail -n 120 || true", timeout=15)
        (REPORT_DIR / "isar_persistence_check.json").write_text(json.dumps({
            "stat": isar_stat.strip(),
            "strings_tail": isar_strings.splitlines()[-100:],
        }, indent=2, ensure_ascii=False))

        # Capture full 16MB logcat and extract ALL I/flutter + media_kit/mpv lines
        _, full_logcat = adb("logcat", "-d", "-v", "time", timeout=30)
        (REPORT_DIR / "logcat_precision_all.txt").write_text(full_logcat)
        flutter_and_mpv = [
            ln for ln in full_logcat.splitlines()
            if any(k in ln for k in ("I/flutter", "E/flutter", "mpv", "media_kit", "VideoOutput", "WindAd", "Sigmob", "ToBid", "TalkingData"))
        ]
        (REPORT_DIR / "logcat_flutter_and_mpv.txt").write_text("\n".join(flutter_and_mpv))

        _, crash_log = adb("logcat", "-d", "-b", "crash", timeout=15)
        (REPORT_DIR / "logcat_crash.txt").write_text(crash_log)

        (REPORT_DIR / "precision_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    finally:
        emu_proc.terminate()
        emu_log.close()

    tar_path = pathlib.Path("work/precision_dynamic_report.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(REPORT_DIR, arcname="precision_dynamic")
    log(f"Uploading {tar_path} ({tar_path.stat().st_size} bytes)...")
    upload_report(tar_path)
    log("Precision dynamic report uploaded successfully!")


if __name__ == "__main__":
    main()
