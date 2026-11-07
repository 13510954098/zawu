#!/usr/bin/env python3
"""Black-box Android Emulator dynamic observation harness for CI."""
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import time
from collections import Counter

PKG = "com.clggjv.xcjfmd.ffo"
MAIN_ACTIVITY = "com.clggjv.xcjfmd.ffo/com.clggjv.xcjfmd.ffo.MainActivity"
APK_PATH = pathlib.Path("work/sample.apk")
REPORT_DIR = pathlib.Path("work/report")


def run_cmd(cmd, timeout=120, check=False, text=True):
    try:
        p = subprocess.run(
            cmd,
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


def parse_dns_qname(buf, offset):
    labels = []
    jumped = False
    max_jumps = 10
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
            if jumps > max_jumps:
                break
            continue
        offset += 1
        if offset + length > len(buf):
            break
        labels.append(buf[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), orig_next


def extract_tls_sni(payload):
    # TLS record: ContentType=22 (Handshake), Version(2), Length(2), HandshakeType=1 (ClientHello)
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    try:
        pos = 5 + 4 + 2 + 32  # Handshake header(4) + client_version(2) + random(32)
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
    result = {
        "dns_queries": Counter(),
        "tls_sni": Counter(),
        "http_requests": [],
        "tcp_endpoints": Counter(),
    }
    if not pcap_path.exists():
        return {k: (dict(v) if isinstance(v, Counter) else v) for k, v in result.items()}

    data = pcap_path.read_bytes()
    if len(data) < 24:
        return {k: (dict(v) if isinstance(v, Counter) else v) for k, v in result.items()}

    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    _, _, _, _, _, _, linktype = struct.unpack(endian + "IHHiIII", data[:24])
    hdr_sizes = {1: 14, 113: 16, 276: 20, 101: 0}
    lhdr = hdr_sizes.get(linktype)
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
        l4 = ip[ihl:]

        if proto == 17 and len(l4) >= 8:  # UDP
            sport, dport = struct.unpack("!HH", l4[:4])
            dns = l4[8:]
            if dport == 53 and len(dns) >= 12:
                qdcount = struct.unpack("!H", dns[4:6])[0]
                off = 12
                for _ in range(min(qdcount, 4)):
                    qname, off = parse_dns_qname(dns, off)
                    if qname:
                        result["dns_queries"][qname.lower()] += 1
                    off += 4
        elif proto == 6 and len(l4) >= 20:  # TCP
            sport, dport = struct.unpack("!HH", l4[:4])
            flags = l4[13]
            if (flags & 0x02) and not (flags & 0x10):  # SYN
                if not dst_ip.startswith(("127.", "10.0.2.")):
                    result["tcp_endpoints"][f"{dst_ip}:{dport}"] += 1
            doff = ((l4[12] >> 4) & 0x0F) * 4
            payload = l4[doff:]
            if not payload:
                continue
            sni = extract_tls_sni(payload)
            if sni:
                result["tls_sni"][sni.lower()] += 1
            elif payload[:5] in (b"GET /", b"POST ", b"HEAD ", b"PUT /"):
                head_txt = payload[:1024].decode("latin1", "replace")
                lines = head_txt.split("\r\n")
                req_line = lines[0][:160]
                host_hdr = ""
                for ln in lines[1:15]:
                    if ln.lower().startswith("host:"):
                        host_hdr = ln.split(":", 1)[1].strip()
                        break
                key = (host_hdr, req_line)
                if key not in seen_http and len(result["http_requests"]) < 50:
                    seen_http.add(key)
                    result["http_requests"].append({"host": host_hdr, "request": req_line, "dst": f"{dst_ip}:{dport}"})

    return {
        "dns_queries": dict(result["dns_queries"].most_common(100)),
        "tls_sni": dict(result["tls_sni"].most_common(100)),
        "http_requests": result["http_requests"],
        "tcp_endpoints": dict(result["tcp_endpoints"].most_common(80)),
    }


def capture_screenshot(out_file: pathlib.Path):
    rc, png_bytes = adb("exec-out", "screencap", "-p", timeout=20, text=False)
    if rc == 0 and png_bytes and png_bytes.startswith(b"\x89PNG"):
        out_file.write_bytes(png_bytes)
        return len(png_bytes)
    return 0


def capture_ui_xml(out_file: pathlib.Path):
    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml", timeout=15)
    rc, xml_txt = adb("shell", "cat", "/sdcard/ui.xml", timeout=10)
    if rc == 0 and "<?xml" in xml_txt:
        out_file.write_text(xml_txt)
        return len(xml_txt)
    return 0


def dismiss_system_dialogs():
    # Dismiss Android "System UI isn't responding" if present on slow CI boot
    adb("shell", "am", "broadcast", "-a", "android.intent.action.CLOSE_SYSTEM_DIALOGS")


def run_test_pass(label: str, install_args: list[str]):
    pass_dir = REPORT_DIR / label
    pass_dir.mkdir(parents=True, exist_ok=True)
    info = {"label": label, "install_args": install_args, "timeline": []}

    adb("uninstall", PKG, timeout=30)
    rc, out = adb("install", *install_args, str(APK_PATH), timeout=120)
    info["install_rc"] = rc
    info["install_output"] = out.strip()
    if rc != 0:
        return info

    _, pkg_dump = adb("shell", "dumpsys", "package", PKG, timeout=30)
    (pass_dir / "dumpsys_package.txt").write_text(pkg_dump)
    m_abi = re.search(r"primaryCpuAbi=(\S+)", pkg_dump)
    info["primaryCpuAbi"] = m_abi.group(1) if m_abi else "unknown"

    adb("logcat", "-c")
    pcap_file = pass_dir / "net.pcap"
    tcpdump_proc = subprocess.Popen(
        ["sudo", "tcpdump", "-i", "any", "-U", "-s", "1024", "-w", str(pcap_file), "udp port 53 or tcp"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    t0 = time.time()
    rc_start, start_out = adb("shell", "am", "start", "-W", "-n", MAIN_ACTIVITY, timeout=30)
    info["am_start"] = start_out.strip()

    for checkpoint in (5, 15, 25):
        wait_rem = checkpoint - (time.time() - t0)
        if wait_rem > 0:
            time.sleep(wait_rem)
        elapsed = round(time.time() - t0, 1)
        _, pid_out = adb("shell", "pidof", PKG)
        _, ps_out = adb("shell", "ps -A | grep -E 'clggjv|ffo|kwad|bytedance' || true")
        _, resumed_out = adb("shell", "dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity|mFocusedWindow' || true")
        png_sz = capture_screenshot(pass_dir / f"screen_{checkpoint:02d}s.png")
        xml_sz = 0
        if checkpoint in (15, 25):
            xml_sz = capture_ui_xml(pass_dir / f"ui_{checkpoint:02d}s.xml")
        info["timeline"].append({
            "t": elapsed,
            "pid": pid_out.strip(),
            "processes": [ln.strip() for ln in ps_out.splitlines() if ln.strip()],
            "resumed": [ln.strip() for ln in resumed_out.splitlines() if ln.strip()][:6],
            "screenshot_bytes": png_sz,
            "ui_xml_bytes": xml_sz,
        })

        # At 15s, if a native consent/dialog button ("同意" / "我知道了" / "允许") is visible in uiautomator XML, click it to see main screen at 25s
        if checkpoint == 15 and (pass_dir / "ui_15s.xml").exists():
            xml_content = (pass_dir / "ui_15s.xml").read_text(errors="replace")
            for kw in ("同意并继续", "同意", "我知道了", "进入", "允许", "始终允许"):
                m_btn = re.search(rf'text="[^"]*{kw}[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml_content)
                if m_btn:
                    x1, y1, x2, y2 = map(int, m_btn.groups())
                    cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
                    adb("shell", "input", "tap", str(cx), str(cy))
                    info["auto_tapped_dialog"] = {"keyword": kw, "x": cx, "y": cy}
                    break

    # Stop tcpdump cleanly
    subprocess.run(["sudo", "kill", "-INT", str(tcpdump_proc.pid)], check=False)
    try:
        tcpdump_proc.wait(timeout=5)
    except Exception:
        tcpdump_proc.kill()

    # Collect logcat & meminfo & loaded non-system mapped basenames
    _, logcat_all = adb("logcat", "-d", "-v", "time", timeout=30)
    (pass_dir / "logcat_full.txt").write_text(logcat_all[-400_000:])  # cap at 400KB per pass

    key_patterns = re.compile(
        r"(FATAL EXCEPTION|AndroidRuntime|UnsatisfiedLinkError|SIGSEGV|SIGABRT|backtrace:|"
        r"flutter\s*:|StubApp|jgccxf|clggjv|xcjfmd|mpv|isar|ksad|pangolin|pangle|gdt|sigmob| linker\s*:)",
        re.IGNORECASE,
    )
    filtered_lines = [ln for ln in logcat_all.splitlines() if key_patterns.search(ln)]
    (pass_dir / "logcat_key.txt").write_text("\n".join(filtered_lines[:1500]))
    info["key_log_line_count"] = len(filtered_lines)

    # Check crash buffer specifically
    _, crash_log = adb("logcat", "-d", "-b", "crash", "-v", "time", timeout=15)
    (pass_dir / "logcat_crash.txt").write_text(crash_log)
    info["crash_log_preview"] = crash_log.strip()[:2000]

    # Parse network capture & delete raw pcap before archiving
    net_summary = parse_pcap(pcap_file)
    (pass_dir / "network.json").write_text(json.dumps(net_summary, indent=2, ensure_ascii=False))
    info["network_summary_counts"] = {
        "dns_domains": len(net_summary.get("dns_queries", {})),
        "tls_sni_hosts": len(net_summary.get("tls_sni", {})),
        "http_cleartext_requests": len(net_summary.get("http_requests", [])),
        "tcp_endpoints": len(net_summary.get("tcp_endpoints", {})),
    }
    if pcap_file.exists():
        pcap_file.unlink()

    return info


def upload_report_tarball(tar_path: pathlib.Path):
    repo = os.environ["REPO"]
    commit_sha = os.environ["COMMIT_SHA"]
    data = tar_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    chunk_size = 18 * 1024 * 1024
    blobs = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        payload = pathlib.Path("work/blob_payload.json")
        payload.write_text(json.dumps({
            "encoding": "base64",
            "content": base64.b64encode(chunk).decode("ascii"),
        }))
        res = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/git/blobs", "--method", "POST", "--input", str(payload)],
            text=True,
        )
        blob_sha = json.loads(res)["sha"]
        blobs.append({"sha": blob_sha, "size": len(chunk)})

    manifest = {
        "type": "dynamic_report",
        "sha256": sha256,
        "size": len(data),
        "blobs": blobs,
    }
    comment_payload = pathlib.Path("work/comment_payload.json")
    comment_payload.write_text(json.dumps({"body": json.dumps(manifest)}))
    subprocess.check_call(
        ["gh", "api", f"repos/{repo}/commits/{commit_sha}/comments", "--method", "POST", "--input", str(comment_payload)]
    )


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _, abilist = adb("shell", "getprop", "ro.product.cpu.abilist")
    _, sdk_ver = adb("shell", "getprop", "ro.build.version.sdk")
    _, rel_ver = adb("shell", "getprop", "ro.build.version.release")
    _, gl_ver = adb("shell", "dumpsys SurfaceFlinger | grep -iE 'GLES|OpenGL' | head -n 5 || true")

    abilist_str = abilist.strip()
    abis = [x.strip() for x in abilist_str.split(",") if x.strip()]

    # Unlock & disable animations
    adb("shell", "input", "keyevent", "82")
    adb("shell", "wm", "dismiss-keyguard")
    for setting in ("window_animation_scale", "transition_animation_scale", "animator_duration_scale"):
        adb("shell", "settings", "put", "global", setting, "0")
    dismiss_system_dialogs()

    summary = {
        "emulator": {
            "android_release": rel_ver.strip(),
            "sdk": sdk_ver.strip(),
            "abilist": abis,
            "gles": gl_ver.strip(),
        },
        "passes": [],
    }

    # Pass 1: Default installation (selects x86_64 on x86_64 image)
    print(">>> Running Pass 1: default install", flush=True)
    p1 = run_test_pass("pass1_default", ["-r"])
    summary["passes"].append(p1)

    # Pass 2: Explicit ARM ABI installation (full 20 native libraries) if supported by emulator translation
    arm_abi = None
    for cand in ("arm64-v8a", "armeabi-v7a"):
        if cand in abis:
            arm_abi = cand
            break
    if arm_abi:
        print(f">>> Running Pass 2: explicit --abi {arm_abi} install", flush=True)
        p2 = run_test_pass(f"pass2_{arm_abi}", ["-r", "--abi", arm_abi])
        summary["passes"].append(p2)

    (REPORT_DIR / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    tar_path = pathlib.Path("work/dynamic_report.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(REPORT_DIR, arcname="report")

    print(f"Created {tar_path} ({tar_path.stat().st_size} bytes)", flush=True)
    upload_report_tarball(tar_path)
    print("Uploaded dynamic report successfully!", flush=True)


if __name__ == "__main__":
    main()
