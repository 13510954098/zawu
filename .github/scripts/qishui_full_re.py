#!/usr/bin/env python3
"""
Phase 2 Pure-Static Deep-Dive Triage (~60s, no emulator needed):
  1. Full `is.snssdk.com/service/settings/v3/` download matrix (Win, Mac, Android, Car/Auto, iOS) + H5 Share route inspection
  2. Android APK (`com.luna.music` v21.5.0) X.509 certificate DN/SHA-256, apktool.yml SDK metadata, App ID (`aid=8478`), all custom schemes/AppLinks
  3. Multi-DEX Deep String & Class Extraction:
     - REST / Protobuf API endpoint paths (`/luna/...`, `/music/...`, etc.)
     - Room `*_Impl` `CREATE TABLE ...` schemas across all databases
     - Core subsystem classes (`com.luna.biz.playing`, `com.luna.common.player`, `com.luna.biz.aicreate`, `com.luna.biz.ai_v2`, `com.luna.kmp`, `com.luna.biz.listentogether`, `com.luna.biz.entitlement`)
     - Native `.so` complete 155-library categorized inventory
  4. Windows Desktop (`SodaMusic v3.7.0`) Deep Inspection:
     - Authenticode certificate of `SodaMusic_win64.exe` & `SodaMusic.exe`
     - `shell_config.json`, `entry.js` (99B), `main.js` (98B), `SodaMusic-v3.7.0-darwin_arm64-feed.json`
     - Chromium / Electron / Node / Lynx version strings in `main.dll` & `lynx_shared.dll`
     - N-API exports of `entry.node`, `main.node`, `ttnet.node`, `lmdb.node`, `bdticket.node`, `device.node`, `bdms.node`, `taskbar_widget_helper.node`
     - Source-map (`main.js.map` / `entry.js.map`) `sources` file tree list ONLY (module filenames for architecture audit; zero proprietary source code!)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path

WORK = Path("/tmp/qishui_phase2")
WORK.mkdir(parents=True, exist_ok=True)

APK_URL = "https://lf9-apk.ugapk.cn/package/apk/luna/8986_100215040/luna_43074760a_v8986_100215040_2641_1793726798.apk?v=1793726798"
EXE_URL = "https://lf-luna-release.qishui.com/obj/luna-release/3.7.0/452316191/SodaMusic-v3.7.0-official-win32_x64.exe"
MAC_FEED_URL = "https://lf-luna-release.qishui.com/obj/luna-release/3.7.0/452316191/SodaMusic-v3.7.0-darwin_arm64-feed.json"


def run_cmd(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def parse_dex_strings_and_classes(dex_bytes: bytes) -> tuple[list[str], list[str]]:
    if len(dex_bytes) < 112 or not dex_bytes.startswith(b"dex\n"):
        return [], []
    string_ids_size, string_ids_off = struct.unpack_from("<II", dex_bytes, 56)
    type_ids_size, type_ids_off = struct.unpack_from("<II", dex_bytes, 64)
    class_defs_size, class_defs_off = struct.unpack_from("<II", dex_bytes, 96)

    strings_all: list[str] = []
    for i in range(string_ids_size):
        data_off = struct.unpack_from("<I", dex_bytes, string_ids_off + i * 4)[0]
        # skip uleb128
        pos = data_off
        while dex_bytes[pos] & 0x80:
            pos += 1
        pos += 1
        end = dex_bytes.find(b"\x00", pos)
        if end >= pos:
            strings_all.append(dex_bytes[pos:end].decode("utf-8", errors="replace"))
        else:
            strings_all.append("")

    classes: list[str] = []
    for i in range(class_defs_size):
        t_idx = struct.unpack_from("<I", dex_bytes, class_defs_off + i * 32)[0]
        if 0 <= t_idx < type_ids_size:
            s_idx = struct.unpack_from("<I", dex_bytes, type_ids_off + t_idx * 4)[0]
            if 0 <= s_idx < len(strings_all):
                desc = strings_all[s_idx]
                if desc.startswith("L") and desc.endswith(";"):
                    classes.append(desc[1:-1].replace("/", "."))
    return strings_all, classes


def main() -> None:
    out: dict = {}

    # 1. Fetch full settings/v3 from www.qishui.com/download via Playwright + macOS feed JSON
    from playwright.sync_api import sync_playwright

    settings_data = {}
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        page = b.new_page()

        def on_resp(resp):
            if "service/settings/v3" in resp.url:
                try:
                    settings_data["settings_v3"] = resp.json()
                except Exception:
                    pass

        page.on("response", on_resp)
        try:
            page.goto("https://www.qishui.com/download", wait_until="networkidle", timeout=25000)
        except Exception:
            pass
        # Also click "车载版" to see how Car APK URL is resolved
        try:
            loc = page.get_by_text("车载版", exact=False).first
            if loc.count() > 0:
                loc.click(timeout=3000)
                page.wait_for_timeout(1500)
                car_links = page.eval_on_selector_all("a[href]", "els => els.map(e => ({t: e.innerText, h: e.href}))")
                settings_data["after_car_click_links"] = [x for x in car_links if "apk" in x["h"].lower() or "car" in x["h"].lower() or "auto" in x["h"].lower()]
                settings_data["car_modal_text"] = page.locator("body").inner_text()[:1500]
        except Exception:
            pass
        b.close()

    try:
        with urllib.request.urlopen(MAC_FEED_URL, timeout=15) as r:
            settings_data["mac_arm64_feed_json"] = json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception as e:
        settings_data["mac_feed_err"] = str(e)

    # Inspect JS bundle `index-d6b15e58.js` for Car APK / iOS App Store / Android download logic
    try:
        js_url = "https://lf-luna.qishui.com/obj/music-luna-fe/luna/home/1.0.0.287/assets/index-d6b15e58.js"
        with urllib.request.urlopen(js_url, timeout=15) as r:
            js_txt = r.read().decode("utf-8", errors="replace")
        out["fe_index_urls_and_constants"] = {
            "all_urls": sorted(set(re.findall(r'https?://[^\s"\'`<>\\)]+', js_txt))),
            "itunes_or_appstore": re.findall(r'(?:apps\.apple\.com|itunes\.apple\.com)[^\s"\'`<>\\)]*', js_txt),
            "ugapk_or_car": re.findall(r'[a-zA-Z0-9_./:-]*(?:ugapk|car|auto|luna-release|app_id|aid)[a-zA-Z0-9_./:?=&-]*', js_txt)[:80],
        }
    except Exception as e:
        out["fe_js_err"] = str(e)

    out["distribution_settings"] = settings_data

    # 2. Download APK & EXE in parallel
    apk_path = WORK / "luna.apk"
    exe_path = WORK / "soda.exe"
    p1 = subprocess.Popen(["curl", "-sL", "-o", str(apk_path), APK_URL])
    p2 = subprocess.Popen(["curl", "-sL", "-o", str(exe_path), EXE_URL])
    p1.wait(timeout=240)
    p2.wait(timeout=240)

    # 3. Android Deep Static
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "/usr/local/lib/android/sdk"
    bt_dirs = sorted(Path(sdk_root, "build-tools").glob("*"), reverse=True)
    aapt2 = str(bt_dirs[0] / "aapt2")
    apksigner = str(bt_dirs[0] / "apksigner")

    _, cert_out, _ = run_cmd([apksigner, "verify", "--verbose", "--print-certs", str(apk_path)])
    _, badging_out, _ = run_cmd([aapt2, "dump", "badging", str(apk_path)])
    out["android_cert_and_badging"] = {
        "apksigner_full": cert_out.splitlines()[:30],
        "badging_header": badging_out.splitlines()[:25],
    }

    api_routes: set[str] = set()
    room_creates: list[str] = []
    room_db_classes: list[str] = []
    subsystems: dict[str, list[str]] = defaultdict(list)
    proto_messages: list[str] = []
    so_all_names: list[dict] = []

    with zipfile.ZipFile(apk_path, "r") as zf:
        for zi in sorted(zf.infolist(), key=lambda x: x.file_size, reverse=True):
            if zi.filename.startswith("lib/arm64-v8a/") and zi.filename.endswith(".so"):
                so_all_names.append({"name": Path(zi.filename).name, "size": zi.file_size})

        dex_files = sorted([n for n in zf.namelist() if re.match(r"^classes\d*\.dex$", n)])
        for dn in dex_files:
            strs, clss = parse_dex_strings_and_classes(zf.read(dn))
            for s in strs:
                if s.startswith("/") and 6 <= len(s) <= 100 and " " not in s and "//" not in s:
                    if re.match(r"^/(?:luna|music|track|playlist|feed|search|artist|album|user|vip|commerce|ai|lyric|comment|passport|aweme|bytecast|openapi)/[a-zA-Z0-9_/{}-]+$", s):
                        api_routes.add(s)
                elif s.startswith("CREATE TABLE IF NOT EXISTS `") and len(room_creates) < 90:
                    room_creates.append(s[:320])

            for c in clss:
                if "$" in c:
                    continue
                if c.endswith("_Impl") and ("Database" in c or "Db" in c):
                    room_db_classes.append(c)
                for key, prefix in [
                    ("playing_core", "com.luna.biz.playing."),
                    ("common_player", "com.luna.common.player."),
                    ("audio_effect", "com.luna.audio."),
                    ("ai_create", "com.luna.biz.aicreate."),
                    ("ai_agent_v2", "com.luna.biz.ai_v2."),
                    ("kmp_multiplatform", "com.luna.kmp."),
                    ("douyin_kmp", "douyinkmp."),
                    ("listen_together", "com.luna.biz.listentogether."),
                    ("entitlement_vip", "com.luna.biz.entitlement."),
                    ("download_offline", "com.luna.biz.download."),
                    ("hybrid_container", "com.luna.biz.hybrid."),
                ]:
                    if c.startswith(prefix) and len(subsystems[key]) < 25:
                        subsystems[key].append(c)

    out["android_deep_dex"] = {
        "api_route_count": len(api_routes),
        "api_routes_sample": sorted(api_routes)[:140],
        "room_database_impl_classes": sorted(room_db_classes),
        "room_create_table_sql": room_creates[:60],
        "subsystem_classes": dict(subsystems),
        "all_155_arm64_so": so_all_names,
    }

    # 4. Windows Desktop Deep Static
    _, sig_installer, err_sig1 = run_cmd(["osslsigncode", "verify", "-in", str(exe_path)])
    win_u1 = WORK / "win1"
    win_u2 = WORK / "win2"
    run_cmd(["7z", "x", "-y", f"-o{win_u1}", str(exe_path)])
    app_7z = list(win_u1.rglob("app.7z"))
    if app_7z:
        run_cmd(["7z", "x", "-y", f"-o{win_u2}", str(app_7z[0])])

    soda_exe = win_u2 / "SodaMusic.exe"
    _, sig_app, _ = run_cmd(["osslsigncode", "verify", "-in", str(soda_exe)]) if soda_exe.exists() else (0, "", "")

    shell_cfg = (win_u2 / "shell_config.json").read_text(encoding="utf-8", errors="replace") if (win_u2 / "shell_config.json").exists() else ""

    # Read Chromium/Electron version strings from main.dll
    main_dll = win_u2 / "main.dll"
    ver_fingerprints: list[str] = []
    if main_dll.exists():
        _, s_out, _ = run_cmd(["strings", "-n", "8", str(main_dll)], timeout=60)
        for pat in [r"Chrome/\d+\.\d+\.\d+\.\d+", r"Electron/\d+\.\d+\.\d+", r"Node/\d+\.\d+\.\d+", r"SodaMusic[^\s]{0,40}", r"app_shell[^\s]{0,40}"]:
            for m in re.findall(pat, s_out):
                if m not in ver_fingerprints:
                    ver_fingerprints.append(m)
                if len(ver_fingerprints) >= 30:
                    break

    # Inspect app.asar small bootstrap files & source-map file path list (paths ONLY, zero sourceContent!)
    app_asar = win_u2 / "resources" / "app.asar"
    asar_deep: dict = {}
    if app_asar.exists():
        with open(app_asar, "rb") as f:
            raw_hdr = f.read(16)
            hdr_sz = struct.unpack("<I", raw_hdr[4:8])[0]
            json_len = struct.unpack("<I", raw_hdr[12:16])[0]
            hdr = json.loads(f.read(json_len).decode("utf-8", errors="replace"))
            base = 8 + hdr_sz
            files_d = hdr.get("files", {})
            for small_f in ["package.json", "entry.js", "main.js"]:
                meta = files_d.get(small_f)
                if meta and int(meta.get("size", 9999)) < 2000:
                    f.seek(base + int(meta["offset"]))
                    asar_deep[small_f] = f.read(int(meta["size"])).decode("utf-8", errors="replace")
            for sm_f in ["entry.js.map", "main.js.map"]:
                meta = files_d.get(sm_f)
                if meta:
                    f.seek(base + int(meta["offset"]))
                    sm_json = json.loads(f.read(int(meta["size"])).decode("utf-8", errors="replace"))
                    srcs = sm_json.get("sources", [])
                    has_sources_content = bool(sm_json.get("sourcesContent"))
                    asar_deep[sm_f] = {
                        "version": sm_json.get("version"),
                        "sources_count": len(srcs),
                        "has_embedded_sourcesContent": has_sources_content,
                        "sources_sample": srcs[:80],
                    }

    # Inspect main.asar HTML & asset manifest (filenames only)
    main_asar = win_u2 / "resources" / "main.asar"
    main_asar_files: list[str] = []
    if main_asar.exists():
        with open(main_asar, "rb") as f:
            raw_hdr = f.read(16)
            hdr_sz = struct.unpack("<I", raw_hdr[4:8])[0]
            json_len = struct.unpack("<I", raw_hdr[12:16])[0]
            hdr = json.loads(f.read(json_len).decode("utf-8", errors="replace"))
            base = 8 + hdr_sz

            def walk(n: dict, pfx: str = "") -> None:
                for k, v in (n.get("files") or {}).items():
                    c = f"{pfx}/{k}" if pfx else k
                    if "files" in v:
                        walk(v, c)
                    else:
                        main_asar_files.append(f"{c} ({v.get('size', 0)} B)")

            walk(hdr)
            mh = hdr.get("files", {}).get("main.html")
            if mh:
                f.seek(base + int(mh["offset"]))
                asar_deep["main_html"] = f.read(int(mh["size"])).decode("utf-8", errors="replace")[:2500]

    # Inspect exported symbols / N-API module names of .node addons in app.asar.unpacked
    node_addons_info: list[dict] = []
    unpacked_dir = win_u2 / "resources" / "app.asar.unpacked"
    if unpacked_dir.exists():
        for nf in sorted(unpacked_dir.glob("*.node")):
            _, s_nf, _ = run_cmd(["strings", "-n", "6", str(nf)], timeout=15)
            napi_syms = sorted(set(re.findall(r"(?:napi_register_module_v1|node_register_module_[a-zA-Z0-9_]+|[a-zA-Z0-9_]+::Init|[A-Za-z0-9_]{4,40}IPC[A-Za-z0-9_]*)", s_nf)))[:20]
            v8_bytecode_hint = "v8::ScriptCompiler::ConsumeCodeCache" in s_nf or "bytenode" in s_nf.lower() or "CodeCache" in s_nf
            node_addons_info.append({
                "name": nf.name,
                "size": nf.stat().st_size,
                "v8_code_cache_or_bytenode_hint": v8_bytecode_hint,
                "symbols_sample": napi_syms,
            })

    out["windows_deep"] = {
        "installer_authenticode": (sig_installer + "\n" + err_sig1).splitlines()[:30],
        "sodamusic_exe_authenticode": sig_app.splitlines()[:30],
        "shell_config_json": shell_cfg,
        "main_dll_version_fingerprints": ver_fingerprints,
        "asar_deep": asar_deep,
        "main_asar_virtual_files": main_asar_files[:70],
        "node_addons_analysis": node_addons_info,
    }

    Path("/tmp/qishui_full_re_report.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Phase 2 complete!", flush=True)


if __name__ == "__main__":
    main()
