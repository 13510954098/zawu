#!/usr/bin/env python3
"""
Comprehensive Multi-Surface Reverse Engineering & Security/Architecture Triage
Target: https://music.douyin.com/qishui (ByteDance Qishui Music / SodaMusic)
Surfaces:
  1. Web Portal, JS Bundles, Release Distribution & H5 Share Player
  2. Official Android Client (com.luna.music) Static Analysis (APK, Cert, Manifest, Multi-DEX, Native ELF .so, Hybrid Assets/Gecko/Lynx)
  3. Official Android Client Dynamic Execution (Android 11 x86_64 + ARM64 ndk_translation + adb root + tcpdump SNI/DNS + SQLite/MMKV/SharedPrefs + UI tree)
  4. Official Windows Desktop Client (SodaMusic win32_x64.exe) PE, NSIS/7z Unpack, Electron app.asar Header/Package/Entrypoints & Native .node/.dll Inventory
Strict Guardrails:
  - Structural, architectural, protocol, and security/privacy audit metadata ONLY.
  - Zero secret/key extraction, zero DRM/VIP circumvention, zero token/cookie leakage.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

WORK = Path("/tmp/qishui_work")
WORK.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd: list[str] | str, timeout: int = 120, shell: bool = False, env: dict | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
             errors="replace",
            timeout=timeout,
            env=env,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") if isinstance(e.stdout, str) else "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", str(e)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ==============================================================================
# SURFACE 1: Web Portal, JS Bundle & Multi-Platform Official Download Discovery
# ==============================================================================
def analyze_web_and_discover_urls() -> dict:
    print("[1/4] Analyzing Web Portal & Discovering Multi-Platform Packages...", flush=True)
    result: dict = {
        "pages": {},
        "js_bundles": [],
        "discovered_urls": {},
        "api_endpoints_in_fe": [],
        "deeplink_schemes_in_fe": [],
        "tech_fingerprints": [],
    }

    from playwright.sync_api import sync_playwright

    captured_urls: set[str] = set()
    captured_json_apis: list[dict] = []

    def inspect_url_str(u: str) -> None:
        if any(ext in u.lower() for ext in [".apk", ".exe", ".dmg", ".pkg", "itunes.apple.com", "apps.apple.com", "luna-release"]):
            clean = u.split("?")[0] if "lf-luna-release" in u else u
            captured_urls.add(clean)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # Pass A: Desktop browser on music.douyin.com/qishui and www.qishui.com/download
        ctx_desk = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            accept_downloads=True,
        )
        page = ctx_desk.new_page()

        def on_resp(resp):
            u = resp.url
            inspect_url_str(u)
            ct = resp.headers.get("content-type", "")
            if "json" in ct and any(k in u for k in ["qishui", "douyin", "luna", "release", "download", "version"]):
                try:
                    body = resp.text()
                    captured_json_apis.append({"url": u.split("?")[0], "status": resp.status, "preview": body[:1200]})
                    for m in re.findall(r'https?://[^\s"\'<>\\]+', body):
                        inspect_url_str(m)
                except Exception:
                    pass

        page.on("response", on_resp)
        for target in ["https://music.douyin.com/qishui", "https://www.qishui.com/download"]:
            try:
                page.goto(target, wait_until="networkidle", timeout=30000)
                time.sleep(1.5)
                html = page.content()
                for m_html in re.findall(r'https?://[^\s"\'<>\\]+', html):
                    inspect_url_str(m_html)
                scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                links = page.eval_on_selector_all("a[href]", "els => els.map(e => ({text: e.innerText.trim(), href: e.href}))")
                for lk in links:
                    inspect_url_str(lk.get("href", ""))
                globals_found = page.evaluate(
                    """() => Object.keys(window).filter(k =>
                        k.includes('ROUTER') || k.includes('SSR') || k.includes('INITIAL') ||
                        k.includes('LUNA') || k.includes('Slardar') || k.includes('collect') || k.includes('Tea')
                    )"""
                )
                result["pages"][target] = {
                    "title": page.title(),
                    "html_bytes": len(html),
                    "scripts": scripts,
                    "links": links[:25],
                    "window_globals": globals_found[:40],
                }
                for sc in scripts:
                    if sc not in result["js_bundles"]:
                        result["js_bundles"].append(sc)

                # Try clicking download buttons on www.qishui.com/download to capture dynamic links
                if "download" in target:
                    for label in ["64 位", "32 位", "Intel 系列", "M 系列", "车载版", "Android"]:
                        try:
                            loc = page.get_by_text(label, exact=False).first
                            if loc.count() > 0:
                                with page.expect_download(timeout=3500) as dl_info:
                                    loc.click(timeout=2000)
                                dl = dl_info.value
                                inspect_url_str(dl.url)
                                result["discovered_urls"][f"button_{label}"] = dl.url
                                dl.cancel()
                        except Exception:
                            pass
            except Exception as e:
                result["pages"][target] = {"error": str(e)}

        ctx_desk.close()

        # Pass B: Android Mobile User-Agent on https://music.douyin.com/qishui to trigger Android APK download link
        ctx_mob = browser.new_context(
            user_agent="Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
            viewport={"width": 412, "height": 915},
            is_mobile=True,
            has_touch=True,
            accept_downloads=True,
        )
        mpage = ctx_mob.new_page()
        mpage.on("response", on_resp)
        mpage.on("request", lambda req: inspect_url_str(req.url))
        try:
            mpage.goto("https://music.douyin.com/qishui", wait_until="networkidle", timeout=30000)
            time.sleep(1.5)
            m_html = mpage.content()
            for m_u in re.findall(r'https?://[^\s"\'<>\\]+', m_html):
                inspect_url_str(m_u)
            m_links = mpage.eval_on_selector_all("a[href]", "els => els.map(e => ({text: e.innerText.trim(), href: e.href}))")
            result["pages"]["mobile_qishui"] = {
                "title": mpage.title(),
                "links": m_links[:20],
            }
            for lk in m_links:
                inspect_url_str(lk.get("href", ""))
            for btn_txt in ["点击下载", "立即下载", "下载", "Android"]:
                try:
                    loc = mpage.get_by_text(btn_txt, exact=False).first
                    if loc.count() > 0:
                        with mpage.expect_download(timeout=5000) as dl_info:
                            loc.click(timeout=2500)
                        dl = dl_info.value
                        inspect_url_str(dl.url)
                        result["discovered_urls"]["android_mobile_cta"] = dl.url
                        dl.cancel()
                        break
                except Exception:
                    pass
        except Exception as e:
            result["pages"]["mobile_qishui_err"] = str(e)
        ctx_mob.close()
        browser.close()

    # Inspect JS bundles directly for API endpoints, release URLs, URL schemes, hybrid SDKs
    fe_apis: set[str] = set()
    fe_schemes: set[str] = set()
    fe_tech: set[str] = set()
    js_details: list[dict] = []

    for js_url in result["js_bundles"][:12]:
        try:
            req = urllib.request.Request(js_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                js_code = r.read().decode("utf-8", errors="replace")
            js_details.append({"url": js_url, "size_bytes": len(js_code)})
            for m in re.findall(r'https?://[^\s"\'`<>\\)]+', js_code):
                inspect_url_str(m)
                if any(h in m for h in ["qishui.com", "douyin.com", "snssdk.com", "bytedance.com", "zijieapi.com"]):
                    fe_apis.add(m.split("?")[0][:140])
            for m in re.findall(r'[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"\'`<>\\)]{0,80}', js_code):
                scheme = m.split("://")[0].lower()
                if scheme not in ("http", "https", "file", "data", "blob", "ws", "wss", "javascript", "chrome"):
                    fe_schemes.add(m[:90])
            for kw, label in [
                ("react", "React"),
                ("semi-", "ByteDance Semi Design"),
                ("slardar", "ByteDance Slardar RUM/APM"),
                ("collect-rangers", "Volcengine DataRangers / Tea Analytics"),
                ("hybrid_sdk_version", "Bullet Hybrid Container"),
                ("lynx", "ByteDance Lynx"),
                ("applink", "AppLink / Universal Link Attribution"),
                ("clipboard", "Clipboard Deferred Deep-Linking"),
                ("SodaMusic", "SodaMusic Desktop Brand"),
                ("com.luna.music", "Android Package com.luna.music"),
            ]:
                if kw.lower() in js_code.lower():
                    fe_tech.add(label)
        except Exception:
            pass

    result["js_bundle_details"] = js_details
    result["all_captured_package_urls"] = sorted(captured_urls)
    result["captured_json_apis"] = captured_json_apis[:15]
    result["api_endpoints_in_fe"] = sorted(fe_apis)[:60]
    result["deeplink_schemes_in_fe"] = sorted(fe_schemes)[:40]
    result["tech_fingerprints"] = sorted(fe_tech)
    return result


# ==============================================================================
# HELPER: Download Official Android APK & Official Windows EXE
# ==============================================================================
def fetch_official_binaries(web_info: dict) -> tuple[Path | None, Path | None, dict]:
    dl_meta: dict = {}
    apk_urls = [u for u in web_info.get("all_captured_package_urls", []) if ".apk" in u.lower() and "car" not in u.lower() and "auto" not in u.lower()]
    car_apk_urls = [u for u in web_info.get("all_captured_package_urls", []) if ".apk" in u.lower() and ("car" in u.lower() or "auto" in u.lower())]
    exe_urls = [u for u in web_info.get("all_captured_package_urls", []) if "x64.exe" in u.lower() or u.lower().endswith(".exe")]

    # Fallback redirect probes if mobile click used JS location redirect
    if not apk_urls:
        for probe in [
            "https://d.qishui.com/iR11/",
            "https://music.douyin.com/qishui/download/android",
            "https://api.qishui.com/luna/pc/download?platform=android",
        ]:
            rc, out, _ = run_cmd(["curl", "-sIL", "-o", "/dev/null", "-w", "%{url_effective}", "-A", "Mozilla/5.0 (Linux; Android 14) Mobile", probe], timeout=20)
            if rc == 0 and ".apk" in out.lower():
                apk_urls.append(out.strip())

    # Check captured JSON APIs for direct download URLs across all platforms
    for api_item in web_info.get("captured_json_apis", []):
        for m in re.findall(r'https?://[^\s"\'<>\\]+', api_item.get("preview", "")):
            if ".apk" in m.lower() and "car" not in m.lower() and "auto" not in m.lower():
                apk_urls.append(m)
            elif ".apk" in m.lower():
                car_apk_urls.append(m)
            elif ".exe" in m.lower():
                exe_urls.append(m)

    dl_meta["candidate_android_apk_urls"] = list(dict.fromkeys(apk_urls))
    dl_meta["candidate_car_apk_urls"] = list(dict.fromkeys(car_apk_urls))
    dl_meta["candidate_windows_exe_urls"] = list(dict.fromkeys(exe_urls))

    apk_path: Path | None = None
    if apk_urls:
        target_apk_url = apk_urls[0]
        apk_path = WORK / "qishui_official.apk"
        print(f"Downloading Android APK: {target_apk_url}", flush=True)
        rc, _, err = run_cmd(["curl", "-L", "--fail", "--retry", "3", "-o", str(apk_path), target_apk_url], timeout=300)
        if rc != 0 or not apk_path.exists() or apk_path.stat().st_size < 1_000_000:
            dl_meta["apk_download_error"] = err
            apk_path = None
        else:
            dl_meta["android_apk"] = {
                "url": target_apk_url,
                "size_bytes": apk_path.stat().st_size,
                "sha256": sha256_file(apk_path),
            }

    exe_path: Path | None = None
    x64_exes = [u for u in exe_urls if "x64" in u.lower()] or exe_urls
    if x64_exes:
        target_exe_url = x64_exes[0]
        exe_path = WORK / "SodaMusic_win64.exe"
        print(f"Downloading Windows EXE: {target_exe_url}", flush=True)
        rc, _, err = run_cmd(["curl", "-L", "--fail", "--retry", "3", "-o", str(exe_path), target_exe_url], timeout=300)
        if rc != 0 or not exe_path.exists() or exe_path.stat().st_size < 1_000_000:
            dl_meta["exe_download_error"] = err
            exe_path = None
        else:
            dl_meta["windows_exe"] = {
                "url": target_exe_url,
                "size_bytes": exe_path.stat().st_size,
                "sha256": sha256_file(exe_path),
            }

    return apk_path, exe_path, dl_meta


# ==============================================================================
# SURFACE 2: Official Android APK Deep Static Analysis
# ==============================================================================
def parse_dex_classes_fast(dex_bytes: bytes) -> tuple[int, int, list[str]]:
    """Fast binary parser for Dalvik DEX header + string_ids + type_ids + class_defs."""
    if len(dex_bytes) < 112 or not dex_bytes.startswith(b"dex\n"):
        return 0, 0, []
    string_ids_size, string_ids_off = struct.unpack_from("<II", dex_bytes, 56)
    type_ids_size, type_ids_off = struct.unpack_from("<II", dex_bytes, 64)
    method_ids_size, _ = struct.unpack_from("<II", dex_bytes, 88)
    class_defs_size, class_defs_off = struct.unpack_from("<II", dex_bytes, 96)

    def read_uleb128(idx: int) -> tuple[int, int]:
        res = 0
        shift = 0
        while True:
            b = dex_bytes[idx]
            idx += 1
            res |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return res, idx

    def get_str(str_idx: int) -> str:
        if str_idx < 0 or str_idx >= string_ids_size:
            return ""
        data_off = struct.unpack_from("<I", dex_bytes, string_ids_off + str_idx * 4)[0]
        _, pos = read_uleb128(data_off)
        end = dex_bytes.find(b"\x00", pos)
        if end < 0:
            return ""
        return dex_bytes[pos:end].decode("utf-8", errors="replace")

    def get_type(type_idx: int) -> str:
        if type_idx < 0 or type_idx >= type_ids_size:
            return ""
        s_idx = struct.unpack_from("<I", dex_bytes, type_ids_off + type_idx * 4)[0]
        return get_str(s_idx)

    classes: list[str] = []
    for i in range(class_defs_size):
        c_type_idx = struct.unpack_from("<I", dex_bytes, class_defs_off + i * 32)[0]
        desc = get_type(c_type_idx)
        if desc.startswith("L") and desc.endswith(";"):
            classes.append(desc[1:-1].replace("/", "."))
    return class_defs_size, method_ids_size, classes


def analyze_android_static(apk_path: Path) -> dict:
    print("[2/4] Performing Deep Static Analysis on Official Android APK...", flush=True)
    out: dict = {}

    # 1. apksigner & aapt2 badging
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "/usr/local/lib/android/sdk"
    bt_dirs = sorted(Path(sdk_root, "build-tools").glob("*"), reverse=True)
    aapt2 = str(bt_dirs[0] / "aapt2") if bt_dirs else "aapt2"
    apksigner = str(bt_dirs[0] / "apksigner") if bt_dirs else "apksigner"

    _, badging, _ = run_cmd([aapt2, "dump", "badging", str(apk_path)], timeout=60)
    pkg_m = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'(?: compileSdkVersion='([^']*)')?", badging)
    sdk_m = re.search(r"sdkVersion:'([^']+)'", badging)
    tsdk_m = re.search(r"targetSdkVersion:'([^']+)'", badging)
    abi_m = re.search(r"native-code: (.+)", badging)
    out["package_identity"] = {
        "package_name": pkg_m.group(1) if pkg_m else "",
        "version_code": pkg_m.group(2) if pkg_m else "",
        "version_name": pkg_m.group(3) if pkg_m else "",
        "compile_sdk": pkg_m.group(4) if pkg_m else "",
        "min_sdk": sdk_m.group(1) if sdk_m else "",
        "target_sdk": tsdk_m.group(1) if tsdk_m else "",
        "native_abis": abi_m.group(1).strip() if abi_m else "",
    }

    _, sign_out, _ = run_cmd([apksigner, "verify", "--verbose", "--print-certs", str(apk_path)], timeout=60)
    out["signature_verification"] = [ln for ln in sign_out.splitlines() if any(k in ln for k in ["Verified using", "Signer #1"])]

    # 2. Manifest XML tree via aapt2 dump xmltree + apktool for res/xml/network_security_config
    _, xmltree, _ = run_cmd([aapt2, "dump", "xmltree", str(apk_path), "--file", "AndroidManifest.xml"], timeout=60)
    perms = sorted(set(re.findall(r'android:name\(0x01010003\)="([^"]+permission[^"]*)"', xmltree, re.I)))
    # Also capture standard android.permission.*
    perms_all = sorted(set(re.findall(r'E: uses-permission.*?\n\s+A: .*?="([^"]+)"', xmltree)))
    schemes = sorted(set(re.findall(r'android:scheme\(0x01010027\)="([^"]+)"', xmltree)))
    hosts = sorted(set(re.findall(r'android:host\(0x01010028\)="([^"]+)"', xmltree)))
    app_cls = re.findall(r'E: application.*?\n(?:.*\n){0,12}?\s+A: android:name\(0x01010003\)="([^"]+)"', xmltree)
    cleartext_flag = re.findall(r'android:usesCleartextTraffic.*?=\(type .*?\)0x([0-9a-fA-F]+)', xmltree)

    out["manifest_summary"] = {
        "application_class": app_cls[0] if app_cls else "",
        "uses_cleartext_traffic_raw": cleartext_flag[0] if cleartext_flag else "unspecified",
        "permissions_count": len(perms_all),
        "permissions": perms_all[:80],
        "deeplink_schemes": schemes,
        "deeplink_hosts": hosts[:50],
        "activity_count": len(re.findall(r"^\s*E: activity ", xmltree, re.M)),
        "service_count": len(re.findall(r"^\s*E: service ", xmltree, re.M)),
        "receiver_count": len(re.findall(r"^\s*E: receiver ", xmltree, re.M)),
        "provider_count": len(re.findall(r"^\s*E: provider ", xmltree, re.M)),
    }

    # Decode resources/manifest cleanly with apktool (no-src `-s` is super fast!)
    apk_dec = WORK / "apk_decoded"
    rc_apktool, _, _ = run_cmd(["apktool", "d", "-s", "-f", "-o", str(apk_dec), str(apk_path)], timeout=180)
    if rc_apktool == 0 and (apk_dec / "AndroidManifest.xml").exists():
        try:
            tree = ET.parse(apk_dec / "AndroidManifest.xml")
            root_el = tree.getroot()
            ns = "{http://schemas.android.com/apk/res/android}"
            app_el = root_el.find("application")
            if app_el is not None:
                exported_comps: dict[str, list[str]] = defaultdict(list)
                key_services: list[str] = []
                key_providers: list[str] = []
                for tag in ["activity", "activity-alias", "service", "receiver", "provider"]:
                    for el in app_el.findall(tag):
                        nm = el.attrib.get(f"{ns}name", "")
                        exp = el.attrib.get(f"{ns}exported", "")
                        has_if = el.find("intent-filter") is not None
                        if exp == "true" or (exp == "" and has_if):
                            exported_comps[tag].append(nm)
                        if tag == "service":
                            fg = el.attrib.get(f"{ns}foregroundServiceType", "")
                            proc = el.attrib.get(f"{ns}process", "")
                            key_services.append(f"{nm} (proc={proc or 'main'}, fg={fg or 'none'})")
                        if tag == "provider":
                            auth = el.attrib.get(f"{ns}authorities", "")
                            key_providers.append(f"{nm} [{auth}]")
                out["manifest_decoded"] = {
                    "application_attrs": {k.replace(ns, ""): v for k, v in app_el.attrib.items()},
                    "exported_counts": {k: len(v) for k, v in exported_comps.items()},
                    "exported_activities_sample": exported_comps["activity"][:35],
                    "exported_services": exported_comps["service"][:25],
                    "exported_receivers": exported_comps["receiver"][:25],
                    "exported_providers": exported_comps["provider"][:20],
                    "services_sample": key_services[:35],
                    "providers_sample": key_providers[:25],
                }
            net_sec = apk_dec / "res" / "xml" / "network_security_config.xml"
            if net_sec.exists():
                out["network_security_config_xml"] = net_sec.read_text(encoding="utf-8", errors="replace")[:4000]
            else:
                xml_files = [p.name for p in (apk_dec / "res" / "xml").glob("*.xml")] if (apk_dec / "res" / "xml").exists() else []
                out["res_xml_files"] = xml_files[:40]
                for xf in (apk_dec / "res" / "xml").glob("*net*.xml") if (apk_dec / "res" / "xml").exists() else []:
                    out[f"res_xml_{xf.name}"] = xf.read_text(encoding="utf-8", errors="replace")[:3000]
        except Exception as e:
            out["apktool_parse_err"] = str(e)

    # 3. ZIP Inventory, Multi-DEX Class/Package Map, Assets, Native .so ELF Analysis
    with zipfile.ZipFile(apk_path, "r") as zf:
        infos = zf.infolist()
        ext_sizes: dict[str, int] = Counter()
        dir_sizes: dict[str, int] = Counter()
        dex_names: list[str] = []
        so_entries: list[zipfile.ZipInfo] = []
        asset_entries: list[zipfile.ZipInfo] = []

        for zi in infos:
            top = zi.filename.split("/")[0]
            dir_sizes[top] += zi.file_size
            ext = Path(zi.filename).suffix.lower() or "<none>"
            ext_sizes[ext] += zi.file_size
            if re.match(r"^classes\d*\.dex$", zi.filename):
                dex_names.append(zi.filename)
            elif zi.filename.startswith("lib/") and zi.filename.endswith(".so"):
                so_entries.append(zi)
            elif zi.filename.startswith("assets/") and not zi.is_dir():
                asset_entries.append(zi)

        out["archive_breakdown"] = {
            "total_entries": len(infos),
            "uncompressed_bytes_by_top_dir": dict(Counter(dir_sizes).most_common(12)),
            "uncompressed_bytes_by_ext": dict(Counter(ext_sizes).most_common(15)),
            "dex_count": len(dex_names),
            "native_so_count": len(so_entries),
            "asset_file_count": len(asset_entries),
        }

        # Multi-DEX full scan
        total_classes = 0
        total_methods = 0
        pkg2_counter: Counter[str] = Counter()
        pkg3_luna: Counter[str] = Counter()
        pkg3_bd: Counter[str] = Counter()
        interesting_classes: dict[str, list[str]] = defaultdict(list)

        for dn in sorted(dex_names):
            raw_dex = zf.read(dn)
            c_cnt, m_cnt, cls_list = parse_dex_classes_fast(raw_dex)
            total_classes += c_cnt
            total_methods += m_cnt
            for c in cls_list:
                parts = c.split(".")
                if len(parts) >= 2:
                    pkg2_counter[".".join(parts[:2])] += 1
                if c.startswith("com.luna.") and len(parts) >= 4:
                    pkg3_luna[".".join(parts[:4])] += 1
                elif (c.startswith("com.bytedance.") or c.startswith("com.ss.android.")) and len(parts) >= 4:
                    pkg3_bd[".".join(parts[:4])] += 1

                cl = c.lower()
                if c.startswith("com.luna."):
                    for tag, pat in [
                        ("player_audio", r"player|audio|lyric|effect|equalizer|spatial|vinyl|ttm"),
                        ("feed_recommend", r"feed|recommend|swipe|track|playlist|radio"),
                        ("vip_commerce", r"vip|pay|commerce|reward|ad|free"),
                        ("social_douyin", r"douyin|passport|share|comment|im|sync"),
                        ("download_cache", r"download|cache|offline|local"),
                        ("car_device", r"car|auto|bluetooth|widget|wear|dlna|cast"),
                        ("database_storage", r"database|room|dao|entity|mmkv"),
                        ("network_api", r"retrofit|api|net|interceptor|protobuf|pb"),
                    ]:
                        if re.search(pat, cl) and len(interesting_classes[tag]) < 20 and "$" not in c:
                            interesting_classes[tag].append(c)

        out["dex_architecture"] = {
            "dex_files": len(dex_names),
            "total_classes": total_classes,
            "total_method_refs": total_methods,
            "top_level_packages": dict(pkg2_counter.most_common(30)),
            "luna_business_modules": dict(pkg3_luna.most_common(45)),
            "bytedance_middleware_modules": dict(pkg3_bd.most_common(45)),
            "feature_class_samples": dict(interesting_classes),
        }

        # Assets & Hybrid (Gecko / Lynx / Bullet / DSP / Protobuf)
        asset_top_dirs: Counter[str] = Counter()
        lynx_bundles: list[str] = []
        gecko_items: list[str] = []
        dsp_or_audio_assets: list[str] = []
        largest_assets = sorted(asset_entries, key=lambda x: x.file_size, reverse=True)[:25]
        for ai in asset_entries:
            rel = ai.filename[len("assets/"):]
            top_a = rel.split("/")[0]
            asset_top_dirs[top_a] += ai.file_size
            rl = rel.lower()
            if "lynx" in rl or rl.endswith(".template.js") or "card" in rl:
                lynx_bundles.append(f"{rel} ({ai.file_size} B)")
            if "gecko" in rl or "offline" in rl or "hybrid" in rl:
                gecko_items.append(f"{rel} ({ai.file_size} B)")
            if any(k in rl for k in ["dsp", "effect", "eq", "reverb", "spatial", "audio", "sami", ".bin", ".model"]):
                dsp_or_audio_assets.append(f"{rel} ({ai.file_size} B)")

        out["assets_and_hybrid"] = {
            "top_asset_dirs_bytes": dict(asset_top_dirs.most_common(25)),
            "largest_assets": [{"path": a.filename, "size": a.file_size} for a in largest_assets],
            "lynx_samples": lynx_bundles[:25],
            "gecko_hybrid_samples": gecko_items[:25],
            "audio_dsp_ai_model_samples": dsp_or_audio_assets[:25],
        }

        # Native .so Analysis (prefer arm64-v8a, fallback armeabi-v7a)
        abis_present = sorted({s.filename.split("/")[1] for s in so_entries})
        target_abi = "arm64-v8a" if "arm64-v8a" in abis_present else (abis_present[0] if abis_present else "")
        abi_sos = sorted([s for s in so_entries if f"lib/{target_abi}/" in s.filename], key=lambda x: x.file_size, reverse=True)

        so_extract_dir = WORK / "so_extract"
        so_extract_dir.mkdir(exist_ok=True)
        so_catalog: list[dict] = []
        for si in abi_sos[:45]:
            so_name = Path(si.filename).name
            so_file = so_extract_dir / so_name
            so_file.write_bytes(zf.read(si.filename))
            _, dyn_out, _ = run_cmd(["readelf", "-d", str(so_file)], timeout=15)
            needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dyn_out)
            _, sym_out, _ = run_cmd(["nm", "-D", "--defined-only", str(so_file)], timeout=15)
            jni_exports = [
                ln.split()[-1]
                for ln in sym_out.splitlines()
                if "Java_" in ln or "JNI_OnLoad" in ln
            ]
            so_catalog.append(
                {
                    "name": so_name,
                    "size_bytes": si.file_size,
                    "needed": needed[:12],
                    "jni_export_count": len(jni_exports),
                    "jni_samples": jni_exports[:8],
                }
            )

        out["native_libraries"] = {
            "abis_present": abis_present,
            "analyzed_abi": target_abi,
            "total_so_in_abi": len(abi_sos),
            "total_abi_uncompressed_bytes": sum(x.file_size for x in abi_sos),
            "libraries": so_catalog,
        }

    return out


# ==============================================================================
# SURFACE 3: Official Android APK Real Emulator Dynamic Observation
# ==============================================================================
def analyze_android_dynamic(apk_path: Path, pkg_name: str) -> dict:
    print("[3/4] Running Real Android Emulator Dynamic Observation...", flush=True)
    dyn: dict = {}
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "/usr/local/lib/android/sdk"
    avd_home = Path.home() / ".android" / "avd"
    avd_home.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env["ANDROID_SDK_ROOT"] = sdk_root
    env["ANDROID_HOME"] = sdk_root
    env["ANDROID_AVD_HOME"] = str(avd_home)
    env["PATH"] = f"{sdk_root}/emulator:{sdk_root}/platform-tools:{sdk_root}/cmdline-tools/latest/bin:" + env.get("PATH", "")

    # Install android-30 google_apis x86_64 (includes native ARM/ARM64 libndk_translation + adb root!)
    sys_img = "system-images;android-30;google_apis;x86_64"
    run_cmd(f'set +o pipefail; yes | sdkmanager --sdk_root="{sdk_root}" "platform-tools" "emulator" "{sys_img}" >/dev/null', timeout=300, shell=True, env=env)
    rc_avd, _, err_avd = run_cmd(
        f'echo "no" | avdmanager create avd -f -n qishui_avd -k "{sys_img}" -d pixel_5',
        timeout=60,
        shell=True,
        env=env,
    )
    dyn["avd_created"] = rc_avd == 0
    if rc_avd != 0:
        dyn["avd_error"] = err_avd
        return dyn

    pcap_path = WORK / "emu_net.pcap"
    tcpdump_proc = subprocess.Popen(
        ["sudo", "tcpdump", "-i", "any", "-nn", "-s", "0", "-w", str(pcap_path), "port 53 or port 80 or port 443"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    emu_proc = subprocess.Popen(
        [
            f"{sdk_root}/emulator/emulator",
            "-avd",
            "qishui_avd",
            "-no-window",
            "-no-audio",
            "-no-boot-anim",
            "-gpu",
            "swiftshader_indirect",
            "-memory",
            "4096",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        run_cmd(["adb", "wait-for-device"], timeout=90, env=env)
        for _ in range(45):
            _, boot, _ = run_cmd(["adb", "shell", "getprop", "sys.boot_completed"], timeout=10, env=env)
            if boot.strip() == "1":
                break
            time.sleep(2)

        _, abilist, _ = run_cmd(["adb", "shell", "getprop", "ro.product.cpu.abilist"], timeout=10, env=env)
        _, bridge, _ = run_cmd(["adb", "shell", "getprop", "ro.dalvik.vm.native.bridge"], timeout=10, env=env)
        dyn["emulator_props"] = {"abilist": abilist.strip(), "native_bridge": bridge.strip()}

        run_cmd(["adb", "root"], timeout=15, env=env)
        time.sleep(1)

        rc_inst, out_inst, err_inst = run_cmd(["adb", "install", "-r", "-g", str(apk_path)], timeout=120, env=env)
        dyn["install_rc"] = rc_inst
        dyn["install_output"] = (out_inst + " " + err_inst).strip()[:500]

        if rc_inst == 0:
            run_cmd(["adb", "logcat", "-c"], timeout=10, env=env)
            # Launch main launcher activity via monkey
            run_cmd(["adb", "shell", "monkey", "-p", pkg_name, "-c", "android.intent.category.LAUNCHER", "1"], timeout=20, env=env)
            time.sleep(12)

            # Dump first screen (likely privacy modal), tap Agree if present, wait 12s more
            _, xml1, _ = run_cmd(["adb", "exec-out", "uiautomator", "dump", "/dev/tty"], timeout=20, env=env)
            dyn["ui_stage1_texts"] = re.findall(r'(?:text|content-desc)="([^"]+)"', xml1)[:35]

            # Try clicking "同意" (Agree to privacy policy) if visible so main feed & TTNet/Cronet initialize!
            for m in re.finditer(r'text="([^"]*同意[^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml1):
                label = m.group(1)
                if "不同意" not in label and len(label) <= 8:
                    cx = (int(m.group(2)) + int(m.group(4))) // 2
                    cy = (int(m.group(3)) + int(m.group(5))) // 2
                    run_cmd(["adb", "shell", "input", "tap", str(cx), str(cy)], timeout=10, env=env)
                    dyn["privacy_agreed_tap"] = {"label": label, "x": cx, "y": cy}
                    break

            time.sleep(14)
            _, xml2, _ = run_cmd(["adb", "exec-out", "uiautomator", "dump", "/dev/tty"], timeout=20, env=env)
            dyn["ui_stage2_texts"] = re.findall(r'(?:text|content-desc)="([^"]+)"', xml2)[:45]

            # Running processes, threads, loaded maps, databases, shared_prefs, mmkv
            _, ps_out, _ = run_cmd(["adb", "shell", f"ps -A | grep {pkg_name}"], timeout=15, env=env)
            dyn["processes"] = ps_out.strip().splitlines()

            _, pid_out, _ = run_cmd(["adb", "shell", "pidof", pkg_name], timeout=10, env=env)
            main_pid = pid_out.strip().split()[0] if pid_out.strip() else ""
            if main_pid:
                _, maps_out, _ = run_cmd(["adb", "shell", f"cat /proc/{main_pid}/maps"], timeout=15, env=env)
                loaded_sos = sorted(set(re.findall(r"/[^\s]+\.so", maps_out)))
                dyn["loaded_so_count"] = len(loaded_sos)
                dyn["loaded_app_sos"] = [s.split("/")[-1] for s in loaded_sos if pkg_name in s or "/data/app/" in s][:50]

                _, threads_out, _ = run_cmd(["adb", "shell", f"ls /proc/{main_pid}/task | head -n 60 | xargs -I{{}} cat /proc/{main_pid}/task/{{}}/comm 2>/dev/null"], timeout=15, env=env)
                dyn["sample_threads"] = sorted(set(t.strip() for t in threads_out.splitlines() if t.strip()))[:50]

            # On-disk data directory inspection (table names & pref file names ONLY; no tokens/secrets!)
            _, data_tree, _ = run_cmd(["adb", "shell", f"ls -la /data/data/{pkg_name}/ /data/data/{pkg_name}/databases/ /data/data/{pkg_name}/shared_prefs/ /data/data/{pkg_name}/files/ 2>/dev/null"], timeout=15, env=env)
            dyn["data_dir_listing"] = data_tree[:4000]

            _, db_names_out, _ = run_cmd(["adb", "shell", f"ls /data/data/{pkg_name}/databases/ 2>/dev/null"], timeout=10, env=env)
            db_schemas: dict[str, list[str]] = {}
            for dbn in [x.strip() for x in db_names_out.splitlines() if x.strip().endswith(".db")][:12]:
                local_db = WORK / f"pulled_{dbn}"
                if run_cmd(["adb", "pull", f"/data/data/{pkg_name}/databases/{dbn}", str(local_db)], timeout=15, env=env)[0] == 0 and local_db.exists():
                    try:
                        conn = sqlite3.connect(str(local_db))
                        rows = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
                        db_schemas[dbn] = [f"{r[0]}: {(r[1] or '')[:180]}" for r in rows[:20]]
                        conn.close()
                    except Exception:
                        pass
            dyn["sqlite_databases_schema"] = db_schemas

            # Filtered logcat highlights (engine init, Cronet/TTNet, Lynx, TTMPlayer, crashes)
            _, logcat_out, _ = run_cmd(["adb", "logcat", "-d", "-t", "2500"], timeout=20, env=env)
            interesting_logs = []
            for ln in logcat_out.splitlines():
                if any(k in ln for k in ["luna", "Cronet", "TTNet", "Lynx", "ttmplayer", "MDL", "Gecko", "FATAL EXCEPTION", "Room", "AudioTrack"]):
                    # Strip any query params / tokens
                    sanitized = re.sub(r"\?[^\s\"']+", "?<REDACTED>", ln)
                    interesting_logs.append(sanitized[:200])
            dyn["logcat_highlights"] = interesting_logs[:45]

    finally:
        run_cmd(["adb", "emu", "kill"], timeout=15, env=env)
        emu_proc.terminate()
        tcpdump_proc.terminate()
        time.sleep(1)

    # Parse PCAP for DNS / TLS SNI / QUIC domains (excluding Azure runner internal hosts)
    if pcap_path.exists():
        _, strings_pcap, _ = run_cmd(["strings", "-n", "6", str(pcap_path)], timeout=30)
        domains = set()
        for m in re.findall(r"\b(?:[a-z0-9-]+\.)+(?:qishui\.com|douyin\.com|douyinpic\.com|douyinvod\.com|snssdk\.com|bytedance\.com|zijieapi\.com|bdurl\.net|byteimg\.com|bytetos\.com|volces\.com|ibytedtos\.com|amemv\.com|toutiao\.com|mssdk\.[^\s]+)\b", strings_pcap.lower()):
            domains.add(m[:90])
        dyn["observed_network_domains"] = sorted(domains)

    return dyn


# ==============================================================================
# SURFACE 4: Official Windows Desktop Client (SodaMusic win32_x64.exe) Analysis
# ==============================================================================
def analyze_windows_desktop(exe_path: Path) -> dict:
    print("[4/4] Unpacking & Auditing Official Windows Desktop Client (SodaMusic)...", flush=True)
    win: dict = {}

    # PE info & Authenticode signature via osslsigncode / file
    _, file_info, _ = run_cmd(["file", str(exe_path)], timeout=15)
    win["pe_file_type"] = file_info.strip()
    _, sig_info, _ = run_cmd(["osslsigncode", "verify", "-in", str(exe_path)], timeout=30)
    win["authenticode_signature"] = [
        ln.strip()
        for ln in sig_info.splitlines()
        if any(k in ln for k in ["Subject:", "Issuer:", "Signing time:", "Signature verification:", "Message digest algorithm:"])
    ][:20]

    # Unpack NSIS / 7z archive
    unpack_dir = WORK / "win_unpack"
    unpack_dir.mkdir(exist_ok=True)
    rc_7z, out_7z, _ = run_cmd(["7z", "x", "-y", f"-o{unpack_dir}", str(exe_path)], timeout=120)
    win["unpack_7z_rc"] = rc_7z

    # Check if there is a nested `$PLUGINSDIR/app-64.7z` (standard electron-builder NSIS layout!)
    nested_archives = list(unpack_dir.rglob("*.7z")) + list(unpack_dir.rglob("*.zip"))
    win["nested_archives"] = [str(p.relative_to(unpack_dir)) for p in nested_archives]
    app_root = unpack_dir
    for na in nested_archives:
        if "app" in na.name.lower() or "64" in na.name.lower():
            app_root = WORK / "win_app_payload"
            app_root.mkdir(exist_ok=True)
            run_cmd(["7z", "x", "-y", f"-o{app_root}", str(na)], timeout=120)
            break

    all_files = [p for p in app_root.rglob("*") if p.is_file()]
    win["payload_file_count"] = len(all_files)
    win["top_level_files"] = sorted(
        [{"name": p.name, "size": p.stat().st_size if p.is_file() else -1, "is_dir": p.is_dir()} for p in app_root.iterdir()],
        key=lambda x: x["size"],
        reverse=True,
    )[:35]

    dlls = sorted([{"path": str(p.relative_to(app_root)), "size": p.stat().st_size} for p in all_files if p.suffix.lower() in (".dll", ".node", ".exe")], key=lambda x: x["size"], reverse=True)
    win["binaries_dll_node_exe"] = dlls[:45]

    # Inspect Electron `app.asar` header JSON (standard Chromium/Electron ASAR archive format!)
    asar_files = list(app_root.rglob("*.asar"))
    asar_summaries: list[dict] = []
    for af in asar_files:
        try:
            with open(af, "rb") as f:
                # Electron ASAR header: 4B pickle size (4), 4B header_size, 4B header_obj_size, 4B str_len, JSON UTF-8
                raw_hdr = f.read(16)
                _, _, _, json_len = struct.unpack("<IIII", raw_hdr)
                hdr_json_bytes = f.read(json_len)
                hdr_tree = json.loads(hdr_json_bytes.decode("utf-8", errors="replace"))
                base_data_offset = 8 + struct.unpack("<I", raw_hdr[4:8])[0]

                top_entries = list(hdr_tree.get("files", {}).keys())
                pkg_meta = {}
                pkg_node = hdr_tree.get("files", {}).get("package.json")
                if pkg_node and "offset" in pkg_node and "size" in pkg_node:
                    f.seek(base_data_offset + int(pkg_node["offset"]))
                    pkg_raw = json.loads(f.read(int(pkg_node["size"])).decode("utf-8", errors="replace"))
                    pkg_meta = {
                        "name": pkg_raw.get("name"),
                        "version": pkg_raw.get("version"),
                        "main": pkg_raw.get("main"),
                        "dependencies": list((pkg_raw.get("dependencies") or {}).items())[:35],
                    }

                # Walk ASAR virtual file tree (paths & sizes only; zero proprietary source code!)
                asar_file_count = 0
                asar_dirs: dict[str, int] = Counter()
                native_addons_in_asar: list[str] = []

                def walk_asar(node: dict, prefix: str = "") -> None:
                    nonlocal asar_file_count
                    for k, v in (node.get("files") or {}).items():
                        cur = f"{prefix}/{k}" if prefix else k
                        if "files" in v:
                            walk_asar(v, cur)
                        else:
                            asar_file_count += 1
                            top_d = cur.split("/")[0]
                            asar_dirs[top_d] += int(v.get("size", 0))
                            if cur.endswith(".node") or cur.endswith(".dll") or cur.endswith(".wasm"):
                                native_addons_in_asar.append(f"{cur} ({v.get('size', 0)} B)")

                walk_asar(hdr_tree)
                asar_summaries.append(
                    {
                        "asar_path": str(af.relative_to(app_root)),
                        "asar_size_bytes": af.stat().st_size,
                        "total_virtual_files": asar_file_count,
                        "top_entries": top_entries[:30],
                        "top_dir_bytes": dict(asar_dirs.most_common(20)),
                        "package_json": pkg_meta,
                        "embedded_native_or_wasm": native_addons_in_asar[:25],
                    }
                )
        except Exception as e:
            asar_summaries.append({"asar_path": str(af), "error": str(e)})

    win["asar_archives"] = asar_summaries
    return win


def main() -> None:
    report: dict = {"timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    web_res = analyze_web_and_discover_urls()
    report["surface_1_web_and_distribution"] = web_res

    apk_path, exe_path, dl_meta = fetch_official_binaries(web_res)
    report["binary_acquisition"] = dl_meta

    if apk_path and apk_path.exists():
        static_res = analyze_android_static(apk_path)
        report["surface_2_android_static"] = static_res
        pkg = static_res.get("package_identity", {}).get("package_name") or "com.luna.music"
        report["surface_3_android_dynamic"] = analyze_android_dynamic(apk_path, pkg)

    if exe_path and exe_path.exists():
        report["surface_4_windows_desktop"] = analyze_windows_desktop(exe_path)

    out_path = Path("/tmp/qishui_full_re_report.json")
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Report written: {out_path} ({out_path.stat().st_size} bytes)", flush=True)


if __name__ == "__main__":
    main()
