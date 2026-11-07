#!/usr/bin/env python3
"""Run Blutter on Dart 3.9.2 arm64 libapp.so and package architectural & object-pool analysis."""
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
import zlib

APK_PATH = pathlib.Path("work/sample.apk")
LIB_DIR = pathlib.Path("work/apk_lib/arm64-v8a")
BLUTTER_OUT = pathlib.Path("work/blutter_out")
SUMMARY_DIR = pathlib.Path("work/blutter_summary")
STEP_LOG = pathlib.Path("work/step_blutter.log")


def log(msg: str):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    STEP_LOG.parent.mkdir(parents=True, exist_ok=True)
    with STEP_LOG.open("a") as f:
        f.write(line + "\n")


def extract_arm64_libs_and_notices():
    LIB_DIR.mkdir(parents=True, exist_ok=True)
    oss_pkgs = set()
    with zipfile.ZipFile(APK_PATH) as zf:
        for name in ("libapp.so", "libflutter.so"):
            data = zf.read(f"lib/arm64-v8a/{name}")
            (LIB_DIR / name).write_bytes(data)
            log(f"Extracted {name} ({len(data)} bytes)")
        if "assets/flutter_assets/NOTICES.Z" in zf.namelist():
            raw = zf.read("assets/flutter_assets/NOTICES.Z")
            try:
                txt = zlib.decompress(raw).decode("utf-8", "replace")
            except Exception:
                import gzip
                txt = gzip.decompress(raw).decode("utf-8", "replace")
            for block in txt.split("-" * 80):
                lines = [ln.strip() for ln in block.strip().splitlines() if ln.strip()]
                if lines and len(lines[0]) < 60:
                    oss_pkgs.add(lines[0])
    return oss_pkgs


def run_blutter():
    blutter_dir = pathlib.Path("work/blutter")
    if not blutter_dir.exists():
        log("Cloning worawit/blutter...")
        subprocess.check_call(
            ["git", "clone", "--depth", "1", "https://github.com/worawit/blutter.git", str(blutter_dir)],
            stdin=subprocess.DEVNULL,
        )
    log("Running blutter.py (compiling Dart 3.9.2 snapshot dumper + analyzing libapp.so)...")
    p = subprocess.run(
        [sys.executable, "blutter.py", str(LIB_DIR.resolve()), str(BLUTTER_OUT.resolve())],
        cwd=str(blutter_dir),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    (SUMMARY_DIR / "blutter_stdout.log").write_text(p.stdout[-50_000:])
    if p.returncode != 0:
        log(f"blutter.py exited with {p.returncode}:\n{p.stdout[-3000:]}")
        raise RuntimeError(f"blutter.py failed with rc={p.returncode}")
    log("blutter.py succeeded!")


def summarize_blutter_output(oss_pkgs: set[str]):
    asm_root = BLUTTER_OUT / "asm"
    pkg_stats = []
    app_asm_dest = SUMMARY_DIR / "app_asm"
    app_asm_dest.mkdir(parents=True, exist_ok=True)

    sdk_prefixes = {
        "dart", "flutter", "material", "widgets", "rendering", "painting", "cupertino",
        "foundation", "gestures", "scheduler", "semantics", "services", "animation", "physics",
        "vector_math", "collection", "async", "meta", "typed_data", " sky_engine",
    }

    class_re = re.compile(r"^class\s+(\S+)(?:\s+extends\s+([^\s{]+))?", re.MULTILINE)
    func_re = re.compile(r"^\s*(?:static\s+)?[^\n{};]+\s+([A-Za-z0-9_$<>]+)\([^)]*\)\s*(?:async\s*)?\{", re.MULTILINE)

    classes_index = {}
    if asm_root.exists():
        # 1) Capture top-level .dart files directly under blutter_out/asm/ (where --obfuscate places stripped-URI libraries)
        top_dart_files = sorted(f for f in asm_root.iterdir() if f.is_file() and f.suffix == ".dart")
        if top_dart_files:
            top_bytes = sum(f.stat().st_size for f in top_dart_files)
            pkg_stats.append({
                "package": "<root_obfuscated_asm>",
                "category": "first_party_or_custom",
                "file_count": len(top_dart_files),
                "total_bytes": top_bytes,
                "files": [f.name for f in top_dart_files],
            })
            root_classes = []
            for df in top_dart_files:
                shutil.copy2(df, app_asm_dest / df.name)
                txt = df.read_text(errors="replace")
                cls_found = [{"name": m.group(1), "extends": m.group(2) or ""} for m in class_re.finditer(txt)]
                fns_found = [m.group(1) for m in func_re.finditer(txt)][:120]
                root_classes.append({
                    "file": df.name,
                    "bytes": len(txt),
                    "class_count": len(cls_found),
                    "classes_sample": cls_found[:200],
                    "functions_sample": fns_found,
                })
            classes_index["<root_obfuscated_asm>"] = root_classes

        # 2) Capture subdirectories under blutter_out/asm/
        for pkg_dir in sorted(asm_root.iterdir()):
            if not pkg_dir.is_dir():
                continue
            pname = pkg_dir.name
            dart_files = list(pkg_dir.rglob("*.dart"))
            total_bytes = sum(f.stat().st_size for f in dart_files)
            is_oss = pname in oss_pkgs or pname in sdk_prefixes
            category = "sdk_or_oss" if is_oss else "first_party_or_custom"
            pkg_stats.append({
                "package": pname,
                "category": category,
                "file_count": len(dart_files),
                "total_bytes": total_bytes,
                "files": [str(f.relative_to(pkg_dir)) for f in sorted(dart_files)[:120]],
            })

            # Copy all first-party / custom packages AND key bridge plugins (ads, media_kit, dio, isar)
            interesting_plugins = {"flutter_ads_plugin", "ffx_spd", "ceval", "floating"}
            if category == "first_party_or_custom" or pname in interesting_plugins:
                shutil.copytree(pkg_dir, app_asm_dest / pname, dirs_exist_ok=True)
                pkg_classes = []
                for df in sorted(dart_files):
                    txt = df.read_text(errors="replace")
                    cls_found = [{"name": m.group(1), "extends": m.group(2) or ""} for m in class_re.finditer(txt)]
                    fns_found = [m.group(1) for m in func_re.finditer(txt)][:80]
                    pkg_classes.append({
                        "file": str(df.relative_to(pkg_dir)),
                        "bytes": len(txt),
                        "classes": cls_found,
                        "functions_sample": fns_found,
                    })
                classes_index[pname] = pkg_classes

    pkg_stats.sort(key=lambda x: (0 if x["category"] == "first_party_or_custom" else 1, -x["total_bytes"]))
    (SUMMARY_DIR / "package_inventory.json").write_text(json.dumps(pkg_stats, indent=2, ensure_ascii=False))
    (SUMMARY_DIR / "first_party_classes.json").write_text(json.dumps(classes_index, indent=2, ensure_ascii=False))

    # Record full manifest of files generated by Blutter
    all_blutter_files = [
        {"path": str(p.relative_to(BLUTTER_OUT)), "bytes": p.stat().st_size}
        for p in sorted(BLUTTER_OUT.rglob("*")) if p.is_file()
    ]
    (SUMMARY_DIR / "blutter_out_manifest.json").write_text(json.dumps(all_blutter_files, indent=2))

    frida_js = BLUTTER_OUT / "blutter_frida.js"
    if frida_js.exists():
        shutil.copy2(frida_js, SUMMARY_DIR / "blutter_frida.js")

    # Note: pp.txt was already downloaded in full (2,825,728 bytes); skip re-bundling pp.txt to keep archive fast & compact


def upload_report_tarball(tar_path: pathlib.Path):
    repo = os.environ["REPO"]
    commit_sha = os.environ["COMMIT_SHA"]
    data = tar_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    chunk_size = 24 * 1024 * 1024
    blobs = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        payload = pathlib.Path("work/blutter_blob.json")
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
        "type": "blutter_asm_complete",
        "sha256": sha256,
        "size": len(data),
        "blobs": blobs,
    }
    comment_payload = pathlib.Path("work/blutter_comment.json")
    comment_payload.write_text(json.dumps({"body": json.dumps(manifest)}))
    subprocess.check_call(
        ["gh", "api", f"repos/{repo}/commits/{commit_sha}/comments", "--method", "POST", "--input", str(comment_payload)],
        stdin=subprocess.DEVNULL,
    )


def main():
    SUMMARY_DIR.mkdir(parents=True, exist_ok=True)
    oss_pkgs = extract_arm64_libs_and_notices()
    run_blutter()
    summarize_blutter_output(oss_pkgs)

    tar_path = pathlib.Path("work/blutter_asm_complete.tar.xz")
    with tarfile.open(tar_path, "w:xz", preset=3) as tf:
        tf.add(SUMMARY_DIR, arcname="blutter_asm_complete")

    log(f"Created {tar_path} ({tar_path.stat().st_size} bytes), uploading...")
    upload_report_tarball(tar_path)
    log("Blutter complete ASM analysis uploaded successfully!")


if __name__ == "__main__":
    main()
