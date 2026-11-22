#!/usr/bin/env python3
"""Per-node exit-IP probe: one mihomo instance per lane, GLOBAL switch per node."""
import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time
import urllib.request

import yaml

MIHOMO = os.environ.get("MIHOMO", os.path.abspath("mihomo"))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
HTTP_BASE = 17890
CTRL_BASE = 20090
PER_NODE_TIMEOUT = 9
TOTAL_LANES_SCALE = 10000


def run(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception:
        return ""


def ctrl_put(ctrl_port, name):
    req = urllib.request.Request(
        f"http://127.0.0.1:{ctrl_port}/proxies/GLOBAL",
        data=json.dumps({"name": name}).encode(),
        method="PUT",
        headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=6).read()


def wait_ctrl(ctrl_port, deadline):
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{ctrl_port}/version", timeout=2).read()
            return True
        except Exception:
            time.sleep(0.15)
    return False


def query_ip(http_port):
    """Return (exit_ip, info dict, delay_ms, err)."""
    t0 = time.time()
    body = run(["curl", "-sS", "-m", str(PER_NODE_TIMEOUT), "--proxy",
                f"http://127.0.0.1:{http_port}", "-A", UA,
                "https://ipwho.is/"], PER_NODE_TIMEOUT + 3)
    delay = int((time.time() - t0) * 1000)
    try:
        d = json.loads(body)
    except Exception:
        d = None
    if isinstance(d, dict) and d.get("success") and d.get("ip"):
        conn = d.get("connection") or {}
        return d["ip"], {
            "country": d.get("country"),
            "cc": d.get("country_code"),
            "region": d.get("region"),
            "city": d.get("city"),
            "asn": f"AS{conn.get('asn')}" if conn.get("asn") else None,
            "asname": conn.get("org"),
            "isp": conn.get("isp"),
            "org": conn.get("org"),
            "rdns": None,
            "src": "ipwho.is",
        }, delay, None

    # fallback 1: ip-api over plain HTTP
    body = run(["curl", "-sS", "-m", str(PER_NODE_TIMEOUT), "--proxy",
                f"http://127.0.0.1:{http_port}", "-A", UA,
                "http://ip-api.com/json/?fields=status,message,country,countryCode,"
                "regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting,query&lang=zh-CN"],
               PER_NODE_TIMEOUT + 3)
    try:
        d = json.loads(body)
        if d.get("status") == "success" and d.get("query"):
            return d["query"], {
                "country": d.get("country"),
                "cc": d.get("countryCode"),
                "region": d.get("regionName"),
                "city": d.get("city"),
                "asn": d.get("as"),
                "asname": d.get("asname") or d.get("isp"),
                "isp": d.get("isp"),
                "org": d.get("org"),
                "rdns": d.get("reverse"),
                "hosting": d.get("hosting"),
                "proxy": d.get("proxy"),
                "mobile": d.get("mobile"),
                "src": "ip-api",
            }, delay, None
    except Exception:
        pass

    # fallback 2: plain ip echo
    body = run(["curl", "-sS", "-m", str(PER_NODE_TIMEOUT), "--proxy",
                f"http://127.0.0.1:{http_port}", "-A", UA,
                "https://api.ipify.org?format=json"], PER_NODE_TIMEOUT + 3)
    try:
        d = json.loads(body)
        if d.get("ip"):
            return d["ip"], {"src": "ipify"}, delay, None
    except Exception:
        pass
    return None, None, delay, "request failed"


def run_lane(lane, proxies, base_dir, deadline):
    http_port = HTTP_BASE + lane * 10
    ctrl_port = CTRL_BASE + lane * 10
    cfgdir = os.path.join(base_dir, f"lane{lane}")
    os.makedirs(cfgdir, exist_ok=True)
    cfg = {
        "mixed-port": http_port,
        "allow-lan": False,
        "mode": "global",
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{ctrl_port}",
        "unified-delay": True,
        "proxies": proxies,
    }
    cfgpath = os.path.join(cfgdir, "config.yaml")
    with open(cfgpath, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)

    proc = subprocess.Popen([MIHOMO, "-d", cfgdir, "-f", cfgpath],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = []
    if not wait_ctrl(ctrl_port, time.time() + 45):
        proc.terminate()
        for p in proxies:
            out.append({"name": p["name"], "ok": False, "err": "mihomo not ready"})
        return out
    try:
        for p in proxies:
            if time.time() > deadline:
                out.append({"name": p["name"], "ok": False, "err": "lane deadline"})
                continue
            name = p["name"]
            ip = info = None
            delay = 0
            err = None
            for attempt in range(2):
                try:
                    ctrl_put(ctrl_port, name)
                except Exception as e:
                    err = f"switch: {e}"
                    time.sleep(0.3)
                    continue
                time.sleep(0.2 if attempt == 0 else 0.6)
                ip, info, delay, err = query_ip(http_port)
                if ip:
                    break
            rec = {
                "name": name,
                "type": p.get("type"),
                "server": p.get("server"),
                "port": p.get("port"),
                "ok": bool(ip),
                "ip": ip,
                "delay": delay,
                "err": None if ip else err,
            }
            if info:
                rec.update(info)
            out.append(rec)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--shard", type=int, required=True)
    ap.add_argument("--shards", type=int, required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", required=True)
    ap.add_argument("--budget", type=int, default=900, help="lane budget seconds")
    a = ap.parse_args()

    data = yaml.safe_load(open(a.config, encoding="utf-8"))
    proxies = data["proxies"]
    total = a.shards * a.workers
    tasks = []
    for w in range(a.workers):
        lane = a.shard * a.workers + w
        subset = [p for i, p in enumerate(proxies) if i % total == lane]
        tasks.append((lane, subset))
    base_dir = os.path.join("/tmp", "jcprobe")
    os.makedirs(base_dir, exist_ok=True)

    deadline = time.time() + a.budget
    result = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(run_lane, lane, subset, base_dir, deadline)
                for lane, subset in tasks]
        for f in concurrent.futures.as_completed(futs):
            try:
                result.extend(f.result())
            except Exception as e:
                print("lane failed", e, file=sys.stderr)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in result:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    ok = sum(1 for r in result if r.get("ok"))
    print(f"shard {a.shard}: {ok}/{len(result)} ok")


if __name__ == "__main__":
    main()
