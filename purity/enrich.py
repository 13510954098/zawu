#!/usr/bin/env python3
"""Enrich exit IPs with reputation data and build CSV/XLSX/report.

Sources (all queried from the runner, no proxy needed):
  - ip-api batch  : country/ASN/ISP + hosting & proxy flags
  - scamalytics   : fraud score 0-100
  - ping0.cc      : risk % (best effort, may hit captcha)
"""
import argparse
import concurrent.futures
import csv
import gzip
import html
import json
import os
import re
import threading
import time
import urllib.request

UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")


def http(url, data=None, timeout=25, headers=None):
    h = {"User-Agent": UA, "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        raw = r.read()
        if r.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
        return raw.decode("utf-8", "replace")
    except Exception as e:
        return f"__ERR__{type(e).__name__}:{e}"


def flat(h):
    t = re.sub(r"<script.*?</script>|<style.*?</style>", "", h, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    return html.unescape(re.sub(r"\s+", " ", t))


def ipapi_batch(ips):
    out = {}
    fields = ("status,message,country,countryCode,regionName,city,isp,org,as,asname,"
              "hosting,proxy,mobile,query")
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        body = json.dumps([{"query": ip} for ip in chunk]).encode()
        txt = http(f"http://ip-api.com/batch?fields={fields}&lang=zh-CN",
                   data=body, headers={"Content-Type": "application/json"}, timeout=30)
        try:
            for d in json.loads(txt):
                if d.get("status") == "success" and d.get("query"):
                    out[d["query"]] = d
        except Exception:
            pass
        time.sleep(4.2)  # free tier: 15 batch requests / minute
    return out


def scam_one(ip):
    txt = http(f"https://scamalytics.com/ip/{ip}", timeout=25)
    if txt.startswith("__ERR__"):
        return ip, {"err": txt[:80]}
    t = flat(txt)
    d = {"ip": ip}
    m = re.search(r"Fraud Score:\s*(\d+)", t)
    d["fraud"] = int(m.group(1)) if m else None
    m = re.search(r"Fraud Risk\s+(Very High Risk|High Risk|Medium Risk|Low Risk)", t)
    d["band"] = m.group(1) if m else None
    if d["fraud"] is None:
        d["err"] = "no fraud score"
    return ip, d


def ping0_one(ip):
    txt = http(f"https://ping0.cc/ip?ip={ip}", timeout=28)
    if txt.startswith("__ERR__"):
        return ip, {"err": txt[:60]}
    t = flat(txt)
    d = {"ip": ip}
    if "风控值" not in t:
        d["err"] = "captcha/no data"
        return ip, d
    m = re.search(r"风控值 \(说明\?\) (\d+)% (.+?) 原生 IP", t)
    d["risk"] = int(m.group(1)) if m else None
    d["risklv"] = m.group(2).strip() if m else None
    m = re.search(r"IP 类型 \(说明\?\) (.+?) 为什么双ISP", t)
    d["type"] = m.group(1).strip() if m else None
    m = re.search(r"原生 IP \(说明\?\) (.+?) 大模型检测", t)
    d["native"] = m.group(1).strip() if m else None
    m = re.search(r"共享人数 \(说明\?\) (.+?) 适用场景", t)
    d["shared"] = m.group(1).strip() if m else None
    return ip, d


def run_pool(fn, ips, workers, pace=0.6):
    out = {}
    lock = threading.Lock()
    last = [0.0]

    def wrapped(ip):
        with lock:
            wait = last[0] + pace - time.time()
        if wait > 0:
            time.sleep(wait)
        with lock:
            last[0] = max(time.time(), last[0] + pace)
        return fn(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ip, d in ex.map(wrapped, ips):
            out[ip] = d
    return out


def score_of(sc, api, p0):
    if not sc or sc.get("fraud") is None:
        return None, None
    s = 100 - sc["fraud"]
    if api:
        if api.get("hosting"):
            s -= 22
        if api.get("proxy"):
            s -= 10
        if api.get("mobile"):
            s += 3
    if p0 and p0.get("risk") is not None:
        s = (s + (100 - p0["risk"])) / 2
        if (p0.get("native") or "") != "原生 IP":
            s -= 6
        if "10000" in (p0.get("shared") or ""):
            s -= 6
    s = max(0, min(100, round(s)))
    grade = "A" if s >= 80 else "B" if s >= 65 else "C" if s >= 50 else "D"
    return s, grade


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shards-dir", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--ping0", action="store_true")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)

    recs = []
    for fn in sorted(os.listdir(a.shards_dir)):
        if fn.endswith(".jsonl"):
            with open(os.path.join(a.shards_dir, fn), encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            recs.append(json.loads(line))
                        except Exception:
                            pass
    good = [r for r in recs if r.get("ok") and r.get("ip")]
    ips = sorted({r["ip"] for r in good})
    print(f"records {len(recs)} ok {len(good)} unique ips {len(ips)}", flush=True)

    api = ipapi_batch(ips)
    print(f"ip-api {len(api)}/{len(ips)}", flush=True)
    sc = run_pool(scam_one, ips, a.workers, 0.8)
    print(f"scamalytics {sum(1 for v in sc.values() if v.get('fraud') is not None)}/{len(ips)}", flush=True)
    p0 = {}
    if a.ping0:
        p0 = run_pool(ping0_one, ips, a.workers, 1.0)
        print(f"ping0 {sum(1 for v in p0.values() if v.get('risk') is not None)}/{len(ips)}", flush=True)

    rows = []
    for r in recs:
        ip = r.get("ip")
        ai = api.get(ip, {}) if ip else {}
        si = sc.get(ip, {}) if ip else {}
        pi = p0.get(ip, {}) if ip else {}
        s, g = score_of(si, ai, pi) if si.get("fraud") is not None else (None, None)
        rows.append({
            "节点": r.get("name"),
            "协议": r.get("type"),
            "入口": str(r.get("server") or ""),
            "端口": r.get("port"),
            "出口IP": ip or "",
            "国家/地区": ai.get("country") or r.get("country") or "",
            "城市": ai.get("city") or r.get("city") or "",
            "ASN": ai.get("as") or r.get("asn") or "",
            "ISP/组织": ai.get("isp") or ai.get("org") or r.get("asname") or "",
            "欺诈分": si.get("fraud"),
            "风险档": si.get("band") or "",
            "机房IP": "是" if ai.get("hosting") else ("否" if ai else ""),
            "代理标记": "是" if ai.get("proxy") else ("否" if ai else ""),
            "移动网络": "是" if ai.get("mobile") else ("否" if ai else ""),
            "ping0风控": pi.get("risk"),
            "ping0类型": pi.get("type") or "",
            "ping0原生": pi.get("native") or "",
            "ping0共享": pi.get("shared") or "",
            "延迟ms": r.get("delay") if r.get("ok") else None,
            "纯净分": s,
            "等级": g,
            "判定": ("无法连接" if not r.get("ok") else
                     "未取到数据" if s is None else
                     "优质" if s >= 80 and not ai.get("hosting") else
                     "可用" if s >= 65 else "慎用"),
            "备注": r.get("err") or si.get("err") or "",
            "测试时间": time.strftime("%Y-%m-%d %H:%M:%S"),
        })

    csv_path = os.path.join(a.outdir, "JC节点纯净度.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter

    keys = list(rows[0].keys())
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "明细"
    ws.append(keys)
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="4F6BED")
        c.alignment = Alignment(horizontal="center", vertical="center")
    for r in rows:
        ws.append([r[k] for k in keys])
    widths = {"节点": 38, "入口": 26, "ISP/组织": 34, "国家/地区": 14, "ASN": 10}
    for i, k in enumerate(keys, 1):
        ws.column_dimensions[get_column_letter(i)].width = widths.get(k, 11)
    ws.freeze_panes = "A2"
    fill = {"A": "C6EFCE", "B": "DDEBF7", "C": "FFF2CC", "D": "FFC7CE"}
    gi = keys.index("等级")
    for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
        g = row[gi].value
        if g in fill:
            for c in row:
                c.fill = PatternFill("solid", fgColor=fill[g])

    top = [r for r in rows if r["判定"] == "优质"]
    top.sort(key=lambda r: (-(r["纯净分"] or 0), r["延迟ms"] or 99999))
    ws2 = wb.create_sheet("优质节点")
    ws2.append(keys)
    for r in top:
        ws2.append([r[k] for k in keys])
    for i, k in enumerate(keys, 1):
        ws2.column_dimensions[get_column_letter(i)].width = widths.get(k, 11)
    ws2.freeze_panes = "A2"

    ws3 = wb.create_sheet("国家分布")
    ws3.append(["国家/地区", "节点数", "可连通", "取到数据", "平均欺诈分", "优质数"])
    by = {}
    for r in rows:
        c = r["国家/地区"] or "未知"
        d = by.setdefault(c, [0, 0, 0, [], 0])
        d[0] += 1
        if r["判定"] != "无法连接":
            d[1] += 1
        if r["欺诈分"] is not None:
            d[2] += 1
            d[3].append(r["欺诈分"])
        if r["判定"] == "优质":
            d[4] += 1
    for c, d in sorted(by.items(), key=lambda x: -x[1][0]):
        ws3.append([c, d[0], d[1], d[2], round(sum(d[3]) / len(d[3]), 1) if d[3] else None, d[4]])
    for i, wdt in enumerate([18, 10, 10, 12, 14, 10], 1):
        ws3.column_dimensions[get_column_letter(i)].width = wdt

    ws4 = wb.create_sheet("说明")
    for k, v in [
        ("测试对象", "JC 节点订阅（1801 个节点）"),
        ("测试环境", "GitHub Actions Ubuntu runner + mihomo v1.19.34"),
        ("出口 IP", "经每个节点请求 ipwho.is 取真实出口 IP"),
        ("欺诈分", "scamalytics.com 按出口 IP 查询，0-100，越低越干净"),
        ("机房/代理标记", "ip-api.com 批量接口返回的 hosting / proxy / mobile"),
        ("纯净分", "100-欺诈分；机房 -22；代理 -10；移动 +3；有 ping0 数据时取均值并扣原生/共享"),
        ("等级", "A≥80，B≥65，C≥50，D<50"),
        ("ping0", "批量查询会触发验证码，仅部分 IP 能取到风控值，作参考列"),
        ("注意", "第三方口径随时间波动，共享出口 IP 的节点纯净度会一起变化"),
    ]:
        ws4.append([k, v])
    ws4.column_dimensions["A"].width = 16
    ws4.column_dimensions["B"].width = 92

    xlsx_path = os.path.join(a.outdir, "JC节点纯净度.xlsx")
    wb.save(xlsx_path)

    okn = sum(1 for r in rows if r["判定"] != "无法连接")
    pn = sum(1 for r in rows if r["欺诈分"] is not None)
    grades = {g: sum(1 for r in rows if r["等级"] == g) for g in "ABCD"}
    lines = [
        "# JC 节点纯净度实测",
        "",
        f"- 节点总数：{len(rows)}，可连通：{okn}，取到欺诈分：{pn}，唯一出口 IP：{len(ips)}",
        f"- 等级分布：A {grades['A']} / B {grades['B']} / C {grades['C']} / D {grades['D']}",
        f"- 测试时间：{time.strftime('%Y-%m-%d %H:%M:%S')}（UTC+8）",
        "",
        "## 优质节点（非机房、纯净分 ≥80）",
        "",
        "| # | 节点 | 出口IP | 国家 | ASN | 欺诈分 | 机房 | 延迟 | 纯净分 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(top[:50], 1):
        lines.append(f"| {i} | {r['节点']} | {r['出口IP']} | {r['国家/地区']} | {r['ASN']} | "
                     f"{r['欺诈分']} | {r['机房IP']} | {r['延迟ms']} | {r['纯净分']} |")
    lines += ["", "## 欺诈分最高（建议避开）", "",
              "| 节点 | 出口IP | 国家 | 欺诈分 | 机房 | 代理标记 |", "|---|---|---|---|---|---|"]
    for r in sorted([r for r in rows if r["欺诈分"] is not None],
                    key=lambda r: -r["欺诈分"])[:20]:
        lines.append(f"| {r['节点']} | {r['出口IP']} | {r['国家/地区']} | {r['欺诈分']} | "
                     f"{r['机房IP']} | {r['代理标记']} |")
    lines += ["", "## 说明", "",
              "欺诈分来自 scamalytics，机房/代理标记来自 ip-api；ping0 风控值因验证码只覆盖一部分 IP，"
              "在明细里单列参考。机房 IP 即使欺诈分低也不适合账号类业务。", ""]
    md_path = os.path.join(a.outdir, "JC节点纯净度报告.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("done", xlsx_path)


if __name__ == "__main__":
    main()
