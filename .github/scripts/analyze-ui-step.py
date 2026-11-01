#!/usr/bin/env python3
"""Summarize a screenshot and UIAutomator dump without exporting raw UI text."""
from __future__ import annotations

import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

xml_path, image_path, stage, output_dir = map(Path, sys.argv[1:5])
target = sys.argv[5] if len(sys.argv) > 5 else ''
out = output_dir / f'{stage}-ui-summary.txt'
coord_file = output_dir / f'{stage}-target-coordinate.txt'

width = height = 0
try:
    data = image_path.read_bytes()
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        width, height = struct.unpack('>II', data[16:24])
except Exception:
    pass

nodes = []
parents = {}
if xml_path.exists():
    try:
        root = ET.parse(xml_path).getroot()
        nodes = list(root.iter('node'))
        parents = {child: parent for parent in nodes for child in list(parent)}
    except Exception:
        nodes = []

sensitive = re.compile(r'(?i)(authorization|cookie|bearer|token|trans.?id|device.?id|advertising.?id|android.?id|imei|oaid|gaid|phone|email|account|password)')
email = re.compile(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b')
phone = re.compile(r'\b(?:\+?\d[\d .()\-]{7,}\d)\b')
opaque = re.compile(r'\b[A-Za-z0-9_-]{24,}\b')

def safe(value: str) -> str:
    value = value.strip()
    if not value:
        return ''
    if sensitive.search(value) or email.search(value) or phone.search(value) or opaque.search(value):
        return '[REDACTED]'
    return value[:100]

def get_center(bounds: str) -> str:
    match = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds)
    if not match:
        return ''
    x1, y1, x2, y2 = map(int, match.groups())
    return f'{(x1+x2)//2},{(y1+y2)//2}'

labels: list[str] = []
exact_seen = False
click_coord = ''
for node in nodes:
    text = safe(node.attrib.get('text', ''))
    desc = safe(node.attrib.get('content-desc', ''))
    for value in (text, desc):
        if value and value not in labels:
            labels.append(value)
    if target and (node.attrib.get('text', '').strip() == target or node.attrib.get('content-desc', '').strip() == target):
        exact_seen = True
        candidate = node
        while candidate is not None:
            if candidate.attrib.get('clickable') == 'true':
                click_coord = get_center(candidate.attrib.get('bounds', ''))
                if click_coord:
                    break
            candidate = parents.get(candidate)

ocr_full = ''
ocr_ok = False
if image_path.exists() and image_path.stat().st_size:
    try:
        result = subprocess.run(
            ['tesseract', str(image_path), 'stdout', '-l', 'chi_sim+eng', '--psm', '6'],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode == 0:
            ocr_full = result.stdout
            ocr_ok = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
ocr_compact = re.sub(r'\s+', '', ocr_full)
ocr_seen = bool(target and target in ocr_compact)
hierarchy_text = ' '.join(node.attrib.get('text', '') + ' ' + node.attrib.get('content-desc', '') for node in nodes)
combined_compact = re.sub(r'\s+', '', hierarchy_text + ' ' + ocr_full)
home_visible = '首页' in combined_compact
welfare_visible = '福利' in combined_compact
login_hint = bool(re.search(r'登录|注册|手机号|验证码', hierarchy_text + ocr_full))
download_hint = bool(re.search(r'下载|次数|权限', hierarchy_text + ocr_full))
ad_hint = bool(re.search(r'广告|看视频|视频奖励|观看视频', hierarchy_text + ocr_full))
relevant = []
for line in ocr_full.splitlines():
    line = line.strip()
    if re.search(r'已知晓|首页|福利|登录|注册|手机号|验证码|下载|次数|金币|权限|广告|任务', line):
        line = safe(line)
        if line and line not in relevant:
            relevant.append(line)

coord_file.write_text(click_coord, encoding='utf-8')
summary = [
    f'Step: {stage}',
    f'Screenshot size: {width}x{height}' if width and height else 'Screenshot size: unavailable',
    f'UI hierarchy nodes: {len(nodes)}',
    f'target_in_hierarchy={"yes" if exact_seen else "no"}',
    f'target_clickable={"yes" if click_coord else "no"}',
    f'target_ocr_visible={"yes" if ocr_seen else "no"}',
    f'ocr_available={"yes" if ocr_ok else "no"}',
    f'home_visible={"yes" if home_visible else "no"}',
    f'welfare_visible={"yes" if welfare_visible else "no"}',
    f'login_hint={"yes" if login_hint else "no"}',
    f'download_hint={"yes" if download_hint else "no"}',
    f'ad_hint={"yes" if ad_hint else "no"}',
    f'Target {target!r} in hierarchy: {"yes" if exact_seen else "no"}',
    f'Target {target!r} clickable in hierarchy: {"yes" if click_coord else "no"}',
    f'Target {target!r} OCR-visible: {"yes" if ocr_seen else "no"} (OCR available: {"yes" if ocr_ok else "no"})',
    'Visible hierarchy labels (redacted):',
    *[f'- {label}' for label in labels[:80]],
    'Relevant OCR lines (redacted):',
    *[f'- {line}' for line in relevant[:40]],
]
out.write_text('\n'.join(summary) + '\n', encoding='utf-8')
