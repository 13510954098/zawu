#!/usr/bin/env python3
"""Emit a minimal, redacted UI summary and optional coordinates for a Welfare tab."""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

source, summary_path, coordinate_path = map(Path, sys.argv[1:4])
try:
    root = ET.parse(source).getroot()
except Exception as exc:
    summary_path.write_text(f'UI hierarchy parse: FAILED ({type(exc).__name__})\n', encoding='utf-8')
    coordinate_path.write_text('', encoding='utf-8')
    raise SystemExit(0)

nodes = list(root.iter('node'))
parents = {child: parent for parent in nodes for child in list(parent)}
labels: list[str] = []
home = False
welfare_seen = False
welfare_center = ''
sensitive = re.compile(r'(?i)(authorization|cookie|bearer|token|trans.?id|device.?id|advertising.?id|android.?id|imei|oaid|gaid|phone|email|account|password)')
email = re.compile(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b')
longopaque = re.compile(r'\b[A-Za-z0-9_-]{24,}\b')
phone = re.compile(r'\b(?:\+?\d[\d .()\-]{7,}\d)\b')

def safe(value: str) -> str:
    value = value.strip()
    if not value:
        return ''
    if sensitive.search(value) or email.search(value) or phone.search(value) or longopaque.search(value):
        return '[REDACTED]'
    return value[:100]

def center(bounds: str) -> str:
    match = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds)
    if not match:
        return ''
    x1, y1, x2, y2 = map(int, match.groups())
    return f'{(x1+x2)//2},{(y1+y2)//2}'

for node in nodes:
    text = safe(node.attrib.get('text', ''))
    desc = safe(node.attrib.get('content-desc', ''))
    values = [v for v in (text, desc) if v]
    if not values:
        continue
    label = ' | '.join(values)
    if label not in labels:
        labels.append(label)
    if text == '首页' or desc == '首页':
        home = True
    if text == '福利' or desc == '福利':
        welfare_seen = True
        candidate = node
        while candidate is not None:
            if candidate.attrib.get('clickable') == 'true':
                welfare_center = center(candidate.attrib.get('bounds', ''))
                if welfare_center:
                    break
            candidate = parents.get(candidate)

summary_path.write_text(
    'Home label detected: ' + ('yes' if home else 'no') + '\n'
    + 'Welfare label detected: ' + ('yes' if welfare_seen else 'no') + '\n'
    + 'Welfare entry clickable: ' + ('yes' if welfare_center else 'no') + '\n'
    + 'Visible UI labels (redacted):\n'
    + '\n'.join(f'- {label}' for label in labels[:120]) + '\n',
    encoding='utf-8',
)
coordinate_path.write_text(welfare_center, encoding='utf-8')
