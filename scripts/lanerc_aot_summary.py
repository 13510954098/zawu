"""Export AOT call metadata only; never export object-pool/string values."""
import argparse
import json
import pathlib
import re


def summarize(root):
    functions = {}
    addr_re = re.compile(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)')
    call_re = re.compile(r'\bbl\s+#?(0x[0-9a-f]+)\b')
    focus = re.compile(r'buildSignature|encrypt|decrypt|\bAES\b|\bHmac\b|onRequest|onResponse|Interceptor|ApiService|Doh|Bootstrap', re.I)
    for path in sorted(root.rglob('*.dart')):
        current = None
        previous = ''
        for line in path.read_text(errors='replace').splitlines():
            match = addr_re.search(line)
            if match:
                # Only the declaration preceding the address, never field initializers.
                declaration = previous.strip()
                if not declaration.endswith('{') or '"' in declaration or "'" in declaration:
                    declaration = '<declaration omitted>'
                current = {
                    'address': match[1], 'size': match[2],
                    'library': str(path.relative_to(root)),
                    'declaration': declaration, 'calls': [], 'markers': [],
                }
                functions[match[1]] = current
            elif line == '  }':
                current = None
            elif current:
                call = call_re.search(line)
                if call and call[1] not in current['calls']:
                    current['calls'].append(call[1])
                # Report fixed categories, not literal values or neighboring text.
                for needle, label in [
                    ('Authorization', 'authorization-header'),
                    ('app/v2/play', 'playback-endpoint'),
                    ('app/config', 'configuration-endpoint'),
                    ('application/json', 'json-mime'),
                    ('String: "', 'string-constant-present'),
                ]:
                    if needle in line and label not in current['markers']:
                        current['markers'].append(label)
            previous = line
    seeds = {a for a, fn in functions.items() if focus.search(fn['declaration']) or any(m != 'string-constant-present' for m in fn['markers'])}
    selected = set(seeds)
    # Two graph hops include callers and callees; unresolved indirect calls remain unknown.
    for _ in range(2):
        old = set(selected)
        for addr, fn in functions.items():
            if addr in old:
                selected.update(c for c in fn['calls'] if c in functions)
            if any(c in old for c in fn['calls']):
                selected.add(addr)
    if not seeds:
        selected = set(functions)
    return {
        'scope': 'Static ARM64 direct-call graph; no runtime execution or credential validation',
        'redaction': 'No object pool, raw assembly, string constants, keys, IVs or tokens exported',
        'limitations': 'Obfuscation, inlining, dynamic dispatch and indirect calls limit completeness; names do not prove purpose',
        'total_functions': len(functions), 'seed_count': len(seeds),
        'assembly_files': [str(p.relative_to(root)) for p in sorted(root.rglob('*.dart'))],
        'functions_with_calls': sum(bool(f['calls']) for f in functions.values()),
        'seeds': sorted(seeds, key=lambda a: int(a, 16)),
        'functions': [functions[a] for a in sorted(selected, key=lambda a: int(a, 16))],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('asm', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    report = summarize(args.asm)
    if report['total_functions'] == 0:
        raise SystemExit('No function headers parsed; refusing to emit an empty success report')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2))
    print(f"Parsed {report['total_functions']} functions; exported {len(report['functions'])} metadata records")
