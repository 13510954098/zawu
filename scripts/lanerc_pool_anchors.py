"""Find fixed, non-secret protocol markers referenced via ARM64 Dart PP loads.
Only labels, code addresses and direct BL targets are exported. No pool values.
Nearest function entries are hints, NOT proof of function ownership.
"""
import bisect
import json
import pathlib
import re
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

MARKERS = {
    'buildSignature': 'signature-name',
    'Authorization': 'authorization-header',
    'app/config': 'configuration-endpoint',
    'app/v2/play': 'playback-endpoint',
    'app/home': 'home-endpoint',
    'app/v2/guest/captcha': 'guest-captcha-endpoint',
    'app/v2/guest/credential': 'guest-credential-endpoint',
    'app/v2/guest/play': 'guest-play-endpoint',
    'guest_credential': 'guest-credential-field',
    'challenge_id': 'guest-challenge-field',
    'selected': 'guest-selected-field',
    'AES': 'aes-label', 'CBC': 'cbc-label', 'GCM': 'gcm-label',
    'PKCS7': 'pkcs7-label', 'SHA-256': 'sha256-label',
    'encrypted': 'encrypted-field-label',
}


def analyze(lib, pool, graph):
    slots = {}
    for line in pool.read_text(errors='replace').splitlines():
        # Restrict matches to exact whitelisted String values, never export text.
        slot = re.search(r'\[pp\+(0x[0-9a-f]+)\]', line)
        if not slot:
            continue
        for needle, label in MARKERS.items():
            if f'String: "{needle}"' in line:
                slots[int(slot[1], 16)] = label
    known = {int(f['address'], 16): f for f in graph['functions']}
    entries = sorted(known)
    with lib.open('rb') as stream:
        elf = ELFFile(stream)
        sections = [(s['sh_addr'], s.data()) for s in elf.iter_sections() if s['sh_flags'] & 4]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    hits = []
    for base, data in sections:
        derived = {}
        recent_calls = []
        for address, size, mnemonic, operands in md.disasm_lite(data, base):
            derived = {k: v for k, v in derived.items() if address - v[1] <= 12}
            recent_calls = [(a, t) for a, t in recent_calls if address - a <= 96]
            if mnemonic == 'bl':
                target = re.fullmatch(r'#?(0x[0-9a-f]+)', operands)
                if target:
                    recent_calls.append((address, target[1]))
            match = re.fullmatch(r'(x\d+), x27, #(0x[0-9a-f]+|\d+)(?:, lsl #(0x[0-9a-f]+|\d+))?', operands) if mnemonic == 'add' else None
            if match:
                derived[match[1]] = (int(match[2], 0) << (int(match[3], 0) if match[3] else 0), address)
            load = re.fullmatch(r'[xw]\d+, \[(x\d+)(?:, #(0x[0-9a-f]+|\d+))?\]', operands) if mnemonic in ('ldr', 'ldur') else None
            if load:
                register = load[1]
                if register == 'x27' or register in derived:
                    offset = (0 if register == 'x27' else derived[register][0]) + (int(load[2], 0) if load[2] else 0)
                    if offset in slots:
                        index = bisect.bisect_right(entries, address) - 1
                        preceding = entries[index] if index >= 0 else None
                        hits.append({
                            'marker': slots[offset], 'instruction': hex(address),
                            'pool_offset': hex(offset),
                            'preceding_known_entry_hint': hex(preceding) if preceding is not None else None,
                            'distance_from_hint': address - preceding if preceding is not None else None,
                            'recent_direct_call_targets': [target for _, target in recent_calls],
                        })
            if mnemonic in ('b', 'br', 'blr', 'ret', 'bl'):
                derived.clear()
    return {
        'method': 'Exact whitelisted object-pool strings and ARM64 x27-relative loads',
        'limitations': 'Heuristic register tracking; no constant values exported; nearest entry is not proven ownership; incomplete function metadata',
        'pool_marker_slots': [{'offset': hex(k), 'label': v} for k, v in sorted(slots.items())],
        'code_anchors': hits,
    }


if __name__ == '__main__':
    lib, pool, graph, output = map(pathlib.Path, sys.argv[1:])
    result = analyze(lib, pool, json.loads(graph.read_text()))
    output.write_text(json.dumps(result, indent=2))
    print(f"Exported {len(result['code_anchors'])} redacted code anchors")
