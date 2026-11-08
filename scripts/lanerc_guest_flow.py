"""Actions-only native guest control-flow inspection. No pool values or credentials."""
import bisect
import json
import pathlib
import re
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile


def inspect(lib, anchors):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    instructions = []
    with lib.open('rb') as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if section['sh_flags'] & 4:
                instructions.extend(md.disasm_lite(section.data(), section['sh_addr']))
    instructions.sort()
    entries = [addr for addr, _, op, args in instructions if op == 'stp' and re.match(r'x29, x30, \[(?:sp|x15), #-', args) and args.endswith('!')]
    if not entries:
        raise ValueError('No Dart frame prologues recognized')
    def owner(address):
        index = bisect.bisect_right(entries, address) - 1
        return entries[index] if index >= 0 else None
    markers = {int(item['instruction'], 16): item['marker'] for item in anchors['code_anchors']
               if item['marker'] in {'guest-captcha-endpoint', 'guest-credential-endpoint', 'guest-play-endpoint', 'playback-endpoint'}}
    seeds = {owner(address) for address in markers}
    seeds.discard(None)
    calls = []
    for address, _, op, operands in instructions:
        if op == 'bl' and re.fullmatch(r'#?0x[0-9a-f]+', operands):
            calls.append((address, owner(address), int(operands.lstrip('#'), 16)))
    selected = set(seeds)
    # Two caller hops expose branch sites choosing between login/guest paths.
    for _ in range(2):
        previous = set(selected)
        selected.update(caller for _, caller, target in calls if target in previous and caller is not None)
    functions = []
    for entry in sorted(selected)[:24]:
        index = bisect.bisect_right(entries, entry)
        next_entry = entries[index] if index < len(entries) else entry + 0x1800
        end = min(next_entry, entry + 0x1800)
        rows = [{'address': hex(addr), 'op': op, 'operands': args,
                 **({'marker': markers[addr]} if addr in markers else {})}
                for addr, _, op, args in instructions if entry <= addr < end]
        functions.append({'entry': hex(entry), 'endpoint_owner': entry in seeds,
                          'truncated': end < next_entry, 'instructions': rows,
                          'callers': [{'call_site':hex(site), 'entry':hex(caller) if caller is not None else None}
                                      for site, caller, target in calls if target == entry]})
    return {'scope': 'Static prologue/control-flow evidence only; no first-play or captcha trigger behavior verified',
            'limitations': 'Indirect calls, tail calls, inlining, async resume entries and frame-less functions may be missing; prologues are heuristic',
            'pool_values_exported': False, 'endpoint_markers_found':len(markers), 'seed_entries':list(map(hex, sorted(seeds))),
            'selected_entries':len(selected), 'functions':functions}


if __name__ == '__main__':
    lib, anchors, output = map(pathlib.Path, sys.argv[1:])
    output.write_text(json.dumps(inspect(lib, json.loads(anchors.read_text())), indent=2)+'\n')
