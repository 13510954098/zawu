"""Runner-only layout investigation for user-selected original APK import.
Outputs offsets/encodings only, never protocol material or object-pool contents.
"""
import argparse
import hashlib
import json
import pathlib
import re


def probe(binary, pool):
    line = next(line for line in pool.splitlines() if line.startswith('[pp+0xe238]'))
    parts = re.findall(r'List<int>\(16\) \[([^\]]+)\]', line)
    chunks = [[int(value.strip(), 0) for value in part.split(',')] for part in parts]
    if len(chunks) != 4 or any(len(chunk) != 16 or any(not 0 <= v <= 15 for v in chunk) for chunk in chunks):
        raise ValueError('Unexpected original nibble-array structure')
    records = []
    for index, chunk in enumerate(chunks):
        matches = []
        # Search each independent snapshot array, not a nonexistent concatenation.
        # Bias allows small snapshot reference IDs, stride allows Smi tagging.
        for stride in (1, 2):
            for bias in range(512):
                for width in (1, 2, 4):
                    if max(chunk) * stride + bias >= 1 << (width * 8):
                        continue
                    for endian in ('little', 'big') if width > 1 else ('little',):
                        encoded = b''.join((value * stride + bias).to_bytes(width, endian) for value in chunk)
                        offset = binary.find(encoded)
                        if offset >= 0:
                            matches.append({'offset': offset, 'stride': stride, 'bias': bias, 'width': width, 'endian': endian,
                                            'unique': binary.find(encoded, offset + 1) < 0})
        records.append({'array_index': index, 'matches': matches})
    return {'scope': 'Static layout probe only; not an implemented or verified Android APK importer',
            'libapp_sha256': hashlib.sha256(binary).hexdigest(),
            'all_arrays_uniquely_located': all(any(m['unique'] for m in record['matches']) for record in records),
            'arrays': records, 'raw_material_published': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('pool', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    result = probe(args.binary.read_bytes(), args.pool.read_text())
    args.output.write_text(json.dumps(result, indent=2) + '\n')
