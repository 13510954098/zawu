"""Runner-only layout investigation for user-selected original APK import.
Outputs offsets/encodings only, never protocol material or object-pool contents.
"""
import argparse
import hashlib
import json
import pathlib
import re


def joint_reference_layout(binary, chunks, records):
    """Require one shared, injective reference dictionary across all four arrays."""
    candidates = []
    for chunk, record in zip(chunks, records):
        options = []
        for group in record['reference_structure_candidates']:
            if group['width'] != 'dart-variable-reference' or group['truncated']:
                continue
            for offset in group['offsets']:
                cursor, mapping = offset, {}
                for nibble in chunk:
                    start = cursor
                    while cursor < len(binary) and cursor - start < 5:
                        terminal = binary[cursor] >= 128
                        cursor += 1
                        if terminal:
                            break
                    else:
                        raise ValueError('Invalid candidate reference')
                    token = binary[start:cursor]
                    if nibble in mapping and mapping[nibble] != token:
                        break
                    mapping[nibble] = token
                else:
                    if len(set(mapping.values())) == len(mapping):
                        options.append((offset, mapping))
        candidates.append(options)
    solutions = []

    def visit(index, dictionary, offsets):
        if len(solutions) > 1:
            return
        if index == len(chunks):
            solutions.append((offsets, dictionary))
            return
        for offset, mapping in candidates[index]:
            if any(key in dictionary and dictionary[key] != value for key, value in mapping.items()):
                continue
            combined = dict(dictionary)
            combined.update(mapping)
            if len(set(combined.values())) == len(combined):
                visit(index + 1, combined, offsets + [offset])

    visit(0, {}, [])
    result = {'unique': len(solutions) == 1, 'candidate_solution_count_capped_at_two': len(solutions)}
    if len(solutions) == 1:
        offsets, mapping = solutions[0]
        result.update(offsets=offsets, mapped_nibble_count=len(mapping),
                      dictionary_sha256=hashlib.sha256(json.dumps({str(k):v.hex() for k,v in sorted(mapping.items())}, sort_keys=True).encode()).hexdigest())
    return result


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
        reference_candidates = []
        if not matches:
            # Snapshot arrays may store arbitrary object-reference IDs rather
            # than literal Smi values. Match equality structure, not key bytes.
            # No mapping or captured values are exported.
            encodings = [(width, f'.{{{width}}}') for width in (1, 2, 3, 4, 8)]
            encodings += [
                ('dart-variable-reference', r'[\x00-\x7f]{0,4}[\x80-\xff]'),
                ('uleb128-variable-reference', r'[\x80-\xff]{0,4}[\x00-\x7f]'),
            ]
            for width, word_pattern in encodings:
                groups = {}
                pattern = []
                for value in chunk:
                    if value in groups:
                        pattern.append(f'(?P={groups[value]})')
                    else:
                        name = f'n{len(groups)}'
                        if groups:
                            pattern.append('(?!(?:' + '|'.join(f'(?P={group})' for group in groups.values()) + '))')
                        pattern.append(f'(?P<{name}>{word_pattern})')
                        groups[value] = name
                expression = re.compile(('(?=' + ''.join(pattern) + ')').encode(), re.DOTALL)
                found = []
                for match in expression.finditer(binary):
                    found.append(match.start())
                    if len(found) == 65:
                        break
                if found:
                    reference_candidates.append({'width': width, 'offsets': found[:64], 'truncated': len(found) > 64})
        records.append({'array_index': index, 'matches': matches,
                        'reference_structure_candidates': reference_candidates,
                        'reference_value_mapping_recovered': False})
    return {'scope': 'Static layout probe only; not an implemented or verified Android APK importer',
            'libapp_sha256': hashlib.sha256(binary).hexdigest(),
            'all_arrays_uniquely_located': all(any(m['unique'] for m in record['matches']) for record in records),
            'arrays': records, 'joint_reference_layout': joint_reference_layout(binary, chunks, records),
            'raw_material_published': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('pool', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    result = probe(args.binary.read_bytes(), args.pool.read_text())
    args.output.write_text(json.dumps(result, indent=2) + '\n')
