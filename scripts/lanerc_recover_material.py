"""Recover statically identified material from the PRIVATE ARM64 object-pool dump.
Pinned to APK SHA-256 4368de63ae2003138dbe63b673422a3b3a5414ab652ffb1feb3424964f88bcfd.
No values are printed. Do not commit the output to Git.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re

APK_SHA256 = '4368de63ae2003138dbe63b673422a3b3a5414ab652ffb1feb3424964f88bcfd'


def recover(text):
    line = next(line for line in text.splitlines() if line.startswith('[pp+0xe238]'))
    parts = re.findall(r'List<int>\(16\) \[([^\]]+)\]', line)
    if len(parts) != 4:
        raise ValueError('Expected four 16-nibble arrays')
    nibbles = [int(token.strip(), 0) for part in parts for token in part.split(',')]
    if len(nibbles) != 64 or any(not 0 <= n < 16 for n in nibbles):
        raise ValueError('Invalid key-nibble structure')
    key = bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, 64, 2))
    match = re.search(r'\[pp\+0x11b70\] String: "((?:\\.|[^"\\])*)"', text)
    if not match:
        raise ValueError('Signing suffix slot missing')
    suffix = json.loads('"' + match[1] + '"')
    if len(suffix) != 17:
        raise ValueError('Unexpected signing suffix length')
    return {
        'apk_sha256': APK_SHA256,
        'validation': 'Static binary reconstruction; no production traffic or server validation',
        'response_encryption': {
            'algorithm': 'AES-256-GCM', 'key_hex': key.hex(),
            'key_sha256': hashlib.sha256(key).hexdigest(),
            'raw_envelope': 'nonce[12] || ciphertext || authentication_tag[16]',
            'associated_data': 'empty/default; verify against your original protocol',
            'source': 'initializer 0x60c4d8 -> 0x63298c; nibble array pool slot 0xe238',
        },
        'request_signature': {
            'digest': 'MD5', 'secret_suffix': suffix,
            'suffix_sha256': hashlib.sha256(suffix.encode()).hexdigest(),
            'preimage': 'canonical_uri + @ + unix_seconds + @ + nonce + secret_suffix',
            'query_parameter': 'sign', 'parameter_value': 'unix_seconds-nonce-lowercase_md5_hex',
            'placement_evidence': 'RequestOptions queryParameters field offset 0x50 is merged at 0x7ee380-0x7ee448; URI getter reads same field at 0x4a9930',
            'nonce': '3 lowercase ASCII letters',
            'source': 'request interceptor 0x7ee08c; suffix pool slot 0x11b70',
            'uri_note': 'Use the exact final Dart/Dio URI string, including query encoding/order; Python URI normalization is not assumed equivalent',
        },
        'release_signing': {
            'private_key': None,
            'status': 'Not recoverable from APK public certificate; original keystore/backup required',
            'certificate_sha256': '74322d4d62b9f4a986dfa8973ee70ebc034e74551b8715c755edd9ed18e6820b',
        },
    }


def write_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pool', type=pathlib.Path)
    parser.add_argument('--output', type=pathlib.Path, default=pathlib.Path('.local/lanerc/recovered-secrets.json'))
    args = parser.parse_args()
    recovered = recover(args.pool.read_text())
    write_private(args.output, recovered)
    print('Recovered 32-byte response key and 17-character signing suffix; private output mode 0600')
