"""Offline helpers for the statically reconstructed protocol. No network access.
Requires `cryptography` for decryption. Never place recovered secrets in Git.
The supplied URI must already match Dart/Dio canonicalization exactly.
"""
import argparse
import hashlib
import json
import pathlib
import re


def sign(canonical_uri, unix_seconds, nonce, suffix):
    if not re.fullmatch('[a-z]{3}', nonce):
        raise ValueError('Nonce must be three lowercase ASCII letters')
    if isinstance(unix_seconds, bool) or not isinstance(unix_seconds, int) or unix_seconds < 0:
        raise ValueError('Expected nonnegative integer Unix seconds')
    preimage = f'{canonical_uri}@{unix_seconds}@{nonce}{suffix}'.encode('utf-8')
    digest = hashlib.md5(preimage).hexdigest()
    return f'{unix_seconds}-{nonce}-{digest}'


def decrypt_envelope(blob, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(key) != 32:
        raise ValueError('Expected a 32-byte AES-256 key')
    if len(blob) < 28:
        raise ValueError('Expected at least 12 nonce bytes and 16 tag bytes')
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def decrypt_json_transport(encoded, material):
    """Decode the separately identified legacy ECB transport, without network I/O.
    Padding/UTF-8 checks are not authentication: ECB has no integrity guarantee.
    """
    import base64
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = bytes.fromhex(material['key_hex'])
    if len(key) != 32:
        raise ValueError('Expected a 32-byte legacy response key')
    for source, target in material['ordered_replacements']:
        if len(source) != 1 or len(target) != 1:
            raise ValueError('Expected single-character ordered replacements')
        encoded = encoded.replace(source, target)
    ciphertext = base64.b64decode(encoded, validate=True)
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError('Expected nonempty AES block-aligned ciphertext')
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    plaintext.decode('utf-8')
    return plaintext


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--secrets', required=True, type=pathlib.Path)
    sub = parser.add_subparsers(dest='command', required=True)
    signature = sub.add_parser('sign')
    signature.add_argument('--uri', required=True)
    signature.add_argument('--timestamp', required=True, type=int)
    signature.add_argument('--nonce', required=True)
    decrypt = sub.add_parser('decrypt')
    decrypt.add_argument('--input', required=True, type=pathlib.Path, help='Raw decoded binary envelope, not JSON/base64')
    decrypt.add_argument('--output', required=True, type=pathlib.Path)
    legacy = sub.add_parser('decrypt-json-response')
    legacy.add_argument('--input', required=True, type=pathlib.Path, help='Local encoded data string, not the entire HTTP JSON wrapper')
    legacy.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    material = json.loads(args.secrets.read_text())
    if args.command == 'sign':
        print(sign(args.uri, args.timestamp, args.nonce, material['request_signature']['secret_suffix']))
    else:
        if args.command == 'decrypt':
            key = bytes.fromhex(material['response_encryption']['key_hex'])
            plaintext = decrypt_envelope(args.input.read_bytes(), key)
        else:
            plaintext = decrypt_json_transport(args.input.read_text(), material['json_response_encryption'])
        # Authentication succeeds before plaintext is written. Restrictive creation mode.
        import os
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(plaintext)
        print('Authenticated offline decryption completed' if args.command == 'decrypt' else 'Offline ECB decoding completed; ECB is not authenticated')
