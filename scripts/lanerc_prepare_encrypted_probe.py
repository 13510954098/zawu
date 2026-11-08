#!/usr/bin/env python3
"""Locally sign and encrypt one authorized native request; never export client keys.
The supplied unsigned canonical URI must already match Dart/Dio serialization.
Only the CMS ciphertext is written under analysis/. Plaintext is ephemeral.
"""
import argparse
import json
import pathlib
import secrets
import subprocess
import tempfile
import time
import urllib.parse

from lanerc_offline_crypto import sign
from lanerc_encrypted_probe_runner import validate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--number', required=True, type=int, choices=range(1, 8))
    parser.add_argument('--canonical-uri', required=True)
    parser.add_argument('--body-file', type=pathlib.Path)
    parser.add_argument('--material', type=pathlib.Path, default=pathlib.Path('.local/lanerc/recovered-secrets.json'))
    args = parser.parse_args()
    uri = urllib.parse.urlsplit(args.canonical_uri)
    if any(key == 'sign' for key, _ in urllib.parse.parse_qsl(uri.query)):
        raise ValueError('URI already contains a signature')
    material = json.loads(args.material.read_text())
    now = int(time.time())
    nonce = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(3))
    signature = sign(args.canonical_uri, now, nonce, material['request_signature']['secret_suffix'])
    signed = args.canonical_uri + ('&' if uri.query else '?') + 'sign=' + signature
    body = json.loads(args.body_file.read_text()) if args.body_file else None
    payload = {'run_id':str(args.run_id), 'url':signed, 'method':'POST' if body is not None else 'GET', 'body':body}
    parsed, method, _, _ = validate(payload, args.run_id, now)
    directory = pathlib.Path('analysis/lanerc/native-probe') / str(args.run_id)
    recipient = directory / 'runner.pem'
    if not recipient.exists():
        raise ValueError('Runner has not published its ephemeral recipient certificate')
    output = directory / f'request-{args.number:02d}.p7m'
    if output.exists():
        raise ValueError('Never overwrite an existing probe request')
    with tempfile.TemporaryDirectory() as temporary:
        plaintext = pathlib.Path(temporary) / 'request.json'
        plaintext.write_text(json.dumps(payload))
        plaintext.chmod(0o600)
        subprocess.run(['openssl','cms','-encrypt','-binary','-aes-256-cbc','-in',str(plaintext),'-outform','DER','-out',str(output),str(recipient)], check=True, capture_output=True)
    print(json.dumps({'encrypted_request_file':str(output), 'method':method, 'path':parsed.path, 'keys_exported':False}))


if __name__ == '__main__':
    main()
