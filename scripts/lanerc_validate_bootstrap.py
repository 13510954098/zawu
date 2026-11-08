"""Privately decode saved public DoH TXT records; export host-only diagnostics.
No DNS/HTTP requests are made. ECB plausibility is not authenticity validation.
Raw records and recovered keys must remain private; outputs omit URL paths/queries.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import urllib.parse
from lanerc_offline_crypto import decrypt_json_transport


def validate(records, material, expected_host):
    result = {
        'validated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'Offline decode of previously obtained public DNS TXT records',
        'algorithm': 'AES-256-ECB/PKCS7/UTF-8',
        'key_sha256': hashlib.sha256(bytes.fromhex(material['key_hex'])).hexdigest(),
        'expected_hostname': expected_host, 'records': [],
        'protected_requests_performed': False,
        'caveat': 'Padding, UTF-8 and expected hostname checks do not authenticate ECB ciphertext, prove ownership or validate playback access',
    }
    for record in records:
        for answer in record.get('response', {}).get('Answer', []):
            if answer.get('type') != 16:
                continue
            raw = str(answer.get('data', ''))
            chunks = re.findall(r'"((?:\\.|[^"\\])*)"', raw)
            encoded = ''.join(chunks) if chunks else raw
            item = {'query_name': record.get('name'), 'ciphertext_length': len(encoded)}
            try:
                if len(encoded) > 4096:
                    raise ValueError('Public TXT size limit')
                plain = decrypt_json_transport(encoded, material).decode('utf-8')
                if any(ord(char) < 32 for char in plain):
                    raise ValueError('Control characters in URI')
                uri = urllib.parse.urlsplit(plain)
                if uri.scheme != 'https' or not uri.hostname or uri.username or uri.password:
                    raise ValueError('Expected an HTTPS URL without embedded credentials')
                item.update({
                    'padding_and_utf8_valid': True,
                    'decoded_scheme': uri.scheme, 'decoded_hostname': uri.hostname,
                    'matches_expected_hostname': uri.hostname.lower() == expected_host.lower(),
                    'decoded_text_sha256': hashlib.sha256(plain.encode()).hexdigest(),
                })
            except Exception as error:
                # Never export plaintext, exceptions containing raw values, paths or tokens.
                item.update({'padding_and_utf8_valid': False, 'error_type': type(error).__name__})
            result['records'].append(item)
    result['matching_txt_record_count'] = sum(bool(item.get('matches_expected_hostname')) for item in result['records'])
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records', type=pathlib.Path, required=True)
    parser.add_argument('--secrets', type=pathlib.Path, required=True)
    parser.add_argument('--expected-host', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = validate(json.loads(args.records.read_text()), json.loads(args.secrets.read_text())['bootstrap_txt_encryption'], args.expected_host)
    result['encrypted_record_provenance'] = 'Public DNS records were transferred as CMS ciphertext; no recovered keys were used by the connectivity runner'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    if not result['matching_txt_record_count']:
        raise SystemExit('No decoded TXT record matched the expected hostname')
    print('Saved public TXT decoded to expected hostname; protected APIs were not called')
