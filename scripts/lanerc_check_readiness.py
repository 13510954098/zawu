"""Local recovery/readiness audit. Never makes network requests or exports secrets.
A clean offline audit is NOT live guest authentication or playback verification.
"""
import argparse
import hashlib
import json
import pathlib

from lanerc_validate_bootstrap import validate

ROOT = pathlib.Path(__file__).resolve().parents[1]


def check(material, status, records=None):
    checks = {}
    checks['apk_identity'] = material.get('apk_sha256') == status['apk_sha256']
    entries = (
        ('request_signature_suffix', 'request_signature', 'secret_suffix', False),
        ('play_resolve_gcm', 'response_encryption', 'key_hex', True),
        ('general_json_ecb', 'json_response_encryption', 'key_hex', True),
        ('bootstrap_txt_ecb', 'bootstrap_txt_encryption', 'key_hex', True),
    )
    for name, section, field, is_hex in entries:
        try:
            value = material[section][field]
            raw = bytes.fromhex(value) if is_hex else value.encode('utf-8')
            size_ok = len(raw) == 32 if is_hex else len(value) == 17
            checks[name] = size_ok and hashlib.sha256(raw).hexdigest() == status['key_material'][name]['sha256']
        except (KeyError, TypeError, ValueError, AttributeError):
            checks[name] = False
    try:
        pairs = material['json_response_encryption']['ordered_replacements']
        checks['legacy_mapping_structure'] = isinstance(pairs, list) and len(pairs) == 10 and all(
            isinstance(pair, list) and len(pair) == 2 and all(isinstance(char, str) and len(char) == 1 for char in pair)
            for pair in pairs)
        checks['bootstrap_mapping_is_empty'] = material['bootstrap_txt_encryption']['ordered_replacements'] == []
    except (KeyError, TypeError):
        checks['legacy_mapping_structure'] = False
        checks['bootstrap_mapping_is_empty'] = False
    bootstrap = {'checked': False, 'matching_record_count': 0}
    if records is not None:
        bootstrap['checked'] = True
        if checks['bootstrap_txt_ecb'] and checks['bootstrap_mapping_is_empty']:
            result = validate(records, material['bootstrap_txt_encryption'], 'v3.yyghk.com')
            bootstrap['matching_record_count'] = result['matching_txt_record_count']
        checks['saved_public_txt_matches_expected_host'] = bootstrap['matching_record_count'] > 0
    return {
        'scope': 'Local recovery-material audit, optional saved public DNS replay; no server access',
        'checks': checks,
        'offline_checks_passed': all(checks.values()),
        'saved_public_bootstrap': bootstrap,
        'network_requests_performed': False,
        'production_authentication_verified': False,
        'production_playback_verified': False,
        'release_private_key_recovered': False,
        'all_user_goals_completed': False,
        'unresolved_requirements': [
            'Valid server-issued guestCredential and a legitimate production playback response',
            'Original release keystore/private-key backup for original Android signing identity',
        ],
        'caveat': 'Fingerprint matches confirm material identity, not server acceptance; ECB hostname matching is not authenticity verification. Mapping structure checks do not verify its semantic correctness.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--secrets', required=True, type=pathlib.Path)
    parser.add_argument('--records', type=pathlib.Path, help='Optional local saved DoH JSON; not a URL')
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        inputs = [args.secrets, ROOT / 'analysis/lanerc/protocol-status.json']
        if args.records:
            inputs.append(args.records)
        if any(args.output.resolve() == path.resolve() for path in inputs):
            raise ValueError('Output must not overwrite an input')
        material = json.loads(args.secrets.read_text())
        status = json.loads((ROOT / 'analysis/lanerc/protocol-status.json').read_text())
        records = json.loads(args.records.read_text()) if args.records else None
        report = check(material, status, records)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Report contains booleans/counts only, never raw material or decoded URLs.
        from lanerc_recover_material import write_private
        write_private(args.output, report)
    except Exception:
        # Do not disclose raw inputs/paths/decoder exception payloads.
        print('Local audit failed: check input files and JSON structure. No request was sent.')
        return 1
    print('Local audit saved. Production playback and original release signing remain unverified.')
    # 0 = all goals verified; 1 = bad material; 2 = offline checks pass but live/signing goals unresolved.
    return 2 if report['offline_checks_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
