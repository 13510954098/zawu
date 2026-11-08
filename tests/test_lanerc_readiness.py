"""Readiness must never upgrade local checks into live authentication claims."""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from lanerc_check_readiness import check


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        key = bytes(range(32))
        suffix = 'fixture-suffix-17'
        self.material = {'apk_sha256': 'dummy-apk',
                         'request_signature': {'secret_suffix': suffix},
                         'response_encryption': {'key_hex': key.hex()},
                         'json_response_encryption': {'key_hex': key.hex(), 'ordered_replacements': [[str(i), str(i)] for i in range(10)]},
                         'bootstrap_txt_encryption': {'key_hex': key.hex(), 'ordered_replacements': []}}
        hashes = {name: {'sha256': hashlib.sha256(key).hexdigest()} for name in
                  ('play_resolve_gcm', 'general_json_ecb', 'bootstrap_txt_ecb')}
        hashes['request_signature_suffix'] = {'sha256': hashlib.sha256(suffix.encode()).hexdigest()}
        self.status = {'apk_sha256': 'dummy-apk', 'key_material': hashes}

    def test_local_success_is_not_live_success(self):
        report = check(self.material, self.status)
        self.assertTrue(report['offline_checks_passed'])
        for name in ('network_requests_performed', 'production_authentication_verified',
                     'production_playback_verified', 'release_private_key_recovered', 'all_user_goals_completed'):
            self.assertFalse(report[name])
        text = json.dumps(report)
        self.assertNotIn(self.material['response_encryption']['key_hex'], text)
        self.assertNotIn('fixture-suffix-17', text)

    def test_original_release_key_is_not_an_animeko_acceptance_requirement(self):
        report = check(self.material, self.status)
        self.assertFalse(report['release_private_key_required'])
        self.assertTrue(any('source-format' in item for item in report['unresolved_requirements']))
        self.assertFalse(any('keystore/private-key' in item for item in report['unresolved_requirements']))
        self.assertFalse(report['all_user_goals_completed'])

    def test_tampered_material_fails(self):
        material = copy.deepcopy(self.material)
        material['response_encryption']['key_hex'] = 'ff' * 32
        self.assertFalse(check(material, self.status)['offline_checks_passed'])
        material['response_encryption']['key_hex'] = 'private-invalid-hex-marker'
        self.assertFalse(check(material, self.status)['checks']['play_resolve_gcm'])

    def test_missing_sections_fail_closed(self):
        self.assertFalse(check({}, self.status)['offline_checks_passed'])

    def test_provided_empty_dns_is_failure_not_skip(self):
        report = check(self.material, self.status, [])
        self.assertTrue(report['saved_public_bootstrap']['checked'])
        self.assertFalse(report['offline_checks_passed'])

    def test_output_cannot_destroy_private_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'secrets.json'
            original = json.dumps(self.material)
            path.write_text(original)
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/lanerc_check_readiness.py'),
                                     '--secrets', str(path), '--output', str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(path.read_text(), original)
            self.assertNotIn('fixture-suffix-17', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
