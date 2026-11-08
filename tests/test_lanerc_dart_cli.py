"""Exercise the usable Dart signing CLI with public dummy secrets only."""
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from urllib.parse import urlsplit, parse_qs

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('dart'), 'Dart SDK required for CLI integration checks')
class DartSigningCliTests(unittest.TestCase):
    def invoke(self, request, suffix='fixture-suffix-17'):
        with tempfile.TemporaryDirectory() as directory:
            request_path = pathlib.Path(directory) / 'request.json'
            material_path = pathlib.Path(directory) / 'material.json'
            request_path.write_text(json.dumps(request))
            material_path.write_text(json.dumps({'request_signature': {'secret_suffix': suffix}}))
            return subprocess.run(
                ['dart', 'run', 'bin/sign_offline.dart', str(request_path), str(material_path)],
                cwd=ROOT / 'reference/lanerc', capture_output=True, text=True, timeout=60,
            )

    def test_seven_uri_cases(self):
        fixtures = json.loads((ROOT / 'analysis/lanerc/dart-reference-fixtures.json').read_text())
        for case in fixtures['uriSignatures']:
            with self.subTest(case=case['name']):
                result = self.invoke({
                    'baseUrl': case['baseUrl'], 'path': case['path'],
                    'queryParameters': case['query'], 'timestamp': case['timestamp'], 'nonce': case['nonce'],
                }, case['syntheticSuffix'])
                self.assertEqual(result.returncode, 0, result.stderr)
                output = json.loads(result.stdout)
                self.assertEqual(output['canonicalUriBeforeSign'], case['canonicalUri'])
                self.assertEqual(output['queryParameterValue'], case['sign'])
                self.assertEqual(parse_qs(urlsplit(output['signedUri']).query)['sign'], [case['sign']])
                self.assertFalse(output['networkRequestPerformed'])
                self.assertNotIn(case['syntheticSuffix'], result.stdout + result.stderr)

    def test_existing_signature_rejected(self):
        request = {'baseUrl': 'https://example.invalid/', 'path': 'x?%73ign=old',
                   'timestamp': 1700000000, 'nonce': 'abc'}
        result = self.invoke(request)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('fixture-suffix-17', result.stderr)

    def test_invalid_nonce_rejected_without_input_disclosure(self):
        result = self.invoke({'baseUrl': 'https://example.invalid/', 'path': 'private-input-marker',
                              'timestamp': 1700000000, 'nonce': 'ABC'})
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('private-input-marker', result.stdout + result.stderr)
        self.assertNotIn('fixture-suffix-17', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
