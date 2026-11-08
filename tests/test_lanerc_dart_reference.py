"""Cross-check against synthetic fixtures produced by independent Dart libraries.
These fixtures do not come from executing the original APK or a production API.
"""
import base64
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import lanerc_offline_crypto as crypto
import lanerc_play_proto as proto


class DartLibraryReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'analysis/lanerc/dart-reference-fixtures.json'
        if not path.exists():
            raise unittest.SkipTest('Run the independent Dart fixture generator first')
        try:
            import cryptography
        except ImportError:
            raise unittest.SkipTest('cryptography is required')
        cls.fixture = json.loads(path.read_text())
        cls.key = bytes.fromhex(cls.fixture['syntheticKeyHex'])

    def test_fixture_is_public_synthetic_material(self):
        self.assertEqual(self.key, bytes(range(32)))
        self.assertEqual(self.fixture['dartVersion'], '3.9.2')
        self.assertFalse(self.fixture['apkLibraryVersionsConfirmed'])

    def test_dart_gcm_payload_decrypts_in_python(self):
        gcm = self.fixture['gcm']
        actual = crypto.decrypt_envelope(base64.b64decode(gcm['encryptedEnvelopeBase64']), self.key)
        self.assertEqual(actual, base64.b64decode(gcm['plaintextProtoBase64']))

    def test_dart_play_response_decodes_in_python(self):
        gcm = self.fixture['gcm']
        actual = proto.decode_play_response(base64.b64decode(gcm['responseProtoBase64']), self.key)
        self.assertEqual(actual['playUrl'], gcm['expectedPlayUrl'])
        self.assertTrue(actual['encrypted'])

    def test_dart_ecb_pkcs7_utf8_decrypts_in_python(self):
        ecb = self.fixture['ecb']
        material = {'key_hex': self.key.hex(), 'ordered_replacements': []}
        actual = crypto.decrypt_json_transport(ecb['ciphertextBase64'], material)
        self.assertEqual(actual.decode('utf-8'), ecb['expectedPlaintext'])

    def test_md5_signatures_for_dio_canonical_uris(self):
        self.assertEqual(len(self.fixture['uriSignatures']), 7)
        for case in self.fixture['uriSignatures']:
            with self.subTest(case=case['name']):
                self.assertEqual(crypto.sign(case['canonicalUri'], case['timestamp'], case['nonce'], case['syntheticSuffix']), case['sign'])


if __name__ == '__main__':
    unittest.main()
