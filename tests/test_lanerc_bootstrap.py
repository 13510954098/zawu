import base64
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import lanerc_validate_bootstrap as bootstrap


class BootstrapDecodeTests(unittest.TestCase):
    def fixture(self, plaintext):
        try:
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            self.skipTest('cryptography not installed')
        key = bytes(range(32))
        pad = padding.PKCS7(128).padder()
        value = pad.update(plaintext.encode()) + pad.finalize()
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        encoded = base64.b64encode(enc.update(value) + enc.finalize()).decode()
        records = [{'name': 'example.invalid', 'response': {'Answer': [{'type': 16, 'data': '"' + encoded + '"'}]}}]
        return records, {'key_hex': key.hex(), 'ordered_replacements': []}

    def test_expected_host_and_no_sensitive_url_export(self):
        records, material = self.fixture('https://example.invalid/private-path?token=DO_NOT_EXPORT')
        result = bootstrap.validate(records, material, 'example.invalid')
        self.assertEqual(result['matching_txt_record_count'], 1)
        self.assertNotIn('DO_NOT_EXPORT', json.dumps(result))
        self.assertNotIn('private-path', json.dumps(result))

    def test_other_host_not_accepted_as_success(self):
        records, material = self.fixture('https://other.invalid/')
        self.assertEqual(bootstrap.validate(records, material, 'example.invalid')['matching_txt_record_count'], 0)

    def test_embedded_credentials_rejected(self):
        records, material = self.fixture('https://user:DO_NOT_EXPORT@example.invalid/')
        result = bootstrap.validate(records, material, 'example.invalid')
        self.assertEqual(result['matching_txt_record_count'], 0)
        self.assertNotIn('DO_NOT_EXPORT', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
