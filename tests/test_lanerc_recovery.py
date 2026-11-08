import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


crypto = load('lanerc_offline_crypto')
recovery = load('lanerc_recover_material')


class StaticRecoveryTests(unittest.TestCase):
    def fixture(self):
        # Synthetic, public test values only; not recovered application material.
        nibbles = [n for b in range(32) for n in (b >> 4, b & 15)]
        parts = ['List<int>(16) [' + ', '.join(map(str, nibbles[i:i+16])) + ']' for i in range(0, 64, 16)]
        return '[pp+0xe238] List<List<int>>(4) [' + ', '.join(parts) + ']\n[pp+0x11b70] String: "' + 'x' * 17 + '"'

    def test_recovery_nibble_pairs(self):
        material = recovery.recover(self.fixture())
        self.assertEqual(material['response_encryption']['key_hex'], bytes(range(32)).hex())
        self.assertEqual(material['request_signature']['secret_suffix'], 'x' * 17)
        self.assertIsNone(material['release_signing']['private_key'])

    def test_invalid_nibble_rejected(self):
        with self.assertRaises(ValueError):
            recovery.recover(self.fixture().replace('[0, 0,', '[32, 0,', 1))

    def test_signature_format(self):
        import hashlib
        expected = hashlib.md5(b'/app/config@1700000000@abctest-only').hexdigest()
        self.assertEqual(crypto.sign('https://example.invalid/app/config', 1700000000, 'abc', 'test-only'), '1700000000-abc-' + expected)

    def test_invalid_sign_inputs(self):
        for nonce in ['ABc', 'abcd', '', '12a']:
            with self.assertRaises(ValueError):
                crypto.sign('https://example.invalid/', 1700000000, nonce, 'test')
        with self.assertRaises(ValueError):
            crypto.sign('https://example.invalid/', True, 'abc', 'test')

    def test_authenticated_decryption(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.exceptions import InvalidTag
        except ImportError:
            self.skipTest('cryptography is not installed')
        key, nonce, plaintext = bytes(range(32)), bytes(range(12)), b'local-test-only'
        blob = nonce + AESGCM(key).encrypt(nonce, plaintext, None)
        self.assertEqual(crypto.decrypt_envelope(blob, key), plaintext)
        with self.assertRaises(InvalidTag):
            crypto.decrypt_envelope(blob[:-1] + bytes([blob[-1] ^ 1]), key)

    def test_short_envelope_rejected(self):
        try:
            import cryptography
        except ImportError:
            self.skipTest('cryptography is not installed')
        with self.assertRaises(ValueError):
            crypto.decrypt_envelope(b'short', bytes(32))


if __name__ == '__main__':
    unittest.main()
