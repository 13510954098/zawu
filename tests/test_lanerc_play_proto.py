import base64
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import lanerc_play_proto as proto
import lanerc_offline_crypto as crypto


def vint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def ld(number, value):
    return vint((number << 3) | 2) + vint(len(value)) + value


def envelope(payload, encrypted=False, status=200):
    return b'\x08' + vint(status) + b'\x18' + vint(int(encrypted)) + ld(4, payload)


class PlaybackWireTests(unittest.TestCase):
    def test_plain_response(self):
        payload = ld(1, b'https://example.invalid/test.m3u8')
        result = proto.decode_play_response(envelope(payload))
        self.assertFalse(result['encrypted'])
        self.assertEqual(result['playUrl'], 'https://example.invalid/test.m3u8')

    def test_unknown_fields_and_last_singular_value(self):
        payload = ld(9, b'unknown') + ld(1, b'first') + ld(1, b'last')
        self.assertEqual(proto.play_resolve(payload), {'playUrl': 'last'})

    def test_truncation_and_invalid_tags(self):
        for payload in [b'\x00', b'\x80', b'\x0a\x09abc', b'\x09abc', b'\x0dabc', b'\x0b', b'\x08' + b'\xff' * 10]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                list(proto.fields(payload))

    def test_failure_and_empty_url(self):
        for data in [envelope(b'', status=403), envelope(b''), b'\x0a\x01x']:
            with self.assertRaises(ValueError):
                proto.decode_play_response(data)

    def test_signed_int32_status(self):
        result = proto.response(b'\x08' + vint((1 << 64) - 1))
        self.assertEqual(result['code'], -1)

    def test_encrypted_response(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.exceptions import InvalidTag
        except ImportError:
            self.skipTest('cryptography not installed')
        key, nonce = bytes(range(32)), bytes(range(12))
        inner = ld(1, b'https://example.invalid/local-fixture')
        blob = nonce + AESGCM(key).encrypt(nonce, inner, None)
        encoded = envelope(blob, encrypted=True)
        self.assertEqual(proto.decode_play_response(encoded, key)['playUrl'], 'https://example.invalid/local-fixture')
        with self.assertRaises(ValueError):
            proto.decode_play_response(encoded)
        with self.assertRaises(InvalidTag):
            proto.decode_play_response(envelope(blob[:-1] + bytes([blob[-1] ^ 1]), True), key)

    def test_ecb_transport_fixture(self):
        try:
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            self.skipTest('cryptography not installed')
        key = bytes(range(32))
        plain = b'{"fixture":true}'
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        encoded = base64.b64encode(cipher.update(padded) + cipher.finalize()).decode()
        material = {'key_hex': key.hex(), 'ordered_replacements': []}
        self.assertEqual(crypto.decrypt_json_transport(encoded, material), plain)
        with self.assertRaises(ValueError):
            crypto.decrypt_json_transport('not base64', material)


if __name__ == '__main__':
    unittest.main()
