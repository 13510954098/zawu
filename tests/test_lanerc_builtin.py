"""Public synthetic fixtures only; run on Actions before generating client constants."""
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
from lanerc_generate_builtin import client_material


class ClientMaterialTests(unittest.TestCase):
    def test_only_client_fields_are_selected(self):
        recovered = {
            'response_encryption': {'key_hex': '00'*32, 'token': 'must-not-copy'},
            'request_signature': {'secret_suffix': 'public-fixture', 'password': 'must-not-copy'},
            'json_response_encryption': {'key_hex': '11'*32, 'ordered_replacements': [['a', 'b']], 'guest_credential': 'must-not-copy'},
            'bootstrap_txt_encryption': {'key_hex': '22'*32},
            'account_token': 'must-not-copy', 'release_signing': {'private_key': 'must-not-copy'},
        }
        result = client_material(recovered)
        self.assertEqual(len(result), 4)
        self.assertNotIn('must-not-copy', str(result))
        self.assertEqual(result['request_signature'], {'secret_suffix': 'public-fixture'})
