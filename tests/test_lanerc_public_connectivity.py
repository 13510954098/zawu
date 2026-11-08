import importlib.util
import pathlib
import socket
import ssl
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lanerc_public_connectivity', ROOT / 'scripts/lanerc_public_connectivity.py')
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


class PublicDiagnosticsTests(unittest.TestCase):
    def test_txt_values_redacted(self):
        import json
        value = diag.summarize_txt({'type': 16, 'TTL': 60, 'data': '"https://v3.yyghk.com/private-path?token=DO_NOT_EXPORT"'})
        self.assertEqual(value['url_hostnames_only'], ['v3.yyghk.com'])
        self.assertNotIn('DO_NOT_EXPORT', json.dumps(value))
        self.assertNotIn('private-path', json.dumps(value))

    def test_private_address_rejected(self):
        with patch.object(socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]):
            with self.assertRaises(ValueError):
                diag.public_addresses('v3.yyghk.com')

    def test_unlisted_host_rejected_without_network(self):
        with self.assertRaises(ValueError):
            diag.https_root_head('example.invalid', None)

    def test_certificate_failure_classification(self):
        self.assertEqual(diag.error_kind(ssl.SSLCertVerificationError('test')), 'certificate-verification-failed')

    def test_timeout_recorded_without_response_values(self):
        class Opener:
            def open(self, request, timeout):
                raise TimeoutError('private diagnostic text')
        value = diag.doh_query('dohx.lanerc.moe', Opener())
        self.assertEqual(value, {'name': 'dohx.lanerc.moe', 'error': 'timeout'})


if __name__ == '__main__':
    unittest.main()
