"""No network and no recovered keys: validate the encrypted probe's narrow scope."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
from lanerc_encrypted_probe_runner import validate


class EncryptedProbeScopeTests(unittest.TestCase):
    def request(self, path='/app/v2/guest/captcha'):
        return {'run_id':'7', 'url':'https://v3.yyghk.com'+path+'?sign=1000-abc-'+'0'*32, 'method':'GET', 'body':None}

    def test_only_expected_host_and_tls(self):
        for bad in ['http://v3.yyghk.com', 'https://localhost', 'https://127.0.0.1', 'https://example.invalid', 'https://user:password@v3.yyghk.com', 'https://v3.yyghk.com:8443']:
            payload = self.request()
            payload['url'] = payload['url'].replace('https://v3.yyghk.com', bad)
            with self.assertRaises(ValueError): validate(payload, '7', 1000)

    def test_expired_signature_and_wrong_runner_are_rejected(self):
        with self.assertRaises(ValueError): validate(self.request(), '8', 1000)
        with self.assertRaises(ValueError): validate(self.request(), '7', 1121)

    def test_sensitive_unrelated_endpoints_are_not_allowed(self):
        for path in ['/admin', '/app/login', '/app/delete', '/app/vod/../../admin']:
            with self.assertRaises(ValueError): validate(self.request(path), '7', 1000)

    def test_anonymous_native_reads_are_scoped(self):
        for path in ['/app/v2/guest/captcha','/app/vod/search','/app/vod/37','/app/chat/comment','/app/chat/barragev2']:
            self.assertEqual('GET', validate(self.request(path), '7', 1000)[1])

    def test_no_duplicate_signature_or_unexpected_queries(self):
        for extra in ['&sign=1000-abc-'+'1'*32, '&password=unexpected', '#fragment']:
            payload = self.request()
            payload['url'] += extra
            with self.assertRaises(ValueError): validate(payload, '7', 1000)

    def test_post_is_limited_to_native_guest_fields(self):
        captcha = self.request()
        captcha.update(method='POST', body={})
        self.assertEqual('POST', validate(captcha, '7', 1000)[1])
        p = self.request('/app/v2/guest/credential')
        p.update(method='POST', body={'challenge_id':'public-fixture', 'selected':'0'})
        self.assertEqual('POST', validate(p, '7', 1000)[1])
        p['body']['password'] = 'not-allowed'
        with self.assertRaises(ValueError): validate(p, '7', 1000)

    def test_no_implicit_captcha_guessing_or_other_methods(self):
        p = self.request('/app/v2/guest/credential')
        p.update(method='POST', body={'challenge_id':'public-fixture', 'selected':'guess'})
        with self.assertRaises(ValueError): validate(p, '7', 1000)
        p = self.request()
        p['method'] = 'DELETE'
        with self.assertRaises(ValueError): validate(p, '7', 1000)


if __name__ == '__main__':
    unittest.main()
