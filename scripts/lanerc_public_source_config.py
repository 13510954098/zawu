"""Inspect only the two public fallback configuration URLs embedded in the APK.
No signing material, accounts, guest endpoints, cookies or media requests.
Response contents are written only to a temporary private file for CMS encryption.
"""
import argparse
import base64
import hashlib
import json
import os
import urllib.error
import urllib.request

URLS = (
    'http://uminainfo.cc/api.json',
    'https://anime999x-1366475786.cos.ap-guangzhou.myqcloud.com/apis.json',
)
LIMIT = 256 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--private-output', required=True)
    args = parser.parse_args()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    public, private = [], []
    for index, url in enumerate(URLS):
        record = {'configuration_index': index, 'redirects_followed': False,
                  'scope': 'Unsigned public fallback configuration GET', 'transport_tls': url.startswith('https:')}
        raw = None
        try:
            request = urllib.request.Request(url, headers={'Accept': 'application/json', 'User-Agent': 'Lanerc-source-compatibility-audit/1.0'})
            with opener.open(request, timeout=12) as response:
                record['http_status'] = response.status
                raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError('Size limit exceeded')
            record['body_bytes'] = len(raw)
            record['body_sha256'] = hashlib.sha256(raw).hexdigest()
            try:
                parsed = json.loads(raw)
                record['json_root_type'] = type(parsed).__name__
                record['json_valid'] = True
            except (ValueError, UnicodeError):
                record['json_valid'] = False
            private.append({'configuration_index': index, 'body_base64': base64.b64encode(raw).decode()})
        except urllib.error.HTTPError as error:
            record['http_status'] = error.code
            record['error_type'] = 'HTTPError'
        except Exception as error:
            record['error_type'] = type(error).__name__
        public.append(record)
    for path, value in ((args.output, {'production_authentication_attempted': False, 'records': public}),
                        (args.private_output, private)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')


if __name__ == '__main__':
    main()
