"""Actions-only bounded anonymous read/play-resolution probe. Never solves captchas,
logs in, supplies credentials, fetches media, or publishes community content.
Only response status/counts/boolean classifications are retained.
"""
import json
import pathlib
import re
import secrets
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from lanerc_offline_crypto import decrypt_json_transport, sign
from lanerc_play_proto import response, decode_play_response


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(NoRedirect())


def fetch(url, body=None, protobuf=False, timeout=12):
    headers = {'Accept': 'application/x-protobuf' if protobuf else 'application/json', 'User-Agent': 'Dart/3.9 (dart:io)'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        connection = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        connection = error
    with connection:
        raw = connection.read(2*1024*1024 + 1)
        if len(raw) > 2*1024*1024:
            raise ValueError('Response size limit')
        return connection.status, raw


def load_material():
    source = pathlib.Path('integration/animeko/overlay/app/shared/app-data/src/commonMain/kotlin/domain/mediasource/lanerc/core/LanercBuiltInMaterial.kt').read_text()
    match = re.search(r'const val RAW = """(.*?)"""', source, re.S)
    return json.loads(match[1].replace("${'$'}", '$'))


def discover(material):
    for domain in ('dohx.lanerc.moe', 'doh.lanercdns1.cc', 'doh.uminadns2.cc'):
        for provider in ('https://dns.google/resolve', 'https://doh.pub/resolve', 'https://dns.alidns.com/resolve'):
            try:
                status, raw = fetch(provider + '?' + urllib.parse.urlencode({'name':domain, 'type':'TXT'}), timeout=4)
                if status != 200:
                    continue
                for answer in json.loads(raw).get('Answer', []):
                    if answer.get('type') != 16:
                        continue
                    parts = re.findall(r'"([^"\\]*)"', answer['data'])
                    encoded = ''.join(parts) if parts else answer['data']
                    plain = decrypt_json_transport(encoded, dict(material['bootstrap_txt_encryption'], ordered_replacements=[])).decode()
                    uri = urllib.parse.urlsplit(plain)
                    if uri.scheme == 'https' and uri.hostname and not uri.username and not uri.password and not uri.fragment:
                        return plain.rstrip('/') + '/'
            except Exception:
                continue
    raise ValueError('No valid HTTPS backend discovered')


def run():
    report = {'scope':'Anonymous Actions-network probe with no account, device identity or guest credential; not an original-device first-play trace',
              'source_commit': __import__('os').environ['GITHUB_SHA'], 'credentials_used':False, 'captcha_solved':False,
              'media_fetched':False, 'production_playback_verified':False, 'requests':[]}
    try:
        material = load_material()
        backend = discover(material)
        report['dynamic_discovery_succeeded'] = True
        def request(path, query=None, body=None, protobuf=False):
            url = urllib.parse.urljoin(backend, path)
            parameters = dict(query or {})
            nonce = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(3))
            parameters['sign'] = sign(url, int(time.time()), nonce, material['request_signature']['secret_suffix'])
            return fetch(url + '?' + urllib.parse.urlencode(parameters), body, protobuf)
        def decoded(raw):
            root = json.loads(raw)
            if isinstance(root, str):
                root = json.loads(decrypt_json_transport(root, material['json_response_encryption']))
            if isinstance(root, dict) and isinstance(root.get('data'), str):
                value = root['data']
                root['data'] = json.loads(value) if value.lstrip().startswith(('{', '[')) else json.loads(decrypt_json_transport(value, material['json_response_encryption']))
            return root
        status, raw = request('app/vod/search', {'keyword':'海贼王'})
        root = decoded(raw)
        entries = root.get('data', {}).get('search_vods', [])
        report['requests'].append({'operation':'search', 'http_status':status, 'code':root.get('code'), 'result_count':len(entries)})
        if not entries:
            raise ValueError('No native search results')
        native_id = str(entries[0]['id'])
        if not re.fullmatch('[A-Za-z0-9_-]{1,128}', native_id):
            raise ValueError('Invalid native identity')
        status, raw = request('app/v2/vod/' + native_id)
        root = decoded(raw)
        lines = root.get('data', {}).get('video_play_list', [])
        report['requests'].append({'operation':'detail', 'http_status':status, 'code':root.get('code'), 'line_count':len(lines)})
        resource = next(episode['resource_id'] for line in lines for episode in line.get('video', []))
        if not isinstance(resource, str) or not re.fullmatch('[A-Za-z0-9_-]{1,4096}', resource):
            raise ValueError('Invalid resource identity')
        for endpoint in ('app/v2/play', 'app/v2/guest/play'):
            item = {'operation':endpoint, 'credential_omitted':True}
            try:
                status, raw = request(endpoint, body={'resource_id':resource}, protobuf=True)
                item['http_status'] = status
                try:
                    outer = response(raw)
                    item['format'] = 'protobuf'
                except Exception:
                    outer = json.loads(raw)
                    item['format'] = 'json'
                item['code'] = outer.get('code')
                message = str(outer.get('msg', '')).lower()
                item['verification_mentioned'] = any(word in message for word in ('验证码', '验证', 'captcha', 'challenge'))
                item['login_mentioned'] = any(word in message for word in ('登录', 'login'))
                if item['format'] == 'protobuf' and outer.get('code') == 200:
                    resolved = decode_play_response(raw, bytes.fromhex(material['response_encryption']['key_hex']))
                    uri = urllib.parse.urlsplit(resolved['playUrl'])
                    item['https_media_url_returned'] = uri.scheme == 'https'
                    item['url_scheme'] = uri.scheme if uri.scheme in ('http', 'https', 'magnet') else 'other'
                    item['network_host_present'] = bool(uri.hostname)
                    item['userinfo_present'] = bool(uri.username or uri.password)
            except Exception as error:
                item['error_type'] = type(error).__name__
            report['requests'].append(item)
    except Exception as error:
        report['error_type'] = type(error).__name__
    finally:
        pathlib.Path('analysis/lanerc/anonymous-play-probe.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    run()
