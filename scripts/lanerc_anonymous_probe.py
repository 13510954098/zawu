"""Actions-only bounded anonymous read/play-resolution probe. Never solves captchas,
logs in, supplies credentials, or publishes community content. Optional media
metadata probe is explicit and timeout-bounded; no media bytes or URLs are retained.
Only status/counts/classifications and codec/dimension metadata are retained.
"""
import json
import os
import ipaddress
import socket
import subprocess
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


def inspect_hls(url):
    """At most three 64KiB resource prefixes; no URLs or bytes retained."""
    result = {}
    for depth in range(3):
        uri = urllib.parse.urlsplit(url)
        if uri.scheme not in ('http', 'https') or not uri.hostname or uri.username or uri.password:
            raise ValueError('Invalid media destination')
        addresses = socket.getaddrinfo(uri.hostname, uri.port or (443 if uri.scheme == 'https' else 80), type=socket.SOCK_STREAM)
        if not addresses or not all(ipaddress.ip_address(entry[4][0]).is_global for entry in addresses):
            raise ValueError('Non-public media destination')
        request = urllib.request.Request(url, headers={'Range':'bytes=0-65535'})
        try:
            connection = opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            connection = error
        with connection:
            raw = connection.read(65536)
            status = connection.status
            content_type = connection.headers.get('Content-Type', '').split(';')[0][:80]
        if raw.lstrip(b'\xef\xbb\xbf\r\n ').startswith(b'#EXTM3U'):
            text = raw.decode('utf-8', errors='replace')
            entries = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
            result['playlist_http_status'] = status
            result['playlist_entries'] = len(entries)
            result['master_playlist'] = '#EXT-X-STREAM-INF' in text
            methods = re.findall(r'#EXT-X-KEY:METHOD=([A-Z0-9-]+)', text)
            result['encryption_methods'] = sorted({method if method in ('NONE','AES-128','SAMPLE-AES') else 'other' for method in methods})
            result['init_map_present'] = '#EXT-X-MAP' in text
            if not entries:
                return result
            if depth == 2:
                result['depth_limit_reached'] = True
                return result
            url = urllib.parse.urljoin(url, entries[0])
            continue
        result.update(segment_http_status=status, segment_content_type=content_type, segment_prefix_bytes=len(raw),
                      segment_starts_jpeg=raw.startswith(b'\xff\xd8\xff'), segment_starts_png=raw.startswith(b'\x89PNG'),
                      segment_starts_html=raw.lstrip().lower().startswith((b'<!doctype html', b'<html')),
                      segment_starts_mp4=len(raw) >= 8 and raw[4:8] in (b'ftyp', b'styp', b'moof'))
        result['mpegts_sync_offset'] = next((offset for offset in range(min(len(raw), 4096))
            if offset + 188*3 < len(raw) and all(raw[offset + 188*i] == 0x47 for i in range(4))), None)
        return result
    return result


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
                    if os.environ.get('LANERC_PROBE_MEDIA') == '1':
                        if uri.scheme not in ('http', 'https') or not uri.hostname or uri.username or uri.password or uri.fragment:
                            raise ValueError('Invalid media address')
                        addresses = socket.getaddrinfo(uri.hostname, uri.port or (443 if uri.scheme == 'https' else 80), type=socket.SOCK_STREAM)
                        if not addresses or not all(ipaddress.ip_address(entry[4][0]).is_global for entry in addresses):
                            raise ValueError('Non-public media destination')
                        report['media_fetch_attempted'] = True
                        try:
                            head = urllib.request.Request(resolved['playUrl'], method='HEAD')
                            try:
                                connection = opener.open(head, timeout=10)
                            except urllib.error.HTTPError as error:
                                connection = error
                            with connection:
                                item['media_http_status'] = connection.status
                                item['media_content_type'] = connection.headers.get('Content-Type', '').split(';')[0][:80]
                        except Exception as error:
                            item['media_head_error_type'] = type(error).__name__
                        try:
                            item['hls_diagnostics'] = inspect_hls(resolved['playUrl'])
                        except Exception as error:
                            item['hls_diagnostic_error_type'] = type(error).__name__
                        process = subprocess.run(['ffprobe', '-v', 'quiet', '-protocol_whitelist', 'http,https,tcp,tls,crypto',
                            '-rw_timeout', '10000000', '-probesize', '1048576', '-analyzeduration', '2000000',
                            '-read_intervals', '%+1', '-show_entries', 'stream=codec_type,codec_name,width,height:format=format_name,duration',
                            '-of', 'json', resolved['playUrl']], capture_output=True, timeout=25)
                        metadata = json.loads(process.stdout) if process.returncode == 0 else {}
                        report['media_fetched'] = bool(metadata.get('streams'))
                        item['media_streams'] = [{key:stream[key] for key in ('codec_type','codec_name','width','height') if key in stream}
                                                 for stream in metadata.get('streams', [])]
                        item['media_format'] = metadata.get('format', {}).get('format_name')
                        item['media_stream_probe_verified'] = process.returncode == 0 and any(
                            stream.get('codec_type') == 'video' and stream.get('width', 0) > 0 and stream.get('height', 0) > 0
                            and stream.get('codec_name') not in ('mjpeg', 'png', 'gif', 'bmp') for stream in item['media_streams'])
            except Exception as error:
                item['error_type'] = type(error).__name__
            report['requests'].append(item)
    except Exception as error:
        report['error_type'] = type(error).__name__
    finally:
        pathlib.Path('analysis/lanerc/anonymous-play-probe.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    run()
