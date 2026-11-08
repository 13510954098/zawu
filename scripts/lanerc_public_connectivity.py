"""Read-only public DNS/HTTPS diagnostics. Never uses recovered key material.
Only user-named domains are probed. No captcha, credential or playback requests.
TXT records are untrusted: raw values/query strings are not exported or fetched.
"""
import argparse
import datetime
import hashlib
import ipaddress
import json
import pathlib
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

USER_HOSTS = ('dohx.lanerc.moe', 'v3.yyghk.com')
MAX_BODY = 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def error_kind(error):
    if isinstance(error, urllib.error.HTTPError):
        return 'http-error'
    reason = getattr(error, 'reason', error)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return 'certificate-verification-failed'
    if isinstance(reason, ssl.SSLError):
        return 'tls-error'
    if isinstance(reason, socket.gaierror):
        return 'dns-resolution-failed'
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return 'timeout'
    return type(reason).__name__


def summarize_txt(answer):
    # DoH returns quoted TXT chunks; never log the raw value.
    raw = str(answer.get('data', ''))
    tokens = re.findall(r'https?://[^\s"<>]+', raw)
    hosts = []
    for token in tokens:
        try:
            parsed = urllib.parse.urlsplit(token)
            host = parsed.hostname
            if host and re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', host):
                hosts.append(host.lower())
        except ValueError:
            pass
    return {
        'record_type': answer.get('type'), 'ttl': answer.get('TTL'),
        'text_length': len(raw), 'text_sha256': hashlib.sha256(raw.encode()).hexdigest(),
        'url_hostnames_only': sorted(set(hosts)),
    }


def doh_query(name, opener):
    url = 'https://dns.google/resolve?' + urllib.parse.urlencode({'name': name, 'type': 'TXT'})
    request = urllib.request.Request(url, headers={'Accept': 'application/dns-json', 'User-Agent': 'Lanerc-owner-public-diagnostics/1.0'})
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError('response-size-limit')
        payload = json.loads(body)
        answers = payload.get('Answer') or []
        return {'name': name, 'dns_status': payload.get('Status'),
                'authenticated_data': payload.get('AD'),
                'txt_records': [summarize_txt(a) for a in answers if a.get('type') == 16],
                'other_record_count': sum(a.get('type') != 16 for a in answers)}
    except Exception as error:
        return {'name': name, 'error': error_kind(error)}


def public_addresses(host):
    addresses = sorted({info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError('non-public-address-rejected')
    return addresses


def https_root_head(host, opener):
    if host not in USER_HOSTS:
        raise ValueError('Host not explicitly named by user')
    result = {'host': host, 'method': 'HEAD', 'path': '/', 'redirects_followed': False}
    try:
        # Check public addresses first. Requests still use standard TLS/SNI and certificate verification.
        result['resolved_public_addresses'] = public_addresses(host)
        request = urllib.request.Request('https://' + host + '/', method='HEAD', headers={'User-Agent': 'Lanerc-owner-public-diagnostics/1.0'})
        try:
            response = opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result['http_status'] = response.code
            result['content_type'] = response.headers.get_content_type()
            location = response.headers.get('Location')
            if location:
                try:
                    result['redirect_host_only'] = urllib.parse.urlsplit(urllib.parse.urljoin('https://' + host + '/', location)).hostname
                except ValueError:
                    result['redirect_host_only'] = '<invalid>'
    except Exception as error:
        result['error'] = error_kind(error)
    return result


def probe():
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    prefix = 'diag-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')
    queries = [doh_query(name, opener) for name in ('dohx.lanerc.moe', prefix + '.dohx.lanerc.moe')]
    return {
        'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'Public DNS TXT and unsigned HTTPS HEAD / only',
        'recovered_keys_used': False, 'credentials_requested': False,
        'captcha_requested_or_solved': False, 'media_or_playback_requested': False,
        'dns': queries, 'https': [https_root_head(host, opener) for host in USER_HOSTS],
        'limitations': 'Public records/root reachability do not prove ownership, API identity, credentials, current media availability or end-to-end compatibility. TXT raw values are redacted and never fetched.',
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(probe(), indent=2) + '\n')
    print('Public diagnostics finished; no recovered keys or guest/playback requests used')
