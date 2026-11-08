#!/usr/bin/env python3
"""Runner-side bounded native API probe. Never receives client signing/AES keys.
Requests are CMS-encrypted to an ephemeral runner key. Responses are CMS-encrypted
to the existing analysis recipient; only status/size/hash metadata is published.
"""
import base64
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

BRANCH = 'arena/44f5d2ee-zawu'
HOST = 'v3.yyghk.com'
REPOSITORY = '13510954098/zawu'
LIMIT = 4 * 1024 * 1024
GETS = {'/app/health', '/app/v2/guest/captcha', '/app/vod/search', '/app/chat/comment', '/app/chat/barragev2'}
POSTS = {'/app/v2/guest/captcha': set(), '/app/v2/guest/credential': {'challenge_id', 'selected'}, '/app/v2/guest/play': {'resource_id', 'guest_credential'}}


def validate(payload, run, now):
    if not isinstance(payload, dict) or set(payload) - {'run_id', 'url', 'method', 'body'}:
        raise ValueError('Unexpected encrypted request fields')
    if str(payload.get('run_id')) != str(run):
        raise ValueError('Wrong runner session')
    url = payload['url']
    if not isinstance(url, str) or len(url) > 16384 or any(ord(c) < 32 for c in url):
        raise ValueError('Invalid URL')
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname != HOST or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Unexpected probe origin')
    method = payload.get('method', 'GET')
    body = payload.get('body')
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    signatures = query.get('sign', [])
    if len(signatures) != 1 or not re.fullmatch(r'\d+-[a-z]{3}-[a-f0-9]{32}', signatures[0]):
        raise ValueError('Expected one precomputed native signature')
    if abs(int(signatures[0].split('-')[0]) - now) > 120:
        raise ValueError('Expired probe request')
    if method == 'GET':
        if parsed.path not in GETS and not re.fullmatch(r'/app/v2/vod/[A-Za-z0-9_-]{1,128}', parsed.path):
            raise ValueError('Endpoint not allowed')
        if body is not None:
            raise ValueError('GET body not allowed')
        if set(query) - {'sign', 'keyword', 'vid', 'vod', 'page'}:
            raise ValueError('Unexpected query field')
    elif method == 'POST':
        if parsed.path not in POSTS or set(query) != {'sign'} or not isinstance(body, dict) or set(body) != POSTS[parsed.path]:
            raise ValueError('Unexpected POST endpoint or fields')
        if not all(isinstance(v, str) and 0 < len(v) <= 16384 for v in body.values()):
            raise ValueError('Invalid native POST value')
        if 'selected' in body and not re.fullmatch(r'\d{1,3}', body['selected']):
            raise ValueError('Explicit captcha selection required')
    else:
        raise ValueError('Unexpected method')
    return parsed, method, body, query


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(payload, run):
    parsed, method, body, query = validate(payload, run, int(time.time()))
    addresses = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
    if not addresses or not all(ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise ValueError('Non-public target address')
    request = urllib.request.Request(payload['url'], method=method,
        data=None if body is None else json.dumps(body, separators=(',', ':')).encode(),
        headers={'Accept':'application/x-protobuf' if parsed.path.endswith('/play') else 'application/json',
                 'Content-Type':'application/json', 'User-Agent':'Lanerc-compatibility-audit/1.0'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError('Response size limit')
        status = response.code
        content_type = response.headers.get('Content-Type', '')
    private = {'status':status, 'content_type':content_type, 'body_base64':base64.b64encode(raw).decode()}
    public = {'method':method, 'path':parsed.path, 'query_fields':sorted(query),
              'body_fields':sorted(body or {}), 'http_status':status, 'body_bytes':len(raw),
              'body_sha256':hashlib.sha256(raw).hexdigest(), 'client_keys_supplied_to_runner':False}
    return private, public


def publish(paths, message):
    subprocess.run(['git','config','user.name','github-actions[bot]'], check=True)
    subprocess.run(['git','config','user.email','41898282+github-actions[bot]@users.noreply.github.com'], check=True)
    subprocess.run(['git','add',*map(str, paths)], check=True)
    subprocess.run(['git','commit','-m',message], check=True, stdout=subprocess.DEVNULL)
    for _ in range(3):
        subprocess.run(['git','pull','--rebase','-X','theirs','origin',BRANCH], check=True, stdout=subprocess.DEVNULL)
        if subprocess.run(['git','push','origin',BRANCH], stdout=subprocess.DEVNULL).returncode == 0:
            return
    raise RuntimeError('Could not publish probe evidence')


def read_request(path):
    result = subprocess.run(['gh','api',f'repos/{REPOSITORY}/contents/{path}', '--method','GET','-f',f'ref={BRANCH}'], capture_output=True, text=True)
    if result.returncode:
        return None
    return base64.b64decode(json.loads(result.stdout)['content'])


def main():
    assert os.environ['GITHUB_REPOSITORY'] == REPOSITORY
    run = os.environ['GITHUB_RUN_ID']
    recipient = pathlib.Path(os.environ.get('LANERC_PROBE_RECIPIENT', 'analysis/lanerc/analysis-recipient.pem'))
    if recipient.parent != pathlib.Path('analysis/lanerc') or recipient.suffix != '.pem':
        raise ValueError('Invalid local public recipient path')
    directory = pathlib.Path('analysis/lanerc/native-probe') / run
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        tmp = pathlib.Path(temporary)
        key = tmp / 'runner-key.pem'
        cert = directory / 'runner.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj',f'/CN=Lanerc-probe-{run}'], check=True, capture_output=True)
        publish([cert], 'Publish ephemeral public recipient for encrypted native probe requests')
        for number in range(1, 8):
            request_path = directory / f'request-{number:02d}.p7m'
            deadline = time.monotonic() + 180
            encrypted = None
            while time.monotonic() < deadline:
                encrypted = read_request(request_path)
                if encrypted is not None:
                    break
                time.sleep(3)
            if encrypted is None:
                return
            sealed = tmp / 'request.p7m'
            sealed.write_bytes(encrypted)
            try:
                decoded = subprocess.run(['openssl','cms','-decrypt','-binary','-inform','DER','-in',str(sealed),'-recip',str(cert),'-inkey',str(key)], check=True, capture_output=True).stdout
                private, public = fetch(json.loads(decoded), run)
            except Exception as error:
                private = {'probe_error_type':type(error).__name__}
                public = {'probe_error_type':type(error).__name__, 'client_keys_supplied_to_runner':False}
            plaintext = tmp / 'response.json'
            plaintext.write_text(json.dumps(private))
            os.chmod(plaintext, 0o600)
            response = directory / f'response-{number:02d}.p7m'
            subprocess.run(['openssl','cms','-encrypt','-binary','-aes-256-cbc','-in',str(plaintext),'-outform','DER','-out',str(response),str(recipient)], check=True, capture_output=True)
            record = directory / f'response-{number:02d}.json'
            record.write_text(json.dumps({'run_id':run, 'request':number, 'recipient_certificate_sha256':hashlib.sha256(recipient.read_bytes()).hexdigest(), **public}, indent=2)+'\n')
            publish([response, record], 'Record encrypted native probe response and non-secret transport metadata')


if __name__ == '__main__':
    main()
