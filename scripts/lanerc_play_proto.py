"""Bounded offline protobuf parser for the reconstructed playback messages.
No server requests, credential generation, captcha solving, or media fetching.
Original protobuf package/options are unknown. Supports ordinary wire types
0, 1, 2 and 5; groups are intentionally rejected. Limits protect local parsing.
"""
MAX_MESSAGE_BYTES = 16 * 1024 * 1024


def varint(data, position):
    value = 0
    for index in range(10):
        if position >= len(data):
            raise ValueError('Truncated protobuf varint')
        byte = data[position]
        position += 1
        if index == 9 and byte > 1:
            raise ValueError('Protobuf varint exceeds uint64')
        value |= (byte & 127) << (index * 7)
        if byte < 128:
            return value, position
    raise ValueError('Overlong protobuf varint')


def fields(data):
    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError('Protobuf message exceeds offline size limit')
    position = 0
    while position < len(data):
        tag, position = varint(data, position)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number <= (1 << 29) - 1:
            raise ValueError('Invalid protobuf field number')
        if wire == 0:
            value, position = varint(data, position)
        elif wire in (1, 5):
            length = 8 if wire == 1 else 4
            if position + length > len(data):
                raise ValueError('Truncated protobuf fixed-width field')
            value = data[position:position + length]
            position += length
        elif wire == 2:
            length, position = varint(data, position)
            if length > len(data) - position:
                raise ValueError('Truncated protobuf length-delimited field')
            value = data[position:position + length]
            position += length
        else:
            raise ValueError('Unsupported protobuf wire type (groups not supported)')
        yield number, wire, value


def response(data):
    result = {'code': 0, 'msg': '', 'encrypted': False, 'data': b''}
    known = {1: (0, 'code'), 2: (2, 'msg'), 3: (0, 'encrypted'), 4: (2, 'data')}
    for number, wire, value in fields(data):
        if number not in known:
            continue
        expected, name = known[number]
        if wire != expected:
            raise ValueError('Known response field has unexpected wire type')
        if name == 'code':
            value &= 0xffffffff
            value = value - (1 << 32) if value & (1 << 31) else value
        elif name == 'msg':
            value = value.decode('utf-8')
        elif name == 'encrypted':
            value = bool(value)
        result[name] = value
    return result


def play_resolve(data):
    url = ''
    for number, wire, value in fields(data):
        if number == 1:
            if wire != 2:
                raise ValueError('playUrl has unexpected wire type')
            url = value.decode('utf-8')
    return {'playUrl': url}


def decode_play_response(data, key=None):
    outer = response(data)
    if outer['code'] != 200:
        raise ValueError(f"Playback response status is not 200: {outer['code']}")
    payload = outer['data']
    if outer['encrypted']:
        if key is None:
            raise ValueError('Encrypted payload requires the separately provided key')
        from lanerc_offline_crypto import decrypt_envelope
        payload = decrypt_envelope(payload, key)
    url = play_resolve(payload)['playUrl'].strip()
    if not url:
        raise ValueError('Playback response contains no nonempty playUrl')
    return {'code': outer['code'], 'msg': outer['msg'], 'encrypted': outer['encrypted'], 'playUrl': url}


if __name__ == '__main__':
    import argparse
    import json
    import os
    import pathlib
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=pathlib.Path, required=True, help='A local binary PlayResolveResponse fixture')
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--secrets', type=pathlib.Path, help='Private recovery JSON; required only for encrypted payloads')
    args = parser.parse_args()
    key = None
    if args.secrets:
        key = bytes.fromhex(json.loads(args.secrets.read_text())['response_encryption']['key_hex'])
    # Do not echo signed URLs or plaintext server errors to public logs.
    decoded = decode_play_response(args.input.read_bytes(), key)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(decoded, stream, indent=2)
    print('Offline playback fixture decoded; no request or media fetch performed')
