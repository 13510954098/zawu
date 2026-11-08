"""Generate shared CLIENT protocol constants from the checksum-verified original APK.
Never includes account tokens, passwords, guest credentials, or captured responses.
Run only on Actions after the pinned APK/AOT checks.
"""
import json
import pathlib
import sys
from lanerc_recover_material import recover


def client_material(recovered):
    return {
        'response_encryption': {'key_hex': recovered['response_encryption']['key_hex']},
        'request_signature': {'secret_suffix': recovered['request_signature']['secret_suffix']},
        'json_response_encryption': {
            'key_hex': recovered['json_response_encryption']['key_hex'],
            'ordered_replacements': recovered['json_response_encryption']['ordered_replacements'],
        },
        'bootstrap_txt_encryption': {'key_hex': recovered['bootstrap_txt_encryption']['key_hex']},
    }


if __name__ == '__main__':
    pool, output = map(pathlib.Path, sys.argv[1:])
    material = client_material(recover(pool.read_text()))
    raw = json.dumps(material, separators=(',', ':'), ensure_ascii=True)
    # Kotlin raw strings still interpolate dollar signs.
    raw = raw.replace('$', "${'$'}")
    output.write_text('// SPDX-License-Identifier: AGPL-3.0-only\n'
        'package me.him188.ani.app.domain.mediasource.lanerc.core\n\n'
        '/** Shared original-APK client constants, NOT user authentication credentials. */\n'
        'internal object LanercBuiltInMaterial {\n'
        '    const val VERSION = "original-apk-4368de63-v1"\n'
        '    const val RAW = """' + raw + '"""\n}\n')
    print('Generated client-only protocol constants; no values printed')
