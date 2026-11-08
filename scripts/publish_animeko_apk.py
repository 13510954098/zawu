#!/usr/bin/env python3
"""Publish one compiled arm64 APK, refusing mismatched or unproven build artifacts."""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = '13510954098/zawu'
BRANCH = 'arena/44f5d2ee-zawu'


def gh(path):
    return json.loads(subprocess.check_output(['gh', 'api', path], text=True))


def validate_apk(path):
    if not 1_000_000 < path.stat().st_size < 100_000_000:
        raise ValueError('APK outside expected delivery size')
    with zipfile.ZipFile(path) as apk:
        names = set(apk.namelist())
        if not {'AndroidManifest.xml', 'classes.dex'}.issubset(names):
            raise ValueError('Missing APK manifest or code')
        if not any(name.startswith('lib/arm64-v8a/') for name in names):
            raise ValueError('Missing arm64 native libraries')
        if apk.testzip() is not None:
            raise ValueError('Corrupted APK ZIP')
    # Detailed install/signature and runtime checks remain separate, not implied by ZIP validation.
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=int)
    parser.add_argument('--artifacts', required=True, type=pathlib.Path)
    args = parser.parse_args()
    run = gh(f'repos/{REPOSITORY}/actions/runs/{args.run}')
    if run['head_branch'] != BRANCH or run['name'] != 'Animeko Lanerc Android integration build':
        raise ValueError('Unexpected build identity')
    jobs = gh(f'repos/{REPOSITORY}/actions/runs/{args.run}/jobs?per_page=100')['jobs']
    required = {'Compile and package the Android integration without private production material',
                'Save APK and build provenance', 'Run actions/upload-artifact@v4'}
    if not any(required.issubset({s['name'] for s in j['steps'] if s['conclusion'] == 'success'}) for j in jobs):
        raise ValueError('Compilation, packaging and upload must all have succeeded')
    apk = args.artifacts / 'android-default-arm64-v8a-debug.apk'
    digest = validate_apk(apk)
    from apkutils2 import APK
    manifest = APK(str(apk)).get_manifest()
    application_id = manifest.get('@package')
    if application_id != 'me.him188.ani.lanerc.debug2':
        raise ValueError('Unexpected compiled APK application ID')
    sdk = manifest.get('uses-sdk', {})
    destination = ROOT / 'downloads/animeko'
    destination.mkdir(parents=True, exist_ok=True)
    filename = 'animeko-lanerc-arm64-debug.apk'
    shutil.copyfile(apk, destination / filename)
    (destination / 'SHA256SUMS').write_text(f'{digest}  {filename}\n')
    report = {
        'source_commit': run['head_sha'], 'build_run': args.run, 'build_url': run['html_url'],
        'upstream_commit': '6d79729a135cee6af861a7a095d3880d1b452260',
        'android_app_built': True, 'ui_compiled': True, 'ui_device_tested': False,
        'application_id': application_id, 'base_application_id': 'me.him188.ani.lanerc',
        'version_name': manifest.get('@android:versionName'), 'min_sdk': sdk.get('@android:minSdkVersion'),
        'target_sdk': sdk.get('@android:targetSdkVersion'), 'build_type': 'defaultDebug',
        'private_production_material_embedded': False, 'original_source_import_verified': False,
        'production_playback_verified': False,
        'apk_files': [{'name': filename, 'sha256': digest, 'bytes': apk.stat().st_size}],
    }
    (ROOT / 'analysis/lanerc/animeko-android-validation.json').write_text(json.dumps(report, indent=2) + '\n')
    (destination / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    (destination / 'README.md').write_text(f'''# Animeko + Lanerc Android debug build

APK: `{filename}` (arm64-v8a, independent installed application ID `{application_id}`; Android 8.1 / API 27 or later).

Build: {run['html_url']}\nSource: `{run['head_sha']}`\nSHA256: `{digest}`

This is a compiled integration preview, **not a verified production-ready release**.
No recovered production keys or guest credentials are embedded. Configure private
protocol material inside the app; the default build does not bypass server login.
Original-format source import is partial. Lanerc comments/danmaku currently have
read-only protocol DTOs, not a complete player integration. No device test or
successful production playback is claimed. Debug APKs use the CI-generated debug
key; later builds may require uninstalling first, which removes app data.

Verify download: `sha256sum -c SHA256SUMS`.

The host and modifications are AGPL-3.0; see `integration/animeko/LICENSE.txt`,
`integration/animeko/upstream.json`, the pinned public upstream and repository overlay
for the corresponding source and build instructions.
''')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
