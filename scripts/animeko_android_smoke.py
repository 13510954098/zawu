"""Actions-only Android emulator smoke check. No login, captcha solving or publication."""
import hashlib
import json
import os
import pathlib
import subprocess
import xml.etree.ElementTree as ET

PACKAGE = 'me.him188.ani.lanerc.debug2'
OUTPUT = pathlib.Path('/tmp/lanerc-app-smoke')


def adb(*args):
    return subprocess.check_output(['adb', *args], text=True).strip()


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    report = {'source_commit': os.environ['GITHUB_SHA'], 'scope': 'Fresh-install and initial UI launch on API30 x86_64 emulator only',
              'application_id': PACKAGE, 'install_verified': False, 'launch_verified': False,
              'arm64_code_apk_device_verified': False, 'production_playback_verified': False,
              'production_account_login_verified': False, 'production_publication_verified': False}
    try:
        apks = sorted(pathlib.Path('.local/animeko/worktree/app/android/build/outputs/apk').rglob('*x86_64*debug.apk'))
        if len(apks) != 1:
            raise ValueError('Expected exactly one x86_64 debug APK')
        apk = apks[0]
        with apk.open('rb') as source:
            report['apk_sha256'] = hashlib.file_digest(source, 'sha256').hexdigest()
        install = adb('install', '-r', str(apk))
        if 'Success' not in install:
            raise RuntimeError('APK installation did not succeed')
        report['install_verified'] = True
        adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
        adb('shell', 'wm', 'dismiss-keyguard')
        activity = adb('shell', 'cmd', 'package', 'resolve-activity', '--brief', PACKAGE).splitlines()[-1]
        if not activity.startswith(PACKAGE + '/'):
            raise RuntimeError('Unexpected launcher activity')
        adb('logcat', '-c')
        launch = adb('shell', 'am', 'start', '-W', '-n', activity)
        if 'Status: ok' not in launch:
            raise RuntimeError('Activity launch not acknowledged')
        adb('shell', 'uiautomator', 'dump', '/sdcard/lanerc-smoke.xml')
        subprocess.run(['adb', 'pull', '/sdcard/lanerc-smoke.xml', str(OUTPUT / 'ui.xml')], check=True)
        packages = {node.get('package') for node in ET.parse(OUTPUT / 'ui.xml').getroot().iter('node')}
        if PACKAGE not in packages or not adb('shell', 'pidof', PACKAGE):
            raise RuntimeError('Application UI or process absent after initial idle')
        foreground = adb('shell', 'dumpsys', 'activity', 'activities')
        if not any(PACKAGE in line and ('mResumedActivity' in line or 'topResumedActivity' in line) for line in foreground.splitlines()):
            raise RuntimeError('Application did not remain foreground')
        report['launch_verified'] = True
        with (OUTPUT / 'startup.png').open('wb') as image:
            subprocess.run(['adb', 'exec-out', 'screencap', '-p'], stdout=image, check=True)
    except Exception as error:
        report['error_type'] = type(error).__name__
        raise
    finally:
        # Fresh emulator only; no account input or production material is ever provided.
        try:
            (OUTPUT / 'startup-log.txt').write_text(adb('logcat', '-d', '-t', '250'))
        finally:
            (OUTPUT / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
