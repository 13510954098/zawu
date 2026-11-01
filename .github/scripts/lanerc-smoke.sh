#!/usr/bin/env bash
# Runs inside a disposable, unauthenticated Android emulator. The caller verifies the APK hash.
set -uo pipefail

api_level="${1:-unknown}"
pkg='com.clggjv.xcjfmd.ffo'
mkdir -p run-data
printf 'API level: %s\nABI: %s\n' "$api_level" "$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')" > run-data/emulator.txt

# Keep the untrusted APK offline; do not sign in or enable network access.
adb shell svc wifi disable >/dev/null 2>&1 || true
adb shell svc data disable >/dev/null 2>&1 || true
adb logcat -c >/dev/null 2>&1 || true

adb install -r lanerc.apk > run-data/install.txt 2>&1
install_rc=$?
identity_ok=0
version='not checked'
if [ "$install_rc" -eq 0 ]; then
  if adb shell pm path "$pkg" 2>/dev/null | grep -q 'package:'; then
    version=$(adb shell dumpsys package "$pkg" 2>/dev/null | sed -n 's/.*versionName=//p' | head -n 1 | tr -d '\r')
    [ "$version" = '1.0.8' ] && identity_ok=1
  fi
fi
{
  printf '\nInstall exit: %s\n' "$install_rc"
  printf 'Expected package: %s\nObserved version: %s\n' "$pkg" "$version"
  if [ "$identity_ok" -eq 1 ]; then
    printf 'Package/version check: PASS\n'
  else
    printf 'Package/version check: FAIL\n'
  fi
} >> run-data/install.txt

launch_rc=125
process_alive=0
if [ "$install_rc" -eq 0 ] && [ "$identity_ok" -eq 1 ]; then
  adb shell pm clear "$pkg" >/dev/null 2>&1 || true
  adb shell monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 > run-data/launch.txt 2>&1
  launch_rc=$?
  sleep 15
  if [ -n "$(adb shell pidof "$pkg" 2>/dev/null | tr -d '\r')" ]; then
    process_alive=1
    printf '\nApp process after 15s: RUNNING\n' >> run-data/launch.txt
  else
    printf '\nApp process after 15s: NOT RUNNING\n' >> run-data/launch.txt
  fi
  printf 'Launcher command exit: %s\n' "$launch_rc" >> run-data/launch.txt
  adb shell screencap -p /sdcard/lanerc-screen.png >/dev/null 2>&1 || true
  adb pull /sdcard/lanerc-screen.png run-data/screenshot.png >/dev/null 2>&1 || true
else
  printf 'Launch: NOT ATTEMPTED (install or identity check failed)\n' > run-data/launch.txt
fi

# Limit collected output and redact common credentials and personal identifiers.
adb logcat -d -v threadtime 2>/dev/null | grep -E 'com\\.clggjv\\.xcjfmd\\.ffo|AndroidRuntime|Flutter|flutter|FATAL EXCEPTION' | tail -n 500 > run-data/logcat-candidate.txt || true
python3 - <<'PY'
from pathlib import Path
import re
src = Path('run-data/logcat-candidate.txt')
text = src.read_text(errors='replace') if src.exists() else ''
patterns = [
    (r'(?i)(authorization|cookie|bearer|token|trans.?id|device.?id|advertising.?id|android.?id|imei|oaid|gaid|phone|email)(\s*[:=]\s*)[^\s,;]+', r'\1\2[REDACTED]'),
    (r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[EMAIL REDACTED]'),
    (r'\b(?:\+?\d[\d .()\-]{7,}\d)\b', '[NUMBER REDACTED]'),
    (r'\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\b', '[UUID REDACTED]'),
    (r'https?://[^\s]+', '[URL REDACTED]'),
]
for pattern, replacement in patterns:
    text = re.sub(pattern, replacement, text)
Path('run-data/app-crash-log-sanitized.txt').write_text(text[-150000:])
src.unlink(missing_ok=True)
PY
sanitize_rc=$?
if [ "$sanitize_rc" -ne 0 ]; then
  printf 'Log sanitization: FAILED; raw log omitted\n' > run-data/app-crash-log-sanitized.txt
fi

status="install=$install_rc identity=$identity_ok launch_command=$launch_rc process_alive=$process_alive"
echo "::notice title=Lanerc API $api_level smoke result::$status"
{
  printf '## Lanerc 1.0.8 smoke test (API %s)\n\n' "$api_level"
  printf -- '- Install exit: `%s`\n- Package/version check: `%s` (version `%s`)\n- Launch command exit: `%s`\n- Process alive after 15 seconds: `%s`\n- Network: disabled; no sign-in or ad/reward actions performed\n' "$install_rc" "$identity_ok" "$version" "$launch_rc" "$process_alive"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ "$install_rc" -ne 0 ] || [ "$identity_ok" -ne 1 ] || [ "$process_alive" -ne 1 ]; then
  exit 1
fi
exit 0
