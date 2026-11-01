#!/usr/bin/env bash
# Online startup smoke test only. Does not click ads or enter reward/download flows.
set -uo pipefail

api_level="${1:-unknown}"
pkg='com.clggjv.xcjfmd.ffo'
mkdir -p run-data
trap 'rm -f run-data/logcat-candidate.txt' EXIT

abi="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
printf 'API level: %s\nABI: %s\n' "$api_level" "$abi" > run-data/emulator.txt

# Fresh emulator, no user accounts. Enable the emulator's normal network connection.
adb shell svc wifi enable >/dev/null 2>&1 || true
adb shell svc data enable >/dev/null 2>&1 || true
sleep 8
if adb shell dumpsys connectivity 2>/dev/null | grep -q 'VALIDATED'; then
  network_validated=yes
else
  network_validated=no
fi
printf 'Emulator network validated: %s\n' "$network_validated" > run-data/network-status.txt
adb logcat -c >/dev/null 2>&1 || true

adb install -r lanerc.apk > run-data/install.txt 2>&1
install_rc=$?
identity_ok=0
version='not checked'
if [ "$install_rc" -eq 0 ] && adb shell pm path "$pkg" 2>/dev/null | grep -q 'package:'; then
  version=$(adb shell dumpsys package "$pkg" 2>/dev/null | sed -n 's/.*versionName=//p' | head -n 1 | tr -d '\r')
  [ "$version" = '1.0.8' ] && identity_ok=1
fi
{
  printf '\nInstall exit: %s\nExpected package: %s\nObserved version: %s\n' "$install_rc" "$pkg" "$version"
  printf 'Package/version check: %s\n' "$([ "$identity_ok" -eq 1 ] && echo PASS || echo FAIL)"
} >> run-data/install.txt

launch_rc=125
process_alive=0
if [ "$identity_ok" -eq 1 ]; then
  adb shell pm clear "$pkg" >/dev/null 2>&1 || true
  # Launch only; no taps, ad playback, reward callbacks, or download attempts.
  adb shell monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 > run-data/launch.txt 2>&1
  launch_rc=$?
  sleep 20
  if [ -n "$(adb shell pidof "$pkg" 2>/dev/null | tr -d '\r')" ]; then
    process_alive=1
    printf '\nApp process after 20s: RUNNING\n' >> run-data/launch.txt
  else
    printf '\nApp process after 20s: NOT RUNNING\n' >> run-data/launch.txt
  fi
  printf 'Launcher command exit: %s\n' "$launch_rc" >> run-data/launch.txt
else
  printf 'Launch: NOT ATTEMPTED (install or identity check failed)\n' > run-data/launch.txt
fi

# Filter likely app/crash messages, redact values and URLs, and never upload the raw candidate.
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
    (r'\b[0-9a-fA-F]{24,}\b', '[OPAQUE ID REDACTED]'),
]
for pattern, replacement in patterns:
    text = re.sub(pattern, replacement, text)
Path('run-data/app-log-sanitized.txt').write_text(text[-100000:])
src.unlink(missing_ok=True)
PY
sanitize_rc=$?
if [ "$sanitize_rc" -ne 0 ]; then
  rm -f run-data/logcat-candidate.txt
  printf 'Log sanitization failed; raw app logs omitted.\n' > run-data/app-log-sanitized.txt
fi

status="network_validated=$network_validated install=$install_rc identity=$identity_ok launch_command=$launch_rc process_alive=$process_alive"
echo "::notice title=Lanerc API $api_level online smoke::$status"
{
  printf '## Lanerc online launch smoke test (API %s)\n\n' "$api_level"
  printf -- '- Network validated: `%s`\n- Install exit: `%s`\n- Package/version check: `%s` (version `%s`)\n- Launch command exit: `%s`\n- Process alive after 20 seconds: `%s`\n- Scope: launch only; no ad/reward/download interaction\n' "$network_validated" "$install_rc" "$identity_ok" "$version" "$launch_rc" "$process_alive"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ "$install_rc" -ne 0 ] || [ "$identity_ok" -ne 1 ] || [ "$process_alive" -ne 1 ]; then
  exit 1
fi
exit 0
