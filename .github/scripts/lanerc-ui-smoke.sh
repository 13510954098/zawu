#!/usr/bin/env bash
# Online UI navigation only. No account sign-in, ad tap, reward, or download action.
set -uo pipefail
api_level="${1:-unknown}"
pkg='com.clggjv.xcjfmd.ffo'
mkdir -p run-data
trap 'rm -f run-data/*-raw.xml run-data/logcat-candidate.txt' EXIT

abi="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
printf 'API level: %s\nABI: %s\n' "$api_level" "$abi" > run-data/emulator.txt
adb shell svc wifi enable >/dev/null 2>&1 || true
adb shell svc data enable >/dev/null 2>&1 || true
sleep 8
if adb shell dumpsys connectivity 2>/dev/null | grep -q 'VALIDATED'; then network_validated=yes; else network_validated=no; fi
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
printf '\nInstall exit: %s\nExpected package: %s\nObserved version: %s\nPackage/version check: %s\n' \
  "$install_rc" "$pkg" "$version" "$([ "$identity_ok" -eq 1 ] && echo PASS || echo FAIL)" >> run-data/install.txt

launch_rc=125
process_alive=0
home_detected=no
welfare_found=no
welfare_clicked=no
if [ "$identity_ok" -eq 1 ]; then
  adb shell pm clear "$pkg" >/dev/null 2>&1 || true
  adb shell monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 > run-data/launch.txt 2>&1
  launch_rc=$?
  sleep 20
  if [ -n "$(adb shell pidof "$pkg" 2>/dev/null | tr -d '\r')" ]; then process_alive=1; fi
  adb exec-out screencap -p > run-data/01-after-launch.png 2>/dev/null || true
  adb shell uiautomator dump /sdcard/lanerc-ui.xml >/dev/null 2>&1 || true
  adb pull /sdcard/lanerc-ui.xml run-data/01-raw.xml >/dev/null 2>&1 || true
  if [ -s run-data/01-raw.xml ]; then
    python3 .github/scripts/summarize-ui.py run-data/01-raw.xml run-data/01-after-launch-ui.txt run-data/01-welfare-coordinate.txt
    rm -f run-data/01-raw.xml
    grep -q 'Home label detected: yes' run-data/01-after-launch-ui.txt && home_detected=yes
    grep -q 'Welfare label detected: yes' run-data/01-after-launch-ui.txt && welfare_found=yes
  else
    printf 'UI hierarchy capture: unavailable\n' > run-data/01-after-launch-ui.txt
    : > run-data/01-welfare-coordinate.txt
  fi

  # Navigate only to the visible 福利 tab when it is explicitly found as clickable.
  coord=''
  [ -s run-data/01-welfare-coordinate.txt ] && coord=$(cat run-data/01-welfare-coordinate.txt)
  if [ -n "$coord" ]; then
    adb shell input tap "${coord%,*}" "${coord#*,}" >/dev/null 2>&1 || true
    welfare_clicked=yes
    sleep 5
    adb exec-out screencap -p > run-data/02-after-welfare.png 2>/dev/null || true
    adb shell uiautomator dump /sdcard/lanerc-ui.xml >/dev/null 2>&1 || true
    adb pull /sdcard/lanerc-ui.xml run-data/02-raw.xml >/dev/null 2>&1 || true
    if [ -s run-data/02-raw.xml ]; then
      python3 .github/scripts/summarize-ui.py run-data/02-raw.xml run-data/02-after-welfare-ui.txt run-data/02-unused-coordinate.txt
      rm -f run-data/02-raw.xml run-data/02-unused-coordinate.txt
    else
      printf 'UI hierarchy capture: unavailable\n' > run-data/02-after-welfare-ui.txt
    fi
  fi
else
  printf 'Launch: NOT ATTEMPTED (install or identity check failed)\n' > run-data/launch.txt
  printf 'UI capture: NOT ATTEMPTED\n' > run-data/01-after-launch-ui.txt
fi
printf '\nLauncher command exit: %s\nProcess alive after 20 seconds: %s\n' "$launch_rc" "$process_alive" >> run-data/launch.txt

# Keep only app/crash lines; remove URL/query strings and common identifiers before upload.
adb logcat -d -v threadtime 2>/dev/null | grep -E 'com\.clggjv\.xcjfmd\.ffo|AndroidRuntime|Flutter|flutter|FATAL EXCEPTION' | tail -n 500 > run-data/logcat-candidate.txt || true
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

status="network=$network_validated install=$install_rc identity=$identity_ok launched=$process_alive home=$home_detected welfare=$welfare_found welfare_clicked=$welfare_clicked"
echo "::notice title=Lanerc API $api_level UI smoke::$status"
{
  printf '## Lanerc online UI smoke (API %s)\n\n' "$api_level"
  printf -- '- Network validated: `%s`\n- Install/version: `%s` / `%s`\n- Process alive after 20 seconds: `%s`\n- Home label detected: `%s`\n- Welfare entry detected: `%s`\n- Welfare entry clicked: `%s`\n- No account credentials entered; no ad/reward/download action performed\n' "$network_validated" "$identity_ok" "$version" "$process_alive" "$home_detected" "$welfare_found" "$welfare_clicked"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ "$install_rc" -ne 0 ] || [ "$identity_ok" -ne 1 ] || [ "$process_alive" -ne 1 ]; then exit 1; fi
exit 0
