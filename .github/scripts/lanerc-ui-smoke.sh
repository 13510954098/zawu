#!/usr/bin/env bash
# Online UI navigation only. No sign-in, ad playback, reward callback, or download action.
set -uo pipefail
api_level="${1:-unknown}"
pkg='com.clggjv.xcjfmd.ffo'
mkdir -p run-data
trap 'rm -f run-data/*-raw.xml run-data/*-log-candidate.txt run-data/ocr-raw.txt' EXIT

abi="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
printf 'API level: %s\nABI: %s\n' "$api_level" "$abi" > run-data/emulator.txt
adb shell svc wifi enable >/dev/null 2>&1 || true
adb shell svc data enable >/dev/null 2>&1 || true
sleep 8
if adb shell dumpsys connectivity 2>/dev/null | grep -q 'VALIDATED'; then network_validated=yes; else network_validated=no; fi
printf 'Emulator network validated: %s\n' "$network_validated" > run-data/network-status.txt
adb logcat -c >/dev/null 2>&1 || true

sanitize_logs() {
  local stage="$1"
  adb logcat -d -v threadtime 2>/dev/null | grep -E 'com\.clggjv\.xcjfmd\.ffo|AndroidRuntime|Flutter|flutter|FATAL EXCEPTION' | tail -n 500 > "run-data/${stage}-log-candidate.txt" || true
  python3 - "$stage" <<'PY'
from pathlib import Path
import re, sys
stage = sys.argv[1]
src = Path(f'run-data/{stage}-log-candidate.txt')
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
Path(f'run-data/{stage}-app-log-sanitized.txt').write_text(text[-80000:])
src.unlink(missing_ok=True)
PY
}

capture_step() {
  local stage="$1" target="$2" second_target="${3:-}"
  adb exec-out screencap -p > "run-data/${stage}.png" 2>/dev/null || true
  adb shell uiautomator dump /sdcard/lanerc-ui.xml >/dev/null 2>&1 || true
  adb pull /sdcard/lanerc-ui.xml "run-data/${stage}-raw.xml" >/dev/null 2>&1 || true
  python3 .github/scripts/analyze-ui-step.py \
    "run-data/${stage}-raw.xml" "run-data/${stage}.png" "$stage" run-data "$target"
  if [ -n "$second_target" ]; then
    python3 .github/scripts/analyze-ui-step.py \
      "run-data/${stage}-raw.xml" "run-data/${stage}.png" "${stage}-welfare" run-data "$second_target"
  fi
  rm -f "run-data/${stage}-raw.xml"
  sanitize_logs "$stage" || true
}

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
ack_tapped=no
ack_dismissed=unconfirmed
welfare_tapped=no
home_detected=no
welfare_detected=no
login_prompt=no
download_hint=no
ad_entry_hint=no
if [ "$identity_ok" -eq 1 ]; then
  adb shell pm clear "$pkg" >/dev/null 2>&1 || true
  adb shell monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 > run-data/launch.txt 2>&1
  launch_rc=$?
  sleep 20
  if [ -n "$(adb shell pidof "$pkg" 2>/dev/null | tr -d '\r')" ]; then process_alive=1; fi

  # Stage 0: screenshot + sanitized hierarchy/OCR before any tap.
  capture_step 00-launch '已知晓'
  grep -q 'Target.*in hierarchy: yes' run-data/00-launch-ui-summary.txt && ack_initial_ui=yes || ack_initial_ui=no
  grep -q 'target_ocr_visible=yes' run-data/00-launch-ui-summary.txt && ack_initial_ocr=yes || ack_initial_ocr=no
  grep -q 'home_visible=yes' run-data/00-launch-ui-summary.txt && home_detected=yes

  # Prefer exact UIAutomator bounds; use user coordinates only when 1080x1920 is verified and label is visible.
  ack_coord=''
  [ -s run-data/00-launch-target-coordinate.txt ] && ack_coord=$(cat run-data/00-launch-target-coordinate.txt)
  ack_method='ui-hierarchy'
  if [ -z "$ack_coord" ] && { [ "$ack_initial_ocr" = yes ] || [ "$ack_initial_ui" = yes ]; } \
       && grep -q 'Screenshot size: 1080x1920' run-data/00-launch-ui-summary.txt; then
    ack_coord='540,1294'
    ack_method='user-coordinate-fallback-1080x1920'
  fi
  printf 'Acknowledgement visible: hierarchy=%s OCR=%s\nTap method: %s\n' \
    "$ack_initial_ui" "$ack_initial_ocr" "$ack_method" > run-data/01-ack-action.txt
  if [ -n "$ack_coord" ]; then
    adb shell input tap "${ack_coord%,*}" "${ack_coord#*,}" >/dev/null 2>&1 || true
    ack_tapped=yes
    sleep 3
    # Capture/confirm dismissal before proceeding, and analyze 福利 separately on the same frame.
    capture_step 01-after-ack '已知晓' '福利'
    grep -q 'target_ocr_visible=no' run-data/01-after-ack-ui-summary.txt && ack_ocr_gone=yes || ack_ocr_gone=no
    grep -q 'ocr_available=yes' run-data/01-after-ack-ui-summary.txt && ack_ocr_available=yes || ack_ocr_available=no
    grep -q 'Target.*in hierarchy: no' run-data/01-after-ack-ui-summary.txt && ack_ui_gone=yes || ack_ui_gone=no
    if { [ "$ack_initial_ocr" = yes ] && [ "$ack_ocr_available" = yes ] && [ "$ack_ocr_gone" = yes ]; } \
       || { [ "$ack_initial_ui" = yes ] && [ "$ack_ui_gone" = yes ]; }; then
      ack_dismissed=confirmed
    fi
    grep -q 'home_visible=yes' run-data/01-after-ack-ui-summary.txt && home_detected=yes
  else
    printf 'Acknowledgement tap skipped: label not positively located or dimensions differ.\n' >> run-data/01-ack-action.txt
  fi

  if [ "$ack_dismissed" = confirmed ]; then
    welfare_summary='run-data/01-after-ack-welfare-ui-summary.txt'
    grep -q 'welfare_visible=yes' "$welfare_summary" && welfare_detected=yes
    welfare_ui=no
    grep -q 'Target.*in hierarchy: yes' "$welfare_summary" && welfare_ui=yes
    welfare_ocr=no
    grep -q 'target_ocr_visible=yes' "$welfare_summary" && welfare_ocr=yes
    welfare_coord=''
    [ -s run-data/01-after-ack-welfare-target-coordinate.txt ] && welfare_coord=$(cat run-data/01-after-ack-welfare-target-coordinate.txt)
    welfare_method='ui-hierarchy'
    if [ -z "$welfare_coord" ] && [ "$welfare_ocr" = yes ] \
       && grep -q 'Screenshot size: 1080x1920' "$welfare_summary"; then
      welfare_coord='540,1693'
      welfare_method='user-coordinate-fallback-1080x1920'
    fi
    printf 'Welfare visible: hierarchy=%s OCR=%s\nTap method: %s\n' \
      "$welfare_ui" "$welfare_ocr" "$welfare_method" > run-data/02-welfare-action.txt
    if [ -n "$welfare_coord" ]; then
      adb shell input tap "${welfare_coord%,*}" "${welfare_coord#*,}" >/dev/null 2>&1 || true
      welfare_tapped=yes
      sleep 3
      capture_step 02-after-welfare '福利'
      grep -q 'login_hint=yes' run-data/02-after-welfare-ui-summary.txt && login_prompt=yes
      grep -q 'download_hint=yes' run-data/02-after-welfare-ui-summary.txt && download_hint=yes
      grep -q 'ad_hint=yes' run-data/02-after-welfare-ui-summary.txt && ad_entry_hint=yes
      grep -E 'download_hint=|ad_hint=|login_hint=|Visible hierarchy labels|Relevant OCR lines|下载|次数|金币|权限|广告|视频|登录|福利' \
        run-data/02-after-welfare-ui-summary.txt > run-data/welfare-state-labels.txt || true
      printf 'Displayed values are visual text only; entitlement was not verified.\n' >> run-data/welfare-state-labels.txt
      welfare_text=$(grep -E '下载|次数|金币|权限|广告|视频|登录|福利' run-data/02-after-welfare-relevant-labels.txt 2>/dev/null | tr '\n' ' ' | cut -c1-500)
      if [ -n "$welfare_text" ]; then
        echo "::notice title=Lanerc API $api_level welfare labels::$welfare_text"
      fi
    else
      printf 'Welfare tap skipped: entry not positively located.\n' >> run-data/02-welfare-action.txt
    fi
  else
    printf 'Welfare navigation skipped: dismissal not confirmed by UI hierarchy/OCR.\n' > run-data/02-welfare-action.txt
  fi
else
  printf 'Launch/UI capture: NOT ATTEMPTED (install or identity check failed)\n' > run-data/00-launch-ui-summary.txt
fi
printf '\nLauncher command exit: %s\nProcess alive after 20 seconds: %s\n' "$launch_rc" "$process_alive" >> run-data/launch.txt 2>/dev/null || true

status="network=$network_validated install=$install_rc identity=$identity_ok process=$process_alive home=$home_detected ack_tapped=$ack_tapped ack_dismissed=$ack_dismissed welfare=$welfare_detected welfare_tapped=$welfare_tapped login_prompt=$login_prompt download_hint=$download_hint ad_entry_hint=$ad_entry_hint"
echo "::notice title=Lanerc API $api_level UI-step result::$status"
{
  printf '## Lanerc UI steps (API %s)\n\n' "$api_level"
  printf -- '- Network validated: `%s`\n- Install/version: `%s` / `%s`\n- Process alive: `%s`\n- Home label detected: `%s`\n- Acknowledgement tapped/dismissal confirmed: `%s` / `%s`\n- Welfare visible/tapped: `%s` / `%s`\n- Login prompt detected: `%s`\n- Download-related text detected: `%s` (display text only)\n- Ad-entry text detected: `%s`\n- No credentials entered; no ad/reward/download action performed\n' \
    "$network_validated" "$identity_ok" "$version" "$process_alive" "$home_detected" "$ack_tapped" "$ack_dismissed" "$welfare_detected" "$welfare_tapped" "$login_prompt" "$download_hint" "$ad_entry_hint"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ "$install_rc" -ne 0 ] || [ "$identity_ok" -ne 1 ] || [ "$process_alive" -ne 1 ]; then exit 1; fi
exit 0
