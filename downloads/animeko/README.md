# Animeko + Lanerc Android debug build

APK: `animeko-lanerc-arm64-debug.apk` (arm64-v8a, independent installed application ID `me.him188.ani.lanerc.debug2`; Android 8.1 / API 27 or later).

Build: https://github.com/13510954098/zawu/actions/runs/42450838673
Source: `65b40e6253f5287308d4c368479abe2c493730c8`
SHA256: `5a42e046187f207ad7f734d2605bd4d2ad4dd0339afac4c19bbf965db8697bd7`

This is a compiled integration preview, **not a verified production-ready release**.
No recovered production keys or guest credentials are embedded. Configure private
protocol material inside the app; the default build does not bypass server login.
Original-format source import is partial. Native comments UI included in this
compiled source: **True**. Not device/backend verified.
Native danmaku timeline included in compiled source: **True**. Device/backend
verification remains incomplete. Native account login UI: **False**;
explicit-confirmation comment/reply/barrage posting UI: **False**. No real
account login or publication has been verified. No whole-app device test or
successful production playback is claimed. Debug APKs use the CI-generated debug
key; later builds may require uninstalling first, which removes app data.

Verify download: `sha256sum -c SHA256SUMS`.

The host and modifications are AGPL-3.0; see `integration/animeko/LICENSE.txt`,
`integration/animeko/upstream.json`, the pinned public upstream and repository overlay
for the corresponding source and build instructions.
