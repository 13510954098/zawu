# Animeko + Lanerc Android debug build

APK: `animeko-lanerc-arm64-debug.apk` (arm64-v8a, independent installed application ID `me.him188.ani.lanerc.debug2`; Android 8.1 / API 27 or later).

Build: https://github.com/13510954098/zawu/actions/runs/42447182147
Source: `043a4bf807ed6d3c85fdb8dd580c37b74582d0ea`
SHA256: `f7a0af28abe682e03947051c27783f6ad0c82a2a0ea02f6ef2587a84e4cfbb08`

This is a compiled integration preview, **not a verified production-ready release**.
No recovered production keys or guest credentials are embedded. Configure private
protocol material inside the app; the default build does not bypass server login.
Original-format source import is partial. Native comments UI included in this
compiled source: **True**. It is read-only, not device/backend verified.
Native danmaku timeline included in compiled source: **True**. Device/backend
verification and native account login/posting remain unfinished. No device test or
successful production playback is claimed. Debug APKs use the CI-generated debug
key; later builds may require uninstalling first, which removes app data.

Verify download: `sha256sum -c SHA256SUMS`.

The host and modifications are AGPL-3.0; see `integration/animeko/LICENSE.txt`,
`integration/animeko/upstream.json`, the pinned public upstream and repository overlay
for the corresponding source and build instructions.
