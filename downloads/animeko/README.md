# Animeko + Lanerc Android debug build

APK: `animeko-lanerc-arm64-debug.apk` (arm64-v8a, independent installed application ID `me.him188.ani.lanerc.debug2`; Android 8.1 / API 27 or later).

Build: https://github.com/13510954098/zawu/actions/runs/42443902879
Source: `2e3cce687e8eeab44c1099d252627f4dc7bbff2a`
SHA256: `a4e7c5828e01dae3bc2fb133511058bffaf0f238f9385068c8d54be3587fe15d`

This is a compiled integration preview, **not a verified production-ready release**.
No recovered production keys or guest credentials are embedded. Configure private
protocol material inside the app; the default build does not bypass server login.
Original-format source import is partial. Native comments UI included in this
compiled source: **False**. It is read-only, not device/backend verified.
Danmaku rendering and native account login/posting remain unfinished. No device test or
successful production playback is claimed. Debug APKs use the CI-generated debug
key; later builds may require uninstalling first, which removes app data.

Verify download: `sha256sum -c SHA256SUMS`.

The host and modifications are AGPL-3.0; see `integration/animeko/LICENSE.txt`,
`integration/animeko/upstream.json`, the pinned public upstream and repository overlay
for the corresponding source and build instructions.
