# Animeko + Lanerc Android debug build

APK: `animeko-lanerc-arm64-debug.apk` (arm64-v8a, independent installed application ID `me.him188.ani.lanerc.debug2`; Android 8.1 / API 27 or later).

Version: `6.4.0-post15.lanerc.preview` (Lanerc preview, not an official Animeko release).
Upstream: `6d79729a135cee6af861a7a095d3880d1b452260`
Build: https://github.com/13510954098/zawu/actions/runs/42461386876
Source: `a9e28a318e08f175e5a93b4f778ad8e97a6ea750`
SHA256: `cdb5569d1b9a0c7b8d4a660a3f6e2c57b5c28dc76f3221d266422d7dccf22984`

This is a compiled integration preview, **not a verified production-ready release**.
Shared original-APK client protocol constants bundled: **True**.
No user passwords, account tokens or guest credentials are bundled. Legacy builds
without shared constants require manual protocol configuration. Bundling client
constants does not bypass service-side authentication or verification.
Original-format source import is partial. Native comments UI included in this
compiled source: **True**. Not device/backend verified.
Native danmaku timeline included in compiled source: **True**. Device/backend
verification remains incomplete. Native account login UI: **True**;
explicit-confirmation comment/reply/barrage posting UI: **True**. No real
account login or publication has been verified. No whole-app device test or
successful production playback is claimed. Debug APKs use the CI-generated debug
key; later builds may require uninstalling first, which removes app data.

Verify download: `sha256sum -c SHA256SUMS`.

The host and modifications are AGPL-3.0; see `integration/animeko/LICENSE.txt`,
`integration/animeko/upstream.json`, the pinned public upstream and repository overlay
for the corresponding source and build instructions.
