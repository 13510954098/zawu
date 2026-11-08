"""Materialize the pinned Animeko source and apply the tracked Lanerc overlay.
The upstream checkout/cache is intentionally private and excluded from snapshots;
all integration source files remain tracked in integration/animeko/overlay.
No branch switching, dependency execution, app traffic or private material upload.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import stat
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / 'integration/animeko'
DESTINATION = ROOT / '.local/animeko/worktree'


def extract(archive, destination, expected_commit):
    with zipfile.ZipFile(archive) as bundle:
        if bundle.comment.decode('ascii') != expected_commit:
            raise ValueError('Unexpected source commit')
        roots = {pathlib.PurePosixPath(info.filename).parts[0] for info in bundle.infolist()}
        if len(roots) != 1:
            raise ValueError('Expected exactly one source root')
        # Validate every entry before creating any files.
        entries = []
        for info in bundle.infolist():
            path = pathlib.PurePosixPath(info.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in info.filename:
                raise ValueError('Unsafe archive path')
            if len(path.parts) < 2:
                continue
            relative = pathlib.Path(*path.parts[1:])
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                # The upstream agent-skill symlinks are not required to build.
                continue
            if not (destination / relative).resolve().is_relative_to(destination.resolve()):
                raise ValueError('Extraction outside destination')
            entries.append((info, relative, mode))
        for info, relative, mode in entries:
            target = destination / relative
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(info) as source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)
                if mode & 0o111:
                    target.chmod(0o755)


def apply_preview_version(destination, pin):
    """Replace upstream's stale default, without claiming an official release."""
    release = pin['baseline_release']
    distance = pin['commits_after_release']
    if not isinstance(release, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', release):
        raise ValueError('Invalid baseline release')
    if type(distance) is not int or distance < 0:
        raise ValueError('Invalid release distance')
    version = f'{release}-post{distance}.lanerc.preview'
    properties = destination / 'gradle.properties'
    text = properties.read_text()
    updated, count = re.subn(r'^version\.name=.*$', f'version.name={version}', text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError('Expected exactly one upstream version.name property')
    properties.write_text(updated)
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=pathlib.Path, help='Optional already downloaded pinned source ZIP')
    args = parser.parse_args()
    pin = json.loads((INTEGRATION / 'upstream.json').read_text())
    cache = ROOT / '.local/animeko'
    cache.mkdir(parents=True, exist_ok=True)
    archive = args.archive or cache / 'upstream.zip'
    if not archive.exists():
        if args.archive:
            raise SystemExit('Specified archive is missing')
        with urllib.request.urlopen(pin['archive_url'], timeout=90) as response, archive.open('wb') as output:
            shutil.copyfileobj(response, output)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != pin['archive_sha256']:
        raise SystemExit('Archive checksum mismatch; source was not applied')
    marker = DESTINATION / '.lanerc-upstream-commit'
    if DESTINATION.exists() and not marker.exists():
        raise SystemExit('Refusing to overwrite an unrecognized worktree')
    if marker.exists() and marker.read_text().strip() != pin['commit']:
        raise SystemExit('Worktree belongs to a different baseline')
    if not marker.exists():
        extract(archive, DESTINATION, pin['commit'])
        marker.write_text(pin['commit'] + '\n')
    overlay = INTEGRATION / 'overlay'
    files = list(overlay.rglob('*'))
    for source in files:
        if source.is_symlink():
            raise SystemExit('Symlinks are not accepted in the integration overlay')
        if source.is_file():
            target = DESTINATION / source.relative_to(overlay)
            if not target.resolve().is_relative_to(DESTINATION.resolve()):
                raise SystemExit('Overlay path escaped source root')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    version = apply_preview_version(DESTINATION, pin)
    print(f'Lanerc preview version: {version}; pinned upstream: {pin["commit"]}')
    print('Pinned Animeko source prepared at .local/animeko/worktree')
    print('Overlay includes protocol, source runtime, settings UI and Android integration; production readiness requires separate verification.')


if __name__ == '__main__':
    main()
