"""Synthetic APK-shaped ZIPs; these tests do not claim APK install/signature validity."""
import hashlib
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import publish_animeko_apk as delivery


class ApkDeliveryTests(unittest.TestCase):
    def fixture(self, root, missing=()):
        p = pathlib.Path(root) / 'synthetic.apk'
        with zipfile.ZipFile(p, 'w', compression=zipfile.ZIP_STORED) as z:
            for name, data in [('AndroidManifest.xml', b'not a real binary manifest'),
                               ('classes.dex', b'not real dex'),
                               ('lib/arm64-v8a/libfixture.so', b'x' * 1_100_000)]:
                if name not in missing:
                    z.writestr(name, data)
            if missing:
                z.writestr('padding', b'x' * 1_100_000)
        return p

    def test_zip_shape_and_hash_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.fixture(d)
            self.assertEqual(delivery.validate_apk(p), hashlib.sha256(p.read_bytes()).hexdigest())

    def test_no_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                delivery.validate_apk(self.fixture(d, ('AndroidManifest.xml',)))

    def test_no_dex_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                delivery.validate_apk(self.fixture(d, ('classes.dex',)))

    def test_no_arm64_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                delivery.validate_apk(self.fixture(d, ('lib/arm64-v8a/libfixture.so',)))

    def test_small_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'tiny.apk'
            p.write_bytes(b'not apk')
            with self.assertRaises(ValueError):
                delivery.validate_apk(p)

    def run_identity_check(self, run, jobs=None):
        responses = [run] if jobs is None else [run, jobs]
        with patch.object(sys, 'argv', ['publish', '--run', '1', '--artifacts', '/nonexistent']), \
                patch.object(delivery, 'gh', side_effect=responses), self.assertRaises(ValueError):
            delivery.main()

    def test_other_branch_rejected(self):
        self.run_identity_check({'head_branch': 'main', 'name': 'Animeko Lanerc Android integration build'})

    def test_other_workflow_rejected(self):
        self.run_identity_check({'head_branch': delivery.BRANCH, 'name': 'unrelated workflow'})

    def test_failed_compile_rejected_even_with_artifact(self):
        run = {'head_branch': delivery.BRANCH, 'name': 'Animeko Lanerc Android integration build'}
        self.run_identity_check(run, {'jobs': [{'steps': [
            {'name': 'Compile and package the Android integration without private production material', 'conclusion': 'failure'},
            {'name': 'Save APK and build provenance', 'conclusion': 'success'},
            {'name': 'Run actions/upload-artifact@v4', 'conclusion': 'success'},
        ]}]})


if __name__ == '__main__':
    unittest.main()
