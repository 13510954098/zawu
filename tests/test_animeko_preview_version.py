"""Executed by Actions; no network, credentials or Android toolchain required."""
import pathlib
import tempfile
import unittest

from scripts.prepare_animeko_lanerc import apply_preview_version


class PreviewVersionTests(unittest.TestCase):
    def test_replaces_stale_default_idempotently_without_changing_other_properties(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / 'gradle.properties'
            path.write_text('# comment\nversion.name=4.9.0-dev\nandroid.version.code=50406\n')
            pin = {'baseline_release': '6.4.0', 'commits_after_release': 15}
            self.assertEqual(apply_preview_version(root, pin), '6.4.0-post15.lanerc.preview')
            first = path.read_text()
            self.assertIn('android.version.code=50406\n', first)
            self.assertNotIn('4.9.0-dev', first)
            apply_preview_version(root, pin)
            self.assertEqual(path.read_text(), first)

    def test_refuses_missing_or_duplicate_version_property(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / 'gradle.properties'
            for text in ('# absent\n', 'version.name=a\nversion.name=b\n'):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    apply_preview_version(root, {'baseline_release': '6.4.0', 'commits_after_release': 15})
                self.assertEqual(path.read_text(), text)

    def test_refuses_invalid_metadata(self):
        for release, distance in [('6.4.0\nunsafe=true', 15), ('6.4.0', -1), ('6.4.0', True)]:
            with self.assertRaises(ValueError):
                apply_preview_version(pathlib.Path('/nonexistent'), {'baseline_release': release, 'commits_after_release': distance})
