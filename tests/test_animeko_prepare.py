"""Small synthetic ZIPs only; no upstream download or code execution."""
import pathlib
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
from prepare_animeko_lanerc import extract


class AnimekoPrepareTests(unittest.TestCase):
    def archive(self, directory, paths, commit='test-commit'):
        path = pathlib.Path(directory) / 'source.zip'
        with zipfile.ZipFile(path, 'w') as bundle:
            bundle.comment = commit.encode()
            for name in paths:
                bundle.writestr(name, 'fixture')
        return path

    def test_valid_source_root_is_stripped(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = self.archive(directory, ['upstream/src/file.kt'])
            destination = pathlib.Path(directory) / 'worktree'
            extract(archive, destination, 'test-commit')
            self.assertEqual((destination / 'src/file.kt').read_text(), 'fixture')

    def test_mismatched_commit_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = self.archive(directory, ['upstream/file'])
            destination = pathlib.Path(directory) / 'worktree'
            with self.assertRaises(ValueError):
                extract(archive, destination, 'different')
            self.assertFalse(destination.exists())

    def test_traversal_rejected_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = self.archive(directory, ['upstream/good', 'upstream/../../escape'])
            destination = pathlib.Path(directory) / 'worktree'
            with self.assertRaises(ValueError):
                extract(archive, destination, 'test-commit')
            self.assertFalse(destination.exists())

    def test_absolute_and_multiple_roots_rejected(self):
        for paths in (['/upstream/escape'], ['one/file', 'two/file']):
            with self.subTest(paths=paths), tempfile.TemporaryDirectory() as directory:
                archive = self.archive(directory, paths)
                with self.assertRaises(ValueError):
                    extract(archive, pathlib.Path(directory) / 'worktree', 'test-commit')


if __name__ == '__main__':
    unittest.main()
