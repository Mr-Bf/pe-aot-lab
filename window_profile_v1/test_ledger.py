"""Regression for a concrete extra-artifact omission found in self-review."""
from pathlib import Path
import tempfile
import unittest

from window_profile_v1.build import files


class Ledger(unittest.TestCase):
    def test_nested_result_and_unrelated_cache_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'native/cache').mkdir(parents=True);(root/'cache').mkdir()
            for name in ('result.json','native/result.json','native/.program-build.lock','native/cache/shader','cache/unexpected'):
                (root/name).write_text('test')
            self.assertEqual(set(files(root)), {'native/result.json','cache/unexpected'})

    def test_symlink_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'target').mkdir();(root/'alias').symlink_to(root/'target', target_is_directory=True)
            with self.assertRaises(ValueError): files(root)


if __name__=='__main__':
    unittest.main()
