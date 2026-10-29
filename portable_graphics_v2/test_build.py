"""Build-input isolation checks; no compiler, tool installation or GPU run."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from . import build as builder


class BuildInputIsolation(unittest.TestCase):
    def test_nested_cache_provider_and_evidence_rejected_before_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for child, parent in ((0, 1), (1, 0), (0, 2), (2, 0), (1, 2), (2, 1)):
                paths = [root/'provider', root/'cache', root/'evidence']
                paths[child] = paths[parent]/'nested'
                with self.subTest(child=child, parent=parent), \
                     mock.patch.object(builder.common, 'Recorder') as recorder, \
                     mock.patch.object(builder.cache, 'check_cache') as check, \
                     self.assertRaisesRegex(ValueError, 'must be disjoint'):
                    builder.build(*paths)
                recorder.assert_not_called()
                check.assert_not_called()
                self.assertEqual(list(root.iterdir()), [])

    def test_equal_cache_and_output_rejected_before_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(builder.common, 'Recorder') as recorder, \
                 self.assertRaisesRegex(ValueError, 'must be disjoint'):
                builder.build(root/'provider', root/'same', root/'same')
            recorder.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_declared_v2_inputs_and_frozen_provider_interface(self):
        self.assertIs(builder.cache, __import__('portable_graphics_v2.cache', fromlist=['cache']))
        self.assertIs(builder.paths_for, builder.frozen.paths_for)
        self.assertEqual(builder.PROFILE, builder.frozen.PROFILE)
        self.assertEqual(builder.NAMES, builder.frozen.NAMES)
        declared = set(builder.SOURCES)
        self.assertTrue(set(builder.frozen.SOURCES) <= declared)
        for name in ('__init__.py', '__main__.py', 'build.py', 'cache.py', 'cache-lock.json'):
            self.assertIn(Path(builder.__file__).parent/name, declared)


if __name__ == '__main__':
    unittest.main()
