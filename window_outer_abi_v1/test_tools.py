import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import build, run


class ToolGates(unittest.TestCase):
    def test_existing_input_hash_cannot_be_replaced(self):
        original = {'header': 'first'}
        with self.assertRaisesRegex(ValueError, 'previously observed'):
            build.merge_inputs(original, {'header': 'changed', 'other': 'new'})
        self.assertEqual(original, {'header': 'first'})

    def test_changed_compiled_object_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'object.o'; p.write_bytes(b'first')
            fixed = build.identities([p]); p.write_bytes(b'other')
            with self.assertRaisesRegex(ValueError, 'immutable'):
                build.unchanged(fixed)

    def test_prior_build_and_temporary_app_are_observed(self):
        rows = ('101 /another/work/window-outer-abi-v1/build-old/outer-reference-O3 --data-dir /tmp/data\n'
                '102 /private/tmp/PE AOT Converted.app/Contents/MacOS/pe-aot-window\n'
                '103 /bin/zsh -c echo /private/tmp/PE AOT Converted.app/Contents/MacOS/pe-aot-window\n'
                '104 /usr/bin/python3 unrelated.py\n')
        with patch.object(run.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=rows)):
            value = run.active_project_processes([])
        self.assertEqual([x['pid'] for x in value['matching_processes']], [101, 102])
        self.assertFalse(value['all_process_stdout_retained'])

    def test_unobservable_processes_are_not_assumed_absent(self):
        with patch.object(run.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout='')):
            with self.assertRaisesRegex(ValueError, 'cannot observe'):
                run.active_project_processes([])

    def test_existing_and_aliased_outputs_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve(); existing = root / 'existing'; existing.mkdir()
            (root / 'link').symlink_to(existing, target_is_directory=True)
            with patch.object(build, 'BASE', root):
                for output in [existing, root / 'link/new', root.parent / 'outside']:
                    with self.assertRaises(ValueError):
                        build.fresh(output)

    def test_bad_timeout_rejected_before_any_read(self):
        for value in [True, 0, 9, 121, '60']:
            with self.assertRaisesRegex(ValueError, 'timeout'):
                run.run('/missing', '/missing', value)


if __name__ == '__main__':
    unittest.main()
