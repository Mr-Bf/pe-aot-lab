"""Pure-file regressions for the independent production callback reader."""
import ast
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import probe_review as r


class ProbeReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve()
        self.audit = r.single.old.Audit()
        self.write('nm-u-O3.stdout', '_calloc\n_free\n_qsort\n')
        self.write('nm-O3.stdout', '_aot_begin\n_aot_execute\n')
        self.write('disasm-O3.stdout', '_aot_begin:\n ret\n_aot_execute:\n ret\n')

    def write(self, name, text):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_candidate_inspection(self):
        value = r.inspection(self.audit, self.directory, 'O3')
        self.assertEqual(value['strategy'], 'candidate')
        self.assertFalse(value['bsearch_imported'])

    def test_reference_import_rejected(self):
        self.write('nm-u-O3.stdout', '_calloc\n_bsearch\n')
        with self.assertRaisesRegex(ValueError, 'reference lookup'): r.inspection(self.audit, self.directory, 'O3')

    def test_selector_symbol_rejected(self):
        self.write('nm-O3.stdout', '_aot_pair_lookup_mode\n')
        with self.assertRaisesRegex(ValueError, 'strategy selector'): r.inspection(self.audit, self.directory, 'O3')

    def test_missing_actual_runtime_disassembly(self):
        self.write('disasm-O3.stdout', '_fake:\n ret\n')
        with self.assertRaisesRegex(ValueError, 'runtime disassembly'): r.inspection(self.audit, self.directory, 'O3')

    def test_transitive_relative_source_closure(self):
        self.write('pkg/__init__.py', '')
        self.write('pkg/main.py', 'from . import helper\nif False:\n import pkg.hidden\n')
        self.write('pkg/helper.py', 'from pkg import nested\n')
        self.write('pkg/hidden.py', '')
        self.write('pkg/nested.py', '')
        with patch.object(r, 'ROOT', self.directory):
            actual = r.source_closure(self.audit, [self.directory / 'pkg/main.py'])
        self.assertEqual(actual, {str(self.directory / ('pkg/' + name + '.py'))
                                 for name in ('__init__', 'main', 'helper', 'hidden', 'nested')})

    def test_escaped_relative_source_rejected(self):
        self.write('pkg/main.py', 'from ... import nope\n')
        with patch.object(r, 'ROOT', self.directory), self.assertRaisesRegex(ValueError, 'relative source'):
            r.source_closure(self.audit, [self.directory / 'pkg/main.py'])

    def test_no_execution_or_producer_imports(self):
        tree = ast.parse(Path(r.__file__).read_text())
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): names += [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom): names.append(node.module)
        self.assertEqual(set(names), {'argparse', 'ast', 'itertools', 'json', 'pathlib', 'sys', 'window_callback_single_v1', None})
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))


if __name__ == '__main__':
    unittest.main()
