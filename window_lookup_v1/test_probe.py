"""Reject incomplete or changed cross-build callback evidence without native runs."""
import copy
import gzip
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from . import probe


class ProbeInterfaceTests(unittest.TestCase):
    def test_prepared_tuple_contract(self):
        reviewed, ready = {'status': 'read'}, {'product': 'product'}
        with patch.object(probe.single_review, 'review', return_value=reviewed), \
             patch.object(probe.single, 'verify_prepared', return_value=({'baseline_prepared': '/baseline'}, ready)):
            self.assertEqual(probe.accepted_inputs('/accepted'), (reviewed, Path('/baseline'), ready))

    def test_dependency_target_matches_frozen_parser(self):
        command = probe.dependency_command(['clang'], Path(__file__).resolve())
        target = command[command.index('-MT')+1]
        data = (target+': '+str(Path(__file__).resolve())+'\n').encode()
        self.assertIn(Path(__file__).resolve(), probe.pair.dependencies(data))


class ProbeComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.current = self.root/'current'; self.current.mkdir()
        self.reference = self.root/'reference'; self.reference.mkdir()
        self.value = dict(budget_stream=dict(path='budget.bin.gz', records=364,
                          record_size=probe.single.BUDGET_RECORD_SIZE,
                          uncompressed_bytes=364*probe.single.BUDGET_RECORD_SIZE),
                          budget_checks=[dict(scenario=0, budget=i, status=0,
                              stream_offset=i*probe.single.BUDGET_RECORD_SIZE) for i in range(364)])
        self.stream(self.reference)
        for case in range(8):
            for suffix in ('.bin', '.context.bin'):
                (self.reference/('case-%d%s' % (case, suffix))).write_bytes(bytes([case])*16)
        for path in self.reference.iterdir():
            shutil.copyfile(path, self.current/path.name)

    def stream(self, directory, changed=False, count=364, trailing=False):
        with gzip.open(directory/'budget.bin.gz', 'wb') as stream:
            for index in range(count):
                body = bytearray(probe.single.BUDGET_RECORD_SIZE-16)
                if changed and index == 201:
                    body[-1] = 1  # Late, otherwise unobserved Context byte.
                stream.write(struct.pack('<4I', 0, index, 0, 0)+body)
            if trailing:
                stream.write(b'x')

    def compare(self, value=None):
        return probe.compare(self.current, self.value if value is None else value,
                             self.reference, self.value)

    def test_complete_equal(self):
        self.assertEqual(self.compare(), 364)

    def test_raw_response_change(self):
        value = copy.deepcopy(self.value); value['unexpected'] = True
        with self.assertRaisesRegex(ValueError, 'raw response'):
            self.compare(value)

    def test_state_or_context_change(self):
        for suffix in ('.bin', '.context.bin'):
            path = self.current/('case-7'+suffix); before = path.read_bytes()
            path.write_bytes(before[:-1]+b'\xff')
            with self.assertRaisesRegex(ValueError, 'complete payload'):
                self.compare()
            path.write_bytes(before)

    def test_late_budget_context_change(self):
        self.stream(self.current, changed=True)
        with self.assertRaisesRegex(ValueError, 'budget prefix'):
            self.compare()

    def test_truncated_budget_stream(self):
        self.stream(self.current, count=363)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            self.compare()

    def test_trailing_budget_stream(self):
        self.stream(self.current, trailing=True)
        with self.assertRaisesRegex(ValueError, 'trailing'):
            self.compare()


if __name__ == '__main__':
    unittest.main()
