"""Bounded recovery rejection tests; never invoke finalization/native commands."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from . import resume

ORIGIN = resume.build.REPO / 'build/portable-graphics-v1/build-03'


class ResumeBoundaries(unittest.TestCase):
    def test_pinned_real_receipts_and_all_actual_command_exits_are_readable(self):
        for name, expected in resume.PINS.items():
            self.assertEqual(resume.sha(ORIGIN / name), expected)
        failure = resume.bound_json(ORIGIN / 'failure.json', resume.PINS['failure.json'])
        records = resume.command_records(ORIGIN, failure)
        self.assertEqual([r['returncode'] for r in records], [0] * 26 + [1])
        self.assertEqual(records[19]['label'], 'dxmt-build')
        self.assertEqual(records[-1]['label'], 'runtime-paths-winemetal.dylib')

    def test_command_ledger_cannot_change_exit_output_hash_or_stage(self):
        original = resume.bound_json(ORIGIN / 'failure.json')
        changes = [(19, 'returncode', 1), (19, 'returncode', False), (19, 'stdout_sha256', '0' * 64),
                   (26, 'returncode', 0), (26, 'expected', 1), (26, 'label', 'another-failure')]
        for index, key, value in changes:
            changed = copy.deepcopy(original)
            changed['commands'][index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises((ValueError, FileNotFoundError)):
                resume.command_records(ORIGIN, changed)
        changed = copy.deepcopy(original)
        changed['commands'].pop()
        with self.assertRaises(ValueError):
            resume.command_records(ORIGIN, changed)

    def test_bound_json_rejects_wrong_hash_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory(prefix='resume-json-') as temporary:
            path = Path(temporary).resolve() / 'record.json'
            raw = b'{"status":"fixture"}'
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(resume.bound_json(path, digest), {'status': 'fixture'})
            path.write_text('{"status":"changed"}')
            with self.assertRaises(ValueError):
                resume.bound_json(path, digest)
            path.write_text('{"status":1,"status":2}')
            with self.assertRaises(resume.build.macho_graph.IntegrityError):
                resume.bound_json(path)

    def test_new_prefix_and_evidence_are_bidirectionally_disjoint_and_absent(self):
        with tempfile.TemporaryDirectory(prefix='resume-isolation-') as temporary:
            base = Path(temporary).resolve()
            original = base / 'original'
            original.mkdir()
            prefix, out = base / 'new', base / 'evidence'
            resume.isolated(prefix, out, original)
            for a, b, inputs in ((original, out, ()), (original / 'child', out, (original,)),
                                  (base, out, (original,)), (prefix, prefix / 'child', (original,)),
                                  (prefix, original / 'evidence', (original,))):
                with self.subTest(a=a, b=b), self.assertRaises(ValueError):
                    resume.isolated(a, b, *inputs)
            self.assertEqual(list(base.iterdir()), [original])

    def test_unpinned_origin_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory(prefix='resume-origin-') as temporary:
            base = Path(temporary).resolve()
            origin = base / 'fake'
            origin.mkdir()
            (origin / 'started.json').write_text(json.dumps({'prefix': 'fake'}))
            with self.assertRaisesRegex(ValueError, 'only pinned graphics build-03'):
                resume.finalize(origin, base / 'prefix', base / 'evidence')
            self.assertFalse((base / 'prefix').exists())
            self.assertFalse((base / 'evidence').exists())

    def test_failed_validation_retires_only_fresh_provider_entry_without_losing_bytes(self):
        with tempfile.TemporaryDirectory(prefix='resume-failed-provider-') as temporary:
            prefix = Path(temporary).resolve()
            resume.retire_failed_provider(prefix)
            raw = b'{"status":"synthetic success that failed final validation"}\n'
            (prefix / 'provider.json').write_bytes(raw)
            resume.retire_failed_provider(prefix)
            self.assertFalse((prefix / 'provider.json').exists())
            self.assertEqual((prefix / 'failed-provider.json').read_bytes(), raw)
            (prefix / 'provider.json').write_bytes(b'new attempt')
            with self.assertRaises(ValueError):
                resume.retire_failed_provider(prefix)
            self.assertEqual((prefix / 'failed-provider.json').read_bytes(), raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
