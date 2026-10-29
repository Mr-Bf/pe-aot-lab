"""Admission boundaries exercised before native build; no guest execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from window_profile_v1.profile import analyze, read_profile, validate

ROOT = Path(__file__).resolve().parents[1]
DATA = (ROOT / 'build/window-bridge/save-load-program-v1-01/input.exe').read_bytes()
PROFILE = json.loads((ROOT / 'window_profile_v1/examples/integer-tile.json').read_bytes())


class Admission(unittest.TestCase):
    def reject(self, profile, data=DATA):
        self.assertEqual(analyze(data, profile)['status'], 'UNSUPPORTED')

    def test_real_pe_without_observation_symbols(self):
        report = analyze(DATA, PROFILE)
        self.assertEqual(report['status'], 'ELIGIBLE_FOR_BUILD_NOT_DECODED')
        self.assertEqual(report['observation_count'], 0)
        self.assertEqual(report['guest_executions'], 0)

    def test_changed_data_and_file_name_are_not_fixed_to_fixture(self):
        old, new = b'integer-tile.bin\0', b'profile-save.bin\0'
        self.assertEqual(DATA.count(old), 1)
        data = DATA.replace(old, new)
        profile = copy.deepcopy(PROFILE)
        profile.update(pe_sha256=hashlib.sha256(data).hexdigest(), save_observation=new[:-1].decode())
        self.assertEqual(analyze(data, profile)['status'], 'ELIGIBLE_FOR_BUILD_NOT_DECODED')
        self.reject(PROFILE, data)

    def test_invalid_profile_fields(self):
        values = [('schema', True), ('schema', 2), ('runtime_contract', 'arbitrary-d3d11'),
                  ('resources', 'copy-entire-game'), ('pe_sha256', '0'*64)]
        for key, value in values:
            with self.subTest(key=key, value=value):
                profile = copy.deepcopy(PROFILE); profile[key] = value; self.reject(profile)
        profile = copy.deepcopy(PROFILE); profile['unknown'] = 1; self.reject(profile)
        profile = copy.deepcopy(PROFILE); del profile['resources']; self.reject(profile)

    def test_callback_roots(self):
        _, image, _ = validate(DATA, PROFILE)
        for roots in ([], [True], [-1], [len(image.data)], [0], [image.entry_rva],
                      [4096, 4096], list(range(9)), [4096.0]):
            with self.subTest(roots=roots):
                profile = copy.deepcopy(PROFILE); profile['callback_rvas'] = roots; self.reject(profile)

    def test_exact_import_contract(self):
        for transform in (lambda x: x[:-1], lambda x: list(reversed(x)), lambda x: x + [x[0]],
                          lambda x: [{'dll':'kernel32.dll', 'name':'LoadLibraryA'}]):
            profile = copy.deepcopy(PROFILE); profile['imports'] = transform(profile['imports']); self.reject(profile)

    def test_observation_bounds_and_names(self):
        for name, value in [('bad"name', {'rva':4096, 'size':4}), ('x', {'rva':True, 'size':4}),
                            ('x', {'rva':4096, 'size':0}), ('x', {'rva':4096, 'size':65537}),
                            ('x', {'rva':-1, 'size':4}), ('x', {'rva':0x1000000, 'size':4}),
                            ('x', {'rva':4096, 'size':4, 'write':True})]:
            profile = copy.deepcopy(PROFILE); profile['observations'] = {name:value}; self.reject(profile)

    def test_save_observation_is_safe_basename(self):
        for name in ('', '../save', '/tmp/save', '.', '..', 'a/b', 'a\\b', 'a"b', 'x\n', 'x'*121, None):
            with self.subTest(name=name):
                profile = copy.deepcopy(PROFILE); profile['save_observation'] = name; self.reject(profile)

    def test_json_parser_rejects_duplicates_and_nonfinite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'
            for raw in ('{"schema":1,"schema":2}', '{"number":NaN}', 'x'*65537, '[['):
                path.write_text(raw)
                with self.assertRaises(ValueError): read_profile(path)

    def test_profile_snapshot_is_owned(self):
        original = copy.deepcopy(PROFILE)
        snapshot, _, _ = validate(DATA, original)
        original['callback_rvas'].clear()
        self.assertEqual(snapshot['callback_rvas'], [4096])


if __name__ == '__main__':
    unittest.main()
