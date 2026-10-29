"""Independent reader counterexamples. Synthetic data only; never launches code."""
import ast
import copy
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from . import review, runner, validation
from .test_run import normal_result


def transition(initial_position=3, initial_moves=0, initial_draws=0, events=None):
    events = events or ['right', 'right', 'left', 'escape']
    result, profile, image = normal_result()
    initial = struct.pack('<5I', 0x31574f43, 1, initial_position, initial_moves, initial_draws)
    position, moves = initial_position, initial_moves
    for event in events[:-1]:
        after = max(0, position - 1) if event == 'left' else min(7, position + 1)
        moves = (moves + (after != position)) & 0xffffffff
        position = after
    presents = 2 + sum((event in ('left', 'right')) for event in events[:-1])
    saved = struct.pack('<5I', 0x31574f43, 1, position, moves, (initial_draws + presents) & 0xffffffff)
    guest = [0] * 15
    guest[3] = len(events) - (events[-1] == 'close')
    guest[6] = int(events[-1] == 'close')
    guest[7:11] = [1, presents, 1, 20]
    guest[13] = 1
    profile['observations'] = {name: {'rva': index * 4096, 'size': size}
                               for index, (name, size) in enumerate((('window_state', 20), ('window_result', 60), ('window_load_result', 36)))}
    result['observations'] = dict(window_state=saved.hex(), window_result=struct.pack('<15I', *guest).hex(),
                                  window_load_result=struct.pack('<9I', 1, 0, 1, 0, 0, 0, 2, 0, 0).hex())
    result['saved_file']['data_hex'] = saved.hex()
    result['switch_commits'] = events.count('right')
    result['host_after_finish']['cocoa_key_events'] = 2 * guest[3]
    result['d3d_before_cleanup']['present_calls'] = presents
    actions = {'events': list(events)}
    return result, profile, initial, actions


class IndependentReviewTests(unittest.TestCase):
    def test_real_event_transition_and_boundary7_counter_are_required(self):
        for kwargs in ({}, {'initial_position': 7, 'events': ['right', 'escape']},
                       {'initial_position': 0, 'events': ['left', 'right', 'close']},
                       {'initial_moves': 0xffffffff, 'initial_draws': 0xffffffff, 'events': ['right', 'escape']}):
            with self.subTest(kwargs=kwargs):
                result, profile, initial, actions = transition(**kwargs)
                self.assertEqual(review.event_state(result, profile, initial, actions), bytes.fromhex(result['saved_file']['data_hex']))

    def test_static_only_or_wrong_counter_cannot_prove_switch_runtime(self):
        original, profile, initial, actions = transition()
        for value in (0, 1, True, -1, 100):
            result = copy.deepcopy(original)
            result['switch_commits'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                review.event_state(result, profile, initial, actions)

    def test_missing_right_wrong_state_repeat_or_legacy_profile_is_rejected(self):
        original, profile, initial, actions = transition()
        invalid = []
        result = copy.deepcopy(original); result['observations']['window_state'] = initial.hex(); invalid.append((result, actions))
        result = copy.deepcopy(original); result['host_after_finish']['cocoa_key_events'] = 0; invalid.append((result, actions))
        invalid.append((original, {'events': ['left', 'escape']}))
        invalid.append((original, {'events': ['right', 'escape', 'right']}))
        result = copy.deepcopy(original)
        words = list(struct.unpack('<15I', bytes.fromhex(result['observations']['window_result'])))
        words[4] = 1; result['observations']['window_result'] = struct.pack('<15I', *words).hex(); invalid.append((result, actions))
        for index, (result, events) in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(ValueError):
                review.event_state(result, profile, initial, events)
        result, runtime_profile, image = normal_result()
        runtime_profile.update(schema=1, runtime_contract='win32-d3d11-tile-v1')
        with self.assertRaisesRegex(ValueError, 'versioned switch'):
            validation.validate_result(result, 0, runtime_profile, image, runtime_profile['pe_sha256'])

    def test_supervisor_rejects_v5_before_static_verifier_or_any_launch(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'result.json').write_text(json.dumps(dict(schema=1, profile='window-portable-v5', status=runner.pipeline.STATUS)))
            with mock.patch.object(runner.pipeline, 'verify', side_effect=AssertionError('must reject before verifier')), \
                 mock.patch.object(runner.subprocess, 'Popen', side_effect=AssertionError('must not launch')):
                with self.assertRaisesRegex(ValueError, 'only successful migration_v6'):
                    runner.load_product(root)

    def test_review_has_no_production_or_execution_imports_and_rejects_bad_pin(self):
        source = Path(review.__file__).read_text()
        names = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                names.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or '').split('.')[0])
        self.assertLessEqual(names, {'argparse', 'hashlib', 'json', 'pathlib', 'plistlib', 're', 'stat', 'struct', 'uuid'})
        with tempfile.TemporaryDirectory() as temporary:
            product = Path(temporary).resolve()
            with self.assertRaisesRegex(ValueError, 'explicit product receipt SHA'):
                review.review(product, [], 'not-a-hash')
            self.assertFalse((product / 'result.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
