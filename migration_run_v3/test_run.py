"""Synthetic records and temporary files only: no App, process or GUI launch."""
import copy
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from . import runner, validation as v


def normal_result():
    """Explicit synthetic single-window lifecycle, never an execution receipt."""
    profile = dict(schema=2, runtime_contract='win32-d3d11-tile-switch-v1', switch_leaf_rva=0x1c30, pe_sha256='a' * 64, observations={}, save_observation='save.bin')
    image = SimpleNamespace(base=0x140000000, entry_rva=0x1000)
    d3d = {key: 0 for key in v.STATS}
    d3d.update(created=8, guest_released=8, release_calls=8, draw_calls=2, clear_calls=2, present_calls=2)
    host = {key: 0 for key in v.HOST}
    host.update(windows_created=1, windows_destroyed=1, views_created=1, views_released=1,
                stopped=1, error=1, quit_messages=1, cocoa_key_events=2, cocoa_window_events=3)
    user = dict(callbacks=3, sent_notifications=1, posted_dispatches=2, discarded_stale=0,
                classes_registered=1, classes_unregistered=1, windows_created=1, windows_destroyed=1,
                registered=0, window_state=4, hwnd=123, api_calls=[1] * 14)
    result = dict(outcome='PROCESS_EXITED', aot_status=11, setup_status=0, pe_sha256=profile['pe_sha256'],
                  image_base=image.base, entry_rva=image.entry_rva, entry_arguments=0, host_exit_code=0,
                  proc_translated=0, proc_translated_errno=0, timed_out=False, join_status=0, host_finished=True,
                  exit_requested=1, exit_code=0, exit_pc=0x230000000, exit_rsp=0x70000000, exit_depth=1,
                  returned=0, steps=100, switch_commits=1, call_depth=1, fault=dict(status=0, pc=0, address=0, width=0, access=0),
                  rax=1, rsp=0x70000000, rip=0x230000000, d3d_cleanup_result=0,
                  d3d_before_cleanup=d3d, d3d_after_cleanup=copy.deepcopy(d3d),
                  callback_stats=dict(calls=3, returns=3, rejections=0, depth=0, max_depth=1, end_status=0),
                  user32_stats=user, user32_end_status=0, host_before_finish=host, host_after_finish=copy.deepcopy(host),
                  files=dict(last_error=0, open_before_cleanup=0, open_after_cleanup=0, cleanup_closes=0,
                             cleanup_errors=0, bytes_read=0, bytes_written=4, api_calls_4_to_9=[2, 1, 0, 1, 1, 0]),
                  test_queue=dict(requested=0, posted=0, injection_error=0, observed_hwnd=123, events=[]),
                  observations={}, saved_file=dict(name='save.bin', errno=0, truncated=False, data_hex='01000000'))
    return result, profile, image


def wrapper_records():
    run_id = '5B2B3538-D742-49BB-9735-1A4C7F0BB09C'
    args = dict(pid=4242, run_id=run_id, identifier='org.peaotlab.synthetic', app=Path('/new app/Product.app'),
                data=Path('/home/Library/Application Support/org.peaotlab.synthetic/Data'),
                runs=Path('/home/Library/Application Support/org.peaotlab.synthetic/Runs'), uid=501)
    start = dict(schema=1, status='ENTRY_STARTED_NOT_ACCEPTED', pid=args['pid'], uid=501, run_id=run_id,
                 bundle_identifier=args['identifier'], bundle_path=str(args['app']), argument_count=1,
                 data_directory=str(args['data']), run_directory=str(args['runs'] / run_id), instance_lock_held=True,
                 host_arguments=['--data-dir', str(args['data']), '--budget', '100000000'], test_queue_requested=False)
    finish = dict(schema=1, status='HOST_RETURNED_NOT_ACCEPTED', pid=args['pid'], run_id=run_id,
                  host_returncode=0, instance_lock_held_until_host_return=True, test_queue_requested=False,
                  active_ever=True, guest_window_key_ever=True, final_activation_policy=0)
    return start, finish, args


class SupervisionTests(unittest.TestCase):
    def validate(self, result, profile, image):
        return v.validate_result(result, 0, profile, image, profile['pe_sha256'])

    def test_normal_synthetic_result_uses_explicit_profile_without_legacy_path(self):
        result, profile, image = normal_result()
        self.assertEqual(self.validate(result, profile, image), b'\x01\0\0\0')
        profile['save_observation'] = 'different.bin'
        with self.assertRaisesRegex(ValueError, 'saved-file'):
            self.validate(result, profile, image)

    def test_fault_queue_identity_exit_and_cleanup_counterexamples(self):
        original, profile, image = normal_result()
        changes = [(('switch_commits',), 0), (('switch_commits',), True), (('switch_commits',), 101),
                   (('proc_translated',), 1), (('proc_translated_errno',), 2), (('steps',), True),
                   (('steps',), v.BUDGET + 1), (('pe_sha256',), 'b' * 64), (('entry_rva',), 1),
                   (('timed_out',), 0), (('exit_code',), 1), (('fault', 'address'), 32),
                   (('test_queue', 'requested'), 1), (('test_queue', 'events'), [{}]),
                   (('host_before_finish', 'test_queue_events'), 1),
                   (('host_after_finish', 'forced_cleanup_windows'), 1),
                   (('d3d_after_cleanup', 'cleanup_releases'), 1), (('callback_stats', 'returns'), 2),
                   (('files', 'cleanup_closes'), 1), (('saved_file', 'truncated'), True),
                   (('saved_file', 'errno'), False), (('user32_stats', 'registered'), 1)]
        for keys, value in changes:
            result = copy.deepcopy(original)
            target = result
            for key in keys[:-1]:
                target = target[key]
            target[keys[-1]] = value
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                self.validate(result, profile, image)
        with self.assertRaises(ValueError):
            v.validate_result(original, False, profile, image, profile['pe_sha256'])

    def test_wrapper_requires_exact_child_pid_paths_types_and_lock_declarations(self):
        start, finish, args = wrapper_records()
        v.validate_wrapper(start, finish, **args)
        for side, key, value in (('start', 'pid', 4243), ('finish', 'pid', True),
                                 ('start', 'argument_count', True), ('start', 'bundle_path', '/old/Product.app'),
                                 ('start', 'run_id', str(uuid.uuid4()).upper()), ('start', 'instance_lock_held', 1),
                                 ('finish', 'host_returncode', False), ('finish', 'test_queue_requested', 0),
                                 ('finish', 'guest_window_key_ever', False), ('start', 'host_arguments', [])):
            a, b = copy.deepcopy(start), copy.deepcopy(finish)
            (a if side == 'start' else b)[key] = value
            with self.subTest(side=side, key=key), self.assertRaises(ValueError):
                v.validate_wrapper(a, b, **args)

    def test_process_inventory_catches_relocated_apps_outside_repository(self):
        expected = '/outside with spaces/Moved.app/Contents/MacOS/pe-aot-window'
        rows = runner.process_rows('  1 0 /sbin/launchd\n  4321 40 ' + expected + '\n  91 1 /usr/bin/other\n')
        self.assertEqual(rows, [dict(pid=4321, ppid=40, executable=expected)])
        for text in ('4321 40 pe-aot-window', 'bad ps row', '1 0 /a\n1 0 /b'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                runner.process_rows(text)

    def test_dyld_pid_paths_uuid_conflict_and_unknown_diagnostics_fail_closed(self):
        app = '/new app/Product.app/Contents/MacOS/pe-aot-window'
        identity = 'A6F7F596-EFBD-4BEF-92C0-70312A495AAE'
        line = f'dyld[4242]: <{identity}> {app}\n'
        expected = {app: identity}
        self.assertEqual(v.validate_dyld(line + line, 4242, expected), expected)
        for text in ('', line.replace('[4242]', '[4243]'), line.replace('/new app/', '/old app/'),
                     line + line.replace(identity, 'B6F7F596-EFBD-4BEF-92C0-70312A495AAE'),
                     line + 'dyld[4242]: unrecognized output\n',
                     line + 'dyld[4242]: move loaded to delayed: unobserved.dylib\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                v.validate_dyld(text, 4242, expected)

    def test_uuid_is_read_from_actual_thin_macho_bytes(self):
        with tempfile.TemporaryDirectory(prefix='runv3-uuid-') as temporary:
            path = Path(temporary) / 'image'
            identity = uuid.UUID('a6f7f596-efbd-4bef-92c0-70312a495aae')
            command = struct.pack('<II', 0x1b, 24) + identity.bytes
            path.write_bytes(struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 1, 24, 0, 0) + command)
            self.assertEqual(v.image_uuid(path), str(identity).upper())
            path.write_bytes(struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 2, 48, 0, 0) + command * 2)
            with self.assertRaises(ValueError):
                v.image_uuid(path)

    def test_saved_snapshots_are_frozen_and_symlinks_or_overlap_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix='runv3-data-') as temporary:
            root = Path(temporary).resolve()
            source = root / 'live'
            source.mkdir()
            (source / 'save.bin').write_bytes(b'first')
            before = runner.snapshot_data(source, root / 'before')
            (source / 'save.bin').write_bytes(b'second')
            after = runner.snapshot_data(source, root / 'after')
            self.assertNotEqual(before, after)
            self.assertEqual((root / 'before/save.bin').read_bytes(), b'first')
            self.assertEqual((root / 'after/save.bin').read_bytes(), b'second')
            with self.assertRaises(ValueError):
                runner.snapshot_data(source, source / 'snapshot')
            (source / 'alias').symlink_to(source / 'save.bin')
            with self.assertRaises(ValueError):
                runner.snapshot_data(source, root / 'bad')
            self.assertFalse((root / 'bad').exists())
            with self.assertRaises(ValueError):
                runner.disjoint(root, source)

    def test_unsupported_product_version_fails_before_any_native_action(self):
        with tempfile.TemporaryDirectory(prefix='runv3-version-') as temporary:
            root = Path(temporary).resolve()
            (root / 'result.json').write_text(json.dumps(dict(schema=1, profile='window-v4', status='BUILT_WINDOW_APP_NOT_EXECUTED')))
            with self.assertRaisesRegex(ValueError, 'only successful migration_v6'):
                runner.load_product(root)
            self.assertEqual({p.name for p in root.iterdir()}, {'result.json'})

    def test_timeout_cleanup_uses_only_supplied_child_handle(self):
        class Handle:
            def __init__(self, exited=False, slow=False):
                self.returncode = 0 if exited else None
                self.slow, self.calls = slow, []
            def poll(self):
                return self.returncode
            def terminate(self):
                self.calls.append('terminate')
            def kill(self):
                self.calls.append('kill')
            def wait(self, timeout):
                self.calls.append(('wait', timeout))
                if self.slow:
                    self.slow = False
                    raise subprocess.TimeoutExpired('synthetic child', timeout)
                self.returncode = -9 if 'kill' in self.calls else -15
                return self.returncode
        for child, code, calls in ((Handle(exited=True), 0, []),
                                   (Handle(), -15, ['terminate', ('wait', 3)]),
                                   (Handle(slow=True), -9, ['terminate', ('wait', 3), 'kill', ('wait', 3)])):
            self.assertEqual(runner.stop_child(child), code)
            self.assertEqual(child.calls, calls)


if __name__ == '__main__':
    unittest.main(verbosity=2)
