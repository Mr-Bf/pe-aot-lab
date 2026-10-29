"""Independent frozen-file reader of switch-enabled Cocoa runs.

Stdlib only. No production validator, subprocess, live AppData, native or UI
operation is imported or invoked. Writes only the requested new JSON result.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import stat
import struct
import uuid

ROOT = Path(__file__).resolve().parents[1]
PS = ['/bin/ps', '-ww', '-axo', 'pid=,ppid=,comm=']
OBSERVED = {}
NAMES = {'d3d11.dylib', 'dxgi.dylib', 'winemetal.dylib'}
FIELDS = set('switch_commits outcome aot_status setup_status pe_sha256 image_base entry_rva entry_arguments host_exit_code proc_translated proc_translated_errno timed_out join_status host_finished exit_requested exit_code exit_pc exit_rsp exit_depth returned steps call_depth fault rax rsp rip d3d_cleanup_result d3d_before_cleanup d3d_after_cleanup callback_stats user32_stats user32_end_status host_before_finish host_after_finish files test_queue observations saved_file'.split())
D3D = set('create_device_calls create_texture_calls create_rtv_calls clear_calls copy_calls map_calls unmap_calls get_removed_calls release_calls exit_calls this_checks created guest_released cleanup_releases cleanup_unmaps map_bytes_copied map_postcall_failures live_objects active_maps last_native_release create_vs_calls create_ps_calls create_rasterizer_calls om_set_calls rs_set_calls viewport_calls topology_calls vs_set_calls ps_set_calls draw_calls create_swapchain_calls present_calls get_buffer_calls clear_state_calls flush_calls cleanup_clear_state_calls cleanup_flush_calls'.split())
HOST = set('windows_created windows_destroyed forced_cleanup_windows views_created views_released active_views cocoa_key_events cocoa_window_events test_queue_events focus_recovery_events guest_queue_events ignored_keys messages_taken waits quit_messages queue_overflows main_dispatches event_pumps close_requests resize_events api_focus_transitions sent_notifications pending_messages error stopped worker_bound paint_invalid tombstones'.split())

def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, expected=None):
    path = Path(path).absolute()
    need(path == path.resolve() and path.is_file() and stat.S_ISREG(path.stat().st_mode), 'aliased or nonregular file: ' + str(path))
    data = path.read_bytes()
    value = digest(data)
    need(expected is None or expected == value, 'hash differs: ' + str(path))
    need(str(path) not in OBSERVED or OBSERVED[str(path)] == value, 'input changed: ' + str(path))
    OBSERVED[str(path)] = value
    return data


def pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, 'duplicate JSON key')
        out[key] = value
    return out


def js(path, expected=None):
    return json.loads(read(path, expected), object_pairs_hook=pairs,
                      parse_constant=lambda value: need(False, 'nonfinite JSON: ' + value))


def identities(values):
    for path, value in values.items():
        read(path, value)


def tree(base, data=False):
    need(base == base.resolve() and base.is_dir(), 'noncanonical tree root')
    result = {}
    for path in sorted(base.rglob('*')):
        mode = path.lstat().st_mode
        need(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'tree contains special file/link')
        if stat.S_ISREG(mode):
            value = read(path)
            result[path.relative_to(base).as_posix()] = {'sha256': digest(value), **(
                {'size': len(value)} if data else {'mode': stat.S_IMODE(mode)})}
    return result


def system(path):
    return path.startswith(('/usr/lib/', '/System/Library/')) and '..' not in Path(path).parts


def image(path, expected_type):
    raw = read(path)
    need(len(raw) >= 32, 'truncated Mach-O')
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', raw)
    need((magic, cpu, kind) == (0xfeedfacf, 0x100000c, expected_type), 'thin ARM64 image required')
    need(0 < count < 4096 and 32 + size <= len(raw), 'bad load command span')
    result = {'uuid': None, 'minimum': None, 'rpaths': [], 'dependencies': [], 'id': None}
    at = 32
    for _ in range(count):
        command, length = struct.unpack_from('<II', raw, at)
        need(length >= 8 and at + length <= 32 + size, 'load command bounds')
        if command == 0x1b:
            need(length == 24 and result['uuid'] is None, 'duplicate or invalid UUID')
            result['uuid'] = str(uuid.UUID(bytes=raw[at + 8:at + 24])).upper()
        elif command == 0x32:
            platform, version = struct.unpack_from('<II', raw, at + 8)
            need(platform == 1, 'non-macOS image')
            result['minimum'] = [version >> 16, (version >> 8) & 255, version & 255]
        elif command in (0xc, 0xd, 0x80000018, 0x8000001f, 0x20, 0x80000023, 0x8000001c):
            offset = struct.unpack_from('<I', raw, at + 8)[0]
            need(12 <= offset < length, 'bad load string offset')
            value = raw[at + offset:at + length]
            need(b'\0' in value, 'unterminated load string')
            value = value.split(b'\0')[0].decode()
            if command == 0xd:
                need(result['id'] is None, 'duplicate ID'); result['id'] = value
            elif command == 0x8000001c:
                result['rpaths'].append(value)
            else:
                result['dependencies'].append(value)
        at += length
    need(at == size + 32 and result['uuid'] is not None and result['minimum'] == [15, 2, 0], 'image identity/deployment mismatch')
    return result


def app_images(app, receipt):
    need(tree(app) == receipt['app_tree'], 'executed App bytes/modes/set differ')
    plist = plistlib.loads(read(app / 'Contents/Info.plist'))
    need(plist['CFBundleIdentifier'] == receipt['spec']['identifier'] and plist['LSMinimumSystemVersion'] == '15.2', 'App plist differs')
    executable = app / 'Contents/MacOS/pe-aot-window'
    paths = [executable, *(app / 'Contents/Frameworks' / name for name in sorted(NAMES))]
    result = {}
    for path in paths:
        is_exe = path == executable
        node = image(path, 2 if is_exe else 6)
        need(node['rpaths'] == (['@executable_path/../Frameworks'] if is_exe else ['@loader_path/']), 'external/residual rpath')
        need(is_exe or node['id'] == '@rpath/' + path.name, 'nonrelative library ID')
        need(all(system(name) or name in {'@rpath/' + n for n in NAMES} for name in node['dependencies']), 'external dependency name')
        result[str(path)] = node['uuid']
    need(digest(read(executable)) == receipt['executable_sha256'], 'executed main digest differs')
    return result


def pe_identity(raw, profile):
    offset = struct.unpack_from('<I', raw, 0x3c)[0]
    need(raw[:2] == b'MZ' and raw[offset:offset + 4] == b'PE\0\0', 'not PE')
    machine, sections, _, _, _, optional, _ = struct.unpack_from('<HHIIIHH', raw, offset + 4)
    start = offset + 24
    need(machine == 0x8664 and struct.unpack_from('<H', raw, start)[0] == 0x20b, 'not x86-64 PE32+')
    entry = struct.unpack_from('<I', raw, start + 16)[0]
    base = struct.unpack_from('<Q', raw, start + 24)[0]
    observed = {}
    for name, expected in profile['observations'].items():
        candidates = []
        for i in range(sections):
            header = start + optional + i * 40
            virtual_size, rva, disk_size, disk = struct.unpack_from('<4I', raw, header + 8)
            if rva <= expected['rva'] and expected['rva'] + expected['size'] <= rva + disk_size:
                begin = disk + expected['rva'] - rva
                candidates.append(raw[begin:begin + expected['size']].hex())
        need(len(candidates) == 1, 'observation does not map uniquely to PE bytes')
        observed[name] = candidates[0]
    return base, entry, observed


def process_rows(raw):
    result, seen = [], set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*(\d+)\s+(\d+)\s+(.+)', line)
        need(match is not None, 'unparseable process row')
        pid, parent, path = int(match[1]), int(match[2]), match[3]
        need(pid > 0 and pid not in seen, 'duplicate process PID'); seen.add(pid)
        if Path(path).name == 'pe-aot-window':
            need(path.startswith('/') and path.endswith('/Contents/MacOS/pe-aot-window'), 'ambiguous launcher path')
            result.append({'pid': pid, 'ppid': parent, 'executable': path})
    return result


def process_file(path, embedded, earliest=None, latest=None):
    raw = js(path)
    need(raw['command'] == PS and raw['returncode'] == 0 and raw['stderr'] == '', 'process query failed/differs')
    need(all(embedded[k] == v for k, v in raw.items()), 'embedded process record differs from raw query')
    need(process_rows(raw['stdout']) == embedded['matching_project_app_processes'] == [], 'project App remains in process inventory')
    need((earliest is None or raw['observed_unix_ns'] >= earliest) and
         (latest is None or raw['observed_unix_ns'] <= latest), 'process query time differs')


def dyld(raw, pid, expected):
    loaded, transitions = {}, []
    for line in raw.splitlines():
        if not line.startswith('dyld['):
            continue
        match = re.fullmatch(r'dyld\[(\d+)\]: (.+)', line)
        need(match is not None and int(match[1]) == pid, 'mixed dyld PID')
        row = re.fullmatch(r'<([0-9A-Fa-f-]{36})> (/[^\n]+)', match[2])
        if row:
            identity, path = str(uuid.UUID(row[1])).upper(), row[2]
            need(path not in loaded or loaded[path] == identity, 'conflicting UUID for loaded image')
            loaded[path] = identity
        else:
            transition = re.fullmatch(r'move (?:loaded to delayed|delayed to loaded): ([^/\s]+)', match[2])
            need(transition is not None, 'unexpected dyld message'); transitions.append(transition[1])
    need({p: u for p, u in loaded.items() if not system(p)} == expected, 'actual loaded non-system closure differs')
    need(set(transitions) <= {Path(p).name for p in loaded}, 'unobserved transition image')
    return loaded


def counter(value, keys):
    need(type(value) is dict and set(value) == set(keys) and
         all(type(n) is int and 0 <= n <= 0xffffffffffffffff for n in value.values()), 'counter schema/types differ')


def host_result(r, profile, pe, index):
    need(set(r) == FIELDS and r['timed_out'] is False and r['host_finished'] is True, 'result shape/completion differs')
    nested = set('outcome pe_sha256 timed_out host_finished fault d3d_before_cleanup d3d_after_cleanup callback_stats user32_stats host_before_finish host_after_finish files test_queue observations saved_file'.split())
    need(all(type(r[k]) is int and 0 <= r[k] <= 0xffffffffffffffff for k in FIELDS - nested), 'result scalar type differs')
    need(r['outcome'] == 'PROCESS_EXITED' and r['aot_status'] == 11 and r['exit_requested'] == 1 and r['returned'] == 0, 'not a normal guest exit')
    need(all(r[k] == 0 for k in ('setup_status', 'host_exit_code', 'exit_code', 'proc_translated', 'proc_translated_errno', 'join_status', 'd3d_cleanup_result', 'user32_end_status')), 'guest/host/cleanup/ISA failure')
    need(r['pe_sha256'] == profile['pe_sha256'] and (r['image_base'], r['entry_rva'], r['entry_arguments']) == (*pe[:2], 0), 'different PE/entry/base')
    need(0 < r['steps'] <= 100000000 and r['exit_rsp'] == r['rsp'] and r['exit_pc'] == r['rip'], 'step or exit state differs')
    need(0 < r['switch_commits'] <= r['steps'], 'no actual switch commit')
    counter(r['fault'], ('status', 'pc', 'address', 'width', 'access'))
    need(not any(r['fault'].values()), 'guest fault')
    for key in ('d3d_before_cleanup', 'd3d_after_cleanup'):
        d = r[key]; counter(d, D3D)
        need(all(d[k] == 0 for k in ('live_objects', 'active_maps', 'cleanup_releases', 'cleanup_unmaps', 'cleanup_clear_state_calls', 'cleanup_flush_calls', 'map_postcall_failures', 'last_native_release')), 'D3D leak/forced cleanup')
        need(d['created'] == d['guest_released'] == d['release_calls'] == 8 and d['present_calls'] == d['draw_calls'] > 0, 'actual draw/release lifecycle differs')
    need(r['d3d_before_cleanup'] == r['d3d_after_cleanup'], 'D3D cleanup changed state')
    c = r['callback_stats']; counter(c, ('calls', 'returns', 'rejections', 'depth', 'max_depth', 'end_status'))
    need(c['calls'] == c['returns'] > 0 and c['max_depth'] > 0 and c['rejections'] == c['depth'] == c['end_status'] == 0, 'callback did not unwind')
    for key in ('host_before_finish', 'host_after_finish'):
        h = r[key]; counter(h, HOST)
        need(all(h[k] == 0 for k in ('forced_cleanup_windows', 'active_views', 'test_queue_events', 'queue_overflows', 'pending_messages', 'paint_invalid')), 'host leak/forced cleanup')
        need(all(h[k] == 1 for k in ('windows_created', 'windows_destroyed', 'views_created', 'views_released', 'stopped', 'error', 'quit_messages')), 'single-window STOPPED lifecycle differs')
        need(h['cocoa_key_events'] > 0 and h['cocoa_window_events'] > 0 and h['close_requests'] <= 1, 'actual Cocoa event/close evidence differs')
    u = r['user32_stats']
    counter({k: v for k, v in u.items() if k != 'api_calls'}, 'callbacks sent_notifications posted_dispatches discarded_stale classes_registered classes_unregistered windows_created windows_destroyed registered window_state hwnd'.split())
    need(type(u['api_calls']) is list and len(u['api_calls']) == 14 and all(type(v) is int and v >= 0 for v in u['api_calls']), 'User32 vector differs')
    need(u['callbacks'] == c['calls'] and u['registered'] == 0 and u['window_state'] == 4 and all(u[k] == 1 for k in ('classes_registered', 'classes_unregistered', 'windows_created', 'windows_destroyed')), 'User32 lifecycle differs')
    f = r['files']; counter({k: v for k, v in f.items() if k != 'api_calls_4_to_9'}, 'last_error open_before_cleanup open_after_cleanup cleanup_closes cleanup_errors bytes_read bytes_written'.split())
    need(type(f['api_calls_4_to_9']) is list and len(f['api_calls_4_to_9']) == 6 and all(type(v) is int and v >= 0 for v in f['api_calls_4_to_9']), 'file API vector differs')
    need(all(f[k] == 0 for k in ('open_before_cleanup', 'open_after_cleanup', 'cleanup_closes', 'cleanup_errors')) and (f['bytes_read'], f['bytes_written']) == (20 * index, 20), 'guest file I/O/cleanup differs')
    q = r['test_queue']; counter({k: v for k, v in q.items() if k != 'events'}, ('requested', 'posted', 'injection_error', 'observed_hwnd'))
    need(q['events'] == [] and q['requested'] == q['posted'] == q['injection_error'] == 0, 'TEST_QUEUE used')
    need(type(r['observations']) is dict and set(r['observations']) == set(profile['observations']), 'observation closure differs')
    for name, item in profile['observations'].items():
        need(type(r['observations'][name]) is str and re.fullmatch('[0-9a-f]{%d}' % (item['size'] * 2), r['observations'][name]), 'observation encoding differs')
    saved = r['saved_file']
    need(set(saved) == {'name', 'errno', 'truncated', 'data_hex'} and saved['name'] == profile['save_observation'] and
         type(saved['errno']) is int and saved['errno'] == 0 and saved['truncated'] is False and
         isinstance(saved['data_hex'], str) and re.fullmatch('[0-9a-f]{40}', saved['data_hex']), 'save observation differs')
    return bytes.fromhex(saved['data_hex'])


def event_state(result, profile, initial, actions):
    """Independently recompute the fixed fixture's key-to-save transition."""
    events = actions.get('events')
    need(type(events) is list and 2 <= len(events) <= 100 and
         all(type(event) is str for event in events), 'explicit bounded event sequence required')
    need(events[-1] in ('escape', 'close') and
         all(event in ('left', 'right') for event in events[:-1]) and 'right' in events,
         'RIGHT followed by one normal exit action required')
    need(len(initial) == 20, 'initial fixed save length differs')
    state = list(struct.unpack('<5I', initial))
    need(state[:2] == [0x31574f43, 1] and state[2] <= 7, 'initial save invalid')
    for event in events[:-1]:
        before = state[2]
        if event == 'left':
            state[2] = max(0, before - 1)
        else:
            state[2] = min(7, before + 1)
        state[3] = (state[3] + (state[2] != before)) & 0xffffffff
    present = result['d3d_before_cleanup']['present_calls']
    state[4] = (state[4] + present) & 0xffffffff
    saved = bytes.fromhex(result['saved_file']['data_hex'])
    need(struct.unpack('<5I', saved) == tuple(state), 'Cocoa-event/save state transition differs')
    need(type(result['switch_commits']) is int and result['switch_commits'] == events.count('right') > 0,
         'actual switch commits do not match RIGHT actions')
    need(result['host_after_finish']['cocoa_key_events'] >= len(events) - (events[-1] == 'close'),
         'Cocoa key evidence insufficient for events')
    observations = result['observations']
    for name, size in (('window_state', 20), ('window_result', 60), ('window_load_result', 36)):
        need(name in profile['observations'] and profile['observations'][name]['size'] == size,
             'fixed fixture state observation required: ' + name)
    need(observations['window_state'] == saved.hex(), 'actual guest state and frozen save differ')
    counters = struct.unpack('<15I', bytes.fromhex(observations['window_result']))
    keydowns = len(events) - (events[-1] == 'close')
    need(counters[3] == keydowns and counters[4] == 0 and counters[6] == (events[-1] == 'close') and
         counters[7] == 1 and counters[8] == present and counters[9] == 1 and counters[10] == 20 and
         counters[13] == 1, 'guest key/close/render/save observations differ')
    return saved


def review_run(out, product, receipt, receipt_sha, profile, pe):
    out = Path(out).absolute()
    need(out == out.resolve() and out.parent == ROOT / 'build/migration-run-v3', 'canonical v3 run directory required')
    record = js(out / 'evidence.json')
    need(record['schema'] == 2 and record['status'] == 'ACTUAL_SWITCH_V6_APP_EXECUTION_OBSERVED_NOT_ACCEPTED',
         'run not eligible for independent review')
    need(type(record['pid']) is int and record['pid'] > 0 and record['dyld_pid'] == record['pid'], 'supervised PID differs')
    need(type(record['returncode']) is int and record['returncode'] == 0 and record['external_timeout'] is False,
         'run timeout/failure')
    need(record['product'] == str(product) and record['native_directory'] == str(product / 'native') and
         record['supported_product_profile'] == 'window-switch-v6', 'run product differs')
    need(record['product_receipt_sha256'] == receipt_sha and record['switch_leaf_rva'] == profile['switch_leaf_rva'],
         'run did not use expected product/switch root')
    for key in ('input_sha256', 'cpu_provider_sha256', 'graphics_provider_sha256', 'profile_sha256', 'executable_sha256'):
        need(record[key] == receipt[key], 'run identity differs: ' + key)
    need(record['identifier'] == receipt['spec']['identifier'] and type(record['relocated_copy']) is bool,
         'identifier/copy type differs')
    app = (out / 'relocated with spaces' / Path(receipt['app']).name) if record['relocated_copy'] else Path(receipt['app'])
    need(record['app'] == str(app) and record['command'] == [str(app / 'Contents/MacOS/pe-aot-window')] and
         type(record['argv_count']) is int and record['argv_count'] == 1, 'run target/arguments differ')
    images = app_images(app, receipt)
    need(record['expected_images'] == images and record['app_tree'] == receipt['app_tree'], 'image expectations differ')
    for name in ('started.json', 'prepared.json'):
        previous = js(out / name)
        need(all(record[k] == v for k, v in previous.items() if k != 'status'), 'run changed prepared/start identity')
    launched = js(out / 'launched.json')
    need(launched == {'pid': record['pid'], 'command': record['command'], 'cwd': str(out),
                     'launched_unix_ns': record['launched_unix_ns']}, 'raw launch receipt differs')
    need(record['started_unix_ns'] <= record['launched_unix_ns'] < record['ended_unix_ns'] and
         record['ended_unix_ns'] - record['launched_unix_ns'] < record['timeout_seconds'] * 1000000000,
         'supervision time differs')
    identities(record['sources'])
    need(record['product_app_sources_unchanged'] is True, 'run did not preserve inputs')
    process_file(out / 'processes-before.json', record['processes_before'], latest=record['launched_unix_ns'])
    process_file(out / 'processes-after.json', record['processes_after'], earliest=record['ended_unix_ns'])
    result = js(out / 'stdout', record['stdout_sha256'])
    need(result == record['result'], 'embedded host result differs from raw stdout')
    loaded = dyld(read(out / 'stderr', record['stderr_sha256']).decode(), record['pid'], images)
    need(loaded == record['loaded_images'], 'dyld record differs from raw stderr')
    for phase in ('before', 'after'):
        snapshot = record['data_' + phase]
        frozen = out / ('data-' + phase)
        need(type(snapshot['exists']) is bool, 'snapshot presence type differs')
        if snapshot['exists']:
            need(tree(frozen, data=True) == snapshot['files'], 'frozen Data differs')
        else:
            need(snapshot['files'] == {} and not frozen.exists() and not frozen.is_symlink(), 'absent snapshot differs')
    save_name = profile['save_observation']
    before = record['data_before']['files']
    need(set(before) in (set(), {save_name}) and set(record['data_after']['files']) == {save_name},
         'fixed fixture Data file set differs')
    restored = save_name in before
    saved = host_result(result, profile, pe, int(restored))
    need(read(out / 'data-after' / save_name) == saved, 'frozen disk save differs from host observation')
    initial = read(out / 'data-before' / save_name) if restored else bytes.fromhex(pe[2]['window_state'])
    load = struct.unpack('<9I', bytes.fromhex(result['observations']['window_load_result']))
    need(load[:6] == (1, int(restored), int(not restored), 0, 20 * restored, 0) and
         load[6:] == ((0, 0, 0) if restored else (2, 0, 0)), 'guest restore/missing observations differ')
    need(type(record['uid']) is int and record['uid'] >= 0, 'supervised uid differs')
    need(len(record['new_run_directories']) == 1 and len(set(record['existing_run_directories'])) == len(record['existing_run_directories']),
         'wrapper history set differs')
    run_id = record['new_run_directories'][0]
    need(str(uuid.UUID(run_id)).upper() == run_id and run_id not in record['existing_run_directories'], 'wrapper UUID invalid/reused')
    wrapper = out / 'wrapper-runs' / run_id
    need(set(tree(wrapper)) == {'entry-started.json', 'entry-finished.json'}, 'wrapper pair file set differs')
    start, finish = js(wrapper / 'entry-started.json'), js(wrapper / 'entry-finished.json')
    for item in (start, finish):
        need(type(item['schema']) is int and item['schema'] == 1 and type(item['pid']) is int and item['pid'] == record['pid'] and
             item['run_id'] == run_id and item['test_queue_requested'] is False, 'wrapper process/run/queue differs')
    support = record['expected_support']
    need(Path(support).is_absolute() and Path(support) == Path(support).resolve() and
         support.endswith('/Library/Application Support/' + record['identifier']), 'support namespace differs')
    need(start['status'] == 'ENTRY_STARTED_NOT_ACCEPTED' and type(start['argument_count']) is int and start['argument_count'] == 1 and
         type(start['uid']) is int and start['uid'] == record['uid'] and start['bundle_identifier'] == record['identifier'] and
         start['bundle_path'] == str(app) and start['data_directory'] == support + '/Data' and
         start['run_directory'] == support + '/Runs/' + run_id and start['instance_lock_held'] is True and
         start['host_arguments'] == ['--data-dir', support + '/Data', '--budget', '100000000'], 'wrapper start/arguments differ')
    need(finish['status'] == 'HOST_RETURNED_NOT_ACCEPTED' and type(finish['host_returncode']) is int and finish['host_returncode'] == 0 and
         finish['instance_lock_held_until_host_return'] is True and finish['active_ever'] is True and finish['guest_window_key_ever'] is True and
         type(finish['final_activation_policy']) is int and finish['final_activation_policy'] == 0, 'wrapper finish/activation differs')
    actions = js(out / 'cua-actions.json')
    need(actions.get('kind') == 'TRANSCRIBED_ACTUAL_CUA_TOOL_ACTIONS_NOT_RAW_OS_TRACE' and
         type(actions.get('pid')) is int and actions['pid'] == record['pid'] and actions.get('app') == str(app) and
         actions.get('physical_keyboard') is False and
         actions.get('post_exit_policy') == 'No getApp/AX/screenshot after final exit action; wait supervisor then non-activating listApps only.',
         'Cocoa action transcript identity/scope differs')
    need(type(actions.get('actions')) is list and actions['actions'] and
         all(type(item) is dict and type(item.get('operation')) is str and item['operation'] and
             type(item.get('reported_wall_seconds')) in (float, int) and 0 <= item['reported_wall_seconds'] < float('inf')
             for item in actions['actions']), 'Cocoa action tool observations missing')
    event_state(result, profile, initial, actions)
    environment = js(out / 'launch-environment.json')
    need(environment['DYLD_PRINT_LIBRARIES'] == '1' and environment['DXMT_LOG_PATH'] == 'none' and
         environment['XDG_CACHE_HOME'] == str(out / 'cache') and environment['DXMT_SHADER_CACHE_PATH'] == str(out / 'cache/dxmt') and
         not any('TEST_QUEUE' in name or name.startswith('DYLD_INSERT') for name in environment), 'launch environment differs')
    return record, saved, dict(run=str(out), pid=record['pid'], app=str(app), steps=result['steps'],
        switch_commits=result['switch_commits'], events=actions['events'],
        presents=result['d3d_before_cleanup']['present_calls'], saved_words=list(struct.unpack('<5I', saved)),
        save_sha256=digest(saved), restored=restored, relocated=record['relocated_copy'], non_system_images=images)


def review(product, runs, receipt_sha):
    OBSERVED.clear()
    product = Path(product).absolute()
    need(product == product.resolve() and product.is_dir(), 'canonical product directory required')
    need(type(receipt_sha) is str and re.fullmatch('[0-9a-f]{64}', receipt_sha), 'explicit product receipt SHA required')
    read(__file__)
    receipt = js(product / 'result.json', receipt_sha)
    need(receipt['schema'] == 1 and receipt['profile'] == 'window-switch-v6' and
         receipt['status'] == 'BUILT_PORTABLE_WINDOW_APP_NOT_EXECUTED' and
         receipt['guest_executions'] == receipt['gpu_executions'] == 0, 'only successful static switch v6 product eligible')
    actual = tree(product)
    actual.pop('result.json')
    need(actual == receipt['files'], 'product ledger differs')
    identities(receipt['sources'])
    native = js(product / 'native/producer.json', receipt['producer_sha256'])
    package = js(product / 'package/package.json', receipt['package_sha256'])
    profile = js(product / 'profile.json', receipt['profile_sha256'])
    need(profile.get('schema') == 2 and profile.get('runtime_contract') == 'win32-d3d11-tile-switch-v1' and
         type(profile.get('switch_leaf_rva')) is int, 'versioned switch profile required')
    need(js(product / 'native/profile.json') == native['profile'] == profile, 'native profile differs')
    need(native['cpu_provider_sha256'] == receipt['cpu_provider_sha256'] and
         native['backend']['provider_sha256'] == receipt['graphics_provider_sha256'] and
         native['input_sha256'] == receipt['input_sha256'] == profile['pe_sha256'] and
         native['inputs_before'] == native['inputs_after'] and native['compile_inputs_before'] == native['compile_inputs_after'] and
         package['inputs_before'] == package['inputs_after'], 'native/package identities differ')
    pe = pe_identity(read(product / 'input.exe', receipt['input_sha256']), profile)
    need('window_state' in pe[2], 'fixed fixture initial state missing')
    records, saves, rows = [], [], []
    need(type(runs) is list and 1 <= len(runs) <= 2 and len(set(map(str, runs))) == len(runs), 'one or two distinct runs required')
    for out in runs:
        record, save, row = review_run(out, product, receipt, receipt_sha, profile, pe)
        records.append(record)
        saves.append(save)
        rows.append(row)
    if len(records) == 2:
        first, second = records
        need(first['pid'] != second['pid'] and first['ended_unix_ns'] < second['started_unix_ns'], 'runs not successive independent processes')
        need(first['sources'] == second['sources'] and first['expected_support'] == second['expected_support'], 'roundtrip source/namespace differs')
        need(first['data_after'] == second['data_before'] and read(Path(runs[1]) / 'data-before' / profile['save_observation']) == saves[0],
             'second input is not first frozen save')
        need(set(second['existing_run_directories']) == set(first['existing_run_directories'] + first['new_run_directories']),
             'roundtrip wrapper history differs')
        need(first['relocated_copy'] is False and second['relocated_copy'] is True, 'roundtrip must include original then relocated App')
    for path, expected in list(OBSERVED.items()):
        read(path, expected)
    need(tree(product) == {**receipt['files'], 'result.json': {'sha256': receipt_sha, 'mode': 0o644}}, 'product changed at review end')
    return dict(schema=1, status='PASS_SWITCH_V6_COCOA_RUNS_INDEPENDENTLY_REVIEWED', product=str(product),
        product_receipt_sha256=receipt_sha, checked_product_files=len(receipt['files']), unique_files_read=len(OBSERVED),
        files=dict(OBSERVED), runs=rows, roundtrip_verified=len(records) == 2,
        actual_right_path_and_switch_commits_verified=True, native_or_UI_commands_executed_by_reader=0,
        limitations=['CUA transcript is transcribed tool observations, not a raw OS input trace or physical keyboard claim.',
                     'Checks frozen Data only; direct bundle launch, not Finder/LaunchServices.',
                     'No pixel equivalence, performance, clean-machine or broader-game acceptance.',
                     'Static build receipt alone cannot satisfy the required positive runtime switch counter.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--product', type=Path, required=True)
    parser.add_argument('--product-receipt-sha', required=True)
    parser.add_argument('--run', type=Path, action='append', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    output = args.out.absolute()
    need(output == output.resolve() and not output.exists() and output.parent.is_dir(), 'new canonical output file required')
    for source in [args.product, *args.run]:
        source = source.absolute()
        need(not output.is_relative_to(source) and not source.is_relative_to(output), 'review output overlaps inputs')
    result = review(args.product, args.run, args.product_receipt_sha)
    with output.open('x') as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({k: result[k] for k in ('status', 'unique_files_read', 'checked_product_files', 'roundtrip_verified')}))


if __name__ == '__main__':
    main()
