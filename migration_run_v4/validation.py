"""Pure, strict observations for the frozen single-window runtime contract.

The field/type contract is derived from window_profile_v1.Program's pure
validate_execution method. This version accepts the validated profile directly;
it never constructs Program or reads its legacy window-profile.json path.
Only a normal guest ExitProcess endpoint is eligible for this supervisor.
"""
import re
import struct
import uuid
from pathlib import Path

from graphics_stage5 import d3d11_probe as graphics

BUDGET = 100000000
FIELDS = set('switch_commits outcome aot_status setup_status pe_sha256 image_base entry_rva entry_arguments host_exit_code proc_translated proc_translated_errno timed_out join_status host_finished exit_requested exit_code exit_pc exit_rsp exit_depth returned steps call_depth fault rax rsp rip d3d_cleanup_result d3d_before_cleanup d3d_after_cleanup callback_stats user32_stats user32_end_status host_before_finish host_after_finish files test_queue observations saved_file'.split())
STATS = set('create_device_calls create_texture_calls create_rtv_calls clear_calls copy_calls map_calls unmap_calls get_removed_calls release_calls exit_calls this_checks created guest_released cleanup_releases cleanup_unmaps map_bytes_copied map_postcall_failures live_objects active_maps last_native_release create_vs_calls create_ps_calls create_rasterizer_calls om_set_calls rs_set_calls viewport_calls topology_calls vs_set_calls ps_set_calls draw_calls create_swapchain_calls present_calls get_buffer_calls clear_state_calls flush_calls cleanup_clear_state_calls cleanup_flush_calls'.split())
HOST = set('windows_created windows_destroyed forced_cleanup_windows views_created views_released active_views cocoa_key_events cocoa_window_events test_queue_events focus_recovery_events guest_queue_events ignored_keys messages_taken waits quit_messages queue_overflows main_dispatches event_pumps close_requests resize_events api_focus_transitions sent_notifications pending_messages error stopped worker_bound paint_invalid tombstones'.split())


def need(value, message):
    if not value:
        raise ValueError(message)


def uint(value):
    return type(value) is int and 0 <= value <= 0xffffffffffffffff


def counters(value, fields):
    need(type(value) is dict and set(value) == set(fields) and all(uint(v) for v in value.values()),
         'counter fields/types differ')


def validate_result(result, returncode, profile, image, input_sha256):
    need(profile.get('schema') == 2 and profile.get('runtime_contract') == 'win32-d3d11-tile-switch-v1' and
         type(profile.get('switch_leaf_rva')) is int, 'versioned switch runtime profile required')
    need(type(returncode) is int and returncode == 0 and type(result) is dict and set(result) == FIELDS,
         'normal result field/exit contract differs')
    nested = set('outcome pe_sha256 timed_out host_finished fault d3d_before_cleanup d3d_after_cleanup callback_stats user32_stats host_before_finish host_after_finish files test_queue observations saved_file'.split())
    need(all(uint(result[k]) for k in FIELDS - nested), 'host scalar type differs')
    need(result['timed_out'] is False and result['host_finished'] is True, 'host timeout or unfinished execution')
    need(result['outcome'] == 'PROCESS_EXITED' and result['aot_status'] == 11 and
         result['exit_requested'] == 1 and result['returned'] == 0, 'guest ExitProcess endpoint differs')
    need(all(result[k] == 0 for k in ('setup_status', 'host_exit_code', 'exit_code', 'proc_translated',
                                    'proc_translated_errno', 'join_status', 'd3d_cleanup_result', 'user32_end_status')),
         'native/guest/cleanup failure')
    need(result['pe_sha256'] == input_sha256 == profile['pe_sha256'] and
         (result['image_base'], result['entry_rva'], result['entry_arguments']) == (image.base, image.entry_rva, 0),
         'actual PE/entry/base differs')
    need(0 < result['steps'] <= BUDGET and result['exit_rsp'] == result['rsp'] and result['exit_pc'] == result['rip'],
         'guest step budget/exit registers differ')
    need(0 < result['switch_commits'] <= result['steps'], 'actual switch commit required')
    counters(result['fault'], ('status', 'pc', 'address', 'width', 'access'))
    need(all(value == 0 for value in result['fault'].values()), 'guest fault')
    for name in ('d3d_before_cleanup', 'd3d_after_cleanup'):
        counters(result[name], STATS)
        need(all(result[name][key] == 0 for key in ('live_objects', 'active_maps', 'cleanup_releases', 'cleanup_unmaps',
                 'cleanup_clear_state_calls', 'cleanup_flush_calls', 'map_postcall_failures', 'last_native_release')),
             'D3D forced cleanup/leak')
    d3d = result['d3d_before_cleanup']
    need(d3d == result['d3d_after_cleanup'] and d3d['created'] == d3d['guest_released'] > 0 and
         d3d['present_calls'] > 0 and d3d['draw_calls'] > 0, 'guest rendering/release lifecycle differs')
    cb = result['callback_stats']
    counters(cb, ('calls', 'returns', 'rejections', 'depth', 'max_depth', 'end_status'))
    need(cb['calls'] == cb['returns'] > 0 and cb['max_depth'] > 0 and
         cb['rejections'] == cb['depth'] == cb['end_status'] == 0, 'callback completion differs')
    for name in ('host_before_finish', 'host_after_finish'):
        host = result[name]
        counters(host, HOST)
        need(all(host[k] == 0 for k in ('forced_cleanup_windows', 'active_views', 'test_queue_events',
                                      'queue_overflows', 'pending_messages', 'paint_invalid')),
             'host forced cleanup/queue failure')
        need(all(host[k] == 1 for k in ('windows_created', 'windows_destroyed', 'views_created', 'views_released',
                                      'stopped', 'error', 'quit_messages')), 'single-window STOPPED lifecycle differs')
    need(result['host_after_finish']['cocoa_key_events'] > 0,
         'actual switch commit after Cocoa input required')
    user = result['user32_stats']
    need(type(user) is dict, 'User32 statistics must be an object')
    counters({k: v for k, v in user.items() if k != 'api_calls'},
             ('callbacks', 'sent_notifications', 'posted_dispatches', 'discarded_stale', 'classes_registered',
              'classes_unregistered', 'windows_created', 'windows_destroyed', 'registered', 'window_state', 'hwnd'))
    need(type(user.get('api_calls')) is list and len(user['api_calls']) == 14 and all(map(uint, user['api_calls'])),
         'User32 call vector differs')
    need(user['callbacks'] == cb['calls'] and user['registered'] == 0 and user['window_state'] == 4 and
         all(user[k] == 1 for k in ('classes_registered', 'classes_unregistered', 'windows_created', 'windows_destroyed')),
         'User32 final lifecycle differs')
    files = result['files']
    need(type(files) is dict, 'file statistics must be an object')
    counters({k: v for k, v in files.items() if k != 'api_calls_4_to_9'},
             ('last_error', 'open_before_cleanup', 'open_after_cleanup', 'cleanup_closes', 'cleanup_errors', 'bytes_read', 'bytes_written'))
    need(type(files.get('api_calls_4_to_9')) is list and len(files['api_calls_4_to_9']) == 6 and
         all(map(uint, files['api_calls_4_to_9'])), 'file call vector differs')
    need(all(files[k] == 0 for k in ('open_before_cleanup', 'open_after_cleanup', 'cleanup_closes', 'cleanup_errors')),
         'file forced cleanup/leak')
    queue = result['test_queue']
    need(type(queue) is dict, 'queue statistics must be an object')
    counters({k: v for k, v in queue.items() if k != 'events'}, ('requested', 'posted', 'injection_error', 'observed_hwnd'))
    need(queue.get('events') == [] and queue['requested'] == queue['posted'] == queue['injection_error'] == 0,
         'TEST_QUEUE was used')
    observations = result['observations']
    need(type(observations) is dict and set(observations) == set(profile['observations']), 'observation closure differs')
    for name, item in profile['observations'].items():
        need(type(observations[name]) is str and re.fullmatch('[0-9a-f]{%d}' % (item['size'] * 2), observations[name]),
             'observation bytes differ')
    saved = result['saved_file']
    need(type(saved) is dict and set(saved) == {'name', 'errno', 'truncated', 'data_hex'} and
         saved['name'] == profile['save_observation'] and type(saved['errno']) is int and saved['errno'] == 0 and
         saved['truncated'] is False and type(saved['data_hex']) is str and
         re.fullmatch(r'(?:[0-9a-f]{2}){1,4096}', saved['data_hex']), 'successful saved-file observation required')
    need(files['bytes_written'] >= len(bytes.fromhex(saved['data_hex'])), 'guest did not account for saved bytes')
    return bytes.fromhex(saved['data_hex'])


def validate_wrapper(start, finish, *, pid, run_id, identifier, app, data, runs, uid):
    need(type(pid) is int and pid > 0 and str(uuid.UUID(run_id)).upper() == run_id, 'invalid process/run identity')
    need(type(start) is type(finish) is dict, 'wrapper records must be objects')
    need(start.get('status') == 'ENTRY_STARTED_NOT_ACCEPTED' and finish.get('status') == 'HOST_RETURNED_NOT_ACCEPTED',
         'wrapper state transition differs')
    for value in (start, finish):
        need(type(value.get('schema')) is int and value['schema'] == 1 and type(value.get('pid')) is int and
             value['pid'] == pid and value.get('run_id') == run_id and value.get('test_queue_requested') is False,
             'wrapper process/schema/run/queue identity differs')
    need(type(start.get('argument_count')) is int and start['argument_count'] == 1 and
         type(start.get('uid')) is int and start['uid'] == uid, 'wrapper argc/user differs')
    need(start.get('bundle_identifier') == identifier and start.get('bundle_path') == str(app) and
         start.get('data_directory') == str(data) and start.get('run_directory') == str(runs / run_id),
         'wrapper actual bundle/data directory differs')
    need(start.get('host_arguments') == ['--data-dir', str(data), '--budget', str(BUDGET)], 'wrapper host arguments differ')
    need(start.get('instance_lock_held') is True and finish.get('instance_lock_held_until_host_return') is True and
         type(finish.get('host_returncode')) is int and finish['host_returncode'] == 0, 'wrapper lock/return declaration differs')
    need(finish.get('active_ever') is True and finish.get('guest_window_key_ever') is True and
         type(finish.get('final_activation_policy')) is int and finish['final_activation_policy'] == 0,
         'wrapper activation observation differs')


def image_uuid(path):
    graphics.macho(path)
    raw = Path(path).read_bytes()
    count, size = struct.unpack_from('<II', raw, 16)
    position, found = 32, []
    for _ in range(count):
        command, length = struct.unpack_from('<II', raw, position)
        if command == 0x1b:
            need(length == 24, 'invalid Mach-O UUID command')
            found.append(str(uuid.UUID(bytes=raw[position + 8:position + 24])).upper())
        position += length
    need(position == 32 + size and len(found) == 1, 'one Mach-O image UUID required')
    return found[0]


def validate_dyld(text, pid, expected_images):
    need(type(pid) is int and pid > 0 and bool(expected_images), 'explicit process/images required')
    loaded, transitions = {}, []
    for line in text.splitlines():
        if not line.startswith('dyld['):
            continue
        match = re.fullmatch(r'dyld\[([0-9]+)\]: (.+)', line)
        need(match is not None and int(match[1]) == pid, 'dyld process identity differs')
        image = re.fullmatch(r'<([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})> (/[^\n]+)', match[2])
        if image:
            identity, name = image[1].upper(), image[2]
            need(name not in loaded or loaded[name] == identity, 'conflicting dyld image UUID')
            loaded[name] = identity
        else:
            transition = re.fullmatch(r'move (?:loaded to delayed|delayed to loaded): ([^/\s]+)', match[2])
            need(transition is not None, 'unknown dyld diagnostic')
            transitions.append(transition[1])
    need(loaded and set(transitions) <= {Path(name).name for name in loaded}, 'dyld image/transition evidence absent')
    need({name: identity for name, identity in loaded.items() if not graphics.system_image(name)} == expected_images,
         'actual loaded App image path/UUID closure differs')
    return loaded
