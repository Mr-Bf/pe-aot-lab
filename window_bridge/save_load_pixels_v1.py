"""Full-RGBA scene predicate whose initial position comes from prior saved bytes.

No process launch. Centers choose a candidate only; every pixel/channel is then
compared. Duplicate same-position frames are allowed, but ordered position
transitions must equal the fixed input workload starting at the restored state.
"""
from pathlib import Path
import struct
from window_bridge import window_pixels_v1 as scene


def initial_position(before_bytes):
    if before_bytes is None:
        return 3
    if type(before_bytes) is not bytes or len(before_bytes) != 20:
        raise ValueError('historical save must be exactly 20 bytes')
    magic, version, position, _, _ = struct.unpack('<5I', before_bytes)
    if magic != 0x31574F43 or version != 1 or position > 7:
        raise ValueError('invalid restored state for successful pixel workload')
    return position


def movement_positions(sequence, before_bytes):
    position = initial_position(before_bytes)
    positions = [position]
    for event in sequence:
        old = position
        if event == 'right' and position < 7:
            position += 1
        elif event == 'left' and position > 0:
            position -= 1
        elif event not in ('right', 'left', 'right-repeat', 'left-repeat', 'right-up', 'left-up', 'escape', 'close'):
            raise ValueError('unsupported event')
        if position != old:
            positions.append(position)
    return positions


def inspect_frames(directory, count, sequence, before_bytes):
    if type(count) is not int or not 1 <= count <= 64:
        raise ValueError('invalid capture frame count')
    expected = movement_positions(sequence, before_bytes)
    reports, transitions = [], []
    for index in range(1, count + 1):
        path = Path(directory) / f'frame-{index:06d}.rgba'
        if not path.is_file() or path.is_symlink():
            raise ValueError('regular actual RGBA artifact required')
        raw = path.read_bytes()
        if len(raw) != scene.WIDTH * scene.HEIGHT * 4:
            raise ValueError('incomplete RGBA artifact')
        candidates = []
        for position in range(8):
            offset = (180 * scene.WIDTH + 80 * position + 40) * 4
            if all(abs(a - b) <= scene.TOLERANCE for a, b in zip(raw[offset:offset + 4], scene.GREEN)):
                candidates.append(position)
        position = candidates[0] if len(candidates) == 1 else None
        report = scene.compare_frame(raw, expected[0] if position is None else position)
        report.update(frame=index, observed_position=position, center_candidates=candidates)
        reports.append(report)
        if not transitions or transitions[-1] != position:
            transitions.append(position)
    ok = all(r['matches'] and r['observed_position'] is not None for r in reports) and transitions == expected
    return {'status': 'PASS_FULL_RGBA_RESTORED_SCENE' if ok else 'FAIL_FULL_RGBA_RESTORED_SCENE',
            'initial_position': initial_position(before_bytes), 'expected_positions': expected,
            'observed_position_transitions': transitions, 'frames': reports,
            'checked_pixels': count * scene.WIDTH * scene.HEIGHT,
            'checked_channels': count * scene.WIDTH * scene.HEIGHT * 4,
            'tolerance_per_channel': scene.TOLERANCE,
            'scope': 'actual pre-Present backbuffer must start at historical saved position; fixed green/gray scene, no physical-input/compositor/performance claim'}
