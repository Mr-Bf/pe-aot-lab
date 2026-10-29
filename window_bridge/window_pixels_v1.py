"""Independent full-RGBA predicate for the self-authored integer tile scene.

This reads actual capture bytes, not guest drawing counters or observer claims.
Only the fixed green/gray 640x360 scene is covered, not general color rendering.
"""
from pathlib import Path

WIDTH, HEIGHT = 640, 360
BACKGROUND = bytes((32, 32, 32, 255))
GREEN = bytes((0, 255, 0, 255))
TOLERANCE = 1


def expected_frame(position):
    if type(position) is not int or not 0 <= position <= 7:
        raise ValueError("invalid tile position")
    background_row = BACKGROUND * WIDTH
    tile_row = BACKGROUND * (80 * position) + GREEN * 80 + BACKGROUND * (560 - 80 * position)
    return background_row * 140 + tile_row * 80 + background_row * 140


def compare_frame(data, position):
    expected = expected_frame(position)
    if len(data) != len(expected):
        raise ValueError("incomplete RGBA frame")
    maximum = 0
    bad_channels = 0
    bad_pixels = 0
    previous_pixel = -1
    first = []
    for index, (actual, wanted) in enumerate(zip(data, expected)):
        difference = abs(actual - wanted)
        maximum = max(maximum, difference)
        if difference > TOLERANCE:
            bad_channels += 1
            pixel = index // 4
            if pixel != previous_pixel:
                bad_pixels += 1
                previous_pixel = pixel
            if len(first) < 8:
                first.append({"x": pixel % WIDTH, "y": pixel // WIDTH,
                              "channel": index % 4, "actual": actual, "expected": wanted})
    return {"expected_position": position, "checked_pixels": WIDTH * HEIGHT,
            "checked_channels": len(data), "max_channel_error": maximum,
            "mismatched_pixels": bad_pixels, "mismatched_channels": bad_channels,
            "first_mismatches": first, "matches": bad_channels == 0}


def movement_positions(sequence):
    position = 3
    positions = [position]
    for event in sequence:
        before = position
        if event == "right" and position < 7:
            position += 1
        elif event == "left" and position > 0:
            position -= 1
        elif event not in ("right", "left", "right-repeat", "left-repeat",
                            "right-up", "left-up", "escape", "close"):
            raise ValueError("unsupported event in pixel expectation")
        if position != before:
            positions.append(position)
    return positions


def inspect_frames(directory, frame_count, sequence):
    if type(frame_count) is not int or not 1 <= frame_count <= 64:
        raise ValueError("invalid observed frame count")
    expected_positions = movement_positions(sequence)
    frames = []
    seen_positions = []
    for index in range(1, frame_count + 1):
        data = (Path(directory) / f"frame-{index:06d}.rgba").read_bytes()
        if len(data) != WIDTH * HEIGHT * 4:
            raise ValueError("incomplete observed frame")
        # Centers only choose the candidate. All pixels/channels below still
        # have to match; a center sample alone never establishes a frame PASS.
        candidates = []
        for position in range(8):
            offset = (180 * WIDTH + 80 * position + 40) * 4
            if all(abs(a - b) <= TOLERANCE for a, b in zip(data[offset:offset+4], GREEN)):
                candidates.append(position)
        position = candidates[0] if len(candidates) == 1 else None
        # Even a missing tile is compared across the entire frame, so a real
        # clear-only negative retains pixel mismatch evidence instead of being
        # rejected solely on an API counter or an absent center sample.
        report = compare_frame(data, position if position is not None else expected_positions[0])
        report.update(frame=index, observed_position=position, center_candidates=candidates)
        frames.append(report)
        if not seen_positions or seen_positions[-1] != position:
            seen_positions.append(position)
    passed = all(f["matches"] and f["observed_position"] is not None for f in frames)
    passed = passed and seen_positions == expected_positions
    return {"status": "PASS_FULL_RGBA_SCENE" if passed else "FAIL_FULL_RGBA_SCENE",
            "frames": frames, "expected_positions": expected_positions,
            "observed_position_transitions": seen_positions,
            "checked_pixels": frame_count * WIDTH * HEIGHT,
            "checked_channels": frame_count * WIDTH * HEIGHT * 4,
            "tolerance_per_channel": TOLERANCE,
            "scope": "actual pre-Present backbuffer, fixed green/gray scene; not compositor/physical-input/general-color/performance evidence"}
