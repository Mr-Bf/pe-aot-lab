"""Read-only semantic acceptance for the frozen save-only window PE.

This consumes actual native execution records; it never starts a process or
changes guest memory. TEST_QUEUE input is explicitly not physical keyboard input.
No pixel correctness, Windows oracle, restoration, or performance claim follows.
"""
import argparse
import json
import struct
from pathlib import Path

from window_bridge import window_bindings as producer

PE_SHA256 = "a9997a6e542efee64c19d8a2ac343d28e294341a187ab954b9d8e0a6a9824da1"
RESULT_FIELDS = (
    "stage", "exit_code", "create_messages", "keydowns", "ignored_repeats",
    "paints", "closes", "destroys", "presents", "saves", "saved_bytes",
    "win32_error", "graphics_hr", "quit_requested", "dirty",
)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def semantic_acceptance(record):
    """Validate the completed fixed workload, after producer.verify_run."""
    r = record["result"]
    sequence = record["test_sequence"]
    require(isinstance(sequence, list) and sequence, "explicit workload required")
    require(sequence[-1] in ("escape", "close"), "final event must request exit")
    require(all(x not in ("escape", "close") for x in sequence[:-1]),
            "an early exit leaves later events unconsumed")
    require(r["pe_sha256"] == PE_SHA256, "original PE identity differs")
    require(r["outcome"] == "PROCESS_EXITED" and record["returncode"] == 0,
            "actual child did not exit normally")
    require(r["proc_translated"] == 0 and r["exit_requested"] == 1 and
            r["exit_code"] == 0 and r["fault"]["status"] == 0,
            "guest exit/ISA/fault differs")
    require(not r["timed_out"] and not record["external_timeout"], "timeout")
    require(r["steps"] > 0 and r["entry_arguments"] == 0, "entry not executed")
    queue = r["test_queue"]
    require(queue["posted"] == queue["requested"] == len(sequence) and
            queue["injection_error"] == 0, "incomplete workload")
    require([e["name"] for e in queue["events"]] == sequence and
            all(e["origin"] == 3 for e in queue["events"]), "input source differs")
    host = r["host_before_finish"]
    require(host["cocoa_key_events"] == 0, "real input contaminated deterministic workload")
    require(host["test_queue_events"] == len(sequence), "queue event count differs")

    position, moves, keydowns, repeats, closes = 3, 0, 0, 0, 0
    for event in sequence:
        if event == "close":
            closes += 1
        elif not event.endswith("-up"):
            keydowns += 1
            if event.endswith("-repeat"):
                repeats += 1
            elif event == "right" and position < 7:
                position += 1
                moves += 1
            elif event == "left" and position > 0:
                position -= 1
                moves += 1
    state_bytes = bytes.fromhex(r["observations"]["window_state"])
    require(len(state_bytes) == 20, "state layout differs")
    magic, version, actual_position, actual_moves, draws = struct.unpack("<5I", state_bytes)
    require((magic, version, actual_position, actual_moves) ==
            (0x31574F43, 1, position, moves), "guest movement/repeat semantics differ")
    require(draws >= 1 + moves, "guest did not render each changed position")
    result_bytes = bytes.fromhex(r["observations"]["window_result"])
    require(len(result_bytes) == 60, "result layout differs")
    observations = dict(zip(RESULT_FIELDS, struct.unpack("<15I", result_bytes)))
    expected = dict(stage=5, exit_code=0, create_messages=2, keydowns=keydowns,
                    ignored_repeats=repeats, closes=closes, destroys=1,
                    presents=draws, saves=1, saved_bytes=20, win32_error=0,
                    graphics_hr=0, quit_requested=1, dirty=0)
    require(all(observations[k] == v for k, v in expected.items()),
            "original PE observation counters differ")
    require(bytes.fromhex(r["observations"]["window_handle"]) == bytes(8),
            "guest retained its window handle")
    require(bytes.fromhex(r["observations"]["window_feature"]) == struct.pack("<I", 0xB000),
            "actual feature level differs")
    require(bytes.fromhex(r["observations"]["window_client"]) == struct.pack("<4i", 0, 0, 640, 360),
            "actual guest client rectangle differs")

    saved = r["saved_file"]
    require(saved["name"] == "integer-tile.bin" and saved["errno"] == 0 and
            not saved["truncated"] and saved["data_hex"] == state_bytes.hex(),
            "actual disk save differs from original PE state")
    disk = Path(record["data_directory"]) / saved["name"]
    require(not disk.is_symlink() and disk.is_file() and disk.read_bytes() == state_bytes,
            "saved artifact changed after execution")
    files = r["files"]
    require(files["bytes_written"] == 20 and files["bytes_read"] == 0 and
            files["api_calls_4_to_9"] == [1, 1, 0, 1, 0, 0],
            "guest file API trace differs")
    require(all(files[k] == 0 for k in ("open_before_cleanup", "open_after_cleanup",
                "cleanup_closes", "cleanup_errors")), "host cleanup masked guest file leak")

    d = r["d3d_before_cleanup"]
    require(d["exit_calls"] == 1, "guest ExitProcess count differs")
    for key in ("clear_calls", "om_set_calls", "rs_set_calls", "viewport_calls",
                "topology_calls", "vs_set_calls", "ps_set_calls", "draw_calls", "present_calls"):
        require(d[key] == draws, "Draw/Present call count differs: " + key)
    for key in ("create_swapchain_calls", "get_buffer_calls", "create_rtv_calls",
                "create_vs_calls", "create_ps_calls", "create_rasterizer_calls",
                "clear_state_calls", "flush_calls"):
        require(d[key] == 1, "graphics lifecycle count differs: " + key)
    require(d["created"] == d["guest_released"] == d["release_calls"] == 8,
            "guest graphics ownership is incomplete")
    require(all(d[k] == 0 for k in ("live_objects", "active_maps", "cleanup_releases",
                "cleanup_unmaps", "cleanup_clear_state_calls", "cleanup_flush_calls")),
            "host cleanup masked guest graphics leak")
    require(d == r["d3d_after_cleanup"] and r["d3d_cleanup_result"] == 0,
            "terminal cleanup changed graphics ownership")
    for h in (host, r["host_after_finish"]):
        require(h["windows_created"] == h["windows_destroyed"] == 1 and
                h["views_created"] == h["views_released"] == 1 and
                h["active_views"] == h["forced_cleanup_windows"] == h["queue_overflows"] == 0,
                "native window/view lifecycle differs")
    user = r["user32_stats"]
    require(user["classes_registered"] == user["classes_unregistered"] == 1 and
            user["windows_created"] == user["windows_destroyed"] == 1 and
            user["registered"] == 0 and user["window_state"] == 4,
            "guest User32 lifecycle incomplete")
    for signature in (201, 210, 211, 213, 215, 217, 218, 219, 220, 221):
        index = 0 if signature == 201 else signature - 209
        require(user["api_calls"][index] == 1, "User32 API count differs: " + str(signature))
    require(user["api_calls"][222 - 209] == observations["paints"],
            "paint validation count differs")
    callbacks = r["callback_stats"]
    require(callbacks["calls"] == callbacks["returns"] and callbacks["calls"] > 0 and
            callbacks["rejections"] == callbacks["depth"] == callbacks["end_status"] == 0,
            "callback completion differs")
    return {"position": position, "moves": moves, "draws": draws,
            "keydowns": keydowns, "ignored_repeats": repeats,
            "paint_messages": observations["paints"], "steps": r["steps"],
            "saved_bytes": len(state_bytes), "guest_released_objects": 8,
            "real_keyboard_events": host["cocoa_key_events"], "test_queue_events": len(sequence),
            "scope": "same original PE, TEST_QUEUE input, Draw/Present calls, save and exit; no pixel/read-load/performance acceptance"}


def verify(path):
    record = producer.verify_run(path)
    return semantic_acceptance(record)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.record), ensure_ascii=False, sort_keys=True))
