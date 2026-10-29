"""Read-only semantic acceptance for the frozen save/load window PE.

This consumes actual native execution records; it never starts a process or
changes guest memory. TEST_QUEUE input is explicitly not physical keyboard input.
Two-process restoration requires verify_roundtrip; no pixels, physical input or performance claim follows.
"""
import argparse
import json
import struct
from pathlib import Path

from window_bridge import save_load_bindings_v1 as producer

PE_SHA256 = "0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976"
SEQUENCE = ["right", "right-repeat", "right-up", "right", "right-up", "left", "left-up", "escape"]
RESULT_FIELDS = (
    "stage", "exit_code", "create_messages", "keydowns", "ignored_repeats",
    "paints", "closes", "destroys", "presents", "saves", "saved_bytes",
    "win32_error", "graphics_hr", "quit_requested", "dirty",
)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def semantic_acceptance(record, before_bytes, after_bytes):
    """Pure semantic check of supplied snapshots, after producer.verify_run.

    Never read phase-1 output from the current shared disk: phase 2 legitimately
    replaced it. This function does not authenticate a caller-forged record.
    """
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

    require(sequence == SEQUENCE, "closed roundtrip workload differs")
    require(before_bytes is None or type(before_bytes) is bytes, "before must be bytes or None")
    require(type(after_bytes) is bytes and len(after_bytes) == 20, "after snapshot must be 20 bytes")
    if before_bytes is None:
        initial = (0x31574F43, 1, 3, 0, 0)
    else:
        require(len(before_bytes) == 20, "before snapshot must be 20 bytes")
        initial = struct.unpack("<5I", before_bytes)
        require(initial[:2] == (0x31574F43, 1) and initial[2] <= 7, "invalid successful-restore input format")
    position, moves, initial_draws = initial[2], initial[3], initial[4]
    keydowns, repeats, closes, current_moves = 0, 0, 0, 0
    for event in sequence:
        if event == "close":
            closes += 1
        elif not event.endswith("-up"):
            keydowns += 1
            if event.endswith("-repeat"):
                repeats += 1
            elif event == "right" and position < 7:
                position += 1
                moves = (moves + 1) & 0xffffffff
                current_moves += 1
            elif event == "left" and position > 0:
                position -= 1
                moves = (moves + 1) & 0xffffffff
                current_moves += 1
    state_bytes = bytes.fromhex(r["observations"]["window_state"])
    require(len(state_bytes) == 20, "state layout differs")
    magic, version, actual_position, actual_moves, draws = struct.unpack("<5I", state_bytes)
    require((magic, version, actual_position, actual_moves) ==
            (0x31574F43, 1, position, moves), "guest movement/repeat semantics differ")
    current_presents = r["d3d_before_cleanup"]["present_calls"]
    require(type(current_presents) is int and 1 + current_moves <= current_presents <= 0xffffffff,
            "guest did not render each changed position")
    require(draws == (initial_draws + current_presents) & 0xffffffff,
            "persisted draws must be initial total plus current presents")
    result_bytes = bytes.fromhex(r["observations"]["window_result"])
    require(len(result_bytes) == 60, "result layout differs")
    observations = dict(zip(RESULT_FIELDS, struct.unpack("<15I", result_bytes)))
    expected = dict(stage=5, exit_code=0, create_messages=2, keydowns=keydowns,
                    ignored_repeats=repeats, closes=closes, destroys=1,
                    presents=current_presents, saves=1, saved_bytes=20, win32_error=0,
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
    require(after_bytes == state_bytes, "historical after snapshot differs from actual guest state")
    load_bytes = bytes.fromhex(r["observations"]["window_load_result"])
    require(len(load_bytes) == 36, "load observation layout")
    load = list(struct.unpack("<9I", load_bytes))
    expected_load = [1,0,1,0,0,0,2,0,0] if before_bytes is None else [1,1,0,0,20,0,0,0,0]
    require(load == expected_load, "guest load attempt/EOF/validation/close observations differ")
    candidate = bytes.fromhex(r["observations"]["window_load_candidate"])
    require(candidate == (bytes(20) if before_bytes is None else before_bytes), "guest load candidate is not actual prior file bytes")
    require(bytes.fromhex(r["observations"]["window_load_count"]) == struct.pack("<I", 0 if before_bytes is None else 20)
            and bytes.fromhex(r["observations"]["window_load_extra_count"]) == bytes(4)
            and bytes.fromhex(r["observations"]["window_load_extra"]) == bytes(1), "load count/EOF byte output differs")
    files = r["files"]
    expected_calls = [2,1,0,1,1,0] if before_bytes is None else [2,1,2,2,0,0]
    require(files["bytes_written"] == 20 and files["bytes_read"] == (0 if before_bytes is None else 20)
            and files["api_calls_4_to_9"] == expected_calls, "guest file API trace differs")
    # Success does not universally clear Win32 LastError. In particular the
    # second CREATE_ALWAYS normally leaves ERROR_ALREADY_EXISTS (183).
    require(type(files["last_error"]) is int and 0 <= files["last_error"] <= 0xffffffff,
            "LastError type/range differs")
    # This fixed local profile leaves the final CREATE_ALWAYS result in its
    # shared LastError: new file -> 0; existing file -> 183. Later successful
    # WriteFile/CloseHandle and admitted teardown calls preserve it. This is
    # not a claim that every successful general Win32 API preserves LastError.
    require(files["last_error"] == (0 if before_bytes is None else 183),
            "fixed profile LastError after actual CREATE_ALWAYS differs")
    require(all(files[k] == 0 for k in ("open_before_cleanup", "open_after_cleanup",
                "cleanup_closes", "cleanup_errors")), "host cleanup masked guest file leak")

    d = r["d3d_before_cleanup"]
    require(d["exit_calls"] == 1, "guest ExitProcess count differs")
    for key in ("clear_calls", "om_set_calls", "rs_set_calls", "viewport_calls",
                "topology_calls", "vs_set_calls", "ps_set_calls", "draw_calls", "present_calls"):
        require(d[key] == current_presents, "Draw/Present call count differs: " + key)
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
    return {"position": position, "moves": moves, "persisted_draws": draws,
            "initial_position": initial[2], "initial_moves": initial[3], "initial_draws": initial_draws,
            "current_moves": current_moves, "current_presents": current_presents,
            "load_observations": load, "restored": before_bytes is not None,
            "file_api_calls": expected_calls, "bytes_read": files["bytes_read"], "last_error": files["last_error"],
            "keydowns": keydowns, "ignored_repeats": repeats,
            "paint_messages": observations["paints"], "steps": r["steps"],
            "saved_bytes": len(state_bytes), "guest_released_objects": 8,
            "real_keyboard_events": host["cocoa_key_events"], "test_queue_events": len(sequence),
            "scope": "same original save/load PE with supplied historical before/after snapshots; no pixel/physical-key/performance acceptance"}


accept = semantic_acceptance


def _regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "regular historical artifact required: " + str(path))
    return path.read_bytes()


def verify_record(path, before_bytes, after_bytes):
    """Read-only producer identity + semantic check of historical snapshots."""
    record = producer.verify_run(Path(path).resolve())
    # verify_run has already used Program.from_build and checked every producer
    # input/header/IR/object. Read that verified receipt without recompiling or
    # repeating the full dependency scan for a second time.
    program_dir = Path(record["program_out"])
    build = producer.graphics.read_json(program_dir / "program-build.json")
    main = producer.graphics.read_json(program_dir / "compiler/main/manifest.json")
    require(build["input_sha256"] == PE_SHA256, "new save/load PE required")
    require(build["status"] == "BUILT_NATIVE_SAVE_LOAD_WINDOW_PE_NOT_EXECUTED",
            "wrong producer/profile receipt")
    reads = [i for i in build["imports"] if i["dll"] == "kernel32.dll" and i["name"] == "ReadFile"]
    require(len(reads) == 1 and reads[0]["signature"] == 6 and reads[0]["iat_rva"] == 0x2728,
            "actual new ReadFile import binding differs")
    require(main["profile"] == {
        "virtual_slots": sorted(producer.lifter.VIRTUAL_SLOTS),
        "new_scalar_shapes": ["CMOVNB reg32,reg32 with defined CF",
            "SETZ AL/SIL/DIL with defined ZF",
            "non-LOCK INC m32 [RIP+disp32] or [GPR64+0] excluding RSP/index; preserving CF definedness",
            "SETNZ CL/DL/SIL with defined ZF", "AND8 AL,CL/DL opcode20 only",
            "TEST16 AX,AX only", "exact observed 15/12/10-byte CS-prefixed NOP padding only"]},
        "new finite scalar profile differs")
    # verify_run/from_build already verify exact new lifter/loader/patch source
    # sets and regenerate all native headers. No old save-only object is used.
    return semantic_acceptance(record, before_bytes, after_bytes)


def verify_roundtrip(directory):
    """Accept two already-completed phases; no process launch or disk writes."""
    from window_bridge import save_load_roundtrip_v1 as coordinator
    directory = Path(directory).resolve()
    require(directory.is_dir() and not directory.is_symlink(), "real roundtrip directory required")
    start_path = directory / "coordinator.started.json"
    observed_path = directory / "coordinator-observed.json"
    start = producer.graphics.strict_json(_regular(start_path).decode())
    observed = producer.graphics.strict_json(_regular(observed_path).decode())
    attempt = producer.graphics.strict_json(_regular(directory / "attempt.json").decode())
    data_directory = directory / "data"
    save = data_directory / "integer-tile.bin"
    require(data_directory.is_dir() and not data_directory.is_symlink() and
            {p.name for p in data_directory.iterdir()} == {"integer-tile.bin"}, "exact shared file set differs")
    source_hash = producer.sha(coordinator.__file__)
    expected_start = {"status": "STARTED_NOT_ACCEPTED", "program": str(coordinator.PROGRAM),
        "program_build_sha256": producer.sha(coordinator.PROGRAM / "program-build.json"),
        "pe_sha256": PE_SHA256, "driver_sha256": source_hash, "data_directory": str(data_directory),
        "initial_files": [], "sequence": SEQUENCE, "budget": 1000000, "timeout_ms": 45000,
        "scope": "two starts of the same PE; original file retained between starts; no host restoration into guest memory"}
    require(start == expected_start, "coordinator initial inputs/command contract changed")
    require(attempt == {"status": "PREFLIGHT_NOT_EXECUTED", "driver_sha256": source_hash}, "coordinator attempt identity")
    require(set(observed) == {"status", "started_sha256", "phases", "final_shared_save", "new_guest_executions"}
            and observed["status"] == "TWO_ORIGINAL_PE_RUNS_OBSERVED_NOT_FINAL_ACCEPTANCE"
            and observed["started_sha256"] == producer.sha(start_path)
            and type(observed["new_guest_executions"]) is int and observed["new_guest_executions"] == 2,
            "two-phase coordinator receipt differs")
    require(type(observed["phases"]) is list and len(observed["phases"]) == 2, "exact two phases required")
    required = [Path(__file__), Path(coordinator.__file__), Path(producer.__file__),
                start_path, observed_path, directory / "attempt.json", save]
    for index in (1, 2):
        phase = directory / f"phase-{index}"
        required += [p for p in phase.rglob('*') if p.is_file()]
        required += [Path(p) for p in producer.graphics.read_json(phase / "run.json")["inputs_before"]]
    before_identity = producer.snapshot(required)
    prior = None
    pids = []
    accepted = []
    for index in (1, 2):
        phase = directory / f"phase-{index}"
        require(phase.is_dir() and not phase.is_symlink(), "real phase directory required")
        before_path, after_path = phase / "input-before.bin", phase / "saved-after.bin"
        before = None if index == 1 else _regular(before_path)
        require(before == prior, "phase 2 input snapshot is not phase 1 actual saved bytes")
        expected_before = {"name": "integer-tile.bin", "exists": index == 2,
            "sha256": None if before is None else producer.hashlib.sha256(before).hexdigest(),
            "data_hex": None if before is None else before.hex(), "size": None if before is None else len(before)}
        before_record = producer.graphics.strict_json(_regular(phase / "before.json").decode())
        require(type(before_record.get("exists")) is bool and before_record == expected_before,
                "before snapshot metadata differs")
        require(before_path.exists() == (index == 2), "unexpected/missing before snapshot")
        after = _regular(after_path)
        record_path = phase / "run.json"
        result = verify_record(record_path, before, after)
        record = producer.graphics.read_json(record_path)
        require(record["program_out"] == start["program"] and record["data_directory"] == str(data_directory)
                and record["requested_base"] is None and record["requested_budget"] == start["budget"]
                and record["timeout_ms"] == start["timeout_ms"] and record["test_sequence"] == SEQUENCE,
                "phase executed a different program/base/budget/shared directory/workload")
        require(record["stdout_path"] == str(phase / "run.stdout") and record["stderr_path"] == str(phase / "run.stderr"),
                "phase actual stream locations differ")
        require(type(record["pid"]) is int and record["pid"] > 0, "invalid actual child PID")
        pids.append(record["pid"])
        paths = [phase / "before.json", after_path, record_path, phase / "run.started.json",
                 phase / "run.stdout", phase / "run.stderr"]
        if before is not None:
            paths.append(before_path)
        require({p.name for p in phase.iterdir()} == {p.name for p in paths} | {"observed.json", "history"},
                "phase exact artifact set differs")
        # Program.run initially writes run.json as STARTED, then its normal
        # graphics.save preserves precisely that prior record on completion.
        history = phase / "history"
        require(history.is_dir() and not history.is_symlink(), "real start-history directory required")
        history_files = list(history.iterdir())
        require(len(history_files) == 1, "exactly one archived initial run record required")
        historical = history_files[0]
        archived = producer.graphics.strict_json(_regular(historical).decode())
        expected_archive = {**producer.graphics.read_json(phase / "run.started.json"),
            "started_path": str(phase / "run.started.json"),
            "started_sha256": producer.sha(phase / "run.started.json")}
        require(historical.name == "run.json." + producer.sha(historical) + ".json" and archived == expected_archive,
                "archived initial run does not match immutable start")
        for path in paths:
            _regular(path)
        phase_entry = producer.graphics.strict_json(_regular(phase / "observed.json").decode())
        basic = {"position": result["position"], "moves": result["moves"],
            "persisted_draws": result["persisted_draws"], "current_presents": result["current_presents"],
            "steps": result["steps"], "load_observations": result["load_observations"],
            "file_api_calls": result["file_api_calls"], "last_error": result["last_error"]}
        expected_entry = {"phase": index, "summary": basic, "artifacts": producer.snapshot(paths)}
        require(type(phase_entry.get("phase")) is int and
                phase_entry == observed["phases"][index - 1] == expected_entry,
                "phase observations/artifact identities differ from actual records")
        accepted.append({"phase": index, "pid": record["pid"], **result,
                         "before_sha256": expected_before["sha256"], "after_sha256": producer.sha(after_path),
                         "run_sha256": producer.sha(record_path)})
        prior = after
    require(len(set(pids)) == 2, "two distinct process records required")
    require(_regular(save) == prior and observed["final_shared_save"] == producer.snapshot([save]),
            "final live save is not the actual phase 2 result")
    require(accepted[0]["position"] == 4 and accepted[0]["moves"] == 3 and
            accepted[1]["position"] == 5 and accepted[1]["moves"] == 6,
            "fixed two-run progression differs")
    require(producer.snapshot(required) == before_identity, "reviewed phase/snapshot/source identities changed")
    return {"status": "PASS_SAME_PE_TWO_PROCESS_SAVE_RESTORE", "pe_sha256": PE_SHA256,
        "phases": accepted, "artifacts": before_identity, "existing_guest_executions": 2,
        "new_guest_executions": 0, "new_gui_executions": 0, "new_gpu_executions": 0,
        "scope": "same original PE actually reads its previous real file in a new process; TEST_QUEUE, no pixel/physical-key/performance acceptance"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_roundtrip(args.directory), ensure_ascii=False, sort_keys=True))
