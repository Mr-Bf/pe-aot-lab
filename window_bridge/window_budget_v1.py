"""Explicitly run three supervised budget prefixes of the original window PE.

Normal runs must already pass window_execution_acceptance. This is a lifecycle
experiment, not a Windows oracle or a proof of every possible interruption.
"""
import argparse
import json
from pathlib import Path

from window_bridge import window_bindings as bindings

BUDGETS = (100, 500, 1060)
SEQUENCE = ["right", "right-repeat", "right-up", "right", "right-up", "left", "left-up", "escape"]


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def check(record, budget):
    r = record["result"]
    require(r["outcome"] == "FAULT" and r["aot_status"] == r["fault"]["status"] == 4,
            "not a precise budget stop")
    require(r["steps"] == budget and r["exit_requested"] == 0 and record["returncode"] == 3,
            "budget/guest/host endpoint differs")
    require(not r["timed_out"] and not record["external_timeout"] and r["proc_translated"] == 0,
            "not a supervised native stop")
    after = r["d3d_after_cleanup"]
    require(after["live_objects"] == after["active_maps"] == 0 and
            after["created"] == after["guest_released"] + after["cleanup_releases"],
            "graphics ownership not balanced after stop")
    host = r["host_after_finish"]
    require(r["host_finished"] and not r["join_status"] and
            host["active_views"] == 0 and host["views_created"] == host["views_released"] and
            host["windows_created"] == host["windows_destroyed"],
            "native window/view cleanup incomplete")
    require(r["files"]["open_after_cleanup"] == r["files"]["cleanup_errors"] == 0 and
            r["callback_stats"]["end_status"] == r["user32_end_status"] == 0,
            "session cleanup failed")
    return {"budget": budget, "steps": r["steps"], "fault_pc": r["fault"]["pc"],
            "callbacks": r["callback_stats"], "test_events_posted": r["test_queue"]["posted"],
            "created_objects": after["created"], "guest_released": after["guest_released"],
            "cleanup_releases": after["cleanup_releases"],
            "cleanup_clear_state_calls": after["cleanup_clear_state_calls"],
            "cleanup_flush_calls": after["cleanup_flush_calls"],
            "draw_calls": after["draw_calls"], "present_calls": after["present_calls"],
            "forced_cleanup_windows": host["forced_cleanup_windows"],
            "file_bytes_written": r["files"]["bytes_written"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--run", action="store_true", help="start actual Cocoa/GPU/PE processes")
    args = parser.parse_args()
    out = args.out.resolve()
    if args.run:
        out.mkdir(parents=True, exist_ok=False)
        started = {"program": str(args.program.resolve()), "budgets": list(BUDGETS),
                   "sequence": SEQUENCE, "driver_sha256": bindings.sha(__file__),
                   "scope": "three actual budget prefixes; not exhaustive; no pixel or performance claim"}
        (out / "started.json").write_text(json.dumps(started, indent=2) + "\n")
        program = bindings.Program.from_build(args.program)
        for budget in BUDGETS:
            directory = out / str(budget)
            directory.mkdir()
            program.run(budget=budget, io_directory=directory / "data", test_sequence=SEQUENCE,
                        timeout_ms=45000, log_path=directory / "run.json")
            summary = check(bindings.verify_run(directory / "run.json"), budget)
            print(json.dumps(summary), flush=True)
        records = [out / str(b) / "run.json" for b in BUDGETS]
        summaries = [check(bindings.verify_run(p), b) for p, b in zip(records, BUDGETS)]
        result = {**started, "status": "PASS_THREE_BUDGET_PREFIXES", "new_guest_executions": 3,
                  "results": summaries, "records": bindings.snapshot(records)}
        (out / "evidence.json").write_text(json.dumps(result, indent=2) + "\n")
    else:
        evidence = bindings.graphics.read_json(out / "evidence.json")
        bindings.unchanged(evidence["records"])
        records = [out / str(b) / "run.json" for b in BUDGETS]
        require(evidence["records"] == bindings.snapshot(records), "record closure differs")
        require(evidence["driver_sha256"] == bindings.sha(__file__), "driver changed")
        require(evidence["program"] == str(args.program.resolve()), "program differs")
        summaries = [check(bindings.verify_run(p), b) for p, b in zip(records, BUDGETS)]
        require(summaries == evidence["results"], "saved summaries differ")
        print(json.dumps({"status": "PASS_READONLY", "results": summaries,
                          "new_guest_executions": 0}), flush=True)


if __name__ == "__main__":
    main()
