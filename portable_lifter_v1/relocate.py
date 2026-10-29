"""Copy a built CPU provider; probe with its original prefix temporarily absent.

Historical manifests retain their original bytes. Only a new evidence directory
is written. This is a selected-runtime relocation test, not a relocated rebuild.
"""
import argparse
import json
from pathlib import Path
import shutil
import traceback

from . import build, deps, tools


def relocate(source, destination, pe, out):
    source, destination, out = map(tools.real_path,(source,destination,out))
    build.require(source.parent == destination.parent and source != destination,'distinct sibling prefixes required')
    held = source.with_name(source.name+'-withheld')
    build.require(not held.exists() and not held.is_symlink(),'withheld path must be absent')
    build.require(not destination.exists() and not destination.is_symlink(),'copy destination must be absent')
    build.require(not out.is_relative_to(source.parent),'evidence must be outside prefix directory')
    original, original_paths = build.paths_for(source)
    original_sha = build.digest(source/'provider.json')
    build.require(deps.tree(original_paths['source']) == original['source_tree'],'original source identity differs')
    out = build.fresh(out)
    snapshots = build.source_snapshot(out,[Path(__file__).resolve(),*build.SOURCES,
                                         build.REPO/'portable_lifter_v1/probe.py'])
    build.write_json(out/'started.json',dict(source=str(source),destination=str(destination),withheld=str(held),
                                           provider_sha256=original_sha,started_at=build.now(),sources=snapshots))
    restored = False
    error = None
    try:
        shutil.copytree(source,destination,symlinks=True)
        copied, copied_paths = build.paths_for(destination)
        build.require(build.digest(destination/'provider.json') == original_sha,'copied provider metadata changed')
        build.require(deps.tree(copied_paths['source']) == copied['source_tree'],'copied source differs')
        source.rename(held)
        build.require(not source.exists() and held.is_dir(),'original prefix was not withheld')
        build.write_json(out/'original-unavailable.json',dict(original_exists=False,withheld_exists=True,
                         withheld_manifest_sha256=build.digest(held/'provider.json'),observed_at=build.now()))
        build.probe(destination,pe,out/'probe')
        build.require(not source.exists(),'original prefix reappeared during probe')
        build.check_sources(snapshots)
    except BaseException as caught:
        error = dict(error=str(caught),traceback=traceback.format_exc())
        raise
    finally:
        restore_error = None
        try:
            if held.exists():
                build.require(not source.exists(),'cannot restore: original path unexpectedly occupied')
                held.rename(source)
            build.require(source.is_dir() and build.digest(source/'provider.json') == original_sha,
                          'restored provider identity differs')
            build.paths_for(source)
            restored = True
        except Exception as caught:
            restore_error = str(caught)
        build.write_json(out/'restoration.json',dict(original_restored=restored,withheld_exists=held.exists(),
                                                   finished_at=build.now(),error=error,restore_error=restore_error,
                                                   source=str(source),withheld=str(held)))
        if error or restore_error:
            build.write_json(out/'failure.json',dict(status='FAIL',original_restored=restored,
                             operation_error=error,restore_error=restore_error,source=str(source),withheld=str(held)))
        if restore_error:
            raise RuntimeError('original-prefix restoration failed; preserved paths recorded in '+str(out/'restoration.json'))
    build.require(restored,'original prefix did not restore')
    build.paths_for(source)
    result = dict(status='COPIED_PROVIDER_STATIC_PROBE_PASSED_ORIGINAL_RESTORED',source=str(source),
                  destination=str(destination),original_provider_sha256=original_sha,
                  copied_provider_sha256=build.digest(destination/'provider.json'),
                  probe_receipt_sha256=build.digest(out/'probe/result.json'),original_restored=True,
                  guest_executions=0,gpu_executions=0,native_layout_harness_executions=2,
                  limitation='Selected CPU provider probe only; no relocated CMake rebuild, App or clean-machine claim.')
    build.write_json(out/'result.json',result)
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','destination','pe','out'):
        parser.add_argument('--'+name,required=True)
    print(relocate(**vars(parser.parse_args()))['status'])
