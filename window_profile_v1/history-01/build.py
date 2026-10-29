"""Build a configured native window host. App packaging is a separate next gate."""
import contextlib
import json
from pathlib import Path
import struct
import traceback

from window_profile_v1.profile import analyze, read_input, validate
from window_profile_v1.bindings import Program, ROOT, output_directory, python_closure, sha, snapshot, unchanged
from window_inc_v1.lift import TranslationError


def dump(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def files(out):
    return {str(p.relative_to(out)): dict(sha256=sha(p), mode=p.stat().st_mode & 0o777)
            for p in sorted(out.rglob('*')) if p.is_file() and
            p.name not in ('.program-build.lock', 'result.json') and 'cache' not in p.relative_to(out).parts}


def build(source, output, profile):
    data = read_input(source)
    out = output_directory(output)
    out.mkdir(parents=True, exist_ok=False)
    frozen = out / 'input.exe'
    frozen.write_bytes(data)
    dump(out / 'profile.json', profile)
    sources = snapshot(python_closure([Path(__file__), ROOT / 'migration_v3/__main__.py',
                                      ROOT / 'migration_v3/__init__.py']))
    analysis = analyze(data, profile)
    dump(out / 'analysis.json', analysis)
    result = dict(schema=1, profile=analysis['profile'], input_sha256=analysis['input_sha256'],
                  original_input=str(Path(source).absolute()), output=str(out),
                  guest_executions=0, sources=sources, limits=analysis['limits'])
    if analysis['status'] != 'ELIGIBLE_FOR_BUILD_NOT_DECODED':
        result.update(status='UNSUPPORTED', stage='profile-or-loader', error=analysis['error'])
    else:
        try:
            with (out / 'producer.stdout').open('x') as stdout, (out / 'producer.stderr').open('x') as stderr:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    program = Program(frozen, out / 'native', metadata=profile, metadata_sources=[out / 'profile.json'])
            unchanged(sources)
            result.update(status='BUILT_NATIVE_WINDOW_NOT_PACKAGED_NOT_EXECUTED', stage='complete',
                          executable=str(program.executable), executable_sha256=sha(program.executable),
                          program_receipt='native/program-build.json', source_inputs=program.build_manifest['native_inputs'],
                          instructions=len(program.root_manifest['instructions']), callback_count=len(program.roots)-1,
                          launch='native executable --data-dir <absolute existing directory>',
                          scope='real input PE AOT; configured roots/diagnostics; fixed runtime/backend; no App packaging or guest execution')
        except Exception as error:
            (out / 'failure.txt').write_text(traceback.format_exc())
            result.update(status='UNSUPPORTED' if isinstance(error, TranslationError) else 'BUILD_FAILED',
                          stage='aot-build', error_type=type(error).__name__, error=str(error))
    result['files'] = files(out)
    dump(out / 'result.json', result)
    return result


def verify(output):
    """File-only verification; no compiler, backend, process, or GPU is started."""
    out = output_directory(output)
    result = json.loads((out / 'result.json').read_bytes())
    if result.get('status') != 'BUILT_NATIVE_WINDOW_NOT_PACKAGED_NOT_EXECUTED' or result.get('output') != str(out):
        raise ValueError('unchanged successful configured window build required')
    required = {'input.exe', 'profile.json', 'analysis.json', 'native/input.exe', 'native/window-profile.json',
                'native/program-build.json', 'native/compiler/roots.json', 'native/compiler/main/manifest.json',
                'native/ret-shim/manifest.json'}
    if not required <= set(result['files']) or files(out) != result['files']:
        raise ValueError('actual artifact file set, mode or bytes differ')
    for name in result['files']:
        path = out / name
        if Path(name).is_absolute() or path != path.resolve() or not path.is_relative_to(out):
            raise ValueError('artifact escaped output or traverses symlink')
    unchanged(result['sources'])
    unchanged(result['source_inputs'])
    data = (out / 'input.exe').read_bytes()
    profile = json.loads((out / 'profile.json').read_bytes())
    normalized, image, _ = validate(data, profile)
    if normalized != json.loads((out / 'native/window-profile.json').read_bytes()):
        raise ValueError('caller and producer profile differ')
    if analyze(data, profile) != json.loads((out / 'analysis.json').read_bytes()):
        raise ValueError('analysis no longer agrees with actual PE/profile')
    exe = Path(result['executable'])
    native = json.loads((out / 'native/program-build.json').read_bytes())
    roots = json.loads((out / 'native/compiler/roots.json').read_bytes())
    if (sha(out / 'input.exe') != result['input_sha256'] or sha(out / 'native/input.exe') != result['input_sha256'] or
            native['input_sha256'] != result['input_sha256'] or native['native_executable'] != str(exe) or
            exe != out / 'native' / ('window-' + result['executable_sha256']) or sha(exe) != result['executable_sha256']):
        raise ValueError('input or executable identity differs')
    if struct.unpack_from('<II', exe.read_bytes()) != (0xfeedfacf, 0x100000c):
        raise ValueError('native executable is not thin ARM64 Mach-O')
    if (native['native_inputs'] != native['native_inputs_after'] or native['native_inputs'] != result['source_inputs'] or
            native['imports'] != image.imports or roots['input_sha256'] != result['input_sha256'] or
            [r['rva'] for r in roots['roots']] != normalized['callback_rvas'] or
            len(roots['instructions']) != result['instructions'] or len(roots['roots']) != result['callback_count']):
        raise ValueError('producer input/root closure differs')
    return dict(status='BUILD_FILES_VERIFIED_NOT_EXECUTED', checked_files=len(result['files']),
                executable_sha256=result['executable_sha256'], guest_executions=0,
                scope='local file integrity; runtime correctness and App packaging are separate gates')
