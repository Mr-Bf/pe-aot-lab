"""Invoke the real process AOT producer on caller PE bytes; never run the guest."""
import contextlib
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import struct
import traceback

from migration_v1.analyze import analyze, read_input
from process_bridge.bindings import Program, python_closure, sha, snapshot, unchanged, run_command
from process_bridge.build_app import text_bytes
from process_bridge.lift import TranslationError

ROOT = Path(__file__).resolve().parents[1]


def dump(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def package(program, out):
    app = out / 'PE AOT Process.app'
    contents = app / 'Contents'
    macos, resources = contents / 'MacOS', contents / 'Resources'
    macos.mkdir(parents=True)
    resources.mkdir()
    executable = macos / 'pe-aot-process'
    shutil.copy2(program.executable, executable)
    licenses = {'Project-LICENSE': ROOT / 'LICENSE', 'Remill-LICENSE': ROOT / 'process_bridge/LICENSE.remill',
                'Remill-Changes.md': ROOT / 'integration_stage3/NOTICE.lifter.md'}
    for name, path in licenses.items():
        shutil.copy2(path, resources / name)
    with (contents / 'Info.plist').open('xb') as stream:
        plistlib.dump(dict(CFBundleExecutable=executable.name, CFBundleIdentifier='org.peaotlab.migration.process',
                          CFBundleName='PE AOT Process', CFBundlePackageType='APPL', CFBundleVersion='1',
                          CFBundleShortVersionString='0.1', LSUIElement=True), stream)
    dump(resources / 'Build.json', dict(input_sha256=program.source_sha256, profile='process-v1',
         status='BUILT_NOT_EXECUTED', entry_arguments=0,
         launch='Contents/MacOS/pe-aot-process --data-dir <existing writable directory>',
         scope='CLI development bundle; no Finder GUI/default data directory/notarization; runtime API arguments remain restricted'))
    (resources / 'MigrationChanges.md').write_text(
        'This native object is lifted from the input PE using project-modified Remill.\n'
        'PE bytes, instruction manifests, retargeted LLVM IR, patches and native build\n'
        'commands accompany this build directory/repository. The process-profile\n'
        'transformations and compatibility runtime are in process_bridge/.\n'
        'The project license does not grant rights to third-party input binaries.\n')
    log = out / 'package.log'
    log.write_text('')
    before = text_bytes(program.executable, log)
    run_command(['codesign', '--force', '--sign', '-', '--identifier', 'org.peaotlab.migration.process', app], log)
    run_command(['codesign', '--verify', '--strict', app], log)
    if text_bytes(executable, log) != before:
        raise ValueError('packaging changed native text')
    return app, executable, licenses


def build(source, output):
    data = read_input(source)
    out = Path(output).absolute()
    if out != out.resolve():
        raise ValueError('output must not traverse symlinks')
    out.mkdir(parents=True, exist_ok=False)
    # One immutable snapshot feeds analysis and compilation, without reopening source.
    frozen = out / 'input.exe'
    frozen.write_bytes(data)
    sources = snapshot(python_closure([Path(__file__), ROOT / 'migration_v1/__init__.py', ROOT / 'migration_v1/analyze.py',
                                      ROOT / 'migration_v1/__main__.py']))
    analysis = analyze(data)
    dump(out / 'analysis.json', analysis)
    report = dict(schema=1, profile='process-v1', input_sha256=analysis['input_sha256'],
                  original_input=str(Path(source).absolute()), output=str(out),
                  analysis='analysis.json', guest_executions=0, sources=sources)
    if analysis['status'] != 'ELIGIBLE_FOR_BUILD_NOT_DECODED':
        report.update(status='UNSUPPORTED', stage='analysis', issues=analysis['issues'])
        dump(out / 'result.json', report)
        return report
    stage = 'aot-build'
    try:
        # No symbol map, fixture observations or fixed PE hash are supplied.
        # The producer discovers direct CFG/IAT sites and builds real Remill IR.
        with (out / 'producer.stdout').open('x') as stdout, (out / 'producer.stderr').open('x') as stderr:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                program = Program(frozen, out / 'native')
        if program.source_sha256 != analysis['input_sha256']:
            raise ValueError('analysis/build snapshot identity differs')
        stage = 'package'
        app, executable, licenses = package(program, out)
        unchanged(sources)
        report.update(status='BUILT_NOT_EXECUTED', stage='complete', app=str(app), executable=str(executable),
                      executable_sha256=sha(executable), program_receipt='native/program-build.json',
                      instructions=len(program.manifest['instructions']),
                      source_inputs={**program.build_manifest['native_inputs'], **snapshot(licenses.values())},
                      limitation='restricted CLI process App, not a generic Windows/GUI converter or runtime correctness claim')
    except Exception as error:
        (out / 'failure.txt').write_text(traceback.format_exc())
        report.update(status='UNSUPPORTED' if isinstance(error, TranslationError) else 'BUILD_FAILED',
                      stage=stage, error_type=type(error).__name__, error=str(error))
        if isinstance(error, TranslationError):
            match = re.search(r'REJECT iclass (\w+) at (\d+)', str(error))
            report['diagnostic'] = dict(code='TRANSLATION_REJECT', message=str(error).strip())
            if match:
                address = int(match[2])
                report['diagnostic'].update(code='INSTRUCTION_UNSUPPORTED', iclass=match[1],
                                             guest_va=address, rva=address - analysis['inventory']['image_base'])
    report['files'] = {str(p.relative_to(out)): dict(sha256=sha(p), mode=p.stat().st_mode & 0o777)
                       for p in sorted(out.rglob('*')) if p.is_file() and p.name != '.program-build.lock'}
    dump(out / 'result.json', report)
    return report


def verify(output):
    out = Path(output).resolve(strict=True)
    result = json.loads((out / 'result.json').read_bytes())
    if result.get('status') != 'BUILT_NOT_EXECUTED' or result.get('output') != str(out):
        raise ValueError('requires an unchanged successful build at its recorded path')
    required = {'input.exe', 'analysis.json', 'native/program-build.json', 'native/compiler/manifest.json',
                'native/ret-shim/manifest.json', 'PE AOT Process.app/Contents/MacOS/pe-aot-process'}
    actual = {str(p.relative_to(out)) for p in out.rglob('*')
              if p.is_file() and p != out / 'result.json' and p.name != '.program-build.lock'}
    if not required.issubset(result['files']) or set(result['files']) != actual:
        raise ValueError('build artifact file set differs or required files missing')
    for name, item in result['files'].items():
        path = out / name
        if Path(name).is_absolute() or path != path.resolve() or not path.is_relative_to(out):
            raise ValueError('artifact escaped build directory')
        if sha(path) != item['sha256'] or path.stat().st_mode & 0o777 != item['mode']:
            raise ValueError('artifact changed: ' + name)
    unchanged(result['sources'])
    unchanged(result['source_inputs'])
    exe = Path(result['executable'])
    if exe != out / 'PE AOT Process.app/Contents/MacOS/pe-aot-process':
        raise ValueError('unexpected packaged executable path')
    if sha(exe) != result['executable_sha256'] or sha(out / 'input.exe') != result['input_sha256']:
        raise ValueError('input/output identity mismatch')
    if struct.unpack_from('<II', exe.read_bytes()) != (0xfeedfacf, 0x100000c):
        raise ValueError('packaged executable is not thin ARM64 Mach-O')
    native = json.loads((out / 'native/program-build.json').read_bytes())
    if (native['input_sha256'] != result['input_sha256'] or native['native_inputs'] != native['native_inputs_after']
            or any(result['source_inputs'].get(p) != h for p, h in native['native_inputs'].items())):
        raise ValueError('native producer provenance differs from wrapper receipt')
    return dict(status='BUILD_FILES_VERIFIED_NOT_EXECUTED', checked_files=len(result['files']),
                executable_sha256=result['executable_sha256'], guest_executions=0,
                scope='local receipt integrity; not a signed attestation or runtime acceptance')
