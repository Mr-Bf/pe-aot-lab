#!/usr/bin/env python3
"""Independent, offline regression tests; never execute GPU or download sources."""
import argparse
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from graphics_stage5 import bootstrap_dxmt as bootstrap
from graphics_stage5 import probe


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identities(paths):
    return {str(Path(p).resolve()): sha(p) for p in sorted(set(map(Path, paths)))}


class Cases:
    def __init__(self):
        self.records = []

    def accept(self, name, operation):
        operation()
        self.records.append({'name': name, 'expected': 'accept', 'status': 'PASS'})

    def reject(self, name, operation):
        try:
            operation()
        except (RuntimeError, tarfile.TarError, OSError, ValueError, KeyError) as error:
            self.records.append({'name': name, 'expected': 'reject', 'status': 'PASS',
                                 'reason': type(error).__name__ + ': ' + str(error)})
            return
        raise RuntimeError('invalid case accepted: ' + name)


def archive(path, entries):
    """Entries: (member name, file/dir/symlink/hardlink/fifo/device, content)."""
    with tarfile.open(path, 'w:gz') as output:
        for name, kind, content in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if kind == 'dir' else 0o644
            if kind == 'file':
                data = content.encode()
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
            else:
                member.type = {'dir': tarfile.DIRTYPE, 'symlink': tarfile.SYMTYPE,
                               'hardlink': tarfile.LNKTYPE, 'fifo': tarfile.FIFOTYPE,
                               'device': tarfile.CHRTYPE}[kind]
                if kind in ('symlink', 'hardlink'):
                    member.linkname = content
                output.addfile(member)


def archive_cases(work):
    cases = Cases()
    prefix = 'pinned-source'
    root = [(prefix, 'dir', '')]
    plain = root + [(prefix + '/a.txt', 'file', 'original')]
    positives = {
        'plain': plain,
        'relative-symlink': plain + [(prefix + '/alias', 'symlink', 'a.txt')],
        'nested-relative-symlink': plain + [(prefix + '/sub', 'dir', ''),
                                          (prefix + '/sub/alias', 'symlink', '../a.txt')],
        'internal-symlink-chain': plain + [(prefix + '/alias', 'symlink', 'a.txt'),
                                          (prefix + '/alias2', 'symlink', 'alias')],
        'internal-hardlink': plain + [(prefix + '/hard', 'hardlink', prefix + '/a.txt')],
    }
    negatives = {
        'member-dotdot': root + [(prefix + '/../escape', 'file', 'bad')],
        'absolute-member': [('/absolute-member', 'file', 'bad')],
        'wrong-prefix': [('other/a.txt', 'file', 'bad')],
        'absolute-symlink': plain + [(prefix + '/alias', 'symlink', '/tmp/outside')],
        'relative-symlink-escape': plain + [(prefix + '/alias', 'symlink', '../outside')],
        'hardlink-other-root': plain + [(prefix + '/hard', 'hardlink', 'other/a.txt')],
        'hardlink-dotdot-escape': plain + [(prefix + '/hard', 'hardlink', prefix + '/../outside')],
        'fifo': root + [(prefix + '/fifo', 'fifo', '')],
        'device': root + [(prefix + '/device', 'device', '')],
        'root-file': [(prefix, 'file', 'bad')],
        'root-symlink': [(prefix, 'symlink', 'internal')],
        'resolved-link-chain-escape': plain + [(prefix + '/sub', 'symlink', '.'),
                                             (prefix + '/sub/alias', 'symlink', '../outside')],
        'empty-archive': [],
    }
    for name, entries in {**positives, **negatives}.items():
        area = work / name
        area.mkdir()
        target = area / 'sources' / prefix
        target.parent.mkdir()
        sentinel = target.parent / 'outside'
        sentinel.write_text('untouched')
        tarpath = area / 'source.tar.gz'
        archive(tarpath, entries)
        operation = lambda: bootstrap.extract_source_archive(tarpath, target)
        if name in positives:
            cases.accept(name, operation)
            require((target / 'a.txt').read_text() == 'original', 'positive file changed')
            for link in ('alias', 'alias2', 'sub/alias', 'hard'):
                if (target / link).exists():
                    require((target / link).read_text() == 'original', 'positive link invalid')
            bootstrap.source_paths_confined(target)
        else:
            cases.reject(name, operation)
            require(not target.exists() and not target.is_symlink(), 'rejected archive published')
            require(set(p.name for p in target.parent.iterdir()) == {'outside'},
                    'rejected archive wrote outside its private extraction directory')
        require(sentinel.read_text() == 'untouched', 'sibling changed')
    existing = work / 'existing'
    existing.mkdir()
    (existing / 'sentinel').write_text('untouched')
    existing_tar = work / 'existing.tar.gz'
    archive(existing_tar, [('existing', 'dir', ''), ('existing/new', 'file', 'bad')])
    cases.reject('existing-destination', lambda: bootstrap.extract_source_archive(existing_tar, existing))
    require(list(existing.iterdir()) == [existing / 'sentinel'] and
            (existing / 'sentinel').read_text() == 'untouched', 'existing destination changed')
    return cases.records


def bootstrap_cases(work):
    """Real main/fetch/header-copy replay, with tiny local pinned-cache fixtures."""
    cases = Cases()
    fake_work = work / 'workspace'
    fake_out = work / 'evidence'
    downloads = fake_work / 'downloads'
    downloads.mkdir(parents=True)
    for name, repo, commit in bootstrap.SOURCES:
        prefix = name + '-' + commit
        tarpath = downloads / (prefix + '.tar.gz')
        entries = [(prefix, 'dir', ''), (prefix + '/input.txt', 'file', name)]
        if name == 'dxmt':
            entries += [(prefix + '/include', 'dir', ''), (prefix + '/include/native', 'dir', ''),
                        (prefix + '/include/native/directx', 'dir', '')]
        elif name == 'mingw-directx-headers':
            entries += [(prefix + '/alias.h', 'symlink', 'input.txt')]
        archive(tarpath, entries)
        tarpath.with_suffix('.json').write_text(json.dumps({
            'url': f'https://codeload.github.com/{repo}/tar.gz/{commit}',
            'commit': commit, 'sha256': sha(tarpath)}))

    def forbidden(*args, **kwargs):
        raise AssertionError('offline regression attempted network or build execution')

    with patch.object(bootstrap, 'WORK', fake_work), patch.object(bootstrap, 'OUT', fake_out), \
         patch.object(bootstrap.urllib.request, 'urlopen', forbidden), patch.object(bootstrap, 'run', forbidden), \
         patch.object(sys, 'argv', ['bootstrap_dxmt.py', '--fetch-only']), contextlib.redirect_stdout(io.StringIO()):
        cases.accept('first-sources-only-main', bootstrap.main)
        cases.accept('repeat-sources-only-main', bootstrap.main)
        record = json.loads((fake_out / 'evidence.json').read_text())
        require(record['status'] == 'SOURCES_FETCHED_NOT_BUILT' and record['commands'] == [],
                'sources-only replay unexpectedly built code')
        dxmt = fake_work / 'sources' / ('dxmt-' + bootstrap.DXMT)
        headers = fake_work / 'sources' / ('mingw-directx-headers-' + bootstrap.HEADERS)
        copied = dxmt / 'include/native/directx'
        require(not copied.is_symlink(), 'header preparation created a cross-root symlink')
        require(bootstrap.tree_identity(copied) == bootstrap.tree_identity(headers), 'header copy differs')
        (copied / 'input.txt').write_text('mutation')
        cases.reject('mutated-header-copy', lambda: bootstrap.prepare_headers(dxmt, headers))
        (copied / 'input.txt').write_text('mingw-directx-headers')
        (dxmt / 'rogue-link').symlink_to(headers, target_is_directory=True)
        cases.reject('cached-cross-root-symlink', lambda: bootstrap.fetch(*bootstrap.SOURCES[0]))
        (dxmt / 'rogue-link').unlink()
        cases.accept('restored-cache', lambda: bootstrap.fetch(*bootstrap.SOURCES[0]))
    return cases.records


class JsonOverride:
    """Inject only one parsed metadata document; real files remain read-only."""
    def __init__(self, original, replacement):
        self.original = original
        self.replacement = replacement

    def loads(self, text, *args, **kwargs):
        if text == self.original:
            return copy.deepcopy(self.replacement)
        return json.loads(text, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(json, name)


def probe_cases():
    cases = Cases()
    cases.accept('current-real-host-evidence', probe.verify)
    record_text = (probe.OUT / 'host.json').read_text()
    record = json.loads(record_text)
    mutations = {
        'nested-fail': lambda d: d['result'].update(status='FAIL'),
        'translated-process': lambda d: d['result'].update(rosetta_query=1),
        'claimed-directx-and-guest': lambda d: d['result'].update(directx_executed=True, guest_executed=True),
        'nonzero-exit': lambda d: d.update(exit_code=9),
        'empty-run-inputs': lambda d: d.update(inputs_before={}, inputs_after={}),
        'missing-run-input': lambda d: [d[k].pop(str(probe.OUT / 'build.json')) for k in ('inputs_before', 'inputs_after')],
        'extra-run-input': lambda d: [d[k].update({str(ROOT / 'AGENTS.md'): sha(ROOT / 'AGENTS.md')}) for k in ('inputs_before', 'inputs_after')],
        'pixel-count': lambda d: d['result'].update(pixel_count=1023),
        'pixel-mismatch': lambda d: d['result'].update(mismatched_channels=1),
        'different-valid-device-in-summary': lambda d: d['result'].update(device='Another GPU'),
        'different-valid-pixel-in-summary': lambda d: d['result'].update(pixel_rgba=[65,128,191,255]),
        'stderr-hash': lambda d: d.update(stderr_sha256='0' * 64),
        'stdout-hash': lambda d: d.update(stdout_sha256='0' * 64),
        'combined-log-hash': lambda d: d.update(log_sha256='0' * 64),
        'recorded-validation-error': lambda d: d.update(validation_error='failure'),
        'promoted-top-scope': lambda d: d.update(scope='DXMT guest rendering verified'),
        'wrong-run-label': lambda d: d.update(label='restricted'),
        'wrong-stream-path': lambda d: d.update(stdout=d['log']),
    }
    for name, mutate in mutations.items():
        value = copy.deepcopy(record)
        mutate(value)
        with patch.object(probe, 'json', JsonOverride(record_text, value)):
            cases.reject(name, probe.verify)
    build_text = (probe.OUT / 'build.json').read_text()
    build = json.loads(build_text)
    for name, dependency in [('missing-build-source', probe.HERE / 'metal_probe.m'),
                             ('missing-build-depfile', probe.OUT / 'probe.d')]:
        value = copy.deepcopy(build)
        for key in ('inputs_before', 'inputs_after'):
            del value[key][str(dependency.resolve())]
        with patch.object(probe, 'json', JsonOverride(build_text, value)):
            cases.reject(name, probe.verify_build)

    # Independent predicate tests avoid summary/stream comparison masking a bad validator.
    predicate = {
        'rgba-byte-overflow': {'pixel_rgba': [64,128,191,256]},
        'boolean-count': {'pixel_count': True},
        'boolean-status-code': {'command_status': True},
        'float-pixel': {'pixel_rgba': [64.0,128,191,255]},
        'missing-device': {'device': ''},
        'query-errno': {'rosetta_query_errno': 5},
        'wrong-command-state': {'command_status': 3},
        'unknown-result-field': {'unknown': 1},
        'wrong-nested-scope': {'scope': 'triangle rendered'},
        'numeric-guest-false': {'guest_executed': 0},
    }
    for name, changes in predicate.items():
        value = copy.deepcopy(record['result'])
        value.update(changes)
        cases.reject(name, lambda: probe.validate_result(value, 0))
    cases.reject('boolean-process-exit', lambda: probe.validate_result(record['result'], False))
    cases.accept('valid-pixel-tolerance', lambda: probe.validate_result(
        {**record['result'], 'pixel_rgba': [63,129,190,254]}, 0))
    return cases.records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'build/graphics-stage5/review-tests')
    args = parser.parse_args()
    out = args.out.resolve()
    require(out.is_relative_to(ROOT / 'build/graphics-stage5') and out != probe.OUT.resolve(),
            'review output must be a separate graphics-stage5 build directory')
    out.mkdir(parents=True, exist_ok=True)
    sources = identities([Path(__file__), Path(bootstrap.__file__), Path(probe.__file__), probe.HERE / 'metal_probe.m'])
    official = identities(p for p in probe.OUT.rglob('*') if p.is_file())
    historical = [ROOT.parents[1] / 'work/graphics-stage5-review' / n for n in
                  ('extraction-proof.json', 'probe-gate-proof.json', 'dxmt-local-proof.json')]
    old_proofs = identities(historical)
    with tempfile.TemporaryDirectory(prefix='cases-', dir=out) as temporary:
        work = Path(temporary)
        (work / 'archives').mkdir()
        (work / 'bootstrap').mkdir()
        groups = {'archive': archive_cases(work / 'archives'),
                  'cached_preparation': bootstrap_cases(work / 'bootstrap'),
                  'probe_evidence': probe_cases()}
    require(identities(sources) == sources, 'review sources changed during tests')
    require(identities(official) == official, 'formal probe files changed during review')
    require(identities(old_proofs) == old_proofs, 'historical failure proofs changed')
    result = {'schema': 1, 'status': 'PASS', 'python_optimized': not __debug__,
              'python': str(Path(sys.executable).resolve()), 'python_sha256': sha(sys.executable),
              'count': sum(len(v) for v in groups.values()),
              'accepted': sum(c['expected'] == 'accept' for v in groups.values() for c in v),
              'rejected': sum(c['expected'] == 'reject' for v in groups.values() for c in v),
              'groups': groups, 'source_sha256_before': sources, 'source_sha256_after': identities(sources),
              'official_files_before': official, 'official_files_after': identities(official),
              'historical_proof_sha256': old_proofs,
              'scope': 'offline archive and evidence-gate regression; zero network/build/GPU execution; not DXMT rendering',
              'trust_limit': 'consistency and stale-evidence checks, not a digital signature or hostile-forgery defense'}
    (out / 'evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'count': result['count'], 'accepted': result['accepted'],
                      'rejected': result['rejected'], 'evidence': str(out / 'evidence.json')}))


if __name__ == '__main__':
    main()
