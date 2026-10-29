"""Official acquisition locations, separate from the frozen byte-identity lock.

URLs describe origins, not proof of present availability. Every acquired file
must still match the existing portable_lifter_v1/cache-lock.json SHA-256.
"""
import json
from pathlib import Path

from portable_lifter_v1 import build, deps, tools

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'portable_lifter_v1/cache-lock.json'
PACKAGES = {
    'llvm17.tar.gz': {'kind': 'ghcr', 'repository': 'llvm/17', 'version': '17.0.6'},
    'cmake.tar.gz': {'kind': 'ghcr', 'repository': 'cmake', 'version': '4.4.4'},
    'ninja.tar.gz': {'kind': 'ghcr', 'repository': 'ninja', 'version': '1.13.2'},
    'remill.tar.gz': {
        'kind': 'https', 'commit': '56918a8c2554088e93389e97d292f4035286506c',
        'url': 'https://codeload.github.com/lifting-bits/remill/tar.gz/56918a8c2554088e93389e97d292f4035286506c'},
    'zstd-1.5.7.tar.gz': {
        'kind': 'https', 'version': '1.5.7',
        'url': 'https://codeload.github.com/facebook/zstd/tar.gz/refs/tags/v1.5.7'},
}
GIT = {
    'gflags': 'https://github.com/gflags/gflags.git',
    'glog': 'https://github.com/google/glog.git',
    'xed': 'https://github.com/intelxed/xed.git',
    'mbuild': 'https://github.com/intelxed/mbuild.git',
}


def plan():
    """Bind acquisition roles to the unchanged consumer contracts."""
    lock = json.loads(LOCK.read_bytes())
    tools.require(lock.get('schema') == 1 and set(lock.get('packages', {})) == set(PACKAGES)
                  and set(lock.get('sources', {})) == set(GIT), 'CPU lock roles differ')
    packages = {}
    expected = {name: value[0] for name, value in tools.PACKAGES.items()}
    expected['remill.tar.gz'] = build.REMILL_ARCHIVE_SHA
    for name, origin in PACKAGES.items():
        tools.require(lock['packages'][name].get('sha256') == expected[name],
                      'CPU consumer/lock digest differs: ' + name)
        row = dict(origin, sha256=expected[name])
        if row['kind'] == 'ghcr':
            row['url'] = ('https://ghcr.io/v2/homebrew/core/' + row['repository'] +
                          '/blobs/sha256:' + row['sha256'])
        packages[name] = row
    sources = {}
    for name, repository in GIT.items():
        row = lock['sources'][name]
        tools.require(set(row) == {'archive', 'sha256', 'commit', 'tree'} and
                      row['archive'] == name + '.tar' and
                      (row['commit'], row['tree']) == deps.PINS[name],
                      'CPU source contract differs: ' + name)
        tools.require(type(row['sha256']) is str and len(row['sha256']) == 64 and
                      all(c in '0123456789abcdef' for c in row['sha256']),
                      'invalid source SHA-256: ' + name)
        sources[name] = dict(row, repository=repository)
    return {'schema': 1, 'lock_sha256': tools.digest(LOCK),
            'packages': packages, 'sources': sources}
