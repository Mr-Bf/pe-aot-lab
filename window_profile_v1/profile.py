"""Bounded, strict configuration admission; this is not instruction discovery.

The selected runtime remains a closed API/graphics contract. Configuration
selects roots and diagnostics; it cannot grant new runtime capabilities.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from migration_v1.analyze import inventory, read_input, MAX_FILE
from window_inc_v1.loader import load_image, SIGNATURES

CONTRACT = 'win32-d3d11-tile-v1'
MAX_PROFILE = 65536
FIELDS = {'schema', 'runtime_contract', 'pe_sha256', 'callback_rvas', 'imports',
          'observations', 'save_observation', 'resources'}
LIMITS = {
    'isa': 'window-inc-v1 decoder subset; build must decode all admitted roots',
    'callbacks': 'explicit Win64 LRESULT(HWND,UINT,WPARAM,LPARAM); no automatic discovery',
    'window': 'one fixed 640x360 Cocoa window; existing restricted User32 arguments',
    'graphics': 'existing typed D3D11/COM subset; RGBA8 swapchain; fixed triangle DXBC bytes and restricted pipeline arguments',
    'resources': 'PE-embedded bytes only; no external asset staging',
    'runtime': 'single guest worker; no general CRT/TLS/SEH/JIT/multimodule support',
    'observations': 'read-only diagnostics; never writes guest state or changes save behavior',
    'backend': 'pinned native-window backend-v2; no backend selection or performance claim',
}


class ProfileError(ValueError):
    pass


def require(value, message):
    if not value:
        raise ProfileError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_profile(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_PROFILE,
                'profile must be a regular file of at most 64 KiB')
        data = stream.read(MAX_PROFILE + 1)
    require(len(data) <= MAX_PROFILE, 'profile exceeds 64 KiB')
    def reject_constant(value):
        raise ProfileError('non-finite JSON number: ' + value)
    try:
        return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProfileError('invalid bounded JSON profile: ' + str(error)) from error


def validate(data, profile):
    require(isinstance(profile, dict) and set(profile) == FIELDS, 'unknown or missing profile fields')
    require(type(profile['schema']) is int and profile['schema'] == 1, 'profile schema must be integer 1')
    require(profile['runtime_contract'] == CONTRACT, 'unsupported runtime contract')
    require(profile['resources'] == 'embedded-pe-only', 'external resource staging is not implemented')
    digest = hashlib.sha256(data).hexdigest()
    require(type(profile['pe_sha256']) is str and profile['pe_sha256'] == digest, 'profile PE identity differs')
    require(len(data) <= MAX_FILE, 'PE exceeds 64 MiB')
    info = inventory(data)
    require(info['machine'] == 0x8664 and info['subsystem'] == 2, 'window profile requires AMD64 Windows GUI PE')
    require(info['image_size'] <= MAX_FILE, 'mapped image exceeds 64 MiB')
    image = load_image(data)
    roots = profile['callback_rvas']
    require(type(roots) is list and 1 <= len(roots) <= 8 and all(type(r) is int for r in roots),
            'one to eight explicit integer callback RVAs required')
    require(len(set(roots)) == len(roots) and image.entry_rva not in roots, 'duplicate or entry callback root')
    for rva in roots:
        require(0 <= rva < len(image.data) and image.permissions[rva // 4096] & 4,
                'callback must be in an executable mapped page')
    imports = profile['imports']
    require(type(imports) is list and len(imports) <= len(SIGNATURES), 'invalid explicit import contract')
    pairs = []
    for item in imports:
        require(type(item) is dict and set(item) == {'dll', 'name'} and
                type(item['dll']) is str and type(item['name']) is str, 'invalid import declaration')
        pair = item['dll'], item['name']
        require(pair in SIGNATURES, 'unsupported import declaration: ' + repr(pair))
        pairs.append(pair)
    require(pairs == sorted(set(pairs)), 'imports must be unique and sorted by dll/name')
    actual = sorted((r['dll'], r['name']) for r in image.imports)
    require(actual == pairs, 'profile imports differ from actual PE imports')
    observations = profile['observations']
    require(type(observations) is dict and len(observations) <= 64, 'too many/invalid observations')
    total = 0
    for name, item in observations.items():
        require(type(name) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name), 'invalid observation name')
        require(type(item) is dict and set(item) == {'rva', 'size'}, 'invalid observation fields')
        rva, size = item['rva'], item['size']
        require(type(rva) is int and type(size) is int and 0 <= rva < len(image.data) and
                1 <= size <= min(65536, len(image.data) - rva), 'observation bounds differ')
        require(all(image.permissions[p] & 1 for p in range(rva // 4096, (rva + size - 1) // 4096 + 1)),
                'observation crosses unreadable image pages')
        total += size
    require(total <= 65536, 'observation output exceeds 64 KiB')
    name = profile['save_observation']
    require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}', name),
            'save observation requires a safe ASCII basename, at most 120 bytes')
    # Round-trip makes a private JSON value; callers cannot mutate admission state.
    return json.loads(json.dumps(profile)), image, info


def analyze(data, profile):
    report = dict(schema=1, profile=CONTRACT, input_sha256=hashlib.sha256(data).hexdigest(),
                  guest_executions=0, limits=LIMITS)
    try:
        normalized, image, info = validate(data, profile)
        report.update(status='ELIGIBLE_FOR_BUILD_NOT_DECODED', inventory=info,
                      callback_rvas=normalized['callback_rvas'], imports=image.imports,
                      observation_count=len(normalized['observations']))
    except ValueError as error:
        report.update(status='UNSUPPORTED', stage='profile-or-loader', error=str(error))
    return report
