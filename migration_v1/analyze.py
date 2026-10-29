"""Bounded, file-only PE inventory and conservative process-profile admission.

Inventory is not instruction discovery or proof that a Windows program runs.
The existing strict loader remains authoritative for the build profile.
"""
import hashlib
import os
from pathlib import Path
import stat
import struct

from process_bridge.loader import SIGNATURES, load_image
from memory_stage2.image_loader import ImageError

MAX_FILE = 64 * 1024 * 1024
DIRECTORIES = ('exports', 'imports', 'resources', 'exception', 'certificate',
               'relocations', 'debug', 'architecture', 'global_ptr', 'tls',
               'load_config', 'bound_imports', 'iat', 'delay_imports', 'clr', 'reserved')
PROFILE = 'process-v1'


class InventoryError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise InventoryError(message)


def read_input(path):
    # Avoid blocking on devices/FIFOs. Hash and parse the exact same bounded bytes.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), 'input must be a regular file')
        require(info.st_size <= MAX_FILE, 'input exceeds 64 MiB inspection limit')
        data = stream.read(MAX_FILE + 1)
    require(len(data) <= MAX_FILE, 'input exceeds 64 MiB inspection limit')
    return data


def inventory(data):
    def field(fmt, offset):
        require(0 <= offset <= len(data) - struct.calcsize(fmt), 'truncated PE field')
        return struct.unpack_from(fmt, data, offset)

    require(data[:2] == b'MZ', 'missing DOS signature')
    pe, = field('<I', 0x3c)
    require(pe >= 64 and data[pe:pe + 4] == b'PE\0\0', 'missing/overlapping PE header')
    machine, count, _, _, _, optsize, characteristics = field('<HHIIIHH', pe + 4)
    require(1 <= count <= 96, 'section count outside inspection bound')
    opt = pe + 24
    require(optsize >= 112 and opt + optsize <= len(data), 'truncated optional header')
    magic, = field('<H', opt)
    require(magic == 0x20b, 'only PE32+ inventory is implemented')
    entry, = field('<I', opt + 16)
    base, = field('<Q', opt + 24)
    image_size, headers_size = field('<II', opt + 56)
    subsystem, = field('<H', opt + 68)
    ndir, = field('<I', opt + 108)
    require(ndir <= 16 and 112 + ndir * 8 <= optsize, 'directory table outside optional header')
    end = opt + optsize + count * 40
    require(end <= headers_size <= len(data), 'invalid section table / headers size')
    sections = []
    for index in range(count):
        name, size, rva, raw_size, raw, _, _, _, _, flags = field('<8sIIIIIIHHI', opt + optsize + index * 40)
        require(not raw_size or (headers_size <= raw <= len(data) - raw_size), 'section raw range outside file')
        span = max(size, raw_size)
        require(span > 0 and headers_size <= rva <= image_size - span, 'section RVA range outside image')
        for previous in sections:
            require(max(rva, previous['rva']) >= min(rva + span, previous['rva'] + previous['span']),
                    'ambiguous overlapping virtual sections')
            if raw_size and previous['raw_size']:
                require(max(raw, previous['raw_offset']) >= min(raw + raw_size, previous['raw_offset'] + previous['raw_size']),
                        'ambiguous overlapping raw sections')
        sections.append(dict(name=name.rstrip(b'\0').decode('ascii', errors='backslashreplace'),
                             rva=rva, virtual_size=size, raw_size=raw_size, raw_offset=raw,
                             span=span, flags=flags))

    def offset(rva, size):
        require(rva >= 0 and size >= 0, 'negative mapped range')
        if rva < headers_size and size <= headers_size - rva:
            return rva
        candidates = [s['raw_offset'] + rva - s['rva'] for s in sections
                      if s['rva'] <= rva and size <= s['raw_size'] - (rva - s['rva'])]
        require(len(candidates) == 1, 'metadata is not a unique file-backed RVA range')
        return candidates[0]

    def string(rva):
        require(rva > 0, 'null import name')
        result = bytearray()
        for i in range(256):
            value = data[offset(rva + i, 1)]
            if value == 0:
                require(bool(result), 'empty import name')
                return result.decode('ascii')
            require(33 <= value <= 126, 'non-printable import name')
            result.append(value)
        raise InventoryError('unterminated import name within 256 bytes')

    dirs = []
    for index in range(ndir):
        address, size = field('<II', opt + 112 + index * 8)
        require(bool(address) == bool(size), 'incomplete directory ' + DIRECTORIES[index])
        if address:
            dirs.append(dict(index=index, name=DIRECTORIES[index], address=address, size=size,
                             address_kind='file_offset' if index == 4 else 'rva'))
    imports = []
    import_dir = next((d for d in dirs if d['index'] == 1), None)
    if import_dir:
        start, length = import_dir['address'], import_dir['size']
        require(length >= 20, 'truncated import directory')
        for index in range(min(length // 20, 256)):
            lookup, stamp, forward, dll_rva, first = field('<IIIII', offset(start + index * 20, 20))
            if not any((lookup, stamp, forward, dll_rva, first)):
                break
            dll = string(dll_rva).lower()
            require(first != 0, 'null IAT RVA')
            for slot in range(4096):
                require(len(imports) < 4096, 'total imports exceed inspection limit')
                value, = field('<Q', offset((lookup or first) + slot * 8, 8))
                if not value:
                    break
                if value & (1 << 63):
                    require(value & 0x7fffffffffff0000 == 0, 'invalid ordinal encoding')
                    name, ordinal = None, value & 0xffff
                else:
                    require(value <= 0xffffffff, 'invalid named import RVA')
                    offset(value, 2)
                    name, ordinal = string(value + 2), None
                imports.append(dict(dll=dll, name=name, ordinal=ordinal, iat_rva=first + slot * 8,
                                    binding='restricted_arguments' if (dll, name) in SIGNATURES else 'unavailable'))
            else:
                raise InventoryError('unterminated import thunk array')
        else:
            raise InventoryError('unterminated or oversized import descriptor array')
    return dict(machine=machine, characteristics=characteristics, entry_rva=entry, image_base=base,
                image_size=image_size, subsystem=subsystem, sections=sections, directories=dirs, imports=imports)


def analyze(data):
    report = dict(schema=1, profile=PROFILE, input_sha256=hashlib.sha256(data).hexdigest(), input_bytes=len(data),
                  status='UNSUPPORTED', issues=[], inventory=None,
                  instruction_analysis='NOT_RUN', guest_executions=0,
                  scope='PE metadata and strict loader admission only; build, runtime API arguments and correctness remain unverified')

    def issue(code, message, **location):
        report['issues'].append(dict(code=code, message=message, **location))

    try:
        require(len(data) <= MAX_FILE, 'input exceeds 64 MiB inspection limit')
        info = inventory(data)
        report['inventory'] = info
    except InventoryError as error:
        issue('INVENTORY_UNAVAILABLE', str(error))
        return report
    if info['machine'] != 0x8664:
        issue('ARCH_UNSUPPORTED', 'process-v1 requires AMD64 machine 0x8664')
    if info['characteristics'] & 0x2000:
        issue('DLL_UNSUPPORTED', 'process-v1 has no multi-module DLL initialization')
    if info['subsystem'] != 3:
        issue('SUBSYSTEM_UNSUPPORTED', 'this entry currently builds console process profiles only')
    for item in info['directories']:
        if item['index'] not in (1, 5, 12):
            issue('DIRECTORY_UNSUPPORTED', 'process-v1 does not accept ' + item['name'], directory=item['index'])
    for item in info['imports']:
        if item['binding'] == 'unavailable':
            issue('IMPORT_UNSUPPORTED', 'no process-v1 binding', dll=item['dll'], name=item['name'],
                  ordinal=item['ordinal'], iat_rva=item['iat_rva'])
    try:
        image = load_image(data)
    except ImageError as error:
        issue('LOADER_REJECT', str(error))
    else:
        executable = [s for s in image.sections if s['permissions'] & 4]
        if len(executable) != 1:
            issue('TEXT_PROFILE_UNSUPPORTED', 'exactly one executable range is required')
        else:
            section = executable[0]
            start, size = section['rva'], min(section['virtual_size'], section['raw_size'])
            if size > 32768 or not start <= image.entry_rva < start + size:
                issue('TEXT_PROFILE_UNSUPPORTED', 'entry must be file-backed within a <=32768-byte executable range')
            if any(start <= r['rva'] < start + size for r in image.relocations):
                issue('TEXT_RELOCATION_UNSUPPORTED', 'relocations in executable bytes are not supported')
        report['loader'] = dict(status='ADMITTED', relocation_count=len(image.relocations),
                                import_count=len(image.imports), mapped_bytes=len(image.data))
    if not report['issues']:
        report['status'] = 'ELIGIBLE_FOR_BUILD_NOT_DECODED'
    return report
