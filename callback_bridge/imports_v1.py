"""Versioned strict import parser; previous milestone remains immutable.

Derived from native_bridge/loader.py SHA256 7fb3a97f1eeea70d74b643507e3a5dcbfa3b75ae55fd7ba82c9780e87e88c774.
The parsing/interval/relocation algorithm is unchanged; the signature table is
an explicit parameter rather than mutable module state. This module only binds
guest IAT addresses. A runtime must separately implement every accepted signature.
No claim is made that earlier evidence applies to this new module.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

from memory_stage2.image_loader import (LoadedImage, ImageError, load_image as load_plain,
                                      read_struct, READ, EXEC, MAX_U64)

THUNK_START = 0xF0000000

@dataclass
class ImportedImage(LoadedImage):
    imports: list
    import_ranges: list

    def manifest(self):
        result = super().manifest()
        result.update(imports=self.imports, import_ranges=self.import_ranges,
                      scope='versioned strict named-import parser; explicit caller-supplied signature profile')
        return result


def load_imported_image(source, load_base=None, *, signatures):
    original = source.read_bytes() if isinstance(source, Path) else bytes(source)
    # The ordinary loader still validates the complete PE header/section/reloc
    # profile. Only these two directories are removed from its temporary input.
    pe, = read_struct('<I', original, 0x3c)
    opt = pe + 24
    directory = opt + 112
    imports_rva, imports_size = read_struct('<II', original, directory + 8)
    iat_rva, iat_size = read_struct('<II', original, directory + 12 * 8)
    if not imports_rva or imports_size < 40 or imports_size % 20:
        raise ImageError('requires a bounded, terminated import descriptor directory')
    if bool(iat_rva) != bool(iat_size):
        raise ImageError('incomplete IAT directory')
    prepared = bytearray(original)
    struct.pack_into('<II', prepared, directory + 8, 0, 0)
    struct.pack_into('<II', prepared, directory + 12 * 8, 0, 0)
    preferred = load_plain(prepared)
    ranges = []

    def read(rva, size, role):
        value = preferred.read(preferred.base + rva, size)
        if size and any(preferred.permissions[p] & EXEC
                        for p in range(rva // 4096, (rva + size - 1) // 4096 + 1)):
            raise ImageError('import metadata overlaps executable memory')
        ranges.append((rva, rva + size, role))
        return value

    def string(rva, role, limit=256):
        if rva <= 0:
            raise ImageError('null import string')
        buf = bytearray()
        for n in range(limit):
            ch = preferred.read(preferred.base + rva + n, 1)[0]
            if preferred.permissions[(rva+n)//4096] & EXEC:
                raise ImageError('import name overlaps executable memory')
            if ch == 0:
                if not buf: raise ImageError('empty import name')
                ranges.append((rva, rva+n+1, role))
                try: return buf.decode('ascii')
                except UnicodeDecodeError: raise ImageError('non-ASCII import name')
            if ch < 33 or ch > 126:
                raise ImageError('invalid import name character')
            buf.append(ch)
        raise ImageError('unterminated import name')

    descriptors = read(imports_rva, imports_size, 'descriptors')
    if iat_size:
        read(iat_rva, iat_size, 'iat_directory')
    rows = []
    slots = set()
    terminated = False
    for pos in range(0, imports_size, 20):
        ilt, stamp, forward, dll_rva, first = struct.unpack_from('<IIIII', descriptors, pos)
        if not any((ilt, stamp, forward, dll_rva, first)):
            if any(descriptors[pos:]): raise ImageError('data after import terminator')
            terminated = True
            break
        if stamp or forward or not ilt or not first or ilt % 8 or first % 8:
            raise ImageError('requires unbound imports with separate aligned ILT/IAT')
        dll = string(dll_rva, 'dll').lower()
        if dll not in {key[0] for key in signatures}:
            raise ImageError('unknown imported DLL: ' + dll)
        count_before = len(rows)
        for index in range(4096):
            lookup_rva, slot = ilt + index * 8, first + index * 8
            lookup, = struct.unpack('<Q', read(lookup_rva, 8, 'ilt'))
            old, = struct.unpack('<Q', read(slot, 8, 'iat'))
            if lookup_rva == slot:
                raise ImageError('shared ILT/IAT is outside the supported import profile')
            if iat_size and not (iat_rva <= slot and slot + 8 <= iat_rva + iat_size):
                raise ImageError('IAT entry outside declared IAT directory')
            if old != lookup: raise ImageError('bound or inconsistent IAT entry')
            if slot in slots: raise ImageError('duplicate IAT entry')
            slots.add(slot)
            if not lookup:
                break
            if lookup & (1 << 63): raise ImageError('ordinal imports unsupported')
            if lookup > 0xffffffff: raise ImageError('invalid import-by-name RVA')
            read(lookup, 2, 'hint')
            name = string(lookup + 2, 'symbol')
            signature = signatures.get((dll, name))
            if signature is None: raise ImageError('unknown imported function: ' + dll + '!' + name)
            rows.append(dict(dll=dll, name=name, signature=signature, iat_rva=slot,
                             target_rva=THUNK_START + signature * 4096))
            if len(rows) > 4096: raise ImageError('too many imports')
        else:
            raise ImageError('unterminated import lookup table')
        if len(rows) == count_before: raise ImageError('empty import descriptor')
    if not terminated or not rows: raise ImageError('missing import terminator or functions')
    # Loader writes to the IAT only. Reject overlap with other import structures,
    # including terminators, and with DIR64 patches before applying any binding.
    iat_intervals = [(start, end) for start, end, role in ranges if role == 'iat']
    other_intervals = [(start, end) for start, end, role in ranges if role not in ('iat', 'iat_directory')]
    def overlaps(left, right):
        # Sorted interval sweeps avoid an import-count x string-length scan.
        left, right = sorted(left), sorted(right)
        i = j = 0
        while i < len(left) and j < len(right):
            a, b = left[i]; c, d = right[j]
            if max(a, c) < min(b, d): return True
            if b <= d: i += 1
            else: j += 1
        return False
    if overlaps(iat_intervals, other_intervals):
        raise ImageError('IAT overlaps import metadata')
    if overlaps([(x['rva'], x['rva']+8) for x in preferred.relocations],
                [(start, end) for start, end, _ in ranges]):
        raise ImageError('relocation overlaps import metadata')
    loaded = load_plain(prepared, load_base=load_base)
    # Restore original guest-visible directory header bytes; the validation copy
    # is never presented as the original PE or used to compute input identity.
    loaded.data[directory + 8:directory + 16] = original[directory + 8:directory + 16]
    loaded.data[directory + 96:directory + 104] = original[directory + 96:directory + 104]
    for row in rows:
        if loaded.base > MAX_U64 - row['target_rva'] - 4096:
            raise ImageError('synthetic import address overflow')
        struct.pack_into('<Q', loaded.data, row['iat_rva'], loaded.base + row['target_rva'])
    loaded.source_sha256 = hashlib.sha256(original).hexdigest()
    return ImportedImage(**vars(loaded), imports=rows,
                         import_ranges=[list(item) for item in ranges])
