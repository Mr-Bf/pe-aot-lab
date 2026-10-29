"""Closed D3D11 probe imports: ExitProcess and D3D11CreateDevice only.

The immutable versioned parser accepts this explicit table without modifying
other profiles. Interface methods are runtime registrations, never IAT imports.
"""
from pathlib import Path
from types import MappingProxyType
from callback_bridge.imports_v1 import ImportedImage, ImageError, THUNK_START, load_imported_image
from memory_stage2.image_loader import load_image as load_plain, read_struct

SIGNATURES=MappingProxyType({('kernel32.dll','ExitProcess'):9,
                           ('d3d11.dll','D3D11CreateDevice'):100})

def load_image(source,load_base=None):
    original=source.read_bytes() if isinstance(source,Path) else bytes(source)
    pe,=read_struct('<I',original,0x3c)
    imports=read_struct('<II',original,pe+24+112+8)
    if imports==(0,0):
        # Import-free synthetic shape tests and the C3 return shim register no API.
        return ImportedImage(**vars(load_plain(original,load_base)),imports=[],import_ranges=[])
    return load_imported_image(original,load_base,signatures=SIGNATURES)
