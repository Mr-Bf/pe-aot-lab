"""Restricted no-argument process profile: files 4..8, ExitProcess 9, or no imports."""
from pathlib import Path
from types import MappingProxyType
from callback_bridge.imports_v1 import ImportedImage,ImageError,THUNK_START,load_imported_image
from memory_stage2.image_loader import load_image as load_plain,read_struct
SIGNATURES=MappingProxyType({('kernel32.dll','CreateFileA'):4,('kernel32.dll','WriteFile'):5,
    ('kernel32.dll','ReadFile'):6,('kernel32.dll','CloseHandle'):7,('kernel32.dll','GetLastError'):8,
    ('kernel32.dll','ExitProcess'):9})
def load_image(source,load_base=None):
    original=source.read_bytes() if isinstance(source,Path) else bytes(source)
    pe,=read_struct('<I',original,0x3c)
    imports=read_struct('<II',original,pe+24+112+8)
    if imports==(0,0):
        return ImportedImage(**vars(load_plain(original,load_base)),imports=[],import_ranges=[])
    return load_imported_image(original,load_base,signatures=SIGNATURES)
