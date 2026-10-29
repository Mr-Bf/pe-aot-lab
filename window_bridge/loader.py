"""Closed import address labels for the prepared Win32 window sample.

The immutable versioned parser accepts this explicit table without modifying
other profiles. Interface methods are runtime registrations, never IAT imports.
This loader does not implement any Win32 or graphics API.
"""
from pathlib import Path
from types import MappingProxyType
from callback_bridge.imports_v1 import ImportedImage, ImageError, THUNK_START, load_imported_image
from memory_stage2.image_loader import load_image as load_plain, read_struct

SIGNATURES=MappingProxyType({
    ('kernel32.dll','CreateFileA'):4, ('kernel32.dll','WriteFile'):5,
    ('kernel32.dll','CloseHandle'):7, ('kernel32.dll','GetLastError'):8,
    ('kernel32.dll','ExitProcess'):9,
    ('d3d11.dll','D3D11CreateDeviceAndSwapChain'):200,
    ('kernel32.dll','GetModuleHandleA'):201,
    ('user32.dll','AdjustWindowRectEx'):210, ('user32.dll','CreateWindowExA'):211,
    ('user32.dll','DefWindowProcA'):212, ('user32.dll','DestroyWindow'):213,
    ('user32.dll','DispatchMessageA'):214, ('user32.dll','GetClientRect'):215,
    ('user32.dll','GetMessageA'):216, ('user32.dll','PostQuitMessage'):217,
    ('user32.dll','RegisterClassExA'):218, ('user32.dll','SetFocus'):219,
    ('user32.dll','ShowWindow'):220, ('user32.dll','UnregisterClassA'):221,
    ('user32.dll','ValidateRect'):222})

def load_image(source,load_base=None):
    original=source.read_bytes() if isinstance(source,Path) else bytes(source)
    pe,=read_struct('<I',original,0x3c)
    imports=read_struct('<II',original,pe+24+112+8)
    if imports==(0,0):
        # Import-free synthetic shape tests and the C3 return shim register no API.
        return ImportedImage(**vars(load_plain(original,load_base)),imports=[],import_ranges=[])
    return load_imported_image(original,load_base,signatures=SIGNATURES)
