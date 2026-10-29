"""Named imports for the synchronous callback milestone, using an explicit profile."""
from types import MappingProxyType
from callback_bridge.imports_v1 import ImportedImage, ImageError, THUNK_START, load_imported_image

# Signature 3 is u64 InvokeCallback(guest_callback, a, b, c, d, e, f).
# The guest callback itself takes six u64 arguments and returns u64.
SIGNATURES = MappingProxyType({('kernel32.dll', 'GetCurrentProcessId'): 1,
    ('aotdemo.dll', 'NativeSix'): 2,
    ('aotdemo.dll', 'NativeInvokeCallback'): 3})

def load_image(source, load_base=None):
    return load_imported_image(source, load_base, signatures=SIGNATURES)
