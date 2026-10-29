"""Complete-host planning and production refusal gates; no compiler is run."""
import copy
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest

from portable_app_v1 import lift, producer
from portable_graphics_v1 import build as graphics_provider
from portable_graphics_v1.test_backend import dylib


def version_image(path, minimum=(15, 2, 0), platform=1, duplicate=False):
    packed = (minimum[0] << 16) | (minimum[1] << 8) | minimum[2]
    command = struct.pack('<6I', 0x32, 24, platform, packed, packed, 0)
    body = command * (2 if duplicate else 1)
    path.write_bytes(struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2,
                                 2 if duplicate else 1, len(body), 0, 0) + body)


def synthetic_provider(base):
    """Real parser input only; this fixture is never a build/execution claim."""
    prefix = base / 'provider'
    source = prefix / 'source'
    for name in ('include/native/directx/d3d11.h', 'include/native/directx/dxgi.h',
                 'include/native/windows/windows.h', 'include/native_wsi.h', 'src/nativemetal/native_wsi.c'):
        item = source / name
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text('fixture header\n')
    runtime = prefix / 'runtime'
    runtime.mkdir()
    for name, dependency in (('d3d11.dylib', '@rpath/dxgi.dylib'),
                             ('dxgi.dylib', '@rpath/winemetal.dylib'),
                             ('winemetal.dylib', '/usr/lib/libSystem.B.dylib')):
        item = runtime / name
        item.write_bytes(dylib(name, dependency))
        item.chmod(0o755)
    licenses = prefix / 'licenses'
    names = ['DXMT-LICENSE', 'DXMT-COPYING.LIB', 'LLVM15-LICENSE.TXT', 'DXBCParser-MIT.txt',
             'DirectX-Headers-COPYING.MinGW-w64.txt', 'DirectX-Headers-README.md']
    names += ['BackendChanges/' + item.name for item in [*graphics_provider.PATCHES, *graphics_provider.ADAPTERS]]
    for name in names:
        item = licenses / name
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text('fixture notice\n')
    sdk = base / 'SDK'
    sdk.mkdir()
    (sdk / 'SDKSettings.json').write_text('{"fixture":true}\n')
    record = dict(schema=1, status=graphics_provider.STATUS, profile=graphics_provider.PROFILE,
                  minimum_macos=graphics_provider.MINIMUM,
                  layout={'source': 'source', **{name[:-6]: 'runtime/' + name for name in graphics_provider.NAMES}},
                  runtime_files={'runtime/' + key: value for key, value in graphics_provider.tree(runtime).items()},
                  source_tree=graphics_provider.tree(source), licenses=graphics_provider.tree(licenses),
                  external_prerequisites={'sdk': str(sdk), 'sdk_settings': {'SDKSettings.json': lift.sha(sdk / 'SDKSettings.json')}})
    (prefix / 'provider.json').write_text(json.dumps(record, sort_keys=True))
    return graphics_provider.paths_for(prefix)


class ProductionBoundaries(unittest.TestCase):
    def test_backend_identity_uses_actual_validated_receipt_and_three_library_closure(self):
        with tempfile.TemporaryDirectory(prefix='portable-backend-binding-') as temporary:
            base = Path(temporary).resolve()
            provider = synthetic_provider(base)
            normalized, identities, graph = producer.backend_identity(provider, base / 'out/native-executable')
            self.assertEqual(normalized['provider_sha256'], lift.sha(provider['provider_manifest']))
            self.assertEqual(set(graph['nodes']), {str(provider[name]) for name in producer.LIBRARIES})
            self.assertIn(str(provider['source'] / 'include/native/directx/d3d11.h'), identities)
            self.assertIn(str(provider['sdk'] / 'SDKSettings.json'), identities)
            provider['provider_manifest'].write_text('not even JSON')
            provider['provider_sha256'] = lift.sha(provider['provider_manifest'])
            with self.assertRaises(ValueError):
                producer.backend_identity(provider, base / 'out/native-executable')

    def test_caller_roles_cannot_differ_from_the_actual_provider_receipt(self):
        with tempfile.TemporaryDirectory(prefix='portable-backend-roles-') as temporary:
            base = Path(temporary).resolve()
            original = synthetic_provider(base)
            alternate = base / 'alternate'
            alternate.mkdir()
            receipt_copy = original['provider_manifest'].parent / 'other-receipt.json'
            receipt_copy.write_bytes(original['provider_manifest'].read_bytes())
            changes = [('source', alternate), ('sdk', alternate),
                       ('d3d11', original['dxgi']), ('dxgi', original['winemetal']),
                       ('winemetal', original['d3d11']), ('minimum_macos', '15.3'),
                       ('provider_manifest', receipt_copy), ('provider_sha256', '0' * 64),
                       ('licenses', {'DXMT-LICENSE': original['licenses']['DXMT-LICENSE']})]
            for key, value in changes:
                provider = copy.deepcopy(original)
                provider[key] = value
                with self.subTest(role=key), self.assertRaises(ValueError):
                    producer.backend_identity(provider, base / 'out/native-executable')

    def test_used_backend_files_cannot_change_behind_an_unchanged_receipt(self):
        with tempfile.TemporaryDirectory(prefix='portable-backend-content-') as temporary:
            base = Path(temporary).resolve()
            provider = synthetic_provider(base)
            files = [provider['source'] / 'include/native/directx/d3d11.h',
                     provider['d3d11'], provider['licenses']['DXMT-LICENSE'],
                     provider['sdk'] / 'SDKSettings.json']
            for item in files:
                before = item.read_bytes()
                item.write_bytes(before + b'changed')
                with self.subTest(item=item.name), self.assertRaises(ValueError):
                    producer.backend_identity(provider, base / 'out/native-executable')
                item.write_bytes(before)
            producer.backend_identity(provider, base / 'out/native-executable')

    def test_output_is_disjoint_from_whole_cpu_and_graphics_installations(self):
        with tempfile.TemporaryDirectory(prefix='portable-output-boundary-') as temporary:
            base = Path(temporary).resolve()
            cpu, graphics = base / 'cpu', base / 'graphics'
            producer.disjoint_output(base / 'attempt', cpu, graphics)
            for out in (cpu, cpu / 'child', graphics, graphics / 'source/new-attempt', base):
                with self.subTest(out=out), self.assertRaisesRegex(ValueError, 'disjoint'):
                    producer.disjoint_output(out, cpu, graphics)
                self.assertEqual(list(base.iterdir()), [])

    def test_actual_pe_and_root_metadata_regenerate_identical_complete_host_headers(self):
        native = lift.ROOT / 'build/migration-v3/unified-349d130f4465be3d0bc363894073b45d/native'
        data = (native / 'input.exe').read_bytes()
        profile = json.loads((native / 'window-profile.json').read_bytes())
        roots = json.loads((native / 'compiler/roots.json').read_bytes())
        normalized, image, _ = producer.validate(data, profile)
        # No old Program object or producer method is instantiated. These are
        # actual PE bytes and frozen metadata used only as compatibility data.
        context = SimpleNamespace(image=image, source_bytes=data, source_sha256=lift.sha(native / 'input.exe'),
                                  roots=[roots['main'], *roots['roots']], root_manifest=roots)
        calls, instructions, observations = producer.generate_headers(context, normalized, write=False)
        self.assertTrue(calls)
        self.assertGreater(len(instructions), len(roots['instructions']))  # Registered RET thunks remain present.
        for name, text in context.generated_headers.items():
            self.assertEqual(text, (native / name).read_text())
        self.assertIn('aot_window_proc_1000', context.generated_headers['native_image.h'])
        self.assertTrue(context.virtual_calls)
        self.assertTrue(context.register_calls)

    def test_all_six_actual_units_and_required_native_flags_are_present(self):
        out = Path('/new/attempt')
        backend = dict(source='/new/backend/source', minimum_macos='15.2')
        tools = dict(clang='/apple/clang', **{'clang++': '/apple/clang++'}, sdk='/apple/sdk')
        rows = producer.compilation_units(out, backend, tools)
        self.assertEqual([row[0] for row in rows], ['host', 'runtime', 'native-backend', 'window-backend', 'cocoa', 'entry'])
        for name, source, compiler, flags in rows:
            self.assertTrue(source.is_file(), 'uses real frozen host source')
            self.assertIn('-mmacosx-version-min=15.2', flags)
            self.assertIn('-O3', flags)
            self.assertIn('-fno-lto', flags)
            self.assertIn(str(out), flags)
            if name == 'host':
                self.assertIn('-Dmain=aot_window_main', flags)
            if name in ('native-backend', 'window-backend'):
                self.assertIn('-I/new/backend/source/include/native/directx', flags)
                self.assertIn('-I/new/backend/source/include/native/windows', flags)
                self.assertIn('-fno-exceptions', flags)
            if name == 'entry':
                self.assertIn('-fno-objc-arc', flags)
                self.assertEqual(source, lift.ROOT / 'window_app_v1/entry.mm')
            self.assertNotIn(str(lift.OLD_WORK), json.dumps([str(source), compiler, flags]))

    def test_deployment_metadata_is_checked_from_macho_bytes(self):
        with tempfile.TemporaryDirectory(prefix='portable-minimum-') as temporary:
            executable = Path(temporary).resolve() / 'image'
            version_image(executable)
            self.assertEqual(producer.minimum_version(executable), (15, 2, 0))
            version_image(executable, platform=2)
            with self.assertRaisesRegex(ValueError, 'non-macOS'):
                producer.minimum_version(executable)
            version_image(executable, duplicate=True)
            with self.assertRaisesRegex(ValueError, 'unique'):
                producer.minimum_version(executable)

    def test_invalid_version_and_backend_descriptor_fail_closed(self):
        for value in ('15', '-1.2', '15.2;command', '15.2.1.3', True, '999999.2'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                producer.version(value)
        with self.assertRaisesRegex(ValueError, 'complete explicit backend'):
            producer.backend_identity({}, Path('/new/out/executable'))
        descriptor = dict(source=lift.OLD_WORK, d3d11='x', dxgi='x', winemetal='x', sdk='x',
                          minimum_macos='15.2', provider_manifest='x', provider_sha256='0'*64, licenses={})
        with self.assertRaisesRegex(ValueError, 'old work'):
            producer.backend_identity(descriptor, Path('/new/out/executable'))

    def test_actual_profile_hash_import_and_callback_fail_before_commands(self):
        product = lift.ROOT / 'build/migration-v4/integration-01/product'
        pe = product / 'input.exe'
        original = json.loads((product / 'profile.json').read_bytes())
        changes = []
        bad = copy.deepcopy(original); bad['pe_sha256'] = '0' * 64; changes.append(bad)
        bad = copy.deepcopy(original); bad['callback_rvas'] = [True]; changes.append(bad)
        bad = copy.deepcopy(original); bad['imports'] = []; changes.append(bad)
        with tempfile.TemporaryDirectory(prefix='portable-profile-') as temporary:
            root = Path(temporary).resolve()
            for index, profile in enumerate(changes):
                calls = []
                output = root / str(index)
                with self.subTest(index=index), self.assertRaises(ValueError):
                    producer.build(root / 'missing-cpu', {}, pe, profile, 'org.peaotlab.Portable', output,
                                   lambda *args, **kwargs: calls.append(args))
                self.assertEqual(calls, [])
                self.assertFalse(output.exists())

    def test_generated_header_dependency_must_point_at_this_attempt(self):
        with tempfile.TemporaryDirectory(prefix='portable-dependency-') as temporary:
            root = Path(temporary).resolve()
            out = root / 'out'; out.mkdir()
            other = root / 'other'; other.mkdir()
            source = lift.ROOT / 'window_bridge/window_host.c'
            (out / 'native_image.h').write_text('new header')
            (other / 'native_image.h').write_text('wrong header')
            valid = f'probe: {source} {out / "native_image.h"}\n'
            self.assertEqual(producer.generated_dependencies('host', valid, out), [source, out / 'native_image.h'])
            invalid = f'probe: {source} {other / "native_image.h"}\n'
            with self.assertRaisesRegex(ValueError, 'different generated header'):
                producer.generated_dependencies('host', invalid, out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
