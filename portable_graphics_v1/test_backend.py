"""Independent synthetic provider boundaries; no real prefix or native execution.

The negative cases express the required consumer contract. A failed rejection
test identifies a real acceptance gap; fixtures are never claimed to be builds.
"""
import copy
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from . import build


def string_command(kind, name, dylib=False):
    offset = 24 if dylib else 12
    raw = name.encode() + b'\0'; size = (offset + len(raw) + 7) // 8 * 8
    header = struct.pack('<III',kind,size,offset)
    if dylib:header += struct.pack('<III',0,0,0)
    return (header + raw).ljust(size,b'\0')


def dylib(name, dependency=None, minimum=(15,2,0), platform=1, filetype=6, identity=None):
    value = minimum[0] << 16 | minimum[1] << 8 | minimum[2]
    commands = [string_command(0x8000001c,'@loader_path/'), struct.pack('<6I',0x32,24,platform,value,0x0f0200,0)]
    if identity is not False:commands.insert(0,string_command(0xd,identity or '@rpath/'+name,True))
    if dependency:commands.append(string_command(0xc,dependency,True))
    raw = b''.join(commands)
    return struct.pack('<8I',0xfeedfacf,0x100000c,0,filetype,len(commands),len(raw),0,0)+raw


class BackendProviderBoundaries(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='graphics-backend-independent-');self.addCleanup(temp.cleanup)
        self.base=Path(temp.name).resolve();self.prefix=self.base/'provider';self.prefix.mkdir()
        source=self.prefix/'source';source.mkdir()
        for name in ('include/native/directx/d3d11.h','include/native/directx/dxgi.h',
                     'include/native/windows/windows.h','include/native_wsi.h','src/nativemetal/native_wsi.c'):
            path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture header\n')
        runtime=self.prefix/'runtime';runtime.mkdir()
        for name,dependency in [('d3d11.dylib','@rpath/dxgi.dylib'),('dxgi.dylib','@rpath/winemetal.dylib'),
                                ('winemetal.dylib','/usr/lib/libSystem.B.dylib')]:
            (runtime/name).write_bytes(dylib(name,dependency))
            (runtime/name).chmod(0o755)
        license_root=self.prefix/'licenses';license_root.mkdir()
        for name in ('DXMT-LICENSE','DXMT-COPYING.LIB','LLVM15-LICENSE.TXT','DXBCParser-MIT.txt',
                     'DirectX-Headers-COPYING.MinGW-w64.txt','DirectX-Headers-README.md'):
            (license_root/name).write_text('fixture notice\n')
        for source_path in [*build.PATCHES,*build.ADAPTERS]:
            path=license_root/'BackendChanges'/source_path.name;path.parent.mkdir(exist_ok=True)
            path.write_text('fixture source adaptation notice\n')
        self.sdk=self.base/'SDK';self.sdk.mkdir();(self.sdk/'SDKSettings.json').write_text('{"fixture":true}\n')
        self.record=dict(schema=1,status=build.STATUS,profile=build.PROFILE,minimum_macos=build.MINIMUM,
                         layout={'source':'source',**{name[:-6]:'runtime/'+name for name in build.NAMES}},
                         runtime_files=build.tree(runtime),source_tree=build.tree(source),licenses=build.tree(license_root),
                         external_prerequisites={'sdk':str(self.sdk),'sdk_settings':{'SDKSettings.json':build.digest(self.sdk/'SDKSettings.json')}})
        self.record['runtime_files']={'runtime/'+name:identity for name,identity in self.record['runtime_files'].items()}
        self.manifest=self.prefix/'provider.json';self.save()

    def save(self):self.manifest.write_text(json.dumps(self.record,sort_keys=True))

    def test_complete_synthetic_three_library_provider_is_accepted(self):
        result=build.paths_for(self.prefix)
        self.assertEqual(result['d3d11'],self.prefix/'runtime/d3d11.dylib')
        self.assertEqual(result['provider_sha256'],build.digest(self.manifest))
        self.assertEqual(set(result['licenses']),set(self.record['licenses']))

    def test_runtime_corruption_is_rejected(self):
        (self.prefix/'runtime/dxgi.dylib').write_bytes(b'changed')
        with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_escaped_layout_and_missing_library_are_rejected(self):
        for relative in ('../outside','/usr/lib/libSystem.B.dylib','runtime/missing.dylib'):
            with self.subTest(relative=relative):
                record=copy.deepcopy(self.record);record['layout']['d3d11']=relative
                self.manifest.write_text(json.dumps(record))
                with self.assertRaises((ValueError,FileNotFoundError)):build.paths_for(self.prefix)

    def test_wrong_minimum_or_platform_is_rejected_without_execution(self):
        for version,platform in [((14,0,0),1),((15,2,0),2)]:
            with self.subTest(version=version,platform=platform):
                path=self.prefix/'runtime/d3d11.dylib';path.write_bytes(dylib(path.name,'@rpath/dxgi.dylib',version,platform))
                self.record['runtime_files']['runtime/'+path.name]['sha256']=build.digest(path);self.save()
                with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_sdk_content_change_is_rejected(self):
        (self.sdk/'SDKSettings.json').write_text('changed')
        with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_three_library_roles_cannot_collapse_to_one_file(self):
        only=self.prefix/'runtime/winemetal.dylib'
        self.record['layout'].update(d3d11='runtime/'+only.name,dxgi='runtime/'+only.name,winemetal='runtime/'+only.name)
        self.record['runtime_files']={'runtime/'+only.name:self.record['runtime_files']['runtime/'+only.name]};self.save()
        with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_empty_sdk_settings_attestation_is_rejected(self):
        self.record['external_prerequisites']['sdk_settings']={};self.save()
        with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_manifest_change_during_verification_is_rejected(self):
        actual_tree=build.tree;changed=False
        def mutate_once(root):
            nonlocal changed
            result=actual_tree(root)
            if not changed:
                changed=True
                unverified=copy.deepcopy(self.record);unverified['minimum_macos']='0.0'
                self.manifest.write_text(json.dumps(unverified))
            return result
        with mock.patch.object(build,'tree',side_effect=mutate_once):
            with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_empty_license_tree_is_rejected(self):
        shutil.rmtree(self.prefix/'licenses');(self.prefix/'licenses').mkdir()
        self.record['licenses']={};self.save()
        with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_runtime_paths_must_be_the_declared_canonical_bundle_layout(self):
        shutil.copytree(self.prefix/'runtime',self.prefix/'elsewhere')
        self.record['layout'].update({name[:-6]:'elsewhere/'+name for name in build.NAMES})
        self.record['runtime_files']={name.replace('runtime/','elsewhere/'):value for name,value in self.record['runtime_files'].items()}
        self.save()
        with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_executable_missing_id_and_mismatched_dylib_id_are_rejected(self):
        for extra in ({'filetype':2},{'identity':False},{'identity':'@rpath/unrelated.dylib'}):
            with self.subTest(extra=extra):
                path=self.prefix/'runtime/d3d11.dylib';path.write_bytes(dylib(path.name,'@rpath/dxgi.dylib',**extra))
                self.record['runtime_files']['runtime/'+path.name]['sha256']=build.digest(path);self.save()
                with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_empty_source_tree_is_rejected(self):
        shutil.rmtree(self.prefix/'source');(self.prefix/'source').mkdir()
        self.record['source_tree']={};self.save()
        with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_missing_required_header_is_rejected_even_with_updated_manifest(self):
        (self.prefix/'source/include/native/directx/d3d11.h').unlink()
        self.record['source_tree']=build.tree(self.prefix/'source');self.save()
        with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_missing_llvm_notice_is_rejected_even_with_updated_manifest(self):
        (self.prefix/'licenses/LLVM15-LICENSE.TXT').unlink()
        self.record['licenses']=build.tree(self.prefix/'licenses');self.save()
        with self.assertRaises(ValueError):build.paths_for(self.prefix)

    def test_required_notice_alias_cannot_disappear_from_returned_license_map(self):
        path=self.prefix/'licenses/LLVM15-LICENSE.TXT';path.unlink();path.symlink_to('DXMT-LICENSE')
        self.record['licenses']=build.tree(self.prefix/'licenses');self.save()
        with self.assertRaises(ValueError):build.paths_for(self.prefix)


if __name__=='__main__':unittest.main()
