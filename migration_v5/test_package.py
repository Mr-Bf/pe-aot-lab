"""Synthetic Mach-O packaging with a Python recorder; never executes native code."""
import contextlib
import copy
import json
from pathlib import Path
import plistlib
import shutil
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from portable_app_v1 import lift, package, producer


def string_command(kind, name, dylib=False):
    offset=24 if dylib else 12;raw=name.encode()+b'\0';size=(offset+len(raw)+7)//8*8
    header=struct.pack('<III',kind,size,offset)+(struct.pack('<III',0,0,0) if dylib else b'')
    return (header+raw).ljust(size,b'\0')


def image(path, *, main=False, identity=None, rpaths=(), dependencies=(), payload=b'AOT!', minimum=(15,2,0)):
    packed=minimum[0]<<16|minimum[1]<<8|minimum[2]
    commands=[struct.pack('<6I',0x32,24,1,packed,packed,0)]
    if not main:commands.append(string_command(0xd,identity or '@rpath/'+path.name,True))
    commands += [string_command(0x8000001c,value) for value in rpaths]
    commands += [string_command(0xc,value,True) for value in dependencies]
    offset=32+sum(map(len,commands))+152
    segment=struct.pack('<II16sQQQQiiII',0x19,152,b'__TEXT',0x1000,0x1000,offset,len(payload),7,5,1,0)
    section=struct.pack('<16s16sQQ8I',b'__text',b'__TEXT',0x1000,len(payload),offset,2,0,0,0x80000400,0,0,0)
    commands.append(segment+section);raw=b''.join(commands)
    path.write_bytes(struct.pack('<8I',0xfeedfacf,0x100000c,0,2 if main else 6,len(commands),len(raw),0,0)+raw+payload)
    path.chmod(0o755)


class Fixture:
    def __init__(self,base,native_directory=None):
        self.base=base;self.native_dir=native_directory or base/'native';self.native_dir.mkdir(parents=True)
        self.cpu=base/'cpu';self.cpu.mkdir(exist_ok=True);(self.cpu/'provider.json').write_text('CPU fixture')
        self.graphics=base/'graphics';self.graphics.mkdir(exist_ok=True)
        self.runtime=self.graphics/'runtime';self.runtime.mkdir()
        self.sdk=base/'SDK';self.sdk.mkdir(exist_ok=True)
        descriptor={'external_prerequisites':{'developer':str(base/'AppleDeveloper')}}
        self.backend_manifest=self.graphics/'provider.json';self.backend_manifest.write_text(json.dumps(descriptor))
        for name,dependency in [('d3d11.dylib','@rpath/dxgi.dylib'),('dxgi.dylib','@rpath/winemetal.dylib'),
                                ('winemetal.dylib','/usr/lib/libSystem.B.dylib')]:
            image(self.runtime/name,rpaths=['@loader_path/'],dependencies=[dependency])
        self.executable=self.native_dir/'native-executable'
        image(self.executable,main=True,rpaths=[str(self.runtime)],dependencies=['@rpath/d3d11.dylib'])
        dependency=self.native_dir/'dependency.txt';dependency.write_text('fixture immutable compilation input')
        self.native=dict(schema=1,status=producer.STATUS,identifier='org.peaotlab.Test',minimum_macos='15.2',
            cpu_prefix=str(self.cpu),cpu_provider_sha256=lift.sha(self.cpu/'provider.json'),
            backend={'provider_manifest':str(self.backend_manifest),'provider_sha256':lift.sha(self.backend_manifest)},
            native_executable=str(self.executable),native_sha256=lift.sha(self.executable),
            library_graph=package.graph_tools.library_graph(self.executable,self.executable),
            input_sha256='1'*64,profile={'fixture':'not guest acceptance'},inputs_before=lift.snapshot([dependency]),
            artifacts=lift.artifacts(self.native_dir),manifest_path=str(self.native_dir/'producer.json'),
            instruction_count=1,callback_count=0)
        self.manifest=Path(self.native['manifest_path']);self.manifest.write_text(json.dumps(self.native))
        self.notice=self.base/'notice.txt';self.notice.write_text('synthetic notice')
        self.resources={'Licenses/Graphics/LLVM15-LICENSE.TXT':self.notice,'LifterChanges/fixture.patch':self.notice}
        self.calls=[]

    def save(self):self.manifest.write_text(json.dumps(self.native))

    def run(self,argv,label,cwd=None,env=None,expected=0):
        argv=list(map(str,argv));self.calls.append((argv,label))
        if argv[0]=='/usr/bin/install_name_tool':
            path=Path(argv[-1]);node=package.graph_tools.macho(path);rpaths=list(node['rpaths'])
            dependencies=[row['name'] for row in node['dependencies']];identity=node['id'];i=1
            while i<len(argv)-1:
                option=argv[i];i+=1
                if option=='-id':identity=argv[i];i+=1
                elif option=='-delete_rpath':rpaths.remove(argv[i]);i+=1
                elif option=='-add_rpath':rpaths.append(argv[i]);i+=1
                elif option=='-change':
                    old,new=argv[i:i+2];i+=2;dependencies=[new if value==old else value for value in dependencies]
                else:raise RuntimeError('unexpected mock transformation '+option)
            image(path,main=node['filetype']==2,identity=identity,rpaths=rpaths,dependencies=dependencies,
                  payload=path.read_bytes()[-4:],minimum=producer.minimum_version(path))
        elif argv[0]!='/usr/bin/codesign':raise RuntimeError('test refuses external/native command: '+repr(argv))
        return dict(argv=argv,returncode=0,stdout='synthetic callback; no native execution',stderr='')

    def invoke(self,out=None,run=None):
        with mock.patch.object(package,'resource_inputs',return_value=self.resources), \
             mock.patch.object(package.formats,'source_program',side_effect=AssertionError('old source guard called')):
            return package.build(self.native,out or self.base/'package',
                                 {'identifier':self.native['identifier'],'name':'PE AOT Portable Window'},run or self.run)


class PackagingBoundaries(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='migration-v5-package-test-');self.addCleanup(temp.cleanup)
        self.base=Path(temp.name).resolve();self.fixture=Fixture(self.base)

    def test_full_mock_packaging_preserves_sections_notices_and_moved_graph(self):
        result=self.fixture.invoke();app=Path(result['app']);moved=Path(result['relocated'])
        self.assertEqual(result['status'],package.STATUS);self.assertEqual(result['guest_executions'],0)
        self.assertEqual(result['gpu_executions'],0);self.assertEqual(result['app_tree'],result['relocated_tree'])
        self.assertEqual(len(result['code_sections']),4)
        self.assertEqual(plistlib.loads((app/'Contents/Info.plist').read_bytes())['LSMinimumSystemVersion'],'15.2')
        for name,source in self.fixture.resources.items():
            self.assertEqual((app/'Contents/Resources'/name).read_bytes(),source.read_bytes())
        self.assertEqual(package.formats.normalized_graph(result['graph'],app),
                         package.formats.normalized_graph(result['relocated_graph'],moved))
        self.assertEqual(len(self.fixture.calls),10)

    def test_tuple_graph_edges_and_path_values_match_their_persisted_json_semantics(self):
        f=self.fixture
        f.native['library_graph']['edges']=tuple(tuple(edge) for edge in f.native['library_graph']['edges'])
        f.native['native_executable']=f.executable
        f.native['manifest_path']=f.manifest
        f.native['backend']['provider_manifest']=f.backend_manifest
        persisted=json.loads(json.dumps(f.native,default=str))
        f.manifest.write_text(json.dumps(persisted))
        result=f.invoke()
        self.assertEqual(result['status'],package.STATUS)
        self.assertEqual(json.loads(f.manifest.read_bytes()),persisted)
        self.assertIsInstance(f.native['library_graph']['edges'],tuple)
        self.assertIsInstance(f.native['native_executable'],Path)
        self.assertEqual(len(result['code_sections']),4)

    def test_json_normalization_does_not_hide_an_actual_receipt_value_difference(self):
        f=self.fixture
        f.native['library_graph']['edges']=[tuple(edge) for edge in f.native['library_graph']['edges']]
        f.native['native_executable']=f.executable
        persisted=json.loads(json.dumps(f.native,default=str))
        persisted['library_graph']['edges'][0][1]='@rpath/incorrect-library.dylib'
        f.manifest.write_text(json.dumps(persisted))
        with self.assertRaisesRegex(ValueError,'producer receipt differs from passed record'):
            f.invoke()
        self.assertFalse(f.calls)
        self.assertFalse((self.base/'package').exists())

    def test_mapping_and_plan_use_only_actual_new_program_and_three_libraries(self):
        f=self.fixture;program=SimpleNamespace(executable=f.executable,build_manifest=f.native)
        app=self.base/'app.app';moved=self.base/'moved.app'
        with mock.patch.object(package.formats,'source_program',side_effect=AssertionError('old guard')):
            mapping=package.formats.mapping_for(program,app)
            plans=package.formats.plans(program,app,moved,{'install_name_tool':'/fake/repair','codesign':'/fake/sign'})
            identities={path:package.formats.section_identity(path) for path in mapping}
        self.assertEqual(set(mapping),{str(f.executable),*(str(f.runtime/name) for name in package.NAMES)})
        self.assertEqual(len(identities),4);self.assertEqual(len(plans),10)
        self.assertNotIn(str(lift.OLD_WORK),json.dumps(plans))

    def test_old_or_incomplete_library_graph_is_rejected(self):
        f=self.fixture;program=SimpleNamespace(executable=f.executable,build_manifest=copy.deepcopy(f.native))
        program.build_manifest['library_graph']['nodes'].pop(str(f.runtime/'dxgi.dylib'))
        with self.assertRaises(Exception):package.formats.mapping_for(program,self.base/'app.app')

    def test_existing_output_is_preserved_without_commands(self):
        out=self.base/'existing';out.mkdir();(out/'keep').write_text('preserve')
        with self.assertRaises(ValueError):self.fixture.invoke(out)
        self.assertEqual((out/'keep').read_text(),'preserve');self.assertFalse(self.fixture.calls)

    def test_failed_signing_records_failure_without_package_success(self):
        def reject(argv,*args,**kwargs):
            if argv[0]=='/usr/bin/codesign':raise RuntimeError('mock signing rejected')
            return self.fixture.run(argv,*args,**kwargs)
        with self.assertRaisesRegex(RuntimeError,'mock signing rejected'):self.fixture.invoke(run=reject)
        out=self.base/'package';self.assertTrue((out/'failure.json').is_file());self.assertFalse((out/'package.json').exists())

    def test_changed_producer_artifact_is_rejected_before_commands(self):
        (self.fixture.native_dir/'dependency.txt').write_text('changed')
        with self.assertRaises(ValueError):self.fixture.invoke()
        self.assertFalse(self.fixture.calls)

    def test_original_executable_change_during_copy_is_rejected(self):
        original=shutil.copy2
        def mutate(source,destination,*args,**kwargs):
            if Path(source)==self.fixture.executable:
                raw=self.fixture.executable.read_bytes();self.fixture.executable.write_bytes(raw[:-4]+b'EVIL')
            return original(source,destination,*args,**kwargs)
        with mock.patch.object(package.shutil,'copy2',side_effect=mutate):
            with self.assertRaises(ValueError):self.fixture.invoke()

    def test_package_output_cannot_be_inside_any_input_installation(self):
        for prefix in (self.fixture.cpu,self.fixture.graphics,self.fixture.native_dir):
            with self.subTest(prefix=prefix),self.assertRaises(ValueError):self.fixture.invoke(prefix/'package')
        self.assertFalse(self.fixture.calls)

    def test_plist_cannot_understate_code_minimum_and_extra_library_is_rejected(self):
        result=self.fixture.invoke();app=Path(result['app']);value=result['spec']
        info=app/'Contents/Info.plist';info.write_bytes(plistlib.dumps(package.plist(value,'14.0')))
        with self.assertRaises(ValueError):package.graph(app,value,'14.0')
        info.write_bytes(plistlib.dumps(package.plist(value,'15.2')))
        (app/'Contents/Frameworks/extra.dylib').write_bytes(b'extra')
        with self.assertRaises(ValueError):package.graph(app,value,'15.2')

    def test_resource_mapping_retains_all_verified_backend_notices_and_cpu_changes(self):
        f=self.fixture;cpu_source=self.base/'cpu-source';cpu_source.mkdir();(cpu_source/'LICENSE').write_text('Remill notice')
        notice_names={'DXMT-LICENSE','DXMT-COPYING.LIB','LLVM15-LICENSE.TXT','DXBCParser-MIT.txt',
                      'DirectX-Headers-COPYING.MinGW-w64.txt','DirectX-Headers-README.md','BackendChanges/native_wsi.c'}
        backend={'provider_sha256':f.native['backend']['provider_sha256'],'licenses':{name:f.notice for name in notice_names}}
        with mock.patch.object(package.cpu,'paths_for',return_value=({}, {'source':cpu_source})), \
             mock.patch.object(package.backend,'paths_for',return_value=backend):
            result=package.resource_inputs(f.native)
        self.assertTrue({'Licenses/Graphics/'+name for name in notice_names}<=set(result))
        self.assertTrue({'LifterChanges/'+path.name for path in package.cpu.PATCHES}<=set(result))
        self.assertEqual(result['Licenses/Remill-LICENSE'],cpu_source/'LICENSE')


if __name__=='__main__':unittest.main()
