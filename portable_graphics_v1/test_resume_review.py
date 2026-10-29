"""Independent finalization boundaries. No native command or compiler executes."""
from pathlib import Path
import copy
import hashlib
import json
import tempfile
import unittest
from unittest import mock

from . import build, resume
from migration_v5.test_package import Fixture, image


class RuntimeCommandReview(unittest.TestCase):
    def test_existing_wanted_rpath_is_kept_without_delete_add_cycle(self):
        target=Path('/new/finalized/runtime/winemetal.dylib')
        info={'rpaths':['@loader_path/','@loader_path/../../'],
              'dependencies':['/usr/lib/libSystem.B.dylib']}
        argv=build.runtime_command(target,info)
        self.assertEqual(argv,['/usr/bin/install_name_tool','-id','@rpath/winemetal.dylib',
                              '-delete_rpath','@loader_path/../../',target])
        self.assertEqual(info['rpaths'],['@loader_path/','@loader_path/../../'])

    def test_missing_rpath_is_added_once_and_library_edges_become_relative(self):
        target=Path('/new/finalized/runtime/d3d11.dylib')
        argv=build.runtime_command(target,{'rpaths':['/fresh/build/src/dxgi'],
            'dependencies':['/fresh/build/src/dxgi/dxgi.dylib','/usr/lib/libSystem.B.dylib']})
        self.assertEqual(argv.count('-add_rpath'),1)
        self.assertIn('@rpath/dxgi.dylib',argv)
        self.assertNotIn('/usr/lib/libSystem.B.dylib',argv)
        self.assertEqual(argv[-1],target)

    def test_ambiguous_rpath_or_unexpected_library_cannot_be_repaired_as_valid(self):
        for info in ({'rpaths':['@loader_path/','@loader_path/'],'dependencies':[]},
                     {'rpaths':[],'dependencies':['/outside/unrecognized.dylib']}):
            with self.subTest(info=info),self.assertRaises(ValueError):
                build.runtime_command(Path('/new/runtime/winemetal.dylib'),info)


class FinalizationReview(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='graphics-finalization-review-');self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name).resolve()

    def test_receipt_digest_duplicate_keys_and_read_time_change_are_rejected(self):
        path=self.base/'receipt.json';path.write_bytes(b'{"status":"fixture"}')
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(resume.bound_json(path,digest),{'status':'fixture'})
        with self.assertRaises(ValueError):resume.bound_json(path,'0'*64)
        original=Path.read_bytes;changed=False
        def concurrent(value):
            nonlocal changed
            raw=original(value)
            if value==path and not changed:changed=True;path.write_bytes(b'{"status":"changed"}')
            return raw
        with mock.patch.object(Path,'read_bytes',concurrent):
            with self.assertRaises(ValueError):resume.bound_json(path,digest)
        path.write_bytes(b'{"status":1,"status":2}')
        with self.assertRaises(Exception):resume.bound_json(path)

    def test_finalization_cannot_overlap_or_overwrite_originals(self):
        origin=self.base/'origin';origin.mkdir();(origin/'keep').write_text('immutable')
        for prefix,out in ((origin,self.base/'out'),(origin/'new',self.base/'out'),
                           (self.base/'new',origin/'new'),(self.base/'new',self.base/'new/out')):
            with self.subTest(prefix=prefix,out=out),self.assertRaises(ValueError):resume.isolated(prefix,out,origin)
        self.assertEqual((origin/'keep').read_text(),'immutable')

    def synthetic_origin(self):
        origin=self.base/'origin';origin.mkdir();(origin/'failure.json').write_text('preserved synthetic failure')
        original=self.base/'graphics-03';original.mkdir()
        stale=original/'runtime';stale.mkdir();(stale/'winemetal.dylib').write_bytes(b'partial unusable runtime: never a code input')
        source=original/'source'
        for relative in ('LICENSE','COPYING.LIB','include/native/directx/d3d11.h','include/native/directx/dxgi.h',
                         'include/native/windows/windows.h','include/native_wsi.h','src/nativemetal/native_wsi.c'):
            path=source/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture source or notice')
        llvm_source=original/'llvm-source';(llvm_source/'llvm').mkdir(parents=True)
        (llvm_source/'llvm/LICENSE.TXT').write_text('LLVM fixture notice')
        headers=original/'headers';headers.mkdir()
        for name in ('COPYING.MinGW-w64.txt','README.md'):(headers/name).write_text('headers fixture notice')
        target=original/'dxmt-build';target.mkdir();raw={}
        edges={'d3d11.dylib':'@rpath/dxgi.dylib','dxgi.dylib':'@rpath/winemetal.dylib',
               'winemetal.dylib':'/usr/lib/libSystem.B.dylib','d3d10core.dylib':'@rpath/d3d11.dylib'}
        for name,dependency in edges.items():
            path=target/name;image(path,rpaths=['@loader_path/','@loader_path/../../'],dependencies=[dependency])
            raw[str(path)]=dict(sha256=resume.sha(path),macho=build.binary.macho(path),deployment=build.minimum(path),
                                sections=resume.sections.section_identity(path))
        sdk=self.base/'SDK';sdk.mkdir();(sdk/'SDKSettings.json').write_text('SDK fixture')
        cache=self.base/'cache';cache.mkdir()
        return dict(origin=str(origin),original_prefix=str(original),source=str(source),source_tree=build.tree(source),
                    headers=str(headers),llvm_source=str(llvm_source),cache_path=str(cache),cache={'fixture':True},
                    raw_outputs=raw,external={'developer':str(self.base/'AppleDeveloper'),'sdk':str(sdk),
                    'sdk_settings':{'SDKSettings.json':resume.sha(sdk/'SDKSettings.json')}},scope=resume.SCOPE)

    @staticmethod
    def recorder():
        class Recorder:
            def __init__(self,out,prefix):self.env={};self.commands=[];self.calls=[];(out/'commands').mkdir()
            def __call__(self,argv,label,cwd=None,env=None,expected=0):
                record=Fixture.run(self,argv,label,cwd,env,expected);self.commands.append(record);return record
        return Recorder

    def test_complete_synthetic_finalization_copies_only_raw_code_and_claims_no_compilation(self):
        before=self.synthetic_origin();origin=Path(before['origin']);original=Path(before['original_prefix'])
        original_tree=build.tree(original);failure=(origin/'failure.json').read_bytes()
        prefix=self.base/'finalized';out=self.base/'evidence'
        with mock.patch.object(resume,'review_origin',return_value=before), \
             mock.patch.object(build.common,'Recorder',self.recorder()):
            provider=resume.finalize(origin,prefix,out)
        self.assertEqual(provider['native_compile_commands_this_attempt'],0)
        self.assertEqual(provider['guest_executions'],0);self.assertEqual(provider['gpu_executions'],0)
        self.assertIn('during finalization',provider['limitation'])
        self.assertIn('not retroactively claimed',provider['limitation'])
        self.assertEqual(set(provider['runtime_files']),{'runtime/'+name for name in build.NAMES})
        result=json.loads((out/'result.json').read_bytes());self.assertEqual(len(result['commands']),9)
        self.assertTrue(all(row['argv'][0] in ('/usr/bin/install_name_tool','/usr/bin/codesign') for row in result['commands']))
        self.assertTrue(all('/dxmt-build/' in row['original'] for row in result['copied'].values()))
        self.assertEqual(build.tree(original),original_tree);self.assertEqual((origin/'failure.json').read_bytes(),failure)
        self.assertEqual(build.paths_for(prefix)['d3d11'],prefix/'runtime/d3d11.dylib')

    def test_failed_final_consumer_check_cannot_leave_a_successful_provider_entry(self):
        before=self.synthetic_origin();prefix=self.base/'finalized';out=self.base/'evidence'
        with mock.patch.object(resume,'review_origin',return_value=before), \
             mock.patch.object(build.common,'Recorder',self.recorder()), \
             mock.patch.object(build,'paths_for',side_effect=ValueError('synthetic consumer rejection')):
            with self.assertRaisesRegex(ValueError,'synthetic consumer rejection'):
                resume.finalize(Path(before['origin']),prefix,out)
        self.assertFalse((prefix/'provider.json').exists())
        self.assertTrue((prefix/'failed-provider.json').is_file());self.assertTrue((out/'failure.json').is_file())
        self.assertFalse((out/'result.json').exists())

    def test_origin_change_during_finalization_cannot_publish_provider(self):
        before=self.synthetic_origin();changed=copy.deepcopy(before);changed['scope']='changed provenance'
        prefix=self.base/'finalized';out=self.base/'evidence'
        with mock.patch.object(resume,'review_origin',side_effect=[before,changed]), \
             mock.patch.object(build.common,'Recorder',self.recorder()):
            with self.assertRaisesRegex(ValueError,'original inputs changed'):
                resume.finalize(Path(before['origin']),prefix,out)
        self.assertFalse((prefix/'provider.json').exists());self.assertTrue((out/'failure.json').is_file())


if __name__=='__main__':unittest.main()
