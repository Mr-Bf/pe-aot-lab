"""Configured entry and file-ledger tests. Compiler/signing callbacks are synthetic."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from portable_app_v1 import lift, package, producer
from . import build as entry
from .test_package import Fixture


class MigrationBoundaries(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='migration-v5-boundary-test-');self.addCleanup(temp.cleanup)
        self.base=Path(temp.name).resolve();self.cpu=self.base/'cpu';self.cpu.mkdir()
        self.graphics=self.base/'graphics';self.graphics.mkdir();self.sdk=self.base/'SDK';self.sdk.mkdir()
        (self.cpu/'provider.json').write_text('CPU fixture')
        self.backend_manifest=self.graphics/'provider.json'
        self.backend_manifest.write_text(json.dumps({'external_prerequisites':{'developer':str(self.base/'AppleDeveloper')}}))
        frozen=lift.ROOT/'build/migration-v4/integration-01/product'
        self.pe=frozen/'input.exe';self.profile=json.loads((frozen/'profile.json').read_bytes())
        self.out=self.base/'product';self.fixture=None
        self.backend={'provider_manifest':self.backend_manifest,'provider_sha256':lift.sha(self.backend_manifest),'sdk':self.sdk}

    def mock_build(self):
        owner=self
        class Recorder:
            def __init__(self,out,prefix):
                self.env={};self.commands=[];(out/'commands').mkdir()
            def __call__(self,argv,label,cwd=None,env=None,expected=0):
                result=owner.fixture.run(argv,label,cwd,env,expected);self.commands.append(result);return result
        def native(cpu,backend,pe,profile,identifier,out,run):
            owner.fixture=Fixture(owner.base,out)
            owner.fixture.native.update(identifier=identifier,input_sha256=lift.sha(pe),profile=profile)
            owner.fixture.save();return owner.fixture.native
        with mock.patch.object(entry.common,'Recorder',Recorder), \
             mock.patch.object(entry.graphics,'paths_for',return_value=self.backend), \
             mock.patch.object(entry.producer,'build',side_effect=native), \
             mock.patch.object(package,'resource_inputs',side_effect=lambda value:self.fixture.resources), \
             mock.patch.object(package.formats,'source_program',side_effect=AssertionError('old guard invoked')):
            result=entry.build(self.pe,self.profile,'org.peaotlab.Test',self.cpu,self.graphics,self.out)
        if result['status']!=entry.STATUS:
            raise AssertionError('synthetic positive pipeline failed: '+str(result.get('error')))
        return result

    def test_full_mock_pipeline_can_verify_without_original_providers(self):
        result=self.mock_build()
        self.assertEqual(result['input_sha256'],lift.sha(self.pe));self.assertEqual(result['minimum_macos'],'15.2')
        self.assertEqual(result['stage'],'complete');self.assertFalse(result['requires_arguments'])
        self.cpu.rename(self.base/'cpu-withheld');self.graphics.rename(self.base/'graphics-withheld')
        verified=entry.verify(self.out)
        self.assertEqual(verified['status'],'PORTABLE_APP_FILES_VERIFIED_NOT_EXECUTED')
        self.assertEqual(verified['guest_executions'],0);self.assertEqual(verified['gpu_executions'],0)

    def test_existing_and_provider_nested_outputs_are_refused_without_modification(self):
        existing=self.base/'existing';existing.mkdir();(existing/'keep').write_text('keep')
        for out in (existing,self.cpu/'new-output',self.graphics/'new-output'):
            with self.subTest(out=out),self.assertRaises(ValueError):
                entry.build(self.pe,self.profile,'org.peaotlab.Test',self.cpu,self.graphics,out)
        self.assertEqual((existing/'keep').read_text(),'keep')
        self.assertFalse((self.cpu/'new-output').exists());self.assertFalse((self.graphics/'new-output').exists())

    def test_output_alias_and_old_work_path_are_refused(self):
        alias=self.base/'alias';alias.symlink_to(self.cpu,target_is_directory=True)
        for out in (alias/'new',lift.OLD_WORK/'never-create-this-test'):
            with self.subTest(out=out),self.assertRaises(ValueError):
                entry.build(self.pe,self.profile,'org.peaotlab.Test',self.cpu,self.graphics,out)
        self.assertFalse((self.cpu/'new').exists())

    def test_unsupported_profile_stops_before_provider_or_compiler(self):
        profile=copy.deepcopy(self.profile);profile['pe_sha256']='0'*64
        with mock.patch.object(entry.graphics,'paths_for',side_effect=AssertionError('provider must not run')), \
             mock.patch.object(entry.producer,'build',side_effect=AssertionError('compiler must not run')):
            result=entry.build(self.pe,profile,'org.peaotlab.Test',self.cpu,self.graphics,self.out)
        self.assertEqual(result['status'],'UNSUPPORTED');self.assertEqual(result['stage'],'analysis')
        self.assertFalse((self.out/'native').exists());self.assertEqual(entry.ledger(self.out),result['files'])
        with self.assertRaises(ValueError):entry.verify(self.out)

    def test_provider_failure_preserves_failed_attempt_and_cannot_verify(self):
        with mock.patch.object(entry.graphics,'paths_for',side_effect=ValueError('synthetic provider rejection')):
            result=entry.build(self.pe,self.profile,'org.peaotlab.Test',self.cpu,self.graphics,self.out)
        self.assertEqual(result['status'],'BUILD_FAILED');self.assertEqual(result['stage'],'provider-validation')
        self.assertIn('failure.txt',result['files']);self.assertFalse((self.out/'native').exists())
        with self.assertRaises(ValueError):entry.verify(self.out)

    def test_modified_bytes_modes_and_file_set_are_rejected(self):
        self.mock_build();path=self.out/'profile.json';original=path.read_bytes();mode=path.stat().st_mode&0o777
        path.write_bytes(original+b' ')
        with self.assertRaises(ValueError):entry.verify(self.out)
        path.write_bytes(original);path.chmod(mode^0o100)
        with self.assertRaises(ValueError):entry.verify(self.out)
        path.chmod(mode);extra=self.out/'unexpected';extra.write_bytes(b'added')
        with self.assertRaises(ValueError):entry.verify(self.out)
        extra.unlink();self.assertEqual(entry.verify(self.out)['status'],'PORTABLE_APP_FILES_VERIFIED_NOT_EXECUTED')

    def test_symlink_cannot_replace_an_identically_hashed_file(self):
        self.mock_build();path=self.out/'profile.json';saved=self.base/'same-profile.json';saved.write_bytes(path.read_bytes())
        path.unlink();path.symlink_to(saved)
        with self.assertRaises(ValueError):entry.verify(self.out)

    def test_receipt_change_during_verification_is_rejected(self):
        self.mock_build();actual=entry.ledger;changed=False
        def concurrent(root):
            nonlocal changed
            result=actual(root)
            if not changed:
                changed=True;path=self.out/'result.json';record=json.loads(path.read_bytes());record['status']='BUILD_FAILED'
                path.write_text(json.dumps(record))
            return result
        with mock.patch.object(entry,'ledger',side_effect=concurrent):
            with self.assertRaises(ValueError):entry.verify(self.out)

    def test_declared_executable_digest_must_match_actual_export(self):
        self.mock_build();path=self.out/'result.json';record=json.loads(path.read_bytes());record['executable_sha256']='0'*64
        path.write_text(json.dumps(record))
        with self.assertRaises(ValueError):entry.verify(self.out)


if __name__=='__main__':unittest.main()
