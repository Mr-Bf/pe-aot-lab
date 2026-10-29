"""Version and provider boundary tests; no native compiler or guest execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from portable_lifter_v1 import build as legacy_provider
from window_profile_v1 import profile as legacy_profile
from window_switch_v1 import profile, provider, lift
from window_switch_v1.test_admission import program, MAIN, CALLBACK, LEAF


def configuration(pe):
    image = profile.legacy.load_image(bytes(pe))
    return dict(schema=2,runtime_contract=profile.CONTRACT,
                pe_sha256=hashlib.sha256(pe).hexdigest(),callback_rvas=[CALLBACK],
                imports=sorted([dict(dll=i['dll'],name=i['name']) for i in image.imports],
                               key=lambda i:(i['dll'],i['name'])),
                observations={},save_observation='profile-test.bin',
                resources='embedded-pe-only',switch_leaf_rva=LEAF)


class ProfileBoundaries(unittest.TestCase):
    def test_new_profile_is_validated_and_copied_without_granting_targets(self):
        for with_import in (False,True):
            pe,_ = program(with_import=with_import)
            value = configuration(pe)
            normalized,image,_ = profile.validate(bytes(pe),value)
            self.assertEqual(normalized,value)
            self.assertIsNot(normalized,value)
            self.assertEqual(image.source_sha256,value['pe_sha256'])
            normalized['callback_rvas'].clear()
            self.assertEqual(value['callback_rvas'],[CALLBACK])
            self.assertEqual(profile.analyze(bytes(pe),value)['status'],'ELIGIBLE_FOR_BUILD_NOT_DECODED')

    def test_legacy_profile_rejects_new_schema_contract_and_fields(self):
        pe,_ = program()
        value = configuration(pe)
        variants = [copy.deepcopy(value)]
        fields_only = {k:v for k,v in value.items() if k in legacy_profile.FIELDS}
        variants.append(fields_only)
        variants.append(dict(fields_only,runtime_contract=legacy_profile.CONTRACT))
        variants.append(dict(fields_only,schema=1))
        for candidate in variants:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                legacy_profile.validate(bytes(pe),candidate)

    def test_new_profile_rejects_old_version_and_configuration_authority(self):
        pe,_ = program()
        value = configuration(pe)
        for key,wrong in [('schema',1),('schema',True),('runtime_contract',legacy_profile.CONTRACT),
                          ('resources','arbitrary-assets'),('switch_leaf_rva',True),
                          ('switch_leaf_rva',MAIN),('switch_leaf_rva',CALLBACK),
                          ('switch_leaf_rva',0),('switch_leaf_rva',0x2000)]:
            candidate=copy.deepcopy(value);candidate[key]=wrong
            with self.subTest(key=key,wrong=wrong),self.assertRaises(ValueError):
                profile.validate(bytes(pe),candidate)
        for key,payload in [('targets',[0x1019]),('table_rva',0x2000),('switches',[]),
                            ('switch_targets',[0x1019]),('allow_indirect',True)]:
            candidate=copy.deepcopy(value);candidate[key]=payload
            with self.subTest(extra_field=key),self.assertRaises(ValueError):
                profile.validate(bytes(pe),candidate)

    def test_profile_still_binds_pe_imports_and_observation_limits(self):
        pe,_ = program(with_import=True)
        value = configuration(pe)
        for key,wrong in [('pe_sha256','0'*64),('imports',[]),('observations',{'huge':{'rva':0x2000,'size':65537}}),
                          ('callback_rvas',[CALLBACK,CALLBACK]),('save_observation','../outside')]:
            candidate=copy.deepcopy(value);candidate[key]=wrong
            with self.subTest(key=key),self.assertRaises(ValueError):
                profile.validate(bytes(pe),candidate)

    def test_legacy_provider_is_rejected_before_dependency_or_compiler_work(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix=Path(directory).resolve()
            (prefix/'provider.json').write_text(json.dumps(dict(schema=1,status='CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED')))
            with mock.patch.object(provider.base,'paths_for',side_effect=AssertionError('must reject before base provider traversal')):
                with self.assertRaisesRegex(ValueError,'legacy provider rejected'):
                    provider.paths_for(prefix)
                with self.assertRaisesRegex(ValueError,'legacy provider rejected'):
                    lift.cpu_identity(prefix)

    def test_new_overlay_does_not_qualify_as_legacy_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix=Path(directory).resolve()
            record=dict(schema=1,status=provider.STATUS,capabilities=[provider.CAPABILITY],prefix=str(prefix))
            (prefix/'provider.json').write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError,'provider not successful'):
                legacy_provider.paths_for(prefix)

    def test_capability_is_exact_and_cannot_be_added_to_legacy_status(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix=Path(directory).resolve()
            base=dict(schema=1,status=provider.STATUS,capabilities=[provider.CAPABILITY],prefix=str(prefix))
            for key,value in [('schema',2),('status','CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED'),
                              ('capabilities',[]),('capabilities',['clang-rel32-v1']),
                              ('capabilities',[provider.CAPABILITY,'arbitrary-indirect']),
                              ('capabilities',provider.CAPABILITY),('prefix',str(prefix/'elsewhere'))]:
                record=dict(base);record[key]=value
                (prefix/'provider.json').write_text(json.dumps(record))
                with self.subTest(key=key,value=value),mock.patch.object(provider.base,'paths_for',side_effect=AssertionError('base traversal must not run')):
                    with self.assertRaisesRegex(ValueError,'explicit window-rel32-v1 capability'):
                        provider.paths_for(prefix)

    def test_symlinked_provider_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();prefix=root/'overlay';prefix.mkdir()
            (root/'descriptor.json').write_text('{}')
            (prefix/'provider.json').symlink_to(root/'descriptor.json')
            with self.assertRaisesRegex(ValueError,'manifest required'):
                provider.paths_for(prefix)


if __name__=='__main__':
    unittest.main()
