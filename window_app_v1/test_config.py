"""App namespace/configuration admission; no target execution."""
import plistlib
import unittest

from window_app_v1.noarg import spec,header
from window_app_v1.package import plist


class AppConfiguration(unittest.TestCase):
    def test_identifiers_cannot_escape_data_directory_or_c_literal(self):
        for identifier in ('../outside','/tmp/x','org..sample','org.sample/x','org.sample."x',
                           'org.sample.x\n','org.sample.😀','x'*121,True,None):
            with self.subTest(identifier=identifier):
                with self.assertRaises(ValueError):spec(dict(identifier=identifier,name='Test'))

    def test_unknown_or_missing_fields_are_rejected(self):
        for value in ({},dict(identifier='org.sample.test'),dict(identifier='org.sample.test',name='Test',data_dir='/tmp')):
            with self.assertRaises(ValueError):spec(value)

    def test_display_name_is_separate_from_data_namespace(self):
        value=dict(identifier='org.peaotlab.example',name='测试 App')
        self.assertEqual(plistlib.loads(plistlib.dumps(plist(value)))['CFBundleDisplayName'],'测试 App')
        self.assertIn('@"org.peaotlab.example"',header(value))
        self.assertNotIn('测试',header(value))

    def test_bad_display_name_is_rejected(self):
        for name in ('',' x','x ','x\n','x\x00','x\x7f','x'*81,None):
            with self.assertRaises(ValueError):spec(dict(identifier='org.sample.test',name=name))

    def test_two_app_namespaces_produce_distinct_configuration(self):
        first=dict(identifier='org.sample.first',name='First')
        second=dict(identifier='org.sample.second',name='Second')
        self.assertNotEqual(header(first),header(second))
        self.assertNotEqual(plist(first)['CFBundleIdentifier'],plist(second)['CFBundleIdentifier'])


if __name__=='__main__':unittest.main()
