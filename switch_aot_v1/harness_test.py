"""Portable argument wiring only: no native build, decoder, library or guest."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from switch_aot_v1 import harness


class PortableInputTests(unittest.TestCase):
    def test_default_paths_preserved(self):
        paths=dict(harness.fixture_inputs())
        self.assertEqual(paths['supported'],harness.REPO/'build/switch-supported-fixture-v1/pe-02/switch8.exe')
        self.assertEqual(paths['variant'],harness.REPO/'build/switch-variant-fixture-v1/pe-01/switch8_variant.exe')

    def test_explicit_paths(self):
        with tempfile.TemporaryDirectory(prefix='switch arguments ') as temporary:
            paths=dict(harness.fixture_inputs(Path(temporary)/'first.exe',Path(temporary)/'second.exe'))
            self.assertEqual(paths['supported'],Path(temporary).resolve()/'first.exe')
            self.assertEqual(paths['variant'],Path(temporary).resolve()/'second.exe')
            self.assertFalse(paths['supported'].exists())

    def test_cli_explicit_inputs(self):
        with patch.object(harness,'main',return_value='wired') as target:
            result=harness.cli(['--build','driver.json','--packets','examples/switch','--out','new out',
                                '--supported-pe','examples/switch/switch8.exe','--variant-pe','examples/switch/switch8_variant.exe'])
            self.assertEqual(result,'wired')
            target.assert_called_once_with(build='driver.json',packets='examples/switch',out='new out',
                supported_pe='examples/switch/switch8.exe',variant_pe='examples/switch/switch8_variant.exe')

    def test_cli_defaults(self):
        with patch.object(harness,'main') as target:
            harness.cli(['--build','driver.json','--packets','packets','--out','fresh'])
            target.assert_called_once_with(build='driver.json',packets='packets',out='fresh',supported_pe=None,variant_pe=None)

    def test_source_and_license_closure(self):
        expected=['LICENSE','integration_stage3/LICENSE.remill','switch_supported_fixture_v1/switch8.c',
                  'switch_variant_fixture_v1/switch8_variant.c']
        for relative in expected:
            self.assertIn(harness.REPO/relative,harness.SOURCES)
            self.assertTrue((harness.REPO/relative).is_file())


if __name__=='__main__':
    unittest.main()
