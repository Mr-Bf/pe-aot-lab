"""CLI identity/output boundaries without importing or executing guest bytes."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from real_pe_inventory_v1.inventory import InventoryError
from .__main__ import main


class CliTests(unittest.TestCase):
    def test_existing_output_is_refused_before_native_decoder_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); pe=root/'input.exe';pe.write_bytes(b'MZ')
            output=root/'existing.json';output.write_text('keep')
            with patch('real_pe_cfg_v1.decoder.Decoder') as constructor:
                with self.assertRaises(InventoryError):
                    main(['analyze',str(pe),'--decoder-receipt',str(root/'none.json'),'--json-out',str(output)])
                constructor.assert_not_called()
            self.assertEqual(output.read_text(),'keep')

    def test_input_and_output_alias_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();pe=root/'input.exe';pe.write_bytes(b'MZ')
            with self.assertRaises(InventoryError):
                main(['analyze',str(pe),'--decoder-receipt',str(root/'none.json'),'--json-out',str(pe)])
            self.assertEqual(pe.read_bytes(),b'MZ')

    def test_symlink_output_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();pe=root/'input.exe';pe.write_bytes(b'MZ')
            (root/'link').symlink_to(root,target_is_directory=True)
            with self.assertRaises(InventoryError):
                main(['analyze',str(pe),'--decoder-receipt',str(root/'none.json'),'--json-out',str(root/'link/out.json')])

    def test_colliding_json_and_markdown_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();pe=root/'input.exe';pe.write_bytes(b'MZ');out=root/'out.json'
            with self.assertRaises(InventoryError):
                main(['analyze',str(pe),'--decoder-receipt',str(root/'none.json'),'--json-out',str(out),'--markdown-out',str(out)])


if __name__ == '__main__':
    unittest.main()
