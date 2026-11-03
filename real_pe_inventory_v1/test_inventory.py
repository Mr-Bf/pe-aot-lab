"""Byte-level parser boundary tests. Fixtures are synthetic PE files, never run."""
import copy
import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from . import inventory as inv
from .__main__ import main, output_path

PE_OFFSET=0x80
OPTIONAL=PE_OFFSET+24


def fixture(optional_size=240,directory_count=16,base=0x140000000):
    b=bytearray(0xc00);b[:2]=b'MZ';struct.pack_into('<I',b,0x3c,PE_OFFSET);b[PE_OFFSET:PE_OFFSET+4]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',b,PE_OFFSET+4,0x8664,2,0,0,0,optional_size,0x22)
    struct.pack_into('<H',b,OPTIONAL,0x20b);struct.pack_into('<I',b,OPTIONAL+16,0x1000)
    struct.pack_into('<Q',b,OPTIONAL+24,base);struct.pack_into('<II',b,OPTIONAL+32,0x1000,0x200)
    struct.pack_into('<II',b,OPTIONAL+56,0x4000,0x200);struct.pack_into('<HH',b,OPTIONAL+68,3,0x8160)
    struct.pack_into('<I',b,OPTIONAL+108,directory_count)
    for i,(name,rva,size,raw,flags) in enumerate([(b'.text',0x1000,0x200,0x200,0x60000020),(b'.rdata',0x2000,0x800,0x400,0x40000040)]):
        struct.pack_into('<8sIIIIIIHHI',b,OPTIONAL+optional_size+40*i,name,0x1000,rva,size,raw,0,0,0,0,flags)
    b[0x200]=0xc3
    return b


def directory(b,index,rva,size):struct.pack_into('<II',b,OPTIONAL+112+index*8,rva,size)
def put(b,rva,data):
    offset=0x400+rva-0x2000 if rva>=0x2000 else 0x200+rva-0x1000
    b[offset:offset+len(data)]=data


def add_import(b,dll=b'kernel32.dll',lookup=True,bound=False):
    directory(b,1,0x2000,40)
    put(b,0x2000,struct.pack('<5I',0x2080 if lookup else 0,1 if bound else 0,0,0x2100,0x20a0))
    values=struct.pack('<3Q',0x2120,0x8000000000000007,0)
    put(b,0x2080,values);put(b,0x20a0,values);put(b,0x2100,dll+b'\0');put(b,0x2120,b'\0\0ExitProcess\0')


def add_delay(b,legacy=False):
    directory(b,13,0x2500,64);base=struct.unpack_from('<Q',b,OPTIONAL+24)[0]
    adjust=base if legacy else 0
    put(b,0x2500,struct.pack('<8I',0 if legacy else 1,adjust+0x2590,0,adjust+0x25d0,adjust+0x25b0,0,0,0))
    put(b,0x2590,b'SDL2.dll\0');put(b,0x25b0,struct.pack('<2Q',0x2600,0));put(b,0x25d0,bytes(16))
    put(b,0x2600,b'\0\0SDL_Init\0')


def analyzed(b):return inv.analyze_bytes(bytes(b),'fixture.exe')
def d(result,index):return result['directories'][index]


class InventoryTests(unittest.TestCase):
    def test_minimal_pe_and_absence_is_not_mechanism_proof(self):
        b=fixture();r=analyzed(b)
        self.assertEqual(r['status'],'INVENTORIED');self.assertEqual(r['sha256'],hashlib.sha256(b).hexdigest())
        self.assertEqual(d(r,9)['parse_status'],'not_declared');self.assertEqual(r['migration_admission'],'not_performed')

    def test_variable_optional_size_and_directory_count(self):
        r=analyzed(fixture(224,14));self.assertEqual(r['status'],'INVENTORIED')
        self.assertFalse(d(r,15)['declared'])

    def test_real_truncations_rejected(self):
        b=fixture()
        for length in (0,1,63,127,151,200,OPTIONAL+239,0x1d7,0x3ff,0xbff):
            with self.subTest(length=length):self.assertEqual(analyzed(b[:length])['status'],'REJECTED')

    def test_header_table_sizes_and_integer_boundaries(self):
        for offset,fmt,value in [(0x3c,'I',0xfffffff0),(PE_OFFSET+6,'H',97),(OPTIONAL+108,'I',17),
                                 (OPTIONAL+56,'I',0x2000),(OPTIONAL+60,'I',0x180),
                                 (OPTIONAL+24,'Q',2**64-0x1000)]:
            b=fixture();struct.pack_into('<'+fmt,b,offset,value)
            with self.subTest(offset=offset):self.assertEqual(analyzed(b)['status'],'REJECTED')

    def test_overlapping_virtual_and_raw_sections_rejected(self):
        section=OPTIONAL+240+40
        for offset,value in [(section+12,0x1000),(section+20,0x300),(section+20,0x100)]:
            b=fixture();struct.pack_into('<I',b,offset,value)
            with self.subTest(offset=offset):self.assertEqual(analyzed(b)['status'],'REJECTED')

    def test_named_and_ordinal_imports(self):
        b=fixture();add_import(b);r=analyzed(b);self.assertEqual(d(r,1)['parse_status'],'parsed')
        self.assertEqual(r['imports'][0]['symbols'][0]['name'],'ExitProcess')
        self.assertEqual(r['imports'][0]['symbols'][1]['ordinal'],7)

    def test_missing_import_descriptor_terminator_preserves_incomplete_header(self):
        b=fixture();add_import(b);directory(b,1,0x2000,20);r=analyzed(b)
        self.assertEqual(r['status'],'INCOMPLETE');self.assertEqual(d(r,1)['parse_status'],'invalid');self.assertIn('headers',r)

    def test_import_reserved_ordinal_and_unmapped_iat_rejected(self):
        for mode in ('ordinal','iat','string'):
            b=fixture();add_import(b)
            if mode=='ordinal':put(b,0x2080,struct.pack('<Q',0x8000000000010001))
            elif mode=='iat':put(b,0x2010,struct.pack('<I',0xffffff00))
            else:put(b,0x2100,b'x'*0x700)
            with self.subTest(mode=mode):self.assertEqual(d(analyzed(b),1)['parse_status'],'invalid')

    def test_bound_iat_without_lookup_not_guessed(self):
        b=fixture();add_import(b,lookup=False,bound=True);r=analyzed(b)
        self.assertEqual(r['imports'][0]['status'],'unparsed');self.assertEqual(r['imports'][0]['symbols'],[])
        self.assertEqual(r['status'],'INCOMPLETE')

    def test_delay_import_rva_and_legacy_va(self):
        for legacy in (False,True):
            b=fixture(base=0x400000);add_delay(b,legacy);r=analyzed(b)
            with self.subTest(legacy=legacy):
                self.assertEqual(d(r,13)['parse_status'],'partial' if legacy else 'parsed')
                if not legacy:self.assertEqual(r['imports'][0]['symbols'][0]['name'],'SDL_Init')
                else:self.assertEqual(r['imports'][0]['symbols'],[])

    def test_unknown_delay_flags_are_unparsed(self):
        b=fixture();add_delay(b);put(b,0x2500,struct.pack('<I',3));r=analyzed(b)
        self.assertEqual(d(r,13)['parse_status'],'partial');self.assertEqual(r['status'],'INCOMPLETE')

    def test_relocation_blocks_and_bad_sizes(self):
        b=fixture();directory(b,5,0x2200,12);put(b,0x2200,struct.pack('<IIHH',0x1000,12,0xa000,0))
        self.assertEqual(d(analyzed(b),5)['detail']['type_counts'],{'10':1,'0':1})
        for size in (0,7,9,14,0xffffffff):
            bad=copy.copy(b);put(bad,0x2204,struct.pack('<I',size))
            with self.subTest(size=size):self.assertEqual(d(analyzed(bad),5)['parse_status'],'invalid')

    def test_runtime_function_unwind_is_not_complete_seh(self):
        b=fixture();directory(b,3,0x2240,12);put(b,0x2240,struct.pack('<III',0x1000,0x1001,0x2260));put(b,0x2260,b'\x01\0\0\0')
        r=analyzed(b);self.assertEqual(d(r,3)['parse_status'],'partial');self.assertIn('unwind_operation_semantics_not_decoded',d(r,3)['detail']['unparsed'])
        put(b,0x2260,b'\x21\0\0\0');put(b,0x2264,struct.pack('<III',0x1000,0x1001,0x2260))
        self.assertIn('chained_unwind_semantics',d(analyzed(b),3)['detail']['unparsed'])

    def test_exception_truncation_and_unmapped_code(self):
        for end,size in [(0x1001,11),(0x5000,12),(0x0fff,12)]:
            b=fixture();directory(b,3,0x2240,size);put(b,0x2240,struct.pack('<III',0x1000,end,0x2260))
            with self.subTest(end=end,size=size):self.assertEqual(d(analyzed(b),3)['parse_status'],'invalid')

    def test_empty_runtime_function_is_preserved_not_called_valid_code(self):
        b=fixture();directory(b,3,0x2240,12);put(b,0x2240,struct.pack('<III',0x1000,0x1000,0x2260));put(b,0x2260,b'\x01\0\0\0')
        result=d(analyzed(b),3)
        self.assertEqual(result['parse_status'],'partial')
        self.assertEqual(result['detail']['runtime_functions'][0]['range_status'],'empty_range_unparsed')

    def test_tls_addresses_and_virtual_index(self):
        b=fixture();base=0x140000000;directory(b,9,0x2280,40)
        put(b,0x2280,struct.pack('<4Q2I',base+0x2300,base+0x2304,base+0x2900,base+0x2320,16,0))
        put(b,0x2320,struct.pack('<2Q',base+0x1000,0));r=analyzed(b)
        self.assertEqual(d(r,9)['parse_status'],'parsed');self.assertEqual(d(r,9)['detail']['callbacks'][0]['rva'],0x1000)
        put(b,0x2280,struct.pack('<Q',base-1));self.assertEqual(d(analyzed(b),9)['parse_status'],'invalid')

    def test_virtual_only_directory_explicitly_invalid(self):
        b=fixture();directory(b,9,0x2800,40);r=analyzed(b)
        self.assertEqual(d(r,9)['parse_status'],'invalid');self.assertIn('virtual-only',d(r,9)['error'])

    def test_load_config_prefix_and_unknown_tail(self):
        b=fixture();directory(b,10,0x2400,328);put(b,0x2400,struct.pack('<I',328));put(b,0x2490,struct.pack('<I',0x100))
        r=analyzed(b);self.assertEqual(d(r,10)['detail']['known_prefix_fields']['guard_flags'],0x100)
        self.assertIn('unknown_extended_load_config_tail',d(r,10)['detail']['unparsed'])
        self.assertEqual(r['status'],'INCOMPLETE')

    def test_security_uses_file_offsets_and_never_verifies_trust(self):
        b=fixture();b.extend(struct.pack('<IHH',11,0x200,2)+b'abc'+bytes(5));directory(b,4,0xc00,16)
        r=analyzed(b);self.assertEqual(d(r,4)['parse_status'],'parsed');self.assertEqual(d(r,4)['address_kind'],'file_offset')
        self.assertEqual(d(r,4)['detail']['signature_validation'],'not_performed')
        directory(b,4,0x400,16);self.assertEqual(d(analyzed(b),4)['parse_status'],'invalid')

    def test_debug_raw_pointer_and_codeview(self):
        b=fixture();blob=b'RSDS'+bytes(16)+struct.pack('<I',1)+b'x.pdb\0';directory(b,6,0x2340,28)
        put(b,0x2340,struct.pack('<IIHHIIII',0,0,0,0,2,len(blob),0x2380,0x780));put(b,0x2380,blob)
        self.assertEqual(d(analyzed(b),6)['detail']['records'][0]['codeview']['pdb_path'],'x.pdb')
        put(b,0x2358,struct.pack('<I',0xfffffff0));self.assertEqual(d(analyzed(b),6)['parse_status'],'invalid')

    def test_delay_auxiliary_pointers_outside_image_are_invalid(self):
        for offset in (8,20,24):
            b=fixture();add_delay(b);put(b,0x2500+offset,struct.pack('<I',0xfffffff0))
            with self.subTest(offset=offset):self.assertEqual(d(analyzed(b),13)['parse_status'],'invalid')

    def test_bound_and_unload_delay_tables_remain_unparsed(self):
        b=fixture();add_delay(b);put(b,0x2514,struct.pack('<II',0x2640,0x2680))
        value=d(analyzed(b),13)
        self.assertEqual(value['parse_status'],'partial')
        self.assertEqual(value['detail']['descriptors'][0]['unparsed_tables'],['bound_iat','unload_iat'])

    def test_relocation_budget_checked_before_bulk_allocation(self):
        b=fixture();directory(b,5,0x2200,408);put(b,0x2200,struct.pack('<II',0x1000,408)+bytes(400))
        sizes=[];original=inv.PE.read
        def observed(pe,rva,size):sizes.append(size);return original(pe,rva,size)
        with patch.object(inv,'MAX_ENTRIES',8),patch.object(inv.PE,'read',observed):result=analyzed(b)
        self.assertEqual(d(result,5)['parse_status'],'invalid');self.assertLessEqual(max(sizes),8)

    def test_repeated_name_strings_charge_cumulative_budget(self):
        b=fixture();add_import(b);put(b,0x2000,struct.pack('<5I',0x2200,0,0,0x2100,0x2900))
        put(b,0x2200,struct.pack('<65Q',*([0x2120]*64+[0])))
        with patch.object(inv,'MAX_STRING_BYTES',50):result=analyzed(b)
        self.assertEqual(d(result,1)['parse_status'],'invalid')
        self.assertIn('string byte bound',d(result,1)['error'])
        self.assertLessEqual(result['inspection_usage']['string_bytes'],50)

    def test_debug_payload_budget_precedes_payload_copy(self):
        b=fixture();directory(b,6,0x2340,28);put(b,0x2340,struct.pack('<IIHHIIII',0,0,0,0,2,30,0x2380,0x780))
        with patch.object(inv,'MAX_PAYLOAD_BYTES',10):result=analyzed(b)
        self.assertEqual(d(result,6)['parse_status'],'invalid');self.assertIn('payload byte bound',d(result,6)['error'])

    def test_directory_inventory_has_aggregate_metadata_budget(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();b=fixture();add_import(b)
            for name in ('a.exe','b.dll'):(root/name).write_bytes(b)
            with patch.object(inv,'MAX_TOTAL_STRING_BYTES',30):result=inv.inventory_path(root)
            self.assertEqual(result['status'],'INCOMPLETE')
            self.assertLessEqual(sum(f.get('inspection_usage',{}).get('string_bytes',0) for f in result['files']),30)

    def test_total_metadata_budget_bounded(self):
        b=fixture();add_import(b)
        with patch.object(inv,'MAX_ENTRIES',1):self.assertEqual(d(analyzed(b),1)['parse_status'],'invalid')

    def test_directory_graph_is_only_basename_candidates(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();(root/'lib').mkdir();b=fixture();add_import(b,b'SDL2.dll')
            (root/'main.exe').write_bytes(b);(root/'lib/SDL2.dll').write_bytes(fixture());(root/'SDL2.DLL').write_bytes(fixture())
            report=inv.inventory_path(root);edge=report['dependency_edges'][0]
            self.assertEqual(edge['match_status'],'ambiguous_basename_candidates');self.assertFalse(edge['missing_dependency_claim'])
            self.assertEqual(edge['loader_resolution'],'not_performed')

    def test_os_dll_not_in_bundle_is_not_missing_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();b=fixture();add_import(b);(root/'main.exe').write_bytes(b)
            edge=inv.inventory_path(root)['dependency_edges'][0]
            self.assertEqual(edge['name_classification_hint'],'windows_os_dll_name');self.assertEqual(edge['match_status'],'not_in_inventory')
            self.assertFalse(edge['missing_dependency_claim'])

    def test_symlink_and_nonregular_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();(root/'a.exe').write_bytes(fixture());(root/'b.exe').symlink_to(root/'a.exe')
            with self.assertRaises(inv.InventoryError):inv.read_input(root/'b.exe')
            with self.assertRaises(inv.InventoryError):inv.read_input(root)

    def test_cli_stable_output_and_input_tree_protection(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();src=root/'src';src.mkdir();(src/'a.exe').write_bytes(fixture())
            with patch('sys.stdout',new_callable=io.StringIO):self.assertEqual(main([str(src),'--json-out',str(root/'one.json')]),0)
            with patch('sys.stdout',new_callable=io.StringIO):self.assertEqual(main([str(src),'--json-out',str(root/'two.json')]),0)
            self.assertEqual((root/'one.json').read_bytes(),(root/'two.json').read_bytes())
            with self.assertRaises(inv.InventoryError):output_path(src/'report.json',src)
            with self.assertRaises(inv.InventoryError):output_path(root/'one.json',src)


if __name__=='__main__':unittest.main()
