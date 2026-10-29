"""Original PE/proof/normalized rows/header binding regressions.

Synthetic entry/callback wrappers surround the frozen real Clang scalar leaf.
No compiler, native, App or GPU execution occurs in these tests.
"""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest

from window_inc_v1.loader import load_image
from window_switch_v1 import admission, headers, lift
from window_switch_v1.test_admission import program, ROOTS, LEAF, MAIN, CALLBACK


def specimen(name="supported",with_import=False):
    pe,packets=program(name,with_import=with_import)
    pe=bytes(pe);image=load_image(pe)
    # Synthetic CALL/RET wrapper metadata is explicit. Real leaf packet fields
    # remain unchanged; a second independent proof is built after defaults.
    for packet in packets:
        for row in packet["instructions"]:
            for field,value in dict(immediate_width=0,immediate=0,iat_slot_pc=0,
                                    rmw_base_reg="",rmw_displacement=0,rmw_width=0,
                                    flags_read=0,flags_written=0,flags_undefined=0).items():
                row.setdefault(field,value)
    imports={item["iat_rva"]:item for item in image.imports}
    roots=[];merged={}
    for packet in packets:
        rva=packet["entry_address"]-image.base
        proof=admission.prove_window_switch(pe,packet,rva,LEAF,ROOTS)
        instructions=lift.normalize(packet["instructions"],image,packet["text_address"]-image.base,
                                    bytes.fromhex(proof["text_bytes"]),imports,rva,
                                    packet["switch_candidates"])
        symbol="aot_entry" if rva==image.entry_rva else f"aot_window_proc_{rva:x}"
        manifest=dict(root_rva=rva,symbol=symbol,function_symbol=symbol,
                      instructions=instructions,switch_proof=proof,
                      virtual_calls=[],register_calls=[])
        roots.append(dict(rva=rva,symbol=symbol,manifest=manifest))
        for row in instructions:merged[row["rva"]]=copy.deepcopy(row)
    program_value=SimpleNamespace(image=image,source_bytes=pe,source_sha256=image.source_sha256,
                                 roots=roots,root_manifest={"instructions":[merged[r] for r in sorted(merged)]},
                                 out=Path("/unused-header-tests"))
    metadata=dict(callback_rvas=[CALLBACK],switch_leaf_rva=LEAF,
                  observations={},save_observation="header-test.bin")
    return program_value,metadata


class HeaderBindingTests(unittest.TestCase):
    def reject(self,p,metadata,reason="."):
        with self.assertRaisesRegex(ValueError,reason):
            headers.generate_headers(p,metadata,write=False)

    def test_valid_two_leaf_shapes_and_real_import_metadata(self):
        for name in ("supported","variant"):
            for with_import in (False,True):
                with self.subTest(name=name,with_import=with_import):
                    p,metadata=specimen(name,with_import)
                    original=copy.deepcopy((p.image,p.roots,p.root_manifest,metadata))
                    calls,rows,observations=headers.generate_headers(p,metadata,write=False)
                    self.assertEqual(len(calls),int(with_import))
                    self.assertEqual(sum(row[2]==5 for row in rows),1)
                    self.assertEqual(observations,[])
                    text=p.generated_headers["native_image.h"]
                    self.assertIn("aot_bind_image_switch",text)
                    self.assertIn("aot_configure_switch",text)
                    self.assertIn("aot_bind_switch",text)
                    self.assertIn('kPeSha256[]="'+p.image.source_sha256+'"',text)
                    self.assertEqual((p.image,p.roots,p.root_manifest,metadata),original)

    def test_direct_call_kind_cannot_be_changed_with_same_bytes_and_proof(self):
        p,metadata=specimen()
        call=next(row for row in p.roots[0]["manifest"]["instructions"] if row["rva"]==MAIN)
        self.assertEqual(call["bytes"],"e8fbfeffff")
        call["kind"]=0
        # Mirror the mutation in the separately held merged table: checking only
        # these two intermediate tables against one another cannot reject it.
        next(row for row in p.root_manifest["instructions"] if row["rva"]==MAIN)["kind"]=0
        self.reject(p,metadata,"proven decoder packet")

    def test_normalized_target_flags_and_added_instruction_fields_are_bound(self):
        for key,value in (("target_rva",LEAF+1),("flags_written",0x8d5),("unproven_field",123)):
            p,metadata=specimen()
            row=next(row for row in p.roots[0]["manifest"]["instructions"] if row["rva"]==MAIN)
            row[key]=value
            next(row for row in p.root_manifest["instructions"] if row["rva"]==MAIN)[key]=value
            with self.subTest(key=key):self.reject(p,metadata,"proven decoder packet")

    def test_root_order_and_rva_are_bound_to_entry_and_callbacks(self):
        p,metadata=specimen();p.roots.reverse()
        self.reject(p,metadata,"entry/callback order")
        p,metadata=specimen();p.roots[0]["rva"]=MAIN+1
        self.reject(p,metadata,"entry/callback order")

    def test_root_symbol_manifest_rva_and_function_symbol_cannot_be_replaced(self):
        for field,value in (("root_rva",MAIN+1),("symbol","aot_alternate"),
                            ("function_symbol","aot_alternate")):
            p,metadata=specimen();p.roots[0]["manifest"][field]=value
            with self.subTest(field=field):self.reject(p,metadata,"root/function binding")
        p,metadata=specimen();p.roots[1]["symbol"]="aot_entry"
        self.reject(p,metadata,"root/function binding")

    def test_complete_proofs_cannot_be_swapped_between_root_manifests(self):
        p,metadata=specimen()
        first=p.roots[0]["manifest"];second=p.roots[1]["manifest"]
        first["switch_proof"],second["switch_proof"]=second["switch_proof"],first["switch_proof"]
        self.reject(p,metadata)

    def test_proof_target_and_identity_overrides_are_rejected(self):
        p,metadata=specimen()
        p.roots[0]["manifest"]["switch_proof"]["switch"]["targets"][0]+=1
        self.reject(p,metadata,"input recomputation")
        p,metadata=specimen()
        p.roots[0]["manifest"]["switch_proof"]["pe_sha256"]="0"*64
        self.reject(p,metadata,"input recomputation")

    def test_loaded_image_bytes_permissions_imports_and_entry_are_original(self):
        for change in ("data","permissions","imports","entry_rva"):
            p,metadata=specimen()
            if change=="data":p.image.data[0x2000]^=1
            elif change=="permissions":p.image.permissions[1]=1
            elif change=="imports":p.image.imports.append({"dll":"forged.dll","name":"Forged"})
            else:p.image.entry_rva+=1
            with self.subTest(change=change):self.reject(p,metadata,"image differs")

    def test_preferred_base_and_pe_identity_used_by_header_are_original(self):
        p,metadata=specimen();p.image.preferred_base+=0x10000
        self.reject(p,metadata)
        p,metadata=specimen();p.source_sha256="0"*64
        self.reject(p,metadata)

    def test_merged_table_cannot_disagree_with_each_bound_root(self):
        p,metadata=specimen()
        row=p.root_manifest["instructions"][0];row["kind"]=(row["kind"]+1)%6
        self.reject(p,metadata,"merged side table")
        p,metadata=specimen();p.root_manifest["instructions"].pop()
        self.reject(p,metadata,"merged side table")

    def test_virtual_and_register_call_metadata_cannot_be_fabricated(self):
        for field in ("virtual_calls","register_calls"):
            p,metadata=specimen();p.roots[0]["manifest"][field]=[{"call_rva":MAIN}]
            with self.subTest(field=field):self.reject(p,metadata,"callsite table")


if __name__=="__main__":unittest.main()
