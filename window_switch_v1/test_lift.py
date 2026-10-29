"""Pure helper ABI and finite-CFG defined-flags counterexamples; no tools."""
import copy
import unittest

from portable_app_v1 import test_lift as legacy_tests
from window_switch_v1 import lift


def retarget(instruction, declaration, attributes=''):
    ir = legacy_tests.ProductionLiftTests.helper_ir(instruction,declaration,attributes)
    return lift.retarget(ir,0x1000,0x1000,'aot_entry',
                         'target datalayout = "e"','target triple = "arm64-apple-macos11"')


def instruction(pc,cls='NOP',kind=0,next_pc=None,target=0,read=0,write=0,undefined=0,**extra):
    return dict(address=pc,rva=pc-0x1000,iclass=cls,kind=kind,
                next_pc=pc+1 if next_pc is None else next_pc,target_pc=target,
                flags_read=read,flags_written=write,flags_undefined=undefined,**extra)


def finite_cfg():
    return [instruction(0x1000,'CMP',write=0x40),
            instruction(0x1001,'JMP',5),
            instruction(0x1002,'JNZ',target=0x1004,read=0x40),
            instruction(0x1003,'RET_NEAR',2),instruction(0x1004,'RET_NEAR',2)]


class LiftBoundaries(unittest.TestCase):
    CALL = '%x = call ptr @aot_switch_miss(ptr %state, i64 %pc, ptr %memory)'
    DECL = 'declare ptr @aot_switch_miss(ptr, i64, ptr)'

    def test_exact_switch_miss_abi_accepts_c_and_explicit_ccc(self):
        for call,decl in [(self.CALL,self.DECL),
                          (self.CALL.replace('call ptr','call ccc ptr'),self.DECL.replace('declare ptr','declare ccc ptr'))]:
            with self.subTest(call=call):
                arm,private=retarget(call,decl)
                self.assertIn('@aot_entry(',arm)
                self.assertIn('@aot_switch_miss(ptr, i64, ptr)',arm)
                self.assertNotIn('@sub_1000(',arm)
                self.assertEqual(private,[])

    def test_switch_miss_call_and_declaration_cannot_change_abi(self):
        cases=[
            (self.CALL.replace('call ptr','call i64'),self.DECL.replace('declare ptr','declare i64')),
            (self.CALL.replace('i64 %pc','i32 42'),self.DECL.replace('i64','i32')),
            (self.CALL,self.DECL.replace('i64','i32')),
            (self.CALL.replace('i64 %pc','i32 42'),self.DECL),
            (self.CALL.replace(', ptr %memory',''),'declare ptr @aot_switch_miss(ptr, i64)'),
            (self.CALL.replace('i64 %pc, ptr %memory','ptr %memory, i64 %pc'),self.DECL.replace('i64, ptr','ptr, i64')),
            (self.CALL.replace('call ptr','call fastcc ptr'),self.DECL),
            (self.CALL,self.DECL.replace('declare ptr','declare win64cc ptr')),
            (self.CALL.replace('call ptr','call zeroext ptr'),self.DECL),
            (self.CALL,self.DECL.replace('ptr, i64, ptr','ptr, i64, ptr, ...')),
        ]
        for call,decl in cases:
            with self.subTest(call=call,decl=decl),self.assertRaises(ValueError):
                retarget(call,decl)

    def test_unknown_undeclared_or_duplicate_switch_helper_is_rejected(self):
        for call,decl in [(self.CALL,''),(self.CALL,self.DECL+'\n'+self.DECL),
                          (self.CALL.replace('aot_switch_miss','aot_any_target'),self.DECL.replace('aot_switch_miss','aot_any_target'))]:
            with self.subTest(decl=decl),self.assertRaises(ValueError):
                retarget(call,decl)

    def test_switch_miss_cannot_claim_readonly_or_speculatable_effects(self):
        call,decl=self.CALL+' #0',self.DECL+' #0'
        retarget(call,decl,'attributes #0 = { nounwind memory(readwrite) }')
        for attrs in ('readonly','readnone','speculatable','memory(none)','memory(read)'):
            with self.subTest(attributes=attrs),self.assertRaisesRegex(ValueError,'false helper effect'):
                retarget(call,decl,'attributes #0 = { '+attrs+' }')

    def test_kind5_propagates_flags_to_every_real_finite_target(self):
        rows=finite_cfg()
        candidates=[dict(jump_pc=0x1001,targets=[0x1002,0x1003])]
        lift.validate_window_flags(rows,0x1000,candidates)
        # Duplicate table entries are meaningful and must not remove the edge
        # through the conditional case that consumes ZF.
        candidates[0]['targets']=[0x1002,0x1002,0x1003]
        lift.validate_window_flags(rows,0x1000,candidates)
        changed=copy.deepcopy(rows);changed[0]['flags_written']=0
        with self.assertRaisesRegex(ValueError,'undefined flags read'):
            lift.validate_window_flags(changed,0x1000,candidates)

    def test_finite_jump_requires_proven_boundary_and_intersects_case_flags(self):
        rows=finite_cfg()
        for candidates in ([],[dict(jump_pc=0x1001,targets=[0x1002,0x9999])],
                           [dict(jump_pc=0x1001,targets=[0x1002]),dict(jump_pc=0x1001,targets=[0x1003])]):
            with self.subTest(candidates=candidates),self.assertRaises(ValueError):
                lift.validate_window_flags(rows,0x1000,candidates)
        # Both the direct finite edge and a case that undefines ZF reach the
        # condition. One good predecessor must not authorize the bad path.
        rows=[instruction(0x1000,'CMP',write=0x40),instruction(0x1001,'JMP',5),
              instruction(0x1002,undefined=0x40),
              instruction(0x1003,'JNZ',target=0x1005,read=0x40),
              instruction(0x1004,'RET_NEAR',2),instruction(0x1005,'RET_NEAR',2)]
        with self.assertRaisesRegex(ValueError,'undefined flags read'):
            lift.validate_window_flags(rows,0x1000,[dict(jump_pc=0x1001,targets=[0x1002,0x1003])])

    def test_direct_iat_com_and_register_calls_do_not_preserve_flags(self):
        for kind,iat in [(1,False),(1,True),(3,False),(4,False)]:
            rows=[instruction(0x1000,'CMP',write=0x40),
                  instruction(0x1001,'CALL_NEAR',kind,target=0x1006 if kind==1 and not iat else 0),
                  instruction(0x1002,'JNZ',target=0x1004,read=0x40),
                  instruction(0x1003,'RET_NEAR',2),instruction(0x1004,'RET_NEAR',2)]
            if iat:rows[1]['iat_slot_rva']=0x2000
            if kind==1 and not iat:rows.append(instruction(0x1006,'RET_NEAR',2))
            with self.subTest(kind=kind,iat=iat),self.assertRaisesRegex(ValueError,'undefined flags read'):
                lift.validate_window_flags(rows,0x1000,[])

    def test_direct_callee_cannot_inherit_callers_defined_flags(self):
        rows=[instruction(0x1000,'CMP',write=0x40),
              instruction(0x1001,'CALL_NEAR',1,target=0x1004),instruction(0x1002,'RET_NEAR',2),
              instruction(0x1004,'JNZ',target=0x1006,read=0x40),
              instruction(0x1005,'RET_NEAR',2),instruction(0x1006,'RET_NEAR',2)]
        with self.assertRaisesRegex(ValueError,'undefined flags read'):
            lift.validate_window_flags(rows,0x1000,[])


if __name__=='__main__':
    unittest.main()
