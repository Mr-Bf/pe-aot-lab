"""Pure IR contract regressions. No compiler, lifter or guest is executed."""
from pathlib import Path
import re
import unittest

from portable_lifter_v1.probe import REPO, retarget, validate_trace_abi


LAYOUT = 'target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"'
TRIPLE = 'target triple = "arm64-apple-macosx11.0.0"'
HEADER = 'target datalayout = "e-m:w-i64:64-n8:16:32:64-S128"\ntarget triple = "x86_64-pc-windows-msvc"\n'
MINIMAL = HEADER + '''define ptr @sub_1000(ptr noalias %state, i64 %pc, ptr noalias %memory) {
  %result = call ptr @sub_2000(ptr %state, i64 %pc, ptr %memory)
  ret ptr %result
}
define ptr @sub_2000(ptr noalias %state, i64 %pc, ptr noalias %memory) {
  ret ptr %memory
}
'''


def transform(text):
    return retarget(text, 0x1000, 0x1000, 'aot_entry', LAYOUT, TRIPLE)


class ProbeAbiTests(unittest.TestCase):
    def test_default_c_and_explicit_ccc_definitions_and_calls(self):
        for text in (MINIMAL, MINIMAL.replace('define ptr', 'define ccc ptr').replace('call ptr', 'call ccc ptr')):
            with self.subTest(explicit='ccc' in text):
                arm, private = transform(text)
                self.assertIn('@aot_entry(', arm)
                self.assertEqual(private, ['window_1000_sub_2000'])
                self.assertRegex(arm, r'define internal (?:ccc )?ptr @window_1000_sub_2000')

    def test_every_non_c_convention_is_rejected_at_definition(self):
        conventions = ('win64cc', 'x86_stdcallcc', 'swiftcc', 'ghccc', 'fastcc', 'coldcc',
                       'preserve_mostcc', 'x86_64_sysvcc', 'cc 0', 'cc 78', 'future_unknowncc')
        for convention in conventions:
            with self.subTest(convention=convention), self.assertRaises(ValueError):
                transform(MINIMAL.replace('define ptr', 'define ' + convention + ' ptr', 1))

    def test_every_non_c_convention_is_rejected_at_call_and_declaration(self):
        for convention in ('win64cc', 'x86_stdcallcc', 'swiftcc', 'ghccc', 'cc 0', 'future_unknowncc'):
            with self.subTest(place='call', convention=convention), self.assertRaises(ValueError):
                transform(MINIMAL.replace('call ptr', 'call ' + convention + ' ptr', 1))
            with self.subTest(place='declaration', convention=convention), self.assertRaises(ValueError):
                transform(MINIMAL + 'declare ' + convention + ' i32 @aot_begin(ptr, i64, ptr)\n')

    def test_wrong_root_return_type_cannot_be_renamed_into_entry(self):
        with self.assertRaises(ValueError):
            transform(HEADER + 'define i32 @sub_1000(){ret i32 7}\n')
        with self.assertRaises(ValueError):
            transform(MINIMAL.replace('define ptr @sub_1000', 'define i32 @sub_1000'))

    def test_root_and_private_parameters_have_exact_trace_abi(self):
        parameter_cases = (
            'ptr %state, i32 %pc, ptr %memory',
            'ptr %state, i64 %pc',
            'ptr %state, i64 %pc, ptr %memory, i64 %extra',
            'ptr %state, i64 %pc, ptr %memory, ...',
            'ptr addrspace(1) %state, i64 %pc, ptr %memory',
            'ptr sret(i64) %state, i64 %pc, ptr %memory',
        )
        original = 'ptr noalias %state, i64 %pc, ptr noalias %memory'
        for root in ('sub_1000', 'sub_2000'):
            for parameters in parameter_cases:
                with self.subTest(root=root, parameters=parameters), self.assertRaises(ValueError):
                    transform(MINIMAL.replace('@' + root + '(' + original + ')',
                                              '@' + root + '(' + parameters + ')'))

    def test_private_calls_have_exact_return_and_argument_types(self):
        calls = (
            'call i32 @sub_2000(ptr %state, i64 %pc, ptr %memory)',
            'call ptr @sub_2000(ptr %state, i32 %pc, ptr %memory)',
            'call ptr @sub_2000(ptr %state, i64 %pc)',
            'call ptr @sub_2000(ptr %state, i64 %pc, ptr %memory, i64 0)',
            'call ptr @sub_2000(ptr addrspace(1) %state, i64 %pc, ptr %memory)',
            'call ptr @sub_2000(ptr byval(i64) %state, i64 %pc, ptr %memory)',
            'call ptr @sub_3000(ptr %state, i64 %pc, ptr %memory)',
            'call ptr %function(ptr %state, i64 %pc, ptr %memory)',
        )
        old = 'call ptr @sub_2000(ptr %state, i64 %pc, ptr %memory)'
        for call in calls:
            with self.subTest(call=call), self.assertRaises(ValueError):
                transform(MINIMAL.replace(old, call))

    def test_unknown_definitions_indirect_forms_and_trace_address_uses_rejected(self):
        cases = (
            MINIMAL + 'define ptr @other(ptr %state, i64 %pc, ptr %memory) {\n ret ptr %memory\n}\n',
            MINIMAL.replace('call ptr @sub_2000', 'invoke ptr @sub_2000'),
            MINIMAL.replace('call ptr @sub_2000', 'callbr ptr @sub_2000'),
            MINIMAL + '@address = global ptr @sub_1000\n',
            MINIMAL + 'declare ptr @sub_3000(ptr, i64, ptr)\n',
            MINIMAL + 'define ptr @sub_2000(ptr %s, i64 %pc, ptr %m) {\n ret ptr %m\n}\n',
        )
        for number, text in enumerate(cases):
            with self.subTest(number=number), self.assertRaises(ValueError):
                transform(text)

    def test_default_c_and_ccc_helper_declarations_and_calls(self):
        for convention in ('', 'ccc '):
            text = MINIMAL.replace('  %result =', '  %begin = call ' + convention + 'i32 @aot_begin(ptr %state, i64 %pc, ptr %memory)\n  %result =')
            text += 'declare ' + convention + 'i32 @aot_begin(ptr, i64, ptr)\n'
            with self.subTest(convention=convention):
                self.assertEqual(validate_trace_abi(text), {'sub_1000', 'sub_2000'})
                transform(text)

    def test_actual_frozen_ir_remains_byte_identical_after_pure_retarget(self):
        compiler = REPO / 'build/migration-v3/unified-349d130f4465be3d0bc363894073b45d/native/compiler'
        for directory, rva, symbol in (('main', 4416, 'aot_entry'), ('window-proc-1000', 4096, 'aot_window_proc_1000')):
            path = compiler / directory
            self.assertTrue((path / 'lifted.ll').is_file(), 'fixed positive IR must be available')
            original = (path / 'lifted.ll').read_text()
            expected = (path / 'arm64.ll').read_text()
            layout = next(line for line in expected.splitlines() if line.startswith('target datalayout'))
            triple = next(line for line in expected.splitlines() if line.startswith('target triple'))
            arm, private = retarget(original, 0x140000000 + rva, rva, symbol, layout, triple)
            self.assertEqual(arm, expected)
            self.assertEqual(len(validate_trace_abi(original)), len(private) + 1)
            # Mutate a real trace call (main) or root definition (both roots).
            with self.assertRaises(ValueError):
                retarget(original.replace('define ptr', 'define win64cc ptr', 1),
                         0x140000000 + rva, rva, symbol, layout, triple)
            if re.search(r'call ptr @sub_', original):
                with self.assertRaises(ValueError):
                    retarget(re.sub(r'call ptr @sub_', 'call swiftcc ptr @sub_', original, count=1),
                             0x140000000 + rva, rva, symbol, layout, triple)


if __name__ == '__main__':
    unittest.main(verbosity=2)
