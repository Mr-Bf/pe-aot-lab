"""Pure production-lift boundaries and real frozen IR compatibility; no tools."""
import copy
import dataclasses
import json
from pathlib import Path
import tempfile
import unittest

from portable_app_v1 import lift
from window_inc_v1.loader import load_image


FROZEN = lift.ROOT / 'build/migration-v3/unified-349d130f4465be3d0bc363894073b45d/native'


class ProductionLiftTests(unittest.TestCase):
    @staticmethod
    def helper_ir(instruction, declaration, attributes=''):
        return ('target datalayout = "e"\n'
                'target triple = "x86_64-pc-windows-msvc"\n'
                'define ptr @sub_1000(ptr noalias %state, i64 %pc, ptr noalias %memory) {\n'
                '  ' + instruction + '\n  ret ptr %memory\n}\n' + declaration + '\n' + attributes)

    def retarget_helper(self, text):
        return lift.retarget(text, 0x1000, 0x1000, 'aot_entry',
                             'target datalayout = "e"', 'target triple = "arm64-apple-macos11"')

    def test_known_wrong_helper_abi_and_indentation_bypasses_are_rejected(self):
        cases = [
            self.helper_ir('%x = call i32 @__remill_function_call(i32 42)',
                           'declare i32 @__remill_function_call(i32)'),
            self.helper_ir('%x = call ptr @malloc(i64 8)', ' declare ptr @malloc(i64)'),
            self.helper_ir('%x = call ptr @__remill_function_call(ptr %state, i64 %pc, ptr %memory)',
                           'declare ptr @__remill_function_call(ptr, i64, ptr) #0',
                           ' attributes #0 = { memory(none) nocallback }'),
        ]
        # These exact counterexamples were accepted by the frozen pure helper.
        # Keep the original gap reproducible while production rejects them.
        for index, text in enumerate(cases):
            with self.subTest(index=index):
                old, _ = lift.frozen_retarget(text, 0x1000, 0x1000, 'aot_entry',
                                              'target datalayout = "e"',
                                              'target triple = "arm64-apple-macos11"')
                self.assertIn('@aot_entry(', old)
                with self.assertRaises(ValueError):
                    self.retarget_helper(text)

    def test_helper_declaration_and_call_types_must_both_match_contract(self):
        valid_call = '%x = call ptr @__remill_function_call(ptr %state, i64 %pc, ptr %memory)'
        valid_decl = 'declare ptr @__remill_function_call(ptr, i64, ptr)'
        self.assertIn('@aot_entry(', self.retarget_helper(self.helper_ir(valid_call, valid_decl))[0])
        self.assertIn('@aot_entry(', self.retarget_helper(self.helper_ir(
            valid_call.replace('call ptr', 'call ccc ptr'), valid_decl.replace('declare ptr', 'declare ccc ptr')))[0])
        for instruction, declaration in (
            (valid_call.replace('i64 %pc', 'i32 42'), valid_decl),
            (valid_call, valid_decl.replace('i64', 'i32')),
            (valid_call, ''),
            (valid_call, valid_decl + '\n' + valid_decl),
            (valid_call.replace('call ptr', 'call win64cc ptr'), valid_decl),
            (valid_call, valid_decl.replace('declare ptr', 'declare swiftcc ptr')),
            (valid_call, valid_decl.replace('declare ', 'declare\t')),
            (valid_call.replace('ptr %memory', 'ptr poison'), valid_decl),
        ):
            with self.subTest(instruction=instruction, declaration=declaration), self.assertRaises(ValueError):
                self.retarget_helper(self.helper_ir(instruction, declaration))

    def test_callback_effect_groups_require_canonical_and_defined_groups(self):
        call = '%x = call ptr @__remill_function_call(ptr %state, i64 %pc, ptr %memory) #0'
        declaration = 'declare ptr @__remill_function_call(ptr, i64, ptr) #0'
        self.retarget_helper(self.helper_ir(call, declaration, 'attributes #0 = { nounwind memory(readwrite) }'))
        for attributes in ('', 'attributes #0 = { memory(none) nocallback }',
                           'attributes #0 = { readonly }', '\tattributes #0 = { nounwind }',
                           'attributes #0 = { nounwind }\nattributes #0 = { nounwind }'):
            with self.subTest(attributes=attributes), self.assertRaises(ValueError):
                self.retarget_helper(self.helper_ir(call, declaration, attributes))

    def test_narrow_helper_extension_abi_cannot_be_changed_or_omitted(self):
        call = '%x = call zeroext i1 @__remill_compare_eq(i1 noundef zeroext false)'
        declaration = 'declare zeroext i1 @__remill_compare_eq(i1 noundef zeroext)'
        self.retarget_helper(self.helper_ir(call, declaration))
        for instruction, decl in ((call.replace('zeroext', 'signext'), declaration),
                                   (call, declaration.replace('zeroext', 'signext')),
                                   (call.replace('zeroext ', ''), declaration),
                                   (call, declaration.replace('zeroext ', '')),
                                   (call.replace('noundef zeroext', 'noundef'), declaration),
                                   (call, declaration.replace('noundef zeroext', 'noundef'))):
            with self.subTest(instruction=instruction, decl=decl), self.assertRaises(ValueError):
                self.retarget_helper(self.helper_ir(instruction, decl))

    def test_static_import_closure_includes_relative_provider_dependencies(self):
        source = lift.ROOT / 'portable_app_v1/producer.py'
        closure = lift.source_closure([source])
        required = ('portable_app_v1/producer.py', 'portable_app_v1/lift.py',
                    'portable_lifter_v1/build.py', 'portable_lifter_v1/tools.py',
                    'portable_lifter_v1/deps.py', 'portable_graphics_v1/build.py',
                    'portable_graphics_v1/cache.py', 'portable_graphics_v1/tooling.py',
                    'portable_graphics_v1/llvm.py', 'portable_lifter_v1/__init__.py')
        self.assertTrue({lift.ROOT / name for name in required} <= closure)
        self.assertEqual(lift.source_closure(closure), closure)
        self.assertTrue(all(item.is_relative_to(lift.ROOT) for item in closure))

    def test_actual_pe_roots_and_different_self_authored_bytes_are_not_hash_pinned(self):
        image = load_image((FROZEN / 'input.exe').read_bytes())
        start, code = lift.executable_bytes(image, [4096])
        self.assertEqual((start, len(code)), (4096, 3110))
        first = load_image(lift.pe_image(b'\xc3'))
        second = load_image(lift.pe_image(b'\x31\xc0\xc3'))
        self.assertNotEqual(first.source_sha256, second.source_sha256)
        self.assertEqual(lift.executable_bytes(first, []), (4096, b'\xc3'))
        self.assertEqual(lift.executable_bytes(second, []), (4096, b'\x31\xc0\xc3'))

    def test_callback_type_duplicate_and_file_backing_boundaries(self):
        image = load_image((FROZEN / 'input.exe').read_bytes())
        for roots in ([True], ['4096'], [4096, 4096], [image.entry_rva], [8191], list(range(9))):
            with self.subTest(roots=roots), self.assertRaises(ValueError):
                lift.executable_bytes(image, roots)
        sections = copy.deepcopy(image.sections)
        sections[0]['virtual_size'] = 40000
        sections[0]['raw_size'] = 40000
        with self.assertRaisesRegex(ValueError, 'bounded executable'):
            lift.executable_bytes(dataclasses.replace(image, sections=sections), [4096])
        with self.assertRaisesRegex(ValueError, 'relocation'):
            lift.executable_bytes(dataclasses.replace(image, relocations=[{'rva': 4092}]), [4096])

    def test_actual_root_and_ret_ir_keep_the_verified_retarget_result(self):
        for folder, rva, symbol in (('compiler/main', 4416, 'aot_entry'),
                                    ('compiler/window-proc-1000', 4096, 'aot_window_proc_1000'),
                                    ('ret-shim', 4096, 'aot_import_ret')):
            directory = FROZEN / folder
            original = (directory / 'lifted.ll').read_text()
            expected = (directory / 'arm64.ll').read_text()
            lines = expected.splitlines()
            layout = next(line for line in lines if line.startswith('target datalayout'))
            triple = next(line for line in lines if line.startswith('target triple'))
            arm, _ = lift.retarget(original, 0x140000000 + rva, rva, symbol, layout, triple)
            self.assertEqual(arm, expected)
            layout_text = lift.layout_ir(original, layout, triple)
            self.assertEqual(layout_text.count('define i64 @layout_'), 26)
            self.assertIn('getelementptr ({ i8, %struct.State }', layout_text)
            with self.assertRaises(ValueError):
                lift.retarget(original.replace('define ptr', 'define win64cc ptr', 1),
                              0x140000000 + rva, rva, symbol, layout, triple)

    @staticmethod
    def folded(values):
        return '\n'.join(f'define i64 @layout_{index}() {{\n  ret i64 {value}\n}}' for index, value in enumerate(values))

    def test_folded_layout_exact_values_and_all_functions_required(self):
        valid = self.folded(lift.EXPECTED_LAYOUT)
        self.assertEqual(lift.folded_layout(valid), lift.EXPECTED_LAYOUT)
        changed = list(lift.EXPECTED_LAYOUT)
        changed[1] = 8
        for text in (self.folded(changed), self.folded(lift.EXPECTED_LAYOUT[:-1]),
                     valid + '\ndefine i64 @layout_0() { ret i64 3504 }',
                     valid.replace('ret i64 3504', 'ret i64 ptrtoint (ptr null to i64)'),
                     valid.replace('ret i64 3504', '%v = add i64 3500, 4\nret i64 %v')):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                lift.folded_layout(text)

    def test_paths_and_input_identity_cannot_redirect_to_old_work(self):
        with self.assertRaisesRegex(ValueError, 'old work'):
            lift.path(lift.OLD_WORK / 'new-looking-output', exists=False)
        with tempfile.TemporaryDirectory(prefix='portable-lift-boundary-') as temporary:
            root = Path(temporary).resolve()
            file = root / 'input'
            file.write_bytes(b'original')
            identity = lift.snapshot([file])
            file.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed'):
                lift.unchanged(identity)
            alias = root / 'alias'
            alias.symlink_to(file)
            with self.assertRaisesRegex(ValueError, 'non-symlink'):
                lift.path(alias)

    def test_absent_provider_fails_before_any_command_or_compiler_output(self):
        with tempfile.TemporaryDirectory(prefix='portable-provider-boundary-') as temporary:
            root = Path(temporary).resolve()
            provider = root / 'provider'
            provider.mkdir()
            commands = []
            with self.assertRaises(ValueError):
                lift.Session(provider, root / 'out', lambda *args, **kwargs: commands.append(args))
            self.assertEqual(commands, [])
            self.assertFalse((root / 'out').exists())

    def test_command_guard_records_failure_without_native_execution(self):
        with tempfile.TemporaryDirectory(prefix='portable-command-boundary-') as temporary:
            root = Path(temporary).resolve()
            calls = []
            def recorder(*args, **kwargs):
                calls.append((args, kwargs))
                return dict(stdout='', stderr='synthetic refusal', returncode=7)
            commands = lift.Commands(root, recorder, 'test')
            with self.assertRaisesRegex(ValueError, 'old work'):
                commands([lift.OLD_WORK / 'old-lifter'], 'bad-path')
            self.assertEqual(calls, [])
            with self.assertRaisesRegex(ValueError, 'unexpected command exit'):
                commands(['/selected/not-executed'], 'synthetic-failure')
            self.assertEqual(len(calls), 1)
            record = json.loads((root / 'commands/001-synthetic-failure.json').read_text())
            self.assertEqual(record['returncode'], 7)


if __name__ == '__main__':
    unittest.main(verbosity=2)
