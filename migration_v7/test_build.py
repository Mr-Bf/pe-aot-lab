"""Actual file-based lookup bindings, independent of App/compiler execution."""
from pathlib import Path
import tempfile
import unittest

from window_lookup_v1 import runtime,producer
from migration_v7.build import verify_lookup


class ProductBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.product=Path(self.temp.name).resolve()/'product'
        self.lookup=runtime.prepare(self.product/'native/runtime-source')
        self.record={'runtime_lookup':self.lookup}
        backend=dict(source='/explicit/backend',minimum_macos='15.2')
        tools=dict(sdk='/explicit/sdk',clang='/explicit/clang',**{'clang++':'/explicit/clang++'})
        _,source,compiler,flags=next(row for row in producer.compilation_units(self.product/'native',backend,tools) if row[0]=='runtime')
        inputs=runtime.lift.snapshot([*runtime.template_paths(),self.lookup['manifest_path'],self.lookup['compile_source'],self.lookup['transaction_source']])
        deps='probe: '+self.lookup['compile_source']+' '+self.lookup['transaction_source']+'\n'
        (self.product/'native/runtime.d').write_text(deps)
        self.native=dict(runtime_lookup=dict(self.lookup),compile_inputs_before=inputs,compile_inputs_after=dict(inputs),
                         backend=backend,tools=tools,native_objects={'runtime':dict(source=str(source),compiler=compiler,flags=flags)},
                         dependency_graphs={'runtime':deps})

    def test_valid_binding(self):
        verify_lookup(self.product,self.record,self.native)

    def test_missing_template_identity(self):
        key=str(runtime.template_paths()[0])
        del self.native['compile_inputs_before'][key]
        del self.native['compile_inputs_after'][key]
        with self.assertRaisesRegex(ValueError,'compilation input identities'):
            verify_lookup(self.product,self.record,self.native)

    def test_before_after_changed(self):
        self.native['compile_inputs_after']['extra']='0'*64
        with self.assertRaisesRegex(ValueError,'compilation input identities'):
            verify_lookup(self.product,self.record,self.native)

    def test_original_runtime_selected(self):
        self.native['native_objects']['runtime']['source']=str(runtime.ROOT/runtime.RUNTIME)
        with self.assertRaisesRegex(ValueError,'source/compiler/flags'):
            verify_lookup(self.product,self.record,self.native)

    def test_arbitrary_extra_compiler_flag(self):
        self.native['native_objects']['runtime']['flags'].append('-DUNDECLARED_VARIANT=1')
        with self.assertRaisesRegex(ValueError,'source/compiler/flags'):
            verify_lookup(self.product,self.record,self.native)

    def test_dependency_record_must_match_raw(self):
        self.native['dependency_graphs']['runtime']+='\n'
        with self.assertRaisesRegex(ValueError,'recorded dependencies'):
            verify_lookup(self.product,self.record,self.native)

    def test_other_product_cannot_reuse_overlay(self):
        other=self.product.parent/'other'
        other.mkdir()
        with self.assertRaisesRegex(ValueError,'not this product overlay'):
            verify_lookup(other,self.record,self.native)


if __name__=='__main__':
    unittest.main()
