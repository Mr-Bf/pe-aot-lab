"""Synthetic LLVM install and command recorder; no native process is launched."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from . import llvm


def archive(cpu=0x100000c, advertised=None):
    payload = struct.pack('<8I', 0xfeedfacf, cpu, 0, 1, 0, 0, 0, 0)
    size = len(payload) if advertised is None else advertised
    header = b'fixture.o/      ' + b'0           ' + b'0     ' + b'0     ' + b'100644  ' + str(size).encode().ljust(10) + b'`\n'
    if len(header) != 60:
        raise RuntimeError('bad test fixture header')
    return b'!<arch>\n' + header + payload


class LLVMBuilderBoundaries(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='graphics-llvm-test-'); self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve(); self.source = self.base/'source'
        for relative, data in [('llvm/CMakeLists.txt','fixture source'),('llvm/LICENSE.TXT','fixture license'),('cmake/placeholder','fixture')]:
            p=self.source/relative; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(data)
        self.sdk = self.base/'SDK'
        for relative in ('SDKSettings.json','usr/lib/libz.tbd','usr/lib/libxml2.tbd','usr/lib/libcurses.tbd',
                         'usr/include/zlib.h','usr/include/libxml2/libxml/parser.h'):
            p=self.sdk/relative; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('fixture SDK')
        self.tools={name:self.base/'tools'/name for name in ('cmake','ninja','meson')}
        self.tools['meson'].mkdir(parents=True)
        for name in ('cmake','ninja'):
            self.tools[name].write_text('fixture not executed'); self.tools[name].chmod(0o755)
        self.build=self.base/'build'; self.install=self.base/'install'; self.calls=[]

    def runner(self, argv, label, cwd=None, env=None, expected=0):
        self.calls.append(dict(argv=list(map(str,argv)),label=label,cwd=cwd,env=env,expected=expected))
        if label == 'graphics-llvm-configure':
            (self.build/'CMakeCache.txt').write_text('CMAKE_IGNORE_PREFIX_PATH:UNINITIALIZED=/opt/homebrew;/usr/local\n')
            (self.build/'build.ninja').write_text('# fixture\n')
            (self.build/'compile_commands.json').write_text('[]\n')
        if label == 'graphics-llvm-install':
            for name in ('llvm/IR/Module.h','llvm/Config/llvm-config.h','llvm/Config/abi-breaking.h'):
                path=self.install/'include'/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('fixture header')
            (self.install/'lib').mkdir()
            for name in llvm.LIBRARIES:
                (self.install/'lib'/('lib'+name+'.a')).write_bytes(archive())
        return dict(returncode=0,stdout='fixture stdout',stderr='',argv=list(map(str,argv)),label=label)

    def invoke(self, run=None):
        return llvm.build(self.source,self.build,self.install,self.tools,self.sdk,sys.executable,run or self.runner)

    def test_full_fixture_install_has_34_arm64_archives_and_unchanged_source(self):
        before=llvm.tree(self.source); result=self.invoke()
        self.assertEqual(result['status'],'LLVM15_STATIC_BUILT_NOT_DXMT_VERIFIED')
        self.assertEqual(len(result['libraries']),34)
        self.assertTrue(all(row['objects']==1 for row in result['libraries'].values()))
        self.assertEqual(before,llvm.tree(self.source)); self.assertEqual(len(self.calls),3)
        self.assertEqual(json.loads((self.build/'provider-result.json').read_text()),result)
        self.assertEqual((self.install/'share/licenses/llvm/LICENSE.TXT').read_text(),'fixture license')
        self.assertEqual(result['guest_executions'],0); self.assertEqual(result['gpu_executions'],0)

    def test_profile_is_explicit_and_has_no_homebrew_selected_dependency(self):
        commands=llvm.plan(self.source,self.build,self.install,self.tools,self.sdk,Path(sys.executable),2)
        args=list(map(str,commands[0][0]))
        for arg in ('-DCMAKE_OSX_ARCHITECTURES=arm64','-DCMAKE_OSX_DEPLOYMENT_TARGET=15.2',
                    '-DLLVM_ENABLE_BINDINGS=OFF','-DLLVM_ENABLE_ZSTD=OFF','-DLLVM_TARGETS_TO_BUILD=',
                    '-DLLVM_ENABLE_ASSERTIONS=ON','-DLLVM_BUILD_LLVM_DYLIB=OFF'):
            self.assertIn(arg,args)
        self.assertIn('-DCMAKE_OSX_SYSROOT='+str(self.sdk),args)
        self.assertFalse(any(str(llvm.OLD_WORK) in arg for arg in args))

    def test_existing_build_preserved_and_no_commands(self):
        self.build.mkdir(); sentinel=self.build/'keep'; sentinel.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(sentinel.read_bytes(),b'keep');self.assertEqual(self.calls,[])

    def test_source_mutation_prevents_success(self):
        def mutating(*a,**kw):
            result=self.runner(*a,**kw)
            if a[1]=='graphics-llvm-build':(self.source/'llvm/CMakeLists.txt').write_text('changed')
            return result
        with self.assertRaisesRegex(ValueError,'source changed'):self.invoke(mutating)
        self.assertFalse((self.build/'provider-result.json').exists())
        self.assertEqual(json.loads((self.build/'provider-failure.json').read_text())['status'],'FAIL')

    def test_command_exception_preserves_failed_receipt_and_stops_install(self):
        def failing(*a,**kw):
            if a[1]=='graphics-llvm-build':raise RuntimeError('fixture compiler failure')
            return self.runner(*a,**kw)
        with self.assertRaisesRegex(RuntimeError,'fixture compiler failure'):self.invoke(failing)
        self.assertEqual(len(self.calls),1);self.assertFalse(self.install.exists())
        self.assertTrue((self.build/'provider-failure.json').exists())

    def test_undeclared_homebrew_dependency_stops_before_build(self):
        def leaked(*a,**kw):
            result=self.runner(*a,**kw)
            if a[1]=='graphics-llvm-configure':(self.build/'CMakeCache.txt').write_text('ZSTD_LIBRARY:FILEPATH=/opt/homebrew/lib/libzstd.dylib\n')
            return result
        with self.assertRaisesRegex(ValueError,'uncontrolled external'):self.invoke(leaked)
        self.assertEqual(len(self.calls),1);self.assertFalse(self.install.exists())

    def test_sdk_mutation_prevents_success(self):
        def mutating(*a,**kw):
            result=self.runner(*a,**kw)
            if a[1]=='graphics-llvm-install':(self.sdk/'usr/lib/libz.tbd').write_text('changed')
            return result
        with self.assertRaisesRegex(ValueError,'inputs changed'):self.invoke(mutating)
        self.assertFalse((self.build/'provider-result.json').exists())

    def test_non_arm64_truncated_and_empty_archives_are_rejected(self):
        for raw in (archive(0x1000007), archive(advertised=1000), archive()[:-1], b'!<arch>\n'):
            with self.subTest(raw=raw):
                path=self.base/'bad.a';path.write_bytes(raw)
                with self.assertRaises(ValueError):llvm.arm_archive(path)

    def test_missing_archive_and_header_cannot_pass(self):
        for target in ('lib/libLLVMSupport.a','include/llvm/Config/abi-breaking.h'):
            with self.subTest(target=target):
                # Each call has exclusive, independent build and install paths.
                self.build=self.base/('build-'+str(len(self.calls)));self.install=self.base/('install-'+str(len(self.calls)))
                def missing(*a,**kw):
                    result=self.runner(*a,**kw)
                    if a[1]=='graphics-llvm-install':(self.install/target).unlink()
                    return result
                with self.assertRaises((ValueError,FileNotFoundError)):self.invoke(missing)
                self.assertFalse((self.build/'provider-result.json').exists())


if __name__ == '__main__':unittest.main()
