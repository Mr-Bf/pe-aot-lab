"""Independent synthetic installer/restore cases; zero compiler or App runs.

The real schema-2 PE/profile parser, filesystem, hashes, journal and flock are
used. Cache/Apple discovery, isolated workers and provider validation are test
fixtures. Provider validators independently read temporary fixture payloads;
they do not simply return a success marker. One separate test launches a short
current-Python child to prove real inherited-flock semantics. No compiler,
native builder, guest, App, GPU or network request is executed.
"""
import copy
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import selectors
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from migration_install_v2 import runner

ROOT = Path(__file__).resolve().parents[1]
STAGES = ['cpu-build', 'switch-build', 'graphics-build', 'app-build', 'app-verify']
REAL_POPEN = subprocess.Popen


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def read(path):
    return json.loads(Path(path).read_bytes())


def tree(root):
    result = {}
    for path in sorted(Path(root).rglob('*')):
        rel = str(path.relative_to(root))
        if path.is_symlink(): result[rel] = ['link', os.readlink(path)]
        elif path.is_file(): result[rel] = ['file', digest(path)]
        else: result[rel] = ['directory']
    return result


class Fixture:
    def __enter__(self):
        self.stack = ExitStack()
        name = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='install-v2-synthetic-'))
        self.root = Path(name).resolve()
        self.cpu, self.graphics = self.root/'cpu-cache', self.root/'graphics-cache'
        self.cpu.mkdir(); self.graphics.mkdir()
        (self.cpu/'remill.tar.gz').write_bytes(b'fixture source archive; never extracted')
        (self.cpu/'tools.fixture').write_bytes(b'fixture CPU tool cache')
        (self.graphics/'cache.fixture').write_bytes(b'fixture graphics cache')
        self.sdk = self.root/'sdk'; self.sdk.mkdir()
        (self.sdk/'SDKSettings.json').write_text('{"fixture":1}\n')
        (self.sdk/'compiler.fixture').write_bytes(b'fixture compiler identity; never executed')
        self.pe, self.profile = self.root/'input.exe', self.root/'profile.json'
        shutil.copyfile(ROOT/'examples/window-switch/switch_tile.exe', self.pe)
        shutil.copyfile(ROOT/'examples/window-switch/profile.json', self.profile)
        self.work, self.out = self.root/'work root', self.root/'evidence-01'
        self.args = dict(cpu_cache=self.cpu, graphics_cache=self.graphics, pe=self.pe,
                         profile=self.profile, identifier='org.peaotlab.installv2.synthetic',
                         work_root=self.work, out=self.out, jobs=2)
        self.calls, self.validated, self.mode, self.hooks = [], [], {}, {}
        self.initial = {str(p): digest(p) for p in (self.pe, self.profile, self.cpu/'remill.tar.gz',
                        self.cpu/'tools.fixture', self.graphics/'cache.fixture', self.sdk/'SDKSettings.json')}
        self.stack.enter_context(mock.patch.object(runner.platform, 'system', return_value='Darwin'))
        self.stack.enter_context(mock.patch.object(runner.platform, 'machine', return_value='arm64'))
        self.stack.enter_context(mock.patch.object(runner, '_apple_preflight', side_effect=self.apple))
        self.stack.enter_context(mock.patch.object(runner.cpu_tools, 'check_cache', side_effect=lambda p: {'fixture':digest(Path(p)/'tools.fixture')}))
        self.stack.enter_context(mock.patch.object(runner.cpu_deps, 'sources', side_effect=lambda p: {'fixture':digest(Path(p)/'remill.tar.gz')}))
        self.stack.enter_context(mock.patch.object(runner.graphics_cache_module, 'check_cache', side_effect=lambda p: {'fixture':digest(Path(p)/'cache.fixture')}))
        self.stack.enter_context(mock.patch.object(runner.cpu_builder, 'REMILL_ARCHIVE_SHA', digest(self.cpu/'remill.tar.gz')))
        # Coordinator tests use a small inventory of real implementation files.
        # The full scanner itself has a separate direct resource-closure test.
        self.stack.enter_context(mock.patch.object(runner, '_implementation',
            side_effect=lambda:{str(p.relative_to(ROOT)):digest(p) for p in runner.SOURCES}))
        self.stack.enter_context(mock.patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=100*1024**3)))
        self.stack.enter_context(mock.patch.object(runner, '_run_worker', side_effect=self.worker))
        self.stack.enter_context(mock.patch.object(runner, '_group_state', return_value='ABSENT'))
        self.stack.enter_context(mock.patch.object(runner.cpu_builder, 'paths_for', side_effect=lambda p:self.validate_provider('cpu-build',p)))
        self.stack.enter_context(mock.patch.object(runner.switch_builder, 'paths_for', side_effect=lambda p:self.validate_provider('switch-build',p)))
        self.stack.enter_context(mock.patch.object(runner.graphics_builder, 'paths_for', side_effect=lambda p:self.validate_provider('graphics-build',p)))
        self.stack.enter_context(mock.patch.object(runner.app_builder, 'verify', side_effect=self.verify_app))
        for name in ('run', 'Popen'):
            self.stack.enter_context(mock.patch.object(runner.subprocess, name, side_effect=AssertionError('native/program launch forbidden in synthetic tests')))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def apple(self):
        return dict(developer=str(self.sdk), sdk=str(self.sdk),
                    sdk_settings={'SDKSettings.json':digest(self.sdk/'SDKSettings.json')},
                    tools={'clang':str(self.sdk/'compiler.fixture')},
                    fixture_tool_sha256=digest(self.sdk/'compiler.fixture'), queries=[])

    def create_provider(self, stage, prefix, parent=None):
        prefix=Path(prefix); prefix.mkdir(parents=True, exist_ok=False)
        payload=prefix/'payload.fixture';payload.write_bytes((stage+' native payload fixture').encode())
        source=prefix/'source';source.mkdir();(source/'fixture.c').write_text('/* synthetic provider source */\n')
        result=dict(schema=1,status={'cpu-build':'CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED',
                                    'switch-build':runner.switch_builder.STATUS,
                                    'graphics-build':runner.graphics_builder.STATUS}[stage],
                    guest_executions=0,gpu_executions=0,
                    runtime_files={'payload.fixture':{'sha256':digest(payload),'mode':payload.stat().st_mode&0o777}},
                    source_tree={'fixture.c':{'sha256':digest(source/'fixture.c'),
                                             'mode':(source/'fixture.c').stat().st_mode&0o777}},
                    external_prerequisites={'sdk':str(self.sdk),
                         'sdk_settings':{'SDKSettings.json':digest(self.sdk/'SDKSettings.json')}})
        if stage=='switch-build':
            result.update(prefix=str(prefix),capabilities=[runner.switch_builder.CAPABILITY],
                          provider=str(parent),provider_sha256=digest(Path(parent)/'provider.json'))
        write(prefix/'provider.json',result)
        return result

    def validate_provider(self, stage, prefix):
        prefix=Path(prefix);self.validated.append((stage,str(prefix)))
        descriptor=prefix/'provider.json'
        if descriptor.is_symlink() or not descriptor.is_file():raise ValueError('fixture manifest is not regular')
        record=read(descriptor)
        expected={'cpu-build':'CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED',
                  'switch-build':runner.switch_builder.STATUS,'graphics-build':runner.graphics_builder.STATUS}[stage]
        if record.get('status')!=expected:raise ValueError('fixture provider status changed')
        for rel,entry in record['runtime_files'].items():
            path=prefix/rel
            if path.is_symlink() or digest(path)!=entry['sha256']:raise ValueError('fixture provider payload changed')
        if stage=='switch-build':
            if record.get('prefix')!=str(prefix) or record.get('capabilities')!=[runner.switch_builder.CAPABILITY]:
                raise ValueError('fixture window capability differs')
            self.validate_provider('cpu-build',record['provider'])
            if digest(Path(record['provider'])/'provider.json')!=record['provider_sha256']:raise ValueError('fixture parent differs')
        roles=dict(lifter=prefix/'payload.fixture',source=prefix/'source',semantics=prefix/'payload.fixture',
                   llvm=prefix,sdk=self.sdk,provider_manifest=descriptor,provider_sha256=digest(descriptor))
        return roles if stage=='graphics-build' else (record,roles)

    def verify_app(self, out):
        out=Path(out);self.validated.append(('app-verify',str(out)))
        record=read(out/'result.json')
        if record.get('status')!=runner.app_builder.STATUS:raise ValueError('fixture product unsuccessful')
        for rel,key in [('input.exe','input_sha256'),('profile.json','profile_sha256')]:
            if digest(out/rel)!=record[key]:raise ValueError('fixture product bytes changed')
        analysis=runner.profiles.analyze((out/'input.exe').read_bytes(),read(out/'profile.json'))
        if analysis['status']!='ELIGIBLE_FOR_BUILD_NOT_DECODED':raise ValueError('fixture product profile invalid')
        return dict(status='PORTABLE_APP_FILES_VERIFIED_NOT_EXECUTED',app=record['app'],files=3,
                    guest_executions=0,gpu_executions=0)

    def worker(self, job, lock_fd):
        stage=job['stage'];args=job['arguments'];mode=self.mode.get(stage)
        self.calls.append((stage,copy.deepcopy(args)))
        os.fstat(lock_fd)  # The coordinator really supplies its live lock descriptor.
        pid=20000+len(self.calls)
        identity=digest(job['_job_path'])
        write(job['launched'],dict(schema=1,stage=stage,pid=pid,pgid=pid,job_sha256=identity,
              protocol='REGISTER_BEFORE_BUILDER_V1',lock_identity=job['lock_identity'],
              started_at='2026-10-29T00:00:00+00:00',process_identity='SYNTHETIC_WORKER_NOT_STARTED'))
        if stage in self.hooks:self.hooks[stage](args)
        if isinstance(mode,BaseException):raise mode
        if stage.endswith('-build') and stage!='app-build':
            prefix,out=Path(args['prefix']),Path(args['out'])
            if prefix.exists() or out.exists():raise AssertionError('coordinator reused an existing attempt path')
            out.mkdir(parents=True)
            parent=args.get('provider')
            returned=self.create_provider(stage,prefix,parent)
            if stage=='switch-build' and mode=='wrong-parent':
                alternate=self.root/'alternate valid CPU'
                self.create_provider('cpu-build',alternate)
                returned.update(provider=str(alternate),provider_sha256=digest(alternate/'provider.json'))
                write(prefix/'provider.json',returned)
            if stage=='switch-build' and mode=='wrong-capability':
                returned['capabilities']=['arbitrary-indirect'];write(prefix/'provider.json',returned)
            recorded=copy.deepcopy(returned) if stage=='switch-build' else dict(status=returned['status'],prefix=str(prefix),provider_sha256=digest(prefix/'provider.json'),commands=[])
        elif stage=='app-build':
            out=Path(args['out'])
            if out.exists():raise AssertionError('coordinator reused an existing App attempt')
            out.mkdir(parents=True)
            shutil.copyfile(args['pe'],out/'input.exe'); profile=copy.deepcopy(args['profile'])
            if mode=='consistent-wrong-input':
                data=bytearray((out/'input.exe').read_bytes());data[-1]^=1;(out/'input.exe').write_bytes(data)
                profile['pe_sha256']=digest(out/'input.exe')
            if mode=='consistent-wrong-profile':profile['save_observation']='different.bin'
            write(out/'profile.json',profile)
            if mode=='consistent-mutated-frozen-profile':
                (out/'profile.json').write_bytes((self.out/'inputs/profile.json').read_bytes())
            returned=dict(schema=1,profile='window-switch-v6',status=runner.app_builder.STATUS,
                original_input=args['pe'],input_sha256=digest(out/'input.exe'),profile_sha256=digest(out/'profile.json'),
                cpu_prefix=args['cpu_prefix'],backend_prefix=args['backend_prefix'],
                cpu_provider_sha256=digest(Path(args['cpu_prefix'])/'provider.json'),
                graphics_provider_sha256=digest(Path(args['backend_prefix'])/'provider.json'),
                spec={'identifier':args['identifier'],'name':'PE AOT Portable Window'},
                app=str(out/'PE AOT Converted.app'),guest_executions=0,gpu_executions=0,requires_arguments=False)
            if mode=='consistent-wrong-cpu':returned['cpu_provider_sha256']='0'*64
            if mode=='consistent-wrong-graphics':returned['graphics_provider_sha256']='0'*64
            recorded=copy.deepcopy(returned)
        else:
            returned=self.verify_app(args['out']);recorded=None
        receipt=job.get('builder_receipt')
        if mode=='wrong-status':returned['status']='FAIL'
        if mode=='receipt-failed' and recorded is not None:recorded['status']='FAIL'
        if mode=='wrong-prefix' and recorded is not None:recorded['prefix']=str(self.root/'unrelated')
        if mode=='wrong-provider' and recorded is not None:recorded['provider_sha256']='0'*64
        if mode=='provider-return-differs':
            changed=copy.deepcopy(returned);changed['changed_after_return']=True
            write(Path(args['prefix'])/'provider.json',changed)
            if stage!='switch-build':recorded['provider_sha256']=digest(Path(args['prefix'])/'provider.json')
        if receipt and mode!='missing-receipt':
            write(receipt,recorded)
            if mode=='symlink-receipt':
                actual=self.root/('external-receipt-'+str(pid)+'.json');Path(receipt).rename(actual);Path(receipt).symlink_to(actual)
        if mode=='not-dict':returned=None
        write(job['worker_result'],dict(schema=1,status='WORKER_RETURNED',stage=stage,returned=returned,job_sha256=identity))
        return dict(returncode=7 if mode=='nonzero-worker' else 0,pid=pid,pgid=pid,
                    group_state=runner._group_state(pid))

    def resume(self, index=2):
        return runner.resume(installation=self.out,out=self.root/('evidence-%02d'%index))

    def stage_args(self, stage):
        return next(args for name,args in self.calls if name==stage)


class InstallTests(unittest.TestCase):
    def test_real_source_inventory_covers_entrypoints_and_nonpython_runtime_resources(self):
        result=runner._implementation()
        for name in ['migration_install_v2/runner.py','migration_install_v2/__main__.py',
                     'window_switch_v1/provider.py','window_switch_v1/window-driver.patch',
                     'window_switch_v1/SwitchProfile.h','window_switch_v1/runtime_impl.inc',
                     'window_bridge/window_runtime/transaction_v1.c']:
            self.assertEqual(result[name],digest(ROOT/name))

    def test_durable_publication_is_atomic_complete_and_never_overwrites(self):
        with tempfile.TemporaryDirectory(prefix='install-v2-atomic-json-') as directory:
            root=Path(directory).resolve();destination=root/'record.json';payload={'registered':True,'rows':list(range(30))}
            actual_link=os.link;observations=[]
            def observe_commit(source,target,*args,**kwargs):
                self.assertFalse(Path(target).exists(),'final journal pathname exposed before atomic publication')
                self.assertEqual(read(source),payload,'published temporary file was incomplete')
                observations.append((str(source),str(target)))
                return actual_link(source,target,*args,**kwargs)
            with mock.patch.object(runner.os,'link',side_effect=observe_commit):
                runner._durable(destination,payload)
            self.assertEqual(len(observations),1);self.assertEqual(read(destination),payload)
            before=destination.read_bytes()
            with self.assertRaises(FileExistsError):runner._durable(destination,{'replaced':True})
            self.assertEqual(destination.read_bytes(),before)
            self.assertEqual({p.name for p in root.iterdir()},{destination.name})

    def test_plan_is_readonly_real_schema2_admission(self):
        with Fixture() as f:
            before=tree(f.root);result=runner.plan(**f.args)
            self.assertEqual(result['status'],runner.PLAN_STATUS)
            self.assertEqual(result['stages'],STAGES)
            self.assertEqual(tree(f.root),before);self.assertEqual(f.calls,[])

    def test_success_orders_stages_and_binds_overlay_to_cpu(self):
        with Fixture() as f:
            result=runner.install(**f.args)
            self.assertEqual(result['status'],runner.STATUS)
            self.assertEqual([s for s,_ in f.calls],STAGES)
            cpu=f.stage_args('cpu-build');overlay=f.stage_args('switch-build');app=f.stage_args('app-build')
            self.assertEqual(overlay['provider'],cpu['prefix'])
            self.assertEqual(app['cpu_prefix'],overlay['prefix'])
            self.assertEqual(app['backend_prefix'],f.stage_args('graphics-build')['prefix'])
            self.assertEqual(result['guest_executions'],0);self.assertEqual(result['gpu_executions'],0)

    def test_bad_stage_receipts_stop_without_downstream_build(self):
        for stage in STAGES[:-1]:
            for mode in ['receipt-failed','missing-receipt','symlink-receipt','wrong-status','not-dict']:
                with self.subTest(stage=stage,mode=mode),Fixture() as f:
                    f.mode[stage]=mode;result=runner.install(**f.args)
                    self.assertNotEqual(result['status'],runner.STATUS)
                    self.assertEqual([s for s,_ in f.calls],STAGES[:STAGES.index(stage)+1])

    def test_provider_return_prefix_hash_and_capability_rejections(self):
        cases=[(stage,mode) for stage in STAGES[:3] for mode in ['wrong-prefix','wrong-provider','provider-return-differs']]
        cases += [('switch-build','wrong-parent'),('switch-build','wrong-capability')]
        for stage,mode in cases:
            with self.subTest(stage=stage,mode=mode),Fixture() as f:
                f.mode[stage]=mode;result=runner.install(**f.args)
                self.assertNotEqual(result['status'],runner.STATUS)
                self.assertEqual([s for s,_ in f.calls],STAGES[:STAGES.index(stage)+1])

    def test_self_consistent_app_wrong_original_identity_is_rejected(self):
        for mode in ['consistent-wrong-input','consistent-wrong-profile','consistent-wrong-cpu','consistent-wrong-graphics']:
            with self.subTest(mode=mode),Fixture() as f:
                f.mode['app-build']=mode;result=runner.install(**f.args)
                self.assertNotEqual(result['status'],runner.STATUS)
                self.assertNotIn('app-verify',[s for s,_ in f.calls])

    def test_failed_stage_resume_uses_new_attempt_and_revalidates_completed(self):
        for stage in STAGES:
            with self.subTest(stage=stage),Fixture() as f:
                f.mode[stage]='wrong-status';first=runner.install(**f.args)
                self.assertNotEqual(first['status'],runner.STATUS)
                old=tree(f.out);calls=len(f.calls);f.mode.clear();f.validated.clear()
                restored=f.resume()
                self.assertEqual(restored['status'],runner.STATUS)
                self.assertEqual([s for s,_ in f.calls[calls:]],STAGES[STAGES.index(stage):])
                new=tree(f.out)
                self.assertTrue(all(new.get(name)==value for name,value in old.items()),'resume changed original session files')
                if stage!='app-verify':
                    attempts=[args['out'] for s,args in f.calls if s==stage]
                    self.assertEqual(len(attempts),2);self.assertNotEqual(*attempts)
                for previous in STAGES[:STAGES.index(stage)]:
                    expected='app-verify' if previous=='app-build' else previous
                    self.assertTrue(any(s==expected for s,_ in f.validated),'completed stage was not revalidated: '+previous)

    def test_nonzero_worker_cannot_accept_even_successful_builder_receipts(self):
        for stage in STAGES:
            with self.subTest(stage=stage),Fixture() as f:
                f.mode[stage]='nonzero-worker';result=runner.install(**f.args)
                self.assertNotEqual(result['status'],runner.STATUS)
                self.assertEqual([s for s,_ in f.calls],STAGES[:STAGES.index(stage)+1])

    def test_implementation_change_refuses_resume_before_new_worker(self):
        with Fixture() as f:
            f.mode['graphics-build']='wrong-status';runner.install(**f.args)
            changed=dict(runner._implementation());changed['synthetic-source-change']='0'*64
            count=len(f.calls)
            with mock.patch.object(runner,'_implementation',return_value=changed):
                with self.assertRaisesRegex(ValueError,'implementation changed'):f.resume()
            self.assertEqual(len(f.calls),count)

    def test_frozen_input_tampering_and_plan_identity_changes_refuse_resume(self):
        for case in ['frozen-pe','frozen-profile','frozen-profile-whitespace','identifier','capability','stage-order']:
            with self.subTest(case=case),Fixture() as f:
                f.mode['graphics-build']='wrong-status';runner.install(**f.args);count=len(f.calls)
                if case.startswith('frozen-'):
                    path=f.out/'inputs'/('input.exe' if case=='frozen-pe' else 'profile.json')
                    path.write_bytes(path.read_bytes()+(b' ' if case=='frozen-profile-whitespace' else b'changed'))
                else:
                    path=f.out/'plan.json';value=read(path)
                    if case=='identifier':value['identifier']='org.peaotlab.other'
                    elif case=='capability':value['capability']='arbitrary-jump'
                    else:value['stages']=list(reversed(STAGES))
                    write(path,value)
                with self.assertRaises((ValueError,OSError)):f.resume()
                self.assertEqual(len(f.calls),count)

    def test_self_consistent_app_using_modified_frozen_profile_hash_is_rejected(self):
        with Fixture() as f:
            f.mode['app-build']='consistent-mutated-frozen-profile'
            def alter_frozen(_):
                path=f.out/'inputs/profile.json';path.write_bytes(path.read_bytes()+b' ')
            f.hooks['app-build']=alter_frozen
            result=runner.install(**f.args)
            self.assertNotEqual(result['status'],runner.STATUS)
            self.assertEqual([s for s,_ in f.calls],STAGES[:-1])
            args=f.stage_args('app-build');receipt=Path(args['out'])/'result.json';returned=read(receipt)
            self.assertEqual(returned['profile_sha256'],digest(f.out/'inputs/profile.json'))
            self.assertNotEqual(returned['profile_sha256'],read(f.out/'plan.json')['inputs']['canonical_profile_sha256'])
            with self.assertRaisesRegex(ValueError,'App identity'):
                runner._accept('app-build',returned,receipt,args,dict(plan=read(f.out/'plan.json'),installation=str(f.out)))

    def test_missing_existing_lock_refuses_resume_without_recreating_inode(self):
        with Fixture() as f:
            f.mode['graphics-build']='wrong-status';runner.install(**f.args)
            lock=f.work/'.install.lock';lock.unlink();count=len(f.calls)
            with self.assertRaises((ValueError,OSError)):f.resume()
            self.assertFalse(lock.exists());self.assertEqual(len(f.calls),count)

    def test_unregistered_attempt_with_builder_output_is_not_assumed_idle(self):
        with Fixture() as f:
            f.mode['cpu-build']='wrong-status';runner.install(**f.args)
            attempt=next((f.out/'attempts').iterdir());(attempt/'launched.json').unlink()
            # There are real temporary fixture provider/output bytes, but no
            # register-before-builder proof. Removing other markers must not
            # transform this into a safe fresh attempt.
            (attempt/'worker-result.json').unlink();(attempt/'worker-exit.json').unlink()
            count=len(f.calls)
            with self.assertRaises((ValueError,OSError)):f.resume()
            self.assertEqual(len(f.calls),count)

    def test_accepted_stage_changed_during_next_worker_cannot_commit_success(self):
        for stage,previous in [('switch-build','cpu-build'),('graphics-build','switch-build'),('app-build','graphics-build')]:
            with self.subTest(stage=stage),Fixture() as f:
                def corrupt(_):
                    prefix=Path(f.stage_args(previous)['prefix'])
                    (prefix/'payload.fixture').write_bytes(b'changed while worker ran')
                f.hooks[stage]=corrupt;result=runner.install(**f.args)
                self.assertNotEqual(result['status'],runner.STATUS)
                self.assertEqual([s for s,_ in f.calls],STAGES[:STAGES.index(stage)+1])

    def test_active_installation_lock_blocks_resume_before_output_creation(self):
        with Fixture() as f:
            f.mode['graphics-build']='wrong-status';runner.install(**f.args)
            fd=runner._lock(f.work)
            try:
                before=tree(f.root);count=len(f.calls)
                with self.assertRaises((BlockingIOError,OSError)):f.resume()
                self.assertEqual(tree(f.root),before);self.assertEqual(len(f.calls),count)
            finally:os.close(fd)

    def test_inherited_real_lock_survives_parent_fd_close_until_child_exit(self):
        # Exercise the real install() cancellation/finally path, not a hand-
        # written unlock stand-in. The mock stage creates only a tiny Python
        # holder, then loses its coordinator through KeyboardInterrupt.
        with Fixture() as f:
            child=None
            try:
                def hold_then_interrupt(job,fd):
                    nonlocal child
                    code=('import os,sys\n'
                          'fd=int(sys.argv[1]);os.fstat(fd)\n'
                          'print("INHERITED_LOCK_READY",flush=True)\n'
                          'sys.stdin.buffer.readline();os.close(fd)\n')
                    child=REAL_POPEN([sys.executable,'-B','-c',code,str(fd)],pass_fds=(fd,),
                        start_new_session=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    with selectors.DefaultSelector() as waiting:
                        waiting.register(child.stdout,selectors.EVENT_READ)
                        self.assertTrue(waiting.select(timeout=5),'controlled lock child did not report ready')
                    self.assertEqual(child.stdout.readline(),b'INHERITED_LOCK_READY\n')
                    write(job['launched'],dict(schema=1,stage=job['stage'],pid=child.pid,pgid=child.pid,
                        job_sha256=digest(job['_job_path']),protocol=runner.PROTOCOL,
                        lock_identity=job['lock_identity'],
                        process_identity='CONTROLLED_PYTHON_LOCK_HOLDER',started_at='2026-10-29T00:00:00+00:00'))
                    raise KeyboardInterrupt('synthetic coordinator interruption while child holds inherited fd')
                with mock.patch.object(runner,'_run_worker',side_effect=hold_then_interrupt):
                    with self.assertRaises(KeyboardInterrupt):runner.install(**f.args)
                self.assertEqual(read(f.out/'result.json')['status'],'INSTALL_CANCELLED_CHILD_STATE_UNKNOWN')
                contender=os.open(f.work/'.install.lock',os.O_RDWR)
                try:
                    with self.assertRaises((BlockingIOError,OSError)):
                        fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(contender)
                with self.assertRaises((BlockingIOError,OSError)):f.resume()
                stdout,stderr=child.communicate(input=b'exit\n',timeout=5)
                self.assertEqual(child.returncode,0,stderr.decode(errors='replace'))
                reacquired=runner._lock(f.work)
                os.close(reacquired)
            finally:
                if child is not None and child.poll() is None:
                    child.terminate();child.communicate(timeout=5)

    def test_worker_rejects_regular_fd_for_another_inode_before_registering(self):
        with tempfile.TemporaryDirectory(prefix='install-v2-wrong-lock-fd-') as directory:
            root=Path(directory).resolve();work=root/'work';fd=runner._lock(work,create=True)
            wrong=None
            try:
                other=root/'regular-but-not-installation-lock';other.write_bytes(b'not the lock')
                wrong=os.open(other,os.O_RDWR)
                job=root/'job.json';launched=root/'launched.json'
                write(job,dict(stage='cpu-build',lock_identity=runner._lock_identity(fd,work),
                               launched=str(launched),arguments={},worker_result=str(root/'worker-result.json')))
                with mock.patch.object(runner.os,'getpgrp',return_value=os.getpid()), \
                     mock.patch.object(runner,'_dispatch',side_effect=AssertionError('builder must not run')):
                    with self.assertRaises((ValueError,OSError)):runner.worker(job,wrong)
                self.assertFalse(launched.exists());self.assertFalse((root/'worker-result.json').exists())
            finally:
                if wrong is not None:os.close(wrong)
                os.close(fd)

    def test_resume_rejects_symlinked_lock_and_journal(self):
        for case in ['lock','plan']:
            with self.subTest(case=case),Fixture() as f:
                f.mode['graphics-build']='wrong-status';runner.install(**f.args)
                path=f.work/'.install.lock' if case=='lock' else f.out/'plan.json'
                external=f.root/('external-'+case);path.rename(external);path.symlink_to(external)
                count=len(f.calls)
                with self.assertRaises((ValueError,OSError)):f.resume()
                self.assertEqual(len(f.calls),count)

    def test_completed_install_resume_never_rebuilds_successful_stages(self):
        with Fixture() as f:
            self.assertEqual(runner.install(**f.args)['status'],runner.STATUS)
            count=len(f.calls);restored=f.resume()
            self.assertEqual(restored['status'],runner.STATUS)
            self.assertEqual(len(f.calls),count)

    def test_completed_provider_payload_corruption_blocks_resume_before_new_worker(self):
        for provider in STAGES[:3]:
            with self.subTest(provider=provider),Fixture() as f:
                f.mode['app-build']='wrong-status';runner.install(**f.args)
                path=Path(f.stage_args(provider)['prefix'])/'payload.fixture';path.write_bytes(b'corrupted after success')
                count=len(f.calls)
                with self.assertRaises((ValueError,OSError)):f.resume()
                self.assertEqual(len(f.calls),count)

    def test_changes_to_plan_inputs_cache_or_sdk_refuse_resume(self):
        for name in ['pe','profile','cpu-cache','graphics-cache','sdk','tool']:
            with self.subTest(name=name),Fixture() as f:
                f.mode['graphics-build']='wrong-status';runner.install(**f.args)
                path={'pe':f.pe,'profile':f.profile,'cpu-cache':f.cpu/'tools.fixture',
                      'graphics-cache':f.graphics/'cache.fixture','sdk':f.sdk/'SDKSettings.json',
                      'tool':f.sdk/'compiler.fixture'}[name]
                path.write_bytes(path.read_bytes()+b'CHANGED');count=len(f.calls)
                with self.assertRaises((ValueError,OSError)):f.resume()
                self.assertEqual(len(f.calls),count)

    def test_live_or_unobservable_worker_group_blocks_acceptance_and_resume(self):
        for state in ['PRESENT','UNOBSERVABLE']:
            with self.subTest(state=state),Fixture() as f:
                with mock.patch.object(runner,'_group_state',return_value=state):
                    result=runner.install(**f.args)
                    self.assertNotEqual(result['status'],runner.STATUS)
                    count=len(f.calls)
                    with self.assertRaises((ValueError,OSError)):f.resume()
                    self.assertEqual(len(f.calls),count)

    def test_resume_group_is_reobserved_not_trusted_from_exit_marker(self):
        with Fixture() as f:
            f.mode['graphics-build']='wrong-status';runner.install(**f.args);count=len(f.calls)
            with mock.patch.object(runner,'_group_state',return_value='PRESENT'):
                with self.assertRaises((ValueError,OSError)):f.resume()
            self.assertEqual(len(f.calls),count)

    def test_existing_resume_output_is_never_overwritten(self):
        with Fixture() as f:
            runner.install(**f.args);out=f.root/'evidence-02';out.mkdir();(out/'keep').write_text('retain')
            before=tree(f.root);count=len(f.calls)
            with self.assertRaises((ValueError,OSError)):f.resume()
            self.assertEqual(tree(f.root),before);self.assertEqual(len(f.calls),count)

    def test_plan_paths_reject_aliases_existing_roots_and_input_symlinks(self):
        for case in ['work-exists','out-exists','cache-equal','cache-nested','out-in-cache','work-out-nested','pe-symlink','out-broken-symlink','cache-symlink']:
            with self.subTest(case=case),Fixture() as f:
                args=dict(f.args)
                if case=='work-exists':f.work.mkdir()
                elif case=='out-exists':f.out.mkdir()
                elif case=='cache-equal':args['graphics_cache']=f.cpu
                elif case=='cache-nested':
                    nested=f.cpu/'graphics';nested.mkdir();args['graphics_cache']=nested
                elif case=='out-in-cache':args['out']=f.cpu/'new-output'
                elif case=='work-out-nested':args['out']=f.work/'evidence'
                elif case=='pe-symlink':
                    p=f.root/'alias.exe';p.symlink_to(f.pe);args['pe']=p
                elif case=='out-broken-symlink':f.out.symlink_to(f.root/'missing')
                elif case=='cache-symlink':
                    p=f.root/'cache-alias';p.symlink_to(f.cpu);args['cpu_cache']=p
                before=tree(f.root)
                with self.assertRaises((ValueError,OSError)):runner.plan(**args)
                self.assertEqual(tree(f.root),before);self.assertEqual(f.calls,[])

    def test_plan_profile_and_jobs_fail_before_worker_or_output(self):
        for case in ['bool-jobs','zero-jobs','old-schema','configured-targets','wrong-input-hash','oversize-profile']:
            with self.subTest(case=case),Fixture() as f:
                args=dict(f.args)
                if case=='bool-jobs':args['jobs']=True
                elif case=='zero-jobs':args['jobs']=0
                else:
                    profile=read(f.profile)
                    if case=='old-schema':profile['schema']=1
                    elif case=='configured-targets':profile['targets']=[0x1c49]
                    elif case=='wrong-input-hash':profile['pe_sha256']='0'*64
                    if case=='oversize-profile':f.profile.write_bytes(b' '*(65536+1))
                    else:write(f.profile,profile)
                before=tree(f.root)
                with self.assertRaises((ValueError,OSError)):runner.install(**args)
                self.assertEqual(tree(f.root),before);self.assertEqual(f.calls,[])


if __name__=='__main__':
    unittest.main(verbosity=2)
