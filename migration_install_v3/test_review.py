"""Read-only verifier counterexamples; synthetic files, no builds/processes/UI.

Provider/product payload validators are stubbed only in journal tests. Their
actual source/patch/ABI checks are separately exercised by the real-file reader.
"""
import copy
import hashlib
import json
import shutil
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock

from . import review as r


def write(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Fixture:
    """Two synthetic sessions: App-build SIGTERM, then exact three-provider reuse."""
    def __init__(self, root):
        self.root=root
        self.initial=root/'full';self.resumed=root/'resume';self.work=root/'work'
        self.initial.mkdir();self.resumed.mkdir();self.work.mkdir()
        self.lock=self.work/'.install.lock';self.lock.write_bytes(b'')
        info=self.lock.stat();self.lock_identity=dict(path=str(self.lock),device=info.st_dev,inode=info.st_ino)
        write(self.initial/'work-identity.json',dict(schema=1,work_root=str(self.work),lock_identity=self.lock_identity))
        write(self.initial/'inputs/profile.json',{'schema':2})
        (self.initial/'inputs/input.exe').write_bytes(b'synthetic input; not a PE')
        self.plan=dict(paths=dict(work_root=str(self.work),out=str(self.initial),cpu_cache=str(root/'cpu-cache'),
                                  graphics_cache=str(root/'graphics-cache'),pe=str(root/'source.exe'),profile=str(root/'source.json')),
                       jobs=2,identifier='org.peaotlab.synthetic.install',apple=dict(python=str(Path(sys.executable).resolve())))
        self.plan.update(schema=3,status='OFFLINE_V7_INSTALL_PLAN_READY_NOT_DECODED_NOT_BUILT',installer='migration_install_v3',product_profile='window-lookup-v7',capability='window-rel32-v1',stages=list(r.STAGES),runtime_lookup=dict(contract=r.lookup_review.CONTRACT,lookup_sha256=r.lookup_review.PINS[r.lookup_review.LOOKUP],templates=dict(r.lookup_review.PINS)))
        write(self.initial/'plan.json',self.plan)
        self.plan_sha=sha(self.initial/'plan.json')
        self.accepted={};self.bindings={};self.history=[];self.attempts={}
        self.session(self.initial,1,[])
        self.attempt(self.initial,'cpu-build',1)
        self.attempt(self.initial,'switch-build',1)
        self.attempt(self.initial,'graphics-build',1)
        self.attempt(self.initial,'app-build',1,failed=True)
        self.result(self.initial,failed=True,reused=[])
        self.session(self.resumed,2,['cpu-build','switch-build','graphics-build'])
        self.attempt(self.resumed,'app-build',2)
        self.attempt(self.resumed,'app-verify',1)
        self.result(self.resumed,failed=False,reused=['cpu-build','switch-build','graphics-build'])

    def session(self, directory, number, reused):
        record=dict(schema=2,installer='migration_install_v3',sequence=number,installation=str(self.initial),directory=str(directory),
                    plan_sha256=self.plan_sha,invocation='install' if number==1 else 'resume')
        write(directory/'session.json',record)
        write(self.initial/'sessions'/f'{number:04d}.json',record)
        observations=[dict(attempt=str(attempt),job_sha256=sha(attempt/'job.json'),pid=launched['pid'],
                           pgid=launched['pgid'],observed_state='ABSENT',observed_at='synthetic')
                      for attempt,launched in self.history]
        write(directory/'historical-groups.json',dict(schema=1,installation=str(self.initial),session=str(directory),observations=observations))
        write(directory/'revalidated.json',dict(completed_stages=reused,dependencies=self.bindings))
        (directory/'attempts').mkdir()

    def attempt(self, session, stage, number, failed=False):
        directory=session/'attempts'/f'{stage}-{number:04d}';directory.mkdir()
        prefix=self.work/'attempts'/directory.name
        if stage=='cpu-build':
            args=dict(prefix=str(prefix),cache=self.plan['paths']['cpu_cache'],out=str(directory/'builder'),jobs=2)
        elif stage=='switch-build':
            args=dict(provider=self.accepted['cpu-build']['arguments']['prefix'],prefix=str(prefix),out=str(directory/'builder'),jobs=2)
        elif stage=='graphics-build':
            args=dict(prefix=str(prefix),cache_path=self.plan['paths']['graphics_cache'],out=str(directory/'builder'),jobs=2)
        elif stage=='app-build':
            args=dict(pe=str(self.initial/'inputs/input.exe'),profile={'schema':2},identifier=self.plan['identifier'],
                      cpu_prefix=self.accepted['switch-build']['arguments']['prefix'],
                      backend_prefix=self.accepted['graphics-build']['arguments']['prefix'],out=str(prefix))
        else:args=dict(out=self.accepted['app-build']['arguments']['out'])
        receipt=None if stage=='app-verify' else str(Path(args['out'])/'result.json')
        job=dict(schema=2,installer='migration_install_v3',product_profile='window-lookup-v7',stage=stage,arguments=args,expected_status=r.EXPECTED[stage],plan_sha256=self.plan_sha,
                 builder_receipt=receipt,worker_result=str(directory/'worker-result.json'),
                 worker_exit=str(directory/'worker-exit.json'),launched=str(directory/'launched.json'),lock_identity=self.lock_identity)
        write(directory/'job.json',job)
        pid=4000+len(self.history)
        launched=dict(protocol='REGISTER_BEFORE_BUILDER_V1',stage=stage,pid=pid,pgid=pid,job_sha256=sha(directory/'job.json'),
                      lock_identity=self.lock_identity,process_identity=dict(pid=pid,pgid=pid,
                      argv=[self.plan['apple']['python'],'-B','-m','migration_install_v3','_worker',str(directory/'job.json')]))
        write(directory/'launched.json',launched)
        for stream in ('stdout','stderr'):(directory/('worker.'+stream)).write_bytes(b'')
        ended=dict(returncode=-15 if failed else 0,pid=pid,pgid=pid,group_state='PRESENT' if failed else 'ABSENT',
                   stdout_sha256=sha(directory/'worker.stdout'),stderr_sha256=sha(directory/'worker.stderr'))
        write(directory/'worker-exit.json',ended)
        self.history.append((directory,launched));self.attempts[(stage,number)]=directory
        if failed:return
        returned=dict(status=r.EXPECTED[stage])
        if stage=='app-verify':returned.update(app=self.product_check()['app'],files=3,guest_executions=0,gpu_executions=0)
        if receipt:write(Path(receipt),returned)
        write(directory/'worker-result.json',dict(status='WORKER_RETURNED',stage=stage,returned=returned,
                                                  job_sha256=sha(directory/'job.json')))
        marker=dict(schema=1,stage=stage,arguments=args,dependencies=copy.deepcopy(self.bindings),returned=returned,
                    job_sha256=sha(directory/'job.json'),worker_result_sha256=sha(directory/'worker-result.json'),
                    worker_exit_sha256=sha(directory/'worker-exit.json'),launched_sha256=sha(directory/'launched.json'),
                    builder_receipt_sha256=sha(Path(receipt)) if receipt else None)
        write(directory/'accepted.json',marker)
        self.accepted[stage]=dict(directory=str(directory),arguments=args,returned=returned)
        if stage in ('cpu-build','switch-build','graphics-build'):
            write(prefix/'provider.json',returned);self.bindings[str(prefix/'provider.json')]=sha(prefix/'provider.json')

    def product_check(self):
        product=self.work/'attempts/app-build-0002'
        return dict(product=str(product),product_sha256=sha(product/'result.json') if (product/'result.json').exists() else '',
                    app=str(product/'PE AOT Converted.app'),files=3)

    def result(self, directory, failed, reused):
        result=dict(schema=3,installer='migration_install_v3',product_profile='window-lookup-v7',runtime_lookup=self.plan['runtime_lookup'],installation=str(self.initial),session=str(directory),plan_sha256=self.plan_sha,
                    completed_stages=list(self.accepted),guest_executions=0,gpu_executions=0,app_executions=0,automatic_retry=False)
        if failed:result.update(status='INSTALL_FAILED',stage='app-build')
        else:
            product=self.product_check()
            result.update(status='OFFLINE_V7_APP_BUILT_VERIFIED_NOT_EXECUTED',stage='complete',reused_stages=reused,
                          dependencies=self.bindings,accepted_attempts={k:v['directory'] for k,v in self.accepted.items()},
                          product=product['product'],product_sha256=product['product_sha256'],app=product['app'])
        write(directory/'result.json',result)

    def environment(self,*args):
        return ({name:Path(value) for name,value in self.plan['paths'].items()},
                self.initial/'inputs/input.exe',self.initial/'inputs/profile.json')

    def create_probe(self):
        directory=self.root/'probe';directory.mkdir()
        source=r.ROOT/'migration_install_v3/recovery_probe.py'
        target=directory/'sources/migration_install_v3/recovery_probe.py';target.parent.mkdir(parents=True)
        shutil.copyfile(source,target)
        argv=[self.plan['apple']['python'],'-B','-m','migration_install_v3','install']
        for name in ('cpu_cache','graphics_cache','pe','profile','identifier','work_root'):
            argv.extend(['--'+name.replace('_','-'),self.plan['identifier'] if name=='identifier' else self.plan['paths'][name]])
        argv.extend(['--out',str(self.initial),'--jobs','2'])
        write(directory/'started.json',dict(argv=argv,cwd=str(r.ROOT),source_sha256=sha(source)))
        write(directory/'coordinator.json',dict(pid=3900,pgid=3900,argv=argv))
        attempt=self.attempts[('app-build',1)];job=json.loads((attempt/'job.json').read_text())
        launched=json.loads((attempt/'launched.json').read_text());pid=launched['pid']
        write(directory/'controlled-signal.json',dict(stage='app-build',pid=pid,pgid=pid,coordinator_pid=3900,
            job=str(attempt/'job.json'),job_sha256=sha(attempt/'job.json'),prefix=job['arguments']['out'],signal=15,
            members=[dict(pid=pid,parent_pid=3900,pgid=pid,command='python -B -m migration_install_v3 _worker '+str(attempt/'job.json')),
                     dict(pid=pid+100,parent_pid=pid,pgid=pid,command='clang -c '+job['arguments']['out']+'/native/example.c')]))
        controlled=json.loads((directory/'controlled-signal.json').read_text())
        members=controlled['members']
        raw=dict(command=['/bin/ps','-ww','-p',','.join(str(row['pid']) for row in members),'-o','pid=,ppid=,pgid=,command='],
                 returncode=0,stderr='',stdout=''.join('%d %d %d %s\n'%(row['pid'],row['parent_pid'],row['pgid'],row['command']) for row in members))
        write(directory/'processes-before-signal.json',raw)
        controlled['process_observation_sha256']=sha(directory/'processes-before-signal.json')
        write(directory/'controlled-signal.json',controlled)
        write(directory/'signal-sent.json',dict(status='OS_SIGNAL_CALL_SUCCEEDED',pid=pid,pgid=pid,signal=15))
        write(directory/'result.json',dict(status='CONTROLLED_REAL_APP_BUILD_INTERRUPTION_OBSERVED_NOT_RESUMED',
            coordinator_returncode=1,installation=str(self.initial),worker_pgid=pid,final_group_state='ABSENT',
            completed_stages=['cpu-build','switch-build','graphics-build'],failed_install_status='INSTALL_FAILED',
            failed_install_result_sha256=sha(self.initial/'result.json'),native_builds_invoked=True,app_executions=0,gpu_executions=0))
        live=dict(status='LIVE_INSTALL_STAGE_WORKER',stage='app-build',pid=pid,attempt=str(attempt))
        failed=json.loads((self.initial/'result.json').read_text())
        (directory/'install.stdout').write_text(json.dumps(live)+'\n'+json.dumps(failed)+'\n')
        (directory/'install.stderr').write_bytes(b'')
        return directory

    def run(self, probe=None):
        with mock.patch.object(r,'verify_environment',side_effect=self.environment), \
             mock.patch.object(r,'verify_cpu',return_value={'synthetic':True}), \
             mock.patch.object(r,'verify_switch',return_value={'synthetic':True}), \
             mock.patch.object(r,'verify_graphics',return_value={'synthetic':True}), \
             mock.patch.object(r,'verify_product',return_value=self.product_check()), \
             mock.patch('subprocess.run',side_effect=AssertionError('read-only verifier cannot run a process')), \
             mock.patch('subprocess.Popen',side_effect=AssertionError('read-only verifier cannot spawn')), \
             mock.patch('os.killpg',side_effect=AssertionError('read-only verifier cannot signal/query live group')):
            return r.review(self.initial,self.resumed,self.root/'review.json',probe=probe)


class ReviewTests(unittest.TestCase):
    def fixture(self):
        temp=tempfile.TemporaryDirectory(prefix='install-review-');self.addCleanup(temp.cleanup)
        return Fixture(Path(temp.name).resolve())

    def test_reconstructs_sigterm_failure_then_only_exact_prior_stage_reuse(self):
        fixture=self.fixture();value=fixture.run()
        self.assertEqual(value['sessions'][1]['reused_stages'],['cpu-build','switch-build','graphics-build'])
        self.assertEqual(len(value['attempts']),6)
        self.assertEqual(value['attempts'][3]['signal'],15)
        self.assertFalse(value['attempts'][3]['accepted'])
        self.assertEqual(value['attempts'][4]['stage'],'app-build')
        self.assertEqual(value['native_builds'],0)

    def test_missing_or_live_historical_group_cannot_be_hidden_by_success(self):
        for mode in ['missing','live','wrong-pid','duplicate']:
            with self.subTest(mode=mode):
                fixture=self.fixture();p=fixture.resumed/'historical-groups.json';v=json.loads(p.read_text())
                if mode=='missing':v['observations'].pop()
                elif mode=='live':v['observations'][-1]['observed_state']='PRESENT'
                elif mode=='wrong-pid':v['observations'][-1]['pid']+=1
                else:v['observations'][-1]=copy.deepcopy(v['observations'][0])
                write(p,v)
                with self.assertRaises(ValueError):fixture.run()

    def test_worker_exit_cannot_be_blessed_by_a_coherent_success_marker(self):
        fixture=self.fixture();directory=fixture.attempts[('switch-build',1)]
        path=directory/'worker-exit.json';ended=json.loads(path.read_text());ended['group_state']='PRESENT';write(path,ended)
        path=directory/'accepted.json';value=json.loads(path.read_text());value['worker_exit_sha256']=sha(directory/'worker-exit.json');write(path,value)
        with self.assertRaisesRegex(ValueError,'normal owned worker'):fixture.run()

    def test_worker_python_symlink_resolves_to_planned_binary_but_other_file_is_refused(self):
        fixture=self.fixture();directory=fixture.attempts[('cpu-build',1)]
        alias=fixture.root/'python-alias';alias.symlink_to(fixture.plan['apple']['python'])
        value=json.loads((directory/'launched.json').read_text());value['process_identity']['argv'][0]=str(alias)
        write(directory/'launched.json',value)
        job=json.loads((directory/'job.json').read_text())
        r.verify_worker(r.Audit(),directory,job,expected_python=fixture.plan['apple']['python'])
        other=fixture.root/'different-python';other.write_bytes(b'not the planned interpreter')
        value['process_identity']['argv'][0]=str(other);write(directory/'launched.json',value)
        with self.assertRaisesRegex(ValueError,'Python identity'):
            r.verify_worker(r.Audit(),directory,job,expected_python=fixture.plan['apple']['python'])

    def test_allocated_arguments_and_returned_provider_cannot_select_other_cpu(self):
        fixture=self.fixture();directory=fixture.attempts[('switch-build',1)]
        job=json.loads((directory/'job.json').read_text());job['arguments']['provider']=str(fixture.root/'unrelated-provider')
        write(directory/'job.json',job)
        with self.assertRaisesRegex(ValueError,'allocation/parent/input'):fixture.run()

    def test_stale_or_swapped_installation_lock_inode_rejected(self):
        fixture=self.fixture();path=fixture.initial/'work-identity.json';value=json.loads(path.read_text())
        value['lock_identity']['inode']+=1;write(path,value)
        with self.assertRaisesRegex(ValueError,'lock path/device/inode'):fixture.run()

    def test_result_cannot_hide_or_change_reused_or_accepted_stages(self):
        for key,value in [('reused_stages',[]),('product_sha256','0'*64),('accepted_attempts',{}),('dependencies',{})]:
            with self.subTest(key=key):
                fixture=self.fixture();path=fixture.resumed/'result.json';result=json.loads(path.read_text());result[key]=value;write(path,result)
                with self.assertRaises(ValueError):fixture.run()

    def test_duplicate_json_and_mutated_read_closure_fail(self):
        with self.assertRaises(ValueError):r.decode(b'{"status":1,"status":2}')
        with self.assertRaises(ValueError):r.decode(b'{"value":NaN}')
        with tempfile.TemporaryDirectory() as name:
            p=Path(name)/'value';p.write_bytes(b'old');audit=r.Audit();audit.sha(p);p.write_bytes(b'new')
            with self.assertRaisesRegex(ValueError,'review input changed'):audit.finish()

    def test_control_json_symlinks_are_not_substitutes_for_real_receipts(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();write(root/'real.json',{'status':'synthetic'})
            (root/'linked.json').symlink_to(root/'real.json')
            with self.assertRaisesRegex(ValueError,'aliased JSON/control'):r.Audit().json(root/'linked.json')

    def test_controlled_signal_requires_terminal_worker_and_coordinator_side_evidence(self):
        fixture=self.fixture();probe=fixture.create_probe();value=fixture.run(probe=probe)
        self.assertEqual(value['controlled_interruption']['signal'],15)
        self.assertEqual(value['controlled_interruption']['actual_build_members'],2)
        for mode in ['intent-only','no-signal-receipt','wrong-parent','no-build-member','wrong-failed-hash','wrong-stdout']:
            with self.subTest(mode=mode):
                fixture=self.fixture();probe=fixture.create_probe()
                if mode=='intent-only':(probe/'result.json').unlink()
                elif mode=='no-signal-receipt':(probe/'signal-sent.json').unlink()
                elif mode=='wrong-parent':
                    v=json.loads((probe/'controlled-signal.json').read_text());v['members'][0]['parent_pid']+=1;write(probe/'controlled-signal.json',v)
                elif mode=='no-build-member':
                    v=json.loads((probe/'controlled-signal.json').read_text());v['members'].pop();write(probe/'controlled-signal.json',v)
                elif mode=='wrong-failed-hash':
                    v=json.loads((probe/'result.json').read_text());v['failed_install_result_sha256']='0'*64;write(probe/'result.json',v)
                else:(probe/'install.stdout').write_text('{}\n')
                with self.assertRaises((ValueError,FileNotFoundError)):fixture.run(probe=probe)

    def test_attach_and_old_worker_versions_are_refused(self):
        fixture=self.fixture();probe=fixture.create_probe()
        path=probe/'started.json';value=json.loads(path.read_text());value['status']='ATTACHING_NO_NEW_BUILDERS';write(path,value)
        with self.assertRaisesRegex(ValueError,'does not accept attach'):fixture.run(probe=probe)
        fixture=self.fixture();directory=fixture.attempts[('app-build',1)]
        value=json.loads((directory/'launched.json').read_text());value['process_identity']['argv'][3]='migration_install_v2'
        write(directory/'launched.json',value)
        with self.assertRaisesRegex(ValueError,'worker command identity'):fixture.run()

    def test_plan_version_and_lookup_contract_are_exact(self):
        fixture=self.fixture();r.plan_contract(fixture.plan)
        cases=[('schema',2),('schema',True),('installer','migration_install_v2'),
               ('product_profile','window-switch-v6'),('status','OFFLINE_V6_INSTALL_PLAN_READY_NOT_DECODED_NOT_BUILT'),
               ('runtime_lookup',{}),('capability','other')]
        for key,value in cases:
            plan=copy.deepcopy(fixture.plan);plan[key]=value
            with self.assertRaisesRegex(ValueError,'plan/lookup'):r.plan_contract(plan)
        for key in ('contract','lookup_sha256','templates'):
            plan=copy.deepcopy(fixture.plan);plan['runtime_lookup'][key]='wrong'
            with self.assertRaisesRegex(ValueError,'plan/lookup'):r.plan_contract(plan)

    def test_old_session_job_and_result_schema_are_refused(self):
        for kind in ('session','job','result'):
            fixture=self.fixture()
            if kind=='session':
                path=fixture.resumed/'session.json';value=json.loads(path.read_text());value['schema']=1
                write(path,value);write(fixture.initial/'sessions/0002.json',value)
            elif kind=='job':
                path=fixture.attempts[('app-build',1)]/'job.json';value=json.loads(path.read_text());value['schema']=1;write(path,value)
            else:
                path=fixture.resumed/'result.json';value=json.loads(path.read_text());value['schema']=2;write(path,value)
            with self.assertRaises(ValueError):fixture.run()

    def test_narrow_process_snapshot_rejects_missing_replaced_or_duplicate_pids(self):
        good=dict(command=['/bin/ps','-ww','-p','4003,4103','-o','pid=,ppid=,pgid=,command='],returncode=0,
                  stdout='4003 3900 4003 python worker\n4103 4003 4003 clang source\n',stderr='')
        self.assertEqual(len(r.process_observation(good,4003)),2)
        for key,value in [('returncode',1),('returncode',False),('stderr','warning'),
                          ('stdout','4003 3900 4003 python worker\n'),
                          ('stdout','4003 3900 4003 python worker\n4103 4003 9999 other\n'),
                          ('stdout','4003 3900 4003 python worker\n4003 3900 4003 duplicate\n')]:
            raw=copy.deepcopy(good);raw[key]=value
            with self.assertRaises(ValueError):r.process_observation(raw,4003)
        for selected in ('4003,4003','4003,4103,9999','0,4103','-1,4103'):
            raw=copy.deepcopy(good);raw['command'][3]=selected
            with self.assertRaises(ValueError):r.process_observation(raw,4003)

    def test_coherent_v6_product_is_rejected_before_payload_validation(self):
        with tempfile.TemporaryDirectory() as name:
            product=Path(name).resolve();old=dict(schema=1,profile='window-switch-v6',status='BUILT_PORTABLE_WINDOW_APP_NOT_EXECUTED')
            write(product/'result.json',old)
            with self.assertRaisesRegex(ValueError,'v7 product'):
                r.verify_product(r.Audit(),product,old,None,None,None,None,None)

    def test_patch_replay_requires_original_exact_context_and_hunk_counts(self):
        original={'file.cpp':b'one\ntwo\nthree\n'}
        patch=b'--- a/file.cpp\n+++ b/file.cpp\n@@ -1,3 +1,3 @@\n one\n-two\n+replacement\n three\n'
        self.assertEqual(r.replay_patch(original,patch)['file.cpp'],b'one\nreplacement\nthree\n')
        self.assertEqual(original['file.cpp'],b'one\ntwo\nthree\n')
        for bad in [patch.replace(b' two',b' wrong').replace(b'-two',b'-wrong'),
                    patch.replace(b'-1,3',b'-1,2'),patch.replace(b'a/file.cpp',b'a/absent.cpp')]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):r.replay_patch(original,bad)

    def test_actual_macho_symbol_reader_ignores_undefined_and_rejects_bounds(self):
        names=b'\0_export\0_undefined\0';symoff=56;stroff=symoff+32
        header=struct.pack('<8I',0xfeedfacf,0x100000c,0,1,1,24,0,0)
        command=struct.pack('<6I',2,24,symoff,2,stroff,len(names))
        defined=struct.pack('<IBBHQ',1,0xf,1,0,0)
        undefined=struct.pack('<IBBHQ',9,1,0,0,0)
        with tempfile.TemporaryDirectory() as name:
            path=Path(name)/'object.o';path.write_bytes(header+command+defined+undefined+names)
            self.assertEqual(r.exports(r.Audit(),path),['_export'])
            path.write_bytes(header+command+defined+undefined+names[:-1])
            with self.assertRaises(ValueError):r.exports(r.Audit(),path)


if __name__=='__main__':
    unittest.main()
