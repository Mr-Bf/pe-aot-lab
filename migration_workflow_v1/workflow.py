"""Fresh attempts and inherited-lock workers over frozen migration backends.

No guest launch, network acquisition, guessed profile or partial-product reuse.
The producer and installer continue to perform their own authoritative checks.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import traceback

from .config import (ROOT, WorkflowError, canonical, digest, encode, decode, load_config,
                     read_json, read_bounded, require, select_profile)
from real_pe_inventory_v1.inventory import read_input, analyze_bytes
from window_switch_v1 import profile as profiles, provider as cpu
from portable_graphics_v1 import build as graphics
from migration_v7 import build as app
from migration_install_v3 import runner as installer
from migration_doctor_v2.doctor import host_python

READY = 'MIGRATION_READY_NOT_DECODED_NOT_BUILT'
STATUS = 'MIGRATION_APP_BUILT_VERIFIED_NOT_EXECUTED'
VERIFIED = 'MIGRATION_APP_VERIFIED_NOT_EXECUTED'
PROTOCOL = 'migration-workflow-v1'


def error_record(error, stage):
    return dict(stage=stage, code=getattr(error,'code','CHECK_FAILED'),
        field=getattr(error,'field',None), message=str(error),
        next_action=getattr(error,'next_action',None), error_type=type(error).__name__)


def _implementation():
    result=installer._implementation()
    for name in ('__init__.py','config.py','workflow.py','offline.py','__main__.py'):
        path=Path(__file__).parent/name
        result[str(path.relative_to(ROOT))]=digest(read_input(path))
    return result


def _paths(config, out):
    out=canonical(out)
    app.lift.path(out,exists=False)
    require(not out.exists(), 'OUTPUT_EXISTS', '目标workspace已存在；使用resume或选择新目录', 'out')
    require(out.parent.is_dir(), 'OUTPUT_PARENT_MISSING', 'workspace父目录必须存在', 'out')
    value=config['value']; inputs=[Path(config['path']),Path(value['pe'])]
    if value['profile']: inputs.append(Path(value['profile']))
    dependencies=[Path(v) for k,v in value['build'].items() if k not in ('mode','jobs')]
    for p in inputs+dependencies:
        require(not p.is_relative_to(out) and not out.is_relative_to(p), 'PATH_OVERLAP', '输出不能包含或位于输入/依赖路径内部: '+str(p))
    require(not ROOT.is_relative_to(out), 'PATH_OVERLAP', '输出不能覆盖源码根目录')
    return str(out)


def _backend_check(value, out):
    backend=value['build']; out=Path(out)
    if backend['mode']=='providers':
        app.lift.path(out,exists=False)
        app.lift.path(backend['cpu_prefix']);app.lift.path(backend['graphics_prefix'])
        cpu_record,_=cpu.paths_for(backend['cpu_prefix'])
        parent=canonical(cpu_record['provider'])
        require(not out.is_relative_to(parent) and not parent.is_relative_to(out),
                'PATH_OVERLAP','输出不能位于CPU overlay依赖的父provider内部或覆盖它')
        gpu=graphics.paths_for(backend['graphics_prefix'])
        return dict(mode='providers', cpu_manifest_sha256=installer._sha(Path(backend['cpu_prefix'])/'provider.json'),
            parent_cpu_prefix=str(parent),parent_cpu_manifest_sha256=cpu_record['provider_sha256'], graphics_manifest_sha256=gpu['provider_sha256'],
            apple=installer._apple_preflight())
    roots=[out/'offline-work',out/'offline-install',Path(backend['cpu_cache']),Path(backend['graphics_cache'])]
    for index,left in enumerate(roots):
        for right in roots[index+1:]:
            require(not left.is_relative_to(right) and not right.is_relative_to(left),
                    'PATH_OVERLAP','offline cache/work/evidence路径必须互相分离')
    return dict(mode='offline', caches=installer._caches(Path(backend['cpu_cache']),Path(backend['graphics_cache'])),
        apple=installer._apple_preflight(), disk=installer._disk_budget(out/'offline-work',out/'offline-install'))


def check(config_path, out):
    checks=[]; values={}
    def run(name, function, dependencies=()):
        missing=[d for d in dependencies if d not in values]
        if missing:
            checks.append(dict(id=name,status='SKIPPED',blocked_by=missing)); return
        try:
            result=function(); values[name]=result
            checks.append(dict(id=name,status='PASS'))
        except (ValueError,OSError,KeyError) as error:
            checks.append(dict(id=name,status='FAIL',**error_record(error,name)))
    run('config',lambda:load_config(config_path))
    run('output',lambda:_paths(values['config'],out),('config',))
    run('host',host_python)
    run('pe',lambda:read_input(Path(values['config']['value']['pe'])),('config',))
    if 'pe' in values:
        inv=analyze_bytes(values['pe'])
        values['inventory']=dict(status=inv['status'],sha256=inv['sha256'],bytes=inv['bytes'],
            headers=inv.get('headers'),findings=inv['findings'],
            declared_directories=[dict(index=d['index'],name=d['name'],address=d['address'],size=d['size'],parse_status=d['parse_status']) for d in inv.get('directories',[]) if d['address'] or d['size']],
            import_descriptors=len(inv.get('imports',[])),import_symbols=sum(len(d.get('symbols',[])) for d in inv.get('imports',[])))
    run('profile',lambda:select_profile(values['config'],values['pe']),('config','pe'))
    def admit():
        raw=read_bounded(Path(values['profile']['path']),65536,'PROFILE_TOO_LARGE')
        value=decode(raw)
        result=profiles.analyze(values['pe'],value)
        require(result['status']=='ELIGIBLE_FOR_BUILD_NOT_DECODED','INPUT_NOT_ADMITTED',
            result.get('error','原backend拒绝输入'),'profile','按原始profile-or-loader错误修复；不绕过准入')
        return dict(pe_sha256=digest(values['pe']),profile_sha256=digest(raw),
            canonical_profile_sha256=digest(encode(value)),profile=value,analysis=result)
    run('admission',admit,('profile','pe'))
    run('backend',lambda:_backend_check(values['config']['value'],values['output']),('config','output','host'))
    run('implementation',_implementation)
    ready=all(c['status']=='PASS' for c in checks)
    report=dict(schema=1,protocol=PROTOCOL,status=READY if ready else 'MIGRATION_BLOCKED',checks=checks,
        config=values.get('config'),out=values.get('output'),inventory=values.get('inventory'),
        selected_profile=values.get('profile'),inputs=values.get('admission'),backend=values.get('backend'),
        implementation=values.get('implementation'),app_executions=0,guest_executions=0,
        scope='Point-in-time checks only; no instruction lift, App build or run. Missing recipe is not proof that every property of a PE is unsupported.')
    return report


def _write(path,value):
    installer._durable(Path(path),value)


def _attempts(out):
    directory=Path(out)/'attempts'; result=[]
    for p in sorted(directory.iterdir()):
        require(p.is_dir() and not p.is_symlink() and re.fullmatch(r'attempt-[0-9]{4}',p.name),
                'UNKNOWN_ATTEMPT','workspace中存在未知attempt条目')
        result.append(p)
    require([p.name for p in result]==['attempt-%04d'%i for i in range(1,len(result)+1)],
            'ATTEMPT_GAP','attempt序列缺失或改名')
    return result


def _load_workspace(out):
    out=canonical(out); record=read_json(out/'workspace.json')
    require(record.get('schema')==1 and record.get('protocol')==PROTOCOL and record.get('out')==str(out),
            'WORKSPACE_CONTRACT_CHANGED','workspace版本或原路径不匹配')
    return out,record


def _revalidate(out,record,fd):
    require(installer._lock_identity(fd,out)==record['lock_identity'],'LOCK_CHANGED','workspace锁文件已被替换')
    require(load_config(record['config']['path'])==record['config'],'RESUME_IDENTITY_CHANGED','原始配置或解析路径已变化')
    value=record['config']['value']
    for path,expected in ((value['pe'],record['inputs']['pe_sha256']),
                          (record['selected_profile']['path'],record['inputs']['profile_sha256']),
                          (out/'inputs/program.exe',record['inputs']['pe_sha256']),
                          (out/'inputs/profile.json',record['inputs']['canonical_profile_sha256'])):
        require(digest(read_input(Path(path)))==expected,'RESUME_IDENTITY_CHANGED','输入身份已变化: '+str(path))
    require(_implementation()==record['implementation'],'RESUME_IDENTITY_CHANGED','构建实现已变化，请使用新workspace')
    if value['build']['mode']=='providers':
        require(_backend_check(value,out)==record['backend'],'RESUME_IDENTITY_CHANGED','provider/SDK/工具身份已变化')
    else:
        from .offline import validate_existing
        validate_existing(record)
    for attempt in _attempts(out):
        job=read_json(attempt/'job.json')
        require(job==dict(protocol=PROTOCOL,out=str(out),attempt=str(attempt),workspace_sha256=installer._sha(out/'workspace.json')),
                'ATTEMPT_IDENTITY_CHANGED','attempt不能来自其他workspace')
        seen=False; registered=[]; spawn_failed=False
        for name in ('process.json','launched.json'):
            p=attempt/name
            if not p.exists():continue
            item=read_json(p);seen=True
            require(item['job_sha256']==installer._sha(attempt/'job.json'),'ATTEMPT_IDENTITY_CHANGED','worker绑定的job变化')
            if name=='process.json' and 'spawn_error' in item:
                require(type(item['spawn_error']) is str and item.get('pid') is None and item.get('pgid') is None and
                        not any((attempt/n).exists() for n in ('launched.json','worker-result.json','product','exit.json')),
                        'WORKER_REGISTRATION_CHANGED','spawn失败记录与实际产物/注册冲突')
                spawn_failed=True
                continue
            require(type(item.get('pid')) is int and item['pid']>1 and item['pid']==item.get('pgid'),
                    'WORKER_REGISTRATION_CHANGED','worker PID/PGID登记缺失或不一致')
            registered.append(item['pid'])
            require(installer._group_state(item['pgid'])=='ABSENT','WORKER_ACTIVE_OR_UNKNOWN',
                '旧worker进程组仍存在或无法观察；不能重复构建')
        require(seen,'UNREGISTERED_ATTEMPT','缺少worker注册/启动记录，不能自动重试未知进程状态')
        require(not registered or (not spawn_failed and len(set(registered))==1),
                'WORKER_REGISTRATION_CHANGED','父子worker登记不一致')
        require(not (attempt/'worker-result.json').exists() or (attempt/'launched.json').exists(),
                'WORKER_REGISTRATION_CHANGED','worker结果缺少先行注册')


def _dispatch(job, record):
    out=Path(record['out']); value=record['config']['value']; backend=value['build']; attempt=Path(job['attempt'])
    if backend['mode']=='providers':
        returned=app.build(pe=str(out/'inputs/program.exe'),profile=read_json(out/'inputs/profile.json'),
            identifier=value['identifier'],cpu_prefix=backend['cpu_prefix'],backend_prefix=backend['graphics_prefix'],out=str(attempt/'product'))
        return dict(backend=returned,product=str(attempt/'product'),backend_ok=returned.get('status')==app.STATUS)
    initial=out/'offline-install'
    if not initial.exists():
        returned=installer.install(cpu_cache=backend['cpu_cache'],graphics_cache=backend['graphics_cache'],
            pe=str(out/'inputs/program.exe'),profile=str(out/'inputs/profile.json'),identifier=value['identifier'],
            work_root=str(out/'offline-work'),out=str(initial),jobs=backend['jobs'])
        session=initial
    else:
        session=attempt/'offline-resume'
        returned=installer.resume(installation=str(initial),out=str(session))
    return dict(backend=returned,product=returned.get('product'),backend_ok=returned.get('status')==installer.STATUS,
                installation=str(initial),session=str(session))


def _verify_product(product,record):
    product=canonical(product);out=Path(record['out'])
    require(product.is_relative_to(out),'PRODUCT_OUTSIDE_WORKSPACE','产物必须属于该workspace')
    returned=app.verify(product)
    raw=read_json(product/'result.json')
    require(raw['input_sha256']==record['inputs']['pe_sha256'] and
            raw['profile_sha256']==record['inputs']['canonical_profile_sha256'] and
            raw['spec']['identifier']==record['config']['value']['identifier'],
            'PRODUCT_INPUT_MISMATCH','产物与本任务PE/profile/identifier不匹配')
    if record['config']['value']['build']['mode']=='providers':
        require(raw['cpu_provider_sha256']==record['backend']['cpu_manifest_sha256'] and
                raw['graphics_provider_sha256']==record['backend']['graphics_manifest_sha256'],
                'PRODUCT_PROVIDER_MISMATCH','产物provider不匹配')
    else:
        from .offline import validate_existing
        accepted=validate_existing(record)
        require(accepted and accepted['complete'] is True and accepted['product']==str(product) and
                raw['cpu_provider_sha256']==accepted['cpu_provider_sha256'] and
                raw['graphics_provider_sha256']==accepted['graphics_provider_sha256'],
                'PRODUCT_PROVIDER_MISMATCH','产物不匹配离线安装实际接受的App/provider阶段')
    return returned


def worker(job_path,lock_fd):
    job_path=canonical(job_path);job=read_json(job_path);out,record=_load_workspace(job['out'])
    require(job.get('protocol')==PROTOCOL and job['workspace_sha256']==installer._sha(out/'workspace.json'),
            'WORKER_CONTRACT_CHANGED','worker job与workspace不匹配')
    require(job_path==Path(job['attempt'])/'job.json' and Path(job['attempt']).parent==out/'attempts',
            'WORKER_PATH_CHANGED','worker attempt位置不匹配')
    require(installer._lock_identity(lock_fd,out)==record['lock_identity'],'LOCK_CHANGED','继承锁身份不匹配')
    fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    require(os.getpid()==os.getpgrp(),'WORKER_GROUP_INVALID','worker需要独立进程组')
    attempt=Path(job['attempt'])
    _write(attempt/'launched.json',dict(pid=os.getpid(),pgid=os.getpgrp(),job_sha256=installer._sha(job_path)))
    try:
        result=_dispatch(job,record)
        if result['backend_ok']:
            result['verification']=_verify_product(result['product'],record)
        _write(attempt/'worker-result.json',dict(status='WORKER_RETURNED',job_sha256=installer._sha(job_path),returned=result))
        return 0
    except BaseException as error:
        _write(attempt/'worker-result.json',dict(status='WORKER_FAILED',job_sha256=installer._sha(job_path),
            error=error_record(error,'backend'),traceback=traceback.format_exc()))
        return 1


def _run_worker(job_path,fd):
    job_path=Path(job_path);attempt=job_path.parent
    env=dict(os.environ);env.pop('PYTHONPATH',None);env.pop('PYTHONHOME',None)
    env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    command=[str(Path(sys.executable).resolve()),'-B','-m','migration_workflow_v1','_worker',str(job_path),'--lock-fd',str(fd)]
    with (attempt/'stdout').open('xb') as stdout,(attempt/'stderr').open('xb') as stderr:
        try:
            child=subprocess.Popen(command,cwd=ROOT,env=env,stdout=stdout,stderr=stderr,
                start_new_session=True,pass_fds=(fd,))
        except OSError as error:
            _write(attempt/'process.json',dict(job_sha256=installer._sha(job_path),pid=None,pgid=None,spawn_error=str(error)))
            return dict(returncode=None,group_state='NOT_SPAWNED')
        _write(attempt/'process.json',dict(job_sha256=installer._sha(job_path),pid=child.pid,pgid=child.pid,argv=command))
        code=child.wait()
    result=dict(returncode=code,pid=child.pid,pgid=child.pid,group_state=installer._group_state(child.pid))
    _write(attempt/'exit.json',result)
    return result


def _worker_result(attempt,record):
    job_path=attempt/'job.json';job=read_json(job_path)
    require(job==dict(protocol=PROTOCOL,out=record['out'],attempt=str(attempt),
                     workspace_sha256=installer._sha(Path(record['out'])/'workspace.json')),
            'ATTEMPT_IDENTITY_CHANGED','worker job与本attempt不匹配')
    launched=read_json(attempt/'launched.json');process=read_json(attempt/'process.json')
    require(type(launched.get('pid')) is int and launched['pid']>1 and
            launched['pid']==launched.get('pgid')==process.get('pid')==process.get('pgid') and
            launched.get('job_sha256')==process.get('job_sha256')==installer._sha(job_path),
            'WORKER_REGISTRATION_CHANGED','worker启动/注册记录不匹配')
    result=read_json(attempt/'worker-result.json')
    require(result['job_sha256']==installer._sha(job_path),'WORKER_RESULT_CHANGED','worker结果job身份变化')
    if result.get('status')=='WORKER_RETURNED' and result['returned'].get('backend_ok'):
        returned=result['returned'];mode=record['config']['value']['build']['mode']
        require(returned['backend_ok'] is True and returned['backend']['status']==(app.STATUS if mode=='providers' else installer.STATUS),
                'BACKEND_STATUS_CHANGED','backend结果不是该路线成功状态')
        if mode=='providers':
            require(returned['product']==str(attempt/'product'),'PRODUCT_ATTEMPT_MISMATCH','产物不属于该attempt')
        else:
            require(returned['installation']==str(Path(record['out'])/'offline-install') and
                    returned['session'] in (returned['installation'],str(attempt/'offline-resume')),
                    'PRODUCT_ATTEMPT_MISMATCH','离线installation/session不匹配本attempt')
    return result,process


def _finish_attempt(attempt,record,exit_record,*,recover_unobserved=False):
    out=Path(record['out']);worker_path=attempt/'worker-result.json'
    if exit_record.get('group_state')!='ABSENT' or not worker_path.exists():
        return dict(status='MIGRATION_BUILD_FAILED',stage='worker',attempt=str(attempt),out=str(out),
            code='WORKER_NOT_ACCEPTED',process=exit_record,app_executions=0,guest_executions=0)
    worker_result,process=_worker_result(attempt,record)
    if recover_unobserved:
        require(not (attempt/'exit.json').exists() and exit_record.get('returncode') is None,
                'EXIT_OBSERVATION_CONFLICT','不能覆盖实际退出记录或伪造退出0')
    else:
        observed=read_json(attempt/'exit.json')
        require(observed==exit_record and observed.get('pid')==observed.get('pgid')==process['pid'],
                'EXIT_OBSERVATION_CHANGED','实际退出记录与worker身份不匹配')
    success=(recover_unobserved or exit_record.get('returncode')==0) and worker_result['status']=='WORKER_RETURNED' and worker_result['returned']['backend_ok']
    result=dict(status=STATUS if success else 'MIGRATION_BUILD_FAILED',stage='complete' if success else 'backend',
        attempt=str(attempt),out=str(out),worker_result_sha256=installer._sha(worker_path),
        app_executions=0,guest_executions=0)
    result.update(worker_exit_status_observed=not recover_unobserved,
                  worker_exit=exit_record,
                  process_sha256=installer._sha(attempt/'process.json'),
                  launched_sha256=installer._sha(attempt/'launched.json'))
    if success:
        returned=worker_result['returned'];verified=_verify_product(returned['product'],record)
        result.update(product=returned['product'],app=verified['app'],verification=verified,
                      product_receipt_sha256=installer._sha(Path(returned['product'])/'result.json'))
    else:
        result['failure']=worker_result.get('error',worker_result.get('returned',{}).get('backend'))
    return result


def _accepted_result(attempt,record):
    result=read_json(attempt/'result.json')
    require(result.get('status')==STATUS and result.get('out')==record['out'] and result.get('attempt')==str(attempt),
            'ACCEPTED_RESULT_CHANGED','成功结果的workspace/attempt绑定变化')
    worker,process=_worker_result(attempt,record)
    require(worker.get('status')=='WORKER_RETURNED' and worker['returned']['backend_ok'] is True and
            result['product']==worker['returned']['product'] and
            result['worker_result_sha256']==installer._sha(attempt/'worker-result.json') and
            result['process_sha256']==installer._sha(attempt/'process.json') and
            result['launched_sha256']==installer._sha(attempt/'launched.json') and
            result['product_receipt_sha256']==installer._sha(Path(result['product'])/'result.json'),
            'ACCEPTED_RESULT_CHANGED','成功结果、worker或产物收据身份变化')
    if result['worker_exit_status_observed'] is True:
        observed=read_json(attempt/'exit.json')
        require(observed==result['worker_exit'] and observed['returncode']==0 and observed['group_state']=='ABSENT' and
                observed['pid']==observed['pgid']==process['pid'],
                'EXIT_OBSERVATION_CHANGED','成功结果没有匹配的退出0观测')
    else:
        require(result['worker_exit_status_observed'] is False and not (attempt/'exit.json').exists() and
                result['worker_exit']==dict(returncode=None,group_state='ABSENT'),
                'EXIT_OBSERVATION_CHANGED','未观测退出状态的恢复标记不匹配')
    verified=_verify_product(result['product'],record)
    require(result['app']==verified['app'],'ACCEPTED_RESULT_CHANGED','App路径绑定变化')
    return dict(result,verification=verified)


def _execute(out,record,fd):
    previous=_attempts(out)
    if previous:
        last=previous[-1]
        if (last/'result.json').exists() and read_json(last/'result.json').get('status')==STATUS:
            result=_accepted_result(last,record)
            _revalidate(out,record,fd)
            return dict(result,reused_verified_product=True)
        # A coordinator can disappear after its worker finishes. Adopt only a
        # registered, absent process group and an independently verified result.
        if not (last/'result.json').exists() and (last/'worker-result.json').exists() and (last/'process.json').exists():
            returned=read_json(last/'worker-result.json')
            if returned.get('status')=='WORKER_RETURNED' and returned['returned']['backend_ok']:
                observed=read_json(last/'exit.json') if (last/'exit.json').exists() else None
                if observed is None or (observed.get('returncode')==0 and observed.get('group_state')=='ABSENT'):
                    result=_finish_attempt(last,record,observed or dict(returncode=None,group_state='ABSENT'),recover_unobserved=observed is None)
                    _revalidate(out,record,fd)
                    _write(last/'result.json',result)
                    return dict(result,adopted_completed_worker=True)
    require(len(previous)<9999,'ATTEMPT_LIMIT','超过attempt限额')
    attempt=out/'attempts'/('attempt-%04d'%(len(previous)+1));attempt.mkdir()
    job=dict(protocol=PROTOCOL,out=str(out),attempt=str(attempt),workspace_sha256=installer._sha(out/'workspace.json'))
    _write(attempt/'job.json',job)
    exit_record=_run_worker(attempt/'job.json',fd)
    if exit_record.get('group_state')=='ABSENT':
        try:
            _revalidate(out,record,fd)
        except (ValueError,OSError,KeyError) as error:
            result=dict(status='MIGRATION_BUILD_FAILED',stage='post-build-identity',attempt=str(attempt),out=str(out),
                        failure=error_record(error,'post-build-identity'),app_executions=0,guest_executions=0)
            _write(attempt/'result.json',result)
            return result
    result=_finish_attempt(attempt,record,exit_record)
    _write(attempt/'result.json',result)
    return result


def build(config_path,out):
    proposed=check(config_path,out)
    if proposed['status']!=READY:return proposed
    out=canonical(out);fd=installer._lock(out,create=True)
    try:
        (out/'inputs').mkdir();(out/'attempts').mkdir()
        pe=read_input(Path(proposed['config']['value']['pe']))
        require(digest(pe)==proposed['inputs']['pe_sha256'],'INPUT_CHANGED','PE在检查后变化')
        (out/'inputs/program.exe').write_bytes(pe)
        (out/'inputs/profile.json').write_bytes(encode(proposed['inputs']['profile']))
        record=dict(proposed,protocol=PROTOCOL,schema=1,status='MIGRATION_WORKSPACE_CREATED',
            lock_identity=installer._lock_identity(fd,out))
        _write(out/'workspace.json',record)
        _revalidate(out,record,fd)
        return _execute(out,record,fd)
    finally:
        os.close(fd)


def resume(out):
    out,record=_load_workspace(out);fd=installer._lock(out)
    try:
        _revalidate(out,record,fd)
        return _execute(out,record,fd)
    finally:
        os.close(fd)


def verify(out):
    out,record=_load_workspace(out);fd=installer._lock(out)
    try:
        _revalidate(out,record,fd)
        attempts=_attempts(out)
        require(attempts and (attempts[-1]/'result.json').is_file(),'NO_COMPLETED_PRODUCT','没有已接受的产物')
        result=_accepted_result(attempts[-1],record)
        verified=result['verification']
        _revalidate(out,record,fd)
        return dict(status=VERIFIED,out=str(out),product=result['product'],app=verified['app'],
                    verification=verified,app_executions=0,guest_executions=0)
    finally:
        os.close(fd)


def status(out):
    out,record=_load_workspace(out)
    attempts=_attempts(out)
    latest=read_json(attempts[-1]/'result.json') if attempts and (attempts[-1]/'result.json').exists() else None
    return dict(status='MIGRATION_STATUS_OBSERVATION_NOT_VERIFIED',out=str(out),route=record['config']['value']['build']['mode'],
        attempts=len(attempts),latest_recorded_result=latest,
        next_action='运行verify核对成功产物，或resume重验后恢复；状态记录不能代替验证',app_executions=0,guest_executions=0)
