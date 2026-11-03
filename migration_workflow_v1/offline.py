"""Read-only revalidation of this workflow's original offline installation.

The installation's inherited flock and accepted-stage checks remain authoritative.
No plan(), install(), resume(), report creation, builder, or App is invoked here.
Call only outside an install/resume operation, while owning the workflow lock.
"""
import os
from pathlib import Path
import re

from migration_install_v3 import runner as installer
from .config import canonical, require


def validate_existing(record):
    """Return bound accepted stages, or None before the first installation.

An accepted app-build can exist before app-verify has completed. The returned
product is its actual validated path; complete separately reports all stages.
Missing/partial receipts and unknown workers are refusals, not an empty install.
"""
    out=canonical(record['out']);value=record['config']['value'];backend=value['build']
    require(backend['mode']=='offline','OFFLINE_ROUTE_REQUIRED','需要offline工作流')
    initial=out/'offline-install';work=out/'offline-work'
    if not os.path.lexists(initial):
        require(not os.path.lexists(work),'OFFLINE_UNREGISTERED_WORK',
                '没有原始installation但offline-work已存在，不能自动接纳')
        return None
    require(canonical(initial)==initial and initial.is_dir(),
            'OFFLINE_INSTALLATION_CHANGED','原始offline installation位置或类型变化')
    require(canonical(work)==work,'OFFLINE_WORK_CHANGED','offline工作目录位置变化')
    plan_path=initial/'plan.json';before=installer._sha(plan_path)
    proposed=installer._read(plan_path);installer._plan_contract(proposed)
    expected_paths=dict(cpu_cache=backend['cpu_cache'],graphics_cache=backend['graphics_cache'],
        pe=str(out/'inputs/program.exe'),profile=str(out/'inputs/profile.json'),
        work_root=str(work),out=str(initial))
    require(proposed['paths']==expected_paths,'OFFLINE_PLAN_PATHS_CHANGED',
            '离线计划没有绑定本工作流输入/cache/work/evidence路径')
    require(proposed['jobs']==backend['jobs'] and type(proposed['jobs']) is int and
            proposed['identifier']==value['identifier'] and
            proposed['spec']==installer.spec(dict(identifier=value['identifier'],name='PE AOT Portable Window')),
            'OFFLINE_PLAN_CONFIG_CHANGED','离线计划jobs或App标识不匹配')
    inputs=record['inputs']
    require(proposed['inputs']['pe_sha256']==inputs['pe_sha256'] and
            proposed['inputs']['profile_sha256']==inputs['canonical_profile_sha256'] and
            proposed['inputs']['canonical_profile_sha256']==inputs['canonical_profile_sha256'],
            'OFFLINE_PLAN_INPUT_CHANGED','离线计划PE或规范化profile身份不匹配')
    require(proposed['caches']==record['backend']['caches'] and proposed['apple']==record['backend']['apple'],
            'OFFLINE_PLAN_BACKEND_CHANGED','离线计划cache/SDK/工具与工作流冻结身份不同')
    require(all(record['implementation'].get(name)==sha for name,sha in proposed['implementation'].items()),
            'OFFLINE_PLAN_IMPLEMENTATION_CHANGED','离线计划实现不属于工作流冻结实现')
    fd=installer._lock(work)
    try:
        identity=installer._read(initial/'work-identity.json')
        require(identity.get('schema')==1 and identity['work_root']==str(work) and
                installer._lock_identity(fd,work)==identity['lock_identity'],
                'OFFLINE_LOCK_CHANGED','原始离线锁inode或work身份变化')
        require(installer._sha(plan_path)==before,'OFFLINE_PLAN_CHANGED','取得锁期间离线计划变化')
        installer._environment(proposed,initial)
        sessions=installer._session_records(initial,proposed)
        for session in sessions:
            path=canonical(session)
            valid=path==initial or (path.name=='offline-resume' and path.parent.parent==out/'attempts' and
                  re.fullmatch(r'attempt-[0-9]{4}',path.parent.name) is not None)
            require(valid,'OFFLINE_SESSION_OUTSIDE_WORKFLOW','离线session不属于本工作流attempt')
        completed,dependencies=installer._completed(sessions,proposed,initial)
        require(installer._sha(plan_path)==before,'OFFLINE_PLAN_CHANGED','读验期间离线计划变化')
        def provider(stage):
            if stage not in completed:return None,None
            prefix=completed[stage]['arguments']['prefix']
            path=str(Path(prefix)/'provider.json');sha=installer._sha(path)
            require(dependencies.get(path)==sha,'OFFLINE_PROVIDER_CHANGED','已接纳provider读验期间变化')
            return prefix,sha
        cpu_prefix,cpu_sha=provider('switch-build')
        graphics_prefix,graphics_sha=provider('graphics-build')
        product=completed['app-build']['arguments']['out'] if 'app-build' in completed else None
        return dict(installation=str(initial),plan_sha256=before,sessions=[str(p) for p in sessions],
            completed_stages=list(completed),complete=list(completed)==list(installer.STAGES),
            product=product,cpu_prefix=cpu_prefix,cpu_provider_sha256=cpu_sha,
            graphics_prefix=graphics_prefix,graphics_provider_sha256=graphics_sha,
            provider_dependencies=dependencies,
            scope='Original installation lock, environment and accepted stages revalidated; no new session or execution.')
    finally:
        os.close(fd)
