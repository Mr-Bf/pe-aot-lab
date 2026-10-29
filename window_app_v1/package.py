"""Self-contained development App for a caller-configured PE build; no launch."""
import json
from pathlib import Path
import plistlib
import shutil
from types import SimpleNamespace

from window_app_v1 import noarg
from window_bridge import app_v3 as frozen
from graphics_stage5 import d3d11_probe as g
from window_profile_v1.bindings import python_closure

ROOT=noarg.ROOT
STATUS='CONFIGURED_APP_STATICALLY_VERIFIED_NOT_EXECUTED'
NAMES=frozen.NAMES


def output(path):
    path=Path(path).absolute();base=ROOT/'build/window-app-v1'
    noarg.require(path==path.resolve() and path.parent==base,'new App directory directly beneath build/window-app-v1 required')
    return path


def plist(value):
    value=noarg.spec(value)
    return dict(CFBundleIdentifier=value['identifier'],CFBundleName=value['name'],CFBundleDisplayName=value['name'],
                CFBundleExecutable='pe-aot-window',CFBundlePackageType='APPL',CFBundleVersion='1',
                CFBundleShortVersionString='0.1',NSHighResolutionCapable=True)


def graph(app,value):
    app=Path(app).resolve();exe=frozen.executable(app);libraries=app/'Contents/Frameworks'
    noarg.require({p.name for p in libraries.iterdir()}==NAMES,'App library set differs')
    noarg.require(plistlib.loads((app/'Contents/Info.plist').read_bytes())==plist(value),'App plist differs')
    result=g.library_graph(exe,exe)
    noarg.require(set(result['nodes'])=={str(exe),*[str(libraries/name) for name in NAMES]},'dependency escaped App')
    for path,node in result['nodes'].items():
        main=path==str(exe)
        noarg.require(node['filetype']==(2 if main else 6),'Mach-O file type differs')
        noarg.require(node['rpaths']==(['@executable_path/../Frameworks'] if main else ['@loader_path/']),'unexpected load search path')
        noarg.require(Path(path).stat().st_mode&0o111,'code file is not executable')
        if not main:noarg.require(node['id']=='@rpath/'+Path(path).name,'dylib identity is not relative')
        for dependency in node['dependencies']:
            noarg.require(g.system_image(dependency['name']) or dependency['name'] in {'@rpath/'+name for name in NAMES},
                          'external non-system dependency name')
    noarg.require(all(g.system_image(target) or Path(target).is_relative_to(app) for _,_,target,_ in result['edges']),
                  'external non-system dependency target')
    return result


def as_program(entry):
    return SimpleNamespace(executable=Path(entry['native_executable']),build_manifest=entry)


def inputs(out,entry,tools):
    resources=resource_sources()
    paths=[*entry['inputs_before'],*entry['artifacts'],out/'entry/entry-build.json',
           *python_closure([Path(__file__),ROOT/'window_app_v1/__main__.py']),*tools.values(),*resources.values()]
    return g.hashes(paths)


def resource_sources():
    return {**frozen.resource_sources(),
            'Licenses/Remill-Changes.md':ROOT/'integration_stage3/NOTICE.lifter.md',
            'BackendChanges/inc-base32-v1.patch':ROOT/'window_inc_v1/inc-base32-v1.patch'}


def resources(entry):
    result={name:path.read_bytes() for name,path in resource_sources().items()}
    result['configuration.json']=(json.dumps(entry['spec'],indent=2,sort_keys=True)+'\n').encode()
    result['provenance.json']=(json.dumps(dict(pe_sha256=entry['pe_sha256'],source_product=entry['source_product'],
        source_receipt_sha256=entry['source_receipt_sha256'],entry_executable_sha256=entry['native_sha256'],
        runtime_contract='win32-d3d11-tile-v1',requires_arguments=False,
        runtime_requires_python=False,runtime_requires_rosetta=False,
        scope='static packaging; runtime, Cocoa input, save recovery, pixels and performance require separate evidence'),
        indent=2,sort_keys=True)+'\n').encode()
    result['README.txt']=('Configured native ARM64 development App. Start without arguments.\n'
        'Data: Foundation Application Support/'+entry['spec']['identifier']+'/Data.\n'
        'The original PE reads/writes its own saves. The launcher holds a single-instance lock.\n'
        'Use the guest window close control or Escape to request normal save/exit.\n'
        'Runtime is restricted to the declared window/D3D11/shader contract.\n'
        'No Python or Rosetta is required by the target. Signing is ad-hoc, not notarized.\n'
        'This build record is static; see separate evidence for actual execution.\n'
        'Input binary rights remain with their owners. Licenses and backend changes are included.\n').encode()
    return result


def build(product,path,value):
    out=output(path);value=noarg.spec(value)
    noarg.require(not out.exists(),'preserve previous App build');out.mkdir(parents=True)
    noarg.write(out/'started.json',dict(status='STARTED_NOT_EXECUTED',source_product=str(Path(product).resolve()),spec=value))
    commands=[]
    try:
        entry=noarg.build(product,out/'entry',value);p=as_program(entry);tools=frozen.tools()
        before=inputs(out,entry,tools)
        app=out/'PE AOT Configured.app';relocated=out/'relocated with spaces/PE AOT Configured.app'
        mapping=frozen.mapping_for(p,app)
        for original,destination in mapping.items():
            destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(original,destination)
            noarg.require(g.sha(original)==g.sha(destination),'code copy differs')
        (app/'Contents/Info.plist').write_bytes(plistlib.dumps(plist(value),sort_keys=True))
        for name,data in resources(entry).items():
            destination=app/'Contents/Resources'/name;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(data)
        plan=frozen.plans(p,app,relocated,tools)
        for name,args in plan[:-1]:frozen.command(out,name,args,commands)
        copied={}
        for original,destination in mapping.items():
            sections=frozen.section_identity(original)
            noarg.require(frozen.section_identity(destination)==sections,'packaging changed code/PE/data sections')
            copied[str(destination.relative_to(app))]=dict(source=original,original_sha256=g.sha(original),
                                                         packaged_sha256=g.sha(destination),section_identity=sections)
        initial_graph=graph(app,value)
        relocated.parent.mkdir();shutil.copytree(app,relocated)
        moved_graph=graph(relocated,value)
        noarg.require(frozen.tree(app)==frozen.tree(relocated),'relocation changed file bytes or modes')
        noarg.require(frozen.normalized_graph(initial_graph,app)==frozen.normalized_graph(moved_graph,relocated),'relocation changed dependency graph')
        name,args=plan[-1];frozen.command(out,name,args,commands)
        g.same(before);noarg.verify(out/'entry');noarg.require(inputs(out,entry,tools)==before,'App inputs changed')
        record=dict(schema=1,status=STATUS,spec=value,pe_sha256=entry['pe_sha256'],entry_receipt_sha256=g.sha(out/'entry/entry-build.json'),
                    inputs_before=before,inputs_after=g.hashes(before),tools=tools,app=str(app),relocated=str(relocated),
                    app_tree=frozen.tree(app),relocated_tree=frozen.tree(relocated),graph=initial_graph,relocated_graph=moved_graph,
                    copied_code=copied,commands=commands,
                    artifacts=g.hashes([out/'started.json',*[row['path'] for row in commands]]),
                    guest_executions=0,requires_arguments=False,signature='ad-hoc; no Developer ID or notarization')
        noarg.write(out/'evidence.json',record);verify(out)
        return record
    except Exception as error:
        noarg.write(out/'first-failure.json',dict(status='FAIL_NOT_EXECUTION_ACCEPTANCE',error=repr(error),commands=commands))
        raise


def verify(path):
    out=output(path);r=g.read_json(out/'evidence.json');value=noarg.spec(r['spec'])
    noarg.require(r['status']==STATUS and r['guest_executions']==0 and r['requires_arguments'] is False,'static App scope differs')
    noarg.require(r['inputs_before']==r['inputs_after'],'packaging inputs drifted');g.same(r['inputs_before']);g.same(r['artifacts'])
    noarg.require(g.sha(out/'entry/entry-build.json')==r['entry_receipt_sha256'],'entry receipt differs')
    entry=noarg.verify(out/'entry');p=as_program(entry)
    noarg.require(entry['spec']==value and entry['pe_sha256']==r['pe_sha256'],'App/entry configuration differs')
    noarg.require(inputs(out,entry,r['tools'])==r['inputs_before'],'package input closure differs')
    app=out/'PE AOT Configured.app';relocated=out/'relocated with spaces/PE AOT Configured.app'
    noarg.require(r['app']==str(app) and r['relocated']==str(relocated),'App path differs')
    noarg.require(frozen.tree(app)==r['app_tree']==r['relocated_tree']==frozen.tree(relocated),'App tree differs')
    noarg.require(graph(app,value)==r['graph'] and graph(relocated,value)==r['relocated_graph'],'actual loading graphs differ')
    noarg.require(frozen.normalized_graph(r['graph'],app)==frozen.normalized_graph(r['relocated_graph'],relocated),'normalized graphs differ')
    expected={}
    for original,destination in frozen.mapping_for(p,app).items():
        sections=frozen.section_identity(original)
        noarg.require(frozen.section_identity(destination)==sections,'native section contents changed')
        expected[str(destination.relative_to(app))]=dict(source=original,original_sha256=g.sha(original),
                packaged_sha256=g.sha(destination),section_identity=sections)
    noarg.require(r['copied_code']==expected,'packaged code provenance differs')
    for name,data in resources(entry).items():
        noarg.require((app/'Contents/Resources'/name).read_bytes()==data,'resource content differs')
    plan=frozen.plans(p,app,relocated,r['tools'])
    noarg.require(len(r['commands'])==len(plan),'package command count differs')
    for (name,args),row in zip(plan,r['commands'],strict=True):
        path=out/'commands'/(name+'.json');actual=g.read_json(path)
        noarg.require(row==dict(name=name,path=str(path),sha256=g.sha(path),returncode=0),'command identity differs')
        noarg.require(actual['command']==args and type(actual['returncode']) is int and actual['returncode']==0,'actual package command differs')
    noarg.require(r['artifacts']==g.hashes([out/'started.json',*[row['path'] for row in r['commands']]]),'package artifact closure')
    return r
