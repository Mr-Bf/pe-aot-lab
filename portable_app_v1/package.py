"""Package the freshly produced no-argument executable and its real three libraries."""
import json
from pathlib import Path
import plistlib
import shutil
from types import SimpleNamespace

from graphics_stage5 import d3d11_probe as graph_tools
from portable_graphics_v1 import build as backend
from portable_lifter_v1 import build as cpu
from portable_app_v1 import lift, producer
from window_app_v1.noarg import spec
from window_bridge import app_v3 as formats

ROOT=Path(__file__).resolve().parents[1]
STATUS='PORTABLE_APP_PACKAGED_NOT_EXECUTED'
NAMES=set(backend.NAMES)


def plist(value,minimum):
    value=spec(value)
    producer.version(minimum)
    return dict(CFBundleIdentifier=value['identifier'],CFBundleName=value['name'],
                CFBundleDisplayName=value['name'],CFBundleExecutable='pe-aot-window',
                CFBundlePackageType='APPL',CFBundleVersion='1',CFBundleShortVersionString='0.1',
                NSHighResolutionCapable=True,LSMinimumSystemVersion=minimum)


def graph(app,value,minimum):
    app=lift.path(app);executable=formats.executable(app);libraries=app/'Contents/Frameworks'
    lift.require({p.name for p in libraries.iterdir()}==NAMES,'exact packaged library set required')
    lift.require(plistlib.loads((app/'Contents/Info.plist').read_bytes())==plist(value,minimum),'packaged plist differs')
    result=graph_tools.library_graph(executable,executable)
    wanted={str(executable),*[str(libraries/name) for name in NAMES]}
    lift.require(set(result['nodes'])==wanted,'App dependency escaped bundle or is unreachable')
    for path,node in result['nodes'].items():
        main=path==str(executable)
        lift.require(node['filetype']==(2 if main else 6),'packaged code file type differs')
        lift.require(node['rpaths']==(['@executable_path/../Frameworks'] if main else ['@loader_path/']),
                     'packaged code has residual search paths')
        lift.require(Path(path).stat().st_mode&0o111,'packaged code lacks executable permission')
        lift.require(producer.minimum_version(path)<=producer.version(minimum),'App declares an OS below its code requirement')
        if not main:lift.require(node['id']=='@rpath/'+Path(path).name,'packaged dylib identity differs')
        for row in node['dependencies']:
            lift.require(graph_tools.system_image(row['name']) or row['name'] in {'@rpath/'+n for n in NAMES},
                         'non-system dependency is not bundle-relative')
    lift.require(all(graph_tools.system_image(target) or Path(target).is_relative_to(app)
                     for _,_,target,_ in result['edges']),'external App dependency')
    return result


def resource_inputs(native):
    _,cpu_paths=cpu.paths_for(native['cpu_prefix'])
    backend_paths=backend.paths_for(Path(native['backend']['provider_manifest']).parent)
    lift.require(backend_paths['provider_sha256']==native['backend']['provider_sha256'],'backend provider changed before packaging')
    lift.require(lift.sha(Path(native['cpu_prefix'])/'provider.json')==native['cpu_provider_sha256'],
                 'CPU provider changed before packaging')
    result={'Licenses/PE-AOT-Lab-LICENSE':ROOT/'LICENSE',
            'Licenses/Remill-LICENSE':cpu_paths['source']/'LICENSE',
            'Licenses/Remill-Changes.md':ROOT/'integration_stage3/NOTICE.lifter.md'}
    result.update({'Licenses/Graphics/'+name:Path(path) for name,path in backend_paths['licenses'].items()})
    for path in cpu.PATCHES:
        result['LifterChanges/'+path.name]=path
    return result


def build(native,out,value,run):
    # Bind the producer's persisted JSON representation, including tuple/list
    # normalization, instead of comparing Python-only container identities.
    native=json.loads(json.dumps(native,default=str))
    value=spec(value);out=lift.path(out,exists=False)
    lift.require(not out.exists(),'fresh package directory required')
    lift.require(native['status']==producer.STATUS and native['identifier']==value['identifier'],
                 'successful producer for this identifier required')
    native_manifest=Path(native['manifest_path'])
    for root in (native['cpu_prefix'],Path(native['backend']['provider_manifest']).parent,native_manifest.parent):
        root=lift.path(root)
        lift.require(not out.is_relative_to(root) and not root.is_relative_to(out),
                     'package output and provider/producer directories must be disjoint')
    lift.require(json.loads(native_manifest.read_bytes())==native,'producer receipt differs from passed record')
    lift.require(lift.sha(native['native_executable'])==native['native_sha256'],'producer executable changed')
    resources=resource_inputs(native)
    source_inputs=lift.snapshot([native_manifest,native['native_executable'],*native['inputs_before'],*resources.values(),
                                *(native_manifest.parent/name for name in native['artifacts']),
                                *lift.source_closure([Path(__file__)])])
    for name,value_hash in native['artifacts'].items():
        lift.require(lift.sha(native_manifest.parent/name)==value_hash,'producer artifact changed: '+name)
    out.mkdir(parents=True)
    commands=lift.Commands(out,run,'package')
    minimum=native['minimum_macos']
    app=out/'PE AOT Portable.app';relocated=out/'relocated with spaces/PE AOT Portable.app'
    program=SimpleNamespace(executable=Path(native['native_executable']),build_manifest=native)
    mapping=formats.mapping_for(program,app)
    lift.write(out/'started.json',dict(status='STARTED_NOT_EXECUTED',spec=value,minimum_macos=minimum,
                                     producer_sha256=lift.sha(native_manifest)))
    try:
        for original,destination in mapping.items():
            destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(original,destination)
            lift.require(lift.sha(original)==lift.sha(destination),'code copy changed bytes')
        (app/'Contents/Info.plist').write_bytes(plistlib.dumps(plist(value,minimum),sort_keys=True))
        for name,path in resources.items():
            destination=app/'Contents/Resources'/name
            destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,destination)
        provenance=dict(schema=1,original_pe_sha256=native['input_sha256'],
                        cpu_provider_sha256=native['cpu_provider_sha256'],
                        graphics_provider_sha256=native['backend']['provider_sha256'],
                        producer_sha256=lift.sha(native_manifest),minimum_macos=minimum,
                        requires_arguments=False,runtime_requires_python=False,runtime_requires_rosetta=False,
                        scope='Native ARM64 static package; runtime, Cocoa input, save recovery and performance require separate evidence.')
        lift.write(app/'Contents/Resources/provenance.json',provenance)
        lift.write(app/'Contents/Resources/profile.json',native['profile'])
        (app/'Contents/Resources/README.txt').write_text(
            'Native ARM64 development App. Start without arguments.\n'
            'Data: Foundation Application Support/'+value['identifier']+'/Data.\n'
            'The original PE reads and writes saves; the launcher does not inject guest state.\n'
            'Use Escape or close the guest window to request a normal save and exit.\n'
            'Runtime is restricted to the recorded Win32/D3D11 window contract.\n'
            'Ad-hoc local signature; not notarized. This package is not itself runtime or performance evidence.\n')
        tools={'install_name_tool':'/usr/bin/install_name_tool','codesign':'/usr/bin/codesign'}
        plan=formats.plans(program,app,relocated,tools)
        for label,argv in plan[:-1]:commands(argv,label)
        copied={}
        for original,destination in mapping.items():
            identity=formats.section_identity(original)
            lift.require(formats.section_identity(destination)==identity,'packaging changed code/PE/data sections')
            copied[str(destination.relative_to(app))]=dict(source=original,original_sha256=lift.sha(original),
                packaged_sha256=lift.sha(destination),section_identity=identity)
        first=graph(app,value,minimum)
        relocated.parent.mkdir();shutil.copytree(app,relocated)
        moved=graph(relocated,value,minimum)
        lift.require(formats.tree(app)==formats.tree(relocated),'App copy changed bytes/modes')
        lift.require(formats.normalized_graph(first,app)==formats.normalized_graph(moved,relocated),'App relocation changed dependencies')
        label,argv=plan[-1];commands(argv,label)
        lift.unchanged(source_inputs)
        lift.require({k:str(v) for k,v in resource_inputs(native).items()}=={k:str(v) for k,v in resources.items()},'package resource mapping changed')
        result=dict(schema=1,status=STATUS,spec=value,minimum_macos=minimum,app=str(app),relocated=str(relocated),
                    original_pe_sha256=native['input_sha256'],producer_sha256=lift.sha(native_manifest),
                    app_tree=formats.tree(app),relocated_tree=formats.tree(relocated),graph=first,relocated_graph=moved,
                    code_sections=copied,inputs_before=source_inputs,inputs_after=lift.snapshot(source_inputs),
                    artifacts=lift.artifacts(out),guest_executions=0,gpu_executions=0,
                    scope='New producer executable and exact three-library provider, complete notices, relative load paths and signatures; not launched.')
        lift.write(out/'package.json',result)
        return result
    except Exception as error:
        lift.write(out/'failure.json',dict(status='FAIL_NOT_EXECUTED',error=repr(error),command_count=len(commands.records)))
        raise
