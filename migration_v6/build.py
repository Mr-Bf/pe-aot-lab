"""One fresh-provider command from configured PE bytes to a native macOS App."""
import json
from pathlib import Path
import shutil
import traceback

from window_switch_v1 import lift, producer, package
from portable_graphics_v1 import build as graphics
from portable_lifter_v1 import build as common
from window_app_v1.noarg import spec
from window_switch_v1.profile import read_input, analyze

STATUS='BUILT_PORTABLE_WINDOW_APP_NOT_EXECUTED'


def ledger(root):
    root=lift.path(root);result={}
    for path in sorted(root.rglob('*')):
        lift.require(not path.is_symlink(),'artifact symlink rejected')
        if path.is_file():
            relative=str(path.relative_to(root))
            if relative=='result.json':continue
            result[relative]={'sha256':lift.sha(path),'mode':path.stat().st_mode&0o777}
        else:lift.require(path.is_dir(),'non-regular artifact rejected')
    return result


def build(pe,profile,identifier,cpu_prefix,backend_prefix,out):
    out=lift.path(out,exists=False);cpu_prefix=lift.path(cpu_prefix);backend_prefix=lift.path(backend_prefix)
    lift.require(not out.exists(),'fresh absent product output required')
    for prefix in (cpu_prefix,backend_prefix):
        lift.require(not out.is_relative_to(prefix) and not prefix.is_relative_to(out),'product/provider outputs must be disjoint')
    data=read_input(pe);value=spec(dict(identifier=identifier,name='PE AOT Portable Window'))
    profile=json.loads(json.dumps(profile))
    out.mkdir(parents=True);frozen=out/'input.exe';frozen.write_bytes(data)
    lift.write(out/'profile.json',profile)
    run=common.Recorder(out,cpu_prefix)
    sources=lift.snapshot(lift.source_closure([Path(__file__),Path(__file__).with_name('__main__.py')]))
    common.source_snapshot(out,[Path(name) for name in sources])
    record=dict(schema=1,profile='window-switch-v6',original_input=str(Path(pe).absolute()),
                input_sha256=lift.sha(frozen),profile_sha256=lift.sha(out/'profile.json'),
                cpu_prefix=str(cpu_prefix),backend_prefix=str(backend_prefix),spec=value,
                sources=sources,guest_executions=0,gpu_executions=0)
    lift.write(out/'started.json',{**record,'status':'STARTED_NOT_EXECUTED'})
    stage='analysis'
    try:
        analysis=analyze(data,profile)
        analysis['producer']='explicit CPU/graphics provider window switch v6'
        lift.write(out/'analysis.json',analysis)
        if analysis['status']!='ELIGIBLE_FOR_BUILD_NOT_DECODED':
            record.update(status='UNSUPPORTED',stage=stage,error=analysis['error'])
        else:
            stage='provider-validation'
            backend=graphics.paths_for(backend_prefix)
            descriptor=json.loads(backend['provider_manifest'].read_bytes())
            lift.require(lift.sha(backend['provider_manifest'])==backend['provider_sha256'],'graphics manifest changed')
            run.env.update(DEVELOPER_DIR=descriptor['external_prerequisites']['developer'],SDKROOT=str(backend['sdk']))
            stage='native-production'
            native=producer.build(cpu_prefix,backend,frozen,profile,identifier,out/'native',run)
            lift.require(native['status']==producer.STATUS and native['input_sha256']==record['input_sha256'],'producer consumed different PE or failed')
            stage='app-package'
            packaged=package.build(native,out/'package',value,run)
            app=out/'PE AOT Converted.app';shutil.copytree(packaged['app'],app)
            lift.require(package.formats.tree(app)==packaged['app_tree'],'App export changed bytes/modes')
            graph=package.graph(app,value,native['minimum_macos'])
            lift.require(package.formats.normalized_graph(graph,app)==package.formats.normalized_graph(packaged['graph'],packaged['app']),
                         'exported graph differs')
            record.update(status=STATUS,stage='complete',minimum_macos=native['minimum_macos'],app=str(app),
                executable=str(package.formats.executable(app)),executable_sha256=lift.sha(package.formats.executable(app)),
                app_tree=packaged['app_tree'],graph=graph,instruction_count=native['instruction_count'],
                callback_count=native['callback_count'],cpu_provider_sha256=native['cpu_provider_sha256'],
                graphics_provider_sha256=backend['provider_sha256'],producer_sha256=lift.sha(out/'native/producer.json'),
                package_sha256=lift.sha(out/'package/package.json'),requires_arguments=False,
                scope='Actual input PE roots and new RET shim, six newly compiled host units, freshly built graphics provider, native no-argument ARM64 App; no guest/GPU execution or performance claim.')
        lift.unchanged(sources)
        lift.require(lift.sha(frozen)==record['input_sha256'] and lift.sha(out/'profile.json')==record['profile_sha256'],'input snapshot changed')
    except Exception as error:
        (out/'failure.txt').write_text(traceback.format_exc())
        record.update(status='BUILD_FAILED',stage=stage,error_type=type(error).__name__,error=str(error))
    record['files']=ledger(out)
    lift.write(out/'result.json',record)
    return record


def verify(out):
    out=lift.path(out);receipt=out/'result.json';receipt_sha=lift.sha(receipt)
    record=json.loads(receipt.read_bytes())
    lift.require(lift.sha(receipt)==receipt_sha,'product receipt changed while reading')
    lift.require(record['schema']==1 and record['profile']=='window-switch-v6' and record['status']==STATUS,
                 'successful portable App product required')
    lift.require(record['guest_executions']==record['gpu_executions']==0 and record['requires_arguments'] is False,'static build scope differs')
    lift.require(ledger(out)==record['files'],'product file bytes/modes/set changed')
    lift.require(lift.sha(out/'input.exe')==record['input_sha256'] and lift.sha(out/'profile.json')==record['profile_sha256'],'input identity differs')
    app=out/'PE AOT Converted.app'
    lift.require(record['app']==str(app) and record['executable']==str(package.formats.executable(app)),'unexpected exported paths')
    lift.require(lift.sha(package.formats.executable(app))==record['executable_sha256'],'exported executable identity differs')
    lift.require(package.formats.tree(app)==record['app_tree'] and package.graph(app,record['spec'],record['minimum_macos'])==record['graph'],
                 'exported App graph/tree differs')
    lift.require(lift.sha(out/'native/producer.json')==record['producer_sha256'] and
                 lift.sha(out/'package/package.json')==record['package_sha256'],'stage receipt identity differs')
    lift.require(lift.sha(receipt)==receipt_sha,'product receipt changed during verification')
    return dict(status='PORTABLE_APP_FILES_VERIFIED_NOT_EXECUTED',app=str(app),files=len(record['files']),
                guest_executions=0,gpu_executions=0)
