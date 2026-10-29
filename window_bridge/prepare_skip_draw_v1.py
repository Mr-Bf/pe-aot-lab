#!/usr/bin/env python3
"""New self-authored skip-Draw negative PE; real compile/lift, no execution.

The frozen positive source/PE and Program admission rules remain unchanged.
Only the guest Draw statement is omitted in this separately named source.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from window_bridge import prepare as original
from window_bridge import lift,loader,window_bindings as binding
from graphics_stage5 import d3d11_probe as g

OUT=ROOT/'build/window-bridge/prepared-skip-draw-v1-01'
SOURCE=HERE/'fixture_skip_draw_v1.cpp'
ORIGINAL_SOURCE_SHA='149eeb9d49b06e600dfe5105506b68bacb77e00701a6650e8b464b5892030bc9'
ORIGINAL_PE_SHA='a9997a6e542efee64c19d8a2ac343d28e294341a187ab954b9d8e0a6a9824da1'
OMITTED='  window_context->Draw(3, 0);'
REPLACEMENT='  /* Negative fixture: omit guest Draw only; keep all frame/state/save code. */'
STATUS='NEGATIVE_SKIP_DRAW_PE_COMPILED_LIFTED_NOT_EXECUTED'
SCOPE=dict.fromkeys(('guest_executions','window_executions','gpu_executions','pixel_frames'),0)


def require(value,message):
    if not value:raise ValueError(message)


def write(path,record):
    with Path(path).open('x') as stream:json.dump(record,stream,indent=2,sort_keys=True);stream.write('\n')


def output(path):
    path=Path(path).absolute()
    require(path==path.resolve() and path.parent==ROOT/'build/window-bridge' and path.name.startswith('prepared-skip-draw-v1-'),
            'separate prepared-skip-draw-v1-* output required')
    return path


def expected_source():
    path=HERE/'fixture.cpp';require(g.sha(path)==ORIGINAL_SOURCE_SHA,'frozen positive source changed')
    text=path.read_text();require(text.count(OMITTED)==1,'Draw omission anchor is not unique')
    return text.replace(OMITTED,REPLACEMENT)


def dependencies():
    require(SOURCE.read_text()==expected_source(),'negative source has changes beyond one Draw omission')
    result={}
    for source in (SOURCE,HERE/'abi_layout.cpp'):
        text=original.run([original.LLVM/'clang',*original.FLAGS,'-M','-MT','inputs',source])
        require(text.startswith('inputs:'),'compiler dependency target differs')
        result[source.name]=sorted(str(Path(p).resolve()) for p in shlex.split(text.split(':',1)[1].replace('\\\n',' ')))
    require(str(original.HEADERS/'winuser.h') in result[SOURCE.name] and str(original.DXHEADERS/'d3d11.h') in result[SOURCE.name],
            'actual original WinUser/DirectX declarations absent')
    return result


def inputs(deps):
    return g.hashes([*original.inputs(deps),*binding.python_closure([Path(__file__)]),HERE/'fixture.cpp',
        original.OUT/'evidence.json',original.OUT/'manifest.json',original.OUT/'integer-tile.exe',
        lift.LIFTER,lift.TOOL_OUT/'build-manifest.json',lift.BUILD/'lib/Arch/X86/Runtime/amd64.bc'])


def inspect(out):
    original.verify();require(g.sha(original.OUT/'integer-tile.exe')==ORIGINAL_PE_SHA,'positive PE baseline changed')
    record=original.inspect(out)
    baseline=g.read_json(original.OUT/'manifest.json')
    wanted=Counter(i['slot'] for i in baseline['virtual_calls']);require(wanted[13]==1,'positive Draw callsite count differs');wanted[13]-=1
    actual=Counter(i['slot'] for i in record['virtual_calls'])
    require(actual==+wanted and not actual[13],'negative PE did not remove exactly the Draw slot call shape')
    require({(i['dll'],i['name']) for i in record['imports']}=={(i['dll'],i['name']) for i in baseline['imports']},'negative changed imported APIs')
    require(record['pe_sha256']!=ORIGINAL_PE_SHA,'negative PE equals positive PE')
    record.update(status='NEGATIVE_SKIP_DRAW_PE_PREPARED_NOT_EXECUTED',negative_fixture=True,
        positive_source_sha256=ORIGINAL_SOURCE_SHA,positive_pe_sha256=ORIGINAL_PE_SHA,
        source_delta={'removed':OMITTED,'replacement':REPLACEMENT,'other_source_changes':False},
        semantic_contract='Self-authored negative: Clear/Present/input/state/save retained; guest Draw omitted; not the unchanged positive PE')
    for row in record['register_calls']:row['status']='REGISTER_OPERAND_ONLY; EXACT_REGISTERED_IAT_TARGET_REQUIRED_AT_RUNTIME'
    return record


def metadata(record):
    sizes={'window_state':20,'window_result':60,'window_message':48,'window_rectangle':16,
           'window_client':16,'window_swap_desc':72,'window_feature':4,'window_handle':8,'window_instance':8}
    symbols=record['symbols']
    return {'pe_sha256':record['pe_sha256'],'callback_rvas':[r['rva'] for r in record['callback_roots']],
        'observations':{n:{'rva':symbols[n],'size':size} for n,size in sizes.items()},
        'save_name_rva':symbols['_ZL16window_save_name'],
        'scope':'negative skip-Draw source fixture only; no GUI/GPU/pixel execution; not frozen normal Program input'}


def verify_modules(out,record):
    roots=g.read_json(out/'compiler/roots.json')
    require(roots['status']=='BUILD_STATIC_NOT_EXECUTED' and roots['input_sha256']==record['pe_sha256'],'negative root identity differs')
    descriptors=[roots['main'],*roots['roots']]
    require(len(descriptors)==2 and descriptors[0]['rva']==record['entry_rva'] and
            descriptors[1]['rva']==record['symbols']['window_proc'],'main/callback root set differs')
    for index,root in enumerate(descriptors):
        directory=out/'compiler'/('main' if index==0 else 'window-proc-%x'%root['rva'])
        symbol='aot_entry' if index==0 else 'aot_window_proc_%x'%root['rva']
        require(root['directory']==str(directory) and root['symbol']==symbol,'root directory/export differs')
        binding.verify_lift(directory,root['manifest'],record['pe_sha256'],symbol)
    ret=g.read_json(out/'ret-shim/manifest.json')
    binding.verify_lift(out/'ret-shim',ret,g.sha(out/'ret-shim/synthetic-ret.exe'),'aot_import_ret')
    require(not any(i.get('kind')==3 and i.get('slot')==13 for i in roots['instructions']),'actual lifted CFG contains Draw slot')
    pe=out/'integer-tile.exe';data=pe.read_bytes();image=loader.load_image(pe)
    meta=metadata(record);name=image.data[meta['save_name_rva']:meta['save_name_rva']+121].split(b'\0',1)[0]
    require(name==b'integer-tile.bin','new PE save name differs')
    program=SimpleNamespace(image=image,roots=descriptors,root_manifest=roots,out=out,source_bytes=data,source_sha256=record['pe_sha256'])
    calls,rows,observations=binding.generate_headers(program,meta,write=False)
    return program,{'roots':2,'ret_modules':1,'unique_reachable_instructions':len(roots['instructions']),
        'direct_iat_calls':len(calls),'virtual_calls':len(program.virtual_calls),'register_calls':len(program.register_calls),
        'draw_slot_calls':0,'rows_including_thunks':len(rows),
        'observations':len(observations),'objects':g.hashes([Path(r['directory'])/n for r in descriptors for n in ('arm64.o','arm64-o0.o')]+[out/'ret-shim'/n for n in ('arm64.o','arm64-o0.o')])}


def tools():
    result={}
    for path in [original.LLVM/name for name in ('clang','llvm-dlltool','llvm-nm','llvm-objdump','llvm-readobj')]+[original.LINK]:
        query=subprocess.run([str(path),'--version'],text=True,capture_output=True)
        require(query.returncode==0 or (path.name=='llvm-dlltool' and query.returncode==1 and query.stdout.startswith('OVERVIEW: llvm-dlltool')),'actual tool version query failed')
        result[str(path)]={'realpath':str(path.resolve()),'sha256':g.sha(path),
            'version_query':{'returncode':query.returncode,'stdout':query.stdout,'stderr':query.stderr},
            'otool_dependencies':original.run(['/usr/bin/otool','-L',path.resolve()])}
    return result


def artifact_set(out):
    return {str(p.relative_to(out)):g.sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p!=out/'evidence.json'}


def verify(out=OUT):
    out=output(out);r=g.read_json(out/'evidence.json')
    require(r['schema']==1 and r['status']==STATUS and r['scope']==SCOPE and all(type(n) is int for n in r['scope'].values()),'negative static scope differs')
    original.verify_shaders();deps=dependencies()
    require(deps==r['dependencies'] and inputs(deps)==r['inputs_before']==r['inputs_after'],'negative input/header/tool closure differs')
    require(artifact_set(out)==r['artifacts'],'exact negative artifact closure differs')
    record=inspect(out);require(record==g.read_json(out/'manifest.json'),'negative PE metadata differs')
    require(metadata(record)==g.read_json(out/'fixture-metadata.json'),'native observation metadata differs')
    p,lifted=verify_modules(out,record);require(lifted==r['lifted'],'static lowered objects/metadata differ')
    require(all((out/name).read_text()==text for name,text in p.generated_headers.items()),'generated negative headers differ')
    require(g.read_json(out/'tool-provenance.json')==tools(),'actual preparation tool identity differs')
    require(g.read_json(out/'started.json')=={'schema':1,'status':'NEGATIVE_PREPARATION_STARTED_NOT_EXECUTED','producer_sha256':g.sha(__file__),
        'negative_source_sha256':g.sha(SOURCE),'positive_source_sha256':ORIGINAL_SOURCE_SHA,'positive_pe_sha256':ORIGINAL_PE_SHA,'scope':SCOPE},'immutable negative start differs')
    expected_compile=list(map(str,[original.LLVM/'clang',*original.FLAGS,'-c',SOURCE,'-o',out/'integer-tile.obj']))
    require(g.read_json(out/'compile.json')['command']==expected_compile and g.read_json(out/'compile.json')['returncode']==0,'actual negative source compile command differs')
    require(r['negative_pe_sha256']==record['pe_sha256'] and r['negative_source_sha256']==g.sha(SOURCE),'negative source/PE identity differs')
    return {'status':STATUS,'negative_pe_sha256':record['pe_sha256'],'entry_rva':record['entry_rva'],
        'wndproc_rva':record['symbols']['window_proc'],'static_linear_instructions':len(record['instructions']),
        'lifted':lifted,'scope':SCOPE}


def build(out=OUT):
    out=output(out);require(not out.exists(),'keep previous attempts; use a fresh negative output directory');out.mkdir(parents=True)
    write(out/'started.json',{'schema':1,'status':'NEGATIVE_PREPARATION_STARTED_NOT_EXECUTED','producer_sha256':g.sha(__file__),
        'negative_source_sha256':g.sha(SOURCE),'positive_source_sha256':ORIGINAL_SOURCE_SHA,'positive_pe_sha256':ORIGINAL_PE_SHA,'scope':SCOPE})
    try:
        shader=original.verify_shaders();deps=dependencies();before=inputs(deps)
        write(out/'dependencies.json',deps);write(out/'tool-provenance.json',tools())
        original.run([original.LLVM/'clang',*original.FLAGS,'-S','-emit-llvm',HERE/'abi_layout.cpp','-o',out/'abi-layout.ll'],out/'abi-compile.json')
        layout={m[1]:int(m[2]) for m in re.finditer(r'^@(\w+) = .*constant i64 (\d+)',(out/'abi-layout.ll').read_text(),re.M)}
        write(out/'abi-layout.json',layout)
        original.run([original.LLVM/'clang',*original.FLAGS,'-c',SOURCE,'-o',out/'integer-tile.obj'],out/'compile.json')
        undefined=original.run([original.LLVM/'llvm-nm','--undefined-only',out/'integer-tile.obj']);(out/'undefined-symbols.txt').write_text(undefined)
        require({line.split()[-1] for line in undefined.splitlines()}=={'__imp_'+name for _,name in original.PARSE_PROFILE},'unexpected import/CRT/helper')
        libs=[]
        for dll,names in original.APIS.items():
            definition=out/(dll+'.def');library=out/(dll+'.lib')
            definition.write_text('LIBRARY '+dll+'.dll\nEXPORTS\n'+''.join('    '+n+'\n' for n in names))
            original.run([original.LLVM/'llvm-dlltool','-m','i386:x86-64','-d',definition,'-l',library],out/(dll+'-import.json'));libs.append(library)
        original.run([original.LINK,'/entry:window_entry','/subsystem:windows','/nodefaultlib','/machine:x64',
            '/base:'+hex(original.BASE),'/dynamicbase','/nxcompat','/fixed:no','/timestamp:0',
            '/out:'+str(out/'integer-tile.exe'),'/map:'+str(out/'integer-tile.map'),out/'integer-tile.obj',*libs],out/'link.json')
        (out/'disassembly.txt').write_text(original.run([original.LLVM/'llvm-objdump','--disassemble',out/'integer-tile.exe']))
        (out/'headers.txt').write_text(original.run([original.LLVM/'llvm-readobj','--file-headers','--sections','--coff-imports','--coff-basereloc',out/'integer-tile.exe']))
        record=inspect(out);write(out/'manifest.json',record);write(out/'fixture-metadata.json',metadata(record))
        lift.lift_roots(out/'integer-tile.exe',out/'compiler',metadata(record)['callback_rvas']);lift.build_ret_shim(out/'ret-shim')
        p,lifted=verify_modules(out,record)
        for name,text in p.generated_headers.items():(out/name).write_text(text)
        after=inputs(dependencies());require(before==after,'inputs changed during negative compile/lift')
        receipt={'schema':1,'status':STATUS,'scope':SCOPE,'negative_source_sha256':g.sha(SOURCE),
            'negative_pe_sha256':record['pe_sha256'],'inputs_before':before,'inputs_after':after,'dependencies':deps,
            'shader_proof':shader,'lifted':lifted,'artifacts':artifact_set(out),
            'not_normal_program':True,'native_host_linked':False,'pixel_predicate_executed':False,
            'limits':'new source negative, not patched original PE; static compile/lift only; image predicate must inspect all pixels before rejecting missing Draw'}
        write(out/'evidence.json',receipt);return verify(out)
    except Exception as error:
        failed=out/'failure-sources';failed.mkdir()
        for source in (Path(__file__),SOURCE):(failed/source.name).write_bytes(source.read_bytes())
        write(out/'first-failure.json',{'status':'NEGATIVE_STATIC_BUILD_FAILED_NOT_EXECUTED','error':repr(error),'scope':SCOPE});raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--verify-only',action='store_true');args=parser.parse_args()
    print(json.dumps(verify(args.out) if args.verify_only else build(args.out),indent=2))
