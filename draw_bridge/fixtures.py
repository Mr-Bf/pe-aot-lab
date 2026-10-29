#!/usr/bin/env python3
"""Compile a real Windows PE containing original DXBC; preparation only."""
import argparse
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
sys.path.insert(0,str(ROOT))
from d3d11_bridge import fixtures as base
from d3d11_bridge.build_lifter import LIFTER,BUILD,OUT as TOOL_OUT
from graphics_stage5 import build_shaders as shaders
from callback_bridge.imports_v1 import load_imported_image

OUT=ROOT/'build/draw-bridge/fixtures'
SIZES={**base.SIZES,'graphics_result':112,'graphics_vs':8,'graphics_ps':8,
       'graphics_rasterizer':8,'graphics_rasterizer_desc':40,'graphics_viewport':24}
FIELDS=base.RESULT_FIELDS+['create_vs_hr','create_ps_hr','create_rasterizer_hr','draw_called']
# Annotation of this fixture's source order, not a global slot/signature map.
# Slot 9 and slot 15 deliberately appear with different interface meanings.
METHODS=[('Device',5,'CreateTexture2D'),('Device',9,'CreateRenderTargetView'),
 ('Device',5,'CreateTexture2D'),('Device',12,'CreateVertexShader'),
 ('Device',15,'CreatePixelShader'),('Device',22,'CreateRasterizerState'),
 ('Context',50,'ClearRenderTargetView'),('Context',33,'OMSetRenderTargets'),
 ('Context',43,'RSSetState'),('Context',44,'RSSetViewports'),
 ('Context',24,'IASetPrimitiveTopology'),('Context',11,'VSSetShader'),
 ('Context',9,'PSSetShader'),('Context',13,'Draw'),('Context',47,'CopyResource'),
 ('Context',14,'Map'),('Context',15,'Unmap'),('Device',39,'GetDeviceRemovedReason')]+[
 (kind,2,'Release') for kind in ('Rasterizer','PixelShader','VertexShader','RTV','Texture2D','Texture2D','Context','Device')]
require=base.require;sha=base.sha;snapshot=base.snapshot;run=base.run

def dependencies(out=None):
    cmd=[base.LLVM/'bin/clang',*base.FLAGS,*base.includes(),'-M','-MT','fixture',HERE/'fixture.cpp']
    p=run(cmd,out/'dependencies.log') if out else subprocess.run(list(map(str,cmd)),capture_output=True,text=True)
    require(p.returncode==0,'dependency query failed: '+p.stderr)
    text=p.stdout.replace('\\\n',' ');require(text.startswith('fixture:'),'dependency target differs')
    paths={Path(x).resolve() for x in shlex.split(text.split(':',1)[1])}
    require({HERE/'fixture.cpp',shaders.HEADER,base.HEADERS/'d3d11.h'}<=paths,'missing actual source/header dependency')
    return paths

def inputs(deps):
    return base.input_paths(deps)|{Path(__file__),Path(base.__file__),Path(shaders.__file__),
        ROOT/'d3d11_bridge/build_lifter.py',LIFTER,BUILD/'lib/Arch/X86/Runtime/amd64.bc',
        TOOL_OUT/'build-manifest.json',shaders.OUT/'evidence.json',shaders.TOOL_RECORD,
        shaders.OUT/'triangle.vs.dxbc',shaders.OUT/'triangle.ps.dxbc'}

def inspect(pe,mapping,disassembly):
    image=load_imported_image(pe,signatures=base.PROFILE)
    symbols=base.parse_map(mapping);require(set(SIZES)<=set(symbols),'missing observation globals')
    require(symbols['graphics_entry']==image.entry_rva,'entry does not match source')
    for name in SIZES:
        if name in ('graphics_requested','graphics_clear','graphics_expected','graphics_target_desc',
                    'graphics_staging_desc','graphics_image_anchor','graphics_rasterizer_desc','graphics_viewport'):continue
        require(image.read(image.base+symbols[name],SIZES[name])==bytes(SIZES[name]),'nonzero initial state: '+name)
    instructions=base.parse_instructions(disassembly,image);calls=[];virtual=[]
    for ins in instructions:
        if ins['mnemonic'] not in ('call','callq'):continue
        row=dict(ins);raw=bytes.fromhex(ins['bytes']);operand=ins['operand']
        if '%rip' in operand:
            require(raw[:2]==b'\xff\x15' and len(raw)==6,'unexpected import CALL shape')
            slot=ins['rva']+6+struct.unpack_from('<i',raw,2)[0]
            imp=next((i for i in image.imports if i['iat_rva']==slot),None);require(imp,'unregistered IAT call')
            row.update(kind='IAT_MEM64',iat_slot_rva=slot,dll=imp['dll'],name=imp['name'])
        else:
            m=re.fullmatch(r'\*(?:(0x[0-9a-f]+|\d+))?\(%(r(?:ax|bx|cx|dx|si|di|bp|sp|[89]|1[0-5]))\)',operand)
            require(m,'unexpected virtual addressing: '+operand)
            displacement=int(m[1],0) if m[1] else 0
            require(len(virtual)<len(METHODS),'unexpected extra virtual call')
            interface,slot,name=METHODS[len(virtual)]
            require(displacement==slot*8,'actual slot differs from fixture order')
            row.update(kind='VTABLE_MEM64',base_register=m[2].upper(),displacement=displacement,
                       slot=slot,fixture_interface_annotation=interface,name=name)
            virtual.append(row)
        calls.append(row)
    require(len(virtual)==26 and [r['name'] for r in calls if r['kind']=='IAT_MEM64']==['D3D11CreateDevice','ExitProcess'],
            'call coverage changed')
    require(not any(re.search(r'\b(?:xmm|ymm|zmm|mm[0-7])\d*\b',i['operand']) for i in instructions),'SIMD unexpectedly generated')
    shader_records={}
    for stage in ('vs','ps'):
        blob=(shaders.OUT/('triangle.'+stage+'.dxbc')).read_bytes()
        rva=bytes(image.data).find(blob)
        require(rva>=0 and bytes(image.data).find(blob,rva+1)==-1,'shader absent or duplicated in PE')
        require(image.read(image.base+rva,len(blob))==blob,'embedded DXBC bytes differ')
        section=next(s for s in image.sections if s['rva']<=rva and rva+len(blob)<=s['rva']+s['virtual_size'])
        require(section['permissions']==1,'DXBC not entirely in read-only data')
        shader_records[stage]={'rva':rva,'size':len(blob),'sha256':sha(shaders.OUT/('triangle.'+stage+'.dxbc'))}
    moved=load_imported_image(pe,0x180000000,signatures=base.PROFILE)
    require(int.from_bytes(moved.read(moved.base+symbols['graphics_image_anchor'],8),'little')==moved.base+symbols['graphics_target_desc'],
            'static DIR64 pointer failed relocation')
    text_section=next(s for s in image.sections if s['permissions']&4)
    code=bytes(image.data[text_section['rva']:text_section['rva']+text_section['virtual_size']])
    require(bytes.fromhex('5a5aa5a5') in code,'post-exit marker missing')
    observations={name:{'rva':symbols[name],'size':size} for name,size in SIZES.items()}
    observations['graphics_image_anchor'].update(kind='image_pointer',target_rva=symbols['graphics_target_desc'])
    return image,code,text_section,{'name':'draw_readback','pe_path':str(pe),'pe_sha256':sha(pe),
      'entry_rva':image.entry_rva,'entry_symbol':'graphics_entry','entry_arguments':0,
      'symbols':symbols,'observations':observations,'result_fields':FIELDS,'instructions':instructions,
      'calls':calls,'virtual_calls':virtual,'imports':image.imports,'sections':image.sections,
      'relocations':image.relocations,'embedded_shaders':shader_records,
      'expected':{'exit_code':0,'stage':11,'width':32,'height':32,'rgba8':[0,255,0,255],
          'clear_rgba8':[255,0,255,255],'tolerance_per_channel':1,'draw_calls':1,
          'pixels_checked':1024,'channels_checked':4096,'released_application_references':8},
      'guest_executions':0,'gpu_executions':0,'windows_executions':0}

def verify(out=OUT):
    out=Path(out).resolve();e=json.loads((out/'evidence.json').read_text())
    require(e['status']=='DRAW_PE_PREPARED_NOT_EXECUTED' and e['guest_executions']==e['gpu_executions']==0,'wrong preparation scope')
    shaders.verify_shaders();deps=dependencies()
    require(snapshot(inputs(deps))==e['inputs_before']==e['inputs_after'],'source/tool/shader inputs changed')
    require(snapshot(out/name for name in e['artifacts'])=={str(out/name):digest for name,digest in e['artifacts'].items()},'artifacts changed')
    required={'draw-readback.exe','draw-readback.obj','draw-readback.map','manifest.json','disassembly.txt','headers.txt',
              'dependencies.log','compile.log','link.log','undefined-symbols.log','old-profile-rejection.log'}
    require(required<=set(e['artifacts']) and all(Path(n).name==n for n in e['artifacts']),'required artifacts absent/unsafe')
    _,_,_,m=inspect(out/'draw-readback.exe',out/'draw-readback.map',(out/'disassembly.txt').read_text())
    require(json.loads((out/'manifest.json').read_text())=={'draw_readback':m},'actual PE metadata differs')
    require(e['old_profile_rejection']['returncode']!=0 and 'REJECT virtual call outside D3D11 slot-shape profile' in e['old_profile_rejection']['stderr'],
            'unsupported profile was not rejected')
    return {'status':'DRAW_PE_CURRENT_NOT_EXECUTED','pe_sha256':m['pe_sha256'],'static_instructions':len(m['instructions']),
            'virtual_calls':26,'import_calls':2,'embedded_shaders':m['embedded_shaders'],'guest_executions':0,'gpu_executions':0}

def build(out=OUT):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence.json'
    if evidence.exists():
        history=out/'history';history.mkdir(exist_ok=True);(history/(sha(evidence)+'.json')).write_bytes(evidence.read_bytes())
    evidence.write_text('{"status":"RUNNING_NOT_ACCEPTED"}\n')
    try:
        shader_proof=shaders.verify_shaders();before=snapshot(inputs(dependencies(out)));libs=[]
        for dll,api in [('kernel32','ExitProcess'),('d3d11','D3D11CreateDevice')]:
            definition=out/(dll+'.def');definition.write_text('LIBRARY '+dll+'.dll\nEXPORTS\n    '+api+'\n')
            lib=out/(dll+'.lib');libs.append(lib)
            run([base.LLVM/'bin/llvm-dlltool','-m','i386:x86-64','-d',definition,'-l',lib],out/(dll+'-import.log'))
        obj=out/'draw-readback.obj';pe=out/'draw-readback.exe';mapping=out/'draw-readback.map'
        run([base.LLVM/'bin/clang',*base.FLAGS,*base.includes(),'-c',HERE/'fixture.cpp','-o',obj],out/'compile.log')
        undefined=run([base.LLVM/'bin/llvm-nm','--undefined-only',obj],out/'undefined-symbols.log').stdout
        require({line.split()[-1] for line in undefined.splitlines() if line.strip()}=={'__imp_D3D11CreateDevice','__imp_ExitProcess'},'unexpected CRT/helper dependency')
        run([base.LINKER,'/entry:graphics_entry','/subsystem:console','/nodefaultlib','/machine:x64','/base:'+hex(base.BASE),
             '/dynamicbase','/nxcompat','/fixed:no','/timestamp:0',*['/include:'+s for s in SIZES],
             '/out:'+str(pe),'/map:'+str(mapping),obj,*libs],out/'link.log')
        disasm=run([base.LLVM/'bin/llvm-objdump','--disassemble',pe],out/'disassembly.txt').stdout
        run([base.LLVM/'bin/llvm-readobj','--file-headers','--sections','--coff-imports','--coff-basereloc',pe],out/'headers.txt')
        image,code,section,meta=inspect(pe,mapping,disasm)
        # This deliberately tests rejection by the previous, frozen producer.
        old=out/'old-profile.json';old.unlink(missing_ok=True)
        rejected=run([LIFTER,'--os=windows','--arch=amd64','--address='+str(image.base+section['rva']),
            '--entry_address='+str(image.base+image.entry_rva),'--bytes='+code.hex(),'--aot_manifest='+str(old),
            '--aot_decode_only','--aot_vtable_mem64','--aot_iat_slots='+','.join(str(image.base+i['iat_rva']) for i in image.imports)],
            out/'old-profile-rejection.log',False)
        require(rejected.returncode!=0 and not old.exists() and 'REJECT virtual call outside D3D11 slot-shape profile' in rejected.stderr,
                'previous producer did not reject new scope')
        (out/'manifest.json').write_text(json.dumps({'draw_readback':meta},indent=2)+'\n')
        after=snapshot(inputs(dependencies()));require(before==after,'inputs changed during build')
        artifacts={p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file() and p!=evidence}
        record={'status':'DRAW_PE_PREPARED_NOT_EXECUTED','inputs_before':before,'inputs_after':after,
            'artifacts':artifacts,'shader_proof':shader_proof,'pe_sha256':meta['pe_sha256'],
            'old_profile_rejection':{'returncode':rejected.returncode,'stderr':rejected.stderr},
            'guest_executions':0,'gpu_executions':0,'windows_executions':0,
            'limits':['Build and static inspection only; no ARM lowering or runtime evidence.',
                      'Interface annotations describe fixture source order, not a global slot/signature authorization.']}
        evidence.write_text(json.dumps(record,indent=2)+'\n');return verify(out)
    except Exception as error:
        evidence.write_text(json.dumps({'status':'FAIL_NOT_ACCEPTED','error':str(error),'guest_executions':0,'gpu_executions':0},indent=2)+'\n')
        history=out/'history'/sha(evidence);history.mkdir(parents=True,exist_ok=True)
        for p in [Path(__file__),HERE/'fixture.cpp',*[p for p in out.iterdir() if p.is_file()]]:
            (history/(sha(p)+'-'+p.name)).write_bytes(p.read_bytes())
        raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--verify-only',action='store_true')
    args=parser.parse_args();print(json.dumps(verify(args.out) if args.verify_only else build(args.out),indent=2))
