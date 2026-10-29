#!/usr/bin/env python3
"""Actual independent roots, private shared traces and callback root rejections."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
sys.path.insert(0,str(ROOT))
from callback_bridge.lift import (lift_roots,lift_pe,build_ret_shim,TranslationError,validate_helper_effects,
    SOURCE_PATHS,EXTERNAL_SOURCE_PATHS,LIFTER,BUILD,TOOL_OUT)
from callback_bridge.fixtures import pe_image
OUT=ROOT/'build/callback-bridge/lift-tests'

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,message):
    if not value:raise RuntimeError(message)

def main():
    OUT.mkdir(parents=True,exist_ok=True);evidence=OUT/'evidence.json'
    evidence.write_text('{"status":"RUNNING"}\n')
    fixtures=ROOT/'build/callback-bridge/fixtures'
    sources=[ROOT/p for p in SOURCE_PATHS+EXTERNAL_SOURCE_PATHS]+[Path(__file__),HERE/'fixtures.py']
    dependencies=sources+[LIFTER,BUILD/'lib/Arch/X86/Runtime/amd64.bc',TOOL_OUT/'build-manifest.json']
    dependencies += [fixtures/(name+'.exe') for name in ('leaf','import','direct','nested')]
    before={str(p.resolve()):sha(p) for p in dependencies};records=[]
    try:
        for name in ('leaf','import','direct','nested'):
            pe=fixtures/(name+'.exe');roots=lift_roots(pe,OUT/name,[0x1040])
            require(roots['input_sha256']==sha(pe),'original PE source identity differs')
            require(all(d['manifest']['input_sha256']==sha(pe) for d in [roots['main'],*roots['roots']]),'root was lifted from different PE')
            require(roots['roots'][0]['manifest']['original_entry_rva']==0x1000,'callback root rewrote original entry')
            require(roots['roots'][0]['manifest']['entry_rva']==0x1040,'wrong callback selection')
            records.append({'case':name+'_two_original_roots','status':'PASS','root_modules':2,
                            'main_instructions':len(roots['main']['manifest']['instructions']),
                            'callback_instructions':len(roots['roots'][0]['manifest']['instructions'])})
        shim=build_ret_shim(OUT/'ret')
        require(shim['instructions'][0]['bytes']=='c3' and len(shim['instructions'])==1,'RET shim changed')
        records.append({'case':'synthetic_ret','status':'PASS','root_modules':1})
        # Two roots call the *same* original direct helper. They must link
        # together without duplicate sub_<VA> exports; helper PCs stay original.
        text=bytearray(b'\x90'*0x40)
        for entry in (0,0x20):
            body=b'\x48\x83\xec\x28\xe8'+struct.pack('<i',0x40-(entry+9))+b'\x48\x83\xc4\x28\xc3'
            text[entry:entry+len(body)]=body
        text+=bytes.fromhex('4889c84801d0c3')
        shared=OUT/'shared-helper.exe';shared.write_bytes(pe_image(bytes(text),[('aotdemo.dll','NativeInvokeCallback',3)]))
        roots=lift_roots(shared,OUT/'shared',[0x1020])
        private=[d['manifest']['private_trace_symbols'] for d in [roots['main'],*roots['roots']]]
        require(private==[['cb_1000_sub_140001040'],['cb_1020_sub_140001040']],'shared helper namespace mismatch')
        command=['xcrun','ld','-r','-arch','arm64','-o',str(OUT/'shared-combined.o'),
                 str(OUT/'shared/main/arm64.o'),str(OUT/'shared/callback-1020/arm64.o')]
        linked=subprocess.run(command,capture_output=True,text=True)
        (OUT/'shared-link.log').write_text(json.dumps(command)+'\n'+linked.stdout+linked.stderr)
        require(linked.returncode==0,'independent shared helper objects do not link')
        symbols=subprocess.check_output(['nm','-gU',str(OUT/'shared-combined.o')],text=True)
        (OUT/'shared-nm.log').write_text(symbols)
        require(sorted(line.split()[-1] for line in symbols.splitlines() if line.split())==['_aot_callback_1020','_aot_entry'],'combined exports differ')
        records.append({'case':'shared_direct_callee_link','status':'PASS','root_modules':2,'private_symbols':private})
        def rejected(name,call,phrase):
            try:call()
            except (ValueError,TranslationError) as error:
                require(phrase in str(error),'wrong rejection: '+name+': '+str(error))
                records.append({'case':name,'status':'REJECT','reason':str(error)})
            else:raise RuntimeError('invalid callback root accepted: '+name)
        pe=fixtures/'leaf.exe'
        rejected('empty_registry',lambda:lift_roots(pe,OUT/'bad-empty',[]),'distinct explicit')
        rejected('duplicate_registry',lambda:lift_roots(pe,OUT/'bad-duplicate',[0x1040,0x1040]),'distinct explicit')
        rejected('bool_registry',lambda:lift_roots(pe,OUT/'bad-bool',[True]),'distinct explicit')
        rejected('main_as_callback',lambda:lift_roots(pe,OUT/'bad-main',[0x1000]),'main entry')
        rejected('outside_root',lambda:lift_pe(pe,OUT/'bad-outside',entry_rva=0x4000),'invalid root RVA')
        rejected('negative_root',lambda:lift_pe(pe,OUT/'bad-negative',entry_rva=-1),'invalid root RVA')
        rejected('data_root',lambda:lift_pe(pe,OUT/'bad-data',entry_rva=0x2000),'entry outside file-backed')
        rejected('helper_name_collision',lambda:lift_pe(pe,OUT/'bad-symbol',entry_symbol='aot_begin'),'invalid root symbol')
        invalid=OUT/'invalid-opcode.exe'
        invalid.write_bytes(pe_image(b'\xc3'+b'\x90'*15+b'\x0f\x0b',[('aotdemo.dll','NativeInvokeCallback',3)]))
        rejected('root_invalid_opcode',lambda:lift_pe(invalid,OUT/'bad-opcode',entry_rva=0x1010),'REJECT iclass UD2')
        # Mutate actual emitted IR one contract site at a time. These are
        # textual gate rejections, separate from real lifter decode negatives.
        original=(OUT/'nested/main/arm64.ll').read_text();validate_helper_effects(original)
        declarations=[x for x in original.splitlines() if x.startswith('declare ') and '@__remill_function_call(' in x]
        calls=[x for x in original.splitlines() if 'call ' in x and '@__remill_function_call(' in x]
        require(len(declarations)==1 and bool(calls),'actual callback helper sites missing')
        forbidden=['nocallback','argmemonly','inaccessiblememonly','inaccessiblemem_or_argmemonly',
                   'readnone','readonly','writeonly','speculatable','memory(none)','memory(read)',
                   'memory(write)','memory(argmem: readwrite)','memory(inaccessiblemem: readwrite)',
                   'memory(argmem: readwrite, inaccessiblemem: readwrite)']
        for site,line in [('declaration',declarations[0]),('callsite',calls[0])]:
            for index,attribute in enumerate(forbidden):
                changed=original.replace(line,line+' '+attribute,1)
                rejected('effect_'+site+'_'+str(index),lambda changed=changed:validate_helper_effects(changed),'helper')
        records.append({'case':'actual_full_memory_readwrite_helper','status':'PASS','textual_effect_mutations_rejected':28})
        after={str(p.resolve()):sha(p) for p in dependencies};require(before==after,'sources/tool/fixtures changed during tests')
        require(len(records)==44 and len({r['case'] for r in records})==44,'record count mismatch')
        result={'status':'PASS','positive_cases':7,'rejected_cases':37,'lifted_root_modules':11,'cases':records,
                'scope':'actual frozen Remill independent-root lift, private helper link and bounded callback-root input checks; does not execute native callback runtime',
                'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sources},
                'inputs_before':before,'inputs_after':after,
                'build_manifest_sha256':sha(TOOL_OUT/'build-manifest.json'),'lifter_sha256':sha(LIFTER),
                'semantics_sha256':sha(BUILD/'lib/Arch/X86/Runtime/amd64.bc'),
                'artifact_sha256':{str(p.relative_to(OUT)):sha(p) for p in OUT.rglob('*') if p.is_file() and p!=evidence}}
        evidence.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'PASS','positive':7,'rejected':37}))
    except Exception as error:
        evidence.write_text(json.dumps({'status':'FAIL','error':str(error)},indent=2)+'\n');raise


if __name__=='__main__':main()
