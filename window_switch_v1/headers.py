"""Generate the original window metadata plus independently proven switch binding."""
import json
import re
import struct
from window_profile_v1.bindings import METHOD_SIGNATURES, THUNK_START, lifter
from . import admission
from .lift import normalize
from window_inc_v1.loader import load_image

def generate_headers(program,metadata,write=True):
    image=program.image;merged={};virtual=[];register=[];calls=[]
    original = load_image(program.source_bytes)
    for name in ('base', 'preferred_base', 'entry_rva', 'source_sha256', 'data', 'permissions', 'imports', 'sections', 'relocations'):
        if getattr(image, name) != getattr(original, name):
            raise ValueError('header image differs from original PE: ' + name)
    if program.source_sha256 != original.source_sha256:
        raise ValueError('header source identity differs from original PE')
    root_rvas = [image.entry_rva, *metadata['callback_rvas']]
    if [root['rva'] for root in program.roots] != root_rvas:
        raise ValueError('header roots differ from declared entry/callback order')
    verified = admission.verify_root_set(
        [root['manifest']['switch_proof'] for root in program.roots],
        program.source_bytes, root_rvas, metadata['switch_leaf_rva'])
    import_slots={r['iat_rva']:r for r in image.imports}
    for root in program.roots:
        manifest=root['manifest']
        proof = verified['root_proofs'][str(root['rva'])]
        if manifest['switch_proof'] != proof:
            raise ValueError('per-root proof differs from its declared root')
        symbol = 'aot_entry' if root['rva'] == image.entry_rva else 'aot_window_proc_%x' % root['rva']
        if (manifest.get('root_rva') != root['rva'] or manifest.get('symbol') != symbol or
                root.get('symbol') != symbol or manifest.get('function_symbol') != symbol):
            raise ValueError('header root/function binding differs')
        packet = proof['candidate_packet']
        expected = normalize(packet['instructions'], image, packet['text_address'] - image.base,
                             bytes.fromhex(proof['text_bytes']), import_slots,
                             root['rva'], packet['switch_candidates'])
        if manifest['instructions'] != expected:
            raise ValueError('header instructions differ from the proven decoder packet')
        root_virtual=[];root_register=[]
        for ins in manifest['instructions']:
            rva,length=ins['rva'],ins['length'];kind=ins['kind']
            if type(rva) is not int or type(length) is not int or not 0<=rva<=len(image.data) or not 0<length<=15 or length>len(image.data)-rva:
                raise ValueError('instruction bounds/shape differs')
            if bytes(image.data[rva:rva+length])!=bytes.fromhex(ins['bytes']):raise ValueError('decoded bytes differ from original PE')
            if kind==3:root_virtual.append(lifter.validate_virtual_instruction(ins))
            elif kind==4:root_register.append(lifter.validate_register_instruction(ins))
            elif kind not in (0,1,2,5):raise ValueError('unknown instruction kind')
            if rva in merged and merged[rva]!=ins:raise ValueError('conflicting multi-root instruction')
            merged[rva]=ins
        if root_virtual!=manifest.get('virtual_calls') or root_register!=manifest.get('register_calls'):
            raise ValueError('root callsite table differs from actual instructions')
    for rva,ins in sorted(merged.items()):
        if ins['kind']==3:virtual.append(lifter.validate_virtual_instruction(ins))
        elif ins['kind']==4:register.append(lifter.validate_register_instruction(ins))
        if ins.get('iat_slot_rva'):
            slot=ins['iat_slot_rva']
            if ins['kind']!=1 or slot not in import_slots:raise ValueError('unbound IAT call')
            binding=import_slots[slot]
            if ins.get('signature')!=binding['signature'] or ins.get('target_rva')!=binding['target_rva']:
                raise ValueError('IAT metadata target/signature differs')
            calls.append({'call_rva':rva,'iat_rva':slot,'target_rva':binding['target_rva'],'signature':binding['signature']})
    if [merged[r] for r in sorted(merged)]!=program.root_manifest['instructions']:raise ValueError('multi-root merged side table differs')
    method_thunks=[THUNK_START+signature*4096 for signature in METHOD_SIGNATURES]
    thunks=sorted({r['target_rva'] for r in image.imports}|set(method_thunks))
    if len(thunks)!=len(image.imports)+len(METHOD_SIGNATURES):raise ValueError('import/method thunk collision')
    rows=[(r,i['length'],i['kind'],i.get('target_rva',0)) for r,i in sorted(merged.items())]
    for thunk in thunks:
        if any(r<=thunk<r+n or thunk<=r<thunk+1 for r,n,_,_ in rows):raise ValueError('synthetic RET overlaps actual guest code')
        rows.append((thunk,1,2,0))
    rows.sort()
    native='/* Exact per-image import closure and per-callsite metadata. */\n'
    for macro,ctype,name,records,fields in [
        ('AOT_IMPORT_CALL_COUNT','AotImportCall','aot_import_calls',calls,('call_rva','iat_rva','target_rva','signature')),
        ('AOT_VIRTUAL_CALL_COUNT','AotVirtualCall','aot_virtual_calls',virtual,('call_rva','base_register','slot')),
        ('AOT_REGISTER_CALL_COUNT','AotRegisterCall','aot_register_calls',register,('call_rva','operand_register')),
        ('AOT_IMPORT_TARGET_COUNT','AotImportTarget','aot_import_targets',image.imports,('target_rva','signature'))]:
        native+='#define %s %d\nstatic const %s %s[]={\n'%(macro,len(records),ctype,name)
        native+=''.join('{'+','.join(str(r[f])+'u' for f in fields)+'},\n' for r in records)
        native+=('' if records else '{'+','.join('0' for f in fields)+'},\n')+'};\n'
    if write:(program.out/'native_imports.h').write_text(native)
    observations=[]
    for name,record in sorted(metadata['observations'].items()):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name):raise ValueError('invalid observation name')
        rva,size=record['rva'],record['size']
        if type(rva) is not int or type(size) is not int or not 0<=rva<=len(image.data) or not 0<size<=len(image.data)-rva:raise ValueError('observation outside image')
        observations.append((name,rva,size))
    pe,=struct.unpack_from('<I',program.source_bytes,0x3c)
    reloc_dir=struct.unpack_from('<II',program.source_bytes,pe+24+112+5*8);characteristics=struct.unpack_from('<H',program.source_bytes,pe+22)[0]
    text='/* Original preferred-base PE image including BSS, no host game state. */\n'
    text+='typedef struct {uint32_t rva;uint64_t value;} NativeRelocation;\n'
    text+='typedef struct {uint32_t iat_rva,target_rva;} NativeImport;\n'
    text+='typedef struct {const char *name;uint32_t rva,size;} NativeObservation;\n'
    text+='static const char kPeSha256[]="%s";\n'%program.source_sha256
    text+='static const uint64_t kPreferredBase=UINT64_C(%d);\n'%image.preferred_base
    text+='static const uint32_t kEntryRva=%du;\n'%image.entry_rva
    text+='static const int kCanRebase=%d;\n'%bool(reloc_dir[0] and reloc_dir[1] and not characteristics&1)
    text+='static const uint8_t kImageBytes[]={'+','.join(map(str,image.data))+'};\n'
    text+='static const uint8_t kImagePermissions[]={'+','.join(map(str,image.permissions))+'};\n'
    text+='static const NativeRelocation kRelocations[]={'+(','.join('{%du,UINT64_C(%d)}'%(r['rva'],r['old']) for r in image.relocations) or '{0,0}')+'};\n'
    text+='static const size_t kRelocationCount=%d;\n'%len(image.relocations)
    text+='static const NativeImport kImports[]={'+(','.join('{%du,%du}'%(r['iat_rva'],r['target_rva']) for r in image.imports) or '{0,0}')+'};\n'
    text+='static const size_t kImportCount=%d;\n'%len(image.imports)
    text+='static const uint32_t kThunks[]={'+','.join(str(r)+'u' for r in thunks)+'};\n'
    text+='static const size_t kThunkCount=%d;\n'%len(thunks)
    text+='static const uint32_t kD3DMethodThunks[]={'+','.join(str(r)+'u' for r in method_thunks)+'};\n'
    text+='static const AotInstruction kInstructions[]={'+','.join('{%du,%du,%du,0,UINT64_C(%d)}'%r for r in rows)+'};\n'
    text+='static const size_t kInstructionCount=%d;\n'%len(rows)
    text+='static const NativeObservation kObservations[]={'+(','.join('{"%s",%du,%du}'%r for r in observations) or '{0,0,0}')+'};\n'
    text+='static const size_t kObservationCount=%d;\n'%len(observations)
    for root in program.roots[1:]:text+='extern void *%s(void*,uint64_t,void*);\n'%root['symbol']
    text+='static const AotWindowCallback kCallbacks[]={'+','.join('{%du,AOT_WINDOW_WNDPROC,%s}'%(r['rva'],r['symbol']) for r in program.roots[1:])+'};\n'
    text+='static const size_t kCallbackCount=%d;\n'%len(program.roots[1:])
    text+='static const char kSaveName[]='+json.dumps(metadata['save_observation'])+';\n'
    if write:(program.out/'native_image.h').write_text(text)
    switch = verified['switch']
    jump = switch['jump_pc'] - image.base
    table = switch['table_pc'] - image.base
    targets = [pc - image.base for pc in switch['targets']]
    text += '\n/* Proven bytes and finite targets; profile does not authorize this list. */\n'
    text += 'static uint32_t aot_bind_image_switch(AotContext *ctx,uint64_t base) {\n'
    text += 'static const uint8_t bytes[]={' + ','.join(str(v) for v in bytes.fromhex(switch['table_bytes'])) + '};\n'
    text += 'static const uint32_t rvas[]={' + ','.join(str(v)+'u' for v in targets) + '};\n'
    text += 'uint64_t targets[sizeof rvas/sizeof *rvas];\n'
    text += 'if(base>UINT64_MAX-UINT64_C(%d))return AOT_INVALID;\n' % max(jump, table, *targets)
    text += 'for(size_t i=0;i<sizeof rvas/sizeof *rvas;i++)targets[i]=base+rvas[i];\n'
    text += 'uint32_t status=aot_configure_switch(ctx,base+UINT64_C(%d),targets,sizeof rvas/sizeof *rvas);\n' % jump
    text += 'return status?status:aot_bind_switch(ctx,base+UINT64_C(%d),bytes,sizeof bytes);\n}\n' % table
    if write:(program.out/'native_image.h').write_text(text)
    program.generated_headers={'native_imports.h':native,'native_image.h':text}
    program.virtual_calls=virtual;program.register_calls=register
    return calls,rows,observations
