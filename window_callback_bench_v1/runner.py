"""Bind an existing v6 App and callback proof before CPU-only measurement.

Only prepare compiles and runs the 32 untimed correctness cases. Measure refuses
any changed identity before launching the prepared O3 binaries. It includes
complete input reset/checksum and validation overhead, and never subtracts a
reset control or infers a game/ABI/GUI speedup.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import statistics
import struct
import subprocess
import sys
import traceback

from migration_v6 import build as app_build
from portable_app_v1.lift import source_closure
from window_switch_v1 import admission, profile
from window_inc_v1.loader import load_image

ROOT = Path(__file__).resolve().parents[1]
PREPARED = 'PASS_CALLBACK_BENCH_PREPARED'
MEASURED = 'PASS_CALLBACK_CPU_BASELINE_MEASURED'
RUNTIME = ('window_switch_v1/runtime.h', 'window_switch_v1/runtime_fields.inc',
           'window_switch_v1/runtime_impl.inc', 'window_bridge/window_runtime/runtime.h',
           'window_bridge/window_runtime/transaction_v1.c', 'memory_stage2/guest_memory.h')
OWN = tuple(ROOT/'window_callback_bench_v1'/n for n in
            ('__init__.py', '__main__.py', 'runner.py', 'benchmark.c'))
BASES = (0x140000000, 0x180000000)
STATE_SIZE, CONTEXT_SIZE, STACK_SIZE = 3504, 5792, 65536
MASK = (1 << 64)-1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key: '+key)
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, 'non-finite JSON: '+value))


def read(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 64*1024**2,
            'regular bounded JSON file required: '+str(p))
    return parse(p.read_bytes())


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False); stream.write('\n')


def identities(paths):
    return {str(Path(p)): sha(p) for p in sorted(set(map(Path, paths)))}


def unchanged(values):
    for name, digest in values.items():
        require(type(digest) is str and sha(name) == digest, 'identity changed: '+name)


def sources():
    return identities([*source_closure(list(OWN[:3])), *OWN, *(ROOT/n for n in RUNTIME)])


def bounded(iterations, rounds):
    require(type(iterations) is int and 1 <= iterations <= 65536, 'iterations must be integer 1..65536')
    require(type(rounds) is int and 1 <= rounds <= 20, 'rounds must be integer 1..20')


def native_host():
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'native Apple Silicon macOS required')
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required')


def fresh(path, excluded):
    p = Path(path).absolute()
    require(p == p.resolve() and not os.path.lexists(p), 'fresh real output path required')
    for other in excluded:
        other = Path(other).resolve()
        require(not p.is_relative_to(other) and not other.is_relative_to(p), 'output overlaps an input')
    p.mkdir(parents=True)
    return p


class Commands:
    def __init__(self, out):
        self.out, self.rows = out, []
        self.env = {k: os.environ[k] for k in ('HOME', 'TMPDIR') if k in os.environ}
        self.env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C')

    def run(self, argv, label, timeout=300):
        argv = list(map(str, argv))
        write(self.out/(label+'.started.json'), dict(argv=argv, cwd=str(ROOT)))
        try:
            result = subprocess.run(argv, cwd=ROOT, env=self.env, capture_output=True, timeout=timeout)
            row = dict(label=label, argv=argv, cwd=str(ROOT), returncode=result.returncode)
            streams = dict(stdout=result.stdout, stderr=result.stderr)
        except (subprocess.TimeoutExpired, OSError) as error:
            row = dict(label=label, argv=argv, cwd=str(ROOT), returncode=None, error=repr(error))
            streams = dict(stdout=getattr(error,'stdout',None) or b'', stderr=getattr(error,'stderr',None) or b'')
        for name in ('stdout', 'stderr'):
            target = self.out/(label+'.'+name); target.write_bytes(streams[name])
            row[name+'_path'], row[name+'_sha256'] = str(target), sha(target)
        self.rows.append(row); write(self.out/(label+'.command.json'), row)
        require(row['returncode'] == 0, 'command failed: '+label)
        return streams['stdout']


def header(image, root, config):
    switch = root['switch_proof']['switch']
    value = '/* Generated from frozen source PE, normalized instructions and proof. */\n'
    for name, number, ctype in (
        ('kProbeImageSize',len(image.data),'size_t'), ('kProbePageCount',len(image.permissions),'size_t'),
        ('kProbeRootRva',0x1000,'uint32_t'), ('kProbeStateRva',config['observations']['window_state']['rva'],'uint32_t'),
        ('kProbeResultRva',config['observations']['window_result']['rva'],'uint32_t'),
        ('kProbeJumpRva',switch['jump_pc']-image.base,'uint32_t'),
        ('kProbeTableRva',switch['table_pc']-image.base,'uint32_t'), ('kProbeTargetCount',8,'size_t')):
        value += 'static const %s %s=%du;\n'%(ctype,name,number)
    value += 'static const uint8_t kProbeTableBytes[]={'+','.join(map(str,bytes.fromhex(switch['table_bytes'])))+'};\n'
    value += 'static const uint32_t kProbeTargetRvas[]={'+','.join(str(pc-image.base)+'u' for pc in switch['targets'])+'};\n'
    value += 'static const AotInstruction kProbeInstructions[]={\n'+''.join(
        '{%du,%du,%du,0,UINT64_C(%d)},\n'%(r['rva'],r['length'],r['kind'],r.get('target_rva',0)) for r in root['instructions'])+'};\n'
    return value.encode()


def bind(product, probe):
    """Reconstruct PE mappings/header and bind raw probe runs to real objects."""
    product, probe = Path(product).resolve(strict=True), Path(probe).resolve(strict=True)
    app_build.verify(product)
    p = read(probe/'result.json'); native = read(product/'native/producer.json')
    require(p['status'] == 'PASS_REAL_ARM64_CALLBACK_TWO_BASES_O0_O3' and
            p['app'] == str(product) and p['successful_callbacks'] == p['translated_callback_executions'] == 32 and
            p['api_calls'] == p['gpu_executions'] == p['cocoa_app_executions'] == 0, 'probe scope differs')
    require(p['inputs_before'] == p['inputs_after'], 'probe inputs changed')
    unchanged(p['inputs_before']); unchanged(p['generated_inputs']); unchanged(p['compiler'])
    pe = product/'native/input.exe'; config = read(product/'native/profile.json')
    data = pe.read_bytes(); config, image, _ = profile.validate(data, config)
    require(image.preferred_base == BASES[0] and config['callback_rvas'] == [0x1000], 'unsupported input profile/base')
    manifest = product/'native/compiler/window-proc-1000/manifest.json'; root = read(manifest)
    require(root['input_sha256'] == sha(pe) == p['pe_sha256'] and root['root_rva'] == 0x1000 and
            root['symbol'] == 'aot_window_proc_1000', 'callback root identity differs')
    proof = root['switch_proof']
    admission.validate_window_switch(proof, data, proof['candidate_packet'], 0x1000,
                                     config['switch_leaf_rva'], [image.entry_rva,0x1000])
    require(proof['switch']['count'] == 8, 'eight-way proof required')
    require(root['instructions'] == sorted(root['instructions'],key=lambda r:r['rva']), 'unordered instruction table')
    for row in root['instructions']:
        require(bytes(image.data[row['rva']:row['rva']+row['length']]).hex() == row['bytes'], 'instruction bytes differ')
    require(header(image,root,config) == (probe/'callback_probe_input.h').read_bytes(), 'generated header differs from PE/proof')
    paths = {product/'result.json', probe/'result.json', pe, product/'native/profile.json', manifest,
             product/'native/producer.json', probe/'callback_probe_input.h'}
    paths.update(map(Path,p['inputs_before'])); paths.update(map(Path,p['generated_inputs']));paths.update(map(Path,p['compiler']))
    for name in RUNTIME:
        expected = sha(ROOT/name)
        require(p['native_runtime_identities'][name] == p['sources'][name] == expected, 'runtime/probe source differs: '+name)
        candidates = [(path,digest) for path,digest in native['compile_inputs_before'].items() if path.endswith('/'+name)]
        require(len(candidates) == 1 and candidates[0][1] == expected and sha(candidates[0][0]) == expected,
                'runtime/product source differs: '+name)
        paths.add(Path(candidates[0][0]))
    objects = {}
    for level in ('O0','O3'):
        obj = Path(root['objects'][level]['path'])
        require(obj.parent == manifest.parent and sha(obj) == root['objects'][level]['sha256'] and
                sha(probe/'inputs'/(level+'.o')) == sha(obj), 'callback object differs')
        objects[level] = str(obj); paths.add(obj)
    require(len(p['records']) == 4, 'probe record count differs')
    goldens = {}
    for base in BASES:
        label = 'preferred' if base == BASES[0] else 'rebased'
        mapped = load_image(data,load_base=base)
        require((probe/(label+'-image.bin')).read_bytes() == bytes(mapped.data) and
                (probe/(label+'-permissions.bin')).read_bytes() == bytes(mapped.permissions), 'mapped PE bytes differ')
        paths.update([probe/(label+'-image.bin'),probe/(label+'-permissions.bin')])
        for level in ('O0','O3'):
            key = label+'-'+level
            matches = [r for r in p['records'] if r['base'] == base and r['optimization'] == level]
            require(len(matches) == 1, 'duplicate/missing probe matrix record')
            parsed = probe/key/'parsed.json'; require(str(parsed) == matches[0]['parsed'] and sha(parsed) == matches[0]['parsed_sha256'], 'probe parsed identity differs')
            commands = [r for r in p['commands'] if r['label'] == key+'-run']; require(len(commands) == 1, 'probe command missing')
            command = commands[0]; require(command['returncode'] == 0, 'probe command failed')
            for stream in ('stdout','stderr'):
                file = probe/(key+'-run.'+stream); require(str(file) == command[stream+'_path'] and sha(file) == command[stream+'_sha256'], 'probe raw log differs'); paths.add(file)
            raw = parse((probe/(key+'-run.stdout')).read_bytes()); recorded = read(parsed)
            require(raw['base'] == recorded['base'] == base and len(raw['cases']) == len(recorded['cases']) == 8, 'probe cases differ')
            paths.add(parsed); cases = []
            for index,(a,b) in enumerate(zip(raw['cases'],recorded['cases'])):
                require(all(b.get(k) == v for k,v in a.items()), 'parsed case differs from raw stdout')
                binary = probe/key/('case-%d.bin'%index); payload = binary.read_bytes()
                require(str(binary) == b['response_path'] and sha(binary) == b['response_sha256'] and
                        len(payload) == STATE_SIZE+len(mapped.data)+STACK_SIZE, 'golden response identity differs')
                require(a['initial_position'] == index and a['status'] == a['fault']['status'] == a['call_depth'] == a['rejected_api_calls'] == 0 and
                        a['returned'] == a['switch_commits'] == a['call_commits'] == 1 and a['ret_commits'] == 2 and
                        a['steps'] == len(a['trace']), 'invalid raw callback completion')
                expected = bytearray(mapped.data); after = min(index+1,7); changed = int(after!=index)
                struct.pack_into('<II',expected,config['observations']['window_state']['rva']+8,after,changed)
                struct.pack_into('<I',expected,config['observations']['window_result']['rva']+12,1)
                struct.pack_into('<I',expected,config['observations']['window_result']['rva']+56,changed)
                require(payload[STATE_SIZE:STATE_SIZE+len(mapped.data)] == expected, 'unexpected golden image effects')
                paths.add(binary); cases.append(dict(path=str(binary),sha256=sha(binary),case=a))
            goldens[key] = cases
        for i in range(8):
            require(Path(goldens[label+'-O0'][i]['path']).read_bytes() == Path(goldens[label+'-O3'][i]['path']).read_bytes(), 'golden O0/O3 differ')
    return dict(product=str(product),probe=str(probe),product_receipt_sha256=sha(product/'result.json'),
                probe_receipt_sha256=sha(probe/'result.json'),objects=objects,goldens=goldens,
                image_size=len(image.data),inputs=identities(paths))


def validate_response(value, directory, golden, base, mode, iterations, rounds, image_size):
    bounded(iterations,rounds)
    require(mode in ('check','measure'),'unknown benchmark mode')
    directory=Path(directory)
    for name in ('base','state_size','context_size','image_size','stack_size','iterations','rounds',
                 'warmup_iterations_per_scenario_path','actual_callback_executions','timed_callback_executions',
                 'untimed_callback_executions','reset_control_iterations','all_reset_calls','timer_calls',
                 'clock_resolution_queries','wall_resolution_ns','thread_cpu_resolution_ns',
                 'reset_bytes_per_iteration','app_executions','gpu_executions'):
        require(type(value[name]) is int and value[name]>=0,'invalid integer response field: '+name)
    require(value['status'] == ('PASS_CALLBACK_CPU_CHECK' if mode == 'check' else 'PASS_CALLBACK_CPU_MEASURE') and
            value['mode'] == mode and value['base'] == base and value['state_size'] == STATE_SIZE and
            value['image_size'] == image_size and value['stack_size'] == STACK_SIZE and len(value['cases']) == 8,
            'benchmark response shape differs')
    for i,(case,gold) in enumerate(zip(value['cases'],golden)):
        for name in ('initial_position','position','moves','draws','keydowns','dirty','status','returned','call_depth','steps','switch_commits','rejected_api_calls'):
            require(type(case[name]) is int and case[name] == gold['case'][name], 'benchmark semantic result differs: '+name)
        require(case['initial_position'] == i and case['response'] == 'case-%d.bin'%i, 'benchmark output path differs')
        require((directory/case['response']).read_bytes() == Path(gold['path']).read_bytes(), 'full State/image/stack differs from golden')
        for name in ('checksum','reset_checksum'):
            require(type(case[name]) is int and 0<=case[name]<=MASK,'invalid checksum word')
        if mode=='measure':
            require(case['timed_final_response']=='final-case-%d.bin'%i,'final output path differs')
            require((directory/case['timed_final_response']).read_bytes()==Path(gold['path']).read_bytes(),
                    'actual timed final State/image/stack differs from golden')
        else:
            require(case['timed_final_response'] is None,'check has a timed final response')
    expected_count = 0 if mode == 'check' else rounds*16
    require(len(value['records']) == expected_count and value['iterations'] == iterations and value['rounds'] == rounds,
            'measurement shape differs')
    expected_callbacks = 8 if mode == 'check' else 8+8*256+rounds*8*(iterations+1)
    timed=0 if mode=='check' else rounds*8*iterations
    untimed=expected_callbacks-timed
    require(value['actual_callback_executions']==expected_callbacks and value['timed_callback_executions']==timed and
            value['untimed_callback_executions']==untimed and value['reset_control_iterations']==expected_callbacks-8 and
            value['all_reset_calls']==2*timed+2*(untimed-8)+8,'actual callback/reset count differs')
    require(value['timer_calls']==4*expected_count and value['clock_resolution_queries']==(2 if mode=='measure' else 0) and
            value['warmup_iterations_per_scenario_path']==(256 if mode=='measure' else 0),'timer/warmup count differs')
    require(value['context_size']==CONTEXT_SIZE and value['reset_bytes_per_iteration']==STATE_SIZE+CONTEXT_SIZE+image_size+STACK_SIZE,
            'reset payload extent differs')
    require(value['app_executions']==value['gpu_executions']==0 and value['legacy_block_fastpath']=='NOT_INTEGRATED',
            'unsupported benchmark scope')
    for name in ('reset_included','checksum_included','key_invariants_per_iteration','full_comparison_per_batch','reset_control_not_subtracted'):
        require(value[name] is True,'measurement inclusion policy differs: '+name)
    for name in ('lto','transaction_trace_hooks','outer_callback_abi_invoked'):
        require(value[name] is False,'unsupported measurement scope: '+name)
    require(value['wall_clock']=='CLOCK_MONOTONIC' and value['cpu_clock']=='CLOCK_THREAD_CPUTIME_ID' and
            value['clock_order']=='wall_start,cpu_start,batch,cpu_end,wall_end','clock contract differs')
    for name in ('wall_resolution_ns','thread_cpu_resolution_ns'):
        require(value[name]>0 if mode=='measure' else value[name]==0,'clock resolution differs')
    expected = []
    for round_index in range(rounds if mode == 'measure' else 0):
        for offset in range(8):
            scenario = (round_index+offset)%8
            for position in range(2):
                path = 'execute' if ((round_index+scenario+position)&1) == 0 else 'reset'
                expected.append((round_index,scenario,path))
    for row,identity in zip(value['records'],expected):
        require((row['round'],row['scenario'],row['path']) == identity, 'record order/matrix differs')
        for key in ('round','scenario','iterations','wall_ns','thread_cpu_ns','checksum',
                    'steps_per_iteration','switch_commits_per_iteration','rejected_api_calls'):
            require(type(row[key]) is int, 'noninteger measurement field: '+key)
        require(row['iterations'] == iterations and row['wall_ns'] > 0 and row['thread_cpu_ns'] > 0, 'invalid clock/count')
        expected_word = value['cases'][row['scenario']]['checksum' if row['path']=='execute' else 'reset_checksum']
        require(row['checksum'] == (expected_word*iterations)&MASK, 'batch checksum differs')
        require(row['steps_per_iteration']==(value['cases'][row['scenario']]['steps'] if row['path']=='execute' else 0) and
                row['switch_commits_per_iteration']==(1 if row['path']=='execute' else 0) and
                row['rejected_api_calls']==0 and row['complete_post_batch_match'] is True,'batch completion differs')


def summarize(runs):
    result = []
    for run in runs:
        value = read(run['parsed'])
        for scenario in range(8):
            for path in ('execute','reset'):
                rows = [r for r in value['records'] if r['scenario'] == scenario and r['path'] == path]
                entry = dict(base=run['base'],scenario=scenario,path=path,samples=len(rows))
                for clock in ('wall_ns','thread_cpu_ns'):
                    samples = [r[clock]/r['iterations'] for r in rows]
                    entry[clock+'_per_iteration'] = dict(median=statistics.median(samples),min=min(samples),max=max(samples))
                result.append(entry)
    return result


def prepare(product, probe, out):
    native_host(); product,probe = Path(product).resolve(strict=True),Path(probe).resolve(strict=True)
    out = fresh(out,[product,probe]); command = Commands(out); checks=[]; before=sources()
    write(out/'started.json',dict(status='PREPARING_NOT_ACCEPTED',sources=before,product=str(product),probe=str(probe)))
    try:
        binding = bind(product,probe); inputs = dict(binding['inputs']); copies = out/'inputs'; copies.mkdir()
        for name in ('callback_probe_input.h','preferred-image.bin','preferred-permissions.bin','rebased-image.bin','rebased-permissions.bin'):
            shutil.copyfile(probe/name,copies/name)
        for level,obj in binding['objects'].items(): shutil.copyfile(obj,copies/(level+'.o'))
        compiler = command.run(['/usr/bin/xcrun','--find','clang'],'compiler-path').decode().strip()
        sdk = command.run(['/usr/bin/xcrun','--show-sdk-path'],'sdk-path').decode().strip()
        require(Path(compiler).is_absolute() and Path(compiler).is_file() and Path(sdk).is_dir(), 'compiler/SDK absent')
        command.run([compiler,'--version'],'compiler-version')
        inputs.update(identities([Path(compiler),Path(sys.executable).resolve(),Path(sdk)/'SDKSettings.json']))
        flags=[compiler,'-std=c11','-arch','arm64','-isysroot',sdk,'-O3','-Wall','-Wextra','-Werror',
               '-DAOT_WINDOW_SWITCH_V1=1','-I',str(copies),'-I',str(ROOT/'window_switch_v1')]
        source=ROOT/'window_callback_bench_v1/benchmark.c'
        raw=command.run([*flags,'-M','-MT','bench',source],'dependencies')
        require(raw.startswith(b'bench:'),'unexpected dependency target')
        deps=[Path(n).resolve(strict=True) for n in shlex.split(raw.decode().replace('\\\n',' ').split(':',1)[1])]
        require({source,*(ROOT/n for n in RUNTIME),copies/'callback_probe_input.h'} <= set(deps),'missing actual compiler dependency')
        dependency_hashes=identities(deps); binaries={}
        for level in ('O0','O3'):
            binary=out/('benchmark-'+level); command.run([*flags,source,copies/(level+'.o'),'-o',binary],'compile-'+level)
            require(binary.read_bytes()[:8] == struct.pack('<II',0xfeedfacf,0x100000c),'native ARM64 benchmark required')
            binaries[level]=str(binary)
        require(command.run([*flags,'-M','-MT','bench',source],'dependencies-after')==raw,'compile dependencies changed')
        for base in BASES:
            label='preferred' if base==BASES[0] else 'rebased'
            for level in ('O0','O3'):
                key=label+'-'+level; directory=out/key;directory.mkdir()
                output=command.run([binaries[level],'--check',copies/(label+'-image.bin'),copies/(label+'-permissions.bin'),hex(base),directory,1,1],'check-'+key)
                value=parse(output);validate_response(value,directory,binding['goldens'][key],base,'check',1,1,binding['image_size'])
                write(directory/'parsed.json',value);checks.append(dict(label=label,base=base,optimization=level,output=str(directory),stdout=str(out/('check-'+key+'.stdout')),parsed=str(directory/'parsed.json')))
        unchanged(before);unchanged(inputs);unchanged(dependency_hashes)
        artifacts=identities([p for p in out.rglob('*') if p.is_file()])
        result=dict(schema=1,status=PREPARED,out=str(out),product=str(product),probe=str(probe),binding=binding,
                    sources_before=before,sources_after=sources(),inputs_before=inputs,inputs_after=identities(inputs),
                    compiler_dependencies=dependency_hashes,artifacts=artifacts,binaries=binaries,checks=checks,commands=command.rows,
                    correctness_callbacks=32,timed_callback_executions=0,app_executions=0,gpu_executions=0,
                    scope='Existing real lifted objects plus same transaction engine; rejecting API stubs. No full callback ABI dispatcher or fastpath.')
        write(out/'result.json',result);return result
    except BaseException as error:
        write(out/'failure.json',dict(status='PREPARATION_FAILED_NOT_ACCEPTED',error=repr(error),traceback=traceback.format_exc(),commands=command.rows,checks=checks));raise


def verify_prepared(prepared):
    prepared=Path(prepared).resolve(strict=True);value=read(prepared/'result.json')
    require(value['schema']==1 and value['status']==PREPARED and value['out']==str(prepared) and
            type(value['correctness_callbacks']) is int and value['correctness_callbacks']==32,'prepare status differs')
    for name in ('timed_callback_executions','app_executions','gpu_executions'):
        require(type(value[name]) is int and value[name]==0,'prepare must have no timing/App/GPU execution')
    require(value['sources_before']==value['sources_after']==sources() and value['inputs_before']==value['inputs_after'], 'prepare source/input identities differ')
    for name in ('sources_before','inputs_before','compiler_dependencies','artifacts'): unchanged(value[name])
    require(bind(value['product'],value['probe']) == value['binding'],'current product/probe binding differs')
    require(all(value['inputs_before'].get(p)==h for p,h in value['binding']['inputs'].items()),'prepare input coverage differs')
    expected_files={str(p) for p in prepared.rglob('*') if p.is_file() and p!=prepared/'result.json'}
    require(set(value['artifacts'])==expected_files,'prepare artifact coverage differs')
    require(all(Path(p).is_relative_to(prepared) and str(Path(p).resolve())==p for p in value['artifacts']),
            'prepare artifact escaped its output directory')
    require(value['binaries']=={level:str(prepared/('benchmark-'+level)) for level in ('O0','O3')},'prepared binary path differs')
    for binary in value['binaries'].values():
        require(binary in value['artifacts'] and Path(binary).read_bytes()[:8]==struct.pack('<II',0xfeedfacf,0x100000c),
                'prepared native ARM64 binary is not frozen')
    copies=prepared/'inputs';probe=Path(value['probe'])
    for name in ('callback_probe_input.h','preferred-image.bin','preferred-permissions.bin','rebased-image.bin','rebased-permissions.bin'):
        require(value['artifacts'].get(str(copies/name))==value['binding']['inputs'][str(probe/name)],'prepared input copy differs')
    for level,path in value['binding']['objects'].items():
        require(value['artifacts'].get(str(copies/(level+'.o')))==value['binding']['inputs'][path],'prepared object copy differs')
    compiler=(prepared/'compiler-path.stdout').read_text().strip();sdk=(prepared/'sdk-path.stdout').read_text().strip()
    require(compiler in value['inputs_before'] and str(Path(sys.executable).resolve()) in value['inputs_before'] and
            str(Path(sdk)/'SDKSettings.json') in value['inputs_before'],'prepared tool identity missing')
    flags=[compiler,'-std=c11','-arch','arm64','-isysroot',sdk,'-O3','-Wall','-Wextra','-Werror',
           '-DAOT_WINDOW_SWITCH_V1=1','-I',str(copies),'-I',str(ROOT/'window_switch_v1')]
    source=ROOT/'window_callback_bench_v1/benchmark.c'
    expected_commands=[('compiler-path',['/usr/bin/xcrun','--find','clang']),
                       ('sdk-path',['/usr/bin/xcrun','--show-sdk-path']),('compiler-version',[compiler,'--version']),
                       ('dependencies',[*flags,'-M','-MT','bench',str(source)])]
    expected_commands += [('compile-'+level,[*flags,str(source),str(copies/(level+'.o')),'-o',value['binaries'][level]]) for level in ('O0','O3')]
    expected_commands += [('dependencies-after',[*flags,'-M','-MT','bench',str(source)])]
    for base in BASES:
        label='preferred' if base==BASES[0] else 'rebased'
        for level in ('O0','O3'):
            key=label+'-'+level
            expected_commands.append(('check-'+key,[value['binaries'][level],'--check',str(copies/(label+'-image.bin')),
                                      str(copies/(label+'-permissions.bin')),hex(base),str(prepared/key),'1','1']))
    require(len(value['commands'])==len(expected_commands),'prepare command count differs')
    for row,(label,argv) in zip(value['commands'],expected_commands):
        require(row['label']==label and row['argv']==argv and row['cwd']==str(ROOT) and
                type(row['returncode']) is int and row['returncode']==0,'prepare command invocation differs')
        require(row==read(prepared/(label+'.command.json')) and
                read(prepared/(label+'.started.json'))==dict(argv=argv,cwd=str(ROOT)),'prepare command record differs')
        for stream in ('stdout','stderr'):
            path=str(prepared/(label+'.'+stream))
            require(row[stream+'_path']==path and row[stream+'_sha256']==value['artifacts'].get(path),'prepare command log differs')
    raw=(prepared/'dependencies.stdout').read_bytes()
    require(raw.startswith(b'bench:') and raw==(prepared/'dependencies-after.stdout').read_bytes(),'prepare dependencies changed')
    dependencies=[Path(n).resolve(strict=True) for n in shlex.split(raw.decode().replace('\\\n',' ').split(':',1)[1])]
    require(identities(dependencies)==value['compiler_dependencies'] and
            {source,*(ROOT/n for n in RUNTIME),copies/'callback_probe_input.h'}<=set(dependencies),'prepare dependency coverage differs')
    require(len(value['checks'])==4 and {(r['base'],r['optimization']) for r in value['checks']}=={(b,l) for b in BASES for l in ('O0','O3')},'prepare correctness matrix differs')
    for run in value['checks']:
        label='preferred' if run['base']==BASES[0] else 'rebased';key=label+'-'+run['optimization']
        require(run['label']==label and run['output']==str(prepared/key) and run['parsed']==str(prepared/key/'parsed.json') and
                run['stdout']==str(prepared/('check-'+key+'.stdout')),'prepare correctness paths differ')
        raw=parse(Path(run['stdout']).read_bytes());require(raw==read(run['parsed']),'prepare parsed/raw mismatch')
        validate_response(raw,Path(run['output']),value['binding']['goldens'][run['label']+'-'+run['optimization']],run['base'],'check',1,1,value['binding']['image_size'])
    return value


def measure(prepared, out, iterations=4096, rounds=12):
    native_host();bounded(iterations,rounds);prepared=Path(prepared).resolve(strict=True)
    # All acceptance/identity checks happen before creating the measurement
    # output or launching any timed process.
    ready=verify_prepared(prepared); receipt=sha(prepared/'result.json')
    out=fresh(out,[prepared,ready['product'],ready['probe']]);command=Commands(out);runs=[]
    write(out/'started.json',dict(status='MEASURING_NOT_ACCEPTED',prepared=str(prepared),prepared_receipt_sha256=receipt,iterations=iterations,rounds=rounds))
    try:
        for base in BASES:
            label='preferred' if base==BASES[0] else 'rebased';directory=out/label;directory.mkdir()
            copies=prepared/'inputs'
            raw=command.run([ready['binaries']['O3'],'--measure',copies/(label+'-image.bin'),copies/(label+'-permissions.bin'),hex(base),directory,iterations,rounds],'measure-'+label)
            value=parse(raw);validate_response(value,directory,ready['binding']['goldens'][label+'-O3'],base,'measure',iterations,rounds,ready['binding']['image_size'])
            write(directory/'parsed.json',value);runs.append(dict(label=label,base=base,optimization='O3',output=str(directory),stdout=str(out/('measure-'+label+'.stdout')),parsed=str(directory/'parsed.json')))
        require(sha(prepared/'result.json')==receipt,'prepare receipt changed');verify_prepared(prepared)
        result=dict(schema=1,status=MEASURED,out=str(out),prepared=str(prepared),prepared_receipt_sha256=receipt,
                    iterations=iterations,rounds=rounds,commands=command.rows,runs=runs,summary=summarize(runs),
                    artifacts=identities([p for p in out.rglob('*') if p.is_file()]),
                    sources_before=ready['sources_before'],sources_after=sources(),inputs_before=ready['inputs_before'],inputs_after=identities(ready['inputs_before']),
                    reset_included=True,reset_subtracted=False,app_executions=0,gpu_executions=0,
                    limitations=['CPU callback component only; no full aot_wndproc_invoke ABI, Cocoa, GPU or game comparison.',
                                 'Includes complete reset, checksum and per-iteration validation; allocation, setup and IO outside timed batches.',
                                 'All samples retained, no reset subtraction; O3 only, no optimization/speedup claim.',
                                 'Warm-cache sequential single-host samples, no affinity/frequency/thermal isolation guarantee.'])
        write(out/'result.json',result);return result
    except BaseException as error:
        write(out/'failure.json',dict(status='MEASUREMENT_FAILED_NOT_ACCEPTED',error=repr(error),traceback=traceback.format_exc(),commands=command.rows,runs=runs));raise
