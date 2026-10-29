"""Pure rejection tests for actual Ninja dependency-block completeness."""
import json
from native_window.present_diag_v1.build import parse_dep_blocks

RAW=b'a.o: #deps 2, deps mtime 1 (VALID)\n    a.h\n    b.h\n\nb.o: #deps 1, deps mtime 2 (VALID)\n    b.h\n'

def main():
    names,targets=parse_dep_blocks(RAW)
    if names!={'a.h','b.h'} or len(targets)!=2:raise RuntimeError('positive fixture')
    bad={
        'deleted_header':RAW.replace(b'    a.h\n',b''),
        'duplicate_header':RAW.replace(b'    a.h\n',b'    b.h\n'),
        'duplicate_target':RAW.replace(b'b.o:',b'a.o:'),
        'stale':RAW.replace(b'(VALID)',b'(STALE)',1),
        'orphan':b'    a.h\n'+RAW,
        'inflated_count':RAW.replace(b'#deps 2',b'#deps 3'),
        'empty':b'',
    }
    for label,raw in bad.items():
        try:parse_dep_blocks(raw)
        except ValueError:continue
        raise RuntimeError('accepted malformed block '+label)
    print(json.dumps({'status':'PASS_PURE_NINJA_BLOCK_GATES','positive':1,'rejections':sorted(bad),
                      'compiler_invocations':0,'new_guest_gui_gpu_executions':0},sort_keys=True))

if __name__=='__main__':main()
