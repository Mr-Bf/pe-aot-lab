"""Pure row-multiplicity checks; no commands, library loads or compilation."""
import json
from pathlib import Path
from native_window.present_diag_v1 import accept_build_v2 as a

RAW=b'a.o: #deps 2, deps mtime 1 (VALID)\n    a.h\n    b.h\n\nb.o: #deps 1, deps mtime 2 (VALID)\n    b.h\n'
def main():
    root=Path('/private/tmp/present-diag-parser-v2');names,blocks=a.parse_dep_blocks(RAW,root)
    a.need(names=={'a.h','b.h'} and len(blocks)==2 and sum(b['row_count'] for b in blocks.values())==3,'normal blocks')
    repeated=RAW.replace(b'    a.h\n',b'    b.h\n')
    names,blocks=a.parse_dep_blocks(repeated,root)
    first=blocks[str(root/'a.o')]
    a.need(names=={'b.h'} and first['row_count']==2 and first['unique_spelling_count']==1 and first['duplicate_rows']==1 and first['repeated_paths']=={'b.h':2},'literal duplicate header allowed and preserved')
    bad={'deleted_row':RAW.replace(b'    a.h\n',b''),'extra_row':RAW.replace(b'    a.h\n',b'    a.h\n    a.h\n'),
        'duplicate_target':RAW.replace(b'b.o:',b'a.o:'),'alias_target':RAW.replace(b'b.o:',b'./a.o:'),
        'stale':RAW.replace(b'(VALID)',b'(STALE)',1),'orphan':b'    a.h\n'+RAW,
        'missing_count':RAW.replace(b'#deps 2,',b'#deps ,'),'empty_row':RAW.replace(b'    a.h\n',b'    \n'),
        'outside_target':RAW.replace(b'a.o:',b'../a.o:'),'empty':b''}
    for name,value in bad.items():
        try:a.parse_dep_blocks(value,root)
        except ValueError:continue
        raise ValueError('malformed dependency block accepted: '+name)
    actual=(a.ORIGINAL/'ninja-deps.log').read_bytes();a.need(a.sha(actual)==a.PINS['ninja-deps.log'],'preserved real dependency log')
    _,blocks=a.parse_dep_blocks(actual.split(b'\n',1)[1])
    targets=len(blocks);duplicate_blocks=sum(x['duplicate_rows']>0 for x in blocks.values());duplicates=sum(x['duplicate_rows'] for x in blocks.values())
    a.need((targets,duplicate_blocks,duplicates)==(135,79,362),'observed actual log multiplicity')
    return {'status':'PASS_PURE_MULTIPLICITY_PARSER_V2','synthetic_positive':2,'rejections':sorted(bad),
        'actual_targets':targets,'actual_targets_with_duplicate_rows':duplicate_blocks,'actual_duplicate_rows':duplicates,
        'literal_dependency_rows':sum(x['row_count'] for x in blocks.values()),'compiler_commands':0,'library_loads':0,'guest_gui_gpu':0,
        'consumer_sha256':a.sha(Path(a.__file__).read_bytes()),'test_sha256':a.sha(Path(__file__).read_bytes())}
if __name__=='__main__':print(json.dumps(main(),sort_keys=True))
