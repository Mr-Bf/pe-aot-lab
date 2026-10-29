#!/usr/bin/env python3
"""Materialize/verify the official LLVM source release plus CMake source asset.

The release is bound to HTTPS asset metadata and full SHA256, not claimed to
reconstruct the complete Git commit tree. No partial input is accepted.
"""
import json
from pathlib import Path
import tempfile
from graphics_stage5 import bootstrap_dxmt as b
from graphics_stage5 import fetch_llvm_release as download

DESTINATION=b.WORK/'sources/llvm-release-15.0.7'

def assets():
    result=[]
    for name,size in download.ASSETS.items():
        metadata=download.OUT/(name+'.json');archive=download.WORK/name
        b.require(metadata.is_file() and archive.is_file(),'official LLVM release download not complete: '+name)
        record=json.loads(metadata.read_text())
        b.require(record.get('status')=='DOWNLOADED_NOT_EXTRACTED' and record['identity']['url']==download.BASE+name
                  and record['identity']['size']==size and archive.stat().st_size==size and
                  b.sha(archive)==record['sha256'],'LLVM release asset identity differs: '+name)
        result.append({'name':name,'archive':str(archive),'sha256':record['sha256'],
                       'url':record['identity']['url'],'metadata':str(metadata),'metadata_sha256':b.sha(metadata)})
    return result

def materialize_and_verify():
    entries=assets();parent=DESTINATION.parent;parent.mkdir(parents=True,exist_ok=True)
    # Always reconstruct the expected source from complete bound archives.
    # Existing extraction stamps are never used as content proof.
    with tempfile.TemporaryDirectory(prefix='.release-source-',dir=parent) as temporary:
        private=Path(temporary);expected=private/'expected';expected.mkdir()
        for entry in entries:
            prefix=entry['name'].removesuffix('.tar.xz');extracted=private/prefix
            b.extract_source_archive(Path(entry['archive']),extracted)
            extracted.rename(expected/('llvm' if prefix.startswith('llvm-') else 'cmake'))
        marker={'schema':1,'version':'15.0.7','source_kind':'official-release-assets',
                'associated_git_commit':b.LLVM,'complete_git_tree_verified':False,'assets':entries}
        (expected/'.release-source.json').write_text(json.dumps(marker,indent=2)+'\n')
        identity=b.tree_identity(expected)
        if not DESTINATION.exists():expected.rename(DESTINATION)
        b.require(b.tree_identity(DESTINATION)==identity,'LLVM source differs from official release assets')
    return {'name':'llvm-project','repo':'llvm/llvm-project','commit':b.LLVM,'source':str(DESTINATION),
            'kind':'official-llvm-15.0.7-release-assets','assets':entries,
            'source_script_sha256':b.sha(__file__),'complete_git_tree_verified':False,
            'scope':'LLVM and CMake release source only; not a full monorepo or signed provenance claim'}

if __name__=='__main__':print(json.dumps(materialize_and_verify(),indent=2))
