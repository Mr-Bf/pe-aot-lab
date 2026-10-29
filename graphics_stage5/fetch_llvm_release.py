#!/usr/bin/env python3
"""Download official LLVM 15 source assets in checked, resumable byte ranges.

This is an HTTPS origin/length/ETag/content identity record, not a signature
verification. It never publishes or treats a partial archive as complete.
"""
import hashlib
import json
from pathlib import Path
import urllib.request
import urllib.parse

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT.parents[1]/'work/graphics-stage5/downloads'
OUT=ROOT/'build/graphics-stage5/llvm-release'
ASSETS={'llvm-15.0.7.src.tar.xz':52935892,'cmake-15.0.7.src.tar.xz':6972}
BASE='https://github.com/llvm/llvm-project/releases/download/llvmorg-15.0.7/'
CHUNK=2*1024*1024

def require(value,message):
    if not value:raise ValueError(message)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def request(url,**headers):
    return urllib.request.Request(url,headers={'User-Agent':'pe-aot-lab-source-download',**headers})
def fetch(name,size):
    url=BASE+name;target=WORK/name;partial=target.with_suffix(target.suffix+'.partial')
    state=OUT/(name+'.json')
    with urllib.request.urlopen(urllib.request.Request(url,method='HEAD'),timeout=90) as response:
        require(response.status==200,'release HEAD failed')
        final=response.url;parsed=urllib.parse.urlparse(final)
        require(parsed.scheme=='https' and parsed.hostname=='release-assets.githubusercontent.com','unexpected release asset origin')
        require(int(response.headers['Content-Length'])==size,'official release asset size differs')
        etag=response.headers.get('ETag');require(bool(etag),'release asset ETag absent')
    identity={'url':url,'size':size,'etag':etag,'asset_host':parsed.hostname,'asset_path':parsed.path}
    if state.exists():
        record=json.loads(state.read_text());require(record['identity']==identity,'release identity changed since prior attempt')
    else:
        require(not partial.exists() and not target.exists(),'release file without origin record')
        record={'status':'DOWNLOADING','identity':identity,'chunks':[],'script_sha256':sha(__file__),
                'trust_limit':'official HTTPS release asset; not GPG signature or Git tree verification'}
    if target.exists():
        require(record['status']=='DOWNLOADED_NOT_EXTRACTED' and target.stat().st_size==size and
                sha(target)==record['sha256'],'completed release file differs')
        return record
    offset=partial.stat().st_size if partial.exists() else 0
    require(offset<=size and sum(c['size'] for c in record['chunks'])==offset,'partial length/checkpoint differs')
    if partial.exists():
        with partial.open('rb') as stream:
            for chunk in record['chunks']:
                require(hashlib.sha256(stream.read(chunk['size'])).hexdigest()==chunk['sha256'],'partial content differs')
    record['status']='DOWNLOADING';state.write_text(json.dumps(record,indent=2)+'\n')
    try:
        while offset<size:
            end=min(size-1,offset+CHUNK-1)
            with urllib.request.urlopen(request(final,Range=f'bytes={offset}-{end}',**{'If-Match':etag}),timeout=90) as response:
                require(response.status==206,'server did not honor byte range')
                require(response.headers.get('Content-Range')==f'bytes {offset}-{end}/{size}','Content-Range differs')
                require(response.headers.get('ETag')==etag,'ETag changed during transfer')
                data=response.read(end-offset+2)
                require(len(data)==end-offset+1,'range body length differs')
            with partial.open('ab') as stream:stream.write(data)
            record['chunks'].append({'offset':offset,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
            offset+=len(data);state.write_text(json.dumps(record,indent=2)+'\n')
            print(json.dumps({'asset':name,'downloaded':offset,'total':size}),flush=True)
        require(partial.stat().st_size==size,'release size differs')
        record.update(status='DOWNLOADED_NOT_EXTRACTED',sha256=sha(partial),archive=str(target))
        partial.replace(target);state.write_text(json.dumps(record,indent=2)+'\n')
        return record
    except Exception as error:
        record.update(status='DOWNLOAD_FAILED_RESUMABLE',error=str(error))
        state.write_text(json.dumps(record,indent=2)+'\n')
        first=OUT/(name+'.first-failure.json')
        if not first.exists():first.write_text(json.dumps(record,indent=2)+'\n')
        raise

if __name__=='__main__':
    WORK.mkdir(parents=True,exist_ok=True);OUT.mkdir(parents=True,exist_ok=True)
    for name,size in ASSETS.items():fetch(name,size)
