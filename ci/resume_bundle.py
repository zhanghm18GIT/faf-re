"""Bounded exact-file native cache for trusted fixed public-source build outputs.
No COFF/path-content scan, no arbitrary-source isolation or cache privacy claim.
"""
from pathlib import Path, PurePosixPath
import hashlib,json,os,stat,zipfile
import resume_transport as transport
import exact_timestamp
from checkpoint import relative_name
MAX_TOTAL=3_221_225_472
MAX_MANIFEST=25_165_824
MAX_MEMBERS=100_000
MANIFEST='RESUME_MANIFEST.json'
class ResumeError(ValueError):pass
def need(ok,message):
    if not ok:raise ResumeError(message)
def rel(value):
    try:return relative_name(value)
    except Exception as exc:raise ResumeError('Invalid Windows relative name') from exc
def path(root,name,missing=False):
    root=Path(root).absolute();p=root/rel(name)
    transport.regular(p,missing=missing)
    return p
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()
def record(root,name):
    p=path(root,name);before=p.stat();digest=sha(p);after=p.stat()
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'File changed during inventory')
    return {'path':name,'size':after.st_size,'sha256':digest,'mtime_ns':after.st_mtime_ns}
def records(root,names):
    names=sorted(names);need(len(names)==len({n.casefold() for n in names})<=MAX_MEMBERS,'Duplicate/oversized inventory')
    return [record(root,n) for n in names]
def stat_identity(p):
    st=p.lstat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not getattr(st,'st_file_attributes',0)&0x400,'Source file type changed')
    return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)
def source_records(root,names,verified):
    if verified is None:
        rows=records(root,names);return rows,{r['path']:stat_identity(Path(root)/r['path']) for r in rows}
    need(set(verified)=={'records','stats'},'Fresh source record shape')
    rows=verified['records'];stats=verified['stats']
    need([r['path'] for r in rows]==sorted(names) and set(stats)==set(names),'Fresh source inventory mismatch')
    for row in rows:
        validate_record(row)
        need(stat_identity(Path(root)/rel(row['path']))==tuple(stats[row['path']]),'Source changed after caller hash')
        need(row['size']==stats[row['path']][2] and row['mtime_ns']==stats[row['path']][3],'Fresh source stat mismatch')
    return rows,stats
def same_content(actual,expected):
    return all(actual[k]==expected[k] for k in ['path','size','sha256'])
def validate_record(r):
    need(type(r) is dict and set(r)=={'path','size','sha256','mtime_ns'},'Record shape')
    rel(r['path']);need(type(r['size']) is int and 0<=r['size']<=MAX_TOTAL,'Record size')
    need(type(r['mtime_ns']) is int,'Record timestamp')
    need(type(r['sha256']) is str and len(r['sha256'])==64 and all(c in '0123456789abcdef' for c in r['sha256']),'Record digest')
def seal(destination,*,source,build,source_names,output_names,metadata,producer,external=None,verified_source=None,tick=lambda:None):
    destination=Path(destination);need(not destination.exists(),'Bundle already exists')
    source_rows,_=source_records(source,source_names,verified_source);output_rows=records(build,output_names)
    need(sum(r['size'] for r in output_rows)<=MAX_TOTAL,'Uncompressed bound')
    manifest={'schema':1,'metadata':metadata,'producer':producer,'source':source_rows,'outputs':output_rows,'external':external or []}
    raw=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode();need(len(raw)<=MAX_MANIFEST,'Manifest bound')
    try:
        with zipfile.ZipFile(destination,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=False) as z:
            z.writestr(MANIFEST,raw)
            for row in output_rows:
                tick();p=path(build,row['path']);need(record(build,row['path'])==row,'Output drift before seal')
                z.write(p,'build/'+row['path'])
                need(destination.stat().st_size<=transport.MAX_BYTES,'Compressed bound')
        with zipfile.ZipFile(destination) as z:
            for row in output_rows:
                tick();h=hashlib.sha256();count=0
                with z.open('build/'+row['path']) as member:
                    for block in iter(lambda:member.read(1<<20),b''):count+=len(block);h.update(block)
                need(count==row['size'] and h.hexdigest()==row['sha256'],'Sealed member differs from manifest')
        return transport.identity(destination)
    except BaseException:
        if destination.exists():destination.unlink()
        raise

def unique_pairs(pairs):
    d={}
    for k,v in pairs:need(k not in d,'Duplicate JSON key');d[k]=v
    return d

def restore(bundle,pin,*,source,build,source_names,output_names,metadata,producer,verify_external=lambda rows:need(rows==[],'Unexpected external records'),verified_source=None,tick=lambda:None):
    # External separately reviewed producer pin precedes all ZIP parsing.
    need(transport.identity(bundle)==transport.expected(pin),'Bundle receipt mismatch')
    with zipfile.ZipFile(bundle) as z:
        infos=z.infolist();names=[i.filename for i in infos]
        need(len(names)==len({n.casefold() for n in names})<=MAX_MEMBERS+1,'Duplicate/oversized ZIP inventory')
        for info in infos:
            need(info.compress_type in {zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED} and not info.flag_bits&1,'ZIP compression/encryption unsupported')
            need(stat.S_IFMT(info.external_attr>>16) in {0,stat.S_IFREG} and not info.is_dir(),'ZIP nonregular member')
        need(MANIFEST in names,'Manifest missing');mi=z.getinfo(MANIFEST)
        need(mi.file_size<=MAX_MANIFEST,'Manifest bound')
        m=json.loads(z.read(MANIFEST),object_pairs_hook=unique_pairs)
        need(set(m)=={'schema','metadata','producer','source','outputs','external'} and m['schema']==1,'Manifest shape')
        need(m['metadata']==metadata and m['producer']==producer,'Producer/config/source/tool identity mismatch')
        verify_external(m['external'])
        for key,expected in [('source',source_names),('outputs',output_names)]:
            need(type(m[key]) is list and len(m[key])<=MAX_MEMBERS,'Inventory bound')
            for r in m[key]:validate_record(r)
            need([r['path'] for r in m[key]]==sorted(expected) and len({n.casefold() for n in expected})==len(expected),'Exact member list mismatch')
        need(set(names)=={MANIFEST}|{'build/'+n for n in output_names},'Unknown/missing ZIP member')
        need(sum(r['size'] for r in m['outputs'])<=MAX_TOTAL,'Uncompressed bound')
        # All source bytes and all archive members verified before any destination write.
        fresh_rows,fresh_stats=source_records(source,source_names,verified_source)
        for fresh,row in zip(fresh_rows,m['source']):
            tick();need(same_content(fresh,row),'Fresh source differs')
        for row in m['outputs']:
            tick();info=z.getinfo('build/'+row['path'])
            need(info.file_size==row['size'] and not info.is_dir() and not(info.flag_bits&1),'Member size/type')
            mode=info.external_attr>>16;need(not stat.S_ISLNK(mode),'ZIP symlink')
            h=hashlib.sha256();count=0
            with z.open(info) as f:
                for block in iter(lambda:f.read(1<<20),b''):count+=len(block);need(count<=row['size'],'Member grew');h.update(block)
            need(count==row['size'] and h.hexdigest()==row['sha256'],'Member hash mismatch')
        for row in m['outputs']:
            tick();p=Path(build)/rel(row['path'])
            parent=Path(build).absolute()
            transport.regular(parent/'unused-resume-check',missing=True)
            for part in PurePosixPath(row['path']).parts[:-1]:
                parent=parent/part
                if not os.path.lexists(parent):parent.mkdir()
                st=parent.lstat();need(stat.S_ISDIR(st.st_mode) and not getattr(st,'st_file_attributes',0)&0x400,'Destination parent link/type')
            path(build,row['path'],missing=True)
            temporary=p.with_name(p.name+'.resume-pending');need(not temporary.exists(),'Pending file already exists')
            created=False
            try:
                with z.open('build/'+row['path']) as src,temporary.open('xb') as dst:
                    created=True
                    for block in iter(lambda:src.read(1<<20),b''):dst.write(block)
                need(sha(temporary)==row['sha256'],'Restored data differs')
                path(build,row['path'],missing=True);os.replace(temporary,p);exact_timestamp.set_mtime(p,row['mtime_ns'])
                need(record(build,row['path'])==row,'Restored output identity differs')
            finally:
                if created and temporary.exists():temporary.unlink()
        for row in m['source']:
            tick();p=path(source,row['path']);need(stat_identity(p)==tuple(fresh_stats[row['path']]),'Source drift before mtime')
            if p.stat().st_mtime_ns!=row['mtime_ns']:exact_timestamp.set_mtime(p,row['mtime_ns'])
            need(p.stat().st_mtime_ns==row['mtime_ns'],'Source timestamp differs')
    return {'source_count':len(m['source']),'output_count':len(m['outputs']),'state':'EXACT_RESTORED_PENDING_INCREMENTAL_CHECK','verified_outputs':m['outputs']}
