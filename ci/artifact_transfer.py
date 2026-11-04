"""Exact public transfer envelope. No provider/cache actions or executable content parsing."""
from pathlib import Path
import hashlib,json,stat,zipfile
import resume_bundle as bundle
import resume_transport as transport
MAX_BYTES=400_000_000
MAX_TOTAL=2_000_000_000
RECEIPT='TRANSFER_RECEIPT.json'
class TransferError(ValueError):pass
def need(ok,msg):
 if not ok:raise TransferError(msg)
def pin(value):
 transport.expected(value);need(value['size']<=MAX_BYTES,'Transfer compressed bound');return value
def digest(data):return hashlib.sha256(data).hexdigest()
def row(name,size,sha):return {'path':bundle.rel(name),'size':size,'sha256':sha}
def validate_rows(rows):
 need(type(rows) is list and 0<len(rows)<=100000,'Material count')
 names=[]
 for r in rows:
  need(type(r) is dict and set(r)=={'path','size','sha256'},'Material record shape')
  names.append(bundle.rel(r['path']));need(type(r['size']) is int and 0<=r['size']<=MAX_TOTAL,'Material size')
  need(type(r['sha256']) is str and len(r['sha256'])==64 and all(c in '0123456789abcdef' for c in r['sha256']),'Material hash')
 need(names==sorted(names) and len(names)==len({n.casefold() for n in names}),'Material aliases/order')
 need(sum(r['size'] for r in rows)<=MAX_TOTAL,'Material total bound')
 return rows

def seal(destination,inner,inner_pin,materials,metadata,tick=lambda:None):
 """materials: exact reviewed name -> (Path or bytes, independently verified size/hash)."""
 rows=validate_rows(sorted([row(n,s,h) for n,(_,s,h) in materials.items()],key=lambda r:r['path']))
 need(transport.identity(inner)==transport.expected(inner_pin),'Inner drift')
 receipt={'schema':1,'metadata':metadata,'checkpoint':inner_pin,'materials':rows}
 raw=json.dumps(receipt,sort_keys=True,separators=(',',':')).encode();need(len(raw)<=bundle.MAX_MANIFEST,'Receipt size')
 destination=Path(destination);need(not destination.exists(),'Transfer exists');created=False
 try:
  with zipfile.ZipFile(destination,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=False) as z:
   created=True;z.writestr(RECEIPT,raw)
   for name,value,expected,method in [('checkpoint.zip',inner,inner_pin,zipfile.ZIP_STORED)]+[('material/'+r['path'],materials[r['path']][0],r,zipfile.ZIP_DEFLATED) for r in rows]:
    tick();h=hashlib.sha256();size=0
    info=zipfile.ZipInfo(name);info.compress_type=method;info.external_attr=(stat.S_IFREG|0o600)<<16
    info._compresslevel=1
    with z.open(info,'w') as dst:
     if isinstance(value,bytes):chunks=[value];handle=None
     else:handle=transport.regular(value).open('rb');chunks=iter(lambda:handle.read(1<<20),b'')
     try:
      for chunk in chunks:size+=len(chunk);need(size<=expected['size'],'Input grew');h.update(chunk);dst.write(chunk);tick()
     finally:
      if handle:handle.close()
    need(size==expected['size'] and h.hexdigest()==expected['sha256'],'Input differs from verified material record')
    need(destination.stat().st_size<=MAX_BYTES,'Transfer exceeds artifact bound')
  result=pin(transport.identity(destination))
  verify(destination,result,metadata,inner_pin,tick=tick)
  return result,receipt
 except BaseException:
  if created and destination.exists():destination.unlink()
  raise

def verify(archive,expected,metadata,inner_pin,*,destination=None,tick=lambda:None):
 need(transport.identity(archive)==pin(expected),'Transfer receipt mismatch before parse')
 with zipfile.ZipFile(archive) as z:
  infos=z.infolist();names=[i.filename for i in infos]
  need(len(names)==len({n.casefold() for n in names})<=100002,'Transfer duplicate/count')
  for i in infos:
   bundle.rel(i.filename);need(not i.is_dir() and stat.S_IFMT(i.external_attr>>16) in {0,stat.S_IFREG},'Transfer nonregular')
   need(i.compress_type in {zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED} and not i.flag_bits&1,'Transfer compression/encryption')
  need(RECEIPT in names and z.getinfo(RECEIPT).file_size<=bundle.MAX_MANIFEST,'Transfer receipt absent/oversized')
  m=json.loads(z.read(RECEIPT),object_pairs_hook=bundle.unique_pairs)
  need(type(m) is dict and set(m)=={'schema','metadata','checkpoint','materials'} and m['schema']==1,'Transfer shape')
  need(m['metadata']==metadata and m['checkpoint']==transport.expected(inner_pin),'Transfer identity mismatch')
  rows=validate_rows(m['materials']);expected_members={'checkpoint.zip':inner_pin,**{'material/'+r['path']:r for r in rows}}
  need(set(names)==set(expected_members)|{RECEIPT},'Unexpected transfer member')
  need(sum(i.file_size for i in infos)<=MAX_TOTAL+MAX_BYTES+bundle.MAX_MANIFEST,'Transfer expanded bound')
  created=False
  try:
   for name,r in expected_members.items():
    tick();need(z.getinfo(name).file_size==r['size'],'Transfer declared size mismatch');h=hashlib.sha256();size=0;dst=None
    if name=='checkpoint.zip' and destination is not None:
     destination=transport.regular(destination,missing=True);need(not destination.exists(),'Inner destination exists');dst=destination.open('xb');created=True
    try:
     with z.open(name) as src:
      for chunk in iter(lambda:src.read(1<<20),b''):
       size+=len(chunk);need(size<=r['size'],'Member exceeds pin');h.update(chunk)
       if dst:dst.write(chunk)
       tick()
    finally:
     if dst:dst.close()
    need(size==r['size'] and h.hexdigest()==r['sha256'],'Transfer member hash mismatch')
   return m
  except BaseException:
   if created and destination.exists():destination.unlink()
   raise
