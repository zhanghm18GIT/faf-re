"""Single-file native-cache handoff. Not a confidentiality or process-isolation boundary.
Caller must validate checkpoint semantics and finish owned-work cleanup before commit.
No network, provider calls, permissions or cache-setting changes occur here.
"""
from pathlib import Path
import hashlib, os, re, stat

MAX_BYTES=400_000_000
class CacheError(ValueError): pass
def need(value,message):
 if not value: raise CacheError(message)
def regular(path,missing=False):
 p=Path(path).absolute()
 for item in reversed([p,*p.parents]):
  try: s=item.lstat()
  except FileNotFoundError:
   need(missing and item==p,'Missing cache path');continue
  need(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'Cache link/reparse forbidden')
  need(stat.S_ISREG(s.st_mode) if item==p else stat.S_ISDIR(s.st_mode),'Wrong cache path type')
  if item==p:need(s.st_nlink==1,'Cache hardlink forbidden')
 return p
def identity(path):
 p=regular(path);h=hashlib.sha256();size=0
 with p.open('rb') as f:
  start=os.fstat(f.fileno())
  for block in iter(lambda:f.read(1<<20),b''):
   size+=len(block);need(size<=MAX_BYTES,'Cache byte ceiling');h.update(block)
  end=os.fstat(f.fileno())
 after=p.stat()
 need((start.st_dev,start.st_ino,start.st_size,start.st_mtime_ns)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'Cache changed while hashing')
 need(0<size<=MAX_BYTES,'Empty or oversized cache')
 return {'size':size,'sha256':h.hexdigest()}
def expected(value):
 need(type(value)==dict and set(value)=={'size','sha256'},'Exact cache identity required')
 need(type(value['size']) is int and 0<value['size']<=MAX_BYTES,'Invalid cache size')
 need(type(value['sha256']) is str and re.fullmatch('[a-f0-9]{64}',value['sha256']),'Invalid cache hash')
 return value
def stage(source,directory,pin):
 """Copy validated bundle into fresh exclusive handoff dir; never merge restored state."""
 expected(pin);source=regular(source);directory=Path(directory).absolute()
 # Require existing parent, but do not accept an existing handoff directory.
 regular(directory.parent/'unused-leaf',missing=True)
 need(not os.path.lexists(directory),'Handoff directory must be absent')
 need(identity(source)==pin,'Source differs from reviewed producer receipt')
 directory.mkdir();pending=directory/'checkpoint.pending';created=False
 try:
  with source.open('rb') as src,pending.open('xb') as dst:
   created=True
   n=0
   for block in iter(lambda:src.read(1<<20),b''):
    n+=len(block);need(n<=pin['size'],'Source grew during handoff');dst.write(block)
   dst.flush();os.fsync(dst.fileno())
  need(identity(pending)==pin and identity(source)==pin,'Handoff identity mismatch')
 except BaseException:
  if created and pending.exists():pending.unlink()
  if not any(directory.iterdir()):directory.rmdir()
  raise
 return pending
def commit(directory,pin,*,owned_cleanup_verified):
 """Only after cleanup success; native provider caches this exact final filename."""
 need(owned_cleanup_verified is True,'Cleanup must complete before cache eligibility')
 expected(pin);directory=Path(directory).absolute();pending=regular(directory/'checkpoint.pending')
 need(set(p.name for p in directory.iterdir())=={'checkpoint.pending'},'Unexpected handoff content')
 need(identity(pending)==pin,'Pending bytes changed')
 final=directory/'checkpoint.zip';need(not os.path.lexists(final),'Cache file already exists')
 pending.rename(final);need(identity(final)==pin,'Committed bytes changed')
 return {'state':'READY_FOR_NATIVE_CACHE_NOT_CONFIRMED_SAVED','size':pin['size'],'sha256':pin['sha256'],'publication':'not_a_published_artifact','cache_access_guarantee':'UNKNOWN','account_quota_headroom':'UNKNOWN'}
def receive(source,destination,pin):
 """Native restore is untrusted until hash/size match the separately pinned A receipt."""
 expected(pin);source=regular(source);destination=regular(destination,missing=True)
 need(not os.path.lexists(destination),'Consumer destination must be absent')
 need(identity(source)==pin,'Restored cache identity mismatch')
 created=False
 try:
  with source.open('rb') as src,destination.open('xb') as dst:
   created=True
   size=0
   for block in iter(lambda:src.read(1<<20),b''):
    size+=len(block);need(size<=pin['size'],'Cache grew during receive');dst.write(block)
  need(identity(destination)==pin and identity(source)==pin,'Received cache changed')
 except BaseException:
  if created and destination.exists():destination.unlink()
  raise
 return destination
