"""Owned temporary cleanup only. No traversal through reparse points or ACL changes."""
from pathlib import Path
import os,shutil,stat,time

class CleanupError(RuntimeError):pass
REPARSE=0x400
READONLY=0x1

def remove_owned_path(root,target,*,owner_check,emit=lambda *x:None,max_entries=200000,max_seconds=60):
 """Cooperative bounds; retry only unlink of an owned read-only regular file once.

 The caller must establish quiescence and unlink its explicit SDK junctions first.
 No generic 'access denied' retry, directory chmod, ACL reset or external traversal.
 """
 root=Path(os.path.abspath(root));target=Path(os.path.abspath(target));owner_check()
 started=time.monotonic();count=0
 def need(ok,msg):
  if not ok:raise CleanupError(msg)
 def kind(st):return 'regular' if stat.S_ISREG(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'other'
 def check(path):
  nonlocal count
  need(path==root or path.is_relative_to(root),'Cleanup target is outside owned root')
  # Explicit ancestors between root and target, without resolve()/link traversal.
  parts=[root];p=root
  for name in path.relative_to(root).parts:p=p/name;parts.append(p)
  for p in parts:
   st=p.lstat();need(not(stat.S_ISLNK(st.st_mode) or getattr(st,'st_file_attributes',0)&REPARSE),'Unexpected cleanup reparse point')
  st=path.lstat();need(kind(st) in {'regular','directory'},'Unexpected cleanup entry type')
  current=root.lstat();need((current.st_dev,current.st_ino)==identity,'Owned cleanup root identity changed')
  count+=1;need(count<=max_entries and time.monotonic()-started<=max_seconds,'Cooperative cleanup allowance exhausted')
  return st
 for parent in [*reversed(root.parents),root]:
  st=parent.lstat();need(not(stat.S_ISLNK(st.st_mode) or getattr(st,'st_file_attributes',0)&REPARSE),'Owned cleanup ancestor is a reparse point')
 initial=root.lstat();need(stat.S_ISDIR(initial.st_mode) and not getattr(initial,'st_file_attributes',0)&REPARSE and not root.is_symlink(),'Invalid owned cleanup root')
 identity=(initial.st_dev,initial.st_ino)
 def diagnostic(operation,path,exc,entry_kind='unknown'):
  try:relative=Path(path).relative_to(root).as_posix()
  except ValueError:relative='<outside-owned-root>'
  emit('CLEANUP_DETAIL',{'operation':operation,'relative_path':relative or '.', 'entry_kind':entry_kind,'error_type':type(exc).__name__,'errno':getattr(exc,'errno',None),'winerror':getattr(exc,'winerror',None)})
 def onexc(function,path,exc):
  p=Path(path)
  try:
   st=check(p)
   readonly=bool(getattr(st,'st_file_attributes',0)&READONLY) if os.name=='nt' else not(st.st_mode&stat.S_IWUSR)
   retry=isinstance(exc,PermissionError) and (getattr(exc,'winerror',None)==5 or (os.name!='nt' and getattr(exc,'winerror',None) is None)) and function in {os.unlink,os.remove} and stat.S_ISREG(st.st_mode) and st.st_nlink==1 and readonly
   if not retry:diagnostic(getattr(function,'__name__','unknown'),p,exc,kind(st));raise exc
   # Windows chmod changes only its read-only attribute. No ACL/security reset.
   owner_check();os.chmod(p,stat.S_IMODE(st.st_mode)|stat.S_IWUSR);check(p)
   function(p)
   emit('CLEANUP_READONLY_RETRY',{'relative_path':p.relative_to(root).as_posix(),'result':'removed'})
  except BaseException as failure:
   if failure is not exc:diagnostic(getattr(function,'__name__','unknown'),p,failure)
   raise
 try:
  check(target)
  for directory,dirs,files in os.walk(target,followlinks=False):
   check(Path(directory))
   for name in dirs+files:check(Path(directory)/name)
  def remove_one(p):
   st=check(p)
   if stat.S_ISDIR(st.st_mode):shutil.rmtree(p,onexc=onexc)
   else:
    try:os.unlink(p)
    except PermissionError as exc:onexc(os.unlink,p,exc)
  if target==root:
   marker=root/'OWNED_WORK.json';need(marker.is_file() and not marker.is_symlink(),'Owned cleanup marker missing')
   for p in sorted(root.iterdir()):
    if p!=marker:remove_one(p)
   owner_check();remove_one(marker);os.rmdir(root)
  else:remove_one(target)
  need(not os.path.lexists(target),'Owned cleanup target remains')
 except BaseException as exc:
  diagnostic('remove-owned-tree',target,exc)
  raise
