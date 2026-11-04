"""Owned temporary cleanup only. No traversal through reparse points or ACL changes."""
from pathlib import Path
import os,shutil,stat,time

class CleanupError(RuntimeError):
 def __init__(self,code,path=None):
  super().__init__(code);self.reason_code=code;self.checked_path=path

REPARSE=0x400
READONLY=0x1

def _operate_owned_path(root,target,*,owner_check,emit=lambda *x:None,max_entries=200000,max_seconds=60,read_only=False,verified_junctions=()):
 """Cooperative bounds; retry only unlink of an owned read-only regular file once.

 The caller must establish quiescence and unlink its explicit SDK junctions first.
 No generic 'access denied' retry, directory chmod, ACL reset or external traversal.
 """
 root=Path(os.path.abspath(root));target=Path(os.path.abspath(target));owner_check()
 started=time.monotonic();count=0
 excluded={Path(os.path.abspath(p)) for p in verified_junctions};found=set()
 def need(ok,code,path=None):
  if not ok:raise CleanupError(code,path)
 def kind(st):return 'regular' if stat.S_ISREG(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'other'
 checked_directories=set()
 def check(path,*,prewalk=False):
  nonlocal count
  need(path==root or path.is_relative_to(root),'OUTSIDE_OWNED_ROOT',path)
  # Root identity is checked before any descendant access, even in the cached prewalk.
  current=root.lstat();need((current.st_dev,current.st_ino)==identity,'ROOT_IDENTITY_CHANGED',root)
  need(not(stat.S_ISLNK(current.st_mode) or getattr(current,'st_file_attributes',0)&REPARSE),'UNEXPECTED_REPARSE_POINT',root)
  if prewalk:
   # Top-down scan: the direct parent was checked before yielding any children.
   need(path==root or path.parent in checked_directories,'PREWALK_PARENT_NOT_VALIDATED',path)
   st=current if path==root else path.lstat()
   need(not(stat.S_ISLNK(st.st_mode) or getattr(st,'st_file_attributes',0)&REPARSE),'UNEXPECTED_REPARSE_POINT',path)
   if stat.S_ISDIR(st.st_mode):checked_directories.add(path)
  else:
   # Deletion roots and retry callbacks always recheck every ancestor.
   parts=[root];p=root
   for name in path.relative_to(root).parts:p=p/name;parts.append(p)
   st=current
   for p in parts:
    if p!=root:st=p.lstat()
    need(not(stat.S_ISLNK(st.st_mode) or getattr(st,'st_file_attributes',0)&REPARSE),'UNEXPECTED_REPARSE_POINT',p)
    if p!=path:need(stat.S_ISDIR(st.st_mode),'INVALID_ANCESTOR_TYPE',p)
    if stat.S_ISDIR(st.st_mode):checked_directories.add(p)
  need(kind(st) in {'regular','directory'},'UNEXPECTED_ENTRY_TYPE',path)
  count+=1;need(count<=max_entries,'CLEANUP_ENTRY_LIMIT',path);need(time.monotonic()-started<=max_seconds,'CLEANUP_TIME_LIMIT',path)
  return st
 for parent in [*reversed(root.parents),root]:
  st=parent.lstat();need(not(stat.S_ISLNK(st.st_mode) or getattr(st,'st_file_attributes',0)&REPARSE),'ANCESTOR_REPARSE_POINT')
 need((read_only or not excluded) and len(excluded)<=2,'INVALID_PREFLIGHT_JUNCTION_SCOPE')
 need(all(p.is_relative_to(root) and p!=root for p in excluded),'INVALID_PREFLIGHT_JUNCTION_SCOPE')
 initial=root.lstat();need(stat.S_ISDIR(initial.st_mode) and not getattr(initial,'st_file_attributes',0)&REPARSE and not root.is_symlink(),'INVALID_OWNED_ROOT')
 identity=(initial.st_dev,initial.st_ino)
 def diagnostic(operation,path,exc,entry_kind='unknown'):
  failed=getattr(exc,'checked_path',None) or getattr(exc,'filename',None)
  path=failed if isinstance(failed,(str,Path)) else path
  try:relative=Path(path).relative_to(root).as_posix()
  except ValueError:relative='<outside-owned-root>'
  emit('CLEANUP_DETAIL',{'operation':operation,'relative_path':relative or '.', 'entry_kind':entry_kind,'error_type':type(exc).__name__,'errno':getattr(exc,'errno',None),'winerror':getattr(exc,'winerror',None),'reason_code':getattr(exc,'reason_code',None),'entries_checked':count,'elapsed_seconds':round(time.monotonic()-started,3),'max_entries':max_entries,'max_seconds':max_seconds})
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
  target_stat=check(target)
  def scan_error(exc):raise exc
  # os.walk on a regular file raises ENOTDIR on Windows. Validate the
  # file directly; only directory targets have descendants to prewalk.
  walk=os.walk(target,followlinks=False,onerror=scan_error) if stat.S_ISDIR(target_stat.st_mode) else ()
  for directory,dirs,files in walk:
   check(Path(directory),prewalk=True)
   for name in list(dirs):
    p=Path(directory)/name
    if p in excluded:
     st=p.lstat();need(getattr(st,'st_file_attributes',0)&REPARSE and getattr(st,'st_reparse_tag',None)==0xa0000003,'INVALID_VERIFIED_JUNCTION_ENTRY',p)
     dirs.remove(name);found.add(p)
    else:check(p,prewalk=True)
   for name in files:check(Path(directory)/name,prewalk=True)
  need(found==excluded,'VERIFIED_JUNCTION_NOT_ENCOUNTERED')
  if read_only:
   owner_check()
   return {'state':'PASS_READ_ONLY_PREWALK','entries_checked':count,'elapsed_seconds':round(time.monotonic()-started,3),'max_entries':max_entries,'max_seconds':max_seconds,'verified_junction_entries_pruned':len(found),'deletion_performed':False}
  def remove_one(p):
   st=check(p)
   if stat.S_ISDIR(st.st_mode):shutil.rmtree(p,onexc=onexc)
   else:
    try:os.unlink(p)
    except PermissionError as exc:onexc(os.unlink,p,exc)
  if target==root:
   marker=root/'OWNED_WORK.json';need(marker.is_file() and not marker.is_symlink(),'OWNERSHIP_MARKER_MISSING')
   for p in sorted(root.iterdir()):
    if p!=marker:remove_one(p)
   owner_check();remove_one(marker);os.rmdir(root)
  else:remove_one(target)
  need(not os.path.lexists(target),'TARGET_REMAINS')
 except BaseException as exc:
  diagnostic('remove-owned-tree',target,exc)
  raise

def remove_owned_path(root,target,*,owner_check,emit=lambda *x:None,max_entries=200000,max_seconds=60):
 return _operate_owned_path(root,target,owner_check=owner_check,emit=emit,max_entries=max_entries,max_seconds=max_seconds)

def preflight_owned_tree(root,target,*,owner_check,verified_junctions=(),emit=lambda *x:None,max_entries=200000,max_seconds=60):
 """Same read-only prewalk/caps; prune only separately verified SDK junction entries."""
 return _operate_owned_path(root,target,owner_check=owner_check,emit=emit,max_entries=max_entries,max_seconds=max_seconds,read_only=True,verified_junctions=verified_junctions)
