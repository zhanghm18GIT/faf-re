"""POSIX synthetic cleanup/control-flow tests, not Windows runtime proof."""
from pathlib import Path
import errno,os,stat,sys,tempfile,unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import owned_cleanup as clean

class CleanupTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)/'owned';self.root.mkdir();self.marker=self.root/'OWNED_WORK.json';self.marker.write_text('fixture');self.tree=self.root/'source';self.tree.mkdir();self.file=self.tree/'object';self.file.write_text('owned');self.events=[]
 def tearDown(self):self.tmp.cleanup()
 def owner(self):self.assertEqual(self.marker.read_text(),'fixture')
 def run_clean(self,target=None):return clean.remove_owned_path(self.root,target or self.tree,owner_check=self.owner,emit=lambda k,v:self.events.append((k,v)))
 def deny_unlink(self,*,always=False,winerror=5):
  original=os.unlink;calls=[]
  def unlink(path,*args,**kwargs):
   if Path(path).name=='object':
    calls.append(str(path))
    if always or len(calls)==1:
     e=PermissionError(errno.EACCES,'synthetic denial');e.winerror=winerror;raise e
   return original(path,*args,**kwargs)
  return unlink,calls
 def test_ordinary_tree_no_chmod(self):
  with mock.patch.object(os,'chmod',wraps=os.chmod) as chmod:self.run_clean();chmod.assert_not_called()
  self.assertFalse(self.tree.exists());self.owner()
 def test_readonly_single_file_one_retry(self):
  self.file.chmod(0o444);unlink,calls=self.deny_unlink()
  with mock.patch.object(os,'unlink',side_effect=unlink),mock.patch.object(os,'chmod',wraps=os.chmod) as chmod:self.run_clean();self.assertEqual(chmod.call_count,1)
  self.assertEqual(len(calls),2);self.assertTrue(any(k=='CLEANUP_READONLY_RETRY' for k,v in self.events))
 def test_retry_failure_not_suppressed(self):
  self.file.chmod(0o444);unlink,calls=self.deny_unlink(always=True)
  with mock.patch.object(os,'unlink',side_effect=unlink),mock.patch.object(os,'chmod',wraps=os.chmod) as chmod:
   with self.assertRaises(PermissionError):self.run_clean()
   self.assertEqual(chmod.call_count,1)
  self.assertEqual(len(calls),2);self.assertTrue(self.marker.exists())
 def test_writable_denial_never_chmods(self):
  unlink,calls=self.deny_unlink(always=True)
  with mock.patch.object(os,'unlink',side_effect=unlink),mock.patch.object(os,'chmod') as chmod:
   with self.assertRaises(PermissionError):self.run_clean()
   chmod.assert_not_called()
 def test_sharing_violation_never_chmods(self):
  self.file.chmod(0o444);unlink,calls=self.deny_unlink(always=True,winerror=32)
  with mock.patch.object(os,'unlink',side_effect=unlink),mock.patch.object(os,'chmod') as chmod:
   with self.assertRaises(PermissionError):self.run_clean()
   chmod.assert_not_called()
 def test_readonly_hardlink_never_chmods(self):
  self.file.chmod(0o444);outside=Path(self.tmp.name)/'outside';os.link(self.file,outside);unlink,calls=self.deny_unlink(always=True)
  with mock.patch.object(os,'unlink',side_effect=unlink),mock.patch.object(os,'chmod') as chmod:
   with self.assertRaises(PermissionError):self.run_clean()
   chmod.assert_not_called()
  self.assertEqual(outside.read_text(),'owned');self.assertFalse(outside.stat().st_mode&stat.S_IWUSR)
 def test_nested_unknown_link_blocks_without_external_mutation(self):
  outside=Path(self.tmp.name)/'outside';outside.mkdir();sentinel=outside/'sentinel';sentinel.write_text('keep');(self.tree/'link').symlink_to(outside,target_is_directory=True)
  with self.assertRaises(clean.CleanupError):self.run_clean()
  self.assertEqual(sentinel.read_text(),'keep');self.assertTrue(self.file.exists())
 def test_outside_target_blocks(self):
  outside=Path(self.tmp.name)/'outside';outside.mkdir()
  with self.assertRaises(clean.CleanupError):self.run_clean(outside)
  self.assertTrue(outside.exists())
 def test_wrong_owner_blocks_all_mutation(self):
  self.marker.write_text('wrong')
  with self.assertRaises(AssertionError):self.run_clean()
  self.assertTrue(self.file.exists())
 def test_marker_is_deleted_last(self):
  original=os.unlink;order=[]
  def unlink(path,*args,**kwargs):
   order.append(Path(path).name)
   if Path(path).name!='OWNED_WORK.json':self.assertTrue(self.marker.exists())
   return original(path,*args,**kwargs)
  with mock.patch.object(os,'unlink',side_effect=unlink):self.run_clean(self.root)
  self.assertEqual(order[-1],'OWNED_WORK.json');self.assertFalse(self.root.exists())
 def test_diagnostics_are_relative_and_structured(self):
  unlink,calls=self.deny_unlink(always=True)
  with mock.patch.object(os,'unlink',side_effect=unlink):
   with self.assertRaises(PermissionError):self.run_clean()
  details=[v for k,v in self.events if k=='CLEANUP_DETAIL'];self.assertTrue(details)
  self.assertTrue(any(v['relative_path']=='source/object' and v['errno']==errno.EACCES and v['winerror']==5 for v in details));self.assertNotIn(str(self.root),str(details))
 def test_directory_denial_no_chmod(self):
  original=os.rmdir
  def rmdir(path,*a,**kw):
   if Path(path).name=='source':raise PermissionError(errno.EACCES,'fixture')
   return original(path,*a,**kw)
  with mock.patch.object(os,'rmdir',side_effect=rmdir),mock.patch.object(os,'chmod') as chmod:
   with self.assertRaises(PermissionError):self.run_clean()
   chmod.assert_not_called()
 def test_entry_and_time_limit_reason_codes(self):
  for kwargs,code in [({'max_entries':1},'CLEANUP_ENTRY_LIMIT'),({'max_seconds':0},'CLEANUP_TIME_LIMIT')]:
   events=[]
   with self.assertRaises(clean.CleanupError) as result:
    clean.remove_owned_path(self.root,self.tree,owner_check=self.owner,emit=lambda k,v:events.append(v),**kwargs)
   self.assertEqual(result.exception.reason_code,code)
   self.assertTrue(any(v.get('reason_code')==code and 'entries_checked' in v and 'elapsed_seconds' in v for v in events))
   self.assertTrue(self.file.exists())
 def test_changed_root_identity_rejected(self):
  original=os.walk;renamed=self.root.parent/'moved'
  def walk(*a,**kw):
   for row in original(*a,**kw):
    self.root.rename(renamed);self.root.mkdir();self.marker.write_text('fixture')
    yield row;return
  with mock.patch.object(os,'walk',side_effect=walk):
   with self.assertRaisesRegex(clean.CleanupError,'ROOT_IDENTITY_CHANGED'):self.run_clean()
  self.assertEqual((renamed/'source/object').read_text(),'owned')
 def test_retry_does_not_trust_prewalk_ancestor_cache(self):
  outside=Path(self.tmp.name)/'outside';outside.mkdir();sentinel=outside/'object';sentinel.write_text('external');self.file.chmod(0o444)
  moved=self.root/'moved';original=os.unlink;fired=False
  def unlink(path,*args,**kwargs):
   nonlocal fired
   if Path(path).name=='object' and not fired:
    fired=True;self.tree.rename(moved);self.tree.symlink_to(outside,target_is_directory=True)
    e=PermissionError(errno.EACCES,'fixture');e.winerror=5;raise e
   return original(path,*args,**kwargs)
  with mock.patch.object(os,'unlink',side_effect=unlink),mock.patch.object(os,'chmod') as chmod:
   with self.assertRaisesRegex(clean.CleanupError,'UNEXPECTED_REPARSE_POINT'):self.run_clean()
   chmod.assert_not_called()
  self.assertEqual(sentinel.read_text(),'external');self.assertEqual((moved/'object').read_text(),'owned')
 def test_read_only_prewalk_never_mutates(self):
  before={str(p):p.stat().st_mtime_ns for p in self.root.rglob('*')}
  with mock.patch.object(os,'unlink') as unlink,mock.patch.object(os,'chmod') as chmod,mock.patch.object(os,'rmdir') as rmdir:
   receipt=clean.preflight_owned_tree(self.root,self.root,owner_check=self.owner)
   unlink.assert_not_called();chmod.assert_not_called();rmdir.assert_not_called()
  self.assertEqual(receipt['state'],'PASS_READ_ONLY_PREWALK');self.assertFalse(receipt['deletion_performed'])
  self.assertEqual(before,{str(p):p.stat().st_mtime_ns for p in self.root.rglob('*')})
 def test_only_verified_mountpoint_entries_pruned_without_descent(self):
  from types import SimpleNamespace
  outside=Path(self.tmp.name)/'sdk';outside.mkdir();(outside/'sentinel').write_text('external')
  link=self.root/'sdk-link';link.symlink_to(outside,target_is_directory=True);original=Path.lstat
  def lstat(path,*a,**kw):
   self.assertFalse(path.is_relative_to(outside),'must not inspect installed subtree')
   result=original(path,*a,**kw)
   if path==link:
    values={n:getattr(result,n) for n in dir(result) if n.startswith('st_')};values.update(st_file_attributes=0x400,st_reparse_tag=0xa0000003);return SimpleNamespace(**values)
   return result
  with mock.patch.object(Path,'lstat',lstat),mock.patch.object(os,'unlink') as unlink,mock.patch.object(os,'rmdir') as rmdir:
   receipt=clean.preflight_owned_tree(self.root,self.root,owner_check=self.owner,verified_junctions=(link,))
   unlink.assert_not_called();rmdir.assert_not_called()
  self.assertEqual(receipt['verified_junction_entries_pruned'],1);self.assertEqual((outside/'sentinel').read_text(),'external');self.assertTrue(link.is_symlink())
 def test_unverified_or_ordinary_entry_cannot_be_skipped(self):
  with self.assertRaisesRegex(clean.CleanupError,'INVALID_VERIFIED_JUNCTION_ENTRY'):
   clean.preflight_owned_tree(self.root,self.root,owner_check=self.owner,verified_junctions=(self.tree,))
  with self.assertRaises(TypeError):clean.remove_owned_path(self.root,self.root,owner_check=self.owner,verified_junctions=(self.tree,))
  self.assertTrue(self.file.exists())
 def test_large_readonly_scan_checks_leafs_without_repeating_ancestor_chains(self):
  folder=self.tree/'a'/'b'/'c'/'d';folder.mkdir(parents=True)
  for i in range(500):(folder/f'{i}.txt').write_text('fixture')
  count=[0];original=Path.lstat
  def counted(path,*a,**kw):count[0]+=1;return original(path,*a,**kw)
  with mock.patch.object(Path,'lstat',counted):receipt=clean.preflight_owned_tree(self.root,self.root,owner_check=self.owner)
  self.assertGreaterEqual(receipt['entries_checked'],500);self.assertLess(count[0],1700);self.assertEqual(len(list(folder.iterdir())),500)
 def test_scandir_error_blocks_readonly_pass_and_no_mutation(self):
  original=os.scandir
  def scandir(path):
   if Path(path)==self.tree:raise PermissionError(errno.EACCES,'fixture',str(self.tree))
   return original(path)
  events=[]
  with mock.patch.object(os,'scandir',side_effect=scandir),mock.patch.object(os,'unlink') as unlink,mock.patch.object(os,'chmod') as chmod:
   with self.assertRaises(PermissionError):clean.preflight_owned_tree(self.root,self.root,owner_check=self.owner,emit=lambda k,v:events.append(v))
   unlink.assert_not_called();chmod.assert_not_called()
  self.assertTrue(any(e['relative_path']=='source' and e['error_type']=='PermissionError' for e in events));self.assertTrue(self.file.exists())
if __name__=='__main__':unittest.main(verbosity=2)
