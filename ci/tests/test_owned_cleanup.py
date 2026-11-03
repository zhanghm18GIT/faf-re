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
if __name__=='__main__':unittest.main(verbosity=2)
