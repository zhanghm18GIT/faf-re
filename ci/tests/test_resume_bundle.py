from pathlib import Path
import sys,unittest,tempfile,json,zipfile,os,stat
from unittest.mock import patch
CI=Path(__file__).resolve().parents[1];sys.path.insert(0,str(CI))
import resume_bundle as r
import resume_transport as transport

class BundleTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.source=self.root/'source';self.build=self.root/'build';self.source.mkdir();self.build.mkdir()
  (self.source/'a.cpp').write_bytes(b'public source');(self.build/'a.obj').write_bytes(b'Public fixture C:\\public-source no COFF parser');(self.build/'.ninja_log').write_bytes(b'public log')
  for p in [self.source/'a.cpp',self.build/'a.obj',self.build/'.ninja_log']:os.utime(p,ns=(1600000000000000000,1600000000000000100))
  self.bundle=self.root/'cache.zip';self.kw=dict(source=self.source,build=self.build,source_names=['a.cpp'],output_names=['a.obj','.ninja_log'],metadata={'fixed':'identity'},producer={'id':'A'})
  self.pin=r.seal(self.bundle,**self.kw)
 def tearDown(self):self.tmp.cleanup()
 def mutate(self,fn):
  with zipfile.ZipFile(self.bundle) as z:rows=[(i,z.read(i)) for i in z.infolist()]
  rows=fn(rows);self.bundle.unlink()
  with zipfile.ZipFile(self.bundle,'w') as z:
   for i,data in rows:z.writestr(i,data)
  self.pin=transport.identity(self.bundle)
 def test_roundtrip_exact_mtimes(self):
  original=r.records(self.build,self.kw['output_names']);(self.build/'a.obj').unlink();os.utime(self.source/'a.cpp',ns=(1700000000000000000,1700000000000000000))
  r.restore(self.bundle,self.pin,**self.kw)
  self.assertEqual(r.records(self.build,self.kw['output_names']),original);self.assertEqual((self.source/'a.cpp').stat().st_mtime_ns,1600000000000000100)
 def test_wrong_external_pin_before_parse(self):
  with patch.object(zipfile,'ZipFile') as z:
   with self.assertRaises(r.ResumeError):r.restore(self.bundle,{'size':self.pin['size'],'sha256':'0'*64},**self.kw)
  z.assert_not_called()
 def test_changed_source_no_write(self):
  (self.source/'a.cpp').write_bytes(b'changed');(self.build/'a.obj').unlink()
  with self.assertRaises(r.ResumeError):r.restore(self.bundle,self.pin,**self.kw)
  self.assertFalse((self.build/'a.obj').exists())
 def test_metadata_producer_mismatch(self):
  for key in ['metadata','producer']:
   kw=dict(self.kw);kw[key]={'wrong':True}
   with self.subTest(key=key),self.assertRaises(r.ResumeError):r.restore(self.bundle,self.pin,**kw)
 def test_unknown_member(self):
  self.mutate(lambda rows:rows+[(zipfile.ZipInfo('build/extra.obj'),b'x')])
  with self.assertRaises(r.ResumeError):r.restore(self.bundle,self.pin,**self.kw)
 def test_payload_corruption_rejected_before_write(self):
  self.mutate(lambda rows:[(i,b'corrupt' if i.filename=='build/a.obj' else d) for i,d in rows]);(self.build/'a.obj').unlink()
  with self.assertRaises(r.ResumeError):r.restore(self.bundle,self.pin,**self.kw)
  self.assertFalse((self.build/'a.obj').exists())
 def test_windows_names(self):
  for name in ['../x','CON','a/NUL.txt','a.','a ','a//b','C:/x','a\\b','.git/x']:
   with self.subTest(name=name),self.assertRaises(r.ResumeError):r.rel(name)
 def test_case_collision(self):
  with self.assertRaises(r.ResumeError):r.records(self.build,['a.obj','A.obj'])
 def test_nonregular_zip(self):
  def change(rows):
   for i,d in rows:
    if i.filename=='build/a.obj':i.external_attr=(stat.S_IFIFO|0o600)<<16
   return rows
  self.mutate(change)
  with self.assertRaises(r.ResumeError):r.restore(self.bundle,self.pin,**self.kw)
 def test_symlink_output(self):
  (self.build/'a.obj').unlink();(self.build/'a.obj').symlink_to(self.source/'a.cpp')
  with self.assertRaises(transport.CacheError):r.records(self.build,['a.obj'])
 def test_seal_rechecks_written_archive(self):
  other=self.root/'other.zip';orig=zipfile.ZipFile.write
  def write(z,p,name,*args,**kw):
   if name=='build/a.obj':Path(p).write_bytes(b'changed during write')
   return orig(z,p,name,*args,**kw)
  with patch.object(zipfile.ZipFile,'write',write):
   with self.assertRaises(r.ResumeError):r.seal(other,**self.kw)
  self.assertFalse(other.exists())
 def test_verified_source_records_avoid_rehash(self):
  rows=r.records(self.source,['a.cpp']);verified={'records':rows,'stats':{'a.cpp':r.stat_identity(self.source/'a.cpp')}}
  original=r.record
  def no_source(root,name):
   self.assertNotEqual(Path(root),self.source)
   return original(root,name)
  with patch.object(r,'record',side_effect=no_source):r.restore(self.bundle,self.pin,verified_source=verified,**self.kw)
 def test_fresh_record_stat_drift_blocks(self):
  rows=r.records(self.source,['a.cpp']);verified={'records':rows,'stats':{'a.cpp':r.stat_identity(self.source/'a.cpp')}}
  os.utime(self.source/'a.cpp',ns=(1700000000000000000,1700000000000000000))
  with self.assertRaises(r.ResumeError):r.restore(self.bundle,self.pin,verified_source=verified,**self.kw)
 def test_external_verifier_before_destination_mutation(self):
  (self.build/'a.obj').unlink()
  def fail(rows):raise r.ResumeError('SDK changed')
  with self.assertRaises(r.ResumeError):r.restore(self.bundle,self.pin,verify_external=fail,**self.kw)
  self.assertFalse((self.build/'a.obj').exists())
if __name__=='__main__':unittest.main()
