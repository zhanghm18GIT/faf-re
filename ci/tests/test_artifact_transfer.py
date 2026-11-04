from pathlib import Path
import sys,unittest,tempfile,json,zipfile,stat
CI=Path(__file__).resolve().parents[1];sys.path.insert(0,str(CI))
import artifact_transfer as t
class TransferTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.inner=self.root/'inner.zip';self.inner.write_bytes(b'fixed public checkpoint');self.ip=t.transport.identity(self.inner)
  self.material=b'fixed public source';self.materials={'corresponding-source/engine/a.cpp':(self.material,len(self.material),t.digest(self.material))};self.meta={'producer':'fixed'}
  self.archive=self.root/'transfer.zip';self.pin,self.receipt=t.seal(self.archive,self.inner,self.ip,self.materials,self.meta)
 def test_round_trip(self):
  dst=self.root/'restored.zip';m=t.verify(self.archive,self.pin,self.meta,self.ip,destination=dst)
  self.assertEqual(dst.read_bytes(),self.inner.read_bytes());self.assertEqual(m,self.receipt)
  with zipfile.ZipFile(self.archive) as z:self.assertEqual(z.getinfo('checkpoint.zip').compress_type,zipfile.ZIP_STORED)
 def test_bad_outer_pin_before_parse(self):
  self.archive.write_bytes(b'not zip')
  with self.assertRaises(t.TransferError):t.verify(self.archive,self.pin,self.meta,self.ip)
 def test_external_identity_mismatch(self):
  with self.assertRaises(t.TransferError):t.verify(self.archive,self.pin,{'producer':'other'},self.ip)
 def test_inner_pin_mismatch(self):
  with self.assertRaises(t.TransferError):t.verify(self.archive,self.pin,self.meta,{'size':1,'sha256':'a'*64})
 def mutate(self,fn):
  with zipfile.ZipFile(self.archive) as z:items=[(i,z.read(i.filename)) for i in z.infolist()]
  fn(items)
  with zipfile.ZipFile(self.archive,'w') as z:
   for i,data in items:z.writestr(i,data)
  return t.transport.identity(self.archive)
 def test_member_negatives(self):
  cases=['extra','traversal','case','symlink','fifo','missing','content','oversize']
  original=self.archive.read_bytes()
  for case in cases:
   self.archive.write_bytes(original)
   def mutation(items):
    if case=='extra':items.append(('unknown.txt',b'x'))
    elif case=='traversal':items.append(('../x',b'x'))
    elif case=='case':items.append(('CHECKPOINT.ZIP',b'x'))
    elif case in ['symlink','fifo']:items[1][0].external_attr=((stat.S_IFLNK if case=='symlink' else stat.S_IFIFO)|0o600)<<16
    elif case=='missing':items.pop()
    elif case=='content':items[-1]=(items[-1][0],b'changed')
    elif case=='oversize':
     m=json.loads(items[0][1]);m['materials'][0]['size']=t.MAX_TOTAL+1;items[0]=(items[0][0],json.dumps(m).encode())
   pin=self.mutate(mutation)
   with self.subTest(case=case),self.assertRaises(Exception):t.verify(self.archive,pin,self.meta,self.ip)
 def test_fail_after_extraction_cleans_created_inner(self):
  pin=self.mutate(lambda items:items.__setitem__(-1,(items[-1][0],b'changed')));dst=self.root/'inner-new.zip'
  with self.assertRaises(t.TransferError):t.verify(self.archive,pin,self.meta,self.ip,destination=dst)
  self.assertFalse(dst.exists())
 def test_existing_destination_not_clobbered(self):
  dst=self.root/'exists';dst.write_bytes(b'keep')
  with self.assertRaises(t.TransferError):t.verify(self.archive,self.pin,self.meta,self.ip,destination=dst)
  self.assertEqual(dst.read_bytes(),b'keep')
 def test_material_drift_seal_removes_output(self):
  dst=self.root/'bad.zip';bad={'a.cpp':(b'bad',len(self.material),t.digest(self.material))}
  with self.assertRaises(t.TransferError):t.seal(dst,self.inner,self.ip,bad,self.meta)
  self.assertFalse(dst.exists())
 def test_duplicate_case_material_rejected(self):
  bad=dict(self.materials);bad['CORRESPONDING-SOURCE/engine/a.cpp']=next(iter(bad.values()))
  with self.assertRaises(t.TransferError):t.seal(self.root/'bad.zip',self.inner,self.ip,bad,self.meta)
if __name__=='__main__':unittest.main()
