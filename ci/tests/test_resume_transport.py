import sys,tempfile,unittest,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import resume_transport as c
class Transport(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.src=self.root/'source.zip';self.src.write_bytes(b'public bounded checkpoint');self.pin=c.identity(self.src);self.d=self.root/'handoff'
 def test_roundtrip(self):
  c.stage(self.src,self.d,self.pin);r=c.commit(self.d,self.pin,owned_cleanup_verified=True);self.assertEqual(r['state'],'READY_FOR_NATIVE_CACHE_NOT_CONFIRMED_SAVED');out=c.receive(self.d/'checkpoint.zip',self.root/'consumer.zip',self.pin);self.assertEqual(out.read_bytes(),self.src.read_bytes())
 def test_cleanup_failure(self):
  c.stage(self.src,self.d,self.pin)
  with self.assertRaises(c.CacheError):c.commit(self.d,self.pin,owned_cleanup_verified=False)
  self.assertFalse((self.d/'checkpoint.zip').exists())
 def test_wrong_source(self):
  p=dict(self.pin,sha256='0'*64)
  with self.assertRaises(c.CacheError):c.stage(self.src,self.d,p)
  self.assertFalse(self.d.exists())
 def test_existing_handoff(self):
  self.d.mkdir()
  with self.assertRaises(c.CacheError):c.stage(self.src,self.d,self.pin)
 def test_extra_handoff(self):
  c.stage(self.src,self.d,self.pin);(self.d/'private.txt').write_bytes(b'synthetic')
  with self.assertRaises(c.CacheError):c.commit(self.d,self.pin,owned_cleanup_verified=True)
 def test_mutation(self):
  c.stage(self.src,self.d,self.pin);(self.d/'checkpoint.pending').write_bytes(b'changed')
  with self.assertRaises(c.CacheError):c.commit(self.d,self.pin,owned_cleanup_verified=True)
 def test_consumer_wrong_identity(self):
  with self.assertRaises(c.CacheError):c.receive(self.src,self.root/'out',dict(self.pin,sha256='0'*64))
  self.assertFalse((self.root/'out').exists())
 def test_existing_consumer_not_overwritten(self):
  out=self.root/'out';out.write_bytes(b'keep')
  with self.assertRaises(c.CacheError):c.receive(self.src,out,self.pin)
  self.assertEqual(out.read_bytes(),b'keep')
 def test_symlink(self):
  p=self.root/'link';p.symlink_to(self.src)
  with self.assertRaises(c.CacheError):c.identity(p)
 def test_hardlink(self):
  os.link(self.src,self.root/'hard')
  with self.assertRaises(c.CacheError):c.identity(self.src)
 def test_pin_types(self):
  for p in [dict(self.pin,size=True),dict(self.pin,size=0),dict(self.pin,extra='x'),dict(self.pin,sha256='F'*64)]:
   with self.assertRaises(c.CacheError):c.expected(p)
if __name__=='__main__':unittest.main()
