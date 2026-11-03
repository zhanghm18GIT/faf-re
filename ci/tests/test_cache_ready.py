import sys,tempfile,json,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import cache_transport as c,cache_ready as r
class Ready(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.p=Path(self.t.name);(self.p/'checkpoint.zip').write_bytes(b'synthetic-public-bundle');pin=c.identity(self.p/'checkpoint.zip');self.env={'APPVEYOR_JOB_ID':'job1','APPVEYOR_BUILD_ID':'1','APPVEYOR_REPO_COMMIT':'a'*40};self.receipt=dict(pin,state='READY_FOR_NATIVE_CACHE_NOT_CONFIRMED_SAVED',publication='not_a_published_artifact',cache_access_guarantee='UNKNOWN',account_quota_headroom='UNKNOWN',recipe='f'*64,producer={'job_id':'job1','build_id':'1','provider_commit':'a'*40},artifact={});self.save()
 def save(self):(self.p/'CACHE_READY.json').write_text(json.dumps(self.receipt))
 def test_valid(self):self.assertTrue(r.verify(self.p,'f'*64,self.env))
 def test_wrong_producer(self):
  with self.assertRaises(c.CacheError):r.verify(self.p,'f'*64,dict(self.env,APPVEYOR_JOB_ID='wrong'))
 def test_wrong_recipe(self):
  with self.assertRaises(c.CacheError):r.verify(self.p,'a'*64,self.env)
 def test_missing_environment(self):
  with self.assertRaises(c.CacheError):r.verify(self.p,'f'*64,{})
 def test_unverified_claim(self):
  self.receipt['cache_access_guarantee']='PRIVATE';self.save()
  with self.assertRaises(c.CacheError):r.verify(self.p,'f'*64,self.env)
 def test_wrong_state(self):
  self.receipt['state']='SAVED';self.save()
  with self.assertRaises(c.CacheError):r.verify(self.p,'f'*64,self.env)
 def test_extra_file(self):
  (self.p/'private.txt').write_text('synthetic')
  with self.assertRaises(c.CacheError):r.verify(self.p,'f'*64,self.env)
 def test_mutated_bundle(self):
  (self.p/'checkpoint.zip').write_bytes(b'changed')
  with self.assertRaises(c.CacheError):r.verify(self.p,'f'*64,self.env)
if __name__=='__main__':unittest.main()
