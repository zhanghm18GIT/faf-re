import sys,unittest,dataclasses,hashlib,json
from unittest import mock
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import checkpoint as c
import structured_objects as so
import test_checkpoint as fixture
coff=fixture.coff;archive=fixture.archive
class StructuredCheckpoint(unittest.TestCase):
 def setUp(self):
  self.f=fixture.TestCheckpoint();self.f.setUp();self.addCleanup(self.f.doCleanups)
  self.f.zip.unlink()
  self.p=dataclasses.replace(self.f.policy,object_mode='fixed-public-source-structured-v1',archive_members={'build/dep.lib':{'a.obj':'build/dep.obj'}},canaries=(b'SYNTHETIC_PRIVATE_CANARY_123456789',))
 def seal(self):return c.seal_checkpoint(self.f.zip,self.p,self.f.meta)
 def test_full_restore(self):
  r=self.seal();self.f.build.joinpath('dep.obj').unlink();self.f.build.joinpath('dep.lib').unlink()
  c.restore_checkpoint(self.f.zip,self.p,r['sha256'],r['bytes'],self.f.meta)
  self.assertEqual((self.f.build/'dep.obj').read_bytes(),coff())
 def test_standalone_prepass_diagnostic_seal_and_subset(self):
  original=c._content
  def reject(spec,data,policy):
   if spec.kind=='obj':
    raise so.StructureError('unsupported CodeView symbol kind',details={'type_index':65534,'section_index':2,'record_offset':144})
   return original(spec,data,policy)
  for mode in ('seal','subset'):
   with self.subTest(mode=mode),mock.patch.object(c,'_content',side_effect=reject):
    with self.assertRaises(c.CheckpointError) as caught:
     if mode=='seal':self.seal()
     else:c.validate_built_subset(self.p,['build/dep.obj','build/dep.lib','build/.ninja_log','build/.ninja_deps'])
    value=json.loads(str(caught.exception));self.assertEqual(value['phase'],'standalone-object-inventory');self.assertEqual(value['member'],'build/dep.obj')
    self.assertEqual(value['format_details'],{'type_index':65534,'section_index':2,'record_offset':144})
 def test_archive_object_substitution(self):
  data=bytearray(coff());data[-1]=0x90;self.f.build.joinpath('dep.lib').write_bytes(archive(bytes(data)))
  with self.assertRaises(Exception):self.seal()
 def test_archive_unknown_member(self):
  self.p=dataclasses.replace(self.p,archive_members={'build/dep.lib':{'wrong.obj':'build/dep.obj'}})
  with self.assertRaises(Exception):self.seal()
 def test_no_canaries(self):
  with self.assertRaises(c.CheckpointError):c.validate_policy(dataclasses.replace(self.p,canaries=()))
 def test_unknown_mode(self):
  with self.assertRaises(c.CheckpointError):c.validate_policy(dataclasses.replace(self.p,object_mode='skip'))
 def test_plaintext_canary_rejected_in_object(self):
  self.f.build.joinpath('dep.obj').write_bytes(coff()+self.p.canaries[0])
  with self.assertRaises(Exception):self.seal()
 def test_manifest_hash_cannot_authorize_wrong_archive(self):
  r=self.seal()
  # Wrong outer identity fails before member-supplied hashes can be used.
  with self.assertRaises(c.CheckpointError):c.validate_checkpoint(self.f.zip,self.p,'0'*64,r['bytes'],self.f.meta)
if __name__=='__main__':unittest.main()
