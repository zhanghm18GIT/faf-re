"""Local exact-byte protocol proof, not native compiler/provider performance evidence."""
from pathlib import Path
import sys,json,tempfile,unittest,os,shutil
from unittest.mock import Mock,patch
CI=Path(__file__).resolve().parents[1];sys.path.insert(0,str(CI))
import artifact_driver as a
import resume_bundle as rb
import resume_driver as legacy
import driver as core

def pin(job):
 return {'url':f'https://ci.appveyor.com/api/buildjobs/{job}/artifacts/resume-transfer.zip','size':10,'sha256':'a'*64,'inner':{'size':5,'sha256':'b'*64},'producer':{'build_id':'123','job_id':job,'configuration_commit':'c'*40},'predecessor':None}
class RelayProtocol(unittest.TestCase):
 def make(self,root,role,predecessor=None):
  b=a.ArtifactBuild(CI,json.loads((CI/f'execution-artifact-{role.lower()}.json').read_text()));b.resume_stage=role;b.root=root;b.source=root/'source';b.build=root/'build';b.source.mkdir(parents=True);b.build.mkdir()
  (b.source/'x.cpp').write_bytes(b'fixed public source')
  b.c['resume_input']=predecessor;b.recipe_key='dependency';b.resume_key='common-allocation';b.material_selection_sha='material';b.graph={'outputs':['dep.lib'],'identity':'graph'};b.compile_argv_identity='argv';b.effective_env_identity='env';b.build_info_command='exact BuildInfo';b.receipt.update(tools={},cache_selections={},appveyor={'build_id':'123','job_id':role.lower()+'123','provider_commit':'c'*40})
  b.owned_baseline={'records':[{'root':'source','path':'x.cpp'}]+[{'root':'generated','path':x} for x in legacy.BUILD_INFO_HEADERS],'sha256':'source','mbedtls_actual_glob':[]}
  full=[{'output':f'engine/{i:04}.obj','source':'x.cpp','command_sha256':'d'*64} for i in range(450)]
  b.selection=full[:150] if role=='A' else full;b.selected=[r['output'] for r in b.selection];b.input_selection=[] if role=='A' else full[:150 if role=='R' else 450]
  return b
 def fill(self,b):
  _,outputs,_=b.bundle_spec()
  for name in outputs:
   p=b.build/name;p.parent.mkdir(parents=True,exist_ok=True)
   if not p.exists():p.write_bytes(('fixed '+name).encode());os.utime(p,ns=(1700000000000000000,1700000000000000000))
 def seal(self,b,path):
  names,outputs,meta=b.bundle_spec()
  return rb.seal(path,source=b.source,build=b.build,source_names=names,output_names=outputs,metadata=meta,producer=b.producer())
 def restore(self,b,path,p):
  names,outputs,meta=b.restore_spec()
  return rb.restore(path,p,source=b.source,build=b.build,source_names=names,output_names=outputs,metadata=meta,producer=b.restore_producer())
 def test_exact_a150_relay450_final_roundtrip(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);first=self.make(root/'a','A');self.fill(first);ap=self.seal(first,root/'a.zip');pa=pin('a123');pa['inner']=ap
   relay=self.make(root/'r','R',pa);report=self.restore(relay,root/'a.zip',ap);self.assertEqual(len([r for r in report['verified_outputs'] if r['path'].endswith('.obj')]),150)
   self.assertFalse((relay.build/'engine/0150.obj').exists());self.assertEqual(sum(relay.producer_groups(),[]),relay.selected[150:450])
   self.fill(relay);rp=self.seal(relay,root/'r.zip');pr=pin('r123');pr['inner']=rp;pr['predecessor']=pa
   final=self.make(root/'b','B',pr);report=self.restore(final,root/'r.zip',rp);self.assertEqual(len([r for r in report['verified_outputs'] if r['path'].endswith('.obj')]),450)
   self.assertEqual(first.transfer_metadata(),relay.transfer_metadata(incoming=True));self.assertEqual(relay.transfer_metadata(),final.transfer_metadata(incoming=True))
 def test_real_driver_receive_restore_seal_uses_distinct_paths(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);first=self.make(root/'a','A');self.fill(first)
   def prepare(b):
    (b.root/'out').mkdir();b.remaining=Mock(return_value=3300);b.verified_source=None;b.external_header_rows=Mock(return_value=[]);b.receipt['resume_selection']={'count':len(b.selection)}
    data=b'fixed synthetic corresponding material';b.material_inputs=Mock(return_value={'source.txt':(data,len(data),a.transfer.digest(data))})
   prepare(first);first.seal();pa=pin('a123');pa.update(first.transfer_pin);pa['inner']=first.cache_pin
   relay=self.make(root/'r','R',pa);prepare(relay)
   def download(url,destination,size,seconds):
    self.assertEqual(url,pa['url']);self.assertEqual(size,first.artifact.stat().st_size);shutil.copyfile(first.artifact,destination)
   relay.download_fixed=Mock(side_effect=download);relay.receive()
   incoming=relay.bundle;incoming_hash=core.sha(incoming);outer=relay.root/'out/incoming-transfer.zip';self.assertTrue(outer.exists())
   self.assertEqual(incoming.name,'incoming-checkpoint.zip');self.assertFalse((relay.root/'out/checkpoint.zip').exists())
   relay.ninja=Path('ninja');relay.command=Mock(return_value='[1/1] exact BuildInfo');relay.verify_external_headers=Mock()
   relay.restore();self.fill(relay);relay.seal()
   self.assertTrue((relay.root/'out/checkpoint.zip').exists());self.assertTrue((relay.root/'out/resume-transfer.zip').exists());self.assertEqual(core.sha(incoming),incoming_hash)
   with self.assertRaises(rb.ResumeError):relay.seal()
 def test_wrong_prefix_and_predecessor_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);first=self.make(root/'a','A');self.fill(first);ap=self.seal(first,root/'a.zip');pa=pin('a123');pa['inner']=ap
   relay=self.make(root/'r','R',pa);relay.input_selection=relay.selection[:151]
   with self.assertRaises(rb.ResumeError):self.restore(relay,root/'a.zip',ap)
   relay.input_selection=relay.selection[:150];relay.c['resume_input']['predecessor']=pin('wrong')
   with self.assertRaises(rb.ResumeError):self.restore(relay,root/'a.zip',ap)
 def test_chain_shape_rejects_missing_self_and_deep(self):
  b=object.__new__(a.ArtifactBuild)
  good=pin('r123');good['predecessor']=pin('a123');b.validate_input_pin(good,expects_parent=True)
  for bad in [pin('r123'),{**good,'predecessor':pin('r123')},{**good,'predecessor':good}]:
   with self.assertRaises(core.Blocked):b.validate_input_pin(bad,expects_parent=True)
 def test_header_dedup_matches_reference(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);b=self.make(root/'fixture','A');b.ninja=Path('ninja');sysroot=root/'sdk';sysroot.mkdir();(sysroot/'one.h').write_bytes(b'one');(sysroot/'two.h').write_bytes(b'two');(b.build/'local.h').write_bytes(b'generated')
   b.external_header_roots=lambda:[sysroot]*5
   text='\n'.join('    '+str(p) for p in [sysroot/'one.h']*300+[sysroot/'../sdk/two.h',b.source/'x.cpp',b.build/'local.h'])
   b.command=Mock(return_value=text)
   def reference(text):
    paths=set()
    for line in text.splitlines():
     if not line.startswith('    '):continue
     value=line[4:];core.require(value and value==value.strip(),'format');p=Path(value);p=(p if p.is_absolute() else b.build/p).resolve()
     if p.is_relative_to(b.build):continue
     if p.is_relative_to(b.source) and not p.is_relative_to(b.source/'dependencies/dxsdk/Include'):continue
     core.require(any(p.is_relative_to(r.resolve()) for r in b.external_header_roots()),'outside');paths.add(p)
    core.require(paths and len(paths)<=50000,'empty')
    return [{'path':str(p),'size':p.stat().st_size,'sha256':core.sha(p)} for p in sorted(paths)]
   original=Path.resolve;calls=[]
   def counted(path,*args,**kwargs):calls.append(str(path));return original(path,*args,**kwargs)
   with patch.object(Path,'resolve',counted):new_rows=b.external_header_rows()
   self.assertEqual(len(calls),12);calls.clear()
   with patch.object(Path,'resolve',counted):old_rows=reference(text)
   self.assertGreater(len(calls),300);self.assertEqual(new_rows,old_rows)
   for bad in ['    ','    /outside.h','    '+str(sysroot/'one.h')+' ','nothing']:
    b.command=Mock(return_value=bad)
    with self.assertRaises(core.Blocked):reference(bad)
    with self.assertRaises(core.Blocked):b.external_header_rows()
if __name__=='__main__':unittest.main()
