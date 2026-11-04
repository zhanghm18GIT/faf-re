from pathlib import Path
import sys,os,json,unittest,tempfile,shutil,subprocess
from unittest.mock import Mock,patch
CI=Path(__file__).resolve().parents[1];sys.path.insert(0,str(CI))
import artifact_driver as a
import driver as core
class ArtifactDriverTests(unittest.TestCase):
 def make(self,stage='A'):
  b=a.ArtifactBuild(CI,json.loads((CI/f'execution-artifact-{stage.lower()}.json').read_text()));b.resume_stage=stage;return b
 def test_inert_contracts(self):
  for st in 'AB':
   b=self.make(st);self.assertEqual(b.c['state'],'DRAFT_NOT_AUTHORIZED');self.assertIsNone(b.c['resume_input']);self.assertIsNone(b.c['root_go_reference'])
 def test_real_contract_validation(self):
  for st in 'AB':
   b=self.make(st);b.c.update(state='APPROVED_FOR_ONE_MANUAL_BUILD',root_go_reference='local fixture only')
   if st=='B':b.c['resume_input']={'url':'https://ci.appveyor.com/api/buildjobs/abc123/artifacts/resume-transfer.zip','size':100,'sha256':'a'*64,'inner':{'size':50,'sha256':'b'*64},'producer':{'build_id':'123','job_id':'abc123','configuration_commit':'c'*40}}
   env={'APPVEYOR':'True','APPVEYOR_ACCOUNT_NAME':b.c['account'],'APPVEYOR_PROJECT_SLUG':b.c['project_slug'],'APPVEYOR_BUILD_WORKER_IMAGE':'Visual Studio 2022','APPVEYOR_SKIP_FINALIZE_ON_EXIT':'true','APPVEYOR_ARTIFACT_UPLOAD_TIMEOUT':'300','APPVEYOR_BUILD_ID':'123','APPVEYOR_BUILD_VERSION':'1','APPVEYOR_JOB_ID':'abc123','APPVEYOR_FORCED_BUILD':'true','APPVEYOR_CACHE_SKIP_SAVE':'true','APPVEYOR_CACHE_SKIP_RESTORE':'true','APPVEYOR_SAVE_CACHE_ON_ERROR':'false'}
   with self.subTest(stage=st),patch.dict(os.environ,env,clear=True),patch.object(core,'validate_interpreter'):b.validate_contract()
   for key in ['APPVEYOR_CACHE_SKIP_SAVE','APPVEYOR_CACHE_SKIP_RESTORE','APPVEYOR_SKIP_FINALIZE_ON_EXIT','APPVEYOR_SAVE_CACHE_ON_ERROR']:
    bad=dict(env);bad[key]='false' if env[key]=='true' else 'true'
    with self.subTest(stage=st,key=key),patch.dict(os.environ,bad,clear=True),patch.object(core,'validate_interpreter'),self.assertRaises(core.Blocked):b.validate_contract()
 def setup_run(self,b,root,fail=None):
  seen=[];b.owned_root=root;root.mkdir();b.verify_owner=Mock();b.remove_junctions=Mock()
  def cleanup(p):
   seen.append('full-cleanup')
   if fail=='full-cleanup':raise core.Blocked('fixture cleanup')
   shutil.rmtree(p)
  b.remove_owned=Mock(side_effect=cleanup)
  names=['validate_contract','verify_configuration_checkout','start_workspace','windows_cleanup_fixture','receive','tools_and_runtime','source_assembly','configure','prepare_build_info','select_objects','capture_before','build_producer','check_after','seal','clean_before_upload','stage_transfer','restore','compile_and_test','stage_package','upload','publish_transfer']
  for name in names:
   def call(n=name):
    seen.append(n)
    if n=='publish_transfer':self.assertFalse(root.exists())
    if n==fail:raise core.Blocked('fixture')
   fn=Mock(side_effect=call);fn.__name__=name;setattr(b,name,fn)
  for name in ['stage_cache','commit_cache','stage_a','stage_b','checkpoint_policy']:
   setattr(b,name,Mock(side_effect=AssertionError('legacy/native method')))
  return seen
 def test_producer_upload_after_complete_cleanup(self):
  with tempfile.TemporaryDirectory() as td:
   b=self.make();seen=self.setup_run(b,Path(td)/'owned');self.assertEqual(b.run(),0)
   self.assertLess(seen.index('full-cleanup'),seen.index('publish_transfer'));self.assertEqual(seen.count('publish_transfer'),1);b.upload.assert_not_called()
 def test_failure_matrix_no_producer_upload(self):
  for fail in ['tools_and_runtime','source_assembly','configure','build_producer','check_after','seal','clean_before_upload','stage_transfer','full-cleanup']:
   with self.subTest(fail=fail),tempfile.TemporaryDirectory() as td:
    b=self.make();self.setup_run(b,Path(td)/'owned',fail);self.assertEqual(b.run(),1);b.publish_transfer.assert_not_called()
 def test_uncertain_child_no_publication(self):
  with tempfile.TemporaryDirectory() as td:
   b=self.make();self.setup_run(b,Path(td)/'owned');b.child_uncertain=True;self.assertEqual(b.run(),1);b.publish_transfer.assert_not_called()
 def test_publication_uncertain_no_retry(self):
  with tempfile.TemporaryDirectory() as td:
   b=self.make();self.setup_run(b,Path(td)/'owned')
   def uncertain():b.upload_attempted=True;raise core.Blocked('provider uncertain')
   b.publish_transfer=Mock(side_effect=uncertain)
   self.assertEqual(b.run(),1);b.publish_transfer.assert_called_once();self.assertFalse(b.upload_accepted);self.assertEqual(b.receipt['state'],'BLOCKED_UPLOAD_UNCERTAIN')
 def test_publish_gate_rejects_owned_root_and_insufficient_budget(self):
  with tempfile.TemporaryDirectory() as td:
   b=self.make();b.owned_root=Path(td)/'owned';b.owned_root.mkdir();b.command=Mock()
   with self.assertRaises(core.Blocked):b.publish_transfer()
   b.owned_root.rmdir();b.transfer_dir=Path(td)/'stage';b.transfer_dir.mkdir();b.pending_transfer=b.transfer_dir/'checkpoint.pending';b.pending_transfer.write_bytes(b'public');b.transfer_pin=a.cache_transport.identity(b.pending_transfer);b.remaining=Mock(return_value=389)
   with self.assertRaises(core.Blocked):b.publish_transfer()
   b.command.assert_not_called()
 def test_consumer_tests_failure_no_client_upload(self):
  with tempfile.TemporaryDirectory() as td:
   b=self.make('B');seen=self.setup_run(b,Path(td)/'owned','compile_and_test');self.assertEqual(b.run(),1);b.upload.assert_not_called();b.publish_transfer.assert_not_called()
 def test_consumer_success_preserves_order(self):
  with tempfile.TemporaryDirectory() as td:
   b=self.make('B');seen=self.setup_run(b,Path(td)/'owned');self.assertEqual(b.run(),0);self.assertLess(seen.index('restore'),seen.index('compile_and_test'));self.assertLess(seen.index('compile_and_test'),seen.index('upload'));b.publish_transfer.assert_not_called()
 def test_material_mapping_matches_existing_material_staging(self):
  with tempfile.TemporaryDirectory() as td:
   b=self.make();b.source=Path(td)/'source';b.stage=Path(td)/'legacy-material';b.stage.mkdir();b.distribution={'additional_notice_paths':{}}
   content={'LEGAL.md':'public legal','src/lua/luaplus/LICENSE':'Lua public notice','src/engine.cpp':'public engine source','lua/options.lua':'public hook','dependencies/ffmpeg/configure':'configure','dependencies/ffmpeg/faf/CMakeLists.txt':'relink','dependencies/ffmpeg/LICENSE':'ffmpeg notice','dependencies/dxc/LICENSE-MS.txt':'MS notice','dependencies/dxc/LICENSE-LLVM.txt':'LLVM notice'}
   for name,data in content.items():
    f=b.source/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(data)
   selected=[n for n in content if not n.startswith('dependencies/dxc/')]
   b.verified_source={'records':[],'stats':{}}
   for name in sorted(selected):
    f=b.source/name;st=a.resume_bundle.stat_identity(f);b.verified_source['records'].append({'path':name,'size':st[2],'sha256':core.sha(f),'mtime_ns':st[3]});b.verified_source['stats'][name]=st
   b.integration={k:[] for k in ['base_commit','base_tree','planned_integrated_tree','submodule_gitlinks','download_dependencies','directx_sdk','build_file_sha256','hook_files','dependency_patch_blobs','changed_files']};b.integration['hook_files']=[{'path':'lua/options.lua'}]
   b.dependency_sources=lambda name,root:sorted(f for f in root.rglob('*') if f.is_file())
   allow={'files':[{'path':n,'git_blob':core.blob_sha(b.source/n)} for n in selected if not n.startswith('dependencies/')]}
   original=core.read_json
   def reader(p):return allow if p.name=='public-source-allowlist.json' else original(p)
   with patch.object(core,'SOURCE_COMPONENTS',['ffmpeg']),patch.object(core,'read_json',side_effect=reader):
    core.Build.stage_materials(b);mapping=b.material_inputs()
   old={f.relative_to(b.stage).as_posix():f.read_bytes() for f in b.stage.rglob('*') if f.is_file()}
   for name,data in old.items():
    if name in {'TESTING.md','README-PACKAGE.md'}:continue
    self.assertIn(name,mapping);value,size,digest=mapping[name];actual=value if isinstance(value,bytes) else value.read_bytes()
    if name=='SOURCE_MANIFEST.json':self.assertEqual(json.loads(actual),json.loads(data))
    else:self.assertEqual(actual,data)
   self.assertEqual({n for n in mapping if n.startswith(('corresponding-source/','notices/','fafengine/'))},{n for n in old if n.startswith(('corresponding-source/','notices/','fafengine/'))})
   (b.source/'src/engine.cpp').write_text('changed input')
   with patch.object(core,'SOURCE_COMPONENTS',['ffmpeg']),self.assertRaises(core.Blocked):b.material_inputs()
 @unittest.skipUnless(shutil.which('pwsh') or shutil.which('powershell'),'PowerShell not installed locally')
 def test_actual_ps_tail_flags_and_failure_no_finalize(self):
  shell=shutil.which('pwsh') or shutil.which('powershell');ps=(CI/'run-artifact-build.ps1').read_text();tail=ps[ps.index('if ($LASTEXITCODE -ne 0)'):]
  flags='\n'.join(l for l in ps.splitlines() if l.startswith('$env:APPVEYOR_') and any(k in l for k in ['CACHE_SKIP','SKIP_FINALIZE','SAVE_CACHE_ON_ERROR']))
  for code in [0,1]:
   with tempfile.TemporaryDirectory() as td:
    root=Path(td);marker=root/'called.txt';script=root/'fixture.ps1'
    stub="function Exit-AppveyorBuild { if ($env:APPVEYOR_CACHE_SKIP_SAVE -ne 'true' -or $env:APPVEYOR_CACHE_SKIP_RESTORE -ne 'true' -or $env:APPVEYOR_SKIP_FINALIZE_ON_EXIT -ne 'true' -or $env:APPVEYOR_SAVE_CACHE_ON_ERROR -ne 'false') { throw 'bad controls' }; Set-Content -LiteralPath '"+str(marker)+"' -Value 'called'; return }"
    script.write_text("$ErrorActionPreference = 'Stop'\n"+flags+'\n'+stub+'\n$LASTEXITCODE = '+str(code)+'\n'+tail)
    result=subprocess.run([shell,'-NoProfile','-NonInteractive','-File',str(script)],capture_output=True,timeout=20)
    self.assertEqual(result.returncode==0,code==0);self.assertEqual(marker.exists(),code==0)
 def test_entry_never_enables_native_cache(self):
  ps=(CI/'run-artifact-build.ps1').read_text();self.assertIn("$env:APPVEYOR_CACHE_SKIP_SAVE = 'true'",ps);self.assertIn("$env:APPVEYOR_CACHE_SKIP_RESTORE = 'true'",ps);self.assertIn("$env:APPVEYOR_SAVE_CACHE_ON_ERROR = 'false'",ps);self.assertNotIn("= 'false'",ps.replace("$env:APPVEYOR_SAVE_CACHE_ON_ERROR = 'false'",''));self.assertTrue(ps.rstrip().endswith('Exit-AppveyorBuild'));self.assertNotIn('resume_ready.py',ps)
  for st in 'ab':
   y=(CI.parent/f'appveyor-artifact-{st}.yml').read_text();self.assertNotIn('\ncache:',y);self.assertIn("APPVEYOR_CACHE_SKIP_RESTORE: 'true'",y)
if __name__=='__main__':unittest.main()
