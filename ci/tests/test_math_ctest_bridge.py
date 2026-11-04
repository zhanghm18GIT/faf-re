from pathlib import Path
import sys,json,tempfile,unittest,copy,os
from unittest.mock import Mock,patch
CI=Path(__file__).resolve().parents[1];sys.path.insert(0,str(CI))
import artifact_driver as a
import driver as core
import resume_driver as resume
class MathCtestBridge(unittest.TestCase):
 def make(self,stage='B'):
  b=a.ArtifactBuild(CI,json.loads((CI/f'execution-artifact-{stage.lower()}.json').read_text()));b.resume_stage=stage;b.c['reviewed_producer_bridge']=a.BRIDGE_ID;b.c['resume_input']=core.read_json(CI/'reviewed-r55025409.json');return b
 def test_exact_bridge_and_normal_consumer_manifest(self):
  b=self.make();own=b.c['reviewed_driver_manifest_sha256'];self.assertNotEqual(own,a.OLD_PRODUCER_MANIFEST);self.assertEqual(b.incoming_manifest(),a.OLD_PRODUCER_MANIFEST);self.assertEqual(b.c['reviewed_driver_manifest_sha256'],own)
  b.c['reviewed_producer_bridge']=None;self.assertEqual(b.incoming_manifest(),own)
 def test_bridge_negative_scope_and_pin_fields(self):
  for stage in ['A','R']:
   with self.subTest(stage=stage),self.assertRaises(core.Blocked):self.make(stage).incoming_manifest()
  for field in ['url','size','sha256','inner','producer','predecessor']:
   b=self.make();b.c['resume_input'][field]=None
   with self.subTest(field=field),self.assertRaises(core.Blocked):b.incoming_manifest()
  b=self.make();b.c['reviewed_producer_bridge']='arbitrary-manifest'
  with self.assertRaises(core.Blocked):b.incoming_manifest()
 def test_bridge_reference_file_is_hard_pinned(self):
  b=self.make()
  with patch.object(core,'sha',return_value='0'*64),self.assertRaises(core.Blocked):b.incoming_manifest()
 def test_incoming_only_manifest_substitution(self):
  b=self.make();b.recipe_key='deps';b.resume_key='recipe';b.material_selection_sha='material';b.receipt.update(tools={'compiler':'fixed'},cache_selections={});b.owned_baseline={'records':[{'root':'source','path':'a.cpp'}],'sha256':'source','mbedtls_actual_glob':[]};b.graph={'outputs':['dep.lib'],'identity':'graph'};b.compile_argv_identity='argv';b.effective_env_identity='env';b.build_info_command='BuildInfo';b.input_selection=[{'output':'engine/a.obj','source':'a.cpp','command_sha256':'f'*64}];b.selection=b.input_selection;b.selected=['engine/a.obj']
  names,outputs,baseline=resume.ResumeBuild.bundle_spec(b,b.input_selection);baseline['predecessor']=b.c['resume_input']['predecessor']
  _,_,incoming=b.restore_spec();diff={k for k in baseline if baseline[k]!=incoming[k]};self.assertEqual(diff,{'driver_manifest_sha256'});self.assertEqual(incoming['driver_manifest_sha256'],a.OLD_PRODUCER_MANIFEST)
  self.assertEqual(b.transfer_metadata(incoming=True)['driver_manifest_sha256'],a.OLD_PRODUCER_MANIFEST);self.assertEqual(b.transfer_metadata()['driver_manifest_sha256'],b.c['reviewed_driver_manifest_sha256'])
  b.receipt['tools']['compiler']='changed';self.assertNotEqual(b.restore_spec()[2]['tools'],{'compiler':'fixed'})
  b.compile_argv_identity='changed';self.assertEqual(b.restore_spec()[2]['compile_argv_identity'],'changed')
 def test_current_consumer_manifest_still_validated(self):
  b=self.make();b.c.update(state='APPROVED_FOR_ONE_MANUAL_BUILD',root_go_reference='fixture');b.c['reviewed_driver_manifest_sha256']='0'*64
  env={'APPVEYOR':'True','APPVEYOR_ACCOUNT_NAME':b.c['account'],'APPVEYOR_PROJECT_SLUG':b.c['project_slug'],'APPVEYOR_BUILD_WORKER_IMAGE':'Visual Studio 2022','APPVEYOR_SKIP_FINALIZE_ON_EXIT':'true','APPVEYOR_ARTIFACT_UPLOAD_TIMEOUT':'300','APPVEYOR_BUILD_ID':'123','APPVEYOR_BUILD_VERSION':'1','APPVEYOR_JOB_ID':'consumer123','APPVEYOR_FORCED_BUILD':'true','APPVEYOR_CACHE_SKIP_SAVE':'true','APPVEYOR_CACHE_SKIP_RESTORE':'true','APPVEYOR_SAVE_CACHE_ON_ERROR':'false'}
  with patch.dict(os.environ,env,clear=True),patch.object(core,'validate_interpreter'),self.assertRaises(core.Blocked):b.validate_contract()
 def test_two_ctests_preserve_inputs_timeouts_and_shared_window(self):
  b=self.make();b.root=Path('/fixture');b.build=b.root/'build';b.ctest=Path('ctest');b.remaining=Mock(return_value=420);b.command=Mock()
  with patch.object(a.time,'monotonic',side_effect=[100,100,120]),patch.object(core,'validate_junit') as validate:b.run_math_ctests()
  calls=b.command.call_args_list;self.assertEqual(len(calls),2);self.assertEqual([c.kwargs['cap'] for c in calls],[420,400]);self.assertEqual([c.args[0][c.args[0].index('--timeout')+1] for c in calls],['180','360']);self.assertEqual([c.args[0][c.args[0].index('-R')+1] for c in calls],['^sim_math$','^math_dump$']);self.assertTrue(all('--iters' not in c.args[0] and '--filter' not in c.args[0] for c in calls));self.assertEqual([c.args[1] for c in validate.call_args_list],[['sim_math'],['math_dump']])
 def test_no_math_launch_after_shared_deadline(self):
  b=self.make();b.root=Path('/fixture');b.build=b.root/'build';b.ctest=Path('ctest');b.remaining=Mock(return_value=420);b.command=Mock()
  with patch.object(a.time,'monotonic',side_effect=[100,100,521]),patch.object(core,'validate_junit'),self.assertRaises(core.Blocked):b.run_math_ctests()
  self.assertEqual(b.command.call_count,1)
 def test_math_failure_or_invalid_junit_does_not_return_success(self):
  for fail in ['command','junit']:
   b=self.make();b.root=Path('/fixture');b.build=b.root/'build';b.ctest=Path('ctest');b.remaining=Mock(return_value=420);b.command=Mock(side_effect=[None,core.Blocked('timeout')] if fail=='command' else None)
   with patch.object(core,'validate_junit',side_effect=[None,core.Blocked('failed result')] if fail=='junit' else None),self.assertRaises(core.Blocked):b.run_math_ctests()
if __name__=='__main__':unittest.main()
