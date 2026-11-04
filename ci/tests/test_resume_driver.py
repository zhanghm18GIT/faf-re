from pathlib import Path
import sys,json,unittest,subprocess,tempfile,os
from unittest.mock import Mock,patch
CI=Path(__file__).resolve().parents[1];sys.path.insert(0,str(CI))
import resume_driver as r
import driver as core
class ResumeTests(unittest.TestCase):
 def make(self,stage='A'):
  b=r.ResumeBuild(CI,json.loads((CI/('execution-resume-'+stage.lower()+'.json')).read_text()));b.resume_stage=stage;return b
 def test_inert_both_contracts(self):
  for st in ['A','B']:
   c=self.make(st).c;self.assertEqual(c['state'],'DRAFT_NOT_AUTHORIZED');self.assertFalse(c['upload_exact_package']);self.assertIsNone(c['resume_input'])
 def test_actual_complete_contract_validation_a_and_b(self):
  for st in ['A','B']:
   b=self.make(st);b.c.update(state='APPROVED_FOR_ONE_MANUAL_BUILD',root_go_reference='local-fixture-only',upload_exact_package=st=='B')
   if st=='B':b.c['resume_input']={'size':1,'sha256':'a'*64,'producer':{'build_id':'123','job_id':'abc123','configuration_commit':'b'*40}}
   env={'APPVEYOR':'True','APPVEYOR_ACCOUNT_NAME':b.c['account'],'APPVEYOR_PROJECT_SLUG':b.c['project_slug'],'APPVEYOR_BUILD_WORKER_IMAGE':'Visual Studio 2022','APPVEYOR_SKIP_FINALIZE_ON_EXIT':'true','APPVEYOR_ARTIFACT_UPLOAD_TIMEOUT':'300','APPVEYOR_BUILD_ID':'123','APPVEYOR_BUILD_VERSION':'1','APPVEYOR_JOB_ID':'abc123','APPVEYOR_FORCED_BUILD':'true','APPVEYOR_CACHE_SKIP_SAVE':'true','APPVEYOR_CACHE_SKIP_RESTORE':'true' if st=='A' else 'false'}
   with self.subTest(stage=st),patch.dict(os.environ,env,clear=True),patch.object(core,'validate_interpreter'):
    b.validate_contract()
   self.assertEqual(b.resume_stage,st)
 def test_selection_uses_exact_real_graph_and_source(self):
  b=self.make()
  with tempfile.TemporaryDirectory() as td:
   b.ninja=Path('ninja');b.source=Path(td)/'source';(b.source/'src').mkdir(parents=True);b.build=Path(td)/'build';b.graph={'outputs':['dep.obj']}
   files=[];rows=[]
   for i in range(301):
    p=b.source/'src'/('file'+str(i)+'.cpp');p.write_text('public');files.append(p)
    rows.append({'output':'src/CMakeFiles/engine.dir/'+str(i).zfill(4)+'.obj','file':str(p),'directory':str(b.build),'command':'clang-cl '+str(p)})
   reader=patch.object(core,'read_json',return_value={'files':[{'path':p.relative_to(b.source).as_posix()} for p in files]});reader.start();self.addCleanup(reader.stop)
   b.command=Mock(side_effect=[json.dumps(rows),json.dumps(rows),'\n'.join(e['command'] for e in rows),'\n'.join(e['output']+': CXX_COMPILER' for e in rows)])
   b.select_objects();self.assertEqual(len(b.selected),300);self.assertEqual(b.selected,sorted(e['output'] for e in rows)[:300])
   b.command=Mock(side_effect=[json.dumps(rows),json.dumps(rows),'\n'.join(e['command'] for e in rows),''])
   with self.assertRaises(core.Blocked):b.select_objects()
   rows[1]['output']=rows[0]['output'];b.command=Mock(side_effect=[json.dumps(rows),json.dumps(rows),'\n'.join(e['command'] for e in rows),'\n'.join(e['output']+': CXX_COMPILER' for e in rows)])
   with self.assertRaises(core.Blocked):b.select_objects()
 def test_batches_bound_count_and_characters(self):
  values=['src/CMakeFiles/engine.dir/'+('a'*180)+str(i)+'.obj' for i in range(300)]
  groups=list(r.batches(values));self.assertEqual(sum(groups,[]),values)
  self.assertTrue(all(len(g)<=50 and len(subprocess.list2cmdline(g))<=7000 for g in groups))
 def test_single_target_too_long(self):
  with self.assertRaises(core.Blocked):list(r.batches(['x'*7001]))
 def setup_run(self,b,fail=None):
  seen=[]
  for name in ['validate_contract','verify_configuration_checkout','start_workspace','windows_cleanup_fixture','receive','tools_and_runtime','source_assembly','configure','prepare_build_info','select_objects','capture_before','build_producer','check_after','seal','clean_before_upload','stage_cache','restore','compile_and_test','stage_package','upload','commit_cache']:
   def call(n=name):
    seen.append(n)
    if n==fail:raise core.Blocked('fixture')
   fn=Mock(side_effect=call);fn.__name__=name;setattr(b,name,fn)
  return seen
 def test_a_completed_boundary_no_tests_or_upload(self):
  b=self.make();seen=self.setup_run(b);self.assertEqual(b.run(),0)
  self.assertLess(seen.index('build_producer'),seen.index('seal'));self.assertLess(seen.index('clean_before_upload'),seen.index('stage_cache'));self.assertEqual(seen.count('configure'),1)
  self.assertNotIn('upload',seen);self.assertNotIn('restore',seen);self.assertIn('commit_cache',seen)
 def test_failure_never_seals_or_commits(self):
  b=self.make();self.setup_run(b,fail='build_producer');self.assertEqual(b.run(),1);b.seal.assert_not_called();b.commit_cache.assert_not_called()
 def test_b_order_and_tests(self):
  b=self.make('B');seen=self.setup_run(b);self.assertEqual(b.run(),0)
  self.assertLess(seen.index('receive'),seen.index('configure'));self.assertLess(seen.index('configure'),seen.index('restore'));self.assertLess(seen.index('restore'),seen.index('compile_and_test'));self.assertEqual(seen.count('configure'),1)
  self.assertNotIn('seal',seen);self.assertNotIn('commit_cache',seen);self.assertIn('upload',seen)
 def test_restore_failure_prevents_build_upload(self):
  b=self.make('B');self.setup_run(b,fail='restore');self.assertEqual(b.run(),1);b.compile_and_test.assert_not_called();b.upload.assert_not_called()
 def test_shared_producer_deadline_not_per_batch(self):
  b=self.make();b.root=Path('/tmp/fixture');b.build=b.root/'build';b.cmake=Path('cmake');b.selected=['engine/'+str(i)+'.obj' for i in range(110)];b.graph={'outputs':['dep.obj']};b.remaining=Mock(return_value=3300)
  clock=[1000]
  def now():clock[0]+=10;return clock[0]
  with patch.object(r.time,'monotonic',side_effect=now),patch.object(r.build_capture,'run_build',return_value={'state':'SUCCESS'}) as run,patch.object(Path,'is_file',return_value=True):b.build_producer()
  caps=[call.kwargs['timeout'] for call in run.call_args_list];self.assertEqual(len(caps),4);self.assertTrue(all(a>b for a,b in zip(caps,caps[1:])))
 def test_mtime_change_during_build_rejected(self):
  b=self.make();b.compile_input_stats={'source/x':(1,2,3,100)};b.input_stats={'source/x':(1,2,3,200)}
  with patch.object(r.single.SingleBuild,'check_after'):
   with self.assertRaises(core.Blocked):b.check_after()
 def test_build_info_only_actual_update_admission(self):
  expected='cmd /C exact-build-info'
  self.assertEqual(r.admitted_update_log('[1/2] '+expected+'\nninja: no work to do.\n',expected),1)
  with self.assertRaises(core.Blocked):r.admitted_update_log('[1/2] '+expected+'\n[2/2] clang-cl compile.cpp',expected)
 def test_client_first_before_incremental_tests(self):
  b=self.make('B');b.cmake=Path('cmake');b.build=Path('/tmp/build');b.command=Mock(return_value='actual client link')
  with patch.object(r.single.SingleBuild,'compile_and_test') as tests:b.compile_and_test()
  self.assertEqual(b.command.call_args.kwargs['name'],'client-first');self.assertIn('faf_main',b.command.call_args.args[0]);tests.assert_called_once()
 def test_exact_buildinfo_headers_added(self):
  b=self.make();b.build=Path('/tmp/build')
  with patch.object(r.single.SingleBuild,'source_inputs',return_value=([],[])),patch.object(Path,'is_file',return_value=True),patch.object(Path,'is_symlink',return_value=False):
   source,generated=b.source_inputs()
  self.assertEqual({p.relative_to(b.build).as_posix() for p in generated},set(r.BUILD_INFO_HEADERS))
 def test_failed_batch_marks_uncertain(self):
  b=self.make();b.root=Path('/tmp/fixture');b.build=b.root/'build';b.cmake=Path('cmake');b.selected=[];b.remaining=Mock(return_value=3300)
  with patch.object(r.build_capture,'run_build',return_value={'state':'TIMEOUT'}):
   with self.assertRaises(core.Blocked):b.build_producer()
  self.assertTrue(b.child_uncertain)
if __name__=='__main__':unittest.main()
