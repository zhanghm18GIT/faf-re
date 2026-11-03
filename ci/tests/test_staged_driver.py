"""Pure and synthetic integration checks. No CI, network or real product build."""
from pathlib import Path
import ast,hashlib,json,os,sys,tempfile,time,unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import build_graph as graph
import staged_driver as staged
import driver
CI=Path(__file__).resolve().parents[1]

class CompilerInputs(unittest.TestCase):
 def setUp(self):
  self.compiler=r'C:\stable\llvm\bin\clang-cl.exe';self.build=r'C:\stable\build'
  self.roots=[r'C:\stable\source',r'C:\sdk\Include',r'C:\stable\build\generated']
  self.sysroots={'/vctoolsdir':r'C:\vc','/winsdkdir':r'C:\sdk','/winsdkversion':'10.0.26100.0'}
  self.argv=[self.compiler,'/vctoolsdir',r'C:\vc','/winsdkdir',r'C:\sdk','/winsdkversion','10.0.26100.0','/I'+r'C:\stable\source','/clang:-ffp-contract=off','/clang:-fno-builtin-sin','/c',r'C:\stable\source\a.cpp']
 def run_args(self,a):return graph.validate_compile_argv(a,self.compiler,self.build,self.roots,self.sysroots)
 def test_expected(self):self.assertEqual(len(self.run_args(self.argv)['include_paths']),1)
 def test_all_explicit_include_forms(self):
  for option in ['/imsvc','-imsvc','-isystem','-idirafter','/external:I','-I','/FI']:
   self.run_args(self.argv+[option,r'C:\sdk\Include'])
 def test_unknown_external_include(self):
  for option in ['/I','-imsvc','-isystem','-idirafter','/external:I','/FI']:
   with self.assertRaises(graph.GraphError):self.run_args(self.argv+[option,r'C:\private'])
 def test_config_overlay_plugin_rsp_rejected(self):
  for arg in ['--config=x','--config-system-dir=x','/external:env:EVIL','-ivfsoverlay=x','/clang:-include','-Xclang','@x','-fplugin=x']:
   with self.assertRaises(graph.GraphError):self.run_args(self.argv+[arg])
 def test_sysroot_override_or_wrong_compiler(self):
  for args in [self.argv+['/winsdkdir',r'C:\other'],['cl.exe']+self.argv[1:],self.argv[:1]+self.argv[3:]]:
   with self.assertRaises(graph.GraphError):self.run_args(args)
 def test_argv_identity_tracks_flags(self):self.assertNotEqual(self.run_args(self.argv)['argv_sha256'],self.run_args(self.argv+['/DNEW=1'])['argv_sha256'])

class GraphChecks(unittest.TestCase):
 def fixture(self):
  targets={t:{'artifact':t+'.lib'} for t in graph.TARGETS};entries=[]
  for t in graph.TARGETS:
   for out in ['x/CMakeFiles/'+t+'.dir/a.obj',t+'.lib']:
    entries.append({'output':out,'file':'a.c','directory':'build','command':'tool '+out})
  return targets,entries
 def test_exact_command_closure(self):
  t,e=self.fixture();r=graph.select_commands(Path('build'),t,e,e,'\n'.join(x['command'] for x in e));self.assertEqual(len(r['outputs']),36)
 def test_unknown_closure_edge_blocks(self):
  t,e=self.fixture()
  with self.assertRaises(graph.GraphError):graph.select_commands(Path('build'),t,e,e,'\n'.join(x['command'] for x in e)+'\nextra')
 def test_response_content_identity(self):
  t,e=self.fixture();expanded=[dict(x) for x in e];expanded[0]['command']+=' /DCHANGED=1'
  a=graph.select_commands(Path('build'),t,e,e,'\n'.join(x['command'] for x in e));b=graph.select_commands(Path('build'),t,e,expanded,'\n'.join(x['command'] for x in e));self.assertNotEqual(a['identity'],b['identity'])
 def test_clean_no_work_and_failures(self):
  self.assertTrue(graph.clean_plan('ninja: no work to do.\n'))
  for x in ['[1/2] compile\nninja: no work to do.','ninja explain: x is dirty\nninja: no work to do.','VERIFY_GLOBS\nninja: no work to do.','']:
   with self.assertRaises(graph.GraphError):graph.clean_plan(x)

class StageChecks(unittest.TestCase):
 def test_contracts_inert_fixed_source_and_limits(self):
  for stage in 'ab':
   c=json.loads((CI/f'execution-stage-{stage}.json').read_text());self.assertEqual(c['state'],'DRAFT_NOT_AUTHORIZED');self.assertFalse(c['upload_exact_package']);self.assertIsNone(c['root_go_reference']);self.assertIsNone(c['checkpoint_input']);self.assertEqual(c['parallelism'],2);self.assertEqual(c['max_total_seconds'],3300);self.assertEqual(c['source_review_status'],'REVIEWED_FIXED_PRODUCT')
  self.assertEqual(driver.BASE,'302eb87072249a4ac2195d3a30cb5475df30f31a');self.assertEqual(driver.TREE,'9ea76a3f4509052ca6ac116581d95b0d42e6384f')
 def test_build_success_sets_acceptance_window_before_link_audit(self):
  with tempfile.TemporaryDirectory() as d:
   b=staged.StagedBuild(CI,{'stage':'B','max_total_seconds':3300,'stage_downstream_reserve_seconds':1050,'stage_build_max_seconds':2100,'stage_min_build_window_seconds':120});b.root=Path(d);b.build=Path(d)/'build';b.build.mkdir();(b.root/'logs').mkdir();(b.root/'logs/build.txt').write_text('log')
   def links(*args):self.assertIsNotNone(b.phase_end);return {'fixture':True}
   with mock.patch.object(staged.build_capture,'run_build',return_value={'state':'SUCCESS'}),mock.patch.object(staged,'validate_effect_link',side_effect=links):b.command(['fixture'],name='build')
   self.assertAlmostEqual(b.phase_end,b.started+2910,places=3)
 def test_insufficient_build_budget_never_launches(self):
  b=staged.StagedBuild(CI,{'stage':'A','max_total_seconds':3300,'stage_downstream_reserve_seconds':900,'stage_build_max_seconds':2100,'stage_min_build_window_seconds':120});b.started=time.monotonic()-2500
  with mock.patch.object(staged.build_capture,'run_build') as run:
   with self.assertRaises(driver.Blocked):b.command(['fixture'],name='dependencies-build')
   run.assert_not_called()
 def test_full_log_keeps_four_engine_links_and_standalone_separate(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);ucrt=root/'libucrt.lib';ucrt.write_text('fixture');lines=[]
   for n in [driver.EXE_NAME+'.exe','faf_sim_math_tests.exe','faf_math_dump.exe','faf_coroutine_tests.exe']:
    lines.append('lld-link /out:'+str(root/n)+' '+str(ucrt)+' /NODEFAULTLIB:libucrt.lib /NODEFAULTLIB:ucrt.lib')
   lines.append('lld-link /out:'+str(root/'faf_effect_scan_tests.exe'))
   text='\n'.join(lines)+'\n'+'x'*20000;self.assertEqual(len(driver.validate_actual_links(text,root,ucrt)),4);self.assertFalse(staged.validate_effect_link(text,root)['engine_linked'])
   with self.assertRaises(driver.Blocked):driver.validate_actual_links(text[-16000:],root,ucrt)
 def test_rehearsal_timestamp_change_precedes_fresh_configure(self):
  tree=ast.parse((CI/'staged_driver.py').read_text());f=next(x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef) and x.name=='stage_a');s=ast.unparse(f)
  self.assertLess(s.index('os.utime('),s.index('shutil.rmtree(self.build)'));self.assertIn('p.is_relative_to(self.source)',s);self.assertIn('checkpoint.restore_checkpoint',s)
 def test_no_mutable_build_lib_in_external_inventory(self):
  tree=ast.parse((CI/'staged_driver.py').read_text());f=next(x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef) and x.name=='external_identity');self.assertNotIn('build-cwd',ast.unparse(f))
 def test_manifest_bytes(self):
  for e in json.loads((CI/'driver-manifest.json').read_text())['files']:
   data=(CI/e['path']).read_bytes();self.assertEqual(hashlib.sha256(data).hexdigest(),e['sha256'],e['path']);self.assertEqual(len(data),e['size'])
if __name__=='__main__':unittest.main(verbosity=2)
