"""Pure and synthetic integration checks. No CI, network or real product build."""
from pathlib import Path
import ast,hashlib,json,os,re,sys,tempfile,time,unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import build_graph as graph
import staged_driver as staged
import driver
CI=Path(__file__).resolve().parents[1]

class PublicLiteralGraph(unittest.TestCase):
 def fixture(self, relative=False):
  source=Path('/owned/source');build=Path('/owned/build');c=staged.checkpoint
  spelling='../source/'+c.WX_LITERAL_SOURCE if relative else str(source/c.WX_LITERAL_SOURCE)
  return {'records':[{'source':spelling,'target':'wxmswu','output':c.WX_LITERAL_OBJECT}]},{'wxmswu':{'artifact':c.WX_LITERAL_LIBRARY}},source,build
 def test_absolute(self):staged.validate_public_literal_graph(*self.fixture())
 def test_relative(self):staged.validate_public_literal_graph(*self.fixture(True))
 def test_wrong_object(self):
  g,t,s,b=self.fixture();g['records'][0]['output']='unrelated.obj'
  with self.assertRaises(driver.Blocked):staged.validate_public_literal_graph(g,t,s,b)
 def test_wrong_source(self):
  g,t,s,b=self.fixture();g['records'][0]['source']='/other/cmndata.cpp'
  with self.assertRaises(driver.Blocked):staged.validate_public_literal_graph(g,t,s,b)
 def test_wrong_library(self):
  g,t,s,b=self.fixture();t['wxmswu']['artifact']='unrelated.lib'
  with self.assertRaises(driver.Blocked):staged.validate_public_literal_graph(g,t,s,b)
 def test_duplicate_edge(self):
  g,t,s,b=self.fixture();g['records']*=2
  with self.assertRaises(driver.Blocked):staged.validate_public_literal_graph(g,t,s,b)

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

 def test_same_sysroot_repeated_groups(self):
  args=self.argv+self.argv[1:7]
  result=self.run_args(args)
  self.assertEqual(result['sysroot_occurrences'],dict.fromkeys(self.sysroots,2))
  self.assertNotEqual(result['argv_sha256'],self.run_args(self.argv)['argv_sha256'])
 def test_equivalent_path_case_slash_and_colon_repeats(self):
  args=self.argv+['/vctoolsdir:c:/VC/','/winsdkdir:C:/SDK','/winsdkversion:10.0.26100.0']
  self.assertEqual(self.run_args(args)['sysroot_occurrences'],dict.fromkeys(self.sysroots,2))
 def test_conflict_then_expected_still_rejected(self):
  for opt in self.sysroots:
   wrong='10.0.22000.0' if opt=='/winsdkversion' else r'C:\wrong'
   for suffix in [[opt,wrong,opt,str(self.sysroots[opt])],[opt+':'+wrong]]:
    with self.assertRaisesRegex(graph.GraphError,'Conflicting sysroot selection'):self.run_args(self.argv+suffix)
 def test_wrong_first_selection_cannot_be_masked(self):
  args=list(self.argv);args[2]=r'C:\wrong'
  with self.assertRaisesRegex(graph.GraphError,'Conflicting sysroot selection'):self.run_args(args+self.argv[1:7])
 def test_empty_missing_and_malformed_version(self):
  for suffix in [['/winsdkdir:'],['/vctoolsdir'],['/winsdkversion','10.0.26100.0/'],['/winsdkversion:10.0.26100.0x']]:
   with self.assertRaises(graph.GraphError):self.run_args(self.argv+suffix)

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
 def test_bootstrap_driver_pin_and_lf(self):
  bootstrap=(CI/'run-client-build.ps1').read_bytes()
  pins=re.findall(rb"Get-FileHash -LiteralPath \$entry -Algorithm SHA256\)\.Hash\.ToLowerInvariant\(\) -ne '([0-9a-f]{64})'",bootstrap)
  self.assertEqual(len(pins),1)
  self.assertEqual(pins[0].decode(),hashlib.sha256((CI/'staged_driver.py').read_bytes()).hexdigest())
  self.assertIn(b"* text eol=lf",(CI.parent/'.gitattributes').read_bytes())
  self.assertNotIn(b'\r',(CI/'staged_driver.py').read_bytes())
  self.assertNotIn(b'\r',bootstrap)
 def test_cross_configuration_hash_chain(self):
  manifest=hashlib.sha256((CI/'driver-manifest.json').read_bytes()).hexdigest()
  recipe=json.loads((CI/'dependency-recipe.json').read_text())
  paths=set(json.loads((CI/'execution-stage-a.json').read_text())['provider_configuration']['tracked_files'])
  for st in 'ab':
   c=json.loads((CI/f'execution-stage-{st}.json').read_text())
   self.assertEqual(c['reviewed_driver_manifest_sha256'],manifest)
   self.assertEqual(c['dependency_recipe_sha256'],staged.json_hash(recipe))
   for key in ['preflight_receipt','distribution_review']:
    self.assertEqual(c[key+'_sha256'],hashlib.sha256((CI/c[key]).read_bytes()).hexdigest())
   self.assertEqual(set(c['provider_configuration']['tracked_files']),paths)
  inner=json.loads((CI/'driver-manifest.json').read_text())
  for f in inner['files']:self.assertIn('ci/'+f['path'],paths)
  self.assertEqual(driver.INTEGRATION_SHA,hashlib.sha256((CI/'integration-manifest.json').read_bytes()).hexdigest())
  d=json.loads((CI/'distribution-review.json').read_text())
  self.assertEqual(d['public_source_allowlist_sha256'],hashlib.sha256((CI/'public-source-allowlist.json').read_bytes()).hexdigest())
  self.assertEqual(d['material_selection_sha256'],hashlib.sha256((CI/'source-material-policy.json').read_bytes()).hexdigest())
 def test_contracts_inert_fixed_source_and_limits(self):
  for stage in 'ab':
   c=json.loads((CI/f'execution-stage-{stage}.json').read_text());self.assertEqual(c['state'],'DRAFT_NOT_AUTHORIZED');self.assertFalse(c['upload_exact_package']);self.assertIsNone(c['root_go_reference']);self.assertIsNone(c['checkpoint_input']);self.assertEqual(c['parallelism'],2);self.assertEqual(c['max_total_seconds'],3300);self.assertEqual(c['source_review_status'],'REVIEWED_FIXED_PRODUCT')
  self.assertEqual(driver.BASE,'293153660c359066d637f1ddac718801e38a8118');self.assertEqual(driver.TREE,'ef844b5d98194249c7434e984c0c12dfa3b042a7')
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
  self.assertLess(s.index('os.utime('),s.index('self.remove_owned(self.build)'));self.assertIn('p.is_relative_to(self.source)',s);self.assertIn('checkpoint.restore_checkpoint',s)
 def test_no_mutable_build_lib_in_external_inventory(self):
  tree=ast.parse((CI/'staged_driver.py').read_text());f=next(x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef) and x.name=='external_identity');self.assertNotIn('build-cwd',ast.unparse(f))
 def test_any_command_exception_suppresses_cleanup(self):
  b=staged.StagedBuild(CI,{'stage':'A','max_total_seconds':3300});b.phase='configure'
  with mock.patch.object(driver.Build,'command',side_effect=driver.Blocked('fixture child failure')):
   with self.assertRaises(driver.Blocked):b.command(['fixture'],name='configure')
  self.assertTrue(b.child_uncertain)
  with mock.patch.object(staged.owned_cleanup,'remove_owned_path') as remove:
   with self.assertRaises(driver.Blocked):b.remove_owned(Path('unused'))
   remove.assert_not_called()
 def test_early_policy_validation_and_windows_fixture_order(self):
  tree=ast.parse((CI/'staged_driver.py').read_text());run=next(x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef) and x.name=='run');text=ast.unparse(run)
  self.assertLess(text.index('self.windows_cleanup_fixture()'),text.index('self.tools_and_runtime'))
  self.assertLess(text.index('checkpoint.validate_policy('),text.index('self.stage_a'))
  self.assertLess(text.index('owned_cleanup.preflight_owned_tree('),text.index('self.stage_a'))
  fixture=next(x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef) and x.name=='windows_cleanup_fixture');f=ast.unparse(fixture)
  self.assertLess(f.index('owned_cleanup.remove_owned_path('),f.rindex('self.verify_owner()'))
  method=next(x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef) and x.name=='checkpoint_policy');text=ast.unparse(method)
  self.assertIn('approved_path_files=(str(self.ninja),)',text)
  self.assertIn("mapping.get('ninja', '')",text)
 def test_manifest_bytes(self):
  for e in json.loads((CI/'driver-manifest.json').read_text())['files']:
   data=(CI/e['path']).read_bytes();self.assertEqual(hashlib.sha256(data).hexdigest(),e['sha256'],e['path']);self.assertEqual(len(data),e['size'])

class MaterialSelection(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.a=self.root/'sample.class';self.a.write_bytes(b'\xca\xfe\xba\xbe fixture')
  self.b=self.root/'build_vms.com';self.b.write_bytes(b'$ ! synthetic OpenVMS source\n')
  self.h=self.root/'public.h';self.h.write_bytes(b'int x;\n')
  def row(p):return {'component':'wxWindows-2.4.2','path':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'classification':'Synthetic exact selection only'}
  self.rules={'schema':1,'omitted_non_build_material':[row(self.a)],'retained_vms_text':[row(self.b)]}
  staged.validate_material_selection(self.rules)
 def selected(self,files=None):return staged.select_dependency_materials('wxWindows-2.4.2',self.root,files or [self.a,self.b,self.h],self.rules)
 def test_exact_omission_retains_source_and_checkout(self):
  self.assertEqual(self.selected(),[self.b,self.h]);self.assertTrue(self.a.is_file())
 def test_unknown_same_suffix_is_not_omitted(self):
  other=self.root/'other.class';other.write_bytes(b'data')
  self.assertIn(other,self.selected([self.a,self.b,self.h,other]))
 def test_omission_changed_hash_blocks(self):
  self.a.write_bytes(b'changed-size');self.assertRaises(driver.Blocked,self.selected)
 def test_omission_missing_blocks(self):self.assertRaises(driver.Blocked,lambda:self.selected([self.b,self.h]))
 def test_text_pin_changed_hash_blocks(self):
  self.b.write_bytes(b'x'*self.b.stat().st_size);self.assertRaises(driver.Blocked,self.selected)
 def test_hardlink_cannot_be_omitted(self):
  os.link(self.a,self.root/'second');self.assertRaises(driver.Blocked,self.selected)
 def test_symlink_cannot_be_omitted(self):
  self.a.unlink();self.a.symlink_to(self.h);self.assertRaises(driver.Blocked,self.selected)
 def test_nonselected_component_unchanged(self):
  self.assertEqual(staged.select_dependency_materials('plog',self.root,[self.a],self.rules),[self.a])
 def test_policy_negative_cases(self):
  import copy
  for field,value in [('path','../outside.class'),('component','unknown'),('sha256','f'*63),('bytes',-1),('path','LICENSE'),('path','public.c')]:
   candidate=copy.deepcopy(self.rules);candidate['omitted_non_build_material'][0][field]=value
   with self.subTest(field=field,value=value),self.assertRaises((driver.Blocked,ValueError)):staged.validate_material_selection(candidate)
 def test_actual_exact_policy_counts(self):
  value=staged.validate_material_selection(json.loads((CI/staged.MATERIAL_POLICY_FILE).read_text()))
  self.assertEqual(len(value['omitted_non_build_material']),16);self.assertEqual(len(value['retained_vms_text']),4)
  self.assertEqual(sum(x['path'].endswith('.class') for x in value['omitted_non_build_material']),4)
 def test_compile_closure_gate_is_preserved(self):
  source=__import__('inspect').getsource(staged.StagedBuild.owned_identity)
  self.assertIn('p.resolve() in admitted for p in self.compile_sources',source)
 def test_full_content_preflight_precedes_stage_dispatch(self):
  source=__import__('inspect').getsource(staged.StagedBuild.run)
  self.assertLess(source.index('preflight_available_content'),source.index('self.stage_a if'))
  self.assertIn('checkpoint_boundary',source)
 def test_linux_pgo_is_explicitly_outside_windows_export(self):
  allow=json.loads((CI/'public-source-allowlist.json').read_text());paths={x['path'] for x in allow['files']}
  policy=json.loads((CI/staged.MATERIAL_POLICY_FILE).read_text())
  excluded=policy['excluded_product_linux_only_material']
  self.assertEqual({x['path'] for x in excluded},{'cmake/pgo/headless-linux-x64.profdata','tools/pgo/record.sh'})
  self.assertFalse(paths & {x['path'] for x in excluded});self.assertEqual(len(paths),2440)
  self.assertEqual(next(x['git_blob'] for x in excluded if x['path'].endswith('.profdata')),'79cad0404d3a1338879ea872173b4b23d71f4c28')
 def test_public_policy_copied_for_both_material_packages(self):
  source=__import__('inspect').getsource(staged.StagedBuild.stage_materials)
  self.assertIn('SOURCE_MATERIAL_POLICY.json',source)


class ProducerPilot(unittest.TestCase):
 def setup_build(self,root):
  b=staged.StagedBuild(CI,{'stage':'A','max_total_seconds':3300,'stage_downstream_reserve_seconds':900,'stage_build_max_seconds':2100,'stage_min_build_window_seconds':1250})
  b.root=root;b.cmake=Path('cmake');b.build=root/'build';b.build.mkdir();b.source=root/'source';b.source.mkdir();(root/'logs').mkdir()
  for name in ['dependency-pilot','dependencies-build']:(root/'logs'/(name+'.txt')).write_text('fixture log')
  b.target_data={'faf_monocypher':{'depends':[],'artifact':'mono.lib'}}
  src=b.source/'dependencies/monocypher/src/monocypher.c';src.parent.mkdir(parents=True);src.write_text('int x;')
  b.graph={'outputs':['mono.obj','mono.lib','other.obj'],'records':[{'target':'faf_monocypher','output':'mono.obj','source':str(src)},{'target':'faf_monocypher','output':'mono.lib','source':'unused'}]}
  wx=staged.checkpoint.WX_LITERAL_OBJECT
  b.graph['outputs'].append(wx);b.graph['records'].append({'target':'wxmswu','output':wx,'source':str(b.source/staged.checkpoint.WX_LITERAL_SOURCE)})
  (b.build/wx).parent.mkdir(parents=True)
  return b
 def test_shared_deadline_no_fresh_full_allowance(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.setup_build(Path(d));b.started=0
   with mock.patch.object(staged.build_capture,'run_build',return_value={'state':'SUCCESS'}) as run,mock.patch.object(staged.time,'monotonic',return_value=100):
    b.command(['fixture'],name='dependency-pilot');self.assertEqual(run.call_args.kwargs['timeout'],120)
    self.assertEqual(b.dependency_compile_deadline,2200);self.assertEqual(b.phase_end,2200)
   with mock.patch.object(staged.build_capture,'run_build',return_value={'state':'SUCCESS'}) as run,mock.patch.object(staged.time,'monotonic',return_value=210):
    b.command(['fixture'],name='dependencies-build');self.assertEqual(run.call_args.kwargs['timeout'],1990)
    self.assertEqual(b.dependency_compile_deadline,2200);self.assertEqual(b.phase_end,2910)
 def test_a_short_initial_window_does_not_launch(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.setup_build(Path(d));b.started=0
   with mock.patch.object(staged.time,'monotonic',return_value=1200),mock.patch.object(staged.build_capture,'run_build') as run:
    with self.assertRaises(driver.Blocked):b.command(['fixture'],name='dependency-pilot')
    run.assert_not_called();self.assertIsNone(b.dependency_compile_deadline)
 def test_expired_shared_window_does_not_launch(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.setup_build(Path(d));b.dependency_compile_deadline=time.monotonic()-1
   with mock.patch.object(staged.build_capture,'run_build') as run:
    with self.assertRaises(driver.Blocked):b.command(['fixture'],name='dependencies-build')
    run.assert_not_called()
 def test_pilot_exact_subset_and_no_archive(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.setup_build(Path(d))
   def produce(*a,**kw):
    self.assertEqual(kw['name'],'dependency-pilot');self.assertIn('faf_monocypher',a[0]);self.assertNotIn('faf_main',a[0])
    for name in ['mono.obj','mono.lib',staged.checkpoint.WX_LITERAL_OBJECT]:(b.build/name).write_bytes(b'fixture')
   with mock.patch.object(b,'command',side_effect=produce),mock.patch.object(b,'checkpoint_policy',return_value='policy'),mock.patch.object(staged.checkpoint,'validate_built_subset',return_value={'state':'PASS_BUILT_SUBSET_ONLY'}) as check:
    b.dependency_pilot();self.assertEqual(set(check.call_args.args[1]),{'build/mono.obj','build/mono.lib','build/'+staged.checkpoint.WX_LITERAL_OBJECT,'build/.ninja_log','build/.ninja_deps'})
    self.assertEqual(b.receipt['dependency_format_pilot']['state'],'PASS_BUILT_SUBSET_ONLY')
    self.assertFalse(list(Path(d).rglob('*.zip')))
 def test_pilot_rejects_wrong_concrete_closure_before_launch(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.setup_build(Path(d));b.target_data['faf_monocypher']['depends']=['wxmswu']
   with mock.patch.object(b,'command') as run:
    with self.assertRaises(driver.Blocked):b.dependency_pilot()
    run.assert_not_called()
 def test_pilot_rejects_unexpected_output_after_build(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.setup_build(Path(d))
   def produce(*a,**kw):
    for name in b.graph['outputs']:(b.build/name).write_bytes(b'fixture')
   with mock.patch.object(b,'command',side_effect=produce),mock.patch.object(staged.checkpoint,'validate_built_subset') as check:
    with self.assertRaises(driver.Blocked):b.dependency_pilot()
    check.assert_not_called()
 def test_pilot_forbidden_in_consumer(self):
  b=staged.StagedBuild(CI,{'stage':'B','max_total_seconds':3300})
  with self.assertRaises(driver.Blocked):b.dependency_pilot()
 def test_only_a_calls_pilot_and_still_builds_all18(self):
  import inspect
  a=inspect.getsource(staged.StagedBuild.stage_a);b=inspect.getsource(staged.StagedBuild.stage_b)
  self.assertIn('self.dependency_pilot()',a);self.assertIn('*build_graph.TARGETS',a);self.assertNotIn('dependency_pilot',b)
  self.assertIn('self.clean_dependency_plan()',b)

if __name__=='__main__':unittest.main(verbosity=2)
