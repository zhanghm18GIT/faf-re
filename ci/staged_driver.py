#!/usr/bin/env python3
"""Inert two-stage entry. No CI or build action occurs on import."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
# Python -I deliberately excludes cwd; import only this verified configuration directory.
sys.path.insert(0,str(Path(__file__).resolve().parent))
import argparse,hashlib,json,os,re,shutil,stat,time,urllib.parse
import driver as core
import build_capture
import build_graph
import owned_cleanup
# Pure helpers are hash-bound by the finished driver manifest before execution.
import checkpoint
import cache_transport
import command_admission
import toolchain_fingerprint as fp

need=core.require
BASE=core.BASE;TREE=core.TREE
STAGES={'A','B'}
EFFECT_REGEX='^effect_scan$'
RECIPE_FILE='dependency-recipe.json'

def validate_public_literal_graph(graph, targets, source, build):
 # Normalize lexical relative paths without following any filesystem links.
 expected=Path(os.path.normpath(str(Path(source)/checkpoint.WX_LITERAL_SOURCE)))
 rows=[]
 for row in graph['records']:
  p=Path(row['source']);p=p if p.is_absolute() else Path(build)/p
  if row['target']=='wxmswu' and Path(os.path.normpath(str(p)))==expected:rows.append(row)
 need(len(rows)==1 and rows[0]['output']==checkpoint.WX_LITERAL_OBJECT,'Public literal source/object graph mismatch')
 need(targets['wxmswu']['artifact']==checkpoint.WX_LITERAL_LIBRARY,'Public literal library graph mismatch')


def json_hash(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def single_test(data,name,exe,commands=True):
 tests=data.get('tests',[]);need(len(tests)==1 and tests[0].get('name')==name,'Unexpected standalone test discovery')
 if commands:
  cmd=tests[0].get('command',[]);need(len(cmd)==1 and Path(cmd[0]).name.lower()==exe.lower(),'Unexpected standalone test command')

def validate_effect_link(text,build):
 found=[]
 for line in text.splitlines():
  if 'lld-link' not in line.lower():continue
  x=core.expand_rsp(line,build)
  if re.search(r'/out:(?:"[^"\r\n]*|[^\s]+)faf_effect_scan_tests\.exe',x,re.I):found.append(x)
 need(len(found)==1,'Expected one fresh standalone effect_scan link')
 need('faf_engine.dir' not in found[0].lower(),'Standalone effect_scan unexpectedly links engine objects')
 return {'target':'faf_effect_scan_tests.exe','command_sha256':hashlib.sha256(found[0].encode()).hexdigest(),'engine_linked':False,'ucrt_policy':'standalone text test; not an engine UCRT compatibility claim'}

MATERIAL_POLICY_FILE='source-material-policy.json'

def validate_material_selection(value):
 need(isinstance(value,dict) and value.get('schema')==1,'Invalid reviewed material selection')
 seen=set()
 for group in ['omitted_non_build_material','retained_vms_text']:
  rows=value.get(group);need(isinstance(rows,list) and len(rows)<=64,'Material selection count/type')
  for row in rows:
   need(isinstance(row,dict) and set(row)=={'component','path','bytes','sha256','classification'},'Material selection fields')
   need(row['component'] in core.SOURCE_COMPONENTS,'Unknown material component')
   rel=core.safe_relative(row['path']).as_posix();key=(row['component'],rel.casefold())
   need(key not in seen,'Duplicate material selection');seen.add(key)
   need(type(row['bytes']) is int and 0<=row['bytes']<=1_000_000,'Selected material size bound')
   need(isinstance(row['sha256'],str) and re.fullmatch('[a-f0-9]{64}',row['sha256']),'Selected material digest')
   need(isinstance(row['classification'],str) and 0<len(row['classification'])<=256,'Selected material classification')
   need(not core.NOTICE_RE.match(Path(rel).name),'Notice/license cannot be omitted or reclassified')
   allowed={'.com'} if group=='retained_vms_text' else {'.ncb','.xls','.class','.bin'}
   need(Path(rel).suffix.lower() in allowed,'Unsupported exact material classification')
 return value

def select_dependency_materials(name,root,files,selection):
 # The original immutable checkout is retained. Only these exact reviewed bytes
 # are omitted from checkpoint/relink material; no suffix-wide omission is added.
 admitted={p.relative_to(root).as_posix():p for p in files};omitted=set()
 for group in ['omitted_non_build_material','retained_vms_text']:
  for row in selection[group]:
   if row['component']!=name:continue
   rel=row['path'];need(rel in admitted,'Exact reviewed material is absent from source selection: '+name+'/'+rel)
   p=admitted[rel]
   for a in [p,*p.parents]:
    st=a.lstat();need(not a.is_symlink() and not getattr(st,'st_file_attributes',0)&0x400,'Selected material link/reparse forbidden')
    if a==root:break
   need(p.is_file() and p.stat().st_nlink==1 and p.stat().st_size==row['bytes'],'Exact reviewed material size/type differs: '+name+'/'+rel)
   need(core.sha(p)==row['sha256'],'Exact reviewed material digest differs: '+name+'/'+rel)
   if group=='omitted_non_build_material':omitted.add(rel)
 return [p for p in files if p.relative_to(root).as_posix() not in omitted]

class StagedBuild(core.Build):
 def __init__(self,here,c):
  super().__init__(here,c);self.stage_name=c.get('stage');self.child_uncertain=False;self.owned_root=None;self.child_env=None;self.phase_end=None;self.dependency_compile_deadline=None;self.graph=None;self.fp_allowance=fp.PassAllowance()
 def validate_contract(self):
  super().validate_contract()
  need(self.stage_name in STAGES,'Unknown reviewed stage')
  need(self.c.get('checkpoint_transport')=='native-project-cache-v1','Unreviewed checkpoint transport')
  need(self.c.get('object_admission_mode')=='fixed-public-source-structured-v1','Unreviewed object admission')
  need(os.environ.get('APPVEYOR_CACHE_SKIP_SAVE','').lower()=='true','Cache must start non-saving')
  need(os.environ.get('APPVEYOR_CACHE_SKIP_RESTORE','').lower()==('true' if self.stage_name=='A' else 'false'),'Unexpected native cache restore policy')
  self.cache_dir=Path('C:/faf-re-cache')/self.c['dependency_recipe_sha256'][:24]
  self.canaries=(b'REFAF_SYNTHETIC_PRIVATE_CANARY_V1_'+os.urandom(24).hex().encode(),)
  self.material_selection=validate_material_selection(core.read_json(self.here/MATERIAL_POLICY_FILE))
  self.material_selection_sha=core.sha(self.here/MATERIAL_POLICY_FILE)
  need(self.distribution.get('material_selection_sha256')==self.material_selection_sha,'Distribution material selection is not bound')
  need(self.distribution.get('material_selection_review_status')=='REVIEWED','Amended material selection review pending')
  need(self.c.get('source_review_status')=='REVIEWED_FIXED_PRODUCT','Source-only review pending')
  need(self.c.get('cross_product_reuse') is False,'Cross-product reuse disabled for this first pair')
  need(self.c.get('max_checkpoint_bytes')==400_000_000,'Checkpoint byte ceiling differs')
  need(self.c.get('stage_build_max_seconds')==2100,'Unreviewed build cap')
  need(self.c.get('stage_min_build_window_seconds')==(1250 if self.stage_name=='A' else 120),'Unreviewed initial compile-window threshold')
  reserve=900 if self.stage_name=='A' else 1050
  need(self.c.get('stage_downstream_reserve_seconds')==reserve,'Unreviewed downstream reservation')
  self.recipe=core.read_json(self.here/RECIPE_FILE);self.recipe_key=json_hash(self.recipe)
  need(self.c['dependency_recipe_sha256']==self.recipe_key,'Dependency recipe identity mismatch')
  need(self.recipe['cross_product_reuse'] is False,'Cross-product reuse is not reviewed')
  need(self.recipe['targets']==list(build_graph.TARGETS),'Dependency target closure changed')
  if self.stage_name=='A':need(self.c.get('checkpoint_input') is None,'Producer must not consume a checkpoint')
  else:
   p=self.c.get('checkpoint_input');need(isinstance(p,dict),'Consumer receipt not supplied')
   for key in ['build_id','job_id','configuration_commit','filename','sha256']:
    need(isinstance(p.get(key),str) and 'REQUIRED' not in p[key],'Missing producer identity')
   need(re.fullmatch('[0-9]+',p['build_id']) and re.fullmatch('[a-z0-9]+',p['job_id']),'Invalid producer job identity')
   need(re.fullmatch('[a-f0-9]{40}',p['configuration_commit']) and re.fullmatch('[a-f0-9]{64}',p['sha256']),'Invalid producer hashes')
   need(re.fullmatch(r'faf-re-deps-[a-f0-9]{16}-[0-9]+-[a-z0-9]+\.zip',p['filename']),'Unexpected checkpoint filename')
   need(0<p.get('size',0)<=400_000_000,'Checkpoint size outside bound')
  self.receipt.update(stage=self.stage_name,dependency_recipe_key=self.recipe_key,cross_product_reuse=False,checkpoint_format='v1-structured-fixed-public-source',checkpoint_transport='native-project-cache-v1',build_instrumentation={'cmake_suppress_regeneration':'ON','source_glob_immutability_required':True,'product_source_modified_by_instrumentation':False})
 def remaining(self,cap):
  n=super().remaining(cap)
  if self.phase_end is not None:n=min(n,int(self.phase_end-time.monotonic()));need(n>0,'Current stage phase allowance exhausted')
  return n
 def command(self,args,cwd=None,cap=120,env=None,name='command',binary=False,permit_failure=False,started_callback=None):
  if name in {'build','dependencies-build','dependency-pilot','dependency-archive-pilot'}:
   available=super().remaining(3300);reserve=self.c['stage_downstream_reserve_seconds']
   if name in {'dependencies-build','dependency-pilot','dependency-archive-pilot'}:
    need(self.stage_name=='A','Dependency pilot/build is producer-only')
    if self.dependency_compile_deadline is None:
     limit=min(self.c['stage_build_max_seconds'],available-reserve)
     need(limit>=self.c['stage_min_build_window_seconds'],'Insufficient build window after downstream reservation')
     self.dependency_compile_deadline=time.monotonic()+limit
     self.phase_end=self.dependency_compile_deadline
    limit=int(self.dependency_compile_deadline-time.monotonic())
    need(limit>0,'Shared dependency compile deadline exhausted')
    if name=='dependency-pilot':limit=min(120,limit)
    else:need(limit>=120,'Insufficient remaining shared dependency compile window')
   else:
    limit=min(self.c['stage_build_max_seconds'],available-reserve)
    need(limit>=self.c['stage_min_build_window_seconds'],'Insufficient build window after downstream reservation')
   print('BUILD_BUDGET '+json.dumps({'stage':self.stage_name,'command':name,'remaining_seconds':available,'build_cap_seconds':limit,'downstream_reserved_seconds':reserve,'pilot_and_full_share_original_compile_deadline':name!='build','reservation_is_not_runtime_prediction':True}),flush=True)
   log=self.root/'logs'/f'{name}.txt'
   result=build_capture.run_build([str(x) for x in args],cwd=cwd or self.root,env=env or self.child_env,log_path=log,timeout=limit,emit=print,aliases=[(self.root,'<owned-work>'),(self.here.parent,'<configuration>')])
   self.receipt.setdefault('build_capture',{})[name]=result
   self.receipt['ninja_timing_summary']=build_capture.ninja_summary(self.build/'.ninja_log',[(self.root,'<owned-work>')])
   if result['state']!='SUCCESS':self.child_uncertain=True;raise core.Blocked('Bounded streamed build did not complete: '+result['state'])
   text=log.read_text(encoding='utf-8',errors='replace')
   if name not in {'dependency-pilot','dependency-archive-pilot'}:self.start_acceptance_window()
   if name=='build':self.receipt['standalone_effect_scan_link']=validate_effect_link(text,self.build)
   return text
  try:return super().command(args,cwd,cap,env if env is not None else self.child_env,name,binary,permit_failure,started_callback)
  except BaseException:
   # Conservative: no snapshot/promotion follows any failed child or uncertain teardown.
   self.child_uncertain=True
   raise
 def start_workspace(self):
  root=Path('C:/faf-re-staged')/self.recipe_key[:24]
  need(not os.path.lexists(root),'Stable owned work root already exists; do not delete/reuse unknown state')
  root.parent.mkdir(exist_ok=True);need(not(root.parent.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT),'Work parent is a reparse point')
  root.mkdir();self.root=self.owned_root=root
  core.write_json(root/'OWNED_WORK.json',{'recipe':self.recipe_key,'job_id':self.receipt['appveyor']['job_id']})
  for sub in ['logs','tools','build','stage','out']:(root/sub).mkdir()
  need(shutil.disk_usage(root).free>=20*1024**3,'Need 20 GiB free workspace')
  self.source=root/'source';self.build=root/'build';self.stage=root/'stage';self.receipt['state']='RUNNING'
  (root/'temp').mkdir()
  # Only locator/version/acquisition commands precede the controlled build environment.
  if self.stage_name=='B':
   p=self.c['checkpoint_input'];self.checkpoint_path=root/'out'/p['filename']
   cache_transport.receive(self.cache_dir/'checkpoint.zip',self.checkpoint_path,{'size':p['size'],'sha256':p['sha256']})
   self.receipt['cache_receive']='PINNED_BYTES_ONLY_SEMANTIC_ADMISSION_PENDING'
 def windows_cleanup_fixture(self):
  self.phase='owned-cleanup-fixture'
  need(os.name=='nt','Windows cleanup fixture requires actual Windows')
  fixture=self.root/'cleanup-fixture';fixture.mkdir();testfile=fixture/'readonly.txt';testfile.write_bytes(b'public cleanup fixture\n')
  os.chmod(testfile,stat.S_IREAD)
  need(testfile.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY,'Fixture READONLY attribute was not set')
  events=[]
  owned_cleanup.remove_owned_path(self.root,fixture,owner_check=self.verify_owner,max_seconds=self.remaining(10),emit=lambda k,v:events.append((k,v)))
  retries=[v for k,v in events if k=='CLEANUP_READONLY_RETRY']
  need(retries==[{'relative_path':'cleanup-fixture/readonly.txt','result':'removed'}] and not fixture.exists(),'Expected one actual fixture-only read-only retry')
  self.verify_owner()
  # Direct-file targets occur in real cleanup (composite.index and out extras).
  direct=self.root/'cleanup-direct.index';direct.write_bytes(b'public direct-file fixture\n')
  owned_cleanup.remove_owned_path(self.root,direct,owner_check=self.verify_owner,max_seconds=self.remaining(10))
  need(not direct.exists(),'Direct regular-file cleanup failed')
  direct.write_bytes(b'public direct-readonly fixture\n');os.chmod(direct,stat.S_IREAD)
  events=[]
  owned_cleanup.remove_owned_path(self.root,direct,owner_check=self.verify_owner,max_seconds=self.remaining(10),emit=lambda k,v:events.append((k,v)))
  need(not direct.exists() and [v for k,v in events if k=='CLEANUP_READONLY_RETRY']==[{'relative_path':'cleanup-direct.index','result':'removed'}],'Direct read-only file cleanup failed')
  self.verify_owner()
  self.receipt['windows_cleanup_fixture']='PASS_DIRECTORY_AND_DIRECT_REGULAR_READONLY_FILES'
  print('WINDOWS_CLEANUP_FIXTURE '+json.dumps({'state':self.receipt['windows_cleanup_fixture'],'large_tree_cleanup':'NOT_ESTABLISHED'}),flush=True)
 def tools_and_runtime(self):
  super().tools_and_runtime()
  path_roots=[('llvm-bin',self.llvm/'bin'),('cmake-bin',self.cmake.parent),('ninja-bin',self.ninja.parent),('python-bin',Path(sys.executable).parent),('git-bin',Path(self.git).parent),('system32',Path(os.environ['WINDIR'])/'System32'),('windows',Path(os.environ['WINDIR']))]
  effective={'SYSTEMROOT':os.environ['SYSTEMROOT'],'WINDIR':os.environ['WINDIR'],'COMSPEC':str(Path(os.environ['WINDIR'])/'System32/cmd.exe'),'TEMP':str(self.root/'temp'),'TMP':str(self.root/'temp'),'GIT_TERMINAL_PROMPT':'0','GIT_LFS_SKIP_SMUDGE':'1','CMAKE_BUILD_PARALLEL_LEVEL':'2','CTEST_PARALLEL_LEVEL':'1','VSLANG':'1033','PYTHONDONTWRITEBYTECODE':'1','CLANG_NO_DEFAULT_CONFIG':'1'}
  labels={'SYSTEMROOT':'windows','WINDIR':'windows','COMSPEC':'system-cmd','TEMP':'owned-temp','TMP':'owned-temp'}
  self.child_env,self.env_receipt=fp.controlled_environment(os.environ,verified_path_roots=path_roots,effective_inputs=effective,policy='remove',effective_public_labels=labels)
  self.receipt['controlled_environment']=self.env_receipt
  self.effective_env_identity={k:self.env_receipt[k] for k in ['schema','path_logical_ids','effective_inputs','inherited_unlisted','scope']}
 def configure(self):
  self.phase='configure'
  query=self.build/'.cmake/api/v1/query';query.mkdir(parents=True,exist_ok=True);(query/'codemodel-v2').write_text('')
  self.extra_cmake_arguments=['-DCMAKE_SUPPRESS_REGENERATION=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
  super().configure()
  self.receipt['public_option_source']=command_admission.verify_public_option_source(self.source/'dependencies/ffmpeg/faf/x64/sources.cmake')
  need(core.read_cache(self.build/'CMakeCache.txt').get('CMAKE_SUPPRESS_REGENERATION')=='ON','Required immutable-stage supervision missing')
  data=json.loads(self.command([self.ctest,'--test-dir',self.build,'--show-only=json-v1','-R',EFFECT_REGEX],name='effect-discovery'))
  single_test(data,'effect_scan','faf_effect_scan_tests.exe',False)
  self.receipt['ctest_discovered'].append('effect_scan')
  targets=build_graph.load_targets(self.build)
  raw=json.loads(self.command([self.ninja,'-C',self.build,'-t','compdb'],cap=120,name='graph-commands-raw'))
  expanded=json.loads(self.command([self.ninja,'-C',self.build,'-t','compdb','-x'],cap=120,name='graph-commands-expanded'))
  commands=self.command([self.ninja,'-C',self.build,'-t','commands',*build_graph.TARGETS],cap=120,name='graph-dependencies')
  graph=build_graph.select_commands(self.build,targets,raw,expanded,commands)
  self.reconcile_compiler_inputs(targets,expanded,graph)
  if self.graph is not None:need(graph==self.graph,'Fresh configure changed dependency commands/response contents')
  self.graph=graph;self.target_data=targets
  script=self.build/'CMakeFiles/VerifyGlobs.cmake';need(script.is_file(),'Expected generated glob verification script missing')
  value=core.sha(script)
  if hasattr(self,'glob_script_sha'):need(value==self.glob_script_sha,'Fresh configuration changed actual glob membership/script')
  self.glob_script_sha=value
 def reconcile_compiler_inputs(self,targets,expanded,graph):
  sdk=Path(self.c['windows_sdk_root']);v=self.c['windows_sdk_headers_version']
  external=[self.msvc/'include',self.msvc/'atlmfc/include',self.llvm/'lib/clang/22/include',self.source/'dependencies/dxsdk/Include']
  external += [sdk/'Include'/v/n for n in ['ucrt','shared','um','winrt','cppwinrt']]
  external += [self.sdk/'Include'/v/n for n in ['ucrt','shared','um','winrt','cppwinrt']]
  generated=[Path(x) for t in targets.values() for x in t['includes'] if Path(x).is_relative_to(self.build)]
  roots=[self.source,*generated,*external]
  for t in targets.values():
   for x in t['includes']:need(any(Path(x).is_relative_to(p) for p in roots),'CMake exposes an undeclared include root')
  objects=set(x for x in graph['outputs'] if x.endswith('.obj'));seen=[];occurrences={k:set() for k in ['/vctoolsdir','/winsdkdir','/winsdkversion']}
  for e in expanded:
   if e['output'] not in objects:continue
   result=build_graph.validate_compile_argv(build_graph.windows_argv(e['command']),self.llvm/'bin/clang-cl.exe',self.build,roots,{'/vctoolsdir':self.msvc,'/winsdkdir':self.sdk,'/winsdkversion':v})
   try:
    strict=command_admission.validate(build_graph.windows_argv(e['command']),compiler=str(self.llvm/'bin/clang-cl.exe'),cwd=str(self.build),source=e['file'],output=e['output'],read_roots=[str(x) for x in roots],write_root=str(self.build),sysroots={'/vctoolsdir':str(self.msvc),'/winsdkdir':str(self.sdk),'/winsdkversion':v})
   except command_admission.AdmissionError as exc:
    detail=json.loads(str(exc));detail['output']=e['output'];detail['target']=next(r['target'] for r in graph['records'] if r['output']==e['output'])
    raise core.Blocked(json.dumps(detail,sort_keys=True,separators=(',',':'))) from None
   seen.append({'output':e['output'],'argv_sha256':result['argv_sha256'],'closed_grammar_sha256':strict['argv_sha256']})
   for k,n in result['sysroot_occurrences'].items():occurrences[k].add(n)
  need(len(seen)==len(objects),'Compile input reconciliation incomplete')
  value=json_hash(sorted(seen,key=lambda x:x['output']))
  if hasattr(self,'compile_argv_identity'):need(value==self.compile_argv_identity,'Fresh expanded argv identity differs')
  self.compile_argv_identity=value
  self.receipt['compiler_sysroot_occurrences']={k:sorted(v) for k,v in occurrences.items()}
  print('COMPILER_SYSROOT_COUNTS '+json.dumps(self.receipt['compiler_sysroot_occurrences'],sort_keys=True),flush=True)
  self.compile_sources=[Path(e['file']) if Path(e['file']).is_absolute() else self.build/e['file'] for e in expanded if e['output'] in objects]
 def source_inputs(self):
  files={self.source/x['path'] for x in core.read_json(self.here/'public-source-allowlist.json')['files']}
  for name in core.SOURCE_COMPONENTS:files.update(self.dependency_sources(name,self.source/'dependencies'/name))
  # Generated public include roots come from the selected target API, not a broad build glob.
  generated=set()
  for t in self.target_data.values():
   for value in t['includes']:
    p=Path(value)
    if p.is_relative_to(self.build):
     need(p.is_dir(),'Missing generated include root')
     for f in p.rglob('*'):
      need(not f.is_symlink(),'Generated include link forbidden')
      if f.is_file():need(f.suffix.lower() in checkpoint.HEADER_SUFFIXES,'Unexpected generated include material');generated.add(f)
  need(len(files)<=100000 and len(generated)<=256,'Source/generated inventory count exceeded')
  return sorted(files),sorted(generated)
 def owned_identity(self):
  source,generated=self.source_inputs();records=[]
  admitted={p.resolve() for p in source+generated}
  need(all(p.resolve() in admitted for p in self.compile_sources),'A dependency command compiles outside the verified source/generated inventory')
  for label,root,files in [('source',self.source,source),('generated',self.build,generated)]:
   for f in files:
    need(self.remaining(120)>0,'Source fingerprint budget');need(not f.is_symlink() and f.is_file(),'Source inventory contains link/missing file')
    records.append({'root':label,'path':f.relative_to(root).as_posix(),'size':f.stat().st_size,'sha256':core.sha(f)})
  glob_root=self.source/'dependencies/mbedtls/library'
  glob_members=[{'name':p.name,'type':'directory' if p.is_dir() else 'file'} for p in sorted(glob_root.glob('*.c'))]
  need(glob_members and all(x['type']=='file' for x in glob_members),'Mbed TLS source glob contains unexpected directory/empty set')
  return {'records':records,'sha256':json_hash(records),'mbedtls_actual_glob':glob_members}
 def assert_owned(self):
  script=self.build/'CMakeFiles/VerifyGlobs.cmake';stamp=self.build/'CMakeFiles/cmake.verify_globs'
  core.checked_hash(script,self.glob_script_sha);need(stamp.is_file(),'Generated glob stamp missing');before=stamp.stat().st_mtime_ns
  output=self.command([self.cmake,'-P',script],cap=30,name='explicit-glob-check')
  need('GLOB mismatch' not in output and stamp.stat().st_mtime_ns==before,'Actual source glob membership changed')
  for item in core.read_json(self.here/'driver-manifest.json')['files']:core.checked_hash(self.here/core.safe_relative(item['path']),item['sha256'])
  need(self.owned_identity()==self.owned_baseline,'Source/generated membership or content changed')
  self.verify_source();core.checked_hash(self.ucrt,self.c['ucrt']['sha256'])
 def external_identity(self):
  sdk=Path(self.c['windows_sdk_root']);v=self.c['windows_sdk_headers_version'];dx=self.source/'dependencies/dxsdk';cmshare=self.cmake.parent.parent/'share/cmake-3.31'
  roots=[fp.RootSpec('msvc-include',self.msvc/'include'),fp.RootSpec('msvc-atlmfc-include',self.msvc/'atlmfc/include',optional=True)]
  roots += [fp.RootSpec('sdk-'+n+'-include',sdk/'Include'/v/n) for n in ['ucrt','shared','um','winrt','cppwinrt']]
  roots += [fp.RootSpec('llvm-resource-include',self.llvm/'lib/clang/22/include'),fp.RootSpec('legacy-dx-include',dx/'Include'),fp.RootSpec('cmake-modules',cmshare/'Modules'),fp.RootSpec('cmake-templates',cmshare/'Templates')]
  libs=[('msvc-lib',self.msvc/'lib/x64',False),('msvc-atlmfc-lib',self.msvc/'atlmfc/lib/x64',True),('sdk-um-lib',sdk/'Lib'/v/'um/x64',False),('sdk-ucrt-lib',sdk/'Lib'/v/'ucrt/x64',False),('legacy-dx-lib',dx/'Lib/x64',False),('llvm-runtime-windows',self.llvm/'lib/clang/22/lib/windows',True),('llvm-runtime-lib',self.llvm/'lib/clang/22/lib',True),('llvm-lib',self.llvm/'lib',True)]
  roots += [fp.RootSpec(n,p,mode='libraries',optional=o) for n,p,o in libs]
  files=[fp.FileSpec('selected-ucrt',self.ucrt,compare_mtime=False,expected_sha256=self.c['ucrt']['sha256'],expected_size=39778014,expected_basename='libucrt.lib',version='10.0.22000.0')]
  for n,p in [('cmake',self.cmake),('ctest',self.ctest),('ninja',self.ninja),('python',Path(sys.executable))]:files.append(fp.FileSpec(n,p))
  for n in ['clang-cl','lld-link','llvm-lib','llvm-rc','llvm-mt','llvm-ml64','llvm-readobj']:files.append(fp.FileSpec('llvm-'+n,self.llvm/'bin'/(n+'.exe')))
  need((self.llvm/'bin/clang.exe').is_file(),'Declared llvm-rc sibling preprocessor missing')
  for n in ['clang','clang-22','x86_64-pc-windows-msvc-clang']:files.append(fp.FileSpec('rc-candidate-'+n,self.llvm/'bin'/(n+'.exe'),optional=True))
  for label,folder in [('llvm',self.llvm/'bin'),('cmake',self.cmake.parent)]:
   for p in sorted(folder.glob('*.dll')):files.append(fp.FileSpec(label+'-dll-'+p.name.lower(),p))
  for n in ['dxcompiler.dll','dxil.dll']:files.append(fp.FileSpec('dxc-'+n,self.source/'dependencies/dxc/bin/x64'/n,compare_mtime=False))
  return fp.capture_inventory(roots,files,bounds=fp.Bounds(max_seconds=min(180,self.remaining(180))),allowance=self.fp_allowance)
 def compile_and_test(self):
  self.assert_owned();super().compile_and_test()
  self.phase='effect-ctest'
  data=json.loads(self.command([self.ctest,'--test-dir',self.build,'--show-only=json-v1','-R',EFFECT_REGEX],name='effect-discovery-built'));single_test(data,'effect_scan','faf_effect_scan_tests.exe')
  junit=self.root/'ctest-effect.xml'
  self.command([self.ctest,'--test-dir',self.build,'-R',EFFECT_REGEX,'--output-on-failure','--no-tests=error','--timeout','180','--parallel','1','--output-junit',junit],cap=210,name='ctest-effect')
  core.validate_junit(junit,['effect_scan']);self.receipt['ctest_executed'].append('effect_scan');self.assert_owned()
 def clean_dependency_plan(self):
  self.assert_owned();plan=self.command([self.ninja,'-C',self.build,'-n','-v','-d','explain',*build_graph.TARGETS],cap=120,name='dependency-reuse-admission');build_graph.clean_plan(plan)
 def dependency_sources(self,name,component_root):
  files=super().dependency_sources(name,component_root)
  return select_dependency_materials(name,component_root,files,self.material_selection)
 def stage_materials(self):
  super().stage_materials()
  self.copy_exact(self.here/MATERIAL_POLICY_FILE,'SOURCE_MATERIAL_POLICY.json')
 def prepare_materials(self):
  self.material_root=self.root/'checkpoint-material';self.material_root.mkdir(exist_ok=True)
  final_stage=self.stage;self.stage=self.material_root
  try:
   self.stage_materials()
   for name in ['README-PACKAGE.md','TESTING.md']:(self.stage/name).unlink()
   shutil.copyfile(self.here/'README-CHECKPOINT.md',self.stage/'README-CHECKPOINT.md')
  finally:self.stage=final_stage
  self.material_hashes={p.relative_to(self.material_root).as_posix():core.sha(p) for p in self.material_root.rglob('*') if p.is_file()}
 def checkpoint_policy(self):
  source,generated=self.source_inputs();roots={'source':self.source,'build':self.build,'material':self.material_root};kinds={'source':'source','build':'build','material':'material'}
  generated_roots=[]
  for t in self.target_data.values():
   for x in t['includes']:
    p=Path(x)
    if p.is_relative_to(self.build):generated_roots.append(p)
  generated_roots=sorted(set(generated_roots),key=lambda p:(len(p.parts),str(p)))
  selected=[]
  for p in generated_roots:
   if not any(p.is_relative_to(x) for x in selected):selected.append(p)
  for i,p in enumerate(selected):roots['generated-'+str(i)]=p;kinds['generated-'+str(i)]='generated'
  inputs=[checkpoint.FileSpec('source',p.relative_to(self.source).as_posix(),'material') for p in source]
  headers=[]
  for p in generated:
   label=next(k for k,r in roots.items() if kinds[k]=='generated' and p.is_relative_to(r))
   spec=checkpoint.FileSpec(label,p.relative_to(roots[label]).as_posix(),'header');inputs.append(spec);headers.append(spec)
  payloads=[checkpoint.FileSpec('build',x,'lib' if x.endswith('.lib') else 'obj') for x in self.graph['outputs']]
  payloads += [checkpoint.FileSpec('build','.ninja_log','ninja_log'),checkpoint.FileSpec('build','.ninja_deps','ninja_deps')]+headers
  # Cache visibility is not proven private; retain the reviewed public-source/license distribution materials.
  payloads += [checkpoint.FileSpec('material',x,'material') for x in sorted(self.material_hashes)]
  archive_members={}
  for target,record in self.target_data.items():
   archive_members['build/'+record['artifact']]={r['output']:'build/'+r['output'] for r in self.graph['records'] if r['target']==target and r['output'].endswith('.obj')}
  allowed=set();approved={str(self.root),str(self.msvc),str(Path(self.c['windows_sdk_root'])),str(self.llvm),str(self.cmake.parent.parent),str(Path(sys.executable).parent)}
  def add(p):
   p=Path(p);allowed.add(str(p));allowed.add(os.path.relpath(p,self.build))
  for p in source+generated:add(p)
  mapping=self.external_before.private_root_mapping()
  need(Path(mapping.get('ninja',''))==self.ninja,'Exact Ninja path lacks matching selected-file fingerprint')
  for item in self.external_before.private_manifest()['roots']:
   physical=Path(mapping[item['logical_id']])
   for r in item['records']:
    if r['kind']!='file':continue
    p=physical if item['mode']=='file' else physical/r['path'];add(p)
    # Clang may report the explicitly verified overlay alias rather than the physical SDK target.
    installed=Path(self.c['windows_sdk_root'])
    if p.is_relative_to(installed/'Include'):add(self.sdk/'Include'/p.relative_to(installed/'Include'))
  outputs=set(self.graph['outputs'])|{str(self.build/x) for x in self.graph['outputs']}
  text_pins={}
  for row in self.material_selection['retained_vms_text']:
   rel='dependencies/'+row['component']+'/'+row['path']
   text_pins['source/'+rel]=row['sha256']
   text_pins['material/corresponding-source/engine/'+rel]=row['sha256']
  # Bind the reviewed public source literal to the actual admitted Ninja edge
  # and CMake artifact. Any graph/layout change fails before dependency build.
  validate_public_literal_graph(self.graph,self.target_data,self.source,self.build)
  return checkpoint.Policy(object_mode='fixed-public-source-structured-v1',archive_members=archive_members,canaries=self.canaries,public_literal_rules=(),material_text_pins=text_pins,owned_roots=roots,root_kinds=kinds,payloads=tuple(payloads),inputs=tuple(inputs),allowed_log_inputs=frozenset(allowed),allowed_log_outputs=frozenset(outputs),approved_path_roots=tuple(sorted(approved)),log_base_root=str(self.build),approved_path_files=(str(self.ninja),),limits=checkpoint.Limits(archive_bytes=400_000_000,member_bytes=536_870_912,total_bytes=3_221_225_472,manifest_bytes=25_165_824))
 def metadata(self):
  if self.stage_name=='A':
   a=self.receipt['appveyor'];producer={'account':a['account'],'project_slug':a['project_slug'],'build_id':a['build_id'],'job_id':a['job_id'],'configuration_commit':a['provider_commit']}
  else:
   p=self.c['checkpoint_input'];producer={'account':self.c['account'],'project_slug':self.c['project_slug'],**{k:p[k] for k in ['build_id','job_id','configuration_commit']}}
  external=self.external_before.public_summary();external.pop('duration_seconds',None)
  return {'schema':1,'public_material_policy_sha256':self.material_selection_sha,'product_base':BASE,'product_tree':TREE,'dependency_recipe_key':self.recipe_key,'dependency_command_identity':self.graph['identity'],'compile_argv_identity':self.compile_argv_identity,'dependency_outputs':self.graph['outputs'],'owned_source_identity':self.owned_baseline['sha256'],'actual_glob_membership':self.owned_baseline['mbedtls_actual_glob'],'controlled_environment':self.effective_env_identity,'external_inputs':external,'producer':producer,'dependency_build_complete':True,'final_client_tests':'NOT_RUN_IN_PRODUCER','not_a_client_package':True,'object_admission_mode':'fixed-public-source-structured-v1','checkpoint_transport':'native-project-cache-v1'}
 def checkpoint_boundary(self,phase,spec,data):
  self.remaining(120)
  if phase in {'manifest','preflight-begin','preflight-end'}:self.assert_owned()
  if spec is not None and spec.root=='material':need(hashlib.sha256(data).hexdigest()==self.material_hashes[spec.relpath],'Checkpoint material differs from independently reconstructed source/notice')
 def start_acceptance_window(self):
  # Aggregate local acceptance is cooperative; reserve actual upload and cleanup time.
  self.phase_end=self.started+self.c['max_total_seconds']-390
  need(self.remaining(1)>0,'No acceptance window remains')
 def dependency_pilot(self):
  need(self.stage_name=='A','Producer pilot cannot run in consumer')
  target=self.target_data['faf_monocypher'];need(target['depends']==[],'Pilot has a concrete dependency')
  rows=[x for x in self.graph['records'] if x['target']=='faf_monocypher']
  objects=[x for x in rows if x['output'].endswith('.obj')];libs=[x for x in rows if x['output'].endswith('.lib')]
  need(len(rows)==2 and len(objects)==1 and len(libs)==1 and libs[0]['output']==target['artifact'],'Pilot closure is not exactly one object plus one archive')
  source=Path(objects[0]['source']);source=source if source.is_absolute() else self.build/source
  need(source.resolve()==(self.source/'dependencies/monocypher/src/monocypher.c').resolve(),'Unexpected pilot translation unit')
  need(not any((self.build/x).exists() for x in self.graph['outputs']),'Producer pilot requires absent selected outputs')
  wx=[r for r in self.graph['records'] if r['output']==checkpoint.WX_LITERAL_OBJECT and r['target']=='wxmswu']
  need(len(wx)==1,'Missing exact public-literal pilot edge')
  rows += wx
  self.phase='dependency-format-pilot'
  self.command([self.cmake,'--build',self.build,'--target','faf_monocypher',checkpoint.WX_LITERAL_OBJECT,'--parallel','2','--verbose','--','-d','keeprsp'],name='dependency-pilot')
  need({x for x in self.graph['outputs'] if (self.build/x).exists()}=={x['output'] for x in rows},'Pilot produced unexpected or missing selected outputs')
  members=['build/'+x['output'] for x in rows]+['build/.ninja_log','build/.ninja_deps']
  self.receipt['dependency_format_pilot']=checkpoint.validate_built_subset(self.checkpoint_policy(),members,self.checkpoint_boundary)
  need(self.remaining(1)>0,'Shared compile deadline exhausted during pilot inspection')
  print('DEPENDENCY_FORMAT_PILOT '+json.dumps(self.receipt['dependency_format_pilot'],sort_keys=True),flush=True)
 def dependency_archive_pilot(self):
  # Build and validate the actual complete wx archive before unrelated targets.
  # This consumes the existing dependency deadline, never a fresh allowance.
  need(self.stage_name=='A','Archive pilot cannot run in consumer')
  target=self.target_data['wxmswu'];need(target['depends']==[],'Archive pilot has a concrete dependency')
  need(target['artifact']==checkpoint.WX_LITERAL_LIBRARY,'Archive pilot artifact changed')
  rows=[x for x in self.graph['records'] if x['target'] in {'faf_monocypher','wxmswu'}]
  wx=[x for x in rows if x['target']=='wxmswu']
  need(wx and any(x['output']==target['artifact'] for x in wx),'Archive pilot closure lacks library')
  previous={x['output'] for x in rows if x['target']=='faf_monocypher'}|{checkpoint.WX_LITERAL_OBJECT}
  need({x for x in self.graph['outputs'] if (self.build/x).exists()}==previous,'Unexpected outputs before archive pilot')
  self.phase='dependency-archive-pilot'
  self.command([self.cmake,'--build',self.build,'--target','wxmswu','--parallel','2','--verbose','--','-d','keeprsp'],name='dependency-archive-pilot')
  need({x for x in self.graph['outputs'] if (self.build/x).exists()}=={x['output'] for x in rows},'Archive pilot output closure differs')
  members=['build/'+x['output'] for x in rows]+['build/.ninja_log','build/.ninja_deps']
  self.receipt['dependency_archive_pilot']=checkpoint.validate_built_subset(self.checkpoint_policy(),members,self.checkpoint_boundary)
  need(self.remaining(1)>0,'Shared compile deadline exhausted during archive pilot inspection')
  print('DEPENDENCY_ARCHIVE_PILOT '+json.dumps(self.receipt['dependency_archive_pilot'],sort_keys=True),flush=True)
 def stage_a(self):
  self.phase='dependency-compile';self.assert_owned();self.dependency_pilot();self.dependency_archive_pilot();self.phase='dependency-compile'
  self.command([self.cmake,'--build',self.build,'--target',*build_graph.TARGETS,'--parallel','2','--verbose','--','-d','keeprsp'],name='dependencies-build')
  self.start_acceptance_window();self.assert_owned();self.external_identity().assert_matches(self.external_before)
  self.phase='seal-checkpoint';policy=self.checkpoint_policy();meta=self.metadata()
  name='faf-re-deps-'+self.recipe_key[:16]+'-'+self.receipt['appveyor']['build_id']+'-'+self.receipt['appveyor']['job_id']+'.zip';path=self.root/'out'/name
  sealed=checkpoint.seal_checkpoint(path,policy,meta,self.checkpoint_boundary)
  self.phase='checkpoint-rehearsal';need(not self.child_uncertain,'Uncertain writer forbids rehearsal or publication')
  # Exercise reacquired source mtimes, after byte verification, only inside the owned root.
  self.assert_owned();source,_=self.source_inputs()
  # This is a new synthetic test timestamp, not rounding a saved manifest time.
  latest=max([time.time_ns()]+[(self.build/x).stat().st_mtime_ns for x in self.graph['outputs']])
  newer=((latest+99)//100)*100+2_000_000_000
  for p in source:
   need(p.is_relative_to(self.source) and not p.is_symlink(),'Rehearsal refuses external/source links')
   checkpoint._mtime(p,newer);need(p.stat().st_mtime_ns==newer,'Fresh-source timestamp simulation failed')
  # Fresh generated graph at identical stable paths; no source/tool download is repeated.
  self.remove_owned(self.build);self.build.mkdir();self.configure();self.assert_owned()
  policy=self.checkpoint_policy();checkpoint.restore_checkpoint(path,policy,sealed['sha256'],sealed['bytes'],meta,self.checkpoint_boundary)
  self.clean_dependency_plan();self.assert_owned()
  self.receipt['checkpoint_rehearsal']='PASS_ON_PRODUCER_WORKER';self.receipt['ctest_result']='NOT_RUN_IN_PRODUCER';self.receipt['build_targets']=list(build_graph.TARGETS)
  self.artifact=path;self.receipt['artifact']={'filename':name,'size':sealed['bytes'],'sha256':sealed['sha256'],'visibility':'public','kind':'dependency-checkpoint','source_tree':TREE}
 def stage_b(self):
  self.phase='checkpoint-admission';p=self.c['checkpoint_input'];policy=self.checkpoint_policy();meta=self.metadata()
  checkpoint.restore_checkpoint(self.checkpoint_path,policy,p['sha256'],p['size'],meta,self.checkpoint_boundary)
  self.clean_dependency_plan();self.assert_owned();self.receipt['checkpoint_reuse']={'state':'ADMITTED_NO_DEPENDENCY_REBUILD','producer':meta['producer'],'size':p['size'],'sha256':p['sha256']}
  self.compile_and_test();self.assert_owned();self.external_identity().assert_matches(self.external_before)
  self.stage_package()
 def verify_owner(self):
  need(self.owned_root==Path('C:/faf-re-staged')/self.recipe_key[:24],'Unexpected cleanup root')
  for p in [self.owned_root.parent,self.owned_root,self.owned_root/'OWNED_WORK.json']:
   st=p.lstat();need(not p.is_symlink() and not(getattr(st,'st_file_attributes',0)&stat.FILE_ATTRIBUTE_REPARSE_POINT),'Unexpected cleanup ownership reparse point')
  need((self.owned_root/'OWNED_WORK.json').is_file(),'Cleanup ownership marker is not a regular file')
  need(core.read_json(self.owned_root/'OWNED_WORK.json')=={'recipe':self.recipe_key,'job_id':self.receipt['appveyor']['job_id']},'Cleanup ownership mismatch')
 def remove_owned(self,target):
  need(not self.child_uncertain,'Uncertain child forbids owned cleanup')
  self.cleanup_operation='remove-owned-path'
  limit=self.remaining(60)
  owned_cleanup.remove_owned_path(self.owned_root,target,owner_check=self.verify_owner,max_seconds=limit,emit=lambda k,v:print(k+' '+json.dumps(v,sort_keys=True),flush=True))
 def remove_junctions(self,read_only=False):
  self.cleanup_operation='unlink-sdk-junctions'
  allowed={self.owned_root/'sdk-overlay/Include',self.owned_root/'sdk-overlay/Lib'/self.c['windows_sdk_headers_version']}
  for p in reversed(self.junctions):
   need(p in allowed,'Unrecognized SDK junction cleanup target')
   if os.path.lexists(p):
    st=p.lstat();need(st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT and getattr(st,'st_reparse_tag',None)==0xa0000003,'Unexpected overlay entry')
    for parent in [self.owned_root,self.owned_root/'sdk-overlay',p.parent]:need(not(parent.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT),'SDK junction parent is a reparse point')
    target=Path(self.c['windows_sdk_root'])/('Include' if p.name=='Include' else 'Lib/'+self.c['windows_sdk_headers_version'])
    need(p.resolve()==target.resolve(),'SDK junction target changed')
    if read_only:continue
    try:os.rmdir(p)
    except OSError as e:
     print('CLEANUP_DETAIL '+json.dumps({'operation':'unlink-sdk-junction','relative_path':p.relative_to(self.owned_root).as_posix(),'error_type':type(e).__name__,'errno':e.errno,'winerror':getattr(e,'winerror',None)},sort_keys=True),flush=True);raise
  if not read_only:self.junctions=[]
 def clean_before_upload(self):
  self.phase='owned-cleanup-before-upload';need(not self.child_uncertain,'Uncertain child forbids artifact promotion');self.verify_owner();self.remove_junctions()
  core.checked_hash(self.artifact,self.receipt['artifact']['sha256'])
  for p in list(self.owned_root.iterdir()):
   if p.name in {'OWNED_WORK.json','out'}:continue
   need(not(p.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT),'Unexpected work reparse entry')
   self.remove_owned(p)
  for p in (self.owned_root/'out').iterdir():
   if p!=self.artifact:need(p.is_file() and not p.is_symlink(),'Unexpected handoff directory');self.remove_owned(p)
  need(set(p.name for p in self.owned_root.iterdir())=={'OWNED_WORK.json','out'},'Owned cleanup incomplete')
  need(list((self.owned_root/'out').iterdir())==[self.artifact],'Handoff contains extra files')
  self.receipt['owned_cleanup_before_upload']='VERIFIED_ONLY_EXACT_ARTIFACT_REMAINS';self.phase_end=None
 def upload(self):
  self.phase='exact-stage-upload';need(self.receipt.get('owned_cleanup_before_upload')=='VERIFIED_ONLY_EXACT_ARTIFACT_REMAINS','No upload before verified owned cleanup')
  if self.stage_name=='A':need(self.receipt.get('checkpoint_rehearsal')=='PASS_ON_PRODUCER_WORKER','No producer upload without restoration proof')
  else:need(self.receipt.get('ctest_result')=='PASS' and sorted(self.receipt['ctest_executed'])==['effect_scan','lua_coroutine','math_dump','sim_math'],'Final acceptance incomplete')
  core.checked_hash(self.artifact,self.receipt['artifact']['sha256']);need(self.remaining(390)>=390,'Full upload plus cleanup window unavailable')
  print('PUBLIC_ARTIFACT_PREPARED '+json.dumps({'appveyor':self.receipt['appveyor'],'artifact':self.receipt['artifact'],'stage':self.stage_name,'state':'PREPARED_NOT_UPLOADED'},sort_keys=True),flush=True)
  # Provider CLI needs its own worker service variables; never serialize this environment.
  self.command([self.appveyor,'PushArtifact',self.artifact,'-FileName',self.artifact.name],env=dict(os.environ),cap=330,name='upload',started_callback=lambda:setattr(self,'upload_attempted',True))
  self.upload_accepted=True;self.receipt['state']='UPLOAD_ACCEPTED_RETRIEVAL_NOT_VERIFIED'
  print('PUBLIC_ARTIFACT_RECEIPT '+json.dumps({'appveyor':self.receipt['appveyor'],'artifact':self.receipt['artifact'],'stage':self.stage_name,'state':self.receipt['state']},sort_keys=True),flush=True)
 def cache_precompile_tests(self):
  # Native timestamp/argv probes run on Windows; synthetic tests do not prove isolation.
  self.phase='precompile-platform-tests'
  print('PLATFORM_TIMESTAMP '+json.dumps({'python':sys.version.split()[0],'platform':sys.platform,'utime_supports_nofollow':os.utime in os.supports_follow_symlinks,'exact_native_probe_required':os.name=='nt'},sort_keys=True),flush=True)
  # Before tool acquisition, pass only platform locators and this job's owned temp.
  probe_env={'SYSTEMROOT':os.environ['SYSTEMROOT'],'WINDIR':os.environ['WINDIR'],'COMSPEC':str(Path(os.environ['WINDIR'])/'System32/cmd.exe'),'PATH':os.pathsep.join([str(Path(sys.executable).parent),str(Path(os.environ['WINDIR'])/'System32')]),'TEMP':str(self.root/'temp'),'TMP':str(self.root/'temp'),'PYTHONDONTWRITEBYTECODE':'1'}
  for pattern in ['test_cache_transport.py','test_cache_ready.py','test_command_admission.py','test_structured_checkpoint.py','test_structured_objects.py','test_full_command_profiles.py','test_exact_timestamp.py','test_timestamp_integration.py','test_codeview_catalog.py']:
   self.command([sys.executable,'-I','-B','-m','unittest','discover','-s',self.here/'tests','-p',pattern,'-q'],cap=90,env=probe_env,name='precompile-'+pattern[:-3])
  self.receipt['cache_precompile_tests']='PASS_SYNTHETIC_GUARD_CHAIN_NOT_READ_ISOLATION'
 def stage_native_cache(self):
  need(self.stage_name=='A' and not self.child_uncertain,'Producer success required')
  need(self.receipt.get('checkpoint_rehearsal')=='PASS_ON_PRODUCER_WORKER','Producer restore proof missing')
  need(self.receipt.get('owned_cleanup_before_upload')=='VERIFIED_ONLY_EXACT_ARTIFACT_REMAINS','Prehandoff cleanup missing')
  need(self.remaining(390)>=390,'Native cache finalization reserve unavailable')
  self.cache_dir.parent.mkdir(exist_ok=True)
  self.cache_pin={'size':self.receipt['artifact']['size'],'sha256':self.receipt['artifact']['sha256']}
  cache_transport.stage(self.artifact,self.cache_dir,self.cache_pin)
  self.receipt['state']='CACHE_PENDING_CLEANUP_NOT_ELIGIBLE'
 def commit_native_cache(self):
  need(self.stage_name=='A' and not self.child_uncertain,'Producer only')
  need(not self.owned_root.exists(),'Owned work still present')
  r=cache_transport.commit(self.cache_dir,self.cache_pin,owned_cleanup_verified=True)
  r.update(recipe=self.recipe_key,producer=self.receipt['appveyor'],artifact=self.receipt['artifact'])
  core.write_json(self.cache_dir/'CACHE_READY.json',r)
  self.receipt['state']=r['state']
  print('NATIVE_CACHE_READY '+json.dumps(r,sort_keys=True),flush=True)
 def run(self):
  result=1
  try:
   self.validate_contract();self.verify_configuration_checkout();self.start_workspace();self.windows_cleanup_fixture();self.cache_precompile_tests()
   for method in [self.tools_and_runtime,self.source_assembly,self.configure]:
    print('PHASE '+method.__name__+' '+str(round(time.monotonic()-self.started,3)),flush=True);method()
   self.prepare_materials();self.owned_baseline=self.owned_identity();self.external_before=self.external_identity()
   need(self.external_before.public_summary()['backend']=='windows-handles','Actual Windows fingerprint backend required')
   self.receipt['external_input_fingerprint']=self.external_before.public_summary()
   self.receipt['checkpoint_policy_preflight']=checkpoint.validate_policy(self.checkpoint_policy(),self.metadata())
   print('CHECKPOINT_POLICY_PREFLIGHT '+json.dumps(self.receipt['checkpoint_policy_preflight'],sort_keys=True),flush=True)
   self.phase='precompile-content-acceptance'
   self.receipt['checkpoint_content_preflight']=checkpoint.preflight_available_content(self.checkpoint_policy(),self.metadata(),self.checkpoint_boundary)
   self.receipt['public_material_selection']={'policy_sha256':self.material_selection_sha,'omitted_exact_non_build_files':len(self.material_selection['omitted_non_build_material']),'retained_exact_vms_text_files':len(self.material_selection['retained_vms_text']),'original_checkout_unchanged':True}
   print('CHECKPOINT_CONTENT_PREFLIGHT '+json.dumps(self.receipt['checkpoint_content_preflight'],sort_keys=True),flush=True)
   self.remove_junctions(read_only=True)
   self.receipt['owned_tree_preflight']=owned_cleanup.preflight_owned_tree(self.root,self.root,owner_check=self.verify_owner,verified_junctions=tuple(self.junctions),max_seconds=self.remaining(60),emit=lambda k,v:print(k+' '+json.dumps(v,sort_keys=True),flush=True))
   print('OWNED_TREE_PREFLIGHT '+json.dumps(self.receipt['owned_tree_preflight'],sort_keys=True),flush=True)
   (self.stage_a if self.stage_name=='A' else self.stage_b)();self.clean_before_upload()
   if self.stage_name=='A':self.stage_native_cache()
   else:self.upload()
   result=0
  except Exception as e:
   self.receipt['state']='BLOCKED_UPLOAD_UNCERTAIN' if self.upload_attempted and not self.upload_accepted else 'BLOCKED'
   print('BUILD_BLOCKED '+json.dumps({'state':self.receipt['state'],'stage':self.stage_name,'phase':self.phase,'reason':build_capture.safe_text(str(e),[(self.owned_root or '<none>','<owned-work>')]),'upload_attempted':self.upload_attempted}),flush=True);result=1
  finally:
   if self.owned_root:
    if self.child_uncertain:result=1;print('CLEANUP_UNCERTAIN no artifact fallback; owned ephemeral work retained for provider teardown',flush=True)
    else:
     try:self.cleanup_operation='verify-owned-marker';self.verify_owner();self.remove_junctions();self.remove_owned(self.owned_root);print('CLEANUP owned work removed',flush=True)
     except Exception as e:result=1;print('CLEANUP_INCOMPLETE '+json.dumps({'operation':getattr(self,'cleanup_operation','unknown'),'error_type':type(e).__name__,'reason_code':getattr(e,'reason_code',None),'errno':getattr(e,'errno',None),'winerror':getattr(e,'winerror',None),'artifact_fallback':False},sort_keys=True),flush=True)
   print('FINALIZATION cache disabled unless producer commits after complete cleanup; no fallback/deploy/retry',flush=True)
  if result==0 and self.stage_name=='A':
   try:self.commit_native_cache()
   except Exception:print('CACHE_COMMIT_BLOCKED no native save eligibility',flush=True);result=1
  return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--contract',type=Path);p.add_argument('--execute',action='store_true');p.add_argument('--check-interpreter',action='store_true');a=p.parse_args()
 if a.check_interpreter:core.validate_interpreter();return 0
 if not a.execute:print('DRAFT ONLY. No execution requested.');return 2
 need(a.contract is not None,'Explicit stage contract required');return StagedBuild(Path(__file__).parent,core.read_json(a.contract)).run()
if __name__=='__main__':raise SystemExit(main())
