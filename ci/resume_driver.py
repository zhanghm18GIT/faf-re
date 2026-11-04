#!/usr/bin/env python3
"""Inert two-job balanced native build resume, trusted fixed public source only."""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import argparse,json,os,hashlib,time,subprocess,re
import driver as core
import single_driver as single
import staged_driver as shared
import build_graph,build_capture,resume_bundle
import resume_transport as cache_transport
need=core.require
COUNT=300
BUILD_INFO_HEADERS=('generated/faf/BuildInfoGenerated.h','generated/faf/EngineSwitchesGenerated.h')

def admitted_update_log(text,expected):
    commands=[re.sub(r'^\[\d+/\d+\] ','',line) for line in text.splitlines() if re.match(r'^\[\d+/\d+\] ',line)]
    need(all(line==expected for line in commands),'Resume verification executed unexpected compile/link/command')
    return len(commands)

def batches(outputs):
    """Bound each Windows invocation: <=50 object targets, <=8000 quoted chars."""
    batch=[]
    for output in outputs:
        need(len(subprocess.list2cmdline([output]))<7000,'Individual target exceeds command bound')
        if batch and (len(batch)>=50 or len(subprocess.list2cmdline(batch+[output]))>7000):
            yield batch;batch=[]
        batch.append(output)
    if batch:yield batch

class ResumeBuild(single.SingleBuild):
    ENGINE_OBJECT_COUNT=COUNT
    def validate_contract(self):
        core.Build.validate_contract(self)
        need(self.c.get('mode')=='native-simple-build-resume-v1' and self.c.get('resume_stage') in ['A','B'],'Unknown resume mode')
        self.resume_stage=self.c['resume_stage']
        need(self.c.get('max_total_seconds')==3300 and self.c.get('parallelism')==2,'Resource bounds changed')
        need(self.c.get('build_reserve_seconds')==390,'Finalization reserve changed')
        need(os.environ.get('APPVEYOR_CACHE_SKIP_SAVE','').lower()=='true','Cache starts disabled')
        need(os.environ.get('APPVEYOR_CACHE_SKIP_RESTORE','').lower()==('true' if self.resume_stage=='A' else 'false'),'Cache restore mode mismatch')
        self.material_selection=shared.validate_material_selection(core.read_json(self.here/shared.MATERIAL_POLICY_FILE))
        self.material_selection_sha=core.sha(self.here/shared.MATERIAL_POLICY_FILE)
        need(self.distribution.get('material_selection_sha256')==self.material_selection_sha and self.distribution.get('material_selection_review_status')=='REVIEWED','Material review mismatch')
        need(self.c.get('source_review_status')=='REVIEWED_FIXED_PRODUCT','Fixed source review missing')
        self.recipe=core.read_json(self.here/shared.RECIPE_FILE);self.recipe_key=shared.json_hash(self.recipe)
        need(self.recipe_key==self.c['dependency_recipe_sha256'],'Dependency recipe mismatch')
        self.resume_recipe=core.read_json(self.here/'resume-recipe.json');self.resume_key=shared.json_hash(self.resume_recipe)
        need(self.resume_key==self.c['resume_recipe_sha256'],'Resume recipe mismatch')
        need(self.resume_recipe=={'schema':1,'base_dependency_recipe':self.recipe_key,'mode':'native-simple-build-resume-v1','engine_object_count':COUNT,'selection':'nondependency-source-src-c-cpp-obj-sorted-output-v1','bundle_limit':900000000},'Unreviewed recipe')
        self.cache_dir=Path('C:/faf-re-resume')/self.resume_key[:24]
        pin=self.c.get('resume_input')
        if self.resume_stage=='A':need(pin is None and self.c['upload_exact_package'] is False,'Producer cannot consume/publish client')
        else:
            need(type(pin) is dict and set(pin)=={'size','sha256','producer'},'Separate producer receipt required')
            cache_transport.expected({'size':pin['size'],'sha256':pin['sha256']})
            need(set(pin['producer'])=={'build_id','job_id','configuration_commit'},'Producer identity fields')
            import re
            need(re.fullmatch(r'[0-9]+',pin['producer']['build_id']) and re.fullmatch(r'[a-z0-9]+',pin['producer']['job_id']) and re.fullmatch(r'[a-f0-9]{40}',pin['producer']['configuration_commit']),'Producer identity invalid')
        self.producer_deadline=None
        self.receipt.update(mode=self.c['mode'],resume_stage=self.resume_stage,completion_guarantee=False,
          trust_model='fixed public source and official tools on fresh controlled worker; no arbitrary-source isolation or cache privacy guarantee')

    def source_inputs(self):
        source,generated=super().source_inputs()
        exact=[self.build/name for name in BUILD_INFO_HEADERS]
        need(all(p.is_file() and not p.is_symlink() for p in exact),'Exact BuildInfo generated headers missing')
        return source,sorted(set(generated)|set(exact))

    def prepare_build_info(self):
        commands=self.command([self.ninja,'-C',self.build,'-t','commands','faf_build_info'],name='build-info-command').splitlines()
        need(len(commands)==1,'BuildInfo target must have exactly one command')
        self.build_info_command=commands[0]
        text=self.command([self.ninja,'-C',self.build,'-v','faf_build_info'],cap=60,name='build-info-prepare')
        need(admitted_update_log(text,self.build_info_command)==1,'BuildInfo command evidence missing')
        need(all((self.build/name).is_file() for name in BUILD_INFO_HEADERS),'BuildInfo byproducts missing')

    def command(self,args,cwd=None,cap=120,env=None,name='command',binary=False,permit_failure=False,started_callback=None):
        if name=='client-first':
            limit=min(2700,self.remaining(3300)-390);need(limit>0,'No client compile window')
            log=self.root/'logs/client-first.txt'
            result=build_capture.run_build([str(a) for a in args],cwd=cwd or self.root,env=self.child_env,log_path=log,timeout=limit,emit=print,aliases=[(self.root,'<owned-work>')])
            self.receipt.setdefault('build_capture',{})[name]=result
            print('NINJA_TIMING_SUMMARY '+json.dumps(build_capture.ninja_summary(self.build/'.ninja_log',[(self.root,'<owned-work>')])),flush=True)
            if result['state']!='SUCCESS':self.child_uncertain=True;raise core.Blocked('Client-first build did not complete')
            return log.read_text(encoding='utf-8',errors='replace')
        result=super().command(args,cwd,cap,env,name,binary,permit_failure,started_callback)
        if name=='build':return getattr(self,'client_first_log','')+'\n'+result
        return result

    def compile_and_test(self):
        self.client_first_log=self.command([self.cmake,'--build',self.build,'--target','faf_main','--parallel','2','--verbose','--','-d','keeprsp'],name='client-first')
        super().compile_and_test()

    def owned_identity(self):
        # One stable hash pass per boundary; seal/restore reuse these fresh records.
        source,generated=self.source_inputs();records=[];source_rows=[];stats={};self.input_stats={}
        admitted={p.resolve() for p in source+generated}
        need(all(p.resolve() in admitted for p in self.compile_sources),'Compile source outside inventory')
        for label,root,files in [('source',self.source,source),('generated',self.build,generated)]:
            for p in files:
                self.remaining(1);before=resume_bundle.stat_identity(p);digest=core.sha(p);after=resume_bundle.stat_identity(p)
                need(before==after,'Input changed while hashing');name=p.relative_to(root).as_posix()
                records.append({'root':label,'path':name,'size':after[2],'sha256':digest});self.input_stats[label+'/'+name]=after
                if label=='source':
                    source_rows.append({'path':name,'size':after[2],'sha256':digest,'mtime_ns':after[3]});stats[name]=after
        self.verified_source={'records':sorted(source_rows,key=lambda r:r['path']),'stats':stats}
        glob_root=self.source/'dependencies/mbedtls/library'
        glob_members=[{'name':p.name,'type':'directory' if p.is_dir() else 'file'} for p in sorted(glob_root.glob('*.c'))]
        need(glob_members and all(x['type']=='file' for x in glob_members),'Mbed TLS glob invalid')
        return {'records':records,'sha256':shared.json_hash(records),'mbedtls_actual_glob':glob_members}

    def capture_before(self):
        super().capture_before()
        self.compile_input_stats=dict(self.input_stats)

    def check_after(self):
        super().check_after()
        need(self.input_stats==self.compile_input_stats,'Input identity/mtime changed during build')

    def select_objects(self):
        expanded=json.loads(self.command([self.ninja,'-C',self.build,'-t','compdb','-x'],name='resume-compdb'))
        raw=json.loads(self.command([self.ninja,'-C',self.build,'-t','compdb'],name='resume-compdb-raw'))
        raw_by_output={build_graph.relpath(e['output']):e['command'] for e in raw}
        need(len(raw_by_output)==len(raw),'Duplicate raw compdb output')
        closure=set(self.command([self.ninja,'-C',self.build,'-t','commands',*core.REQUIRED_TARGETS],name='resume-final-target-closure').splitlines())
        targets=self.command([self.ninja,'-C',self.build,'-t','targets','all'],name='resume-targets')
        target_names={line.rsplit(': ',1)[0] for line in targets.splitlines() if ': ' in line}
        source_inventory={(self.source/core.safe_relative(row['path'])).resolve() for row in core.read_json(self.here/'public-source-allowlist.json')['files']}
        rows=[];seen=set()
        for e in expanded:
            out=resume_bundle.rel(build_graph.relpath(e['output']))
            if out in self.graph['outputs'] or not out.endswith('.obj'):continue
            if raw_by_output.get(out) not in closure:continue
            p=Path(e['file']);p=p if p.is_absolute() else self.build/p
            p=p.resolve()
            if not p.is_relative_to((self.source/'src').resolve()) or p.suffix.lower() not in {'.c','.cpp','.cc','.cxx'}:continue
            need(p in source_inventory and p.is_file(),'Engine TU outside verified source inventory')
            need(out.casefold() not in seen,'Duplicate engine output');seen.add(out.casefold())
            need(Path(e['directory'])==self.build and out in target_names,'Engine target absent from actual Ninja graph')
            rows.append({'output':out,'source':p.relative_to(self.source).as_posix(),'command_sha256':hashlib.sha256(e['command'].encode()).hexdigest()})
        rows.sort(key=lambda r:r['output']);count=self.ENGINE_OBJECT_COUNT;need(len(rows)>=count,'Insufficient actual engine object targets')
        self.selection=rows[:count];self.selected=[r['output'] for r in self.selection]
        self.receipt['resume_selection']={'count':count,'sha256':shared.json_hash(self.selection),'available_engine_objects':len(rows)}
        print('RESUME_SELECTION '+json.dumps(self.receipt['resume_selection']),flush=True)

    def producer(self):
        if self.resume_stage=='B':return self.c['resume_input']['producer']
        a=self.receipt['appveyor'];return {'build_id':a['build_id'],'job_id':a['job_id'],'configuration_commit':a['provider_commit']}

    def bundle_spec(self,selection=None):
        selection=self.selection if selection is None else selection
        selected=[r['output'] for r in selection]
        names=sorted(row['path'] for row in self.owned_baseline['records'] if row['root']=='source')
        generated={row['path'] for row in self.owned_baseline['records'] if row['root']=='generated'}
        outputs=sorted(set(self.graph['outputs'])|set(selected)|{'.ninja_log','.ninja_deps'}|generated)
        meta={'recipe':self.resume_key,'dependency_recipe':self.recipe_key,'base':core.BASE,'tree':core.TREE,
              'driver_manifest_sha256':self.c['reviewed_driver_manifest_sha256'],'tools':self.receipt['tools'],
              'graph_identity':self.graph['identity'],'compile_argv_identity':self.compile_argv_identity,
              'build_info_command_sha256':hashlib.sha256(self.build_info_command.encode()).hexdigest(),'selection':selection,'source_identity':self.owned_baseline['sha256'],
              'controlled_environment':self.effective_env_identity,'glob_membership':self.owned_baseline['mbedtls_actual_glob'],
              'cache_selections':self.receipt['cache_selections']}
        return names,outputs,meta

    def producer_groups(self):
        return [list(build_graph.TARGETS),*list(batches(self.selected))]

    def build_producer(self):
        self.producer_deadline=time.monotonic()+min(2400,self.remaining(3300)-600)
        need(self.producer_deadline>time.monotonic(),'No producer compile window')
        groups=self.producer_groups()
        for i,group in enumerate(groups):
            limit=int(min(self.producer_deadline-time.monotonic(),self.remaining(3300)-600))
            need(limit>0,'Shared producer compile deadline exhausted')
            args=[str(self.cmake),'--build',str(self.build),'--target',*group,'--parallel','2','--verbose','--','-d','keeprsp']
            need(len(subprocess.list2cmdline(args))<8000,'Windows command length bound')
            name='resume-producer-'+str(i);log=self.root/'logs'/(name+'.txt')
            result=build_capture.run_build(args,cwd=self.root,env=self.child_env,log_path=log,timeout=limit,emit=print,aliases=[(self.root,'<owned-work>')])
            self.receipt.setdefault('build_capture',{})[name]=result
            print('RESUME_BUILD_PROGRESS '+json.dumps({'batch':i,'state':result['state'],'last_ninja_status':result.get('last_ninja_status'),'elapsed_seconds':result.get('elapsed_seconds')}),flush=True)
            if result['state']!='SUCCESS':self.child_uncertain=True;raise core.Blocked('Producer batch did not complete normally')
        need(all((self.build/out).is_file() for out in self.graph['outputs']+self.selected),'Producer outputs incomplete')

    def external_header_roots(self):
        return [self.msvc/'include',self.msvc/'atlmfc/include',Path(self.c['windows_sdk_root'])/'Include'/self.c['windows_sdk_headers_version'],self.llvm/'lib/clang/22/include',self.source/'dependencies/dxsdk/Include']

    def external_header_rows(self):
        started=time.monotonic()
        text=self.command([self.ninja,'-C',self.build,'-t','deps'],cap=120,name='resume-actual-header-deps')
        queried=time.monotonic();raw=set()
        for line in text.splitlines():
            if not line.startswith('    '):continue
            value=line[4:];need(value and value==value.strip(),'Unexpected Ninja deps path format');raw.add(value)
        roots=[r.resolve() for r in self.external_header_roots()]
        build=self.build.resolve();source=self.source.resolve();dxsdk=(self.source/'dependencies/dxsdk/Include').resolve()
        paths=set()
        for value in sorted(raw):
            p=Path(value);p=(p if p.is_absolute() else self.build/p).resolve()
            if p.is_relative_to(build):continue
            if p.is_relative_to(source) and not p.is_relative_to(dxsdk):continue
            need(any(p.is_relative_to(r) for r in roots),'Actual header outside declared sysroots');paths.add(p)
        need(paths and len(paths)<=50000,'Actual external header inventory empty/oversized')
        classified=time.monotonic()
        rows=[{'path':str(p),'size':p.stat().st_size,'sha256':core.sha(p)} for p in sorted(paths)]
        print('EXTERNAL_HEADER_TIMING '+json.dumps({'query_seconds':round(queried-started,3),'classify_seconds':round(classified-queried,3),'hash_seconds':round(time.monotonic()-classified,3),'unique_raw_paths':len(raw),'unique_external_headers':len(paths)}),flush=True)
        return rows

    def verify_external_headers(self,rows):
        need(type(rows) is list and 0<len(rows)<=50000,'External header inventory bound')
        seen=set()
        for row in rows:
            need(type(row) is dict and set(row)=={'path','size','sha256'},'External header shape')
            p=Path(row['path']);need(p.is_absolute() and p.resolve()==p and p not in seen,'External header path/duplicate')
            seen.add(p)
            need(any(p.is_relative_to(r.resolve()) for r in self.external_header_roots()),'External header outside declared sysroots')
            self.remaining(1)
            need(p.is_file() and p.stat().st_size==row['size'] and core.sha(p)==row['sha256'],'Actual SDK/tool header differs from producer')

    def seal(self):
        names,outputs,meta=self.bundle_spec();self.artifact=self.root/'out/checkpoint.zip'
        pin=resume_bundle.seal(self.artifact,source=self.source,build=self.build,source_names=names,output_names=outputs,metadata=meta,producer=self.producer(),external=self.external_header_rows(),verified_source=self.verified_source,tick=lambda:self.remaining(1))
        self.cache_pin=pin;self.receipt['artifact']={'filename':'checkpoint.zip',**pin,'kind':'native-build-resume','source_tree':core.TREE}
        print('RESUME_BUNDLE_SEALED '+json.dumps({'pin':pin,'producer':self.producer(),'selection':self.receipt['resume_selection'],'output_count':len(outputs),'source_count':len(names)}),flush=True)

    def receive(self):
        p=self.c['resume_input'];self.bundle=self.root/'out/checkpoint.zip'
        cache_transport.receive(self.cache_dir/'checkpoint.zip',self.bundle,{'size':p['size'],'sha256':p['sha256']})

    def bundle_input(self):
        return self.c['resume_input']

    def restore_spec(self):
        return self.bundle_spec()

    def restore_producer(self):
        return self.producer()

    def restored_selected(self):
        return self.selected

    def restore(self):
        names,outputs,meta=self.restore_spec();p=self.bundle_input()
        selected=self.restored_selected()
        report=resume_bundle.restore(self.bundle,{'size':p['size'],'sha256':p['sha256']},source=self.source,build=self.build,source_names=names,output_names=outputs,metadata=meta,producer=self.restore_producer(),verify_external=self.verify_external_headers,verified_source=self.verified_source,tick=lambda:self.remaining(1))
        # -n predicts downstream compilation before restat and cannot prove reuse.
        # Execute bounded updates; admit only the exact verified BuildInfo command,
        # and require every cached object/archive and generated header unchanged.
        stable_names=sorted(set(self.graph['outputs'])|set(selected)|set(BUILD_INFO_HEADERS))
        before=[row for row in report.pop('verified_outputs') if row['path'] in set(stable_names)]
        need([row['path'] for row in before]==stable_names,'Restored comparison baseline incomplete')
        verification_deadline=time.monotonic()+120
        commands_run=0
        for group in [list(build_graph.TARGETS),*list(batches(selected))]:
            args=[self.ninja,'-C',self.build,'-v',*group]
            need(len(subprocess.list2cmdline([str(a) for a in args]))<8000,'Reuse command length bound')
            limit=min(30,int(verification_deadline-time.monotonic()));need(limit>0,'Reuse verification deadline')
            text=self.command(args,cap=limit,name='resume-verified-update')
            commands_run+=admitted_update_log(text,self.build_info_command)
        need(resume_bundle.records(self.build,stable_names)==before,'Cached output hash/mtime changed during reuse verification')
        report['build_info_commands_executed']=commands_run
        self.compile_input_stats={r['root']+'/'+r['path']:resume_bundle.stat_identity((self.source if r['root']=='source' else self.build)/r['path']) for r in self.owned_baseline['records']}
        report['state']='EXACT_RESTORED_ONLY_BUILDINFO_EXECUTED_CACHED_OUTPUTS_UNCHANGED';self.receipt['resume']=report
        print('RESUME_ADMITTED '+json.dumps(report),flush=True)

    def stage_cache(self):
        need(not self.child_uncertain and self.receipt.get('owned_cleanup_before_upload')=='VERIFIED_ONLY_EXACT_ARTIFACT_REMAINS','Pre-cache cleanup incomplete')
        need(self.remaining(390)==390,'Cache finalization window unavailable')
        self.cache_dir.parent.mkdir(exist_ok=True)
        cache_transport.stage(self.artifact,self.cache_dir,self.cache_pin)

    def commit_cache(self):
        need(not self.owned_root.exists(),'Owned root remains')
        r=cache_transport.commit(self.cache_dir,self.cache_pin,owned_cleanup_verified=True)
        r.update(recipe=self.resume_key,producer=self.receipt['appveyor'],artifact=self.receipt['artifact'])
        core.write_json(self.cache_dir/'CACHE_READY.json',r)
        self.receipt['state']=r['state'];print('NATIVE_CACHE_READY '+json.dumps(r),flush=True)

    def run(self):
        result=1
        try:
            for fn in [self.validate_contract,self.verify_configuration_checkout,self.start_workspace,self.windows_cleanup_fixture]:self.run_phase(fn)
            if self.resume_stage=='B':self.run_phase(self.receive)
            for fn in [self.tools_and_runtime,self.source_assembly,self.configure,self.prepare_build_info,self.select_objects,self.capture_before]:self.run_phase(fn)
            if self.resume_stage=='A':
                for fn in [self.build_producer,self.check_after,self.seal,self.clean_before_upload,self.stage_cache]:self.run_phase(fn)
            else:
                for fn in [self.restore,self.compile_and_test,self.check_after,self.stage_package,self.clean_before_upload,self.upload]:self.run_phase(fn)
            result=0
        except Exception as exc:
            self.receipt['state']='BLOCKED_UPLOAD_UNCERTAIN' if self.upload_attempted and not self.upload_accepted else 'BLOCKED'
            print('BUILD_BLOCKED '+json.dumps({'state':self.receipt['state'],'phase':self.phase,'reason':build_capture.safe_text(str(exc),[(self.owned_root or '<none>','<owned-work>')]),'upload_attempted':self.upload_attempted}),flush=True)
        finally:
            if self.owned_root:
                if self.child_uncertain:result=1;print('CLEANUP_UNCERTAIN no cache eligibility',flush=True)
                else:
                    try:self.verify_owner();self.remove_junctions();self.remove_owned(self.owned_root)
                    except Exception as exc:result=1;print('CLEANUP_INCOMPLETE '+type(exc).__name__,flush=True)
        if result==0 and self.resume_stage=='A':
            try:self.commit_cache()
            except Exception as exc:result=1;print('CACHE_COMMIT_BLOCKED '+type(exc).__name__,flush=True)
        return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--contract',type=Path);p.add_argument('--execute',action='store_true');p.add_argument('--check-interpreter',action='store_true');a=p.parse_args()
    if a.check_interpreter:core.validate_interpreter();return 0
    if not a.execute:print('DRAFT ONLY');return 2
    need(a.contract is not None,'Explicit contract required');return ResumeBuild(Path(__file__).parent,core.read_json(a.contract)).run()
if __name__=='__main__':raise SystemExit(main())
