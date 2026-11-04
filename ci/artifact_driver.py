#!/usr/bin/env python3
"""Public exact-artifact transport for the reviewed fixed-source balanced build."""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import argparse,json,os,hashlib,time
import driver as core
import staged_driver as shared
import resume_driver as resume
import resume_bundle, resume_transport as cache_transport, artifact_transfer as transfer
import build_capture
need=core.require
COUNT=450
PRODUCER_COUNT=150
BRIDGE_ID='R55025409-math-timeout-v1'
OLD_PRODUCER_MANIFEST='1de90b54ec435c11f789ad54d7eb7871d151f91d44d3627228a312f3b22bd1d0'
BRIDGE_PIN_SHA='e107b21df40cda69cc3dbd84b81ead48c7b04292973fc5d10f1d14ce294b18fe'
class ArtifactBuild(resume.ResumeBuild):
    ENGINE_OBJECT_COUNT=COUNT
    def validate_contract(self):
        core.Build.validate_contract(self)
        need(self.c.get('mode')=='public-artifact-build-resume-v1' and self.c.get('resume_stage') in ['A','R','B'],'Unknown resume mode')
        self.resume_stage=self.c['resume_stage']
        need(self.c.get('max_total_seconds')==3300 and self.c.get('parallelism')==2,'Resource bounds changed')
        need(self.c.get('build_reserve_seconds')==390,'Finalization reserve changed')
        need(os.environ.get('APPVEYOR_CACHE_SKIP_SAVE','').lower()=='true','Cache starts disabled')
        need(os.environ.get('APPVEYOR_CACHE_SKIP_RESTORE','').lower()=='true','Cache restore mode mismatch')
        self.material_selection=shared.validate_material_selection(core.read_json(self.here/shared.MATERIAL_POLICY_FILE))
        self.material_selection_sha=core.sha(self.here/shared.MATERIAL_POLICY_FILE)
        need(self.distribution.get('material_selection_sha256')==self.material_selection_sha and self.distribution.get('material_selection_review_status')=='REVIEWED','Material review mismatch')
        need(self.c.get('source_review_status')=='REVIEWED_FIXED_PRODUCT','Fixed source review missing')
        self.recipe=core.read_json(self.here/shared.RECIPE_FILE);self.recipe_key=shared.json_hash(self.recipe)
        need(self.recipe_key==self.c['dependency_recipe_sha256'],'Dependency recipe mismatch')
        self.resume_recipe=core.read_json(self.here/'artifact-recipe.json');self.resume_key=shared.json_hash(self.resume_recipe)
        need(self.resume_key==self.c['resume_recipe_sha256'],'Resume recipe mismatch')
        need(self.resume_recipe=={'schema':1,'base_dependency_recipe':self.recipe_key,'mode':'public-artifact-build-resume-v1','engine_object_count':COUNT,'producer_object_count':PRODUCER_COUNT,'selection':'nondependency-source-src-c-cpp-obj-sorted-output-v1','bundle_limit':900000000},'Unreviewed recipe')
        need(os.environ.get('APPVEYOR_SKIP_FINALIZE_ON_EXIT','').lower()=='true' and os.environ.get('APPVEYOR_SAVE_CACHE_ON_ERROR','').lower()=='false','Provider finalization controls')
        pin=self.c.get('resume_input')
        if self.resume_stage=='A':need(pin is None and self.c['upload_exact_package'] is True,'Producer must explicitly publish transfer')
        else:
            self.validate_input_pin(pin,expects_parent=self.resume_stage=='B')
        self.incoming_manifest()
        self.producer_deadline=None
        self.receipt.update(mode=self.c['mode'],resume_stage=self.resume_stage,completion_guarantee=False,
          trust_model='fixed public source and official tools on fresh controlled worker; no arbitrary-source isolation or artifact confidentiality guarantee')

    def incoming_manifest(self):
        bridge=self.c.get('reviewed_producer_bridge')
        if bridge is None:return self.c['reviewed_driver_manifest_sha256']
        need(bridge==BRIDGE_ID and self.resume_stage=='B','Reviewed producer bridge is final-B only')
        path=self.here/'reviewed-r55025409.json';core.checked_hash(path,BRIDGE_PIN_SHA)
        need(self.c['resume_input']==core.read_json(path),'Reviewed producer bridge requires exact R and A pins')
        return OLD_PRODUCER_MANIFEST

    def run_math_ctests(self):
        if self.resume_stage!='B':return super().run_math_ctests()
        deadline=time.monotonic()+self.remaining(420)
        for name,timeout in [('sim_math',180),('math_dump',360)]:
            cap=int(min(420,deadline-time.monotonic()))
            need(cap>0,'Shared 420-second math CTest window exhausted')
            junit=self.root/('ctest-'+name+'.xml')
            print('CTEST_PHASE '+json.dumps({'test':name,'timeout_seconds':timeout,'shared_remaining_seconds':cap,'inputs_per_target':1000000 if name=='math_dump' else None,'retail_values_unchanged':name=='math_dump'}),flush=True)
            self.command([self.ctest,'--test-dir',self.build,'-R','^'+name+'$','--output-on-failure','--no-tests=error','--timeout',str(timeout),'--parallel','1','--output-junit',junit],cap=cap,name='ctest-'+name)
            core.validate_junit(junit,[name])

    def validate_input_pin(self,pin,*,expects_parent):
        need(type(pin) is dict and set(pin)=={'url','size','sha256','inner','producer','predecessor'},'Separate producer chain required')
        transfer.pin({'size':pin['size'],'sha256':pin['sha256']});cache_transport.expected(pin['inner'])
        producer=pin['producer']
        need(type(producer) is dict and set(producer)=={'build_id','job_id','configuration_commit'},'Producer identity fields')
        import re
        need(all(type(producer[k]) is str for k in producer),'Producer identity types')
        need(re.fullmatch(r'[0-9]+',producer['build_id']) and re.fullmatch(r'[a-z0-9]+',producer['job_id']) and re.fullmatch(r'[a-f0-9]{40}',producer['configuration_commit']),'Producer identity invalid')
        need(pin['url']=='https://ci.appveyor.com/api/buildjobs/'+producer['job_id']+'/artifacts/resume-transfer.zip','Exact producer artifact URL required')
        if expects_parent:
            self.validate_input_pin(pin['predecessor'],expects_parent=False)
            need(pin['predecessor']['producer']!=producer,'Producer cannot be its own predecessor')
        else:need(pin['predecessor'] is None,'Unexpected predecessor depth')

    def select_objects(self):
        super().select_objects()
        full=list(self.selection)
        count=PRODUCER_COUNT if self.resume_stage=='A' else COUNT
        self.selection=full[:count];self.selected=[r['output'] for r in self.selection]
        input_count=PRODUCER_COUNT if self.resume_stage=='R' else COUNT
        self.input_selection=[] if self.resume_stage=='A' else full[:input_count]
        self.receipt['resume_selection'].update(count=count,sha256=shared.json_hash(self.selection))
        print('ARTIFACT_SELECTION '+json.dumps({'role':self.resume_stage,'input_count':len(self.input_selection),'output_count':count,'selection_sha256':shared.json_hash(self.selection)}),flush=True)

    def output_predecessor(self):
        return self.c['resume_input'] if self.resume_stage=='R' else None

    def transfer_metadata(self,*,incoming=False):
        pin=self.c['resume_input'] if incoming else None
        return {'mode':self.c['mode'],'producer':pin['producer'] if incoming else self.producer(),'predecessor':pin['predecessor'] if incoming else self.output_predecessor(),'engine_object_count':(PRODUCER_COUNT if self.resume_stage=='R' else COUNT) if incoming else (PRODUCER_COUNT if self.resume_stage=='A' else COUNT),'base':core.BASE,'tree':core.TREE,'recipe':self.resume_key,'driver_manifest_sha256':self.incoming_manifest() if incoming else self.c['reviewed_driver_manifest_sha256'],'material_policy_sha256':self.material_selection_sha}

    def bundle_spec(self,selection=None):
        names,outputs,meta=super().bundle_spec(selection)
        meta['predecessor']=self.output_predecessor()
        return names,outputs,meta

    def restore_spec(self):
        names,outputs,meta=resume.ResumeBuild.bundle_spec(self,self.input_selection)
        meta['predecessor']=self.c['resume_input']['predecessor']
        meta['driver_manifest_sha256']=self.incoming_manifest()
        return names,outputs,meta

    def restore_producer(self):
        return self.c['resume_input']['producer']

    def restored_selected(self):
        return [r['output'] for r in self.input_selection]

    def producer_groups(self):
        if self.resume_stage=='R':
            need(len(self.input_selection)==PRODUCER_COUNT and self.selection[:PRODUCER_COUNT]==self.input_selection,'Relay prefix mismatch')
            return list(resume.batches(self.selected[PRODUCER_COUNT:COUNT]))
        return super().producer_groups()

    def material_inputs(self):
        # Reuse fresh source selection/hash records already checked at this boundary.
        # No new full-source walk/hash or 35k-file copy is necessary.
        rows={r['path']:r for r in self.verified_source['records']};items={}
        def add_file(name,path,record=None):
            name=resume_bundle.rel(name);need(name not in items,'Duplicate material destination')
            if record is None:record={'size':path.stat().st_size,'sha256':core.sha(path)}
            items[name]=(path,record['size'],record['sha256'])
        for name,r in sorted(rows.items()):
            p=self.source/name
            need(resume_bundle.stat_identity(p)==tuple(self.verified_source['stats'][name]),'Material changed after verified boundary')
            add_file('corresponding-source/engine/'+name,p,r)
        hook=self.integration['hook_files'];need(len(hook)==1 and hook[0]['path'] in rows,'Hook selection missing')
        add_file('fafengine/lua/options/options.lua',self.source/hook[0]['path'],rows[hook[0]['path']])
        for component in core.SOURCE_COMPONENTS:
            prefix='dependencies/'+component+'/'
            candidates={name[len(prefix):]:r for name,r in rows.items() if name.startswith(prefix)}
            need(candidates,'Selected source component absent')
            names={name for name in candidates if core.NOTICE_RE.match(Path(name).name)}
            names.update(self.distribution.get('additional_notice_paths',{}).get(component,[]))
            need(names and names<=set(candidates),'Required component notices missing')
            for name in sorted(names):add_file('notices/'+component+'/'+name,self.source/prefix/name,candidates[name])
        lua='src/lua/luaplus/LICENSE';need(lua in rows,'Lua notice missing');add_file('notices/luaplus/LICENSE',self.source/lua,rows[lua])
        dxc=self.source/'dependencies/dxc'
        notices=[p for p in self.dependency_sources('dxc',dxc) if core.NOTICE_RE.match(p.name)]
        need(notices and any('ms' in p.name.lower() for p in notices) and any('llvm' in p.name.lower() for p in notices),'DXC notices missing')
        for p in notices:add_file('notices/dxc/'+p.relative_to(dxc).as_posix(),p)
        required=['corresponding-source/engine/LEGAL.md','corresponding-source/engine/dependencies/ffmpeg/configure','corresponding-source/engine/dependencies/ffmpeg/faf/CMakeLists.txt']
        need(all(n in items for n in required),'Required legal/relink materials missing')
        for src,dst in [('REBUILD.md','REBUILD.md'),('README-TRANSFER.md','README-TRANSFER.md'),(shared.MATERIAL_POLICY_FILE,'SOURCE_MATERIAL_POLICY.json')]:add_file(dst,self.here/src)
        data={k:self.integration[k] for k in ['base_commit','base_tree','planned_integrated_tree','submodule_gitlinks','download_dependencies','directx_sdk','build_file_sha256','hook_files','dependency_patch_blobs']}
        data['changed_files']=[{k:r[k] for k in ['pr','head','path','before_blob','after_blob','before_sha256','after_sha256']} for r in self.integration['changed_files']]
        raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode();items['SOURCE_MANIFEST.json']=(raw,len(raw),transfer.digest(raw))
        return items

    def seal(self):
        super().seal();inner=self.artifact;inner_pin=self.cache_pin
        need(self.remaining(3300)>390,'No material packaging window')
        materials=self.material_inputs();self.artifact=self.root/'out/resume-transfer.zip'
        self.transfer_pin,self.transfer_receipt=transfer.seal(self.artifact,inner,inner_pin,materials,self.transfer_metadata(),tick=lambda:need(self.remaining(3300)>390,'Transfer packaging reserve exhausted'))
        self.receipt['artifact']={'filename':self.artifact.name,**self.transfer_pin,'inner':inner_pin,'kind':'public-build-resume-with-corresponding-source','source_tree':core.TREE}
        print('PUBLIC_TRANSFER_SEALED '+json.dumps({'artifact':self.receipt['artifact'],'producer':self.producer(),'material_count':len(materials)}),flush=True)

    def bundle_input(self):
        return {**self.c['resume_input']['inner'],'producer':self.c['resume_input']['producer']}

    def receive(self):
        p=self.c['resume_input'];outer=self.root/'out/incoming-transfer.zip';self.bundle=self.root/'out/incoming-checkpoint.zip'
        self.download_fixed(p['url'],outer,p['size'],300)
        self.transfer_receipt=transfer.verify(outer,{'size':p['size'],'sha256':p['sha256']},self.transfer_metadata(incoming=True),p['inner'],destination=self.bundle,tick=lambda:self.remaining(1))

    def restore(self):
        materials=self.material_inputs();expected=sorted([transfer.row(n,s,h) for n,(_,s,h) in materials.items()],key=lambda r:r['path'])
        need(self.transfer_receipt['materials']==expected,'Transfer material selection/content differs from independently assembled source')
        super().restore()

    def stage_transfer(self):
        need(not self.child_uncertain and self.receipt.get('owned_cleanup_before_upload')=='VERIFIED_ONLY_EXACT_ARTIFACT_REMAINS','Transfer cleanup prerequisite')
        need(self.remaining(390)>=390,'Transfer upload reserve')
        parent=Path('C:/faf-re-public-transfer');parent.mkdir(exist_ok=True)
        self.transfer_dir=parent/(self.resume_key[:24]+'-'+self.receipt['appveyor']['job_id'])
        cache_transport.stage(self.artifact,self.transfer_dir,self.transfer_pin)
        # This is an owned exact-file copy only, never a cache entry or cache commit.
        self.pending_transfer=self.transfer_dir/'checkpoint.pending'

    def publish_transfer(self):
        need(not self.child_uncertain and not self.owned_root.exists(),'No publication before complete owned cleanup')
        need(set(p.name for p in self.transfer_dir.iterdir())=={'checkpoint.pending'},'Transfer staging contains extra files')
        need(cache_transport.identity(self.pending_transfer)==self.transfer_pin,'Staged transfer drift')
        need(self.remaining(390)>=390,'Transfer upload reserve exhausted')
        # CLI alone receives provider service variables; never serialize them.
        self.command([self.appveyor,'PushArtifact',self.pending_transfer,'-FileName','resume-transfer.zip'],cwd=self.transfer_dir,env=dict(os.environ),cap=330,name='upload',started_callback=lambda:setattr(self,'upload_attempted',True))
        self.upload_accepted=True;self.receipt['state']='UPLOAD_ACCEPTED_RETRIEVAL_NOT_VERIFIED'
        print('PUBLIC_ARTIFACT_RECEIPT '+json.dumps({'appveyor':self.receipt['appveyor'],'artifact':self.receipt['artifact'],'stage':self.resume_stage,'state':self.receipt['state']}),flush=True)

    def run(self):
        result=1
        try:
            for fn in [self.validate_contract,self.verify_configuration_checkout,self.start_workspace,self.windows_cleanup_fixture]:self.run_phase(fn)
            if self.resume_stage in ['R','B']:self.run_phase(self.receive)
            for fn in [self.tools_and_runtime,self.source_assembly,self.configure,self.prepare_build_info,self.select_objects,self.capture_before]:self.run_phase(fn)
            if self.resume_stage=='R':self.run_phase(self.restore)
            if self.resume_stage in ['A','R']:
                for fn in [self.build_producer,self.check_after,self.seal,self.clean_before_upload,self.stage_transfer]:self.run_phase(fn)
            else:
                for fn in [self.restore,self.compile_and_test,self.check_after,self.stage_package,self.clean_before_upload,self.upload]:self.run_phase(fn)
            result=0
        except Exception as exc:
            self.receipt['state']='BLOCKED_UPLOAD_UNCERTAIN' if self.upload_attempted and not self.upload_accepted else 'BLOCKED'
            print('BUILD_BLOCKED '+json.dumps({'state':self.receipt['state'],'phase':self.phase,'reason':build_capture.safe_text(str(exc),[(self.owned_root or '<none>','<owned-work>')]),'upload_attempted':self.upload_attempted}),flush=True)
        finally:
            if self.owned_root:
                if self.child_uncertain:result=1;print('CLEANUP_UNCERTAIN no publication',flush=True)
                else:
                    try:self.verify_owner();self.remove_junctions();self.remove_owned(self.owned_root)
                    except Exception as exc:result=1;print('CLEANUP_INCOMPLETE '+type(exc).__name__,flush=True)
        if result==0 and self.resume_stage in ['A','R']:
            try:self.publish_transfer()
            except Exception as exc:
                result=1;self.receipt['state']='BLOCKED_UPLOAD_UNCERTAIN' if self.upload_attempted else 'BLOCKED'
                print('TRANSFER_UPLOAD_BLOCKED '+json.dumps({'state':self.receipt['state'],'error_type':type(exc).__name__}),flush=True)
        return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--contract',type=Path);p.add_argument('--execute',action='store_true');p.add_argument('--check-interpreter',action='store_true');a=p.parse_args()
    if a.check_interpreter:core.validate_interpreter();return 0
    if not a.execute:print('DRAFT ONLY');return 2
    need(a.contract is not None,'Explicit contract required');return ArtifactBuild(Path(__file__).parent,core.read_json(a.contract)).run()
if __name__=='__main__':raise SystemExit(main())
