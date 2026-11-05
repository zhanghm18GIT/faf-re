"""One isolated manual Windows build. Draft is fail-closed; never dispatches itself."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from native_checks import *
import toolchain

HERE = Path(__file__).resolve().parent
PRODUCT_LIMIT = 400*1024*1024
DIAGNOSTICS_LIMIT = 32*1024*1024
GRANTS = ['publish_exact_reviewed_driver','one_manual_appveyor_job','temporary_appveyor_settings',
          'restore_original_settings','windows_sdk_license','directx_sdk_license','public_diagnostics_and_product']


def authorize(a, env, now):
    need(a['state']=='AUTHORIZED_FOR_ONE_REVIEWED_RUN', 'Draft: current explicit authorization is absent')
    need(re.fullmatch(r'[0-9a-f]{64}',a.get('approval_receipt_sha256') or '') and all(a['grants'].get(k) is True for k in GRANTS),'Required current grant missing')
    need(a['plan']=='Free' and a['subscription_status']=='Active' and a['paid_budget_usd']==0,'Free Active only')
    need(a['runner']=='Visual Studio 2022' and a['max_job_minutes']==60 and a['max_attempts']==1,'Execution scope changed')
    need(a['work_deadline_minutes']==50 and a['watchdog_minutes']==52 and a['finalize_deadline_minutes']==55,'Deadline contract changed')
    need(a['repository_visibility']=='public' and a['repository']=='zhanghm18GIT/faf-re','Exact public repository only')
    need(a['account']=='zhanghm18GIT' and a['project_slug']=='faf-re','Exact existing project only')
    need(type(a['expected_build_number']) is int and a['expected_build_number']>0,'Verified next build number missing')
    checked=dt.datetime.fromisoformat(a['verified_utc'].replace('Z','+00:00'))
    need(0 <= (now-checked).total_seconds() <= 3600, 'Authorization/account preflight must be current within one hour')
    expected={'APPVEYOR':'True','APPVEYOR_ACCOUNT_NAME':a['account'],'APPVEYOR_PROJECT_SLUG':a['project_slug'],
              'APPVEYOR_REPO_NAME':a['repository'],'APPVEYOR_REPO_BRANCH':a['branch'],
              'APPVEYOR_BUILD_WORKER_IMAGE':a['runner'],'APPVEYOR_FORCED_BUILD':'True',
              'APPVEYOR_BUILD_NUMBER':str(a['expected_build_number']),
              'APPVEYOR_CACHE_SKIP_RESTORE':'true','APPVEYOR_CACHE_SKIP_SAVE':'true'}
    for key,value in expected.items():
        actual=env.get(key,'')
        if key in {'APPVEYOR','APPVEYOR_ACCOUNT_NAME','APPVEYOR_FORCED_BUILD'}: actual,value=actual.lower(),value.lower()
        need(actual==value, 'Wrong execution context '+key)
    for key in ['APPVEYOR_SCHEDULED_BUILD','APPVEYOR_RE_BUILD','APPVEYOR_RE_RUN_INCOMPLETE','APPVEYOR_REPO_TAG']:
        need(env.get(key,'').lower() not in {'true','1'}, 'Rerun/schedule/tag disallowed: '+key)
    need(not env.get('APPVEYOR_PULL_REQUEST_NUMBER'),'PR trigger disallowed')
    need(re.fullmatch(r'[0-9a-f]{40}',env.get('APPVEYOR_REPO_COMMIT','')),'Invalid immutable driver SHA')
    need(re.fullmatch(r'[0-9]+',env.get('APPVEYOR_BUILD_ID','')),'Invalid build ID')
    need(re.fullmatch(r'[a-zA-Z0-9]+',env.get('APPVEYOR_JOB_ID','')),'Invalid job ID')
    need(env.get('APPVEYOR_BUILD_VERSION')=='fresh-native.'+str(a['expected_build_number']),'Wrong single-build version')
    started=dt.datetime.fromisoformat(env.get('FAF_JOB_STARTED_UTC','').replace('Z','+00:00'))
    need(0 <= (now-started).total_seconds() < 50*60,'Job start/deadline missing or expired')


def verify_driver(workspace):
    frozen=json.loads((HERE/'DRIVER_FILES.json').read_text())
    need(frozen['status']=='REVIEWED_FOR_AUTHORIZED_ACTIVATION','Driver independent review not closed')
    verify_files(workspace,frozen['files'])
    actual={p.relative_to(workspace).as_posix() for p in (workspace/'ci').rglob('*') if p.is_file()}
    expected={e['path'] for e in frozen['files'] if e['path'].startswith('ci/')}|{'ci/DRIVER_FILES.json'}
    need(actual==expected,'Unexpected or missing driver runtime/test file')
    return frozen


class Context:
    def __init__(self, workspace):
        self.workspace=workspace.resolve()
        self.out=self.workspace/'ci-results'
        need(not self.out.exists(),'Output already exists; no retries or stale output reuse')
        self.logs=self.out/'raw-logs'; self.logs.mkdir(parents=True)
        started=os.environ.get('FAF_JOB_STARTED_UTC')
        age=(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(started.replace('Z','+00:00'))).total_seconds() if started else 0
        self.deadline=time.monotonic()+max(0,50*60-age)
        self.root=None; self.authorizations={}; self.codes={}
        self.receipt={'status':'BLOCKED_OR_NOT_STARTED','native_gates':'NOT_RUN','native_checks':{},
                      'in_game':'NOT_RUN','replays':'NOT_RUN','not_run_tests':ALL_CTESTS,
                      'network_policy':'official pinned public inputs only; no AppVeyor R artifacts',
                      'paid_budget_usd':0,'started_utc':dt.datetime.now(dt.timezone.utc).isoformat()}
        self.save()
    def save(self):
        (self.out/'RECEIPT.json').write_text(json.dumps(self.receipt,indent=2,default=str)+'\n',encoding='utf-8')
    def remaining(self,cap):
        left=min(cap,self.deadline-time.monotonic())
        need(left>0,'50 minute work deadline reached; no retry')
        return left
    def command(self,args,name,cap,cwd=None,env=None,permit_failure=False):
        need(re.fullmatch(r'[a-zA-Z0-9_-]+',name),'Unsafe diagnostic log name')
        path=self.logs/(name+'.log'); need(not path.exists(),'Duplicate command name '+name)
        # No environment dump, shell invocation or secret-bearing command arguments.
        with path.open('xb') as log:
            p=subprocess.Popen([str(x) for x in args],cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT)
            try: code=p.wait(timeout=self.remaining(cap))
            except BaseException:
                if p.poll() is None:
                    subprocess.run(['taskkill.exe','/PID',str(p.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                    p.wait(timeout=30)
                raise
        self.codes[name]=code
        self.receipt.setdefault('commands',[]).append({'name':name,'exit_code':code,'bytes':path.stat().st_size,'sha256':digest(path)})
        self.save()
        need(path.stat().st_size<=192*1024*1024,'Command log exceeds bounded parser size: '+name)
        text=path.read_text(encoding='utf-8-sig',errors='replace')
        need(permit_failure or code==0, 'Command failed: '+name+'; see retained log')
        return text
    def download(self,pin,dest):
        need(pin['url'].startswith('https://'),'Only HTTPS downloads permitted')
        need(not dest.exists() and dest.resolve().is_relative_to(self.root.resolve()),'Nonexclusive/outside download')
        dest.parent.mkdir(parents=True,exist_ok=True)
        with urllib.request.urlopen(pin['url'],timeout=self.remaining(180)) as response, dest.open('xb') as stream:
            need(response.geturl().startswith('https://'),'Downgraded download redirect')
            total=0
            while block:=response.read(1024*1024):
                self.remaining(180); total+=len(block)
                need(total<=pin['size'],'Download exceeds exact pinned size')
                stream.write(block)
        need(total==pin['size'] and digest(dest)==pin['sha256'],'Download size/hash mismatch')
    def passed(self,name):
        self.receipt['native_checks'][name]='PASS'; self.save()


def git(ctx, source, args, name, cap=120):
    return ctx.command(['git','-c','core.autocrlf=false','-C',source,*args],name,cap).strip()


def source(ctx,inputs):
    path=ctx.root/'source'; path.mkdir()
    git(ctx,path,['init','--quiet'],'source-init')
    git(ctx,path,['config','core.autocrlf','false'],'source-autocrlf')
    git(ctx,path,['remote','add','origin',inputs['repository']],'source-origin')
    git(ctx,path,['fetch','--depth=1','--no-tags','origin',inputs['base']],'source-fetch',600)
    git(ctx,path,['checkout','--detach',inputs['base']],'source-checkout')
    need(git(ctx,path,['rev-parse','HEAD^{tree}'],'base-tree')==inputs['base_tree'],'Wrong base tree')
    verify_files(path,inputs['upstream_files'])
    need(digest(HERE/'candidate.patch')==inputs['patch_sha256'],'Candidate patch changed')
    git(ctx,path,['apply','--check',HERE/'candidate.patch'],'patch-check')
    git(ctx,path,['apply',HERE/'candidate.patch'],'patch-apply')
    git(ctx,path,['add','--',*[e['path'] for e in inputs['changes']]],'candidate-index')
    need(git(ctx,path,['write-tree'],'candidate-tree')==inputs['candidate_tree'],'Wrong reconstructed candidate tree')
    verify_files(path,inputs['candidate_files']); check_resource_set(path,inputs['resources'])
    ctx.receipt.update(base_commit=inputs['base'],candidate_tree=inputs['candidate_tree'],patch_sha256=inputs['patch_sha256'])
    ctx.passed('source'); return path


def dependencies(ctx,src,tools,inputs):
    need(ctx.authorizations['directx_sdk_license'] is True,'DirectX SDK current license authorization absent')
    # Force an owned SDK extraction, rather than accepting an unpinned globally installed SDK.
    env=os.environ.copy(); env.pop('DXSDK_DIR',None)
    ctx.command([tools['cmake'],'-DFAF_DXSDK_FORCE_DOWNLOAD=ON','-P',src/'cmake/FafDependencies.cmake'],'dependencies',1500,cwd=src,env=env)
    rows=json.loads((HERE/'dependencies.json').read_text())['files']
    verify_files(src,[e for e in rows if e['kind']=='regular'])
    for e in rows:
        if e['kind']=='symlink':
            p=src/relative(e['path'])
            # CMake on Windows may materialize archive symlinks as copies. Same content required.
            need(p.is_file() and digest(p)==e['sha256'] and p.stat().st_size==e['bytes'],'Dependency link/content mismatch')
            if p.is_symlink(): need(os.readlink(p)==e['target'],'Dependency link target differs')
    for i,e in enumerate(inputs['gitlinks']):
        need(git(ctx,src/e['path'],['rev-parse','HEAD'],'gitlink-'+str(i))==e['sha'],'Wrong submodule HEAD')
    # All fixed downloaded archives and all prepared non-SDK bytes were just verified.
    dx=src/'dependencies/dxsdk'
    need(dx.is_dir(),'SDK must be private extracted copy; installed fallback not accepted')
    archive=src/'dependencies/.downloads/DXSDK_Jun10.exe'
    need(archive.is_file() and digest(archive)==inputs['dxsdk']['sha256'],'Wrong/unverified DXSDK archive')
    for p in ['Include/d3dx9.h','Include/d3dx11.h','Lib/x64/d3dx9.lib','Lib/x64/d3dx11.lib','Lib/x64/x3daudio.lib']:
        need((dx/p).is_file(),'DirectX SDK component absent '+p)
    verify_files(src,inputs['candidate_files'])
    ctx.passed('dependencies'); return dx


def build_and_test(ctx,src,t,dx,inputs):
    b=ctx.root/'build'
    need(shutil.disk_usage(ctx.root).free>=6*1024**3,'Less than 6GiB free before native compile')
    args=[t['cmake'],'--preset','clang-x64-release','-S',src,'-B',b,
          '-DCMAKE_MAKE_PROGRAM='+str(t['ninja']),'-DFAF_LLVM_ROOT='+str(t['llvm']),'-DFAF_MSVC_TOOLS_DIR='+str(t['msvc']),
          '-DFAF_WINSDK_DIR='+str(t['sdk_root']),'-DFAF_WINSDK_VERSION='+t['sdk_version'],
          '-DFAF_DXSDK_DIR='+str(dx),'-DFAF_UCRT_LIB_VERSION=10.0.22000.0',
          '-DFAF_FETCH_DEPENDENCIES=OFF','-DFAF_OUTPUT_NAME=main_x64','-DFAF_PGO_PROFILE=',
          *['-D'+k+'=OFF' for k in OFF]]
    ctx.command(args,'configure',600,cwd=src)
    check_cache(read_cache(b/'CMakeCache.txt')); ctx.passed('cache')
    log=ctx.command([t['cmake'],'--build',b,'--parallel','2','--target',*TARGETS,'--','-v','-d','keeprsp'],
                    'native-build',3000,cwd=src)
    need('--iters 131072' in log and 'retail_values.txt' in log,'Native math POST_BUILD command absent from actual build log')
    outputs=[]
    for target,rel in OUTPUTS.items():
        p=b/rel; need(p.is_file() and toolchain.pe_machine(p)==0x8664,'Missing/non-x64 target '+target)
        imports=ctx.command([t['llvm']/'bin/llvm-readobj.exe','--coff-imports',p],'imports-'+target,60)
        dlls=[v.lower() for v in re.findall(r'Name:\s+(\S+\.dll)',imports,re.I)]
        need(dlls and not any(re.match(r'(ucrtbase|api-ms-win-crt-|msvcrt|vcruntime|msvcp)',v) for v in dlls),'Dynamic CRT/missing imports '+target)
        outputs.append({'target':target,'path':rel,'sha256':digest(p),'imports':dlls})
    ctx.receipt['outputs']=outputs; ctx.passed('targets')
    names=[Path(rel).name for target,rel in OUTPUTS.items() if target not in {'faf_effect_scan_tests','faf_texture_quality_tests'}]
    ctx.receipt['actual_links']=toolchain.validate_actual_links(log,b,t['ucrt'],names)
    ctx.receipt['standalone_tests_crt']='effect_scan and texture_quality: standalone normal static CRT; engine old UCRT override not applicable'
    ctx.passed('actual_links')
    discovery=ctx.command([t['ctest'],'--test-dir',b,'--show-only=json-v1'],'ctest-discovery',90)
    ctx.receipt['not_run_tests']=check_discovery(json.loads(discovery),src,b)
    junit=ctx.logs/'ctest-results.xml'
    ctx.command([t['ctest'],'--test-dir',b,'--output-on-failure','--no-tests=error','-R','^(sim_math|math_dump|lua_coroutine|effect_scan|replay_scan|texture_quality)$','--output-junit',junit],'ctest-mandatory',900)
    check_junit(junit); ctx.passed('ctest')
    codec=ctx.command([b/OUTPUTS['faf_image_codec_tests']],'image-codec',180,permit_failure=True)
    check_codec(ctx.codes['image-codec'],codec); ctx.passed('image_codec')
    ctx.command([t['cmake'],'-DREADOBJ='+str(t['llvm']/'bin/llvm-readobj.exe'),'-DEXE='+str(b/OUTPUTS['headless']),'-DTRACY=0','-P',src/'cmake/HeadlessImports.cmake'],'headless-imports',90)
    ctx.passed('headless_imports')
    info=b/'generated/faf/BuildInfoGenerated.h'; check_build_info(info.read_text(),inputs['base'])
    shutil.copyfile(info,ctx.logs/'BuildInfoGenerated.h'); ctx.passed('build_info')
    verify_files(src,inputs['candidate_files'])
    need(git(ctx,src,['write-tree'],'postbuild-tree')==inputs['candidate_tree'],'Candidate index drift')
    check_resource_set(src,inputs['resources']); ctx.passed('resources')
    ctx.receipt['native_gates']='PASS'; ctx.receipt['status']='BUILT_NATIVE_GATES_PASS_GAME_NOT_RUN'; ctx.save()
    return b


def diagnostics(ctx):
    ctx.save(); folder=ctx.out/'diagnostics'; folder.mkdir(exist_ok=True)
    archive=folder/'diagnostics.zip'; pending=ctx.out/'diagnostics.pending.zip'
    # Bound TOTAL uncompressed log bytes, then atomically expose only a checked zip.
    # Original size/hash + exact truncation are retained even when large logs are cut.
    remaining=16*1024*1024; entries=[]
    with zipfile.ZipFile(pending,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        z.write(ctx.out/'RECEIPT.json','RECEIPT.json')
        for p in sorted(ctx.logs.iterdir()):
            if not p.is_file() or p.is_symlink(): continue
            size=p.stat().st_size; take=min(size,4*1024*1024,remaining)
            entry={'name':p.name,'original_bytes':size,'sha256':digest(p),'retained_bytes':take,'truncated':take<size}
            entries.append(entry)
            if not take: continue
            with p.open('rb') as f:
                if take<size: f.seek(size-take)
                data=f.read(take)
            suffix='.TAIL_TRUNCATED' if take<size else ''
            z.writestr('logs/'+p.name+suffix,data); remaining-=take
        z.writestr('DIAGNOSTIC_INDEX.json',json.dumps(entries,indent=2))
    need(pending.stat().st_size<=DIAGNOSTICS_LIMIT,'Diagnostic cap exceeded; final upload path not exposed')
    os.replace(pending,archive)
    return archive


def main():
    workspace=Path(os.environ.get('APPVEYOR_BUILD_FOLDER',HERE.parent))
    ctx=Context(workspace)
    try:
        a=json.loads((HERE/'authorization.json').read_text())
        authorize(a,os.environ,dt.datetime.now(dt.timezone.utc))
        need(os.name=='nt' and sys.version_info>=(3,11) and sys.maxsize>2**32,'64-bit Windows/Python >=3.11 required')
        ctx.authorizations=a['grants']
        verify_driver(workspace)
        ctx.receipt['appveyor']={k:os.environ.get('APPVEYOR_'+k) for k in ['BUILD_ID','JOB_ID','BUILD_NUMBER','BUILD_VERSION','REPO_COMMIT']}
        ctx.receipt['one_run_guard']='Exact preflight next build number, forced manual, immutable checkout, rerun flags blocked; operator must not dispatch twice'
        ctx.receipt['authorization']={'approval_receipt_sha256':a['approval_receipt_sha256'],'verified_utc':a['verified_utc']}
        sha=git(ctx,workspace,['rev-parse','HEAD'],'driver-head')
        need(sha==os.environ['APPVEYOR_REPO_COMMIT'],'Driver checkout mismatch')
        root=Path(os.environ['SystemDrive']+'/')/('faf-fresh-'+os.environ['APPVEYOR_BUILD_ID'])
        need(not root.exists() and shutil.disk_usage(root.parent).free>=11*1024**3,'Fresh isolated root / 11GiB free required')
        root.mkdir(); ctx.root=root
        inputs=json.loads((HERE/'inputs.json').read_text())
        t=toolchain.provision(ctx)
        src=source(ctx,inputs)
        dx=dependencies(ctx,src,t,inputs)
        b=build_and_test(ctx,src,t,dx,inputs)
        from packaging_gate import create_package
        product=create_package(ctx,src,b,t,inputs,json.loads((HERE/'materials.json').read_text()))
        zip_path=Path(product); need(zip_path.is_file() and zip_path.stat().st_size<=PRODUCT_LIMIT,'Product missing/too large')
        out=ctx.out/'product'; out.mkdir(); shutil.copyfile(zip_path,out/'faf-re-x64-native-candidate.zip')
        ctx.receipt['product']={'sha256':digest(zip_path),'bytes':zip_path.stat().st_size,'acceptance':'NATIVE_GATES_ONLY_GAME_AND_REPLAYS_NOT_RUN'}
        ctx.save(); diagnostics(ctx)
        ctx.remaining(60)
        ctx.receipt['product_ready']=True; ctx.save()
        print('Native build gates passed. Game/replay acceptance NOT_RUN.'); return 0
    except Exception as e:
        ctx.receipt['status']='BLOCKED'; ctx.receipt['product_ready']=False; ctx.receipt['blocker']=str(e); ctx.save()
        try: diagnostics(ctx)
        except Exception as d: print('Diagnostic preparation blocked: '+str(d))
        print('BLOCKED: '+str(e)); return 1
    # No cleanup of SDK junctions or user paths. Ephemeral runner teardown owns disposal.

if __name__=='__main__': raise SystemExit(main())
