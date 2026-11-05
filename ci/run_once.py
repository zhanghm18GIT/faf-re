"""AppVeyor-only supervisor; import is inert. Never dispatches or changes settings.

50 minutes of worker work; termination starts at 51.5 to finish by minute 52.
All finalization/uploads end
by minute 55 from the init timestamp. Platform timeout remains 60 minutes.
"""
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile
from driver import authorize, verify_driver, PRODUCT_LIMIT, DIAGNOSTICS_LIMIT
from native_checks import need, digest
from check_install import GATES
from windows_job import WindowsJob

HERE=Path(__file__).resolve().parent

class Deadline:
    def __init__(self, started, now=None, monotonic=None):
        now=now or dt.datetime.now(dt.timezone.utc)
        age=(now-started).total_seconds()
        need(0<=age<50*60,'Init timestamp missing/future/expired')
        self.origin=(time.monotonic() if monotonic is None else monotonic)-age
    def left(self, minute, cap, now=None):
        left=self.origin+minute*60-(time.monotonic() if now is None else now)
        need(left>0,'Supervisor deadline reached')
        return min(left,cap)

def run_bounded(args, log_path, timeout, env=None, cwd=None):
    """Contain every descendant before command spawn; verify an empty job."""
    job=WindowsJob(); p=None
    child_env=(os.environ if env is None else env).copy();child_env['FAF_SUPERVISOR_JOB']=job.name
    result={'exit_code':None,'timed_out':False,'tree_stopped':False,'orphaned_descendants':False}
    try:
        with Path(log_path).open('xb') as log:
            p=subprocess.Popen([sys.executable,'-B',str(HERE/'join_job.py'),*[str(x) for x in args]],stdout=log,stderr=subprocess.STDOUT,env=child_env,cwd=cwd)
            try:result['exit_code']=p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                result['timed_out']=True
                result['tree_stopped']=job.terminate()
                # The tiny wrapper may have stalled before joining; it cannot
                # spawn the real command before successful assignment.
                if p.poll() is None:p.kill()
                p.wait(timeout=5)
                result['exit_code']=p.returncode
                result['tree_stopped']=result['tree_stopped'] and job.active()==0
                return result
            if job.active()!=0:
                result['orphaned_descendants']=True
                result['tree_stopped']=job.terminate()
                result['exit_code']=1
            else:result['tree_stopped']=True
            return result
    except Exception as exc:
        result['containment_error']=str(exc)
        try:
            result['tree_stopped']=job.terminate()
            if p is not None and p.poll() is None:p.kill();p.wait(timeout=5)
        except Exception:result['tree_stopped']=False
        result['exit_code']=1
        return result
    finally:
        try:job.close()
        except Exception as exc:result.update(tree_stopped=False,exit_code=1,containment_error=str(exc))


class ContainmentUncertain(RuntimeError):
    pass

def containment_selftest(workspace,control,budget,env):
    fixtures=[('normal',"print('contained')",5),('timeout','import time; time.sleep(20)',0.2),
              ('orphan',"import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'])",5)]
    results={}
    for name,code,cap in fixtures:
        results[name]=run_bounded([sys.executable,'-c',code],control/('containment-'+name+'.log'),budget.left(50,cap),env,workspace)
        if results[name].get('tree_stopped') is not True:
            try:(control/'containment.json').write_text(json.dumps(results,indent=2)+'\n')
            finally:raise ContainmentUncertain('Native containment '+name+' fixture tree termination uncertain')
        (control/'containment.json').write_text(json.dumps(results,indent=2)+'\n')
    need(success_result(results['normal']),'Native containment normal fixture failed')
    need(results['timeout']['timed_out'] and results['timeout']['tree_stopped'],'Native containment timeout fixture failed')
    need(results['orphan']['orphaned_descendants'] and results['orphan']['tree_stopped'],'Native containment orphan fixture failed')
    (control/'containment.json').write_text(json.dumps(results,indent=2)+'\n')
    return results

def success_result(result):
    return result.get('exit_code')==0 and result.get('timed_out') is False and result.get('tree_stopped') is True and result.get('orphaned_descendants',False) is False

def minimal_diagnostics(workspace,result):
    """Small fallback first. A finalizer timeout cannot erase this finished ZIP."""
    out=workspace/'ci-results';out.mkdir(exist_ok=True)
    receipt=out/'RECEIPT.json'
    try: data=json.loads(receipt.read_text()) if receipt.is_file() else {}
    except (OSError,ValueError): data={}
    data['supervisor']=result
    if not success_result(result):
        data.update(status='BLOCKED_BY_SUPERVISOR',product_ready=False)
    data.setdefault('native_gates','NOT_RUN');data.setdefault('in_game','NOT_RUN');data.setdefault('replays','NOT_RUN')
    receipt.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')
    logs=out/'raw-logs';logs.mkdir(exist_ok=True)
    (logs/'supervisor.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    folder=out/'diagnostics';folder.mkdir(exist_ok=True)
    tmp=out/'minimal-diagnostics.pending.zip'
    with zipfile.ZipFile(tmp,'w',zipfile.ZIP_DEFLATED) as z:
        z.write(receipt,'RECEIPT.json')
        for name in ['offline-tests.log','worker.log','containment.json']:
            log=workspace/'ci-control'/name
            if log.is_file() and not log.is_symlink():
                with log.open('rb') as f:
                    f.seek(max(0,log.stat().st_size-65536));z.writestr('control/'+name+'.tail',f.read(65536))
        z.writestr('DIAGNOSTIC_LIMIT.txt','Minimal fallback. Full logs may be unavailable after watchdog termination.\n')
    need(tmp.stat().st_size<=DIAGNOSTICS_LIMIT,'Minimal diagnostics too large')
    os.replace(tmp,folder/'diagnostics.zip')
    return data

def upload_candidates(workspace,result):
    """Product requires successful process AND final, intact native product."""
    out=workspace/'ci-results'
    diag=out/'diagnostics/diagnostics.zip'
    need(diag.is_file() and not diag.is_symlink() and diag.stat().st_size<=DIAGNOSTICS_LIMIT,'Diagnostics missing/out of bounds')
    answer=[diag]
    data=json.loads((out/'RECEIPT.json').read_text())
    if not success_result(result): return answer
    need(data.get('status')=='BUILT_NATIVE_GATES_PASS_GAME_NOT_RUN' and data.get('product_ready') is True,'No final product-ready state')
    need(data.get('native_gates')=='PASS' and set(data.get('native_checks',{}))==GATES and all(x=='PASS' for x in data['native_checks'].values()),'Native gate set incomplete')
    need(data.get('in_game')=='NOT_RUN' and data.get('replays')=='NOT_RUN','Game/replay boundary changed')
    product=out/'product/faf-re-x64-native-candidate.zip'
    need(product.is_file() and not product.is_symlink() and product.stat().st_size<=PRODUCT_LIMIT,'Product missing/out of bounds')
    pin=data.get('product',{})
    need(product.stat().st_size==pin.get('bytes') and digest(product)==pin.get('sha256'),'Product changed after readiness')
    answer.append(product)
    return answer

def main():
    need(os.name=='nt' and sys.maxsize>2**32 and sys.version_info>=(3,11),'64-bit Windows/Python >=3.11 required')
    workspace=Path(os.environ['APPVEYOR_BUILD_FOLDER']).resolve()
    a=json.loads((HERE/'authorization.json').read_text())
    authorize(a,os.environ,dt.datetime.now(dt.timezone.utc));verify_driver(workspace)
    started=dt.datetime.fromisoformat(os.environ['FAF_JOB_STARTED_UTC'].replace('Z','+00:00'))
    budget=Deadline(started)
    control=workspace/'ci-control';need(not control.exists() and not (workspace/'ci-results').exists(),'No stale/repeated invocation')
    control.mkdir()
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env['GIT_TERMINAL_PROMPT']='0'
    result={'exit_code':1,'timed_out':False,'tree_stopped':True,'phase':'pre_worker'}
    try:
        containment_selftest(workspace,control,budget,env)
        result=run_bounded([sys.executable,'-B','-m','unittest','discover','-s',HERE/'tests','-v'],control/'offline-tests.log',budget.left(50,120),env,workspace)
        result['phase']='offline_safety_tests'
        if success_result(result):
            result=run_bounded([sys.executable,'-B',HERE/'driver.py'],control/'worker.log',budget.left(51.5,51.5*60),env,workspace)
            result['phase']='native_worker'
    except Exception as exc:
        result.update(exit_code=1,blocker=str(exc))
        if isinstance(exc,ContainmentUncertain):result['tree_stopped']=False
    if result.get('tree_stopped') is not True:
        print('BLOCKED: child tree termination uncertain; platform teardown required; no finalization, uploads or retry.');return 1
    minimal_diagnostics(workspace,result)
    try:
        final=run_bounded([sys.executable,'-B',HERE/'finalize.py'],control/'finalize.log',budget.left(54.5,75),env,workspace)
        if final.get('tree_stopped') is not True:
            print('BLOCKED: finalizer process tree termination uncertain; no uploads.');return 1
        if not success_result(final):
            result.update(exit_code=1,finalization='FAILED_OR_TIMED_OUT')
            minimal_diagnostics(workspace,result)
            print('Full diagnostics failed; only minimal failure diagnostics eligible.')
    except Exception as exc:
        result.update(exit_code=1,finalization_error=str(exc));minimal_diagnostics(workspace,result)
        print('Finalization incomplete: '+str(exc))
    # These are the only external writes the supervisor can perform. The
    # current explicit grant is checked before work and no secret is logged.
    cli=shutil.which('appveyor.exe') or shutil.which('appveyor')
    need(cli,'Installed AppVeyor CLI absent; artifacts remain unuploaded')
    try: candidates=upload_candidates(workspace,result)
    except Exception as exc:
        result.update(exit_code=1,product_blocker=str(exc))
        minimal_diagnostics(workspace,result)
        candidates=upload_candidates(workspace,result)
    complete=True
    for index,path in enumerate(candidates):
        try:
            upload=run_bounded([cli,'PushArtifact',path],control/('upload-'+str(index)+'.log'),budget.left(54.5,60),env,workspace)
            complete=complete and success_result(upload)
            if not success_result(upload): print('Artifact upload failed or uncertain; not retried: '+path.name)
            if upload.get('tree_stopped') is not True:break
        except Exception as exc:
            complete=False;print('Artifact upload blocked, not retried: '+path.name+': '+str(exc))
            break
    print('Artifact upload attempts finished. Public retrieval/delivery and settings restoration require separate verification.')
    return 0 if complete and success_result(result) else 1

if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as exc: print('BLOCKED BEFORE AUTHORIZED WORK: '+str(exc));raise SystemExit(1)
