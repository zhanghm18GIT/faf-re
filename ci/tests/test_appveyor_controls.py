import copy
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch,Mock
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import driver
import run_once as r
from native_checks import GateError,digest
from check_install import GATES

class Authorization(unittest.TestCase):
    def setUp(self):
        self.now=dt.datetime(2026,11,5,8,tzinfo=dt.timezone.utc)
        self.a=json.loads((Path(__file__).resolve().parents[1]/'authorization.json').read_text())
        self.a.update(state='AUTHORIZED_FOR_ONE_REVIEWED_RUN',approval_receipt_sha256='a'*64,
                      grants=dict.fromkeys(driver.GRANTS,True),expected_build_number=28,verified_utc=self.now.isoformat())
        self.env={'APPVEYOR':'True','APPVEYOR_ACCOUNT_NAME':self.a['account'],'APPVEYOR_PROJECT_SLUG':self.a['project_slug'],
                  'APPVEYOR_REPO_NAME':self.a['repository'],'APPVEYOR_REPO_BRANCH':self.a['branch'],
                  'APPVEYOR_BUILD_WORKER_IMAGE':self.a['runner'],'APPVEYOR_FORCED_BUILD':'True',
                  'APPVEYOR_BUILD_NUMBER':'28','APPVEYOR_BUILD_VERSION':'fresh-native.28',
                  'APPVEYOR_CACHE_SKIP_RESTORE':'true','APPVEYOR_CACHE_SKIP_SAVE':'true',
                  'APPVEYOR_REPO_COMMIT':'b'*40,'APPVEYOR_BUILD_ID':'55000001','APPVEYOR_JOB_ID':'fixture01',
                  'FAF_JOB_STARTED_UTC':self.now.isoformat()}
    def test_allow_fixture_only(self):driver.authorize(self.a,self.env,self.now)
    def test_draft_rejected(self):
        with self.assertRaises(GateError):driver.authorize({**self.a,'state':'DRAFT_NOT_AUTHORIZED'},self.env,self.now)
    def test_each_grant_required(self):
        for k in driver.GRANTS:
            a=copy.deepcopy(self.a);a['grants'][k]=False
            with self.subTest(k=k),self.assertRaises(GateError):driver.authorize(a,self.env,self.now)
    def test_each_context_required(self):
        for k in self.env:
            with self.subTest(k=k),self.assertRaises((GateError,ValueError)):driver.authorize(self.a,{**self.env,k:'!invalid!'},self.now)
    def test_reruns_tags_schedule_rejected(self):
        for k in ['APPVEYOR_RE_BUILD','APPVEYOR_RE_RUN_INCOMPLETE','APPVEYOR_SCHEDULED_BUILD','APPVEYOR_REPO_TAG']:
            with self.subTest(k=k),self.assertRaises(GateError):driver.authorize(self.a,{**self.env,k:'True'},self.now)
    def test_pr_rejected(self):
        with self.assertRaises(GateError):driver.authorize(self.a,{**self.env,'APPVEYOR_PULL_REQUEST_NUMBER':'1'},self.now)
    def test_duplicate_build_number_rejected(self):
        with self.assertRaises(GateError):driver.authorize(self.a,{**self.env,'APPVEYOR_BUILD_NUMBER':'29'},self.now)
    def test_preflight_expiry(self):
        with self.assertRaises(GateError):driver.authorize(self.a,self.env,self.now+dt.timedelta(hours=2))
    def test_plan_and_bounds(self):
        for k,v in [('plan','Pro'),('paid_budget_usd',1),('max_attempts',2),('max_job_minutes',61),('work_deadline_minutes',51),('watchdog_minutes',54),('finalize_deadline_minutes',60),('repository_visibility','private'),('expected_build_number',None)]:
            with self.subTest(k=k),self.assertRaises(GateError):driver.authorize({**self.a,k:v},self.env,self.now)
    def test_approval_digest_required(self):
        with self.assertRaises(GateError):driver.authorize({**self.a,'approval_receipt_sha256':None},self.env,self.now)

class Supervisor(unittest.TestCase):
    def test_deadline_includes_clone_time(self):
        now=dt.datetime(2026,11,5,8,tzinfo=dt.timezone.utc)
        d=r.Deadline(now-dt.timedelta(minutes=2),now,1000)
        self.assertEqual(d.left(52,9999,1000),50*60)
        self.assertEqual(d.left(55,60,1000),60)
        with self.assertRaises(GateError):d.left(52,60,4000)
    def test_invalid_start(self):
        now=dt.datetime.now(dt.timezone.utc)
        for delta in [-1,50*60]:
            with self.subTest(delta=delta),self.assertRaises(GateError):r.Deadline(now-dt.timedelta(seconds=delta),now,0)
    def fake_job(self,active=0,terminate=True):
        job=Mock();job.name='Local\\faf-fresh-fixture';job.active.return_value=active;job.terminate.return_value=terminate
        return job
    def test_process_timeout_tree_kill(self):
        p=Mock();p.returncode=1;p.wait.side_effect=[subprocess.TimeoutExpired('x',1),1]
        job=self.fake_job()
        with tempfile.TemporaryDirectory() as d,patch.object(r,'WindowsJob',return_value=job),patch.object(r.subprocess,'Popen',return_value=p):
            result=r.run_bounded(['fixture'],Path(d)/'log',1)
            self.assertTrue(result['timed_out']);self.assertFalse(r.success_result(result));job.terminate.assert_called_once()
            self.assertTrue(result['tree_stopped']);job.close.assert_called_once()
    def test_uncertain_kill_not_success(self):
        p=Mock();p.returncode=1;p.wait.side_effect=[subprocess.TimeoutExpired('x',1),1]
        job=self.fake_job(terminate=False)
        with tempfile.TemporaryDirectory() as d,patch.object(r,'WindowsJob',return_value=job),patch.object(r.subprocess,'Popen',return_value=p):
            self.assertFalse(r.run_bounded(['fixture'],Path(d)/'log',1)['tree_stopped'])
    def test_exited_parent_with_descendants_is_failure(self):
        p=Mock();p.wait.return_value=0;job=self.fake_job(active=1)
        with tempfile.TemporaryDirectory() as d,patch.object(r,'WindowsJob',return_value=job),patch.object(r.subprocess,'Popen',return_value=p):
            result=r.run_bounded(['fixture'],Path(d)/'log',1)
            self.assertTrue(result['orphaned_descendants']);self.assertFalse(r.success_result(result));job.terminate.assert_called_once()
    def test_containment_query_failure_never_success(self):
        p=Mock();p.wait.return_value=0;job=self.fake_job();job.active.side_effect=OSError('query failed')
        with tempfile.TemporaryDirectory() as d,patch.object(r,'WindowsJob',return_value=job),patch.object(r.subprocess,'Popen',return_value=p):
            result=r.run_bounded(['fixture'],Path(d)/'log',1)
            self.assertFalse(r.success_result(result));self.assertIn('containment_error',result)
    def test_child_command_starts_through_join_guard(self):
        p=Mock();p.wait.return_value=0;job=self.fake_job()
        with tempfile.TemporaryDirectory() as d,patch.object(r,'WindowsJob',return_value=job),patch.object(r.subprocess,'Popen',return_value=p) as popen:
            result=r.run_bounded(['fixture','arg'],Path(d)/'log',1,env={})
            self.assertTrue(r.success_result(result))
            self.assertEqual(Path(popen.call_args.args[0][2]).name,'join_job.py')
            self.assertEqual(popen.call_args.kwargs['env']['FAF_SUPERVISOR_JOB'],job.name)
    def fixture(self,root):
        out=root/'ci-results';(out/'product').mkdir(parents=True)
        prod=out/'product/faf-re-x64-native-candidate.zip';prod.write_bytes(b'fixture')
        data={'status':'BUILT_NATIVE_GATES_PASS_GAME_NOT_RUN','product_ready':True,'native_gates':'PASS','native_checks':dict.fromkeys(GATES,'PASS'),'in_game':'NOT_RUN','replays':'NOT_RUN','product':{'sha256':digest(prod),'bytes':prod.stat().st_size}}
        (out/'RECEIPT.json').write_text(json.dumps(data));return out,data
    def test_success_uploads_exact_two(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out,data=self.fixture(root);result={'exit_code':0,'timed_out':False,'tree_stopped':True}
            r.minimal_diagnostics(root,result);self.assertEqual(len(r.upload_candidates(root,result)),2)
    def test_timeout_cannot_upload_product(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out,data=self.fixture(root);result={'exit_code':0,'timed_out':True,'tree_stopped':True}
            r.minimal_diagnostics(root,result);self.assertEqual(len(r.upload_candidates(root,result)),1)
            self.assertFalse(json.loads((out/'RECEIPT.json').read_text())['product_ready'])
    def test_failed_exit_cannot_upload_product(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out,data=self.fixture(root);result={'exit_code':1,'timed_out':False,'tree_stopped':True}
            r.minimal_diagnostics(root,result);self.assertEqual(len(r.upload_candidates(root,result)),1)
    def test_product_changed_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out,data=self.fixture(root);result={'exit_code':0,'timed_out':False,'tree_stopped':True}
            r.minimal_diagnostics(root,result);(out/'product/faf-re-x64-native-candidate.zip').write_bytes(b'wrong')
            with self.assertRaises(GateError):r.upload_candidates(root,result)
    def test_missing_ready_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out,data=self.fixture(root);data['product_ready']=False;(out/'RECEIPT.json').write_text(json.dumps(data));result={'exit_code':0,'timed_out':False,'tree_stopped':True}
            r.minimal_diagnostics(root,result)
            with self.assertRaises(GateError):r.upload_candidates(root,result)
    def test_existing_output_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            driver.Context(Path(d))
            with self.assertRaises(GateError):driver.Context(Path(d))

if __name__=='__main__':unittest.main()

class FinalizerRegression(unittest.TestCase):
    fixture=Supervisor.fixture
    def execute_fixture(self,root,final):
        from types import SimpleNamespace
        now=dt.datetime.now(dt.timezone.utc).isoformat();calls=[]
        success={'exit_code':0,'timed_out':False,'tree_stopped':True}
        def run(args,log,*rest):
            calls.append(Path(log).name)
            if Path(log).name=='worker.log':self.fixture(root)
            if Path(log).name=='finalize.log':return dict(final)
            return dict(success)
        fakeos=SimpleNamespace(name='nt',environ={'APPVEYOR_BUILD_FOLDER':str(root),'FAF_JOB_STARTED_UTC':now},replace=os.replace)
        with patch.object(r,'os',fakeos),patch.object(r,'authorize'),patch.object(r,'verify_driver'),patch.object(r,'containment_selftest'),patch.object(r,'run_bounded',side_effect=run),patch.object(r.shutil,'which',return_value='appveyor.exe'):
            code=r.main()
        return code,calls
    def test_unknown_finalizer_stops_all_uploads(self):
        with tempfile.TemporaryDirectory() as d:
            code,calls=self.execute_fixture(Path(d),{'exit_code':0,'timed_out':True,'tree_stopped':False})
            self.assertEqual(code,1);self.assertFalse(any(x.startswith('upload') for x in calls))
    def test_known_failed_finalizer_only_diagnostics(self):
        with tempfile.TemporaryDirectory() as d:
            code,calls=self.execute_fixture(Path(d),{'exit_code':1,'timed_out':False,'tree_stopped':True})
            self.assertEqual(code,1);self.assertEqual([x for x in calls if x.startswith('upload')],['upload-0.log'])

class SelftestContainmentRegression(unittest.TestCase):
    def test_unknown_fixture_stops_next_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);control=root/'control';control.mkdir();budget=Mock();budget.left.return_value=5
            bad={'exit_code':1,'timed_out':True,'tree_stopped':False}
            with patch.object(r,'run_bounded',return_value=bad) as run:
                with self.assertRaises(r.ContainmentUncertain):r.containment_selftest(root,control,budget,{})
                self.assertEqual(run.call_count,1)
            self.assertEqual(set(json.loads((control/'containment.json').read_text())),{'normal'})
    def test_unknown_selftest_stops_all_later_phases(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);now=dt.datetime.now(dt.timezone.utc).isoformat()
            fakeos=SimpleNamespace(name='nt',environ={'APPVEYOR_BUILD_FOLDER':str(root),'FAF_JOB_STARTED_UTC':now},replace=os.replace)
            with patch.object(r,'os',fakeos),patch.object(r,'authorize'),patch.object(r,'verify_driver'),patch.object(r,'containment_selftest',side_effect=r.ContainmentUncertain('fixture')),patch.object(r,'run_bounded') as run,patch.object(r,'minimal_diagnostics') as minimal:
                self.assertEqual(r.main(),1);run.assert_not_called();minimal.assert_not_called()

    def test_unknown_fixture_report_error_still_uncertain(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);control=root/'control';control.mkdir();budget=Mock();budget.left.return_value=5
            bad={'exit_code':1,'timed_out':True,'tree_stopped':False}
            with patch.object(r,'run_bounded',return_value=bad) as run,patch.object(Path,'write_text',side_effect=OSError('disk failure')):
                with self.assertRaises(r.ContainmentUncertain):r.containment_selftest(root,control,budget,{})
                self.assertEqual(run.call_count,1)
