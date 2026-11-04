from pathlib import Path
import sys,json,unittest,tempfile
from unittest.mock import patch,Mock
CI=Path(__file__).resolve().parents[1];sys.path.insert(0,str(CI))
import single_driver as single
import driver as core

class SingleTests(unittest.TestCase):
    def make(self):return single.SingleBuild(CI,json.loads((CI/'execution-single.json').read_text()))
    def test_inert_contract(self):
        c=self.make().c
        self.assertEqual(c['state'],'DRAFT_NOT_AUTHORIZED');self.assertIsNone(c['root_go_reference'])
        self.assertFalse(c['upload_exact_package']);self.assertNotIn('checkpoint_transport',c)
    def test_single_config_has_no_cache_or_finalize_enable(self):
        y=(CI.parent/'appveyor-single.yml').read_text();ps=(CI/'run-single-build.ps1').read_text()
        self.assertNotIn('\ncache:',y);self.assertIn('run-single-build.ps1',y)
        self.assertNotIn("APPVEYOR_SKIP_FINALIZE_ON_EXIT = 'false'",ps)
        self.assertNotIn('cache_ready',ps);self.assertNotIn('$Stage',ps)
    def test_run_order_no_transfer(self):
        b=self.make();seen=[]
        names=['validate_contract','verify_configuration_checkout','start_workspace','windows_cleanup_fixture',
               'tools_and_runtime','source_assembly','configure','capture_before','compile_and_test','check_after',
               'stage_package','clean_before_upload','upload']
        for name in names:
            callback=Mock(side_effect=lambda n=name:seen.append(n));callback.__name__=name;setattr(b,name,callback)
        for name in ['stage_a','stage_b','prepare_materials','cache_precompile_tests','stage_native_cache','commit_native_cache','checkpoint_policy']:
            setattr(b,name,Mock(side_effect=AssertionError('Transfer path must not run')))
        self.assertEqual(b.run(),0);self.assertEqual(seen,names);self.assertEqual(seen.count('configure'),1)
    def test_failure_never_uploads(self):
        b=self.make();b.validate_contract=Mock(side_effect=core.Blocked('fixture'));b.validate_contract.__name__='validate_contract';b.upload=Mock();b.upload.__name__='upload'
        self.assertEqual(b.run(),1);b.upload.assert_not_called()
    def test_fourth_ctest_failure_prevents_package_and_upload(self):
        b=self.make();b.root=Path('/tmp');b.build=Path('/tmp/build');b.ctest=Path('/tmp/ctest')
        b.receipt['ctest_executed']=['math_dump','sim_math','lua_coroutine']
        b.command=Mock(side_effect=['{}',core.Blocked('fourth CTest timeout')])
        for name in ['validate_contract','verify_configuration_checkout','start_workspace','windows_cleanup_fixture','tools_and_runtime','source_assembly','configure','capture_before','check_after','stage_package','clean_before_upload','upload']:
            callback=Mock();callback.__name__=name;setattr(b,name,callback)
        with patch.object(core.Build,'compile_and_test'),patch.object(single.shared,'single_test'):
            self.assertEqual(b.run(),1)
        b.stage_package.assert_not_called();b.upload.assert_not_called()
    def test_source_drift_prevents_package_and_upload(self):
        b=self.make()
        for name in ['validate_contract','verify_configuration_checkout','start_workspace','windows_cleanup_fixture','tools_and_runtime','source_assembly','configure','capture_before','compile_and_test','check_after','stage_package','clean_before_upload','upload']:
            callback=Mock();callback.__name__=name;setattr(b,name,callback)
        b.check_after.side_effect=core.Blocked('source drift')
        self.assertEqual(b.run(),1);b.stage_package.assert_not_called();b.upload.assert_not_called()
    def test_core_five_targets_unchanged(self):
        self.assertEqual(core.REQUIRED_TARGETS,['faf_main','faf_sim_math_tests','faf_math_dump','faf_coroutine_tests','faf_effect_scan_tests'])
    def test_fourth_ctest_and_cap(self):
        b=self.make();b.root=Path('/tmp');b.build=Path('/tmp/build');b.ctest=Path('/tmp/ctest')
        b.receipt['ctest_executed']=['math_dump','sim_math','lua_coroutine']
        b.command=Mock(side_effect=['{}',''])
        with patch.object(core.Build,'compile_and_test') as compile,patch.object(single.shared,'single_test'),patch.object(core,'validate_junit'):
            b.compile_and_test()
        compile.assert_called_once();self.assertEqual(b.command.call_args.kwargs['cap'],210)
        self.assertEqual(sorted(b.receipt['ctest_executed']),['effect_scan','lua_coroutine','math_dump','sim_math'])
    def test_upload_requires_four_tests_and_cleanup(self):
        b=self.make();b.receipt['owned_cleanup_before_upload']='VERIFIED_ONLY_EXACT_ARTIFACT_REMAINS'
        b.receipt['ctest_executed']=['math_dump','sim_math','lua_coroutine'];b.command=Mock()
        with self.assertRaises(core.Blocked):b.upload()
        b.command.assert_not_called()
    def test_command_uses_controlled_environment(self):
        b=self.make();b.child_env={'FIXTURE':'public'}
        with patch.object(core.Build,'command',return_value='ok') as call:
            self.assertEqual(b.command(['x']), 'ok')
        self.assertEqual(call.call_args.args[4],b.child_env)
    def test_upload_short_window_never_launches(self):
        b=self.make();b.receipt.update(owned_cleanup_before_upload='VERIFIED_ONLY_EXACT_ARTIFACT_REMAINS',ctest_executed=['math_dump','sim_math','lua_coroutine','effect_scan'])
        b.remaining=Mock(return_value=389);b.command=Mock()
        with self.assertRaises(core.Blocked):b.upload()
        b.command.assert_not_called()
    def test_child_failure_marks_uncertain(self):
        b=self.make()
        with patch.object(core.Build,'command',side_effect=core.Blocked('x')):
            with self.assertRaises(core.Blocked):b.command(['x'])
        self.assertTrue(b.child_uncertain)
    def test_dynamic_compile_budget_streamed(self):
        b=self.make();b.remaining=Mock(return_value=1000)
        with tempfile.TemporaryDirectory() as td:
            b.root=Path(td);b.build=b.root/'build';(b.root/'logs').mkdir();(b.root/'logs/build.txt').write_text('fixture')
            with patch.object(single.build_capture,'run_build',return_value={'state':'SUCCESS'}) as run,patch.object(single.build_capture,'ninja_summary',return_value={}),patch.object(single.shared,'validate_effect_link',return_value={}):
                b.command(['cmake','--build'],name='build',cap=2700)
            self.assertEqual(run.call_args.kwargs['timeout'],610)
    def test_exhausted_build_window_never_launches(self):
        b=self.make();b.remaining=Mock(return_value=390)
        with patch.object(single.build_capture,'run_build') as run:
            with self.assertRaises(core.Blocked):b.command(['cmake'],name='build')
        run.assert_not_called()

if __name__=='__main__':unittest.main()
