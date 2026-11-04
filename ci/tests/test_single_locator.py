from pathlib import Path
import sys,json,unittest,os
from unittest.mock import patch,Mock
CI=Path(__file__).resolve().parents[1];sys.path.insert(0,str(CI))
import single_driver as single
import driver as core

class LocatorTests(unittest.TestCase):
    def make(self):return single.SingleBuild(CI,json.loads((CI/'execution-single.json').read_text()))
    def result(self,text,*,directory=True,missing=None):
        b=self.make()
        def present(p):return not missing or p.name != missing+'.exe'
        with patch.object(core.Build,'command',return_value=text),patch.object(Path,'is_dir',return_value=directory),patch.object(Path,'is_file',present):
            return b.command(['vswhere.exe'],name='vswhere')
    def test_pass(self):self.assertEqual(self.result('C:\\Program Files\\Microsoft Visual Studio\\2022\\Community'), 'C:\\Program Files\\Microsoft Visual Studio\\2022\\Community')
    def test_empty(self):
        with self.assertRaisesRegex(core.Blocked,'exactly one'):self.result('')
    def test_multiline(self):
        with self.assertRaisesRegex(core.Blocked,'exactly one'):self.result('C:\\VS1\nC:\\VS2')
    def test_relative(self):
        for value in ['VS2022','C:VS2022',r'\\server\share\VS']:
            with self.subTest(value=value),self.assertRaisesRegex(core.Blocked,'absolute local'):self.result(value)
    def test_missing_directory(self):
        with self.assertRaisesRegex(core.Blocked,'directory missing'):self.result(r'C:\VS',directory=False)
    def test_each_missing_tool(self):
        for name in single.VS_TOOL_MEMBERS:
            with self.subTest(name=name),self.assertRaisesRegex(core.Blocked,'missing: '+name):self.result(r'C:\VS',missing=name)
    def test_locator_only_whitelist_no_secret_or_compiler_leak(self):
        b=self.make();b.child_env={'SYSTEMROOT':r'C:\Windows','PATH':'fixed','TEMP':'owned','TMP':'owned'};before=dict(b.child_env)
        worker={key:r'C:\fixture' for key in single.VS_LOCATOR_KEYS};worker.update(SECRET_TOKEN='private',USERPROFILE='private',CL='private',INCLUDE='private',LIB='private',ALLUSERSPROFILE='not-required',ProgramFiles='not-required',ProgramW6432='not-required');worker['ProgramFiles(x86)']='not-required'
        with patch.dict(os.environ,worker,clear=True),patch.object(core.Build,'command',return_value=r'C:\VS') as command,patch.object(Path,'is_dir',return_value=True),patch.object(Path,'is_file',return_value=True):
            b.command(['vswhere.exe'],name='vswhere');vsenv=command.call_args.args[4]
            b.command(['cmake.exe'],name='configure');buildenv=command.call_args.args[4]
        self.assertEqual(vsenv,{**before,**{k:worker[k] for k in single.VS_LOCATOR_KEYS}})
        self.assertEqual(buildenv,before);self.assertEqual(b.child_env,before)
    def test_nonzero_fails_before_locator_validation(self):
        b=self.make()
        with patch.object(core.Build,'command',side_effect=core.Blocked('Child failed: vswhere')),patch.object(single,'validate_vswhere_result') as validate:
            with self.assertRaises(core.Blocked):b.command(['vswhere'],name='vswhere')
        validate.assert_not_called();self.assertTrue(b.child_uncertain)
    def test_tools_flow_empty_output_stops_before_version_or_download(self):
        b=self.make();b.command=single.SingleBuild.command.__get__(b)
        with patch.dict(os.environ,{'ProgramFiles(x86)':r'C:\Program Files (x86)'},clear=False),patch.object(Path,'is_file',return_value=True),patch.object(core.Build,'command',return_value='') as command,patch.object(b,'provision_ucrt') as provision:
            with self.assertRaisesRegex(core.Blocked,'exactly one'):core.Build.tools_and_runtime(b)
        self.assertEqual(command.call_count,1);provision.assert_not_called()
    def test_tools_flow_valid_locator_reaches_exact_version_check(self):
        b=self.make()
        with patch.dict(os.environ,{'ProgramFiles(x86)':r'C:\Program Files (x86)'},clear=False),patch.object(Path,'is_file',return_value=True),patch.object(Path,'is_dir',return_value=True),patch.object(core.Build,'command',side_effect=[r'C:\VS','cmake version WRONG']) as command,patch.object(b,'provision_ucrt') as provision:
            with self.assertRaisesRegex(core.Blocked,'Unexpected CMake'):core.Build.tools_and_runtime(b)
        self.assertEqual(command.call_count,2);self.assertEqual(command.call_args.args[5],'cmake-version');provision.assert_not_called()
if __name__=='__main__':unittest.main()
