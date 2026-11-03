import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from command_admission import validate,AdmissionError
class Commands(unittest.TestCase):
 def setUp(self):
  self.kw=dict(compiler='C:/tools/clang-cl.exe',cwd='C:/work/build',source='C:/work/source/a.c',output='C:/work/build/a.obj',read_roots=['C:/work/source','C:/tools','C:/sdk'],write_root='C:/work/build',sysroots={'/vctoolsdir':'C:/tools','/winsdkdir':'C:/sdk','/winsdkversion':'10.0.26100.0'})
  self.a=['C:/tools/clang-cl.exe','/vctoolsdir:C:/tools','/winsdkdir:C:/sdk','/winsdkversion:10.0.26100.0','/nologo','/O2','/Z7','/DWIN32','/IC:/work/source','/FoC:/work/build/a.obj','/c','C:/work/source/a.c']
 def test_valid(self):validate(self.a,**self.kw)
 def test_reviewed_wx_diagnostic(self):validate(self.a+['-Wno-c++11-narrowing','-Wno-overriding-option'],**self.kw)
 def test_reviewed_standard_spellings(self):
  for option in ['-TC','-TP','-std:c++14','-std:c++17','-std:c++20','-std:c11','-std:c17']:
   validate(self.a+[option],**self.kw)
 def test_cmake_terminal_source_and_target(self):
  validate(self.a[:-1]+['--',self.a[-1]],**self.kw)
  validate(self.a+['--target=x86_64-pc-windows-msvc','-MT','-Z7'],**self.kw)
  for tail in [['--',self.a[-1],'/DNEW'],['--','C:/private/a.c'],['--','/c'],['--']]:
   with self.assertRaises(AdmissionError):validate(self.a[:-1]+tail,**self.kw)
 def test_negative_options(self):
  for x in ['@a.rsp','--config=x','-Xclang','-mllvm','/clang:-include','-fprofile-use=x','-fmodule-file=x','/FI C:/private/x','/FoC:/private/x','/unknown','C:/work/source/b.c']:
   with self.subTest(x=x),self.assertRaises(AdmissionError):validate(self.a+[x],**self.kw)
 def test_wrong_tu(self):
  with self.assertRaises(AdmissionError):validate(self.a[:-1]+['C:/work/source/b.c'],**self.kw)
 def test_missing_output(self):
  with self.assertRaises(AdmissionError):validate([x for x in self.a if not x.startswith('/Fo')],**self.kw)
 def test_double_output(self):
  with self.assertRaises(AdmissionError):validate(self.a+['/FoC:/work/build/a.obj'],**self.kw)
 def test_private_include(self):
  with self.assertRaises(AdmissionError):validate(self.a+['/IC:/private'],**self.kw)
 def test_ads_and_unc(self):
  for p in ['C:/work/source/a.c:stream','//server/share/a.c']:
   with self.assertRaises(AdmissionError):validate(self.a[:-1]+[p],**self.kw)
if __name__=='__main__':unittest.main()
