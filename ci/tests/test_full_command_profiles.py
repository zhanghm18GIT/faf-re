"""Full CMake-generated command profiles; no compiler or SDK needed.
Linux forced-identity generation is not lost Windows worker evidence.
"""
import hashlib,json,os,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import command_admission as a
import build_graph
P=Path(__file__).parent/'fixtures/command_profiles.json'
class Profiles(unittest.TestCase):
 def setUp(self):
  self.raw=P.read_bytes();self.data=json.loads(self.raw);self.rows=self.data['fixtures']
 def test_frozen_complete_fixture_identity(self):
  self.assertEqual(hashlib.sha256(self.raw).hexdigest(),'8581d3778a2ef09a2b583e78a1c4bd149202f08250d113e08834a07398ea6357');self.assertEqual(len(self.rows),4)
  for r in self.rows:
   self.assertGreater(len(r['argv']),100);self.assertEqual(set(r),{'profile','command','argv','policy','baseline_result'})
 def test_all_full_profiles(self):
  for r in self.rows:
   with self.subTest(profile=r['profile']):a.validate(r['argv'],**r['policy'])
 @unittest.skipUnless(os.name=='nt','Native Windows CommandLineToArgvW is worker-only')
 def test_native_windows_command_roundtrip(self):
  for r in self.rows:
   argv=build_graph.windows_argv(r['command']);self.assertEqual(argv,r['argv']);a.validate(argv,**r['policy'])
 def test_exact_ffmpeg_options_present(self):
  r=next(r for r in self.rows if 'ffmpeg/' in r['profile'])
  self.assertEqual(len(a.FFMPEG_PUBLIC_OPTIONS),26);self.assertTrue(a.FFMPEG_PUBLIC_OPTIONS<=set(r['argv']))
 def test_unknown_lookalikes_not_admitted(self):
  r=self.rows[0];at=r['argv'].index('--')
  for bad in ['-Wsecret-option','-wd9999','-O3','-utf-16','--target=aarch64-pc-windows-msvc','/clang:-load=private.dll']:
   argv=r['argv'][:at]+[bad]+r['argv'][at:]
   with self.subTest(bad=bad),self.assertRaises(a.AdmissionError):a.validate(argv,**r['policy'])
 def test_bare_fd_does_not_consume_compile_action(self):
  for r in self.rows:
   self.assertIn('/Fd',r['argv']);a.validate(r['argv'],**r['policy'])
   argv=[x for x in r['argv'] if x not in ('/c','-c')]
   with self.assertRaises(a.AdmissionError):a.validate(argv,**r['policy'])
 def test_bare_fd_never_consumes_next_token(self):
  r=self.rows[0];at=r['argv'].index('/Fd')
  for extra in ['C:/fixture/build/extra.pdb','C:/fixture/source/second.c']:
   argv=r['argv'][:at+1]+[extra]+r['argv'][at+1:]
   with self.assertRaises(a.AdmissionError):a.validate(argv,**r['policy'])
 def test_joined_fd_compiler_verified_variant(self):
  for r in self.rows:
   argv=['/FdC:/fixture/build/verified.pdb' if x=='/Fd' else x for x in r['argv']]
   a.validate(argv,**r['policy'])
 def test_bare_fo_cannot_claim_separate_output(self):
  r=self.rows[0];argv=[]
  for token in r['argv']:
   argv.extend(['/Fo',token[3:]] if token.startswith('/Fo') else [token])
  with self.assertRaises(a.AdmissionError):a.validate(argv,**r['policy'])
 def test_option_source_hash_rejects_modified_content(self):
  import tempfile
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'sources.cmake';p.write_bytes(b'synthetic altered public options')
   with self.assertRaises(a.AdmissionError):a.verify_public_option_source(p)
 def test_private_output_and_source_substitution(self):
  r=self.rows[0]
  for argv in [r['argv'][:-1]+['C:/private/data.c'],['/FoC:/private/output.obj' if x.startswith('/Fo') else x for x in r['argv']]]:
   with self.assertRaises(a.AdmissionError):a.validate(argv,**r['policy'])
 def test_redacted_rejection_diagnostics(self):
  r=self.rows[0];at=r['argv'].index('--');token='--private-option=synthetic-sensitive-value';argv=r['argv'][:at]+[token]+r['argv'][at:]
  with self.assertRaises(a.AdmissionError) as cm:a.validate(argv,**r['policy'])
  text=str(cm.exception);self.assertNotIn(token,text);self.assertNotIn('synthetic-sensitive-value',text);detail=json.loads(text)
  self.assertEqual(detail['argument_index'],at);self.assertEqual(detail['argument_sha256'],hashlib.sha256(token.encode()).hexdigest());self.assertEqual(detail['rule'],'unknown_argument')
 def test_option_not_consumed_as_include(self):
  r=self.rows[0];at=r['argv'].index('--');argv=r['argv'][:at]+['/I','-c']+r['argv'][at:]
  with self.assertRaises(a.AdmissionError):a.validate(argv,**r['policy'])
if __name__=='__main__':unittest.main()
