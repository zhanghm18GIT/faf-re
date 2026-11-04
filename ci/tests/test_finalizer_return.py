"""Entrypoint tail regression; optional local PowerShell is a stub, not provider proof."""
from pathlib import Path
import shutil,subprocess,tempfile,unittest
CI=Path(__file__).resolve().parents[1]
ENTRIES=('run-client-build.ps1','run-single-build.ps1','run-resume-build.ps1','run-artifact-build.ps1')
class FinalizerReturnTests(unittest.TestCase):
 def test_every_entry_finishes_at_success_command(self):
  for name in ENTRIES:
   with self.subTest(entry=name):
    lines=[x.strip() for x in (CI/name).read_text().splitlines() if x.strip() and not x.lstrip().startswith('#')]
    self.assertEqual(lines[-1],'Exit-AppveyorBuild')
    self.assertEqual(lines.count('Exit-AppveyorBuild'),1)
    self.assertNotIn('returned unexpectedly',(CI/name).read_text())
 def test_failed_driver_still_throws_before_finalizer(self):
  for name in ENTRIES:
   with self.subTest(entry=name):
    s=(CI/name).read_text();self.assertIn('if ($LASTEXITCODE -ne 0) { throw "Bounded RE driver failed',s)
    self.assertLess(s.index('if ($LASTEXITCODE -ne 0) { throw "Bounded RE driver failed'),s.index('\nExit-AppveyorBuild'))
 def test_cache_readiness_still_precedes_save_enable(self):
  for name,ready in [('run-client-build.ps1','cache_ready.py'),('run-resume-build.ps1','resume_ready.py')]:
   with self.subTest(entry=name):
    s=(CI/name).read_text();gate=s.index(ready);save=s.index("$env:APPVEYOR_CACHE_SKIP_SAVE = 'false'")
    self.assertLess(gate,save);self.assertIn('if ($LASTEXITCODE -ne 0) { throw',s[gate:save])
    self.assertLess(save,s.index("$env:APPVEYOR_SKIP_FINALIZE_ON_EXIT = 'false'"));self.assertLess(save,s.index('\nExit-AppveyorBuild'))
 def test_single_does_not_enable_provider_finalizers(self):
  s=(CI/'run-single-build.ps1').read_text();self.assertNotIn("$env:APPVEYOR_SKIP_FINALIZE_ON_EXIT = 'false'",s)
 @unittest.skipUnless(shutil.which('pwsh') or shutil.which('powershell'),'PowerShell not installed locally')
 def test_actual_powershell_tail_accepts_normal_return_and_propagates_throw(self):
  shell=shutil.which('pwsh') or shutil.which('powershell')
  for name in ENTRIES:
   s=(CI/name).read_text();tail=s[s.rindex('\nExit-AppveyorBuild')+1:]
   for body,success in [('return',True),("throw 'provider failure fixture'",False)]:
    with self.subTest(entry=name,success=success),tempfile.TemporaryDirectory() as tmp:
     path=Path(tmp)/'tail.ps1';path.write_text("$ErrorActionPreference = 'Stop'\nfunction Exit-AppveyorBuild { "+body+" }\n"+tail)
     result=subprocess.run([shell,'-NoProfile','-NonInteractive','-File',str(path)],capture_output=True,timeout=20)
     self.assertEqual(result.returncode==0,success)
if __name__=='__main__':unittest.main()
