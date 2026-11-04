import ast,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import checkpoint as c
import exact_timestamp
class TimestampIntegration(unittest.TestCase):
 def test_unavailable_api_is_not_reported_as_observed_precision_loss(self):
  spec=c.FileSpec('build','synthetic.obj','obj')
  with self.assertRaises(c.CheckpointError) as caught:
   with c._member_guard('restore-payload',spec,{'operation':'timestamp'}):
    raise NotImplementedError('synthetic private detail')
  report=json.loads(str(caught.exception))
  self.assertEqual(report['timestamp_error_type'],'NotImplementedError');self.assertNotIn('private',str(caught.exception))
 def test_preflight_precedes_acquisition(self):
  tree=ast.parse((Path(__file__).resolve().parents[1]/'staged_driver.py').read_text())
  run=next(x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef) and x.name=='run')
  text=ast.unparse(run)
  self.assertLess(text.index('self.cache_precompile_tests()'),text.index('self.tools_and_runtime'))
 def test_preflight_does_not_inherit_provider_environment(self):
  tree=ast.parse((Path(__file__).resolve().parents[1]/'staged_driver.py').read_text())
  fn=next(x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef) and x.name=='cache_precompile_tests')
  assignment=next(x for x in ast.walk(fn) if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='probe_env' for t in x.targets))
  self.assertEqual({x.value for x in assignment.value.keys},{'SYSTEMROOT','WINDIR','COMSPEC','PATH','TEMP','TMP','PYTHONDONTWRITEBYTECODE'})
  command=next(x for x in ast.walk(fn) if isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr=='command')
  self.assertTrue(any(x.arg=='env' and isinstance(x.value,ast.Name) and x.value.id=='probe_env' for x in command.keywords))
 def test_checkpoint_retains_exact_comparison(self):
  import inspect
  self.assertIn('st_mtime_ns == value',inspect.getsource(c._mtime))
if __name__=='__main__':unittest.main()
