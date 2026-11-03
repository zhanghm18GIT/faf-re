import ast
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
CI=HERE.parent
CAP=runpy.run_path(str(CI/'build_capture.py'))
DRIVER=runpy.run_path(str(CI/'driver.py'))


class CaptureTests(unittest.TestCase):
    def run_child(self, code, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'build.txt'; events=[]
            result=CAP['run_build']([sys.executable,'-u','-c',code],cwd=directory,env=os.environ,
                log_path=log,timeout=kwargs.pop('timeout',3),emit=lambda k,v: events.append((k,v)),
                poll_interval=.01,progress_interval=.03,sample_interval=.1,**kwargs)
            return result,log.read_bytes(),events

    def test_complete_large_capture_exact_hash(self):
        wanted=b'x'*4*1024*1024+b'complete\n'
        result,data,events=self.run_child("import sys;sys.stdout.buffer.write(b'x'*4*1024*1024+b'complete\\n')")
        self.assertEqual(result['state'],'SUCCESS');self.assertEqual(data,wanted)
        self.assertEqual(result['log_sha256'],hashlib.sha256(wanted).hexdigest())
        self.assertTrue(any(k=='BUILD_RESOURCE' for k,v in events))

    def test_partial_line_retained_before_timeout(self):
        started=time.monotonic()
        result,data,events=self.run_child("import sys,time;sys.stdout.write('partial-no-newline');sys.stdout.flush();time.sleep(20)",timeout=.25)
        self.assertEqual(result['state'],'TIMED_OUT');self.assertEqual(data,b'partial-no-newline')
        self.assertTrue(result['cleanup']['parent_reaped']);self.assertEqual(result['cleanup']['reader_eof'],'CONFIRMED')
        self.assertLess(time.monotonic()-started,3)
        self.assertIn('partial-no-newline',next(v['text'] for k,v in events if k=='BUILD_TIMEOUT_OR_FAILURE_TAIL'))

    def test_nonzero_failure_tail(self):
        result,data,events=self.run_child("import sys;print('compile failed');sys.exit(7)")
        self.assertEqual(result['state'],'CHILD_FAILED');self.assertEqual(result['returncode'],7)
        self.assertIn(b'compile failed',data)

    def test_log_cap_is_hard_and_cannot_pass(self):
        result,data,events=self.run_child("import sys;sys.stdout.buffer.write(b'x'*1024*1024)",max_log_bytes=4096,tail_bytes=256)
        self.assertEqual(result['state'],'LOG_LIMIT');self.assertEqual(len(data),4096)
        tail=next(v['text'] for k,v in events if k=='BUILD_TIMEOUT_OR_FAILURE_TAIL')
        self.assertLessEqual(len(tail),256)

    def test_split_status_survives_long_verbose_line(self):
        code="import sys,time;sys.stdout.write('FAF_NIN');sys.stdout.flush();time.sleep(.03);sys.stdout.write('JA [1/9 running=2 elapsed=0.1] '+ 'x'*50000);sys.stdout.flush();time.sleep(.15)"
        result,data,events=self.run_child(code,tail_bytes=256)
        self.assertEqual(result['state'],'SUCCESS')
        self.assertEqual(result['last_ninja_status']['completed'],1)
        self.assertTrue(any(k=='BUILD_PROGRESS' and v['total']==9 for k,v in events))

    def test_sampler_failure_is_reported_not_hidden(self):
        def bad(proc):raise OSError('fixture')
        result,data,events=self.run_child("import time;time.sleep(.1)",sampler=bad)
        self.assertEqual(result['state'],'SUCCESS')
        self.assertTrue(any(k=='BUILD_RESOURCE' and v.get('status')=='UNAVAILABLE' for k,v in events))

    def test_cleanup_failure_is_truthful_and_parent_reaped(self):
        def bad(proc,path):raise OSError('simulated tree control failure')
        result,data,events=self.run_child("import time;time.sleep(20)",timeout=.15,terminate=bad)
        self.assertEqual(result['state'],'TIMED_OUT')
        self.assertEqual(result['cleanup']['state'],'TERMINATION_CALLBACK_FAILED')
        self.assertTrue(result['cleanup']['parent_reaped'])
        self.assertEqual(result['cleanup']['descendant_shutdown'],'NOT_INDEPENDENTLY_VERIFIED')

    def test_stalled_writer_does_not_hold_controller_lock(self):
        entered, release = threading.Event(), threading.Event()
        original = Path.open
        class StalledWriter:
            def __init__(self, wrapped): self.wrapped=wrapped
            def write(self, data):
                entered.set();release.wait(15);return self.wrapped.write(data)
            def flush(self): return self.wrapped.flush()
            def close(self): return self.wrapped.close()
        def opening(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            return StalledWriter(value) if path.name=='build.txt' and args==('xb',) else value
        started=time.monotonic()
        try:
            with mock.patch.object(Path,'open',opening):
                result,data,events=self.run_child("import sys,time;print('retained tail',flush=True);time.sleep(20)",timeout=.3)
            self.assertTrue(entered.is_set());self.assertEqual(result['state'],'TIMED_OUT')
            self.assertEqual(result['cleanup']['reader_eof'],'UNCONFIRMED')
            self.assertTrue(result['cleanup']['parent_reaped']);self.assertLess(time.monotonic()-started,7)
        finally:
            release.set()
            time.sleep(.05)

    def test_reader_start_failure_terminates_owned_child(self):
        with mock.patch.object(threading.Thread,'start',side_effect=RuntimeError('fixture')):
            result,data,events=self.run_child("import time;time.sleep(20)")
        self.assertEqual(result['state'],'CAPTURE_ERROR_RuntimeError')
        self.assertTrue(result['cleanup']['parent_reaped'])
        self.assertEqual(result['cleanup']['reader_eof'],'NOT_STARTED')

    def test_failed_launch_has_no_cleanup_target(self):
        with tempfile.TemporaryDirectory() as directory:
            result=CAP['run_build'](['/does/not/exist'],cwd=directory,env=os.environ,
                log_path=Path(directory)/'log',timeout=1,emit=lambda *x:None)
        self.assertEqual(result['state'],'CAPTURE_ERROR_FileNotFoundError')
        self.assertEqual(result['cleanup']['state'],'NOT_NEEDED')

    def test_expired_bound_never_launches(self):
        with mock.patch('subprocess.Popen') as popen:
            with self.assertRaises(ValueError):
                CAP['run_build'](['ignored'],cwd='.',env={},log_path='ignored',timeout=0,emit=lambda *x:None)
            popen.assert_not_called()

    def test_path_alias_slash_case_and_control(self):
        result=CAP['safe_text']('c:/TEMP/owned/source/x.cpp\x1b',[(r'C:\Temp\owned','<WORKSPACE>')])
        self.assertEqual(result,'<WORKSPACE>/source/x.cpp?')
        original=r'C:\Users\appveyor\AppData\Local\Temp\faf-re-reviewed-abc'
        for variant in [original,original.replace('\\','/'),original.upper(),original.replace('\\','/',2)]:
            self.assertEqual(CAP['safe_text'](variant+'/source/file.cpp',[(original,'<WORKSPACE>')]),'<WORKSPACE>/source/file.cpp')

    def test_ninja_summary_is_completed_rows_only(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'.ninja_log';p.write_text('# ninja log v5\n0\t100\t0\ta.obj\thash\n0\t100\t0\tb.obj\thash\n20\t50\t0\tc.obj\thash\n')
            result=CAP['ninja_summary'](p)
        self.assertEqual(result['completed_entries'],3)
        self.assertEqual(result['longest_completed_outputs'][0]['duration_ms'],100)
        self.assertIn('not unique commands',result['note'])

    def test_ninja_growth_read_is_limited_and_partial_ignored(self):
        limit=16*1024*1024
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'.ninja_log';p.write_bytes(b'# ninja log v5\n0\t10\t0\ta.obj\thash')
            partial=CAP['ninja_summary'](p)
            self.assertEqual(partial['completed_entries'],0)
            self.assertTrue(partial['unfinished_trailing_record_ignored'])
            reader=mock.MagicMock()
            reader.__enter__.return_value=reader
            reader.read.return_value=b'x'*(limit+1)
            with mock.patch.object(Path,'open',return_value=reader):
                result=CAP['ninja_summary'](p)
            reader.read.assert_called_once_with(limit+1)
            self.assertEqual(result['state'],'TOO_LARGE_TO_INSPECT')

class NinjaVersionTests(unittest.TestCase):
    def test_versions_five_six_and_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'.ninja_log'
            for version in [5,6]:
                p.write_text(f'# ninja log v{version}\n0\t10\t0\tx.obj\thash\n')
                self.assertEqual(CAP['ninja_summary'](p)['completed_entries'],1)
            p.write_text('# ninja log v7\n')
            self.assertEqual(CAP['ninja_summary'](p)['state'],'UNSUPPORTED_FORMAT')
if __name__=='__main__':unittest.main(verbosity=2)
