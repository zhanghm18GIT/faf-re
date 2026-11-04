import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import exact_timestamp as e

class FakeAPI:
    def __init__(self):
        self.handles = {}; self.closed = []; self.calls = []; self.t = (5, 7, 9)
        self.breakpoint = None; self.modifier = None; self.n = 0
    def open(self, path, *, directory=False, writable=False):
        self.calls.append(('open', path, directory, writable))
        if self.breakpoint == 'open': e.fail('OPEN_FAILED')
        self.n += 1; self.handles[self.n] = (path, directory, writable)
        return self.n
    def info(self, h):
        if self.breakpoint == 'info': e.fail('INFO_FAILED')
        p, directory, writable = self.handles[h]
        v = (0x10, 1, 1, len(p), 0) if directory else (0, 1, 1, 77, 123)
        return self.modifier(h, v) if self.modifier else v
    def times(self, h):
        if self.breakpoint == 'times': e.fail('GET_TIME_FAILED')
        return self.t
    def set_write(self, h, ticks):
        self.calls.append(('set', h, ticks))
        if self.breakpoint == 'set': e.fail('SET_TIME_FAILED')
        self.t = (5, 7, ticks)
        if self.breakpoint == 'round': self.t = (5, 7, ticks + 1)
        if self.breakpoint == 'access': self.t = (5, 8, ticks)
    def close(self, h):
        self.closed.append(h)
        if self.breakpoint == 'close': e.fail('CLOSE_FAILED')

class ExactTimestamp(unittest.TestCase):
    def code(self, code, fn):
        with self.assertRaises(e.TimestampError) as caught: fn()
        self.assertEqual(caught.exception.code, code)
        self.assertIn(code, e.SAFE_CODES)
        return caught.exception
    def run_fake(self, api): return e._set_windows('C:/owned/work/a.obj', 1700000000123456700, api)
    def test_conversion_roundtrip(self):
        for n in [0, 100, -100, -e.EPOCH_TICKS * 100, (e.MAX_TICKS-e.EPOCH_TICKS)*100]:
            self.assertEqual(e.ticks_to_ns(e.ns_to_ticks(n)), n)
    def test_types_precision_bounds(self):
        for x in [True, 1.0, '100', None]: self.code('MTIME_TYPE', lambda: e.ns_to_ticks(x))
        for x in [1, -1, 101]: self.code('MTIME_PRECISION', lambda: e.ns_to_ticks(x))
        for x in [(-e.EPOCH_TICKS-1)*100, (e.MAX_TICKS-e.EPOCH_TICKS+1)*100]:
            self.code('MTIME_RANGE', lambda: e.ns_to_ticks(x))
        for x in [True, -1, e.MAX_TICKS+1]: self.code('FILETIME_RANGE', lambda: e.ticks_to_ns(x))
    def test_layout(self):
        self.assertEqual(e.ctypes.sizeof(e.FILETIME), 8)
        self.assertEqual(e.ctypes.sizeof(e.INFO), 52)
    def test_success_and_handle_cleanup(self):
        a=FakeAPI();self.assertEqual(self.run_fake(a),1700000000123456700)
        self.assertEqual(a.closed,list(reversed(list(a.handles))))
        self.assertEqual(sum(x[0]=='set' for x in a.calls),1)
        self.assertEqual(a.t[:2],(5,7))
    def test_bad_paths_before_open(self):
        for p in ['relative', 'C:relative', '//host/file', r'\\?\C:\owned\a', 'C:/owned/../a', 'C:/owned/./a', 'C:/owned/a:stream', 'C:/owned/NUL', 'C:/owned/a.', 'C:/owned/a\n']:
            a=FakeAPI();self.code('PATH_INVALID',lambda:e._set_windows(p,100,a));self.assertEqual(a.calls,[])
    def test_reparse_file_and_parent(self):
        for parent in [False,True]:
            a=FakeAPI();a.modifier=lambda h,v: (v[0]|0x400,*v[1:]) if a.handles[h][1]==parent else v
            self.code('REPARSE_FORBIDDEN',lambda:self.run_fake(a));self.assertFalse(any(x[0]=='set' for x in a.calls))
    def test_nonregular_and_hardlink(self):
        for attrs,links,code in [(0x10,1,'FILE_TYPE'),(0x40,1,'FILE_TYPE'),(0,2,'HARDLINK_FORBIDDEN'),(0,0,'HARDLINK_FORBIDDEN')]:
            a=FakeAPI();a.modifier=lambda h,v:(attrs,links,*v[2:]) if not a.handles[h][1] else v
            self.code(code,lambda:self.run_fake(a));self.assertFalse(any(x[0]=='set' for x in a.calls))
    def test_path_identity_mismatch(self):
        a=FakeAPI();a.modifier=lambda h,v:(*v[:3],88,v[4]) if not a.handles[h][1] and not a.handles[h][2] else v
        self.code('PATH_IDENTITY_CHANGED',lambda:self.run_fake(a))
        self.assertFalse(any(x[0]=='set' for x in a.calls))
    def test_ancestor_mutation(self):
        a=FakeAPI();counts={}
        def mod(h,v):
            counts[h]=counts.get(h,0)+1
            return (*v[:3],999,v[4]) if a.handles[h][1] and counts[h]>1 else v
        a.modifier=mod;self.code('ANCESTOR_CHANGED',lambda:self.run_fake(a))
    def test_failures_close_every_open_handle(self):
        for point,code in [('open','OPEN_FAILED'),('info','INFO_FAILED'),('times','GET_TIME_FAILED'),('set','SET_TIME_FAILED'),('close','CLOSE_FAILED'),('access','OTHER_TIMESTAMPS_CHANGED'),('round','MTIME_MISMATCH')]:
            a=FakeAPI();a.breakpoint=point;self.code(code,lambda:self.run_fake(a));self.assertEqual(set(a.closed),set(a.handles))
    def test_error_details_only_safe_integers(self):
        a=FakeAPI();a.breakpoint='round';error=self.code('MTIME_MISMATCH',lambda:self.run_fake(a))
        self.assertEqual(set(error.details),{'expected','observed'});self.assertNotIn('owned',str(error))
    def test_native_api_open_flags_and_sharing(self):
        api=e.WindowsAPI.__new__(e.WindowsAPI);api.k=Mock();api.k.CreateFileW.return_value=123
        self.assertEqual(api.open('C:/owned/a',writable=True),123)
        args=api.k.CreateFileW.call_args.args
        self.assertEqual(args[1],0x80000180);self.assertEqual(args[2],1)
        self.assertEqual(args[4],3);self.assertEqual(args[5],0x02200000)
        api.open('C:/owned',directory=True)
        self.assertEqual(api.k.CreateFileW.call_args.args[1],0x80)
        self.assertEqual(api.k.CreateFileW.call_args.args[2],3)
        api.k.CreateFileW.return_value=e.ctypes.c_void_p(-1).value
        self.code('OPEN_FAILED',lambda:api.open('C:/owned/a'))
    def test_native_set_time_null_preserves_other_fields(self):
        api=e.WindowsAPI.__new__(e.WindowsAPI);api.k=Mock();api.k.SetFileTime.return_value=1
        value=0x12345678abcdef01;api.set_write(123,value)
        args=api.k.SetFileTime.call_args.args
        self.assertEqual(args[:3],(123,None,None))
        ft=e.ctypes.cast(args[3],e.ctypes.POINTER(e.FILETIME)).contents
        self.assertEqual(e._ticks(ft),value)
        api.k.SetFileTime.return_value=0
        self.code('SET_TIME_FAILED',lambda:api.set_write(123,value))
    def test_native_api_read_failures(self):
        api=e.WindowsAPI.__new__(e.WindowsAPI);api.k=Mock()
        api.k.GetFileType.return_value=2
        self.code('NOT_DISK_FILE',lambda:api.info(123))
        api.k.GetFileType.return_value=1;api.k.GetFileInformationByHandle.return_value=0
        self.code('INFO_FAILED',lambda:api.info(123))
        api.k.GetFileTime.return_value=0
        self.code('GET_TIME_FAILED',lambda:api.times(123))
        api.k.CloseHandle.return_value=0
        self.code('CLOSE_FAILED',lambda:api.close(123))
    def test_native_winerror_preserved_without_os_text(self):
        api=e.WindowsAPI.__new__(e.WindowsAPI);api.k=Mock()
        api.k.CreateFileW.return_value=e.ctypes.c_void_p(-1).value
        with patch.object(e,'_last_error',return_value=32):
            error=self.code('OPEN_FAILED',lambda:api.open('C:/owned/a'))
        self.assertEqual(error.winerror,32)
        self.assertEqual(str(error),'OPEN_FAILED')
        api.k.GetFileTime.return_value=0
        with patch.object(e,'_last_error',return_value=5):
            error=self.code('GET_TIME_FAILED',lambda:api.times(123))
        self.assertEqual(error.winerror,5)
        for value in (-1,True,'5',1<<32):
            self.assertIsNone(e.TimestampError('OPEN_FAILED',winerror=value).winerror)
    def test_postwrite_identity_change(self):
        a=FakeAPI()
        a.modifier=lambda h,v:(*v[:3],999,v[4]) if not a.handles[h][1] and any(x[0]=='set' for x in a.calls) else v
        self.code('FILE_IDENTITY_CHANGED',lambda:self.run_fake(a))
    def test_precise_conversion_failure_before_open(self):
        a=FakeAPI();self.code('MTIME_PRECISION',lambda:e._set_windows('C:/owned/a',101,a))
        self.assertEqual(a.calls,[])
    def test_reserved_windows_setter_values_before_open(self):
        for ticks in (0,e.MAX_TICKS):
            a=FakeAPI()
            self.code('FILETIME_RESERVED',lambda:e._set_windows('C:/owned/a',e.ticks_to_ns(ticks),a))
            self.assertEqual(a.calls,[])
    @unittest.skipUnless(os.name=='nt','Actual Windows hardlink acceptance must run on Windows')
    def test_native_windows_hardlink_rejected_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'original.obj';p.write_bytes(b'public synthetic hardlink fixture')
            alias=Path(d)/'alias.obj';os.link(p,alias)
            before=p.stat().st_mtime_ns
            self.code('HARDLINK_FORBIDDEN',lambda:e.set_mtime(p,1700000000000000100))
            self.assertEqual(p.stat().st_mtime_ns,before)
            self.assertEqual(alias.stat().st_mtime_ns,before)
    @unittest.skipUnless(os.name=='nt','Actual Windows API acceptance must run on Windows')
    def test_native_windows_exact(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'exact.obj';p.write_bytes(b'public synthetic timestamp fixture')
            target=1700000000123456700;before=p.stat();e.set_mtime(p,target);after=p.stat()
            self.assertEqual(after.st_mtime_ns,target);self.assertEqual(before.st_atime_ns,after.st_atime_ns)
            self.assertEqual(before.st_size,after.st_size)
    @unittest.skipUnless(os.name=='nt','Actual Windows precision acceptance must run on Windows')
    def test_native_windows_all_submicrosecond_lanes(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'lanes.obj';p.write_bytes(b'public synthetic precision fixture')
            observed=p.stat().st_mtime_ns
            self.assertEqual(observed % 100,0)
            base=1700000000000000000
            for lane in range(10):
                with self.subTest(lane=lane):
                    value=base+lane*100
                    e.set_mtime(p,value)
                    self.assertEqual(p.stat().st_mtime_ns,value)
            e.set_mtime(p,observed)
            self.assertEqual(p.stat().st_mtime_ns,observed)
    @unittest.skipUnless(os.name=='nt','Actual Windows replace acceptance must run on Windows')
    def test_native_windows_observed_timestamp_after_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'restored.obj';p.write_bytes(b'original public synthetic fixture')
            observed=p.stat().st_mtime_ns
            self.assertEqual(observed % 100,0)
            for iteration in range(3):
                replacement=Path(d)/('replacement'+str(iteration)+'.obj')
                payload=('public replacement '+str(iteration)).encode('ascii')
                replacement.write_bytes(payload)
                replacement.replace(p)
                before=p.stat()
                e.set_mtime(p,observed)
                after=p.stat()
                self.assertEqual(after.st_mtime_ns,observed)
                self.assertEqual(after.st_atime_ns,before.st_atime_ns)
                self.assertEqual(after.st_size,len(payload))
                self.assertEqual(after.st_ino,before.st_ino)
                # A repeat on the same handle identity must remain exactly idempotent.
                e.set_mtime(p,observed)
                self.assertEqual(p.stat().st_mtime_ns,observed)
    @unittest.skipIf(os.name=='nt','POSIX-only branch test')
    def test_posix_exact_and_links(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.write_bytes(b'x');e.set_mtime(p,1700000000123456789);self.assertEqual(p.stat().st_mtime_ns,1700000000123456789)
            link=Path(d)/'link';link.symlink_to(p);self.code('FILE_TYPE',lambda:e.set_mtime(link,100))
            os.link(p,Path(d)/'hard');self.code('HARDLINK_FORBIDDEN',lambda:e.set_mtime(p,100))

if __name__=='__main__': unittest.main()
