"""Exact timestamp restoration for caller-validated owned manifest files.
No ACL changes, path discovery, rounding, or tolerance. Native Windows tests must
run on Windows; mocked tests do not establish platform acceptance.
"""
import ctypes
import os
from pathlib import Path, PureWindowsPath
import re
import stat

EPOCH_TICKS = 116444736000000000
MAX_TICKS = (1 << 64) - 1
SAFE_CODES = frozenset({"MTIME_TYPE", "MTIME_PRECISION", "MTIME_RANGE", "FILETIME_RANGE", "FILETIME_RESERVED", "WINDOWS_REQUIRED", "OPEN_FAILED", "NOT_DISK_FILE", "INFO_FAILED", "GET_TIME_FAILED", "SET_TIME_FAILED", "CLOSE_FAILED", "PATH_INVALID", "REPARSE_FORBIDDEN", "FILE_TYPE", "HARDLINK_FORBIDDEN", "PATH_IDENTITY_CHANGED", "ANCESTOR_CHANGED", "MTIME_MISMATCH", "OTHER_TIMESTAMPS_CHANGED", "FILE_IDENTITY_CHANGED", "NATIVE_OPERATION_FAILED", "PARENT_TYPE", "POSIX_OPERATION_FAILED"})

class TimestampError(RuntimeError):
    def __init__(self, code, *, expected=None, observed=None, winerror=None):
        self.code = code
        self.winerror = winerror if type(winerror) is int and 0 <= winerror <= 0xffffffff else None
        self.details = {k: v for k, v in (("expected", expected), ("observed", observed)) if type(v) is int}
        super().__init__(code)

def fail(code, **details):
    raise TimestampError(code, **details) from None

def _last_error():
    return getattr(ctypes, "get_last_error", lambda: 0)()

def _native_fail(code):
    # Read immediately after the failed native call; never format OS error text.
    error = _last_error()
    fail(code, winerror=error)

def ns_to_ticks(value):
    if type(value) is not int:
        fail("MTIME_TYPE")
    if value % 100:
        fail("MTIME_PRECISION")
    ticks = value // 100 + EPOCH_TICKS
    if not 0 <= ticks <= MAX_TICKS:
        fail("MTIME_RANGE")
    return ticks

def ticks_to_ns(value):
    if type(value) is not int or not 0 <= value <= MAX_TICKS:
        fail("FILETIME_RANGE")
    return (value - EPOCH_TICKS) * 100

class FILETIME(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

class INFO(ctypes.Structure):
    _fields_ = [("attributes", ctypes.c_uint32), ("creation", FILETIME),
                ("access", FILETIME), ("write", FILETIME), ("volume", ctypes.c_uint32),
                ("size_high", ctypes.c_uint32), ("size_low", ctypes.c_uint32),
                ("links", ctypes.c_uint32), ("index_high", ctypes.c_uint32),
                ("index_low", ctypes.c_uint32)]

def _ticks(ft):
    return (int(ft.high) << 32) | int(ft.low)

class WindowsAPI:
    READ_ATTRIBUTES = 0x80
    WRITE_ATTRIBUTES = 0x100
    GENERIC_READ = 0x80000000
    SHARE_READ = 1
    SHARE_WRITE = 2
    OPEN_EXISTING = 3
    OPEN_REPARSE_POINT = 0x00200000
    BACKUP_SEMANTICS = 0x02000000

    def __init__(self):
        if os.name != "nt":
            fail("WINDOWS_REQUIRED")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        H, D, B = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int
        declarations = {
            "CreateFileW": ([ctypes.c_wchar_p, D, D, H, D, D, H], H),
            "GetFileType": ([H], D),
            "GetFileInformationByHandle": ([H, ctypes.POINTER(INFO)], B),
            "GetFileTime": ([H, ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME)], B),
            "SetFileTime": ([H, ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME)], B),
            "CloseHandle": ([H], B),
        }
        for name, (args, result) in declarations.items():
            f = getattr(self.k, name); f.argtypes = args; f.restype = result

    def open(self, path, *, directory=False, writable=False):
        access = self.READ_ATTRIBUTES if directory else self.GENERIC_READ | self.READ_ATTRIBUTES
        if writable:
            access |= self.WRITE_ATTRIBUTES
        # Never allow deletion/renaming; writer handle also excludes other data writers.
        # WRITE_ATTRIBUTES-only handles are not isolated by sharing modes.
        share = self.SHARE_READ if writable else self.SHARE_READ | self.SHARE_WRITE
        flags = self.OPEN_REPARSE_POINT | self.BACKUP_SEMANTICS
        h = self.k.CreateFileW(path, access, share, None, self.OPEN_EXISTING, flags, None)
        if h is None or h == ctypes.c_void_p(-1).value:
            _native_fail("OPEN_FAILED")
        return h

    def info(self, h):
        kind = self.k.GetFileType(h)
        if kind == 0:
            _native_fail("NOT_DISK_FILE")
        if kind != 1:
            fail("NOT_DISK_FILE")
        i = INFO()
        if not self.k.GetFileInformationByHandle(h, ctypes.byref(i)):
            _native_fail("INFO_FAILED")
        return (int(i.attributes), int(i.links), int(i.volume),
                (int(i.index_high) << 32) | int(i.index_low),
                (int(i.size_high) << 32) | int(i.size_low))

    def times(self, h):
        creation, access, write = FILETIME(), FILETIME(), FILETIME()
        if not self.k.GetFileTime(h, ctypes.byref(creation), ctypes.byref(access), ctypes.byref(write)):
            _native_fail("GET_TIME_FAILED")
        return (_ticks(creation), _ticks(access), _ticks(write))

    def set_write(self, h, ticks):
        ft = FILETIME(ticks & 0xffffffff, ticks >> 32)
        # NULL means unchanged: creation and access timestamps are not rewritten.
        if not self.k.SetFileTime(h, None, None, ctypes.byref(ft)):
            _native_fail("SET_TIME_FAILED")

    def close(self, h):
        if not self.k.CloseHandle(h):
            _native_fail("CLOSE_FAILED")

def _windows_paths(path):
    raw = os.fspath(path)
    if not isinstance(raw, str) or len(raw) > 4096 or not re.match(r"^[A-Za-z]:[\\/]", raw):
        fail("PATH_INVALID")
    if any(ord(c) < 32 for c in raw) or raw.startswith(("\\\\", "//")):
        fail("PATH_INVALID")
    components = re.split(r"[\\/]", raw[3:])
    if not components or any(not x or x in (".", "..") or x[-1] in ". " or
                             any(c in x for c in ':*?"<>|') or
                             re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", x, re.I)
                             for x in components):
        fail("PATH_INVALID")
    p = PureWindowsPath(raw)
    return str(p), [str(x) for x in reversed(p.parents)]

def _check_info(info, directory):
    attributes, links, *_ = info
    if attributes & 0x400:
        fail("REPARSE_FORBIDDEN")
    if bool(attributes & 0x10) != directory or attributes & 0x40:
        fail("FILE_TYPE")
    if not directory and links != 1:
        fail("HARDLINK_FORBIDDEN")
    return info

def _set_windows(path, value, api):
    ticks = ns_to_ticks(value)
    if ticks in (0, MAX_TICKS):
        fail("FILETIME_RESERVED")
    path, parents = _windows_paths(path)
    opened = []
    failed = False
    try:
        chain = []
        for parent in parents:
            h = api.open(parent, directory=True); opened.append(h)
            chain.append((h, _check_info(api.info(h), True)))
        h = api.open(path, writable=True); opened.append(h)
        before = _check_info(api.info(h), False)
        times = api.times(h)
        # Reopening the literal path confirms it still designates the pinned file.
        peer = api.open(path); opened.append(peer)
        if _check_info(api.info(peer), False) != before:
            fail("PATH_IDENTITY_CHANGED")
        for ancestor, prior in chain:
            if _check_info(api.info(ancestor), True) != prior:
                fail("ANCESTOR_CHANGED")
        api.set_write(h, ticks)
        after_times = api.times(h)
        if after_times[2] != ticks:
            fail("MTIME_MISMATCH", expected=value, observed=ticks_to_ns(after_times[2]))
        if after_times[:2] != times[:2]:
            fail("OTHER_TIMESTAMPS_CHANGED")
        if _check_info(api.info(h), False) != before or _check_info(api.info(peer), False) != before:
            fail("FILE_IDENTITY_CHANGED")
        for ancestor, prior in chain:
            if _check_info(api.info(ancestor), True) != prior:
                fail("ANCESTOR_CHANGED")
        return value
    except TimestampError:
        failed = True
        raise
    except (OSError, ValueError, OverflowError, TypeError):
        failed = True
        fail("NATIVE_OPERATION_FAILED")
    finally:
        close_failed = None
        for handle in reversed(opened):
            try:
                api.close(handle)
            except TimestampError as exc:
                if close_failed is None:
                    close_failed = exc
            except Exception:
                if close_failed is None:
                    close_failed = TimestampError("CLOSE_FAILED")
        if close_failed is not None and not failed:
            raise close_failed

def _set_posix(path, value):
    if type(value) is not int:
        fail("MTIME_TYPE")
    p = Path(path)
    if not p.is_absolute() or any(x == ".." for x in p.parts):
        fail("PATH_INVALID")
    try:
        for parent in reversed(p.parents):
            if not stat.S_ISDIR(parent.lstat().st_mode):
                fail("PARENT_TYPE")
        before = p.lstat()
        if not stat.S_ISREG(before.st_mode):
            fail("FILE_TYPE")
        if before.st_nlink != 1:
            fail("HARDLINK_FORBIDDEN")
        os.utime(p, ns=(before.st_atime_ns, value), follow_symlinks=False)
        after = p.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_nlink) != (after.st_dev, after.st_ino, after.st_size, after.st_nlink):
            fail("FILE_IDENTITY_CHANGED")
        if after.st_mtime_ns != value:
            fail("MTIME_MISMATCH", expected=value, observed=after.st_mtime_ns)
        if after.st_atime_ns != before.st_atime_ns:
            fail("OTHER_TIMESTAMPS_CHANGED")
        return value
    except TimestampError:
        raise
    except (OSError, ValueError, OverflowError, TypeError, NotImplementedError):
        fail("POSIX_OPERATION_FAILED")

def set_mtime(path, value):
    """Caller must supply a path admitted by its exact owned-file manifest."""
    if os.name == "nt":
        return _set_windows(path, value, WindowsAPI())
    return _set_posix(path, value)
