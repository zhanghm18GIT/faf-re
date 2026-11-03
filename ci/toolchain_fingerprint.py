"""Bounded external-input fingerprints. No subprocesses, network, or mutations.

The Windows backend pins every ancestor/directory without delete sharing, opens
files without write/delete sharing and validates non-reparse handles. POSIX is
provided for synthetic tests, not as evidence of Windows execution. Callers own
command/search-order reconciliation, SDK junction mapping validation, binary
version/architecture checks, and runtime closure. See README.md for limits.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, field
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, Iterable, Mapping, Sequence

SCHEMA = "faf-external-inputs-v1"
CHUNK = 1024 * 1024
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REPARSE = 0x400


class FingerprintError(RuntimeError):
    """Fail-closed error. Text contains logical IDs/status, never physical paths."""


def _fail(message: str) -> None:
    raise FingerprintError(message) from None


def _logical(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        _fail("invalid logical identifier")
    return value


def _name(value: str) -> str:
    # ASCII-only is deliberate: Python Unicode casefold is not Windows ordinal.
    if (not value or not value.isascii() or value in (".", "..") or
            value[-1] in ". " or any(c in value for c in '\\/:*?"<>|') or
            any(ord(c) < 32 for c in value)):
        _fail("unsupported or ambiguous path component")
    if value.split(".")[0].upper() in ({"CON", "PRN", "AUX", "NUL"} |
            {f"{p}{n}" for p in ("COM", "LPT") for n in range(1, 10)}):
        _fail("reserved path component")
    return value.lower()


def _path(value: os.PathLike[str] | str) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or not raw.isascii() or "\x00" in raw:
        _fail("unsupported declared path")
    if len(raw) > 4096 or raw.startswith(("\\\\", "//")) or (os.name != "nt" and "\\" in raw):
        _fail("device, UNC, or overlong declared path")
    p = Path(raw)
    if not p.is_absolute():
        _fail("declared paths must be absolute")
    # Check raw spelling before pathlib can elide '.' components.
    tail = raw[2:] if os.name == "nt" and re.match(r"^[A-Za-z]:", raw) else raw
    for component in re.split(r"[\\/]", tail):
        if component:
            _name(component)
    if os.name == "nt" and any(c.lower() in ("users", "documents and settings")
                                for c in p.parts[1:]):
        _fail("user-profile paths are not declared toolchain inputs")
    return p


def _encoded(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


@dataclass(frozen=True)
class Bounds:
    max_roots: int = 32
    max_explicit_files: int = 256
    max_files: int = 100_000
    max_directories: int = 20_000
    max_depth: int = 32
    max_file_bytes: int = 1024 ** 3
    max_total_bytes: int = 8 * 1024 ** 3
    max_entries: int = 240_000
    max_seconds: float = 180.0

    def validate(self) -> None:
        ceilings = Bounds()
        for key in self.__dataclass_fields__:
            val = getattr(self, key)
            ceiling = getattr(ceilings, key)
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
                _fail("invalid inventory bounds")
            if val < 0 or val > ceiling or (key != "max_seconds" and not isinstance(val, int)):
                _fail("bounds may only tighten reviewed ceilings")


@dataclass
class PassAllowance:
    """Share across all passes in one job. Failed passes consume allowance too."""
    max_seconds: float = 360.0
    used_seconds: float = 0.0

    def remaining(self) -> float:
        if (not math.isfinite(self.max_seconds) or not 0 < self.max_seconds <= 360 or
                not math.isfinite(self.used_seconds) or self.used_seconds < 0):
            _fail("invalid job fingerprint allowance")
        return max(0.0, self.max_seconds - self.used_seconds)


@dataclass(frozen=True)
class RootSpec:
    logical_id: str
    path: os.PathLike[str] | str
    mode: str = "tree"  # tree: every file/dir; libraries: direct candidates only
    optional: bool = False
    extra_basenames: tuple[str, ...] = ()
    compare_mtime: bool = True
    version: str = ""


@dataclass(frozen=True)
class FileSpec:
    logical_id: str
    path: os.PathLike[str] | str
    optional: bool = False
    compare_mtime: bool = True
    expected_sha256: str | None = None
    expected_size: int | None = None
    version: str = ""
    expected_basename: str | None = None


@dataclass(frozen=True)
class Inventory:
    """Keep this object/private_manifest in-job; publish public_summary only."""
    _manifest_json: str = field(repr=False)
    duration_seconds: float
    platform: str
    _mapping: tuple[tuple[str, str], ...] = field(repr=False)
    _summary_json: str = field(default="", repr=False)

    def private_manifest(self) -> dict:
        # Relative names, no actual local paths. Explicit mappings are opt-in.
        return json.loads(self._manifest_json)

    def private_root_mapping(self) -> dict[str, str]:
        return dict(self._mapping)

    def public_summary(self) -> dict:
        if self._summary_json:
            return json.loads(self._summary_json)
        manifest = self.private_manifest()
        roots = []
        for root in manifest["roots"]:
            records = root["records"]
            files = [r for r in records if r["kind"] == "file"]
            contents = [{k: v for k, v in r.items() if k != "mtime_ns"} for r in records]
            stamps = [{"path": r["path"], "mtime_ns": r["mtime_ns"]}
                      for r in files if "mtime_ns" in r]
            roots.append({"logical_id": root["logical_id"], "version": root["version"],
                          "mode": root["mode"], "status": root["status"],
                          "selection_sha256": _digest({"mode": root["mode"],
                              "optional": root["optional"], "compare_mtime": root["compare_mtime"],
                              "extra_basenames": root.get("extra_basenames", [])}),
                          "file_count": len(files),
                          "directory_count": sum(r["kind"] == "directory" for r in records),
                          "total_bytes": sum(r["size"] for r in files),
                          "content_sha256": _digest(contents),
                          "timestamp_sha256": _digest(stamps) if root["compare_mtime"] else None})
        identity = {"schema": SCHEMA, "roots": roots}
        return {**identity, "complete": True, "identity_sha256": _digest(identity),
                "file_count": sum(r["file_count"] for r in roots),
                "directory_count": sum(r["directory_count"] for r in roots),
                "total_bytes": sum(r["total_bytes"] for r in roots),
                "duration_seconds": round(self.duration_seconds, 6),
                "backend": self.platform}

    def assert_matches(self, other: "Inventory | Mapping") -> None:
        if isinstance(other, Inventory):
            candidate = other.public_summary()
        else:
            candidate = other
        current = self.public_summary()
        # Compare the canonical full aggregate body, not a caller-supplied hash alone.
        keys = ("schema", "roots", "complete", "identity_sha256", "file_count", "directory_count", "total_bytes")
        if any(current[k] != candidate.get(k) for k in keys):
            _fail("external-input identity mismatch; reuse is blocked")


class _Budget:
    def __init__(self, bounds: Bounds, clock: Callable[[], float], remaining: float):
        self.bounds, self.clock = bounds, clock
        self.start = clock()
        self.deadline = self.start + min(bounds.max_seconds, remaining)
        self.files = self.directories = self.bytes = self.entries = 0

    def check(self) -> None:
        if self.clock() >= self.deadline:
            _fail("inventory deadline exhausted")

    def add(self, what: str, count: int = 1) -> None:
        self.check()
        setattr(self, what, getattr(self, what) + count)
        limit_name = {"files": "max_files", "directories": "max_directories",
                      "bytes": "max_total_bytes", "entries": "max_entries"}[what]
        if getattr(self, what) > getattr(self.bounds, limit_name):
            _fail(f"inventory {what} bound exhausted")


def _snapshot(path: Path) -> tuple | None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        _fail("metadata read failed")
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
        _fail("link or reparse input rejected")
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        _fail("non-regular input rejected")
    return (stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns,
            st.st_dev, st.st_ino, getattr(st, "st_file_attributes", 0))


class _NativeHandles:
    """Pin every existing ancestor; inspect by handle before reading."""
    def __init__(self, budget: _Budget):
        self.budget = budget
        self.stack = ExitStack()
        self.directories: dict[str, object] = {}
        self.file_ids: dict[tuple, str] = {}
        if os.name == "nt":
            self.win = _WindowsAPI()
        else:
            self.win = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stack.close()

    def pin(self, path: Path, allow_missing: bool = False) -> bool:
        key = str(path).lower()
        if key in self.directories:
            return True
        if len(path.parts) > 128 or len(self.directories) >= 24_096:
            _fail("pinned ancestor/directory handle bound exhausted")
        if path.parent != path and not self.pin(path.parent, allow_missing):
            if allow_missing:
                return False
            _fail("missing declared ancestor")
        self.budget.check()
        before = _snapshot(path)
        if before is None:
            if allow_missing:
                return False
            _fail("missing declared directory")
        if before[0] != stat.S_IFDIR:
            _fail("declared ancestor is not a directory")
        try:
            if self.win:
                handle = self.win.open(path, directory=True)
                self.stack.callback(self.win.close, handle)
                self.win.validate(handle, path, directory=True)
            else:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                handle = os.open(path, flags)
                self.stack.callback(os.close, handle)
                st = os.fstat(handle)
                if (st.st_dev, st.st_ino) != (before[3], before[4]):
                    _fail("directory changed while opening")
            after = _snapshot(path)
            if after is None or after[0] != before[0] or after[3:5] != before[3:5]:
                _fail("directory identity changed while opening")
        except OSError:
            _fail("directory could not be pinned")
        self.directories[key] = handle
        return True

    def read_file(self, path: Path, before: tuple) -> tuple[str, int, int]:
        self.pin(path.parent)
        self.budget.add("files")
        if before[0] != stat.S_IFREG or before[1] > self.budget.bounds.max_file_bytes:
            _fail("non-regular or oversized input")
        digest = hashlib.sha256()
        size = 0
        try:
            with ExitStack() as stack:
                if self.win:
                    handle = self.win.open(path, directory=False)
                    stack.callback(self.win.close, handle)
                    initial = self.win.validate(handle, path, directory=False)
                    if initial[:2] != (before[1], before[2]):
                        _fail("file changed before opening")
                    identity = initial[2:4]
                    read = lambda: self.win.read(handle, CHUNK)
                else:
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    stream = stack.enter_context(os.fdopen(fd, "rb"))
                    st = os.fstat(stream.fileno())
                    initial = (st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino)
                    if not stat.S_ISREG(st.st_mode) or initial != (before[1], before[2], before[3], before[4]):
                        _fail("file changed before opening")
                    identity = initial[2:4]
                    read = lambda: stream.read(CHUNK)
                previous_path = self.file_ids.get(identity)
                if previous_path is not None and previous_path != str(path).lower():
                    _fail("aliased regular-file identities rejected")
                self.file_ids[identity] = str(path).lower()
                while True:
                    self.budget.check()
                    block = read()
                    if not block:
                        break
                    size += len(block)
                    self.budget.add("bytes", len(block))
                    if size > self.budget.bounds.max_file_bytes or size > before[1]:
                        _fail("file grew while hashing")
                    digest.update(block)
                if self.win:
                    final = self.win.validate(handle, path, directory=False)
                else:
                    st = os.fstat(stream.fileno())
                    final = (st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino)
                if initial != final or size != before[1] or _snapshot(path) != before:
                    _fail("file changed while hashing")
        except OSError:
            _fail("file open or read failed")
        return digest.hexdigest(), size, before[2]


class _WindowsAPI:
    def __init__(self):
        from ctypes import wintypes as w
        self.w = w
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        class Tag(ctypes.Structure):
            _fields_ = [("attributes", w.DWORD), ("tag", w.DWORD)]
        class Info(ctypes.Structure):
            _fields_ = [("attributes", w.DWORD), ("creation", w.FILETIME),
                        ("access", w.FILETIME), ("write", w.FILETIME),
                        ("volume", w.DWORD), ("size_high", w.DWORD), ("size_low", w.DWORD),
                        ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]
        self.Tag, self.Info = Tag, Info
        signatures = {
            "CreateFileW": ([w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "GetFileInformationByHandleEx": ([w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD], w.BOOL),
            "GetFileInformationByHandle": ([w.HANDLE, ctypes.POINTER(Info)], w.BOOL),
            "GetFinalPathNameByHandleW": ([w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD], w.DWORD),
            "GetFileType": ([w.HANDLE], w.DWORD),
            "ReadFile": ([w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.k, name)
            fn.argtypes, fn.restype = args, result

    def close(self, handle):
        self.k.CloseHandle(handle)

    def open(self, path: Path, directory: bool):
        # Directories allow writes to unrelated cwd entries, never rename/delete.
        access = 0x80 if directory else 0x80000000  # attributes / GENERIC_READ
        sharing = 0x1 | (0x2 if directory else 0)  # READ, optional WRITE; no DELETE
        flags = 0x00200000 | (0x02000000 if directory else 0)  # OPEN_REPARSE_POINT / BACKUP_SEMANTICS
        handle = self.k.CreateFileW(str(path), access, sharing, None, 3, flags, None)
        if handle == ctypes.c_void_p(-1).value:
            _fail("Windows non-following handle open failed")
        return handle

    def validate(self, handle, path: Path, directory: bool):
        tag, info = self.Tag(), self.Info()
        if (not self.k.GetFileInformationByHandleEx(handle, 9, ctypes.byref(tag), ctypes.sizeof(tag)) or
                not self.k.GetFileInformationByHandle(handle, ctypes.byref(info))):
            _fail("Windows handle metadata unavailable")
        if tag.tag or tag.attributes & _REPARSE or info.attributes & _REPARSE:
            _fail("Windows reparse handle rejected")
        if bool(info.attributes & 0x10) != directory or self.k.GetFileType(handle) != 1:
            _fail("Windows input handle has wrong type")
        buf = ctypes.create_unicode_buffer(32768)
        length = self.k.GetFinalPathNameByHandleW(handle, buf, len(buf), 0)
        if not length or length >= len(buf):
            _fail("Windows final path unavailable")
        actual = buf.value
        if actual.startswith("\\\\?\\"):
            actual = actual[4:]
        if actual.rstrip("\\").lower() != str(path).rstrip("\\").lower():
            _fail("Windows handle escaped approved physical path")
        ticks = (info.write.dwHighDateTime << 32) | info.write.dwLowDateTime
        return ((info.size_high << 32) | info.size_low,
                (ticks - 116444736000000000) * 100,
                info.volume, (info.index_high << 32) | info.index_low)

    def read(self, handle, count: int) -> bytes:
        buf = ctypes.create_string_buffer(count)
        got = self.w.DWORD()
        if not self.k.ReadFile(handle, buf, count, ctypes.byref(got), None):
            _fail("Windows input read failed")
        return buf.raw[:got.value]


def _scan(path: Path, spec: RootSpec, budget: _Budget) -> list[tuple[str, tuple]]:
    selected = []
    seen = set()
    extras = {x.lower() for x in spec.extra_basenames}
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                budget.add("entries")
                key = _name(entry.name)
                if key in seen:
                    _fail("case-colliding directory entries")
                seen.add(key)
                if spec.mode == "libraries" and not (key.endswith(".lib") or key in extras):
                    continue
                snap = _snapshot(path / entry.name)
                if snap is None:
                    _fail("entry disappeared during enumeration")
                if spec.mode == "libraries" and snap[0] != stat.S_IFREG:
                    _fail("library candidate is not a regular file")
                selected.append((entry.name, snap))
    except OSError:
        _fail("directory enumeration failed")
    return sorted(selected, key=lambda item: item[0].lower())


def _version(value: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or not value.isascii() or any(ord(c) < 32 for c in value):
        _fail("invalid public version label")
    # Public labels must not become another route to publish paths or secrets.
    if value and not re.fullmatch(r"[A-Za-z0-9 ._+()-]+", value):
        _fail("invalid public version label")
    return value


def capture_inventory(roots: Sequence[RootSpec], files: Sequence[FileSpec] = (), *,
                      bounds: Bounds | None = None, allowance: PassAllowance | None = None,
                      clock: Callable[[], float] = time.monotonic) -> Inventory:
    """Perform a fresh full byte pass; errors return no partial manifest/digest.

    `roots` order is semantic and retained. `files` follows in its declared order.
    No junction traversal is accepted, even if a driver separately verified it.
    Declare physical targets instead. All physical paths stay out of aggregates.
    """
    bounds = bounds or Bounds()
    bounds.validate()
    if any(not isinstance(spec, RootSpec) for spec in roots) or any(not isinstance(spec, FileSpec) for spec in files):
        _fail("root and explicit-file declarations must use their assigned containers")
    if len(roots) > bounds.max_roots or len(files) > bounds.max_explicit_files:
        _fail("declared root/file count exhausted")
    if not roots and not files:
        _fail("an empty declared inventory is not complete")
    specs = [*roots, *files]
    ids, paths = set(), set()
    validated = []
    for spec in specs:
        ident = _logical(spec.logical_id)
        path = _path(spec.path)
        key = str(path).lower()
        if ident in ids or key in paths:
            _fail("duplicate declared identity or physical path")
        ids.add(ident); paths.add(key)
        _version(spec.version)
        if not isinstance(spec.optional, bool) or not isinstance(spec.compare_mtime, bool):
            _fail("invalid presence or timestamp policy")
        if isinstance(spec, RootSpec):
            if spec.mode not in ("tree", "libraries"):
                _fail("unknown inventory mode")
            extra_keys = [_name(x) for x in spec.extra_basenames]
            if len(extra_keys) > 256 or len(extra_keys) != len(set(extra_keys)):
                _fail("invalid explicit library candidate basenames")
            if spec.mode == "tree" and not spec.compare_mtime:
                _fail("recursive installed-input roots require exact timestamps")
            if spec.mode == "tree" and spec.extra_basenames:
                _fail("extra basenames only apply to library namespaces")
        else:
            if spec.expected_sha256 is not None and not _SHA.fullmatch(spec.expected_sha256):
                _fail("invalid expected content hash")
            if spec.expected_size is not None and (isinstance(spec.expected_size, bool) or
                    not isinstance(spec.expected_size, int) or spec.expected_size < 0):
                _fail("invalid expected file size")
            if spec.expected_basename is not None and _name(spec.expected_basename) != _name(path.name):
                _fail("explicit input basename differs from approved basename")
        validated.append((spec, path))
    remaining = allowance.remaining() if allowance else 360.0
    budget = _Budget(bounds, clock, remaining)
    manifests, mappings = [], []
    directory_receipts: list[tuple[Path, RootSpec, list[tuple[str, tuple]]]] = []
    absent_paths: list[Path] = []
    explicit_receipts: list[tuple[Path, tuple]] = []
    try:
        with _NativeHandles(budget) as handles:
            def file_record(path: Path, relative: str, snapshot: tuple, compare_mtime: bool) -> dict:
                sha, size, mtime = handles.read_file(path, snapshot)
                record = {"path": relative, "kind": "file", "size": size, "sha256": sha}
                if compare_mtime:
                    record["mtime_ns"] = mtime
                return record

            def visit(path: Path, relative: str, spec: RootSpec, records: list, depth: int):
                if depth > bounds.max_depth:
                    _fail("inventory depth bound exhausted")
                budget.add("directories")
                handles.pin(path)
                records.append({"path": relative, "kind": "directory"})
                initial = _scan(path, spec, budget)
                directory_receipts.append((path, spec, initial))
                present = {name.lower() for name, _ in initial}
                for name, snap in initial:
                    rel = f"{relative}/{name}" if relative else name
                    if snap[0] == stat.S_IFDIR:
                        visit(path / name, rel, spec, records, depth + 1)
                    else:
                        records.append(file_record(path / name, rel, snap, spec.compare_mtime))
                for name in sorted(spec.extra_basenames, key=str.lower):
                    if name.lower() not in present:
                        records.append({"path": name, "kind": "absent-candidate"})

            for spec, path in validated:
                budget.check()
                handles.pin(path.parent, allow_missing=spec.optional)
                snap = _snapshot(path)
                mode = spec.mode if isinstance(spec, RootSpec) else "file"
                item = {"logical_id": spec.logical_id, "version": spec.version, "mode": mode,
                        "compare_mtime": spec.compare_mtime, "optional": spec.optional, "status": "PRESENT", "records": []}
                if isinstance(spec, RootSpec):
                    item["extra_basenames"] = list(spec.extra_basenames)
                if snap is None:
                    if not spec.optional:
                        _fail(f"mandatory input missing: {spec.logical_id}")
                    absent_paths.append(path)
                    item["status"] = "ABSENT"
                    item["records"].append({"path": "", "kind": "absent"})
                elif isinstance(spec, RootSpec):
                    if snap[0] != stat.S_IFDIR:
                        _fail(f"declared root is not a directory: {spec.logical_id}")
                    visit(path, "", spec, item["records"], 0)
                else:
                    if snap[0] != stat.S_IFREG:
                        _fail(f"explicit input is not a regular file: {spec.logical_id}")
                    record = file_record(path, path.name, snap, spec.compare_mtime)
                    if spec.expected_sha256 is not None and record["sha256"] != spec.expected_sha256:
                        _fail(f"explicit content hash mismatch: {spec.logical_id}")
                    if spec.expected_size is not None and record["size"] != spec.expected_size:
                        _fail(f"explicit byte count mismatch: {spec.logical_id}")
                    item["records"].append(record)
                    explicit_receipts.append((path, snap))
                item["records"].sort(key=lambda r: (r["path"].lower(), r["kind"]))
                manifests.append(item)
                mappings.append((spec.logical_id, str(path)))
            # End-of-pass re-enumeration detects additions, deletions and metadata swaps.
            for path, spec, receipt in directory_receipts:
                budget.check()
                if _scan(path, spec, budget) != receipt:
                    _fail("directory inventory changed during pass")
            for path in absent_paths:
                budget.check()
                handles.pin(path.parent, allow_missing=True)
                if _snapshot(path) is not None:
                    _fail("optional input appeared during pass")
            for path, receipt in explicit_receipts:
                budget.check()
                if _snapshot(path) != receipt:
                    _fail("explicit input changed during pass")
            budget.check()
        manifest_json = _encoded({"schema": SCHEMA, "roots": manifests}).decode("ascii")
        platform = "windows-handles" if os.name == "nt" else "posix-synthetic"
        provisional = Inventory(manifest_json, 0.0, platform, tuple(mappings))
        summary = provisional.public_summary()
        budget.check()
        elapsed = max(0.0, clock() - budget.start)
        summary["duration_seconds"] = round(elapsed, 6)
        summary_json = _encoded(summary).decode("ascii")
        budget.check()
        return Inventory(manifest_json, elapsed, platform, tuple(mappings), summary_json)
    except FingerprintError:
        raise
    except (OSError, ValueError, OverflowError):
        _fail("inventory failed; no complete receipt")
    finally:
        if allowance:
            allowance.used_seconds += max(0.0, clock() - budget.start)


# Reject/remove only these enumerated compiler/config channels. This is not a
# claim that an arbitrary process is hermetic. Unlisted inherited values are NOT
# copied to children. Driver still rejects command/config/response overrides.
INJECTION_NAMES = frozenset({
    "CL", "_CL_", "LINK", "_LINK_", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
    "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
    "INCLUDE", "EXTERNAL_INCLUDE", "LIB", "LIBPATH", "CCC_OVERRIDE_OPTIONS",
    "CC", "CXX", "RC", "AR", "ASM", "ASFLAGS", "RCFLAGS", "FFLAGS", "FC", "CUDAFLAGS", "CUDACXX",
    "CMAKE_TOOLCHAIN_FILE", "CMAKE_GENERATOR", "CMAKE_GENERATOR_PLATFORM",
    "CMAKE_GENERATOR_TOOLSET", "CMAKE_GENERATOR_INSTANCE", "CMAKE_PREFIX_PATH",
    "CMAKE_INCLUDE_PATH", "CMAKE_LIBRARY_PATH", "CMAKE_PROGRAM_PATH",
    "CMAKE_FRAMEWORK_PATH", "CMAKE_APPBUNDLE_PATH", "CMAKE_FIND_ROOT_PATH",
    "CMAKE_PROJECT_TOP_LEVEL_INCLUDES", "CMAKE_PROJECT_INCLUDE", "CMAKE_PROJECT_INCLUDE_BEFORE",
    "CMAKE_USER_MAKE_RULES_OVERRIDE", "CMAKE_BUILD_TYPE", "CMAKE_CONFIGURATION_TYPES",
    "CMAKE_AR", "CMAKE_LINKER", "CMAKE_RANLIB", "CMAKE_MAKE_PROGRAM",
    "CMAKE_CROSSCOMPILING_EMULATOR", "CMAKE_MSVC_RUNTIME_LIBRARY",
    "CMAKE_MSVC_DEBUG_INFORMATION_FORMAT", "CMAKE_SYSROOT", "CMAKE_SYSROOT_COMPILE",
    "CMAKE_SYSROOT_LINK", "CMAKE_CLANG_VFS_OVERLAY", "CMAKE_VS_GLOBALS",
    "CLANG_CONFIG_FILE", "CLANG_CONFIG_FILE_SYSTEM_DIR", "CLANG_CONFIG_FILE_USER_DIR",
    "CLANG_NO_DEFAULT_CONFIG", "CLANG_RESOURCE_DIR", "COMPILER_PATH", "GCC_EXEC_PREFIX",
    "LIBRARY_PATH", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
})
_INJECTION_PREFIXES = ("CMAKE_C_", "CMAKE_CXX_", "CMAKE_RC_", "CMAKE_ASM_", "CMAKE_LINKER_",
                       "CMAKE_EXE_LINKER_", "CMAKE_SHARED_LINKER_", "CMAKE_MODULE_LINKER_",
                       "CMAKE_STATIC_LINKER_", "CMAKE_COMPILER_", "CMAKE_CUDA_",
                       "CMAKE_HIP_", "CMAKE_FORTRAN_", "CMAKE_OBJC_", "CMAKE_OBJCXX_",
                       "CMAKE_USER_MAKE_RULES_OVERRIDE_", "CMAKE_PROJECT_",
                       "CMAKE_<LANG>_")
SAFE_EFFECTIVE_NAMES = frozenset({
    "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATHEXT", "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432", "LANG", "LC_ALL", "TZ",
    "SOURCE_DATE_EPOCH", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE", "PYTHONUTF8",
    "PYTHONHASHSEED", "CMAKE_BUILD_PARALLEL_LEVEL", "CTEST_PARALLEL_LEVEL",
    "GIT_TERMINAL_PROMPT", "GIT_LFS_SKIP_SMUDGE", "CLANG_NO_DEFAULT_CONFIG",
    "VSLANG", "VCTOOLSVERSION", "VCTOOLSINSTALLDIR", "VSINSTALLDIR", "VCINSTALLDIR",
    "WINDOWSSDKDIR", "WINDOWSSDKVERSION", "UNIVERSALCRTSDKDIR", "UCRTVERSION",
})
_PATH_EFFECTIVE_NAMES = frozenset({"SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
                                  "VCTOOLSINSTALLDIR", "VSINSTALLDIR", "VCINSTALLDIR",
                                  "WINDOWSSDKDIR", "UNIVERSALCRTSDKDIR"})


def controlled_environment(inherited: Mapping[str, str],
                           verified_path_roots: Sequence[tuple[str, os.PathLike[str] | str]],
                           effective_inputs: Mapping[str, str], *, policy: str = "reject",
                           effective_public_labels: Mapping[str, str] | None = None) -> tuple[dict[str, str], dict]:
    """Construct from empty, NEVER from os.environ.copy().

    `verified_path_roots` are (logical ID, preverified directory) in exact order;
    their verification and required binary candidate inventory are caller duties.
    Only explicitly provided SAFE_EFFECTIVE_NAMES are admitted. Paths are private
    runtime values, represented by caller-supplied public logical labels. The
    receipt lists known injection-variable statuses without values. It omits all
    unrecognized inherited names (including credential names) and values.
    """
    if policy not in ("reject", "remove"):
        _fail("unknown environment injection policy")
    if not 1 <= len(verified_path_roots) <= 32:
        _fail("bounded declared PATH is required")
    seen, env_in, statuses = set(), {}, {}
    for name, value in inherited.items():
        if not isinstance(name, str) or not isinstance(value, str):
            _fail("invalid inherited environment representation")
        upper = name.upper()
        if upper in seen:
            _fail("case-colliding inherited environment names")
        seen.add(upper)
        if upper in INJECTION_NAMES or upper.startswith(_INJECTION_PREFIXES):
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", upper):
                _fail("invalid compiler environment name")
            statuses[upper] = "empty" if value == "" else "nonempty"
            env_in[upper] = value
    blocked = sorted(k for k, v in env_in.items() if v != "")
    if policy == "reject" and blocked:
        # Deliberately no values or full variable names from uncontrolled input.
        _fail("nonempty compiler/configuration injection variables rejected")
    child, effective = {}, {}
    labels = {k.upper(): v for k, v in (effective_public_labels or {}).items()}
    for name, value in effective_inputs.items():
        upper = name.upper()
        if upper not in SAFE_EFFECTIVE_NAMES or upper in child or not isinstance(value, str):
            _fail("effective environment input is not uniquely allowlisted")
        fixed_values = {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
                        "CLANG_NO_DEFAULT_CONFIG": "1"}
        if upper in fixed_values and value != fixed_values[upper]:
            _fail("environment input differs from the approved fixed value")
        if len(value) > 4096 or "\x00" in value or "\n" in value or "\r" in value:
            _fail("effective environment input exceeds safe representation")
        if upper in _PATH_EFFECTIVE_NAMES:
            _path(value.rstrip("\\/") if len(value) > 3 else value)
            if upper not in labels:
                _fail("path-valued environment input requires public logical label")
            effective[upper] = _logical(labels[upper])
        else:
            if not value.isascii() or len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9_.; +():-]*", value):
                _fail("effective environment value is not a bounded public scalar")
            effective[upper] = value
        child[upper] = value
    paths, path_ids, path_keys = [], [], set()
    for ident, raw in verified_path_roots:
        _logical(ident)
        path = _path(raw)
        key = str(path).lower()
        if ident in path_ids or key in path_keys or ";" in str(path) or len(str(path)) > 1024:
            _fail("ambiguous declared PATH entry")
        paths.append(str(path)); path_ids.append(ident); path_keys.add(key)
    separator = ";" if os.name == "nt" else os.pathsep
    child["PATH"] = separator.join(paths)
    receipt = {"schema": "faf-controlled-environment-v1", "policy": policy,
               "known_injection_status": {k: ("removed" if statuses[k] == "nonempty" else "empty-omitted")
                                          for k in sorted(statuses)},
               "path_logical_ids": path_ids, "effective_inputs": effective,
               "inherited_unlisted": "not-copied",
               "scope": "explicit-child-allowlist-and-listed-injection-channels"}
    receipt["identity_sha256"] = _digest(receipt)
    return child, receipt
