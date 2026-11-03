"""Fail-closed, local-only dependency checkpoint protocol (stdlib, schema 1).

This is not a build driver or a graph/provenance/license oracle. The caller supplies
exact graph allowlists, approved stable paths and immutable metadata, and verifies
complete external-header/library fingerprints and expanded command/rsp identity.
Ninja deps are NOT a complete include inventory (MSVC filters system includes).
No globbing, subprocess, network, installation, publication, or fallback build.
Owned roots must be exclusively controlled for the duration of each operation.
"""
from __future__ import annotations
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Mapping


class CheckpointError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise CheckpointError(message)


@dataclass(frozen=True)
class FileSpec:
    root: str
    relpath: str
    kind: str  # obj, lib, header, ninja_log, ninja_deps, source, license, material

    @property
    def member(self):
        return self.root + '/' + self.relpath


@dataclass(frozen=True)
class Limits:
    archive_bytes: int = 400_000_000
    total_bytes: int = 1_500_000_000
    member_bytes: int = 128_000_000
    members: int = 50_000
    manifest_bytes: int = 16_000_000
    log_records: int = 2_000_000


@dataclass(frozen=True)
class Policy:
    owned_roots: Mapping[str, Path]
    root_kinds: Mapping[str, str]  # source, generated, build, material
    payloads: tuple[FileSpec, ...]
    inputs: tuple[FileSpec, ...]
    allowed_log_inputs: frozenset[str]
    allowed_log_outputs: frozenset[str]
    approved_path_roots: tuple[str, ...]
    log_base_root: str  # stable absolute build path for relative Ninja paths
    limits: Limits = field(default_factory=Limits)


MANIFEST = 'checkpoint-manifest.json'
KINDS = {'obj', 'lib', 'header', 'ninja_log', 'ninja_deps', 'source', 'license', 'material'}
FORBIDDEN = {'.exe', '.dll', '.pdb', '.ilk', '.exp', '.dmp', '.zip', '.7z', '.gz', '.tgz', '.tar', '.bz2', '.xz', '.rar', '.log', '.a', '.so', '.dylib', '.o', '.obj', '.lib', '.bin', '.msi', '.cab', '.sys', '.com', '.scr'}
BIGOBJ_ID = bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')
BoundaryCheck = Callable[[str, FileSpec | None, bytes | dict], None]


def relative_name(name):
    require(isinstance(name, str) and bool(name), 'empty/non-string member')
    require('\\' not in name and not name.startswith('/') and ':' not in name, 'absolute/ambiguous member')
    require(all(p not in ('', '.', '..') and not p.endswith((' ', '.')) for p in name.split('/')), 'unsafe member component')
    require(not any(ord(c) < 32 or ord(c) == 127 for c in name), 'control character in member')
    require(not any(c in name for c in '<>"|?*'), 'Windows-special member character')
    for p in name.split('/'):
        require(p.casefold().split('.')[0] not in {'con', 'prn', 'aux', 'nul', *(f'com{x}' for x in range(1, 10)), *(f'lpt{x}' for x in range(1, 10))}, 'reserved Windows name')
        require(p.casefold() != '.git', 'git metadata forbidden')
    return name


def path_key(path):
    require(isinstance(path, str) and path and '\x00' not in path and '\n' not in path and '\r' not in path, 'invalid logical path')
    return ntpath.normpath(path.replace('/', '\\')).casefold()


def absolute(path):
    return bool(ntpath.splitdrive(path)[0]) or path.startswith(('/', '\\'))


def approved_path(path, policy):
    key = path_key(path)
    if not absolute(path):
        key = path_key(ntpath.join(policy.log_base_root, path))
    roots = [path_key(p).rstrip('\\') for p in policy.approved_path_roots]
    require(any(key == r or key.startswith(r + '\\') for r in roots), 'unapproved stable path: ' + path)


SCAN_CHUNK_BYTES = 1024 * 1024
IO_CHUNK_BYTES = 1024 * 1024


def inspect_public_paths(data, policy):
    # This is a conservative recognizable-string gate, NOT proof of absence of
    # private paths. Source literals compiled into an object may also be paths.
    # The driver must separately establish source provenance and debug mapping.
    require(len(data) <= policy.limits.member_bytes, 'path-scan byte bound')
    roots = [p.replace('/', '\\').casefold().rstrip('\\') for p in policy.approved_path_roots]
    require(all(len(root) <= 32768 for root in roots), 'path root length bound')
    span = max((len(p) for p in roots), default=0) + 2
    overlap = 2 * (span + 16)
    # A drive prefix alone followed by machine bytes is not a path string.
    # The token boundary also excludes the final s:/ or p:/ of HTTP(S) schemes.
    pattern = re.compile(r'(?i)(?<![a-z0-9_+.-])[a-z]:[\\/](?=[^\x00-\x20\x7f-\x9f\ufffd])|\\\\[a-z0-9_.-]+[\\/](?=[^\x00-\x20\x7f-\x9f\ufffd])')
    ascii_runs = re.compile(r'[\x20-\x7e]{4,}')
    wide_runs = re.compile(r'[^\x00-\x1f\x7f-\x9f\ufffd]{4,}')
    view = memoryview(data)
    for start in range(0, len(data), SCAN_CHUNK_BYTES):
        lo, hi = max(0, start-overlap), min(len(data), start+SCAN_CHUNK_BYTES+overlap)
        block = bytes(view[lo:hi])
        # One bounded decoded view at a time. Both UTF16 alignments are checked;
        # replacement, rather than deletion, preserves invalid-byte boundaries.
        for encoding, offset, runs in [('latin1', 0, ascii_runs), ('utf-16le', 0, wide_runs), ('utf-16le', 1, wide_runs)]:
            if encoding == 'latin1':
                text = block.decode('latin1')
            else:
                text = block[offset:len(block)-((len(block)-offset) % 2)].decode(encoding, errors='replace')
            for run in runs.finditer(text):
                for match in pattern.finditer(text, run.start(), run.end()):
                    if lo+offset > 0 and match.start() == 0:
                        continue  # previous overlapping window owns this token boundary
                    tail = text[match.start():min(run.end(), match.start()+span)].replace('/', '\\').casefold()
                    require(any(tail.startswith(root + '\\') or tail == root for root in roots), 'unapproved embedded absolute path')
            del text


def metadata_paths(value, policy):
    if isinstance(value, str):
        if absolute(value):
            approved_path(value, policy)
        inspect_public_paths(value.encode('utf-8'), policy)
    elif isinstance(value, dict):
        for k, v in value.items():
            require(isinstance(k, str), 'metadata key must be string')
            metadata_paths(k, policy)
            metadata_paths(v, policy)
    elif isinstance(value, list):
        for v in value:
            metadata_paths(v, policy)
    else:
        require(value is None or type(value) in (bool, int), 'metadata requires JSON strings/integers/bools/lists/objects')


def _safe_path(policy, spec, *, allow_missing=False):
    root = Path(policy.owned_roots[spec.root])
    require(root.is_absolute(), 'owned root must be absolute')
    target = root / relative_name(spec.relpath)
    # Check every ancestor, including ancestors outside the owned root. Never
    # resolve() through a symlink before checking it; Windows junctions are reparse.
    for path in reversed([target, *target.parents]):
        try:
            s = path.lstat()
        except FileNotFoundError:
            require(allow_missing and (path == target or root in path.parents), 'missing owned root/input')
            continue
        require(not stat.S_ISLNK(s.st_mode) and not (getattr(s, 'st_file_attributes', 0) & 0x400), 'link/reparse point forbidden: ' + str(path))
        require(stat.S_ISDIR(s.st_mode) if path != target else stat.S_ISREG(s.st_mode), 'not regular file/directory: ' + str(path))
        if path == target:
            require(s.st_nlink == 1, 'hardlinked file forbidden')
    return target


def _policy(policy):
    require(set(policy.owned_roots) == set(policy.root_kinds), 'root-kind mismatch')
    require(policy.owned_roots and policy.approved_path_roots and absolute(policy.log_base_root), 'missing root boundaries')
    roots = []
    for label, root in policy.owned_roots.items():
        relative_name(label)
        require('/' not in label, 'root label is not a component')
        require(policy.root_kinds[label] in {'source', 'generated', 'build', 'material'}, 'unapproved root kind')
        require(Path(root).is_absolute(), 'root not absolute')
        approved_path(str(root), policy)
        roots.append(path_key(str(root)).rstrip('\\'))
    require(len(set(roots)) == len(roots), 'duplicate owned root')
    # Generated include roots commonly sit below the stable build root. This
    # is the only permitted overlap; individual physical files remain unique.
    items = list(policy.owned_roots)
    for a, aroot in zip(items, roots):
        for b, broot in zip(items, roots):
            if a != b and aroot.startswith(broot + '\\'):
                require(policy.root_kinds[a] == 'generated' and policy.root_kinds[b] == 'build', 'overlapping owned roots')
    approved_path(policy.log_base_root, policy)
    require(all(type(v) is int and v > 0 for v in vars(policy.limits).values()), 'invalid bounds')
    require(policy.limits.member_bytes <= 536870912 and policy.limits.total_bytes <= 3221225472 and policy.limits.archive_bytes <= 400000000, 'limits exceed reviewed ceilings')
    require(len(policy.payloads)+1 <= policy.limits.members, 'payload plus manifest count bound')
    for group in (policy.payloads, policy.inputs):
        require(len(group) <= policy.limits.members, 'too many allowlisted files')
        seen, physical = set(), set()
        for spec in group:
            require(spec.root in policy.owned_roots and spec.kind in KINDS, 'unapproved file kind/root')
            relative_name(spec.member)
            require(spec.member.casefold() not in seen, 'duplicate/case-colliding allowlist')
            seen.add(spec.member.casefold())
            target = path_key(str(Path(policy.owned_roots[spec.root]) / spec.relpath))
            require(target not in physical, 'duplicate physical file through root aliases')
            physical.add(target)
    for spec in policy.inputs:
        require(spec.kind in {'source', 'header', 'material'} and policy.root_kinds[spec.root] in {'source', 'generated'}, 'input timestamp outside source/generated roots')
    for spec in policy.payloads:
        rk = policy.root_kinds[spec.root]
        if spec.kind in {'obj', 'lib', 'ninja_log', 'ninja_deps'}:
            require(rk == 'build', 'binary/state outside build root')
        elif spec.kind == 'header':
            require(rk in {'source', 'generated'} and spec in policy.inputs, 'generated header requires content-equality input guard')
        else:
            require(rk in {'source', 'generated', 'material'}, 'material outside approved material/source root')
    # Exactly one of each reviewed state file; no generic logs or other state.
    for kind, name in [('ninja_log', '.ninja_log'), ('ninja_deps', '.ninja_deps')]:
        matched = [s for s in policy.payloads if s.kind == kind]
        require(len(matched) == 1 and matched[0].relpath == name, 'exactly one ' + name + ' required')
    require({str(policy.owned_roots[s.root]) for s in policy.payloads if s.kind in {'ninja_log', 'ninja_deps'}} == {policy.log_base_root}, 'Ninja state must be at log base root')
    logical_spellings = {}
    for p in policy.allowed_log_inputs | policy.allowed_log_outputs:
        key = path_key(p)
        require(key not in logical_spellings or logical_spellings[key] == p, 'cross-set logical path alias')
        logical_spellings[key] = p
    for group in (policy.allowed_log_inputs, policy.allowed_log_outputs):
        keys = [path_key(p) for p in group]
        require(len(set(keys)) == len(keys), 'logical path aliases/case collisions')
        for p in group:
            approved_path(p, policy)


def _range(data, offset, size, label):
    require(offset >= 0 and size >= 0 and offset <= len(data) and size <= len(data)-offset, 'truncated ' + label)


def inspect_coff(data):
    """Recognized AMD64 relocatable COFF/BigObj only; reject import objects/PE."""
    require(len(data) >= 20, 'short COFF')
    if data[:4] == b'\0\0\xff\xff':
        require(len(data) >= 56, 'short BigObj')
        sig1, sig2, version, machine = struct.unpack_from('<HHHH', data)
        require(version == 2 and machine == 0x8664 and data[12:28] == BIGOBJ_ID, 'unsupported BigObj/import object')
        require(struct.unpack_from('<IIII', data, 28) == (0, 0, 0, 0), 'unsupported BigObj metadata')
        sections, symbols, count = struct.unpack_from('<III', data, 44)
        header, width = 56, 20
    else:
        machine, sections, timestamp, symbols, count, optional, flags = struct.unpack_from('<HHIIIHH', data)
        require(machine == 0x8664 and optional == 0 and not flags & 0x2002, 'not AMD64 relocatable COFF')
        header, width = 20, 18
    require(0 < sections <= 1_000_000, 'invalid COFF section count')
    _range(data, header, sections*40, 'COFF section table')
    table_end = header + sections*40
    for i in range(sections):
        at = header + i*40
        rawsize, raw, reloc, lines, nr, nl, flags = struct.unpack_from('<IIIIHHI', data, at+16)
        for ptr, size, label in [(raw, rawsize, 'section'), (lines, nl*6, 'line table')]:
            # Uninitialized sections may have size but no raw pointer.
            if ptr:
                require(ptr >= table_end, 'COFF data overlaps headers')
                _range(data, ptr, size, label)
            else:
                require(size == 0 or (label == 'section' and flags & 0x80), 'missing COFF data pointer')
        if flags & 0x1000000:
            require(nr == 65535 and reloc >= table_end, 'invalid relocation overflow')
            _range(data, reloc, 10, 'relocation overflow')
            nr = struct.unpack_from('<I', data, reloc)[0]
            require(nr >= 65535, 'invalid overflow count')
        if nr:
            require(reloc >= table_end, 'invalid relocation pointer')
            _range(data, reloc, nr*10, 'relocations')
        else:
            require(reloc == 0, 'unexpected relocation pointer')
    if symbols:
        require(symbols >= table_end, 'symbol table overlaps headers')
        _range(data, symbols, count*width+4, 'COFF symbols/string table')
        strings = symbols + count*width
        slen = struct.unpack_from('<I', data, strings)[0]
        require(slen >= 4, 'invalid COFF string table')
        _range(data, strings, slen, 'COFF strings')
        i = 0
        while i < count:
            aux = data[symbols+i*width+width-1]
            require(i+aux < count, 'COFF auxiliary symbol overrun')
            i += 1+aux
    else:
        require(count == 0, 'symbol count without pointer')
    return {'format': 'bigobj' if header == 56 else 'coff', 'machine': 'AMD64', 'sections': sections}


def _null_count(view):
    return sum(bytes(view[i:i+IO_CHUNK_BYTES]).count(b'\0') for i in range(0, len(view), IO_CHUNK_BYTES))


def inspect_archive(data):
    require(data.startswith(b'!<arch>\n'), 'not a regular COFF archive')
    pos, objects, longnames, symbol_count = 8, 0, None, 0
    object_offsets, symbol_offset_views = set(), []
    view = memoryview(data)
    while pos < len(data):
        _range(data, pos, 60, 'archive header')
        h = data[pos:pos+60]
        require(h[58:] == b'`\n', 'bad archive member trailer')
        require(re.fullmatch(rb'[0-9]+ *', h[48:58]) is not None, 'bad archive member size')
        size = int(h[48:58])
        at = pos+60
        _range(data, at, size, 'archive member')
        body = view[at:at+size]
        try:
            name = h[:16].decode('ascii').rstrip()
        except UnicodeError as exc:
            raise CheckpointError('non-ASCII archive name') from exc
        if name == '//':
            require(longnames is None, 'duplicate archive longnames')
            require(len(body) <= 16 * 1024 * 1024, 'archive longname table bound')
            longnames = bytes(body)
        elif name == '/':
            symbol_count += 1
            require(symbol_count <= 2 and size >= 4, 'unknown archive linker member')
            # COFF first linker member: BE count/offsets + NUL names. Second:
            # LE member-count/offsets + symbol-count/uint16 indices + NUL names.
            if symbol_count == 1:
                count = struct.unpack_from('>I', body)[0]
                _range(body, 4, count*4, 'first linker offsets')
                symbol_offset_views.append(('>I', body[4:4+count*4]))
                rest = body[4+count*4:]
                require(_null_count(rest) == count and (not rest or rest[-1] == 0), 'first linker names')
            else:
                count = struct.unpack_from('<I', body)[0]
                _range(body, 4, count*4+4, 'second linker offsets')
                symbol_offset_views.append(('<I', body[4:4+count*4]))
                p = 4+count*4
                n = struct.unpack_from('<I', body, p)[0]
                _range(body, p+4, n*2, 'second linker indices')
                indices = struct.iter_unpack('<H', body[p+4:p+4+n*2])
                require(all(1 <= i[0] <= count for i in indices), 'bad archive symbol index')
                rest = body[p+4+n*2:]
                require(_null_count(rest) == n and (not rest or rest[-1] == 0), 'second linker names')
        else:
            if name.startswith('/'):
                require(name[1:].isdigit() and longnames is not None, 'unknown archive metadata')
                off = int(name[1:])
                require(off < len(longnames) and (off == 0 or longnames[off-1] == 0), 'bad longname offset')
                end = longnames.find(b'\0', off)
                require(end >= 0, 'unterminated archive longname')
                name = longnames[off:end].decode('utf-8', errors='strict')
            else:
                require(name.endswith('/'), 'unrecognized short archive name')
                name = name[:-1]
            require(name.lower().endswith('.obj') and not any(c in name for c in '\r\n\0'), 'non-object archive member')
            inspect_coff(body)
            object_offsets.add(pos)
            objects += 1
        pos = at+size
        if size % 2:
            _range(data, pos, 1, 'archive padding')
            require(data[pos:pos+1] == b'\n', 'noncanonical archive padding')
            pos += 1
    require(objects > 0 and pos == len(data), 'empty/truncated archive')
    require(all(offset[0] in object_offsets for fmt, offsets in symbol_offset_views for offset in struct.iter_unpack(fmt, offsets)), 'archive symbol points outside object member')
    return {'format': 'coff-archive', 'machine': 'AMD64', 'objects': objects}


def validate_ninja_log(data, policy):
    require(data.startswith(b'# ninja log v6\n'), 'unsupported Ninja build-log version')
    require(data.endswith(b'\n'), 'truncated Ninja build log')
    lines = data.splitlines()[1:]
    require(len(lines) <= policy.limits.log_records, 'too many log records')
    outputs = {path_key(p) for p in policy.allowed_log_outputs}
    for line in lines:
        fields = line.split(b'\t')
        require(len(fields) == 5, 'unknown Ninja build-log record')
        require(all(re.fullmatch(rb'[0-9]+', p) for p in fields[:3]), 'invalid Ninja log times')
        start, end, mtime = map(int, fields[:3])
        require(start <= end <= 2**63-1 and mtime <= 2**63-1, 'out-of-range Ninja times')
        require(re.fullmatch(rb'[0-9a-fA-F]{1,16}', fields[4]) is not None, 'invalid command hash')
        path = fields[3].decode('utf-8', errors='strict')
        require(path_key(path) in outputs, 'unknown build-log output: ' + path)
        approved_path(path, policy)
    return len(lines)


def validate_ninja_deps(data, policy):
    require(len(data) >= 16 and data[:12] == b'# ninjadeps\n' and struct.unpack_from('<I', data, 12)[0] == 4, 'unsupported Ninja dependency-log version')
    allowed = {path_key(p) for p in policy.allowed_log_inputs | policy.allowed_log_outputs}
    outputs = {path_key(p) for p in policy.allowed_log_outputs}
    paths, seen, records, pos = [], set(), 0, 16
    while pos < len(data):
        _range(data, pos, 4, 'dependency record length')
        word = struct.unpack_from('<I', data, pos)[0]
        dep = bool(word & 0x80000000)
        size = word & 0x7fffffff
        require(size >= (12 if dep else 8) and size % 4 == 0 and size <= 0x7fffffff, 'unknown/malformed dependency record')
        pos += 4
        _range(data, pos, size, 'dependency record')
        if dep:
            output, lo, hi = struct.unpack_from('<III', data, pos)
            require(output < len(paths) and path_key(paths[output]) in outputs, 'unknown dependency output')
            require((hi << 32 | lo) <= 2**63-1, 'invalid dependency mtime')
            for i in range(pos+12, pos+size, 4):
                require(struct.unpack_from('<I', data, i)[0] < len(paths), 'unknown dependency path id')
        else:
            raw = data[pos:pos+size-4]
            path_bytes = raw.rstrip(b'\0')
            require(0 <= len(raw)-len(path_bytes) <= 3 and path_bytes and b'\0' not in path_bytes, 'invalid dependency path padding')
            path = path_bytes.decode('utf-8', errors='strict')
            require(struct.unpack_from('<I', data, pos+size-4)[0] == ((~len(paths)) & 0xffffffff), 'dependency path checksum/id mismatch')
            key = path_key(path)
            require(key in allowed and key not in seen, 'unknown/duplicate dependency path: ' + path)
            approved_path(path, policy)
            seen.add(key)
            paths.append(path)
        pos += size
        records += 1
        require(records <= policy.limits.log_records, 'too many dependency records')
    return {'paths': len(paths), 'records': records, 'complete_include_inventory': False}


def _material_bytes(data):
    """Allow reviewed public bytes, never executable/archive/system payloads.

    Provenance is supplied by the caller's exact pinned material inventory, not
    inferred from this format filter. PDF and legacy encodings need no decoder.
    """
    signatures = (b'MZ', b'!<arch>\n', b'!<thin>\n', b'\x7fELF',
        b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08', b'7z\xbc\xaf\x27\x1c',
        b'Rar!\x1a\x07', b'\x1f\x8b', b'BZh', b'\xfd7zXZ\0', b'MSCF',
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', b'MDMP',
        b'Microsoft C/C++ MSF', b'Microsoft C/C++ program database',
        b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
        b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
        b'\0\0\xff\xff')
    require(not data.startswith(signatures), 'executable/archive/dump material signature')
    require(data[257:262] != b'ustar', 'tar archive material forbidden')
    # A raw relocatable COFF object must not bypass the obj gate by being renamed.
    if len(data) >= 20 and struct.unpack_from('<H', data)[0] in {0x14c, 0x8664, 0x1c0, 0x1c4, 0xaa64}:
        require(False, 'COFF/system binary material forbidden')


def _content(spec, data, policy):
    require(len(data) <= policy.limits.member_bytes, 'member content byte bound')
    suffix = Path(spec.relpath).suffix.lower()
    if spec.kind == 'obj':
        require(suffix == '.obj', 'object suffix')
        inspect_coff(data)
        inspect_public_paths(data, policy)
    elif spec.kind == 'lib':
        require(suffix == '.lib', 'library suffix')
        inspect_archive(data)
        inspect_public_paths(data, policy)
    elif spec.kind == 'ninja_log':
        validate_ninja_log(data, policy)
    elif spec.kind == 'ninja_deps':
        validate_ninja_deps(data, policy)
    else:
        require(suffix not in FORBIDDEN and Path(spec.relpath).name not in {'CMakeCache.txt', 'build.ninja', 'rules.ninja'}, 'forbidden source/material payload')
        if spec.kind == 'header':
            require(suffix in {'.h', '.hh', '.hpp', '.hxx', '.inc'}, 'header suffix')
        _material_bytes(data)
        if spec.kind != 'material':
            require(b'\0' not in data, 'binary text source/header/license forbidden; use explicit material kind for public nontext')
            data.decode('utf-8', errors='strict')
            inspect_public_paths(data, policy)
        # Explicit public material is hash-bound to the driver's pinned source
        # inventory. Its literals can document arbitrary example paths; they
        # are not producer debug paths. Do not scan these source bytes as if
        # they were binary/metadata paths. File/root and format gates still apply.


def _read(spec, policy):
    path = _safe_path(policy, spec)
    before = path.stat()
    require(before.st_size <= policy.limits.member_bytes, 'member size bound')
    with path.open('rb') as f:
        data = f.read(before.st_size+1)
    after = path.stat()
    require(len(data) == before.st_size and (before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino), 'file changed during inventory')
    require(0 <= before.st_mtime_ns <= 2**63-1, 'invalid filesystem timestamp')
    entry = {'member': spec.member, 'kind': spec.kind, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mtime_ns': before.st_mtime_ns}
    return entry, data


def _json(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _outer_path(path, *, missing=False):
    path = Path(path).absolute()
    for item in reversed([path, *path.parents]):
        try:
            s = item.lstat()
        except FileNotFoundError:
            require(missing and item == path, 'missing outer path parent/file')
            continue
        require(not stat.S_ISLNK(s.st_mode) and not (getattr(s, 'st_file_attributes', 0) & 0x400), 'outer path link/reparse point')
        require(stat.S_ISREG(s.st_mode) if item == path else stat.S_ISDIR(s.st_mode), 'invalid outer path type')
    return path


def _fingerprint(path):
    h, size = hashlib.sha256(), 0
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
            size += len(block)
    return {'bytes': size, 'sha256': h.hexdigest()}


def _zip_info(name):
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def seal_checkpoint(path, policy, metadata, boundary_check: BoundaryCheck | None = None):
    """Seal only explicit payloads. Callback may raise to enforce material receipts."""
    _policy(policy)
    metadata_paths(metadata, policy)
    path = _outer_path(path, missing=True)
    require(not path.exists() and not path.is_symlink(), 'checkpoint destination already exists')
    require(path.parent.is_dir() and not path.parent.is_symlink(), 'checkpoint parent missing/link')
    manifest = {'schema': 1, 'metadata': metadata, 'owned_roots': {k: str(v) for k, v in policy.owned_roots.items()}, 'inputs': [], 'payloads': []}
    total = 0
    for spec in policy.inputs:
        entry, data = _read(spec, policy)
        _content(spec, data, policy)
        manifest['inputs'].append(entry)
        del data
    fd, temporary = tempfile.mkstemp(prefix='.checkpoint-', suffix='.zip', dir=path.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=False) as archive:
            for spec in policy.payloads:
                entry, data = _read(spec, policy)
                _content(spec, data, policy)
                if boundary_check:
                    boundary_check('seal', spec, data)
                total += len(data)
                require(total <= policy.limits.total_bytes, 'uncompressed size bound')
                manifest['payloads'].append(entry)
                # Stream compression from the single bounded member buffer; do
                # not make a second whole-member compressed-output allocation.
                with archive.open(_zip_info(spec.member), 'w') as member:
                    view = memoryview(data)
                    for offset in range(0, len(data), IO_CHUNK_BYTES):
                        member.write(view[offset:offset+IO_CHUNK_BYTES])
                    del view
                del data
            if boundary_check:
                boundary_check('manifest', None, manifest)
            raw = _json(manifest)
            require(len(raw) <= policy.limits.manifest_bytes and total+len(raw) <= policy.limits.total_bytes, 'manifest/total size bound')
            archive.writestr(_zip_info(MANIFEST), raw)
        require(os.path.getsize(temporary) <= policy.limits.archive_bytes, 'outer archive size bound')
        # Recheck source bytes AND mtime after sealing outputs, without publishing.
        for spec, entry in zip(policy.inputs, manifest['inputs']):
            current, _ = _read(spec, policy)
            require(current == entry, 'source drift during seal')
            del _
        os.replace(temporary, path)
        return _fingerprint(path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _no_duplicate_json(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, 'duplicate JSON key')
        result[k] = v
    return result


def _entry(entry, spec, policy):
    require(isinstance(entry, dict) and set(entry) == {'member', 'kind', 'size', 'sha256', 'mtime_ns'}, 'unexpected manifest entry fields')
    require(entry['member'] == spec.member and entry['kind'] == spec.kind, 'manifest differs from explicit allowlist')
    require(type(entry['size']) is int and 0 <= entry['size'] <= policy.limits.member_bytes, 'invalid member size')
    require(type(entry['mtime_ns']) is int and 0 <= entry['mtime_ns'] <= 2**63-1, 'invalid member mtime')
    require(isinstance(entry['sha256'], str) and re.fullmatch('[0-9a-f]{64}', entry['sha256']) is not None, 'invalid member hash')


def _equal(entry, data):
    require(len(data) == entry['size'] and hashlib.sha256(data).hexdigest() == entry['sha256'], 'member hash/size mismatch: ' + entry['member'])


def validate_checkpoint(path, policy, expected_sha256, expected_size, expected_metadata, boundary_check: BoundaryCheck | None = None):
    """Read-only validation, including fresh local input content equality.

    Caller must get expected outer identity from the exact approved producer,
    not from this archive. Returns parsed manifest only after all gates pass.
    """
    _policy(policy)
    require(type(expected_size) is int and 0 <= expected_size <= policy.limits.archive_bytes, 'invalid expected outer size')
    require(isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None, 'invalid expected outer hash')
    path = _outer_path(path)
    require(path.is_file() and not path.is_symlink() and not (getattr(path.lstat(), 'st_file_attributes', 0) & 0x400), 'invalid outer file')
    require(path.stat().st_size == expected_size, 'outer size mismatch')
    require(_fingerprint(path) == {'bytes': expected_size, 'sha256': expected_sha256}, 'outer hash mismatch')
    expected_names = {s.member for s in policy.payloads} | {MANIFEST}
    with zipfile.ZipFile(path) as archive:
        require(not archive.comment, 'archive comment forbidden')
        infos = archive.infolist()
        require(len(infos) == len(expected_names) <= policy.limits.members, 'archive member count mismatch/bound')
        names, folded, total = set(), set(), 0
        for info in infos:
            relative_name(info.filename)
            require(info.filename not in names and info.filename.casefold() not in folded, 'duplicate/case-colliding ZIP member')
            names.add(info.filename)
            folded.add(info.filename.casefold())
            mode = info.external_attr >> 16
            require(not info.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG) and not (info.external_attr & 0x400), 'ZIP link/reparse/special member')
            require(not info.extra and not info.comment and not info.flag_bits & 1 and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'unsupported ZIP metadata/encryption/compression')
            bound = policy.limits.manifest_bytes if info.filename == MANIFEST else policy.limits.member_bytes
            require(info.file_size <= bound and info.compress_size <= expected_size, 'ZIP member size bound')
            total += info.file_size
            require(total <= policy.limits.total_bytes, 'ZIP total size bound')
        require(names == expected_names, 'unexpected/missing ZIP member')
        manifest = json.loads(archive.read(MANIFEST), object_pairs_hook=_no_duplicate_json)
        require(isinstance(manifest, dict) and set(manifest) == {'schema', 'metadata', 'owned_roots', 'inputs', 'payloads'} and type(manifest['schema']) is int and manifest['schema'] == 1, 'unknown manifest schema/fields')
        require(manifest['owned_roots'] == {k: str(v) for k, v in policy.owned_roots.items()}, 'stable owned root mismatch')
        require(manifest['metadata'] == expected_metadata, 'immutable metadata drift')
        metadata_paths(manifest['metadata'], policy)
        for label, specs in [('inputs', policy.inputs), ('payloads', policy.payloads)]:
            require(isinstance(manifest[label], list) and len(manifest[label]) == len(specs), 'manifest allowlist length mismatch')
            for entry, spec in zip(manifest[label], specs):
                _entry(entry, spec, policy)
                if label == 'inputs':
                    current, data = _read(spec, policy)
                    _equal(entry, data)  # mtime changes alone are restorable.
                    _content(spec, data, policy)
                else:
                    require(archive.getinfo(spec.member).file_size == entry['size'], 'ZIP/manifest size mismatch')
                    data = archive.read(spec.member)
                    _equal(entry, data)
                    _content(spec, data, policy)
                    if policy.root_kinds[spec.root] in {'source', 'generated'}:
                        # These destinations are fresh, owned source/header trees,
                        # not output space. Never overwrite/backdate drifted data.
                        _, existing = _read(spec, policy)
                        _equal(entry, existing)
                        del existing
                    if boundary_check:
                        boundary_check('validate', spec, data)
                del data
        if boundary_check:
            boundary_check('manifest', None, manifest)
    return manifest


def _mtime(path, value):
    os.utime(path, ns=(path.stat().st_atime_ns, value), follow_symlinks=False)
    require(path.stat().st_mtime_ns == value, 'filesystem cannot preserve exact mtime_ns')


def restore_checkpoint(path, policy, expected_sha256, expected_size, expected_metadata, boundary_check: BoundaryCheck | None = None):
    """Validate everything first, restore explicit outputs, then source mtimes.

    Failure never launches a build. On I/O failure partial owned outputs may
    remain; caller must stop and clean its owned root, never silently fall back.
    """
    manifest = validate_checkpoint(path, policy, expected_sha256, expected_size, expected_metadata, boundary_check)
    # Preflight every destination before the first modification.
    for spec in policy.payloads:
        _safe_path(policy, spec, allow_missing=True)
    with zipfile.ZipFile(path) as archive:
        for spec, entry in zip(policy.payloads, manifest['payloads']):
            dest = _safe_path(policy, spec, allow_missing=True)
            data = archive.read(spec.member)
            _equal(entry, data)
            if policy.root_kinds[spec.root] in {'source', 'generated'}:
                _, current = _read(spec, policy)
                _equal(entry, current)
                del current
            dest.parent.mkdir(parents=True, exist_ok=True)
            _safe_path(policy, spec, allow_missing=True)
            fd, temporary = tempfile.mkstemp(prefix='.checkpoint-member-', dir=dest.parent)
            try:
                with os.fdopen(fd, 'wb') as out:
                    view = memoryview(data)
                    for offset in range(0, len(data), IO_CHUNK_BYTES):
                        out.write(view[offset:offset+IO_CHUNK_BYTES])
                    del view
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(temporary, dest)
                _mtime(dest, entry['mtime_ns'])
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            del data
    for spec, entry in zip(policy.inputs, manifest['inputs']):
        _, data = _read(spec, policy)
        _equal(entry, data)  # equality is immediately before touching each source.
        _mtime(_safe_path(policy, spec), entry['mtime_ns'])
        del data
    for label, specs in [('inputs', policy.inputs), ('payloads', policy.payloads)]:
        for spec, entry in zip(specs, manifest[label]):
            current, data = _read(spec, policy)
            require(current == entry, 'post-restore hash/size/mtime mismatch')
            del data
    return manifest
