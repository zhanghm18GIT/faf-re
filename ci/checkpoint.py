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
from contextlib import contextmanager
from bisect import bisect_left
from dataclasses import dataclass, field, replace
from typing import Callable, Mapping


class CheckpointError(ValueError):
    def __init__(self, message, *, code=None, signature_id=None, rule=None, details=None):
        super().__init__(message)
        self.code = code
        self.signature_id = signature_id
        self.rule = rule
        self.details = details



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
    approved_path_files: tuple[str, ...] = ()  # Exact logical-path admission only, never a directory/payload grant.
    material_text_pins: Mapping[str, str] = field(default_factory=dict)
    public_literal_rules: tuple[str, ...] = ()  # Reviewed IDs only; no caller-provided strings, roots, offsets or hashes.


MANIFEST = 'checkpoint-manifest.json'
KINDS = {'obj', 'lib', 'header', 'ninja_log', 'ninja_deps', 'source', 'license', 'material'}
FORBIDDEN = {'.exe', '.dll', '.pdb', '.ilk', '.exp', '.dmp', '.zip', '.7z', '.gz', '.tgz', '.tar', '.bz2', '.xz', '.rar', '.log', '.a', '.so', '.dylib', '.o', '.obj', '.lib', '.bin', '.msi', '.cab', '.sys', '.com', '.scr'}
MATERIAL_TEXT_MAX_BYTES = 16 * 1024
HEADER_SUFFIXES = frozenset({'.h', '.hh', '.hpp', '.hxx', '.inc', '.inl'})
DEFERRED_KINDS = frozenset({'obj', 'lib', 'ninja_log', 'ninja_deps'})
BIGOBJ_ID = bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')
BoundaryCheck = Callable[[str, FileSpec | None, bytes | dict], None]


# Public wx 2.4.2 Windows PostScript default, not a build-worker path.
# This is intentionally not a general literal allowlist. Unknown IDs fail closed.
WX_LITERAL_RULE = 'wx242-msw-afm-default-v1'
WX_LITERAL_SOURCE = 'dependencies/wxWindows-2.4.2/src/common/cmndata.cpp'
WX_LITERAL_SOURCE_SHA256 = 'd7b4712ce7b1cdee89a4c44fb49848fc3143bf8be38c3ed30ea3b2996e0cfb2c'
WX_LITERAL_OBJECT = 'cmake/deps/wxwindows/CMakeFiles/wxmswu.dir/__/__/__/dependencies/wxWindows-2.4.2/src/common/cmndata.cpp.obj'
WX_LITERAL_LIBRARY = 'cmake/deps/wxwindows/wxmswu.lib'
WX_LITERAL_SYMBOL = b'??_C@_1CG@ENHPNFKP@?$AAc?$AA?3?$AA?2?$AAw?$AAi?$AAn?$AAd?$AAo?$AAw?$AAs?$AA?2?$AAs?$AAy?$AAs?$AAt?$AAe?$AAm?$AA?2?$AA?$AA@'
WX_LITERAL_BYTES = ('c:' + chr(92) + 'windows' + chr(92) + 'system' + chr(92) + chr(0)).encode('utf-16le')


def _public_literal_provenance(policy):
    require(type(policy.public_literal_rules) is tuple and policy.public_literal_rules in ((), (WX_LITERAL_RULE,)), 'unknown/duplicate public literal rule')
    if not policy.public_literal_rules:
        return False
    source = FileSpec('source', WX_LITERAL_SOURCE, 'material')
    require(source in policy.inputs and policy.root_kinds.get('source') == 'source', 'public literal source is not a declared source input')
    require(FileSpec('build', WX_LITERAL_OBJECT, 'obj') in policy.payloads and FileSpec('build', WX_LITERAL_LIBRARY, 'lib') in policy.payloads, 'public literal outputs are not declared exact payloads')
    path = _safe_path(policy, source)
    require(path.is_file() and path.stat().st_size <= 128000, 'missing/oversized public literal source')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == WX_LITERAL_SOURCE_SHA256, 'public literal source pin mismatch')
    return True


def _public_literal_ranges(data, policy, spec, archive_name=None):
    if not policy.public_literal_rules:
        return []
    _public_literal_provenance(policy)
    if spec == FileSpec('build', WX_LITERAL_OBJECT, 'obj'):
        require(archive_name is None, 'unexpected public literal archive identity')
    elif spec == FileSpec('build', WX_LITERAL_LIBRARY, 'lib'):
        # llvm-lib preserves the relative input path in its longname table.
        # Also recognize the absolute spelling only at the approved build root.
        names = {WX_LITERAL_OBJECT.replace('/', chr(92)), WX_LITERAL_OBJECT}
        root = str(policy.owned_roots['build']).rstrip('/' + chr(92))
        names |= {root + '/' + WX_LITERAL_OBJECT, root.replace('/', chr(92)) + chr(92) + WX_LITERAL_OBJECT.replace('/', chr(92))}
        if archive_name not in names:
            return []
    else:
        return []
    # inspect_coff has already bounded headers, symbols and every section.
    big = bytes(data[:4]) == b'\0\0\xff\xff'
    header = 56 if big else 20
    sections = struct.unpack_from('<I' if big else '<H', data, 44 if big else 2)[0]
    ranges = []
    extents = []
    metadata_extents = []
    for i in range(sections):
        at = header + i * 40
        size, start = struct.unpack_from('<II', data, at + 16)
        flags = struct.unpack_from('<I', data, at + 36)[0]
        rp, lp, nr, nl = struct.unpack_from('<IIHH', data, at + 24)
        if flags & 0x1000000:
            nr = struct.unpack_from('<I', data, rp)[0]
        if nr: metadata_extents.append((rp, rp + nr * 10))
        if nl: metadata_extents.append((lp, lp + nl * 6))
        if size and start:
            extents.append((start, start + size, i))
        # An entire dedicated, immutable string COMDAT, not an arbitrary match
        # inside rdata. Exact size/value includes its UTF-16 NUL terminator.
        if bytes(data[at:at+8]) != b'.rdata\0\0' or flags != 0x40201040:
            continue
        if size != len(WX_LITERAL_BYTES) or bytes(data[start:start+size]) != WX_LITERAL_BYTES:
            continue
        reloc, lines, nr, nl = struct.unpack_from('<IIHH', data, at + 24)
        if reloc or lines or nr or nl:
            continue
        ranges.append((start, start + size, i))
    # Refuse overlapping section aliases; masking must never hide debug bytes.
    result = []
    for start, end, number in ranges:
        require(not any(other != number and start < b and a < end for a,b,other in extents), 'public literal section overlaps another section')
        symbols = struct.unpack_from('<I', data, 48 if big else 8)[0]
        require(symbols and end <= symbols, 'public literal missing/overlapping symbols')
        require(not any(start < b and a < end for a,b in metadata_extents), 'public literal overlaps COFF metadata')
        require(_public_literal_symbols(data, number + 1, big), 'public literal lacks canonical string COMDAT symbols')
        result.append((start, end))
    require(len(result) <= 1, 'duplicate public literal section')
    return result


def _public_literal_symbols(data, section, big):
    width = 20 if big else 18
    symbols, count = struct.unpack_from('<II', data, 48 if big else 8)
    strings = symbols + count * width
    slen = struct.unpack_from('<I', data, strings)[0]
    section_defs = literal_defs = 0
    i = 0
    while i < count:
        at = symbols + i * width
        name = bytes(data[at:at+8])
        if name[:4] == b'\0' * 4:
            off = struct.unpack_from('<I', name, 4)[0]
            require(4 <= off < slen, 'public literal invalid symbol string offset')
            tail = bytes(data[strings+off:strings+slen])
            end = tail.find(b'\0')
            require(end >= 0, 'public literal unterminated symbol name')
            name = tail[:end]
        else:
            name = name.rstrip(b'\0')
        value = struct.unpack_from('<I', data, at+8)[0]
        sec = struct.unpack_from('<i' if big else '<h', data, at+12)[0]
        typ, storage, aux = struct.unpack_from('<HBB', data, at+(16 if big else 14))
        if sec == section:
            if name == b'.rdata' and value == typ == 0 and storage == 3 and aux == 1:
                a = at + width
                length, nr, nl, crc, number, selection = struct.unpack_from('<IHHIHB', data, a)
                high = struct.unpack_from('<H', data, a+16)[0]
                require(length == len(WX_LITERAL_BYTES) and nr == nl == 0 and crc == 0x2A79B1E3 and (number | (high << 16)) == section and selection == 2, 'public literal invalid COMDAT definition')
                section_defs += 1
            elif name == WX_LITERAL_SYMBOL and value == typ == aux == 0 and storage == 2:
                literal_defs += 1
            else:
                return False
        i += 1 + aux
    return section_defs == literal_defs == 1


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
    exact = {path_key(p) for p in policy.approved_path_files}
    require(key in exact or any(key == r or key.startswith(r + '\\') for r in roots), 'unapproved stable path: ' + path)


SCAN_CHUNK_BYTES = 1024 * 1024
IO_CHUNK_BYTES = 1024 * 1024


def inspect_public_paths(data, policy):
    return _inspect_public_paths(data, policy, ())


def _inspect_public_paths(data, policy, validated_ranges):
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
    ends = [b for a, b in validated_ranges]
    require(all(0 <= a < b <= len(data) and (i == 0 or validated_ranges[i-1][1] <= a) for i, (a, b) in enumerate(validated_ranges)), "invalid validated format spans")
    for start in range(0, len(data), SCAN_CHUNK_BYTES):
        lo, hi = max(0, start-overlap), min(len(data), start+SCAN_CHUNK_BYTES+overlap)
        block = bytearray(view[lo:hi])
        # Mask only previously parsed, canonically decoded and root-checked
        # CodeView command strings or fully checked archive numeric arrays.
        # Never mask a whole record, object, symbol string or archive member.
        i = bisect_left(ends, lo+1)
        while i < len(validated_ranges) and validated_ranges[i][0] < hi:
            a, b = validated_ranges[i]
            left, right = max(a, lo)-lo, min(b, hi)-lo
            block[left:right] = b"\0" * (right-left)
            i += 1
        block = bytes(block)
        # One bounded decoded view at a time. Both UTF16 alignments are checked;
        # replacement, rather than deletion, preserves invalid-byte boundaries.
        for encoding, offset, runs in [('latin1', 0, ascii_runs), ('utf-16le', 0, wide_runs), ('utf-16le', 1, wide_runs)]:
            if encoding == 'latin1':
                text = block.decode('latin1')
            else:
                text = block[offset:len(block)-((len(block)-offset) % 2)].decode(encoding, errors='replace')
            for run in runs.finditer(text):
                for match in pattern.finditer(text, run.start(), run.end()):
                    token_offset = lo+offset+match.start()*(1 if encoding=='latin1' else 2)
                    if not start <= token_offset < min(len(data), start+SCAN_CHUNK_BYTES):
                        continue  # Exactly one primary window owns the token; overlap is context only.
                    tail = text[match.start():min(run.end(), match.start()+span)].replace('/', '\\').casefold()
                    if not any(tail.startswith(root + '\\') or tail == root for root in roots):
                        raise CheckpointError('unapproved embedded absolute path', code='embedded_path_rejected', rule='absolute_path_outside_roots', details={'byte_offset': token_offset, 'encoding': 'ascii' if encoding=='latin1' else 'utf16le'})
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
    _public_literal_provenance(policy)
    require(set(policy.owned_roots) == set(policy.root_kinds), 'root-kind mismatch')
    require(policy.owned_roots and policy.approved_path_roots and absolute(policy.log_base_root), 'missing root boundaries')
    require(len(policy.approved_path_files) <= 16, 'exact external-file count bound')
    exact = [path_key(p) for p in policy.approved_path_files]
    require(len(set(exact)) == len(exact) and all(ntpath.isabs(p) for p in policy.approved_path_files), 'invalid exact external-file declaration')
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
    require(policy.limits.manifest_bytes <= 25_165_824, 'manifest metadata capacity exceeds reviewed 24 MiB ceiling')
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
    require(isinstance(policy.material_text_pins, Mapping) and len(policy.material_text_pins) <= 16, 'material text pin count/type bound')
    pin_names = set()
    for member, digest in policy.material_text_pins.items():
        relative_name(member)
        require(member.casefold() not in pin_names, 'material text pin case collision')
        pin_names.add(member.casefold())
        declared = [spec for spec in policy.inputs + policy.payloads if spec.member == member]
        require(declared and all(spec.kind == 'material' and Path(spec.relpath).suffix.lower() == '.com' for spec in declared), 'text pin requires declared material .com member')
        require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest) is not None, 'invalid material text pin hash')
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


def validate_policy(policy, metadata=None):
    """Validate all declarations before expensive work; no payload-read/pass claim."""
    _policy(policy)
    if metadata is not None:
        metadata_paths(metadata, policy)
    return {'state': 'PASS_DECLARATIONS_ONLY', 'payload_count': len(policy.payloads),
            'input_count': len(policy.inputs), 'exact_external_file_count': len(policy.approved_path_files)}


def _range(data, offset, size, label):
    require(offset >= 0 and size >= 0 and offset <= len(data) and size <= len(data)-offset, 'truncated ' + label)


_COFF_RULES = {'short COFF': 'coff_short_coff', 'short BigObj': 'coff_short_bigobj', 'unsupported BigObj/import object': 'coff_unsupported_bigobj_import_object', 'unsupported BigObj metadata': 'coff_unsupported_bigobj_metadata', 'not AMD64 relocatable COFF': 'coff_not_amd64_relocatable_coff', 'invalid COFF section count': 'coff_invalid_coff_section_count', 'truncated COFF section table': 'coff_truncated_coff_section_table', 'COFF data overlaps headers': 'coff_coff_data_overlaps_headers', 'truncated section': 'coff_truncated_section', 'truncated line table': 'coff_truncated_line_table', 'missing COFF data pointer': 'coff_missing_coff_data_pointer', 'invalid relocation overflow': 'coff_invalid_relocation_overflow', 'truncated relocation overflow': 'coff_truncated_relocation_overflow', 'invalid overflow count': 'coff_invalid_overflow_count', 'invalid relocation pointer': 'coff_invalid_relocation_pointer', 'truncated relocations': 'coff_truncated_relocations', 'unexpected relocation pointer': 'coff_unexpected_relocation_pointer', 'symbol table overlaps headers': 'coff_symbol_table_overlaps_headers', 'truncated COFF symbols/string table': 'coff_truncated_coff_symbols_string_table', 'invalid COFF string table': 'coff_invalid_coff_string_table', 'truncated COFF strings': 'coff_truncated_coff_strings', 'COFF auxiliary symbol overrun': 'coff_coff_auxiliary_symbol_overrun', 'symbol count without pointer': 'coff_symbol_count_without_pointer'}


def inspect_coff(data):
    try:
        return _inspect_coff_structure(data)
    except CheckpointError as exc:
        summary = {'bytes': len(data)}
        if len(data) >= 8:
            if data[:4] == b'\0\0\xff\xff':
                summary.update(format='bigobj_or_import', version=struct.unpack_from('<H', data, 4)[0], machine=struct.unpack_from('<H', data, 6)[0])
                if len(data) >= 56:
                    summary.update(sections=struct.unpack_from('<I', data, 44)[0], symbol_count=struct.unpack_from('<I', data, 52)[0])
            else:
                summary.update(format='coff', machine=struct.unpack_from('<H', data)[0], sections=struct.unpack_from('<H', data, 2)[0])
                if len(data) >= 20:
                    summary.update(symbol_count=struct.unpack_from('<I', data, 12)[0], optional_header_bytes=struct.unpack_from('<H', data, 16)[0])
        rule = _COFF_RULES.get(str(exc), 'coff_structure_other')
        raise CheckpointError(str(exc), code='coff_structure_rejected', rule=rule, details=summary) from None


def _inspect_coff_structure(data):
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


_ARCHIVE_SYMBOL_NAME_CODES = frozenset({
    'archive_symbol_name_count',
    'archive_symbol_name_empty',
    'archive_symbol_name_unterminated',
    'archive_symbol_name_padding',
})


def _archive_symbol_names(body_tail, count):
    """Validate exactly count nonempty NUL names, then optional canonical pad.

    Legacy unpadded name tails remain accepted. LLVM's single internal NUL pad
    is accepted only after an odd-sized name area. The caller retains member
    bounds, external newline alignment, offsets, indices, and object checks.
    Scan in bounded chunks; never copy the whole member or expose its contents.
    """
    def reject(code):
        raise CheckpointError(code, code=code)

    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        reject('archive_symbol_name_count')
    view = memoryview(body_tail).cast('B')
    if count > len(view) // 2:
        reject('archive_symbol_name_count')
    if count == 0:
        if len(view):
            reject('archive_symbol_name_padding')
        return
    seen = pending = 0
    for base in range(0, len(view), IO_CHUNK_BYTES):
        chunk = bytes(view[base:base + IO_CHUNK_BYTES])
        cursor = 0
        while seen < count:
            end = chunk.find(b'\0', cursor)
            if end < 0:
                pending += len(chunk) - cursor
                break
            if pending + end - cursor == 0:
                reject('archive_symbol_name_empty')
            seen += 1
            pending = 0
            cursor = end + 1
        if seen == count:
            consumed = base + cursor
            remaining = len(view) - consumed
            if remaining == 0:
                return
            if remaining == 1 and consumed % 2 == 1 and view[consumed] == 0:
                return
            reject('archive_symbol_name_padding')
    reject('archive_symbol_name_unterminated')


def inspect_archive(data, *, object_spans=None, named_object_spans=None, numeric_spans=None, regions=None):
    require(data.startswith(b'!<arch>\n'), 'not a regular COFF archive')
    pos, objects, longnames, symbol_count = 8, 0, None, 0
    object_offsets, symbol_offset_views = set(), []
    checked_numeric, checked_regions = [], []
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
        checked_regions.append((pos, at, 'archive_header', 0))
        try:
            name = h[:16].decode('ascii').rstrip()
        except UnicodeError as exc:
            raise CheckpointError('non-ASCII archive name') from exc
        if name == '//':
            require(longnames is None, 'duplicate archive longnames')
            require(len(body) <= 16 * 1024 * 1024, 'archive longname table bound')
            longnames = bytes(body)
            checked_regions.append((at, at+size, 'archive_longnames', 0))
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
                _archive_symbol_names(rest, count)
                checked_numeric.append((at, at+4+count*4))
                checked_regions.append((at, at+4+count*4, 'archive_first_linker_numbers', 0))
                checked_regions.append((at+4+count*4, at+size, 'archive_symbol_names', 0))
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
                _archive_symbol_names(rest, n)
                # These are typed counts/offsets/member references, not strings. Legal
                # indices such as 99,58,92,100 happen to spell UTF16 c:\d.
                # Admit only exact parsed numeric fields, after all archive checks.
                checked_numeric.append((at, at+p+4+n*2))
                checked_regions.append((at, at+p+4, 'archive_second_linker_numbers', 0))
                checked_regions.append((at+p+4, at+p+4+n*2, 'archive_second_linker_indices', 0))
                checked_regions.append((at+p+4+n*2, at+size, 'archive_symbol_names', 0))
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
            if object_spans is not None:
                object_spans.append((at, at+size))
            if named_object_spans is not None:
                named_object_spans.append((at, at+size, name))
            object_offsets.add(pos)
            objects += 1
            checked_regions.append((at, at+size, 'archive_object', objects))
        pos = at+size
        if size % 2:
            _range(data, pos, 1, 'archive padding')
            require(data[pos:pos+1] == b'\n', 'noncanonical archive padding')
            pos += 1
    require(objects > 0 and pos == len(data), 'empty/truncated archive')
    require(all(offset[0] in object_offsets for fmt, offsets in symbol_offset_views for offset in struct.iter_unpack(fmt, offsets)), 'archive symbol points outside object member')
    if numeric_spans is not None: numeric_spans.extend(checked_numeric)
    if regions is not None: regions.extend(checked_regions)
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


_CODEVIEW_RULES = frozenset({'cv_section_signature','cv_record_bounds','cv_record_count','cv_record_alignment','cv_buildinfo_shape','cv_buildinfo_padding','cv_command_reference','cv_string_shape','cv_string_padding','cv_string_utf8','cv_command_quotes','cv_command_escape','cv_command_separator','cv_command_canonical','cv_command_frontend','cv_command_controls','cv_decoded_path','cv_external_type_server'})
_SAFE_FORMAT_RULES = frozenset(_COFF_RULES.values()) | _CODEVIEW_RULES | {'coff_structure_other','archive_structure_rule','archive_symbol_names','absolute_path_outside_roots'}


def _cv_fail(rule, *, section=0, offset=0, index=0):
    raise CheckpointError('CodeView command validation rejected', code='codeview_command_rejected', rule=rule, details={'section_index':section, 'record_offset':offset, 'type_index':index})


def _canonical_codeview_args(raw):
    """Inverse of LLVM22 sys::printArg(Quote=true), not shell parsing."""
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeError:
        _cv_fail('cv_string_utf8')
    if any(ord(c)<32 or ord(c)==127 for c in text):
        _cv_fail('cv_command_controls')
    args, i = [], 0
    while i < len(text):
        if text[i] != '"': _cv_fail('cv_command_quotes')
        i += 1; value = []
        while i < len(text) and text[i] != '"':
            if text[i] == '\\':
                i += 1
                if i >= len(text) or text[i] not in '\\"$': _cv_fail('cv_command_escape')
            value.append(text[i]); i += 1
        if i >= len(text): _cv_fail('cv_command_quotes')
        args.append(''.join(value)); i += 1
        if i < len(text):
            if text[i] != ' ' or i+1 == len(text): _cv_fail('cv_command_separator')
            i += 1
    def encode(arg):
        return '"'+''.join(('\\'+c if c in '\\"$' else c) for c in arg)+'"'
    if ' '.join(encode(x) for x in args).encode('utf-8') != raw: _cv_fail('cv_command_canonical')
    if args and (args[0] != '-cc1' or any(not x for x in args)): _cv_fail('cv_command_frontend')
    return args


def _validate_codeview_args(args, policy):
    # Recheck all decoded bytes with the original root scanner, then normalize
    # Windows paths so an escaped approved-root/../outside path cannot hide.
    for arg in args:
        inspect_public_paths(arg.encode('utf-8'), policy)
        for match in re.finditer(r'(?i)(?<![a-z0-9_+.-])[a-z]:[\\/]|\\\\[a-z0-9_.-]+[\\/]', arg):
            value = arg[match.start():].split('"', 1)[0]
            try:
                approved_path(value, policy)
            except CheckpointError:
                _cv_fail('cv_decoded_path')


def _cv_padding(data, used, *, section, offset, rule):
    trailing = bytes(data[used:])
    if len(trailing)>3 or trailing != bytes(range(0xf0+len(trailing),0xf0,-1)):
        _cv_fail(rule, section=section, offset=offset)


def _validated_codeview_ranges(data, policy):
    """Only LF_BUILDINFO's command LF_STRING_ID bytes may bypass raw re-scan.

    The caller has already validated this object's COFF layout. Everything
    outside these proven string spans, including other CodeView fields, still
    passes the unchanged recognizable-path scan. No payload bytes are changed.
    """
    big = data[:4] == b'\0\0\xff\xff'
    header = 56 if big else 20
    count = struct.unpack_from('<I' if big else '<H', data, 44 if big else 2)[0]
    result = []
    for section in range(count):
        at = header+section*40
        if bytes(data[at:at+8]) != b'.debug$T': continue
        size, start = struct.unpack_from('<II', data, at+16)
        if size < 4 or struct.unpack_from('<I',data,start)[0] != 4:
            _cv_fail('cv_section_signature',section=section+1,offset=start)
        pos, end, type_index = start+4, start+size, 0x1000
        strings, commands = {}, []
        while pos < end:
            if pos+4>end: _cv_fail('cv_record_bounds',section=section+1,offset=pos,index=type_index)
            length, kind = struct.unpack_from('<HH',data,pos)
            stop = pos+2+length
            if length<2 or stop>end: _cv_fail('cv_record_bounds',section=section+1,offset=pos,index=type_index)
            if (stop-start)%4: _cv_fail('cv_record_alignment',section=section+1,offset=pos,index=type_index)
            if type_index-0x1000 >= policy.limits.log_records: _cv_fail('cv_record_count',section=section+1,offset=pos,index=type_index)
            if kind == 0x1605:
                strings[type_index] = (pos,stop)
            elif kind == 0x1603:
                if length<24 or struct.unpack_from('<H',data,pos+4)[0] != 5:
                    _cv_fail('cv_buildinfo_shape',section=section+1,offset=pos,index=type_index)
                _cv_padding(data[pos+2:stop],24,section=section+1,offset=pos,rule='cv_buildinfo_padding')
                refs = struct.unpack_from('<IIIII',data,pos+6)
                commands.append((type_index,pos,refs))
            pos = stop; type_index += 1
        for owner, record, refs in commands:
            if any(x not in strings or x >= owner for x in refs):
                _cv_fail('cv_command_reference',section=section+1,offset=record,index=owner)
            values = []
            for ref in refs:
                begin,stop = strings[ref]
                if stop-begin<9 or struct.unpack_from('<I',data,begin+4)[0] != 0:
                    _cv_fail('cv_string_shape',section=section+1,offset=begin,index=ref)
                content = bytes(data[begin+8:stop]); nul = content.find(b'\0')
                if nul<0: _cv_fail('cv_string_shape',section=section+1,offset=begin,index=ref)
                _cv_padding(content,nul+1,section=section+1,offset=begin,rule='cv_string_padding')
                values.append(content[:nul])
            # The approved embedded (/Z7) route has no external type-server PDB.
            if values[3]: _cv_fail('cv_external_type_server',section=section+1,offset=record,index=owner)
            ref = refs[4]; begin,stop = strings[ref]
            content = values[4]; nul = len(content)
            try:
                args = _canonical_codeview_args(content[:nul])
                _validate_codeview_args(args,policy)
            except CheckpointError as exc:
                if exc.code=='embedded_path_rejected':
                    exc.details={'section_index':section+1,'record_offset':begin,'type_index':ref}
                elif exc.code=='codeview_command_rejected':
                    exc.details={'section_index':section+1,'record_offset':begin,'type_index':ref}
                raise
            if nul: result.append((begin+8,begin+8+nul))
    return sorted(set(result))


MATERIAL_SIGNATURES = (
    ('dos_mz', 0, b'MZ'), ('coff_archive', 0, b'!<arch>\n'), ('thin_archive', 0, b'!<thin>\n'),
    ('elf', 0, b'\x7fELF'), ('zip_local', 0, b'PK\x03\x04'), ('zip_empty', 0, b'PK\x05\x06'),
    ('zip_spanned', 0, b'PK\x07\x08'), ('seven_zip', 0, b'7z\xbc\xaf\x27\x1c'),
    ('rar', 0, b'Rar!\x1a\x07'), ('gzip', 0, b'\x1f\x8b'), ('bzip2', 0, b'BZh'),
    ('xz', 0, b'\xfd7zXZ\0'), ('cabinet', 0, b'MSCF'),
    ('compound_document', 0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'), ('minidump', 0, b'MDMP'),
    ('pdb_msf', 0, b'Microsoft C/C++ MSF'), ('pdb_legacy', 0, b'Microsoft C/C++ program database'),
    ('mach_o_be32', 0, b'\xfe\xed\xfa\xce'), ('mach_o_le32', 0, b'\xce\xfa\xed\xfe'),
    ('mach_o_be64', 0, b'\xfe\xed\xfa\xcf'), ('mach_o_le64', 0, b'\xcf\xfa\xed\xfe'),
    ('fat_mach_or_java', 0, b'\xca\xfe\xba\xbe'), ('fat_mach_swapped', 0, b'\xbe\xba\xfe\xca'),
    ('bigobj_or_import', 0, b'\0\0\xff\xff'), ('tar_ustar', 257, b'ustar'),
)


def _material_bytes(data):
    """Reject the same conservative signatures; matches are candidates, not proof."""
    for name, offset, magic in MATERIAL_SIGNATURES:
        if data[offset:offset+len(magic)] == magic:
            raise CheckpointError('executable/archive/dump material signature', code='material_magic_candidate', signature_id=name)
    if len(data) >= 20 and struct.unpack_from('<H', data)[0] in {0x14c, 0x8664, 0x1c0, 0x1c4, 0xaa64}:
        raise CheckpointError('COFF/system binary material forbidden', code='coff_machine_candidate', signature_id='coff_'+data[:2].hex())


def _content(spec, data, policy):
    require(len(data) <= policy.limits.member_bytes, 'member content byte bound')
    suffix = Path(spec.relpath).suffix.lower()
    if spec.kind == 'obj':
        require(suffix == '.obj', 'object suffix')
        inspect_coff(data)
        spans = _validated_codeview_ranges(data, policy)
        spans += _public_literal_ranges(data, policy, spec)
        _inspect_public_paths(data, policy, sorted(spans))
    elif spec.kind == 'lib':
        require(suffix == '.lib', 'library suffix')
        objects, numeric_spans, regions = [], [], []
        try:
            inspect_archive(data, named_object_spans=objects, numeric_spans=numeric_spans, regions=regions)
        except CheckpointError as exc:
            if exc.code:
                raise
            raise CheckpointError('archive structure rejected', code='archive_structure_rejected', rule='archive_structure_rule') from None
        spans = list(numeric_spans)
        view = memoryview(data)
        literal_objects = 0
        for start, end, name in objects:
            ranges = _validated_codeview_ranges(view[start:end], policy)
            literal_ranges = _public_literal_ranges(view[start:end], policy, spec, name)
            literal_objects += bool(literal_ranges)
            require(literal_objects <= 1, 'duplicate public literal archive object')
            ranges += literal_ranges
            spans.extend((start+a, start+b) for a,b in ranges)
        try:
            _inspect_public_paths(data, policy, sorted(spans))
        except CheckpointError as exc:
            if exc.code == 'embedded_path_rejected' and isinstance(exc.details, dict):
                off = exc.details.get('byte_offset')
                if type(off) is int:
                    for begin, end, region, index in regions:
                        if begin <= off < end:
                            exc.details['archive_region'] = region
                            if region == 'archive_object':
                                exc.details['archive_object_index'] = index
                                exc.details['archive_object_offset'] = off - begin
                            break
            raise
    elif spec.kind == 'ninja_log':
        validate_ninja_log(data, policy)
    elif spec.kind == 'ninja_deps':
        validate_ninja_deps(data, policy)
    else:
        pinned_text = suffix == '.com' and spec.kind == 'material' and spec.member in policy.material_text_pins
        require((suffix not in FORBIDDEN or pinned_text) and Path(spec.relpath).name not in {'CMakeCache.txt', 'build.ninja', 'rules.ninja'}, 'forbidden source/material payload')
        if pinned_text:
            if len(data) > MATERIAL_TEXT_MAX_BYTES:
                raise CheckpointError('pinned material text size bound', code='material_text_size_rejected')
            if hashlib.sha256(data).hexdigest() != policy.material_text_pins[spec.member]:
                raise CheckpointError('material text pin mismatch', code='material_text_pin_mismatch')
            if b'\0' in data:
                raise CheckpointError('NUL in pinned material text', code='material_text_encoding_rejected')
            try:
                data.decode('utf-8', errors='strict')
            except UnicodeError:
                raise CheckpointError('invalid pinned UTF-8 text', code='material_text_encoding_rejected') from None
        if spec.kind == 'header':
            require(suffix in HEADER_SUFFIXES, 'header suffix')
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
    if spec.member in policy.material_text_pins and before.st_size > MATERIAL_TEXT_MAX_BYTES:
        raise CheckpointError('pinned material text size bound', code='material_text_size_rejected')
    with path.open('rb') as f:
        data = f.read(before.st_size+1)
    after = path.stat()
    require(len(data) == before.st_size and (before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino), 'file changed during inventory')
    require(0 <= before.st_mtime_ns <= 2**63-1, 'invalid filesystem timestamp')
    entry = {'member': spec.member, 'kind': spec.kind, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mtime_ns': before.st_mtime_ns}
    return entry, data


_SAFE_CODES = frozenset({'material_magic_candidate', 'coff_machine_candidate', 'material_text_pin_mismatch', 'material_text_encoding_rejected', 'material_text_size_rejected', 'source_drift', 'member_identity_mismatch', 'mtime_ns_not_preserved', 'coff_structure_rejected', 'archive_structure_rejected', 'archive_symbol_names_rejected', 'codeview_command_rejected', 'embedded_path_rejected'})


_SAFE_CODES = _SAFE_CODES | _ARCHIVE_SYMBOL_NAME_CODES

@contextmanager
def _member_guard(phase, spec, state=None):
    """Never echo raw exceptions, paths or member bytes into public diagnostics."""
    state = {} if state is None else state
    try:
        yield state
    except Exception as exc:
        code = getattr(exc, 'code', None)
        operation = state.get('operation', 'content')
        fallback = {'read': 'member_read_failed', 'content': 'member_content_rejected', 'provenance': 'provenance_or_license_failed', 'identity': 'member_identity_mismatch', 'timestamp': 'mtime_ns_not_preserved', 'write': 'member_write_failed'}.get(operation, 'member_check_failed')
        report = {'phase': phase, 'member': spec.member if spec is not None else '<manifest>', 'kind': spec.kind if spec is not None else 'manifest', 'reason_code': code if code in _SAFE_CODES else fallback}
        rule = getattr(exc, 'rule', None)
        if rule in _SAFE_FORMAT_RULES:
            report['format_rule'] = rule
        details = getattr(exc, 'details', None)
        if isinstance(details, dict):
            safe = {}
            for key in ['bytes', 'machine', 'version', 'sections', 'symbol_count', 'optional_header_bytes', 'section_index', 'record_offset', 'byte_offset', 'type_index', 'archive_object_index', 'archive_object_offset']:
                value = details.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**64-1:
                    safe[key] = value
            for key, allowed in [('format', {'coff', 'bigobj_or_import'}), ('encoding', {'ascii', 'utf16le'}), ('archive_region', {'archive_header','archive_longnames','archive_first_linker_numbers','archive_second_linker_numbers','archive_second_linker_indices','archive_symbol_names','archive_object'})]:
                if details.get(key) in allowed:
                    safe[key] = details[key]
            if safe:
                report['format_details'] = safe
        entry = state.get('entry')
        if entry is not None:
            report.update(bytes=entry['size'], sha256=entry['sha256'])
        signature = getattr(exc, 'signature_id', None)
        magic = next(((name, offset, raw) for name, offset, raw in MATERIAL_SIGNATURES if name == signature), None)
        if magic is not None:
            report.update(signature_id=magic[0], offset=magic[1], magic_hex=magic[2].hex())
        elif signature in {'coff_4c01', 'coff_6486', 'coff_c001', 'coff_c401', 'coff_64aa'}:
            report.update(signature_id=signature, offset=0, magic_hex=signature[5:])
        error = CheckpointError(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(',', ':')), code=report['reason_code'])
        error.context = report
        raise error from None


def _checked_file(spec, policy, phase, boundary_check=None):
    with _member_guard(phase, spec) as state:
        state['operation'] = 'read'
        entry, data = _read(spec, policy)
        state.update(entry=entry, operation='content')
        _content(spec, data, policy)
        if boundary_check:
            state['operation'] = 'provenance'
            boundary_check(phase, spec, data)
        return entry, data


def _baseline_callback(phase, callback, value):
    if callback:
        with _member_guard(phase, None, {'operation': 'provenance'}):
            callback(phase, None, value)


def preflight_available_content(policy, metadata, boundary_check=None):
    """Check exact available inputs/materials, creating no archive or outputs.

    Production callers validate their baseline in preflight-begin/end callbacks.
    Budget enforcement is cooperative through every callback; retain no buffers.
    Obj/lib/Ninja payloads are deferred even if files already exist. This receipt
    does not admit their contents, predict compressed ZIP size, or admit reuse.
    """
    with _member_guard('preflight-declarations', None):
        validate_policy(policy, metadata)
    _baseline_callback('preflight-begin', boundary_check, {'metadata': metadata})
    records, entries = [], {'inputs': [], 'payloads': []}
    available_input_bytes = available_payload_bytes = 0
    deferred = {kind: 0 for kind in sorted(DEFERRED_KINDS)}
    for label, specs in [('inputs', policy.inputs), ('payloads', policy.payloads)]:
        for spec in specs:
            if label == 'payloads' and spec.kind in DEFERRED_KINDS:
                deferred[spec.kind] += 1
                entry = {'member': spec.member, 'kind': spec.kind, 'size': policy.limits.member_bytes, 'sha256': 'f'*64, 'mtime_ns': 2**63-1}
            else:
                entry, data = _checked_file(spec, policy, 'preflight-'+label, boundary_check)
                records.append({'role': label, **entry})
                if label == 'inputs':
                    available_input_bytes += entry['size']
                else:
                    available_payload_bytes += entry['size']
                del data
                entry = {**entry, 'mtime_ns': 2**63-1}
            entries[label].append(entry)
    manifest_upper = {'schema': 1, 'metadata': metadata, 'owned_roots': {k: str(v) for k, v in policy.owned_roots.items()}, **entries}
    manifest_bytes_upper = len(_json(manifest_upper))
    require(manifest_bytes_upper <= policy.limits.manifest_bytes, 'manifest upper estimate exceeds bound')
    available_total = available_payload_bytes + manifest_bytes_upper
    require(available_total <= policy.limits.total_bytes, 'available payload plus manifest exceeds total bound')
    receipt = {'state': 'CHECKED_AVAILABLE_CONTENT_ONLY', 'input_count': len(policy.inputs), 'available_payload_count': len(policy.payloads)-sum(deferred.values()), 'checked_item_count': len(records), 'unique_checked_member_count': len({r['member'] for r in records}), 'deferred_payload_count': sum(deferred.values()), 'deferred_by_kind': deferred, 'available_input_bytes': available_input_bytes, 'available_payload_bytes': available_payload_bytes, 'available_total_bytes_upper': available_total, 'manifest_bytes_upper': manifest_bytes_upper, 'checked_identity_sha256': hashlib.sha256(_json(records)).hexdigest(), 'metadata_sha256': hashlib.sha256(_json(metadata)).hexdigest(), 'output_content_validation': 'DEFERRED', 'outer_zip_validation': 'NOT_RUN'}
    _baseline_callback('preflight-end', boundary_check, receipt)
    return receipt


def validate_built_subset(policy, members, boundary_check=None):
    """Validate only an exact pilot subset; never create/promote a checkpoint.

    Both Ninja state files are mandatory. The derived log policy admits only
    selected object/archive outputs, preserving full input/root/limit/pin guards.
    Cooperative budgets/provenance are supplied by the per-member callback.
    """
    with _member_guard('built-subset-declarations', None):
        _policy(policy)
        require(isinstance(members, (list, tuple)) and members and all(isinstance(x, str) for x in members), 'nonempty exact member list required')
        require(len(members) <= len(policy.payloads) and len(set(members)) == len(members) and len({x.casefold() for x in members}) == len(members), 'duplicate/oversized subset')
        declared = {spec.member: spec for spec in policy.payloads}
        require(all(member in declared for member in members), 'unknown subset member')
        selected = tuple(declared[member] for member in members)
        require(all(spec.kind in DEFERRED_KINDS for spec in selected), 'non-output subset member')
        require({spec.kind for spec in selected if spec.kind in {'ninja_log', 'ninja_deps'}} == {'ninja_log', 'ninja_deps'}, 'both Ninja states required')
        outputs = set()
        for spec in selected:
            if spec.kind not in {'obj', 'lib'}:
                continue
            target = Path(policy.owned_roots[spec.root]) / spec.relpath
            outputs.update((str(target), os.path.relpath(target, policy.log_base_root)))
        restricted = replace(policy, allowed_log_outputs=frozenset(outputs))
        _policy(restricted)
    _baseline_callback('built-subset-begin', boundary_check, {'selected_count': len(selected)})
    records, counts, total = [], {kind: 0 for kind in sorted(DEFERRED_KINDS)}, 0
    for spec in selected:
        entry, data = _checked_file(spec, restricted, 'built-subset', boundary_check)
        records.append(entry)
        counts[spec.kind] += 1
        total += entry['size']
        require(total <= policy.limits.total_bytes, 'subset bytes exceed total bound')
        del data
    receipt = {'state': 'PASS_BUILT_SUBSET_ONLY', 'member_count': len(records), 'validated_output_count': counts['obj']+counts['lib'], 'counts_by_kind': counts, 'bytes': total, 'checked_identity_sha256': hashlib.sha256(_json(records)).hexdigest(), 'full_checkpoint_validation': 'NOT_RUN', 'outer_zip_validation': 'NOT_RUN'}
    _baseline_callback('built-subset-end', boundary_check, receipt)
    return receipt


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
    with _member_guard('seal-declarations', None):
        _policy(policy)
        metadata_paths(metadata, policy)
    path = _outer_path(path, missing=True)
    require(not path.exists() and not path.is_symlink(), 'checkpoint destination already exists')
    require(path.parent.is_dir() and not path.parent.is_symlink(), 'checkpoint parent missing/link')
    manifest = {'schema': 1, 'metadata': metadata, 'owned_roots': {k: str(v) for k, v in policy.owned_roots.items()}, 'inputs': [], 'payloads': []}
    total = 0
    for spec in policy.inputs:
        entry, data = _checked_file(spec, policy, 'seal-input', boundary_check)
        manifest['inputs'].append(entry)
        del data
    fd, temporary = tempfile.mkstemp(prefix='.checkpoint-', suffix='.zip', dir=path.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=False) as archive:
            for spec in policy.payloads:
                entry, data = _checked_file(spec, policy, 'seal', boundary_check)
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
            _baseline_callback('manifest', boundary_check, manifest)
            raw = _json(manifest)
            require(len(raw) <= policy.limits.manifest_bytes and total+len(raw) <= policy.limits.total_bytes, 'manifest/total size bound')
            archive.writestr(_zip_info(MANIFEST), raw)
        require(os.path.getsize(temporary) <= policy.limits.archive_bytes, 'outer archive size bound')
        # Recheck source bytes AND mtime after sealing outputs, without publishing.
        for spec, entry in zip(policy.inputs, manifest['inputs']):
            with _member_guard('seal-recheck', spec, {'operation': 'read'}) as state:
                current, data = _read(spec, policy)
                state.update(entry=current, operation='identity')
                require(current == entry, 'source drift during seal')
                del data
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
        with _member_guard('validate-metadata', None):
            metadata_paths(manifest['metadata'], policy)
        for label, specs in [('inputs', policy.inputs), ('payloads', policy.payloads)]:
            require(isinstance(manifest[label], list) and len(manifest[label]) == len(specs), 'manifest allowlist length mismatch')
            for entry, spec in zip(manifest[label], specs):
                with _member_guard('validate-'+label, spec) as state:
                    _entry(entry, spec, policy)
                    if label == 'inputs':
                        state['operation'] = 'read'
                        current, data = _read(spec, policy)
                        state.update(entry=current, operation='identity')
                        _equal(entry, data)  # mtime changes alone are restorable.
                        state['operation'] = 'content'
                        _content(spec, data, policy)
                    else:
                        require(archive.getinfo(spec.member).file_size == entry['size'], 'ZIP/manifest size mismatch')
                        state['operation'] = 'read'
                        data = archive.read(spec.member)
                        state.update(entry={'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}, operation='identity')
                        _equal(entry, data)
                        state['operation'] = 'content'
                        _content(spec, data, policy)
                        if policy.root_kinds[spec.root] in {'source', 'generated'}:
                            # These destinations are fresh, owned source/header trees,
                            # not output space. Never overwrite/backdate drifted data.
                            state['operation'] = 'read'
                            _, existing = _read(spec, policy)
                            state['operation'] = 'identity'
                            _equal(entry, existing)
                            del existing
                    if boundary_check:
                        boundary_check('validate', spec, data)
                del data
        _baseline_callback('manifest', boundary_check, manifest)
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
        with _member_guard('restore-destination', spec, {'operation':'read'}):
            _safe_path(policy, spec, allow_missing=True)
    with zipfile.ZipFile(path) as archive:
        for spec, entry in zip(policy.payloads, manifest['payloads']):
            with _member_guard('restore-payload', spec, {'operation':'read'}) as state:
                dest = _safe_path(policy, spec, allow_missing=True)
                data = archive.read(spec.member)
                state.update(entry={'size':len(data),'sha256':hashlib.sha256(data).hexdigest()},operation='identity')
                _equal(entry, data)
                if policy.root_kinds[spec.root] in {'source', 'generated'}:
                    _, current = _read(spec, policy)
                    _equal(entry, current)
                    del current
                state['operation'] = 'write'
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
                    state['operation'] = 'timestamp'
                    _mtime(dest, entry['mtime_ns'])
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
                del data
    for spec, entry in zip(policy.inputs, manifest['inputs']):
        with _member_guard('restore-input', spec, {'operation':'read'}) as state:
            observed, data = _read(spec, policy)
            state.update(entry=observed,operation='identity')
            _equal(entry, data)  # equality is immediately before touching each source.
            state['operation'] = 'timestamp'
            _mtime(_safe_path(policy, spec), entry['mtime_ns'])
            del data
    for label, specs in [('inputs', policy.inputs), ('payloads', policy.payloads)]:
        for spec, entry in zip(specs, manifest[label]):
            with _member_guard('restore-final-'+label, spec, {'operation':'read'}) as state:
                current, data = _read(spec, policy)
                state.update(entry=current,operation='identity')
                require(current == entry, 'post-restore hash/size/mtime mismatch')
                del data
    return manifest
