"""Offline explicit-set packaging gate. No installation, network, or publication.

Contract: ctx.root is a disposable job directory; ctx.receipt is the real driver
receipt. create_package returns the validated ZIP Path. Source and build are
explicit job directories, never discovered user installations. tools is reserved
for the driver toolchain contract; PE/PDB matching uses no external process.
"""
import json
from pathlib import Path
import shutil
import struct
import tempfile
import zipfile

from native_checks import OUTPUTS, check_resource_set
from check_install import (GATES, MAX_ZIP, PackageError, check_package, check_zip,
    file_hash, regular_path, require, safe_path)

INSTALL = '''ISOLATED CANDIDATE ONLY
A successful build and native checks are NOT game or replay acceptance.
Game and replay acceptance: NOT_RUN. No claim of render correctness or compatibility.

Extract this entire ZIP into a NEW side-by-side candidate directory. Never extract
into or copy over the original game, FAF installation, or any existing candidate.
Keep all files, source materials, and component notices together. This package
contains no base-game assets, SDK, or system runtimes. Obtain prerequisites only
through their authorized installers, separately. This script does not install them.
Run: python check_install.py <new-candidate-directory>
This verifies package hashes and recorded gates only; it never launches the game,
reads another installation, installs anything, or changes an existing installation.

Any game testing must be explicitly arranged separately with authorized base-game
assets and configuration; do not redirect an existing production installation.
Rollback: close the candidate and return to the original executable at its original
path. No automatic install, replacement, registry update, or uninstall is performed.

LEGAL: No blanket repository licence is assumed. See source/engine/LEGAL.md and
all original component notices/licences within source/engine/dependencies and src.
This local package creation is not authorization to publish or redistribute.
'''

def pe_info(path):
    data = Path(path).read_bytes()
    require(len(data) >= 64 and data[:2] == b'MZ', 'Not a PE: '+str(path))
    off = struct.unpack_from('<I', data, 60)[0]
    require(off + 24 <= len(data) and data[off:off+4] == b'PE\0\0', 'Invalid PE header')
    machine, count = struct.unpack_from('<HH', data, off+4)
    require(machine == 0x8664, 'Non-AMD64 binary: '+str(path))
    optional_size = struct.unpack_from('<H', data, off+20)[0]
    opt = off+24
    require(opt+optional_size <= len(data) and optional_size >= 168 and struct.unpack_from('<H', data, opt)[0] == 0x20b, 'Invalid PE32+ optional header')
    debug_rva, debug_size = struct.unpack_from('<II', data, opt+112+6*8)
    sections = opt+optional_size
    require(sections + count*40 <= len(data), 'Truncated section table')
    def offset(rva, size):
        for i in range(count):
            pos = sections+i*40
            virtual_size, virtual, raw_size, raw = struct.unpack_from('<IIII', data, pos+8)
            if virtual <= rva and rva+size <= virtual+raw_size:
                result = raw+rva-virtual
                require(result+size <= len(data), 'Truncated PE section')
                return result
        raise PackageError('Unmapped debug RVA')
    records = []
    if debug_size:
        require(debug_size % 28 == 0, 'Invalid debug directory')
        start = offset(debug_rva, debug_size)
        for at in range(start, start+debug_size, 28):
            kind, size, rva, raw = struct.unpack_from('<IIII', data, at+12)
            if kind == 2:
                require(raw+size <= len(data) and size >= 24, 'Truncated CodeView')
                if data[raw:raw+4] == b'RSDS':
                    records.append((data[raw+4:raw+20].hex(), struct.unpack_from('<I', data, raw+20)[0]))
    return records

def pdb_identity(path):
    data = Path(path).read_bytes()
    require(data[:32] == b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0' and len(data) >= 56, 'Unsupported PDB format')
    block_size, _, blocks, directory_size, _, block_map = struct.unpack_from('<6I', data, 32)
    require(block_size in (512, 1024, 2048, 4096) and blocks*block_size <= len(data), 'Invalid PDB block geometry')
    def block(n):
        require(n < blocks, 'Out of range PDB block')
        return data[n*block_size:(n+1)*block_size]
    count = (directory_size+block_size-1)//block_size
    require(count*4 <= block_size, 'Unsupported oversized PDB directory map')
    ids = struct.unpack_from('<'+'I'*count, block(block_map))
    directory = b''.join(block(i) for i in ids)[:directory_size]
    require(len(directory) >= 12, 'Truncated PDB directory')
    streams = struct.unpack_from('<I', directory)[0]
    require(streams >= 2 and 4+streams*4 <= len(directory), 'Invalid PDB stream table')
    sizes = struct.unpack_from('<'+'I'*streams, directory, 4)
    cursor = 4+streams*4
    for index, size in enumerate(sizes[:2]):
        n = 0 if size == 0xffffffff else (size+block_size-1)//block_size
        require(cursor+n*4 <= len(directory), 'Truncated PDB stream blocks')
        ids = struct.unpack_from('<'+'I'*n, directory, cursor)
        if index == 1:
            require(28 <= size <= blocks*block_size, 'Missing PDB info stream')
            info = b''.join(block(i) for i in ids)[:size]
            return info[12:28].hex(), struct.unpack_from('<I', info, 8)[0]
        cursor += n*4

def match_pdb(exe, pdb):
    records = pe_info(exe)
    identity = pdb_identity(pdb)
    require(len(records) == 1 and records[0] == identity, 'Main executable/PDB GUID-age mismatch')
    return {'status':'PASS', 'guid_bytes':identity[0], 'age':identity[1]}

def create_package(ctx, source, build, tools, inputs, materials):
    source, build = Path(source), Path(build)
    receipt = ctx.receipt
    require(receipt.get('native_gates') == 'PASS', 'Native gates have not passed')
    require(set(receipt.get('native_checks', {})) == GATES and all(v == 'PASS' for v in receipt['native_checks'].values()), 'Native checks incomplete')
    require(receipt.get('in_game') == 'NOT_RUN' and receipt.get('replays') == 'NOT_RUN', 'Invalid acceptance boundary')
    check_resource_set(source, inputs['resources'])
    require(any(r['path'] == 'LEGAL.md' for r in inputs['candidate_files']), 'Missing repository legal notice')
    require(materials['files'], 'Dependency source materials missing')
    pdb = regular_path(build, 'src/main_x64.pdb')
    pdb_match = match_pdb(regular_path(build, OUTPUTS['faf_main']), pdb)
    stage = Path(tempfile.mkdtemp(prefix='package-stage-', dir=ctx.root))
    seen = set()
    def copy(root, relative, target, pin=None):
        if hasattr(ctx, 'remaining'):
            ctx.remaining(600)
        safe_path(target)
        require(target.casefold() not in seen, 'Duplicate package destination: '+target)
        seen.add(target.casefold())
        src = regular_path(root, relative)
        size, sha = src.stat().st_size, file_hash(src)
        if pin is not None:
            require(size == pin['bytes'] and sha == pin['sha256'], 'Changed source material: '+relative)
        dst = stage/target
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        require(dst.stat().st_size == size and file_hash(dst) == sha, 'Copy changed: '+target)
    for target, rel in OUTPUTS.items():
        pe_info(regular_path(build, rel))
        copy(build, rel, Path(rel).name)
    copy(build, 'src/main_x64.pdb', 'main_x64.pdb')
    dxc_rows = inputs.get('dxc_runtime', [])
    dxc_pins = {r['path']:r for r in dxc_rows}
    require(len(dxc_rows) == 2 and set(dxc_pins) == {'dependencies/dxc/bin/x64/'+n for n in ('dxcompiler.dll', 'dxil.dll')}, 'DXC runtime pins missing/differ')
    for name in ('dxcompiler.dll', 'dxil.dll'):
        rel = 'dependencies/dxc/bin/x64/'+name
        pe_info(regular_path(source, rel))
        copy(source, rel, name, dxc_pins[rel])
    for row in inputs['resources']:
        copy(source, row['path'], row['path'].removeprefix('data/'), row)
    for row in inputs['candidate_files'] + materials['files']:
        path = row['path']
        require(not any(p.lower() in {'.git', '.aws', '.ssh', '.env', 'dxsdk', 'windows kits'} for p in safe_path(path).parts), 'Forbidden source material: '+path)
        copy(source, path, 'source/engine/'+path, row)
    # Recheck the bytes actually staged, not merely the earlier build paths.
    pdb_match = match_pdb(stage/'main_x64.exe', stage/'main_x64.pdb')
    for name in [Path(v).name for v in OUTPUTS.values()] + ['dxcompiler.dll', 'dxil.dll']:
        pe_info(stage/name)
    copy(Path(__file__).parent, 'check_install.py', 'check_install.py')
    copy(Path(__file__).parent, 'REPLAY_ACCEPTANCE.json', 'REPLAY_ACCEPTANCE.json')
    (stage/'INSTALL.txt').write_text(INSTALL, encoding='utf-8')
    for name, data in [('NATIVE_RECEIPT.json', receipt), ('SOURCE_INPUTS.json', inputs), ('SOURCE_MATERIALS.json', materials)]:
        (stage/name).write_text(json.dumps(data, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    files = [{'path':p.relative_to(stage).as_posix(), 'bytes':p.stat().st_size, 'sha256':file_hash(p)} for p in sorted(stage.rglob('*')) if p.is_file()]
    manifest = {'schema':1, 'native_gates':'PASS', 'native_checks':receipt['native_checks'], 'in_game':'NOT_RUN', 'replays':'NOT_RUN',
        'pdb_match':pdb_match, 'resources':[{**r, 'source_path':r['path'], 'path':r['path'].removeprefix('data/')} for r in inputs['resources']], 'files':files,
        'warning':'Native build is not game or replay acceptance. No publication authorization.'}
    (stage/'FILE_MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    check_package(stage)
    archive = Path(ctx.root)/(stage.name+'.zip')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
        for p in sorted(stage.rglob('*')):
            if p.is_file():
                if hasattr(ctx, 'remaining'):
                    ctx.remaining(600)
                z.write(p, p.relative_to(stage).as_posix())
    check_zip(archive, stage)
    if hasattr(ctx, 'remaining'): ctx.remaining(600)
    receipt['package'] = {'status':'PASS', 'path':str(archive), 'sha256':file_hash(archive), 'bytes':archive.stat().st_size,
        'stage':str(stage), 'pdb_match':pdb_match, 'in_game':'NOT_RUN', 'replays':'NOT_RUN'}
    if hasattr(ctx, 'remaining'): ctx.remaining(600)
    return archive
