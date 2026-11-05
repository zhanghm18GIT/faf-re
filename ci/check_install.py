"""Read-only package audit. Never launches, installs, or modifies a game directory."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

MAX_ZIP = 400 * 1024 * 1024
GATES = {'source', 'dependencies', 'cache', 'targets', 'actual_links', 'ctest',
         'image_codec', 'headless_imports', 'build_info', 'resources'}
BINARY_NAMES = {'main_x64.exe', 'headless_x64.exe', 'main_x64.pdb', 'dxcompiler.dll', 'dxil.dll',
    'faf_sim_math_tests.exe', 'faf_math_dump.exe', 'faf_coroutine_tests.exe',
    'faf_effect_scan_tests.exe', 'faf_image_codec_tests.exe', 'faf_replay_scan_tests.exe', 'faf_texture_quality_tests.exe'}
RESOURCE_NAMES = {'lua/options/options.lua', 'lua/ui/controls/flat_panel.lua',
    'lua/ui/controls/flat_progress.lua', 'lua/ui/controls/flat_text_button.lua',
    'lua/ui/dialogs/disconnect.lua', 'lua/ui/game/gamemain.lua',
    'lua/ui/game/replay_scrubber.lua', 'lua/ui/game/replay_timeline.lua',
    'lua/ui/notify/notify.lua', 'lua/ui/uimain.lua'}

class PackageError(RuntimeError):
    pass

def require(ok, message):
    if not ok:
        raise PackageError(message)

def safe_path(value):
    require(isinstance(value, str) and value, 'Empty/non-string package path')
    p = PurePosixPath(value)
    require(not p.is_absolute() and p.as_posix() == value and not any(c in value for c in '\\:\x00'), 'Unsafe path: '+value)
    for part in p.parts:
        require(part not in {'.', '..'} and not part.endswith((' ', '.')) and
                not re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part, re.I), 'Unsafe Windows path: '+value)
    require(not any(ord(c) < 32 or c in '<>"|?*' for c in value), 'Unsafe Windows path: '+value)
    return p

def regular_path(root, name):
    root = Path(root)
    p = root
    require(not root.is_symlink(), 'Symlink root')
    for part in safe_path(name).parts:
        p = p / part
        require(not p.is_symlink(), 'Symlink path: '+name)
        require(not getattr(p, 'is_junction', lambda:False)(), 'Junction path: '+name)
    require(p.is_file() and p.resolve().is_relative_to(root.resolve()), 'Missing/nonregular file: '+name)
    return p

def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

def validate_manifest(m):
    require(m.get('schema') == 1, 'Unsupported manifest schema')
    require(m.get('native_gates') == 'PASS' and m.get('in_game') == 'NOT_RUN' and m.get('replays') == 'NOT_RUN', 'Untruthful acceptance status')
    checks = m.get('native_checks', {})
    require(set(checks) == GATES and all(v == 'PASS' for v in checks.values()), 'Incomplete native checks')
    require(m.get('pdb_match', {}).get('status') == 'PASS', 'PDB match missing')
    rows = m['files']; names = [r['path'] for r in rows]
    for r in rows:
        safe_path(r['path'])
        require(type(r['bytes']) is int and r['bytes'] >= 0 and re.fullmatch('[0-9a-f]{64}', r['sha256']), 'Invalid hash/length')
    require(len(names) == len(set(n.casefold() for n in names)), 'Duplicate/case-colliding files')
    require('FILE_MANIFEST.json' not in names, 'Manifest must not self-hash')
    require({n for n in names if '/' not in n and (n.endswith('.exe') or n.endswith('.dll') or n.endswith('.pdb'))} == BINARY_NAMES, 'Unexpected binaries')
    resources = {'fafengine/'+n for n in RESOURCE_NAMES}
    require({n for n in names if n.startswith('fafengine/')} == resources, 'Resource file set differs')
    resource_rows = {r['path']:r for r in m['resources']}
    require(set(resource_rows) == resources and len(m['resources']) == 10, 'Pinned resources differ')
    indexed = {r['path']:r for r in rows}
    for name, row in resource_rows.items():
        require(indexed[name]['sha256'] == row['sha256'] and indexed[name]['bytes'] == row['bytes'], 'Resource pin mismatch')
    require({'check_install.py', 'INSTALL.txt', 'NATIVE_RECEIPT.json', 'SOURCE_MATERIALS.json', 'SOURCE_INPUTS.json'} <= set(names), 'Missing package metadata')
    return indexed

def check_package(root):
    root = Path(root)
    m = json.loads(regular_path(root, 'FILE_MANIFEST.json').read_text(encoding='utf-8'))
    rows = validate_manifest(m)
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if not p.is_dir() or p.is_symlink() or getattr(p, 'is_junction', lambda:False)()}
    require(actual == set(rows) | {'FILE_MANIFEST.json'}, 'Package file set differs')
    for name, row in rows.items():
        p = regular_path(root, name)
        require(p.stat().st_size == row['bytes'] and file_hash(p) == row['sha256'], 'Hash/length mismatch: '+name)
    receipt = json.loads((root/'NATIVE_RECEIPT.json').read_text(encoding='utf-8'))
    for key in ('native_gates', 'native_checks', 'in_game', 'replays'):
        require(receipt.get(key) == m[key], 'Receipt differs: '+key)
    source_inputs = json.loads((root/'SOURCE_INPUTS.json').read_text(encoding='utf-8'))
    resource_pins = {r['path']:r for r in source_inputs['resources']}
    for resource in m['resources']:
        pin = resource_pins.get('data/'+resource['path'])
        require(pin is not None and pin['sha256'] == resource['sha256'] and pin['bytes'] == resource['bytes'], 'Runtime resource differs from source pin')
    dxc = source_inputs.get('dxc_runtime', [])
    require(len(dxc) == 2 and {r['path'] for r in dxc} == {'dependencies/dxc/bin/x64/'+n for n in ('dxcompiler.dll', 'dxil.dll')}, 'DXC runtime pins missing/differ')
    for pin in dxc:
        name = PurePosixPath(pin['path']).name
        require(rows[name]['sha256'] == pin['sha256'] and rows[name]['bytes'] == pin['bytes'], 'DXC runtime pin mismatch')
    expected_sources = set()
    for metadata, prefix, key in [('SOURCE_INPUTS.json', 'source/engine/', 'candidate_files'), ('SOURCE_MATERIALS.json', 'source/engine/', 'files')]:
        source = json.loads((root/metadata).read_text(encoding='utf-8'))
        for row in source[key]:
            expected_sources.add(prefix+row['path'])
            target = rows.get(prefix+row['path'])
            require(target is not None and target['sha256'] == row['sha256'] and target['bytes'] == row['bytes'], 'Missing/changed corresponding source: '+row['path'])
    require({n for n in rows if n.startswith('source/')} == expected_sources, 'Unexpected corresponding source files')
    return m

def check_zip(path, stage):
    path = Path(path)
    require(path.stat().st_size <= MAX_ZIP, 'ZIP exceeds 400 MiB; do not remove required materials')
    m = check_package(stage)
    expected = {r['path']:r for r in m['files']}
    expected['FILE_MANIFEST.json'] = {'bytes': (Path(stage)/'FILE_MANIFEST.json').stat().st_size, 'sha256': file_hash(Path(stage)/'FILE_MANIFEST.json')}
    with zipfile.ZipFile(path) as z:
        info = z.infolist(); names = [x.filename for x in info]
        require(len(names) == len(set(n.casefold() for n in names)) and set(names) == set(expected), 'ZIP member set differs')
        for entry in info:
            safe_path(entry.filename)
            require(not entry.is_dir() and not entry.flag_bits & 1 and not stat.S_ISLNK(entry.external_attr >> 16), 'Invalid ZIP member')
            row = expected[entry.filename]
            require(entry.file_size == row['bytes'], 'ZIP size mismatch')
            h = hashlib.sha256()
            with z.open(entry) as f:
                for b in iter(lambda:f.read(1024*1024), b''): h.update(b)
            require(h.hexdigest() == row['sha256'], 'ZIP hash mismatch')
    return m

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    try:
        check_package(args.directory)
    except (OSError, ValueError, KeyError, PackageError) as e:
        parser.exit(1, 'FAIL: '+str(e)+'\n')
    print('PASS: package integrity and recorded native gates. Game/replay acceptance: NOT_RUN. No installation changes made.')

if __name__ == '__main__':
    main()
