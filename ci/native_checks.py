"""Pure validation helpers; no network, process, or installation side effects."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import xml.etree.ElementTree as ET

TARGETS = ['faf_main', 'headless', 'faf_sim_math_tests', 'faf_math_dump', 'faf_coroutine_tests', 'faf_effect_scan_tests', 'faf_image_codec_tests','faf_replay_scan_tests','faf_texture_quality_tests']
CTESTS = ['sim_math', 'math_dump', 'lua_coroutine', 'effect_scan', 'replay_scan', 'texture_quality']
ALL_CTESTS = ['net_robustness', 'net_peer_transport', 'net_fast_retransmit', 'profiler_facade', 'effect_scan', 'image_codec', 'sim_math', 'prefs_threads', 'math_dump', 'remote_netchannel', 'tread_rotation_guard', 'recon_scroll_packet', 'lua_coroutine', 'replay_scan', 'texture_quality']
OUTPUTS = {'faf_main':'src/main_x64.exe', 'headless':'src/headless_x64.exe', **{n:'tests/'+n+'.exe' for n in TARGETS[2:]}}
OFF = ['FAF_PGO_GENERATE', 'FAF_PCH', 'FAF_ENABLE_TRACY', 'FAF_RETAIL_LAYOUT', 'FAF_SYNTAX_ONLY', 'FAF_SERVER_MODE', 'FAF_CALL_HASH_BUILD']

class GateError(RuntimeError): pass

def need(ok, text):
    if not ok: raise GateError(text)

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024), b''): h.update(block)
    return h.hexdigest()

def relative(value):
    p = PurePosixPath(value)
    need(value and not p.is_absolute() and '..' not in p.parts and ':' not in value and '\\' not in value, 'Unsafe path')
    return p

def verify_files(root, rows):
    for e in rows:
        p = Path(root)/relative(e['path'])
        need(p.is_file() and not p.is_symlink(), 'Missing/nonregular input '+e['path'])
        need(p.stat().st_size == e['bytes'] and digest(p) == e['sha256'], 'Changed input '+e['path'])

def read_cache(path):
    return {m[1]:m[2] for l in Path(path).read_text(encoding='utf-8-sig').splitlines() if (m:=re.match(r'([^#/:][^:]*):[^=]+=(.*)$',l))}

def check_cache(cache):
    for flag in OFF: need(cache.get(flag) == 'OFF', 'Missing/off selection '+flag)
    for key,value in {'CMAKE_BUILD_TYPE':'Release','CMAKE_GENERATOR':'Ninja','FAF_PGO_PROFILE':'','FAF_OUTPUT_NAME':'main_x64','FAF_FETCH_DEPENDENCIES':'OFF','FAF_UCRT_LIB_VERSION':'10.0.22000.0'}.items():
        need(cache.get(key) == value, 'Cache selection '+key)

def normalize(p): return str(p).replace('\\','/').lower()

def check_discovery(data, source, build):
    tests=data.get('tests',[])
    need(sorted(t['name'] for t in tests)==sorted(ALL_CTESTS), 'Unexpected full CTest discovery')
    chosen={t['name']:t for t in tests if t['name'] in CTESTS+['image_codec']}
    expected={
        'sim_math':[str(Path(build)/OUTPUTS['faf_sim_math_tests']),str(Path(source)/'tests/sim_math/golden.txt')],
        'math_dump':[str(Path(build)/OUTPUTS['faf_math_dump']),'--check',str(Path(source)/'tests/math_dump/golden.txt'),'--values',str(Path(source)/'tests/math_dump/retail_values.txt')],
        'lua_coroutine':[str(Path(build)/OUTPUTS['faf_coroutine_tests'])],
        'effect_scan':[str(Path(build)/OUTPUTS['faf_effect_scan_tests'])],
        'image_codec':[str(Path(build)/OUTPUTS['faf_image_codec_tests'])],
        'replay_scan':[str(Path(build)/OUTPUTS['faf_replay_scan_tests'])],
        'texture_quality':[str(Path(build)/OUTPUTS['faf_texture_quality_tests'])]}
    for name,args in expected.items():
        got=chosen[name].get('command',[])
        need([normalize(x) for x in got]==[normalize(x) for x in args], 'Changed CTest command '+name)
    return sorted(set(ALL_CTESTS)-set(CTESTS)-{'image_codec'})

def check_junit(path):
    tests=ET.parse(path).getroot().findall('.//testcase')
    need(sorted(t.get('name','') for t in tests)==sorted(CTESTS), 'JUnit names/count')
    for t in tests:
        need(not any(t.find(x) is not None for x in ['skipped','failure','error']), 'CTest failure/skip')
        need(t.get('status','run') not in ['notrun','disabled','skipped'], 'CTest not run')

def check_codec(code, output):
    need(code==0, 'image_codec nonzero exit')
    need(not re.search(r'\bSKIP\b',output,re.I), 'image_codec SKIP is not acceptance')
    endings=re.findall(r'^\s*(\d+) failed\s*$',output,re.M)
    need(endings==['0'], 'image_codec missing/ambiguous successful final count')

def check_build_info(text, base):
    for expected in [f'#define FAF_BUILD_COMMIT "{base}"','#define FAF_BUILD_DIRTY 1','#define FAF_BUILD_ARCH "x64"','#define FAF_BUILD_CONFIG "Release"', f'#define FAF_BUILD_SHOWN "{base[:7]}-dirty"']:
        need(expected in text, 'Untruthful BuildInfo '+expected)

def check_resource_set(source, rows):
    need(len(rows)==10, 'Resource count is not ten')
    wanted={e['path'] for e in rows}
    actual={'data/fafengine/'+p.relative_to(Path(source)/'data/fafengine').as_posix() for p in (Path(source)/'data/fafengine').rglob('*') if p.is_file() or p.is_symlink()}
    need(actual==wanted, 'fafengine resources missing/extra')
    verify_files(source,rows)

def check_package(package):
    root=Path(package).resolve(); manifest=json.loads((root/'FILE_MANIFEST.json').read_text())
    verify_files(root,manifest['files'])
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    need(actual=={e['path'] for e in manifest['files']}|{'FILE_MANIFEST.json'},'Package file set differs')
    need(manifest['native_gates']=='PASS' and manifest['in_game']=='NOT_RUN','Package overstates acceptance')
    return manifest
