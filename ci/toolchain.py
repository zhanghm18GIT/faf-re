"""Job-owned Windows toolchain. Import is inert; provision requires a Windows job.

ctx.root: existing isolated job root (Path)
ctx.command(args, name, cap, cwd=None, env=None, permit_failure=False): stdout str;
    must raise on nonzero exit unless permit_failure is True, redact secrets.
ctx.download({url,size,sha256}, destination): exclusive, bounded HTTPS download.
ctx.receipt: mutable dict. ctx.authorizations['windows_sdk_license']: current grant.
This module never installs software globally or changes machine environment.
The source clang-cl-common.cmake sets compiler/linker sysroot and RC includes;
no INCLUDE/LIB/WindowsSdkDir initialization is required. Configure explicitly
with FAF_LLVM_ROOT, FAF_MSVC_TOOLS_DIR, FAF_WINSDK_DIR=sdk_root,
FAF_WINSDK_VERSION=sdk_version, FAF_UCRT_LIB_VERSION=10.0.22000.0 and
CMAKE_MAKE_PROGRAM=ninja. Use the x64 toolchain and Release configuration.
"""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import struct
import tarfile
import zipfile

LLVM_PIN = {
    'url': 'https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.7/clang%2Bllvm-22.1.7-x86_64-pc-windows-msvc.tar.xz',
    'size': 862033024,
    'sha256': '3b568b5be1443d1a04c63261fa3a7aed16e126a8ed2196a1032aa8ed602144bd',
}
SDK_VERSION = '10.0.26100.0'
LLVM_TOOLS = ('clang-cl', 'lld-link', 'llvm-lib', 'llvm-rc', 'llvm-mt', 'llvm-ml64', 'llvm-readobj')


class Blocked(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Blocked(message)


def sha(path, algorithm='sha256'):
    digest = hashlib.new(algorithm)
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def checked_hash(path, expected):
    require(sha(path) == expected, 'SHA-256 mismatch: ' + Path(path).name)


def owned(root, relative):
    """Resolve only fresh paths below root, rejecting Windows and POSIX escapes."""
    win, posix = PureWindowsPath(str(relative)), PurePosixPath(str(relative))
    require(not win.drive and not win.root and not posix.is_absolute(), 'Absolute job path rejected')
    require('..' not in win.parts and '..' not in posix.parts and ':' not in str(relative), 'Job path traversal rejected')
    path = Path(root) / relative
    require(path.resolve().is_relative_to(Path(root).resolve()) and path.resolve() != Path(root).resolve(), 'Job path escapes root')
    return path


def required_tool(name):
    result = shutil.which(name)
    require(result and Path(result).is_file(), 'Required installed tool missing: ' + name)
    return Path(result)


def pe_machine(path):
    data = Path(path).read_bytes()
    require(len(data) >= 64 and data[:2] == b'MZ', 'Missing/truncated PE DOS header: ' + Path(path).name)
    offset = struct.unpack_from('<I', data, 0x3c)[0]
    require(offset >= 64 and offset + 24 <= len(data) and data[offset:offset+4] == b'PE\0\0', 'Invalid/truncated PE header')
    return struct.unpack_from('<H', data, offset + 4)[0]


def inspect_coff_archive(path):
    data = Path(path).read_bytes()
    require(data.startswith(b'!<arch>\n'), 'Static UCRT is not a COFF archive')
    offset, count = 8, 0
    while offset < len(data):
        header = data[offset:offset+60]
        require(len(header) == 60 and header[58:60] == b'`\n', 'Malformed COFF archive member')
        try:
            length = int(header[48:58].decode('ascii').strip())
            name = header[:16].decode('ascii').strip()
        except (ValueError, UnicodeError) as exc:
            raise Blocked('Malformed COFF archive header') from exc
        start, end = offset + 60, offset + 60 + length
        require(length >= 0 and end <= len(data), 'COFF member length outside archive')
        payload = data[start:end]
        if name not in {'/', '//', '/SYM64/'}:
            require(len(payload) >= 20, 'Truncated COFF object')
            first, second = struct.unpack_from('<HH', payload)
            machine = struct.unpack_from('<H', payload, 6)[0] if (first, second) == (0, 0xffff) else first
            require(machine == 0x8664, 'Non-x64 or unknown COFF archive object')
            count += 1
        offset = end + (length & 1)
    require(offset == len(data) and count > 0, 'Incomplete x64 COFF archive')
    return {'members': count, 'machine': 'AMD64', 'sha256': sha(path)}


def verify_download(ctx, pin, path):
    require(not path.exists(), 'Download destination already exists')
    ctx.download(pin, path)
    require(path.is_file() and path.stat().st_size == pin['size'], 'Download size mismatch')
    checked_hash(path, pin['sha256'])


def signature_check(ctx, archive, tools):
    env = os.environ.copy()
    env.update(DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
               DOTNET_CLI_HOME=str(tools/'dotnet-home'), NUGET_PACKAGES=str(tools/'nuget-cache'),
               NUGET_HTTP_CACHE_PATH=str(tools/'nuget-http-cache'))
    verifier = None
    dotnet, nuget = shutil.which('dotnet.exe'), shutil.which('nuget.exe')
    if dotnet:
        text = ctx.command([dotnet, 'nuget', '--help'], name='dotnet-nuget-capability', cap=45, env=env, permit_failure=True)
        if re.search(r'(?m)^\s*verify\b', text):
            verifier = [dotnet, 'nuget', 'verify', archive, '--all', '--verbosity', 'minimal']
    if verifier is None and nuget:
        text = ctx.command([nuget, 'help', 'verify'], name='nuget-verify-capability', cap=45, env=env, permit_failure=True)
        if re.search(r'-Signatures\b', text, re.I):
            verifier = [nuget, 'verify', '-Signatures', archive, '-NonInteractive']
    if verifier:
        ctx.command(verifier, name='ucrt-nuget-signature', cap=150, env=env)
        return 'PASS: installed supported verifier succeeded'
    return 'NOT_VERIFIED: no installed supported verifier; exact package and entry hashes verified'


def junction(ctx, destination, target):
    require(not destination.exists() and target.is_dir(), 'SDK junction destination occupied or source absent')
    destination.parent.mkdir(parents=True, exist_ok=True)
    quote = lambda p: "'" + str(p).replace("'", "''") + "'"
    script = "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path " + quote(destination) + ' -Target ' + quote(target) + ' | Out-Null'
    ctx.command(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], name='sdk-junction-' + destination.name, cap=45)
    require(destination.resolve() == target.resolve(), 'SDK junction target mismatch')


def provision_ucrt(ctx, installed_sdk, tools):
    require(getattr(ctx, 'authorizations', {}).get('windows_sdk_license') is True,
            'Current Windows SDK license authorization required: https://aka.ms/WinSDKLicenseURL')
    pin = json.loads(Path(__file__).with_name('ucrt-package.json').read_text())
    archive = tools / 'microsoft.windows.sdk.cpp.x64.10.0.22000.194.nupkg'
    verify_download(ctx, {'url': pin['url'], 'size': pin['package_size'], 'sha256': pin['package_sha256']}, archive)
    actual512 = base64.b64encode(bytes.fromhex(sha(archive, 'sha512'))).decode('ascii')
    require(actual512 == pin['sha512_base64'], 'UCRT SHA-512 mismatch')
    signature = signature_check(ctx, archive, tools)
    extracted = tools / 'libucrt-22000-x64.lib'
    with zipfile.ZipFile(archive) as z:
        matches = [e for e in z.infolist() if e.filename == pin['entry_name']]
        require(len(matches) == 1, 'Missing/duplicate exact static UCRT entry')
        entry = matches[0]
        require(not entry.is_dir() and stat.S_IFMT(entry.external_attr >> 16) in {0, stat.S_IFREG} and not entry.flag_bits & 1, 'Unsafe/encrypted static UCRT entry')
        require(entry.file_size == pin['entry_size'] and entry.CRC == int(pin['entry_crc32'], 16), 'Static UCRT size/CRC mismatch')
        with z.open(entry) as src, extracted.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1024*1024)
    require(extracted.stat().st_size == pin['entry_size'], 'Extracted UCRT size mismatch')
    checked_hash(extracted, pin['entry_sha256'])
    coff = inspect_coff_archive(extracted)
    require(coff['members'] == 736 == pin['coff_member_count'], 'Expected exactly 736 AMD64 UCRT members')
    overlay = owned(ctx.root, 'sdk-overlay')
    overlay.mkdir()
    junction(ctx, overlay/'Include', installed_sdk/'Include')
    junction(ctx, overlay/'Lib'/SDK_VERSION, installed_sdk/'Lib'/SDK_VERSION)
    ucrt = overlay/'Lib/10.0.22000.0/ucrt/x64/libucrt.lib'
    ucrt.parent.mkdir(parents=True)
    shutil.copyfile(extracted, ucrt)
    checked_hash(ucrt, pin['entry_sha256'])
    ctx.receipt['ucrt_acquisition'] = {'package_sha256': sha(archive), 'entry_sha256': sha(ucrt), 'coff': coff,
        'signature': signature, 'license_url': pin['license_url'], 'overlay': str(overlay), 'system_sdk_modified': False}
    return overlay, ucrt


def validate_tar(archive, destination):
    """Inspect all names/types before CMake extracts this exact hash-pinned archive."""
    with tarfile.open(archive, 'r:xz') as tar:
        names = set()
        for member in tar:
            owned(destination, member.name)
            key = member.name.replace('\\', '/').casefold().rstrip('/')
            require(key not in names, 'Duplicate/case-alias LLVM archive member')
            names.add(key)
            require(member.isfile() or member.isdir(), 'LLVM archive link/special entry rejected')


def legacy_runtimes(windows_root):
    result = {}
    for dll in ('d3dx9_43.dll', 'd3dx11_43.dll', 'X3DAudio1_7.dll'):
        path = Path(windows_root)/'System32'/dll
        require(path.is_file(), 'Missing x64 legacy runtime: ' + dll + '; no automatic global installation')
        require(pe_machine(path) == 0x8664, 'Legacy runtime is not AMD64: ' + dll)
        try:
            ctypes.WinDLL(str(path))
        except (OSError, AttributeError) as exc:
            raise Blocked('Legacy runtime loader failed: ' + dll) from exc
        result[dll] = {'sha256': sha(path), 'architecture': 'AMD64', 'loadable': True}
    return result


def extract_tool_zip(ctx, archive, destination):
    """Hash-pinned official portable ZIP only; no install scripts/links/overwrite."""
    destination.mkdir()
    with zipfile.ZipFile(archive) as z:
        names=set(); total=0
        for entry in z.infolist():
            ctx.remaining(60)
            key=entry.filename.rstrip('/')
            path=owned(destination,key)
            require(key.casefold() not in names,'Duplicate/case-alias ZIP tool entry')
            names.add(key.casefold())
            kind=stat.S_IFMT(entry.external_attr>>16)
            require(not entry.flag_bits&1 and kind in {0,stat.S_IFREG,stat.S_IFDIR},'Encrypted/link/special tool ZIP entry')
            total+=entry.file_size
            require(total<=600*1024**2,'Portable tool ZIP expands beyond bound')
            if entry.is_dir(): path.mkdir(parents=True,exist_ok=True); continue
            path.parent.mkdir(parents=True,exist_ok=True)
            with z.open(entry) as src,path.open('xb') as dst:
                while chunk:=src.read(1024*1024):
                    ctx.remaining(60); dst.write(chunk)


def provision_build_tools(ctx, tools):
    pins=json.loads(Path(__file__).with_name('build-tools.json').read_text())
    require(pins['state']=='OFFICIAL_PINS_FROZEN','CMake/Ninja official pins incomplete')
    roots={}
    for name in ['cmake','ninja']:
        pin=pins[name]
        require(re.fullmatch(r'[0-9a-f]{64}',pin.get('sha256') or ''),'Tool hash is not frozen: '+name)
        archive=tools/(name+'.zip'); destination=tools/name
        verify_download(ctx,pin,archive);extract_tool_zip(ctx,archive,destination)
        roots[name]=destination
    found=list(roots['cmake'].glob('*/bin/cmake.exe'))
    require(len(found)==1,'CMake portable root missing/ambiguous')
    cmake=found[0]; ctest=cmake.with_name('ctest.exe'); ninja=roots['ninja']/'ninja.exe'
    for path,expected in [(cmake,'cmake version 3.31.6'),(ctest,'ctest version 3.31.6'),(ninja,'1.13.2')]:
        require(path.is_file() and pe_machine(path)==0x8664,'Build tool missing/not x64: '+str(path))
        text=ctx.command([path,'--version'],name=path.stem+'-version',cap=45).strip()
        require(text.splitlines()[0]==expected,'Pinned tool version mismatch: '+path.name)
    return cmake,ctest,ninja


def provision(ctx):
    require(os.name == 'nt', 'Toolchain provisioning requires Windows; import and unit tests are platform independent')
    root = Path(ctx.root)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'Existing absolute isolated job root required')
    pf = os.environ.get('ProgramFiles(x86)')
    require(pf, 'ProgramFiles(x86) missing')
    vswhere = Path(pf)/'Microsoft Visual Studio/Installer/vswhere.exe'
    require(vswhere.is_file(), 'Visual Studio locator missing')
    vs = Path(ctx.command([vswhere, '-latest', '-version', '[17.14,17.15)', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], name='vswhere', cap=45).strip())
    version_file = vs/'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt'
    require(version_file.is_file(), 'Visual Studio 17.14 MSVC default toolset missing')
    version = version_file.read_text().strip()
    require(re.fullmatch(r'14\.44\.\d+', version), 'Expected MSVC 14.44 toolset')
    msvc = vs/'VC/Tools/MSVC'/version
    require((msvc/'include/vcruntime.h').is_file(), 'MSVC vcruntime header missing')
    sdk = Path(pf)/'Windows Kits/10'
    for relative in ('Include/'+SDK_VERSION+'/um/d3d12.h', 'Include/'+SDK_VERSION+'/ucrt/stdio.h', 'Lib/'+SDK_VERSION+'/um/x64/kernel32.lib'):
        require((sdk/relative).is_file(), 'Modern SDK component missing: ' + relative)
    runtime = legacy_runtimes(os.environ.get('WINDIR', 'C:/Windows'))
    ctx.receipt['legacy_runtimes'] = runtime
    tools = owned(root, 'tools')
    tools.mkdir()  # fresh-only; never reuse unknown files
    cmake, ctest, ninja = provision_build_tools(ctx, tools)
    overlay, ucrt = provision_ucrt(ctx, sdk, tools)
    archive, unpack = tools/'llvm.tar.xz', tools/'llvm'
    verify_download(ctx, LLVM_PIN, archive)
    unpack.mkdir()
    validate_tar(archive, unpack)
    ctx.command([cmake, '-E', 'tar', 'xf', archive], name='llvm-extract', cap=600, cwd=unpack)
    found = list(unpack.glob('*/bin/clang-cl.exe')) + list(unpack.glob('bin/clang-cl.exe'))
    require(len(found) == 1, 'Portable LLVM root missing or ambiguous')
    llvm = found[0].parent.parent
    versions = {}
    for tool in LLVM_TOOLS:
        path = llvm/'bin'/(tool+'.exe')
        require(path.is_file() and path.resolve().is_relative_to(unpack.resolve()), 'Pinned LLVM tool missing/outside root: '+tool)
        require(pe_machine(path) == 0x8664, 'Pinned LLVM tool is not AMD64: '+tool)
        versions[tool] = {'sha256': sha(path)}
    for tool in ('clang-cl', 'lld-link', 'llvm-readobj'):
        output = ctx.command([llvm/'bin'/(tool+'.exe'), '--version'], name=tool+'-version', cap=45)
        require(re.search(r'\b22\.1\.7\b', output), 'LLVM binary version mismatch: '+tool)
    coff = ctx.command([llvm/'bin/llvm-readobj.exe', '--file-headers', ucrt], name='ucrt-coff', cap=120)
    machines = re.findall(r'Machine:\s+(IMAGE_FILE_MACHINE_[A-Z0-9_]+)', coff)
    require(len(machines) == 736 and set(machines) == {'IMAGE_FILE_MACHINE_AMD64'}, 'LLVM must confirm 736 AMD64 UCRT objects')
    ctx.receipt['tools'] = {'cmake': '3.31.6', 'ninja': '1.13.2', 'llvm': '22.1.7', 'msvc': version,
        'sdk_headers': SDK_VERSION, 'llvm_archive_sha256': LLVM_PIN['sha256'], 'llvm_tools': versions,
        'cmake_sha256': sha(cmake), 'ctest_sha256': sha(ctest), 'ninja_sha256': sha(ninja)}
    ctx.receipt['in_job_ucrt_gate'] = 'PASS'
    return dict(cmake=cmake, ctest=ctest, ninja=ninja, llvm=llvm, msvc=msvc,
                sdk_root=overlay, sdk_version=SDK_VERSION, ucrt=ucrt, runtime=runtime)


def expand_rsp(command, build):
    result = command
    for quoted, bare in re.findall(r'@(?:"([^"]+)"|([^\s"&]+))', command):
        path = Path(quoted or bare)
        if not path.is_absolute():
            path = Path(build)/path
        require(path.is_file() and path.resolve().is_relative_to(Path(build).resolve()), 'Missing/out-of-build actual link response file')
        content = path.read_text(encoding='utf-8-sig')
        require(not re.search(r'(?:^|\s)@', content), 'Nested link response file not supported')
        result += '\n' + content
    return result


def validate_actual_links(log, build, ucrt, targets):
    """Inspect the caller's engine/faf_sim final EXEs in a full verbose Ninja log.

    Use -d keeprsp. Only targets consuming the pinned UCRT belong here:
    faf_engine exports both NODEFAULTLIB exclusions; faf_sim (headless)
    explicitly links the same UCRT and inherits those link options.
    Standalone faf_effect_scan_tests does NOT consume faf_engine and must be
    checked separately for AMD64 PE/static imports, not passed as a target.
    Unselected standalone link commands in the same log are ignored.
    """
    expected = str(Path(ucrt)).replace('\\', '/').casefold()
    evidence = []
    require(targets, 'Actual-link target list must not be empty')
    for target in targets:
        candidates = []
        for line in log.splitlines():
            if 'lld-link' not in line.lower():
                continue
            expanded = expand_rsp(line, build)
            outputs = re.findall(r'/out:(?:"([^"\r\n]+)"|([^\s]+))', expanded, re.I)
            if any((a or b).replace('\\', '/').rsplit('/', 1)[-1].casefold() == target.casefold() for a, b in outputs):
                candidates.append(expanded)
        require(len(candidates) == 1, 'Expected exactly one actual final link for '+target)
        command = candidates[0]
        normalized = command.replace('\\', '/').casefold()
        tokens = re.findall(r'"([^"\r\n]*)"|([^\s"]+)', normalized)
        values = [a or b for a,b in tokens]
        require(expected in values, 'Exact absolute UCRT missing from actual link: '+target)
        require('/nodefaultlib:libucrt.lib' in values and '/nodefaultlib:ucrt.lib' in values, 'Default UCRT exclusions missing: '+target)
        libraries = [v for v in values if re.search(r'(?:libucrtd?|ucrtd?)\.lib$', v) and not v.startswith('/nodefaultlib:')]
        require(libraries and all(v == expected for v in libraries), 'Alternate UCRT input in actual link: '+target)
        evidence.append({'target': target, 'command_sha256': hashlib.sha256(command.encode()).hexdigest(), 'exact_ucrt_verified': True})
    return evidence
