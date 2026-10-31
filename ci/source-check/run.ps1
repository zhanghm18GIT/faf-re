param([Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceSha,
      [Parameter(Mandatory)][ValidatePattern('^2026-10-31$')][string]$ApprovalDate)
# Public, source-only, disposable runner; no credentials, assets or uploads.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Checked([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit $LASTEXITCODE" }
}
function HashIs([string]$File, [string]$Expected) {
    if (!(Test-Path -LiteralPath $File -PathType Leaf) -or
        (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
        throw "SHA256 mismatch: $(Split-Path -Leaf $File)"
    }
}
# Git may check out text as CRLF on Windows. Normalize only CRLF, not content.
function SourceHashIs([string]$File, [string]$Expected) {
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = [IO.File]::ReadAllBytes($File)
    $text = $utf8.GetString($bytes)
    $normalized = $utf8.GetBytes($text.Replace("`r`n", "`n"))
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($normalized)).ToLowerInvariant()
    $rawHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    $crlfCount = [regex]::Matches($text, "`r`n").Count
    Write-Host "Source identity $(Split-Path -Leaf $File): raw bytes=$($bytes.Length) SHA256=$rawHash; CRLF=$crlfCount; normalized bytes=$($normalized.Length) SHA256=$hash"
    if ($hash -cne $Expected) { throw "Normalized source SHA256 mismatch: $(Split-Path -Leaf $File)" }
}
function Fetch([string]$Url, [string]$File, [string]$Sha) {
    Invoke-WebRequest -Uri $Url -OutFile $File -MaximumRedirection 3
    HashIs $File $Sha
}
function Posix([string]$Path) { return $Path.Replace('\','/') }
if (!$IsWindows -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne 'zhanghm18GIT/faf-re') {
    throw 'Requires intended public fork on Windows hosted runner'
}
if (![Environment]::Is64BitOperatingSystem -or $env:RUNNER_ARCH -ne 'X64') { throw 'Requires x64 Windows host for LAA x86 acceptance' }
if ([string]::IsNullOrWhiteSpace($ApprovalDate)) { throw 'Scoped SDK/public build approval required' }
$source = (Resolve-Path "$PSScriptRoot/../..").Path
Set-Location $source
$actual = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -or $actual -cne $SourceSha) { throw 'Source SHA mismatch' }
# Exact current upstream plus baseline-only native test seam.
$identities = @(
    @('.gitmodules','8777f05826e811b5d0fb3ae7b3fbb30500cdda8e','1a9da3812d426e1d02daf69e121c1bbf27bf7da8fc30f1ea3bbf4601cf998b05'),
    @('CMakeLists.txt','940009c010dbb4f346cc3f41a9c234264f86cd43','3d17310999a93ca23c8999ec97f89b7982339fb1855810365306129aad3a18d7'),
    @('cmake/FafDependencies.cmake','92d2c9d84da6dce8962f32004da5034f00a311be','cd932380c3a52e62d3be790a10cdb7c1dc73096ff089e9078ae8c77bb18bd44e'),
    @('cmake/toolchains/clang-cl-common.cmake','41b52146a682966934c5d490673a72b2eab7f282','ae7f798ec54d9c693823b98d54e64abcac21e08b6dd743706991d23cbe316cea'),
    @('cmake/toolchains/clang-cl-x86.cmake','af823fcf6427d3d400f8dfe9c2605a09c47f227b','12c94da6bafc19b6993f8f33b59a46c95ec3c3871e4379f35c8e26b99e0a33c1'),
    @('src/CMakeLists.txt','36f624f3ac200824c6b371070b9cf2c9b3ee2336','4dfa21a57a903b91218ae8814aabfac9f4f8bb474a53448ee4799ca2894a1b2c'),
    @('src/gpg/core/utils/Global.cpp','5492c1eaa4bbad201781e36a80fe913fa022f170','7d17a9322f6823d2df5fd499eaec104349dd2692097ff1c562ee95c6c3d6c872'),
    @('src/gpg/gal/MeshFormatter.cpp','2c547c446bd5781eb1f8f0e81c8d575940f9fa5c','3aac870af7d02461377f2d30cd4550aeac228f3d12700b54e934861e63b75aa3'),
    @('src/gpg/gal/MeshFormatter.h','c35f7faf50e8ba2f17938abcf37bcaa2b0990e87','33f8e89b0a1a7091e2888ec767bb52fb76b02a0049118cb00fe0cb044eb6a602'),
    @('src/gpg/gal/backends/d3d10/D3D10Interfaces.cpp','b5382d005f8b5d684822c26d455d44ef95bad9d2','79ff660104b3afaedecb83554e63bb9045acd3c4111ea7418245d4df0da498a3'),
    @('tests/CMakeLists.txt','d83c889cb1ba76728578ed02f16e51591619e621','bfb0ee41a191de37e0bb3391af8ff01c36301001321e175b897e08aa0f4f711a'),
    @('tests/memory/AllocatorBoundsNative.cpp','6167ff87fc767dd6b084c7da6aaf6440e2783e18','f2b90034e4901d7ac65f3c957411d7195ee0d2012cb9c6f46bf1336db3f5956a'),
    @('tests/memory/AllocatorBoundsNative.inl','ae834e65a655c4f61e453129fe935b067f3ebfa8','79951a3277708a69c371f2aec97fa9771e8894eecf96ae4868ffda6372db78ab'),
    @('tests/memory/CMakeLists.txt','a282c2b5442b8e2aed02ffa521ef6b9d8e8ba3b1','7f59372bc9b783a27b7d6efba5f6ca4d2fc25ec19b69e2f3e17fad0f553c77f2')
)
foreach ($row in $identities) {
    $blob = (& git rev-parse "HEAD:$($row[0])").Trim()
    if ($LASTEXITCODE -or $blob -cne $row[1]) { throw "Committed source identity mismatch: $($row[0])" }
    SourceHashIs "$source/$($row[0])" $row[2]
}
# Exact already-approved dependency gitlinks and patch tree, before downloads.
$dependencyIdentities = @(
    @('dependencies/FX11','bec3b8fcd8849fcfe0125fbd1a62927e2ada99cc'),
    @('dependencies/WildMagic3p8','9baf054aea272090e0df3289e24cf436fb92c78c'),
    @('dependencies/ffmpeg','8f9ea179334d8ff01292728b9704b7da1f712c5f'),
    @('dependencies/patches','4783e28d8270a2b0a4b30576abae48741500eee6'),
    @('dependencies/vulkan','d4a196d8c84e032d27f999adcea3075517c1c97f'),
    @('dependencies/zlib-1.2.3','abf180a067223611620dd97dd5681df7c7fa7c9b')
)
foreach ($row in $dependencyIdentities) {
    $identity = (& git rev-parse "HEAD:$($row[0])").Trim()
    if ($LASTEXITCODE -or $identity -cne $row[1]) { throw "Dependency identity mismatch: $($row[0])" }
}
$root = Join-Path $env:RUNNER_TEMP 'x86-allocator-source-check'
if (Test-Path $root) { throw 'Runner scratch directory must be fresh' }
New-Item -ItemType Directory -Path $root | Out-Null
$llvm = 'C:/Program Files/LLVM'
foreach ($name in @('clang-cl','clang','lld-link','llvm-lib','llvm-rc','llvm-mt','llvm-readobj','llvm-ml')) {
    if (!(Test-Path "$llvm/bin/$name.exe")) { throw "Missing preinstalled LLVM tool $name" }
}
foreach ($name in @('cmake','ninja','git','python')) { Checked $name @('--version') }
$clangVersion = (& "$llvm/bin/clang-cl.exe" --version) -join "`n"
if ($LASTEXITCODE -or $clangVersion -notmatch 'clang version 20\.1\.8\b') { throw 'Review unexpected LLVM release before running' }
Write-Host $clangVersion
Checked "$llvm/bin/lld-link.exe" @('--version')
$vswhere = "${env:ProgramFiles(x86)}/Microsoft Visual Studio/Installer/vswhere.exe"
$vs = & $vswhere -latest -version '[17.0,18.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -or !$vs) { throw 'VS2022 C++ workload missing' }
$vcVersion = (Get-Content "$vs/VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt" -Raw).Trim()
$vc = Posix "$vs/VC/Tools/MSVC/$vcVersion"
foreach ($leaf in @('include/vcruntime.h','include/vector','lib/x86/libcmt.lib','lib/x86/libvcruntime.lib')) {
    if (!(Test-Path "$vc/$leaf")) { throw "MSVC component missing $leaf" }
}
$sdk = "${env:ProgramFiles(x86)}/Windows Kits/10"
$versions = @(Get-ChildItem "$sdk/Include" -Directory | Where-Object {
    $_.Name -match '^10\.0\.\d+\.\d+$' -and (Test-Path "$($_.FullName)/um/windows.h")
} | Sort-Object { [version]$_.Name } -Descending)
if (!$versions.Count) { throw 'Preinstalled Windows SDK missing' }
$headers = $versions[0].Name
foreach ($leaf in @("Include/$headers/ucrt/stdio.h", "Lib/$headers/um/x86/kernel32.lib")) {
    if (!(Test-Path "$sdk/$leaf")) { throw "SDK component missing $leaf" }
}
# Only official data package; never invoke NuGet/MSBuild/installers.
$package = "$root/ucrt.nupkg"
Fetch 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp.x86/10.0.22000.196/microsoft.windows.sdk.cpp.x86.10.0.22000.196.nupkg' $package '54b2d290b4e315b0111fa4fada52b436672733687455060dc5b6f75e74ab4c5b'
$overlay = "$root/sdk"
New-Item -ItemType Directory -Path "$overlay/Lib/10.0.22000.0/ucrt/x86" -Force | Out-Null
New-Item -ItemType Junction -Path "$overlay/Include" -Target "$sdk/Include" | Out-Null
if ($headers -eq '10.0.22000.0') { throw 'Overlay layout requires separate current SDK header/UM version; review runner' }
New-Item -ItemType Junction -Path "$overlay/Lib/$headers" -Target "$sdk/Lib/$headers" | Out-Null
$ucrt = "$overlay/Lib/10.0.22000.0/ucrt/x86/libucrt.lib"
$zip = [IO.Compression.ZipFile]::OpenRead($package)
try {
    $entries = @($zip.Entries | Where-Object { $_.FullName -ceq 'c/ucrt/x86/libucrt.lib' })
    if ($entries.Count -ne 1) { throw 'Unexpected UCRT archive layout' }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $ucrt, $false)
} finally { $zip.Dispose() }
HashIs $ucrt 'b37c09557bb7c2dc29da57f85c3dce85243d03b9e0312082a2468dcafd677956'
# Native x86 assembler, no ml64 alias or x64 libraries.
$masm = "$llvm/bin/llvm-ml.exe"
$env:FAF_CI_SOURCE = Posix $source
$env:FAF_CI_MASM = Posix $masm
$adapter = Posix "$PSScriptRoot/toolchain.cmake"
$common = @('-G','Ninja','-DCMAKE_BUILD_TYPE=Release',"-DCMAKE_TOOLCHAIN_FILE=$adapter",
    "-DFAF_LLVM_ROOT=$llvm", "-DFAF_MSVC_TOOLS_DIR=$vc", "-DFAF_WINSDK_DIR=$(Posix $overlay)",
    "-DFAF_WINSDK_VERSION=$headers", '-DFAF_UCRT_LIB_VERSION=10.0.22000.0')
Write-Host "Source $actual; runner $env:ImageVersion; MSVC $vcVersion; SDK headers $headers; static UCRT 10.0.22000.0"
# New disposable source tree only. Upstream verifies download hashes and applies its patches.
$build = "$root/build"
Checked cmake (@('-S',$source,'-B',$build,'-DFAF_ENABLE_TRACY=OFF','-DFAF_DXSDK_FORCE_DOWNLOAD=ON','-DFAF_SERVER_MODE=OFF','-DFAF_ALLOCATOR_BOUNDARY_TESTS=ON','-DFAF_OUTPUT_NAME=faf_allocator_ci_x86') + $common)
$dxArchive = "$source/dependencies/.downloads/DXSDK_Jun10.exe"
HashIs $dxArchive '705271dc83bfee54d9b94e028426e288d5f070784b7446d164f48ecfbb2a02cb'
$runtime = "$root/runtime"
New-Item -ItemType Directory -Path $runtime | Out-Null
Checked cmake @("-DSDK_ARCHIVE=$(Posix $dxArchive)", "-DDEST=$(Posix $runtime)", '-P', "$PSScriptRoot/runtime.cmake")
$dlls = @(
  @('Jun2010_D3DCompiler_43_x86.cab','417eebd5b19f45c67c94c2d2ba8b774c0fc6d958b896d7b1ac12cf5a0ea06e0e','D3DCompiler_43.dll','2f23182ec6f4889397ac4bf03d62536136c5bdba825c7d2c4ef08c827f3a8a1c'),
  @('Jun2010_d3dx9_43_x86.cab','fcc6cf0966b4853d6fa3d32ab299cde5a9824feaecb0d4f34ea452fb9fd1c867','d3dx9_43.dll','0b28546be22c71834501f7d7185ede5d79742457331c7ee09efc14490dd64f5f'),
  @('Feb2010_X3DAudio_x86.cab','acba5c4d4ac90e1df1c8404be5ff780e24238153cb410af909cd4364d213f2a9','X3DAudio1_7.dll','288c701bdedf1d45c63dd0b7d424a752f8819f90feb5088c582f76bc98970ba3')
)
foreach ($row in $dlls) {
    $cab = "$runtime/DXSDK/Redist/$($row[0])"
    HashIs $cab $row[1]
    Checked "$env:SystemRoot/System32/expand.exe" @($cab, "-F:$($row[2])", $runtime)
    HashIs "$runtime/$($row[2])" $row[3]
}
# Required before sim-math automatic POST_BUILD execution; process-local only.
$env:PATH = "$runtime;$env:PATH"
HashIs "$source/dependencies/.downloads/dxc_2026_09_29.zip" 'ad31b1fc8443175d204f77a611fdb3ef2ec42759bdc2f1167368de24a4a7e7f1'
HashIs "$source/dependencies/dxc/bin/x86/dxcompiler.dll" '691b2578c2ef13aaaa41b543d1b6019b1f0ebfcef3b9568d78ce2dbaa359faf7'
HashIs "$source/dependencies/dxc/bin/x86/dxil.dll" 'ebf7f9dabeb6d80a167a5b7cab9275573f061afd7b86a90bf5c579d58f9d08dd'
# Fail closed on missing x86 DXC runtime from the unchanged pinned package.
foreach ($dll in @('dxcompiler.dll','dxil.dll')) {
    if (!(Test-Path "$source/dependencies/dxc/bin/x86/$dll")) { throw "Missing pinned x86 DXC $dll" }
}
$targetListing = & ninja -C $build -t targets all
if ($LASTEXITCODE -ne 0) { throw 'Ninja discovery failed' }
$objects = @()
foreach ($suffix in @('/gpg/core/utils/Global.cpp.obj','/faf_allocator_bounds_tests.dir/AllocatorBoundsNative.cpp.obj')) {
    $objectMatches = @($targetListing | ForEach-Object {
        if ($_ -match '^(.+): [^:]+$') {
            $target = $Matches[1].Replace('\','/')
            if ($target.EndsWith($suffix, [StringComparison]::Ordinal)) { $target }
        }
    })
    if ($objectMatches.Count -ne 1) { throw "Expected one object for $suffix; found $($objectMatches.Count)" }
    $objects += $objectMatches[0]
}
Checked ninja (@('-C',$build,'-j','2') + $objects)
Checked cmake @('--build',$build,'--parallel','2','--target','faf_allocator_bounds_tests','faf_net_tests','faf_profiler_tests','faf_sim_math_tests')
function NativeExe {
    $listing = & ctest --test-dir $build --show-only=json-v1
    if ($LASTEXITCODE -ne 0) { throw 'CTest listing failed' }
    $tests = (($listing -join "`n") | ConvertFrom-Json).tests
    $expected = @('allocator_bounds_high','allocator_bounds_low','allocator_bounds_map','allocator_bounds_normal','allocator_bounds_separate','net_robustness','profiler_facade','sim_math')
    $names = @($tests | ForEach-Object { $_.name } | Sort-Object)
    if ($names.Count -ne 8 -or @((Compare-Object $expected $names)).Count -ne 0) { throw 'Exactly eight baseline/candidate test registrations required' }
    $entry = @($tests | Where-Object { $_.name -ceq 'allocator_bounds_normal' })
    return $entry[0].command[0]
}
$native = NativeExe
& "$PSScriptRoot/accept-phase.ps1" -Variant baseline -Exe $native -BuildDirectory $build -LogDirectory "$root/logs"
# The same reviewed test seam remains; only x86 production constants change.
SourceHashIs "$PSScriptRoot/production.patch" 'c6a2530cec0fd25aa804695cc1106e906cbb40105a84d386b3944c016074f818'
Checked git @('apply','--check',"$PSScriptRoot/production.patch")
Checked git @('apply',"$PSScriptRoot/production.patch")
SourceHashIs "$source/src/gpg/core/utils/Global.cpp" '2d151e855ef79a89e97c6fafe01fa60499aee2251d5fce5b4f9a9682d12f6cba'
Checked ninja (@('-C',$build,'-j','2') + $objects)
Checked cmake @('--build',$build,'--parallel','2','--target','faf_main','faf_allocator_bounds_tests','faf_net_tests','faf_profiler_tests','faf_sim_math_tests')
$native = NativeExe
& "$PSScriptRoot/accept-phase.ps1" -Variant candidate -Exe $native -BuildDirectory $build -LogDirectory "$root/logs"
# Both test and actual client must be I386 PE32 LARGEADDRESSAWARE.
$main = @(Get-ChildItem -LiteralPath $build -Filter 'faf_allocator_ci_x86.exe' -Recurse -File)
if ($main.Count -ne 1) { throw 'Exactly one x86 client executable required' }
$peBytes = [IO.File]::ReadAllBytes($main[0].FullName)
if ($peBytes.Length -lt 64 -or [BitConverter]::ToUInt16($peBytes,0) -ne 0x5A4D) { throw 'Invalid client DOS header' }
$pe = [BitConverter]::ToInt32($peBytes,0x3c)
if ($pe -lt 0 -or $pe -gt ($peBytes.Length-26) -or [BitConverter]::ToUInt32($peBytes,$pe) -ne 0x4550 -or [BitConverter]::ToUInt16($peBytes,$pe+4) -ne 0x14c -or [BitConverter]::ToUInt16($peBytes,$pe+24) -ne 0x10b -or (([BitConverter]::ToUInt16($peBytes,$pe+22) -band 0x20) -eq 0)) { throw 'Client must be I386 PE32 LARGEADDRESSAWARE' }
Checked ctest @('--test-dir',$build,'--verbose','--output-on-failure','--no-tests=error','--timeout','120','-R','^(net_robustness|profiler_facade|sim_math)$')
@"
## Source-only x86 allocator validation
- Commit baseline: $actual; candidate: frozen production.patch SHA verified before application.
- PASS: baseline exact high/map assertion failures, low/normal/separate controls; candidate five native cases; x86 client compile/link/PE/LAA; stock core tests.
- Required high-address evidence is fail-closed: unavailable exit77 is BLOCKED, never skipped/passed.
- NOT TESTED: forced public malloc high-address reservation, final inaccessible Windows page, game/replay parity, performance, x64.
- No binaries, SDK files, game data or private telemetry uploaded.
"@ | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
