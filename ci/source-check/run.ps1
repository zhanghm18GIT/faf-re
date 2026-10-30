param([Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceSha,
      [Parameter(Mandatory)][ValidatePattern('^2026-10-30$')][string]$ApprovalDate)
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
if ([string]::IsNullOrWhiteSpace($ApprovalDate)) { throw 'Scoped SDK/public build approval required' }
$source = (Resolve-Path "$PSScriptRoot/../..").Path
Set-Location $source
$actual = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -or $actual -cne $SourceSha) { throw 'Source SHA mismatch' }
# Current b7cf5a24 full-float default-0 base and reviewed test overlay.
$identities = @(
    @('.gitmodules','8777f05826e811b5d0fb3ae7b3fbb30500cdda8e','1a9da3812d426e1d02daf69e121c1bbf27bf7da8fc30f1ea3bbf4601cf998b05'),
    @('CMakeLists.txt','940009c010dbb4f346cc3f41a9c234264f86cd43','3d17310999a93ca23c8999ec97f89b7982339fb1855810365306129aad3a18d7'),
    @('cmake/FafDependencies.cmake','92d2c9d84da6dce8962f32004da5034f00a311be','cd932380c3a52e62d3be790a10cdb7c1dc73096ff089e9078ae8c77bb18bd44e'),
    @('cmake/toolchains/clang-cl-x64.cmake','69c09b528767cb2dd3753ca59c726438cfd19185','c94f12f9a8e00121f56f0c7431ff52bce75ef3b3568bc606f33ebedfc0f3a2c8'),
    @('src/CMakeLists.txt','36f624f3ac200824c6b371070b9cf2c9b3ee2336','4dfa21a57a903b91218ae8814aabfac9f4f8bb474a53448ee4799ca2894a1b2c'),
    @('src/gpg/core/utils/Global.cpp','2c93927323d555ef15a18ce8d34f0737a2326192','079faf46b4dc5b5d82260209d1f005bc2dec7a188b68159de6e8675dcc70a8c6'),
    @('src/gpg/gal/MeshFormatter.cpp','2c547c446bd5781eb1f8f0e81c8d575940f9fa5c','3aac870af7d02461377f2d30cd4550aeac228f3d12700b54e934861e63b75aa3'),
    @('src/gpg/gal/MeshFormatter.h','c35f7faf50e8ba2f17938abcf37bcaa2b0990e87','33f8e89b0a1a7091e2888ec767bb52fb76b02a0049118cb00fe0cb044eb6a602'),
    @('src/gpg/gal/backends/d3d10/D3D10Interfaces.cpp','b5382d005f8b5d684822c26d455d44ef95bad9d2','79ff660104b3afaedecb83554e63bb9045acd3c4111ea7418245d4df0da498a3'),
    @('src/moho/entity/CTextureScroller.cpp','f5e5855ecb6dff1d8c08ea01fe5fe4c60a40c58b','60240d85cb1bff5647af8d452040ac37406d4ab6751650a6bd2754b5136d8ae3'),
    @('src/moho/entity/CTextureScroller.h','095ba7ca98e98c2a4dc1cdd82273fca168c08753','bc085a53b6dfa3d880a071f6dd97b8c85f5e5dfe5195c0ec0c3e095df74e6236'),
    @('src/moho/entity/Entity.cpp','42607cd7cc33a4e6468a1e46ccc3d60d6bbce85d','cc5bab0e48d01797ae91f5cc62229b915a0e16b6ae0a966a79f8a492c0eaed6a'),
    @('src/moho/entity/Entity.h','c3025bfdd4376157f045dd58b2ab9a03eb736ef0','c8b8f159b02b1611d25ce846a20998bc2ac44ec812f49db1fb5fe3a1d19567c8'),
    @('src/moho/entity/SSTIEntityVariableData.cpp','ffb264f9eb36d01aa767c29299b3a42dfb4b59b2','210ab80344b31f257457acbc5c13d8b1fefb38a5583615b4f4d6cc61aa73f2d5'),
    @('src/moho/entity/SSTIEntityVariableData.h','149e5f72c10ab4a7b48f554efa6c33d7782a7c45','3c91734e8fc078e4342ca6f88cb807ddfbe9ebdac6f9c96eabcb9eb89697ecd9'),
    @('src/moho/entity/TreadComponentTestSeams.h','76a234614dcec315b38e9052cfe0a8e09db653fa','160126ae67a1b5bf776dc575894786a6a09259a75f03ce8d93ec6c9a76618a26'),
    @('src/moho/entity/UserEntity.cpp','af387fa9aa0f0fcdefccfd39e3c236ffbf4e9287','44d6e5fe4d3354a30bbbea406ef817b774b404e6ca37be67a317f0ea18cb5ffc'),
    @('src/moho/mesh/HardwareMeshBatch.cpp','3a583f7b2eaa5da25aa575ddb6ca066757d636e8','6cb21e0adb0e6e5886fb917fe94372605963b89f3faed6da54ea2d58d699c59f'),
    @('src/moho/sim/ReconBlip.cpp','f90a8e1b86d94a8a117cc64686a2def139585208','0b55cc50f511bc62289e1ae5ebbd996d53d6637f522765e6f48e41152ea96e9e'),
    @('src/moho/sim/SimDriver.h','a9e541ceb120f2e3f7b02e0f09626d652081294e','f6aa57bdf931b9ec92f6dc4ff39e9551baa5cf76fac9e10a8b8612571459a2ca'),
    @('src/moho/sim/SimWorkerPool.h','2d6eeae602db31f6ce1970d4e7fa75f07b78ba8a','2910613ada701d02e366be884f21e2d5ae1a61f365ebe52e3b8beac28342b13d'),
    @('src/moho/sim/UnitUpdateFill.cpp','843214eb5a59b77ea57a366233007a61bffd6f01','7a7948216065917ddb6ddea407f5f6e0685446d0165071225187f1e59fdc1fe6'),
    @('src/moho/sim/UnitUpdateFill.h','1af96d0fed813a08f4258d21350094722ddbf171','0724a0740ce6ae9a777c62ee560748c31003ea89160017f845971d4c64430022'),
    @('tests/CMakeLists.txt','218447ff8aeb7fd317154672a9429153382b7c65','0f74eafc671720422451d5714f5e2da1dff9b40893749f4499796cbc9e0fe3af'),
    @('tests/memory/X64AllocatorTests.cpp','cb89b5790a6b04fbddea7344cd34176110613d10','aa5de602c2b4f8d788b39c8c19be5b0aeedf47bd8ab72b376316dc5579ae6cc3'),
    @('tests/remote/CMakeLists.txt','9e3daf3612c49c91758425d4ca1f1fec52a4fb41','0b1cccf987519f1ead1840d6240fe753348245359e0235927899bd0759f56b00'),
    @('tests/tread/CMakeLists.txt','97f5536ed57ce113fc63c6b1d72af48ccb75a74b','e3117d0cb32f91e521831a49566c1c99ee8ed898d113bfc103c462d7a6cc6e65'),
    @('tests/tread/TreadComponentTests.cpp','aaca06a2387c485e7e4240beca63d568cb2f45bd','6f631cc92488340ebabc11f9ff23791a30628f42fe36bb85ff72b2ee8120fe7a')
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
$root = Join-Path $env:RUNNER_TEMP 'current-engine-source-check'
if (Test-Path $root) { throw 'Runner scratch directory must be fresh' }
New-Item -ItemType Directory -Path $root | Out-Null
$llvm = 'C:/Program Files/LLVM'
foreach ($name in @('clang-cl','clang','lld-link','llvm-lib','llvm-rc','llvm-mt','llvm-readobj')) {
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
foreach ($leaf in @('include/vcruntime.h','include/vector','lib/x64/libcmt.lib','lib/x64/libvcruntime.lib')) {
    if (!(Test-Path "$vc/$leaf")) { throw "MSVC component missing $leaf" }
}
$sdk = "${env:ProgramFiles(x86)}/Windows Kits/10"
$versions = @(Get-ChildItem "$sdk/Include" -Directory | Where-Object {
    $_.Name -match '^10\.0\.\d+\.\d+$' -and (Test-Path "$($_.FullName)/um/windows.h")
} | Sort-Object { [version]$_.Name } -Descending)
if (!$versions.Count) { throw 'Preinstalled Windows SDK missing' }
$headers = $versions[0].Name
foreach ($leaf in @("Include/$headers/ucrt/stdio.h", "Lib/$headers/um/x64/kernel32.lib")) {
    if (!(Test-Path "$sdk/$leaf")) { throw "SDK component missing $leaf" }
}
# Only official data package; never invoke NuGet/MSBuild/installers.
$package = "$root/ucrt.nupkg"
Fetch 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp.x64/10.0.22000.196/microsoft.windows.sdk.cpp.x64.10.0.22000.196.nupkg' $package '6d83c2c9e2ac3d43e74dd200fd90744cb8b7f9ee780dbcb735a21f4a2542b556'
$overlay = "$root/sdk"
New-Item -ItemType Directory -Path "$overlay/Lib/10.0.22000.0/ucrt/x64" -Force | Out-Null
New-Item -ItemType Junction -Path "$overlay/Include" -Target "$sdk/Include" | Out-Null
if ($headers -eq '10.0.22000.0') { throw 'Overlay layout requires separate current SDK header/UM version; review runner' }
New-Item -ItemType Junction -Path "$overlay/Lib/$headers" -Target "$sdk/Lib/$headers" | Out-Null
$ucrt = "$overlay/Lib/10.0.22000.0/ucrt/x64/libucrt.lib"
$zip = [IO.Compression.ZipFile]::OpenRead($package)
try {
    $entries = @($zip.Entries | Where-Object { $_.FullName -ceq 'c/ucrt/x64/libucrt.lib' })
    if ($entries.Count -ne 1) { throw 'Unexpected UCRT archive layout' }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $ucrt, $false)
} finally { $zip.Dispose() }
HashIs $ucrt '56378d8598e3134d5c7e844079e07c1a56ad7c138f74d5f398f7452e5abc6550'
# LLVM20 driver selects x64 by ml64 basename. Byte-identical alias in TEMP only.
$masm = "$llvm/bin/llvm-ml64.exe"
if (!(Test-Path $masm)) {
    $masm = "$root/llvm-ml64.exe"
    Copy-Item "$llvm/bin/llvm-ml.exe" $masm
    HashIs $masm (Get-FileHash "$llvm/bin/llvm-ml.exe" -Algorithm SHA256).Hash.ToLowerInvariant()
}
$env:FAF_CI_SOURCE = Posix $source
$env:FAF_CI_MASM = Posix $masm
$adapter = Posix "$PSScriptRoot/toolchain.cmake"
$common = @('-G','Ninja','-DCMAKE_BUILD_TYPE=Release',"-DCMAKE_TOOLCHAIN_FILE=$adapter",
    "-DFAF_LLVM_ROOT=$llvm", "-DFAF_MSVC_TOOLS_DIR=$vc", "-DFAF_WINSDK_DIR=$(Posix $overlay)",
    "-DFAF_WINSDK_VERSION=$headers", '-DFAF_UCRT_LIB_VERSION=10.0.22000.0')
Write-Host "Source $actual; runner $env:ImageVersion; MSVC $vcVersion; SDK headers $headers; static UCRT 10.0.22000.0"
# New disposable source tree only. Upstream verifies download hashes and applies its patches.
$build = "$root/build"
Checked cmake (@('-S',$source,'-B',$build,'-DFAF_ENABLE_TRACY=OFF','-DFAF_DXSDK_FORCE_DOWNLOAD=ON','-DFAF_SERVER_MODE=OFF','-DFAF_TREAD_COMPONENT_TESTS=ON') + $common)
$dxArchive = "$source/dependencies/.downloads/DXSDK_Jun10.exe"
HashIs $dxArchive '705271dc83bfee54d9b94e028426e288d5f070784b7446d164f48ecfbb2a02cb'
$runtime = "$root/runtime"
New-Item -ItemType Directory -Path $runtime | Out-Null
Checked cmake @("-DSDK_ARCHIVE=$(Posix $dxArchive)", "-DDEST=$(Posix $runtime)", '-P', "$PSScriptRoot/runtime.cmake")
$dlls = @(
  @('Jun2010_d3dx9_43_x64.cab','9b98a1269af7f3a0007bfdc73206a47a6ee158d34ba8a87009396c18186bb06a','d3dx9_43.dll','84b900dbd7fa978d6e0caee26fc54f2f61d92c9c75d10b35f00e3e82cd1d67b4'),
  @('Feb2010_X3DAudio_x64.cab','832b6d48e169b4725ae482ea4d1c3360a09631a89b2fac3aba81a50805a50adc','X3DAudio1_7.dll','9460709339701ad471a5cabe6365355f4d586dc4fcb86507c1331839dc555446'),
  @('Jun2010_D3DCompiler_43_x64.cab','213ad66ab9e469db1e6a49a646d082bfc3700db94172984e7e36801612af50c6','D3DCompiler_43.dll','44c3a7e330b54a35a9efa015831392593aa02e7da1460be429d17c3644850e8a')
)
foreach ($row in $dlls) {
    $cab = "$runtime/DXSDK/Redist/$($row[0])"
    HashIs $cab $row[1]
    Checked "$env:SystemRoot/System32/expand.exe" @($cab, "-F:$($row[2])", $runtime)
    HashIs "$runtime/$($row[2])" $row[3]
}
# Required before sim-math automatic POST_BUILD execution; process-local only.
$env:PATH = "$runtime;$env:PATH"
# Discover real generated object targets; missing/ambiguous targets fail closed.
$targetListing = & ninja -C $build -t targets all
if ($LASTEXITCODE -ne 0) { throw 'Ninja target discovery failed' }
$objects = @()
foreach ($suffix in @('/moho/entity/Entity.cpp.obj','/moho/entity/CTextureScroller.cpp.obj','/moho/entity/UserEntity.cpp.obj','/moho/entity/SSTIEntityVariableData.cpp.obj','/moho/mesh/HardwareMeshBatch.cpp.obj','/moho/sim/UnitUpdateFill.cpp.obj','/gpg/core/utils/Global.cpp.obj','/faf_tread_component_tests.dir/TreadComponentTests.cpp.obj','/memory/X64AllocatorTests.cpp.obj')) {
    $objectMatches = @($targetListing | ForEach-Object {
        if ($_ -match '^(.+): [^:]+$') {
            $target = $Matches[1].Replace('\','/')
            if ($target.EndsWith($suffix, [StringComparison]::Ordinal)) { $target }
        }
    })
    if ($objectMatches.Count -ne 1) { throw "Expected exactly one object target for $suffix; found $($objectMatches.Count)" }
    $objects += $objectMatches[0]
}
Write-Host "Fail-fast object targets: $($objects -join ', ')"
Checked ninja (@('-C', $build, '-j', '2') + $objects)
Checked cmake @('--build',$build,'--parallel','2','--target','faf_main','faf_tread_component_tests','faf_x64_allocator_tests','faf_net_tests','faf_profiler_tests','faf_sim_math_tests')
# Inspect ALL registrations: no regex masking extra or missing tests.
$listing = & ctest --test-dir $build --show-only=json-v1
if ($LASTEXITCODE -ne 0) { throw 'CTest listing failed' }
$registered = @((($listing -join "`n") | ConvertFrom-Json).tests | ForEach-Object { $_.name } | Sort-Object)
$expected = @('net_robustness','profiler_facade','sim_math','tread_motion_fixture','tread_phase_fixture','tread_snapshot_fixture','x64_allocator_pool_off','x64_allocator_pool_on')
if ($registered.Count -ne 8 -or @((Compare-Object $expected $registered)).Count -ne 0) {
    throw "Expected exactly eight native tests; got: $($registered -join ', ')"
}
$testData = (($listing -join "`n") | ConvertFrom-Json).tests
$executables = @{
    net_robustness = 'faf_net_tests.exe'; profiler_facade = 'faf_profiler_tests.exe'; sim_math = 'faf_sim_math_tests.exe'
    tread_motion_fixture = 'faf_tread_component_tests.exe'; tread_phase_fixture = 'faf_tread_component_tests.exe'; tread_snapshot_fixture = 'faf_tread_component_tests.exe'
    x64_allocator_pool_on = 'faf_x64_allocator_tests.exe'; x64_allocator_pool_off = 'faf_x64_allocator_tests.exe'
}
$modes = @{ tread_motion_fixture='motion'; tread_phase_fixture='phase'; tread_snapshot_fixture='snapshot'; x64_allocator_pool_on='pool-on'; x64_allocator_pool_off='pool-off' }
foreach ($test in $testData) {
    if (!(Test-Path -LiteralPath $test.command[0] -PathType Leaf) -or (Split-Path -Leaf $test.command[0]) -cne $executables[$test.name]) {
        throw "Wrong/missing registered test executable: $($test.name)"
    }
    if ($modes.ContainsKey($test.name) -and ($test.command.Count -ne 2 -or $test.command[1] -cne $modes[$test.name])) {
        throw "Unexpected test mode: $($test.name)"
    }
}
Checked ctest @('--test-dir',$build,'--verbose','--output-on-failure','--no-tests=error','--timeout','120')
@"
## Source-only Windows check
- Commit: $actual
- Runner: $env:ImageVersion; LLVM20.1.8; MSVC $vcVersion; UCRT10.0.22000.0
- PASS: 3 tread component cases, 2 real x64 allocator modes, stock net/profiler/math, full x64 client compile/link.
- NOT TESTED: live game/GPU visibility, live Sim scheduler, core/extended replay parity, x86. No unmerged recon fix applied.
- No binaries, SDK files, DLLs, game data or private archives uploaded.
"@ | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
