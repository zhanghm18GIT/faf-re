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
# Exact frozen recon candidate and unchanged stock renderer (no #220/#222).
$identities = @(
    @('src/moho/sim/ReconBlip.cpp','bb9fef65139e95a217a60d446b7cc7ba50a8d6ae','071be4748be37e487edf1eb94880d5fc646db07e8d606df47242871a697fd78e'),
    @('src/moho/sim/UnitUpdateFill.cpp','34bd192f27bdd2200f8ee7f79a784c27a6968a5e','74530572a89d323df2cb2e0be7007cabbd09e64e140cba8944ac77a347e80e26'),
    @('src/moho/sim/UnitUpdateFill.h','a014bf4777802a5d56103530fce8067c7c47ef59','aca088ca5a7299eb8b590addea04c9ebf4d41b43f889be5099f7fcc1b600c66d'),
    @('tests/CMakeLists.txt','54be39ea25c8f7c39d48932811c85f852df417f4','c4ce763e39c29b862ea6395e0ce6fb9497978cc1cf482bbbb509de97e39ff7c5'),
    @('tests/sim/ReconScrollPacketTests.cpp','ab129327ad3fcabade4c79579741e62a9404e872','0f371b65f93374f5b1d86fe4f9da7ce3622004f70c0dd64e2e6b036c06e17c21'),
    @('src/gpg/gal/MeshFormatter.cpp','cea373d122b0286258c0a6e05cfa00cd89705339','b913d47d65ef06b23a504faafc1c23b4ad7db86096c199d2d6155b9916711457'),
    @('src/gpg/gal/MeshFormatter.h','c32fc2410a224d82356b6f4e07a9646a0074b5a9','03beae63208c89d28f28bbea873bb612145ffa8e8f249dd8ef8f629b34ca9c01'),
    @('src/gpg/gal/backends/d3d10/D3D10Interfaces.cpp','b5382d005f8b5d684822c26d455d44ef95bad9d2','79ff660104b3afaedecb83554e63bb9045acd3c4111ea7418245d4df0da498a3')
)
foreach ($row in $identities) {
    $blob = (& git rev-parse "HEAD:$($row[0])").Trim()
    if ($LASTEXITCODE -or $blob -cne $row[1]) { throw "Committed source identity mismatch: $($row[0])" }
    SourceHashIs "$source/$($row[0])" $row[2]
}
$root = Join-Path $env:RUNNER_TEMP 'recon-source-check'
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
Checked cmake (@('-S',$source,'-B',$build,'-DFAF_ENABLE_TRACY=OFF','-DFAF_DXSDK_FORCE_DOWNLOAD=ON') + $common)
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
# Discover actual generated Ninja object names; do not guess CMake layout.
$targetListing = & ninja -C $build -t targets all
if ($LASTEXITCODE -ne 0) { throw 'Ninja target discovery failed' }
$objects = @()
# UnitUpdateFill.h is covered by the two production translation units.
foreach ($suffix in @('/moho/sim/ReconBlip.cpp.obj', '/moho/sim/UnitUpdateFill.cpp.obj', '/sim/ReconScrollPacketTests.cpp.obj')) {
    $objectMatches = @($targetListing | ForEach-Object {
        if ($_ -match '^(.+): [^:]+$') {
            $target = $Matches[1].Replace('\','/')
            if ($target.EndsWith($suffix, [StringComparison]::Ordinal)) { $target }
        }
    })
    if ($objectMatches.Count -ne 1) { throw "Expected exactly one generated object target for $suffix; found $($objectMatches.Count)" }
    $objects += $objectMatches[0]
}
Write-Host "Fail-fast actual object targets: $($objects -join ', ')"
Checked ninja (@('-C', $build, '-j', '2') + $objects)
Checked cmake @('--build',$build,'--parallel','2','--target','faf_main','faf_recon_scroll_packet_tests','faf_net_tests','faf_profiler_tests','faf_sim_math_tests')
# Require all four registered tests, not merely a nonempty regex match.
$testPattern = '^(recon_scroll_packet|net_robustness|profiler_facade|sim_math)$'
$listing = & ctest --test-dir $build --show-only=json-v1 -R $testPattern
if ($LASTEXITCODE -ne 0) { throw 'CTest listing failed' }
$registered = @((($listing -join "`n") | ConvertFrom-Json).tests | ForEach-Object { $_.name } | Sort-Object)
$expected = @('net_robustness','profiler_facade','recon_scroll_packet','sim_math')
if ($registered.Count -ne 4 -or @((Compare-Object $expected $registered)).Count -ne 0) {
    throw 'Expected four native tests were not registered'
}
Checked ctest @('--test-dir',$build,'--verbose','--output-on-failure','--no-tests=error','--timeout','120','-R','^(recon_scroll_packet|net_robustness|profiler_facade|sim_math)$')
@"
## Source-only Windows check
- Commit: $actual
- Runner: $env:ImageVersion; LLVM20.1.8; MSVC $vcVersion; UCRT10.0.22000.0
- PASS: native recon packet, full x64 client compile/link, net robustness, profiler facade, sim math.
- NOT TESTED: live recon/tread visibility, game launch, core/extended replay parity, x86.
- No binaries, SDK files, DLLs, game data or private archives uploaded.
"@ | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
