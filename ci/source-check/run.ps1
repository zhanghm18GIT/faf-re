param([Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceSha,
      [Parameter(Mandatory)][ValidateSet('223','224')][string]$PullRequest,
      [Parameter(Mandatory)][ValidatePattern('^2026-11-02$')][string]$ApprovalDate)
# Two separate exact-source jobs on disposable standard public Windows runners.
# No game assets, accounts, secrets, installer execution or artifact uploads.
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
if (!$IsWindows -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ARCH -ne 'X64' -or
    $env:GITHUB_REPOSITORY -cne 'zhanghm18GIT/faf-re' -or $env:GITHUB_REF -cne 'refs/heads/ci/formatter-windows-x64' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
    throw 'Only the intended public fork and standard GitHub-hosted Windows x64 runner are permitted'
}
$driver = (Resolve-Path "$PSScriptRoot/../..").Path
$driverSha = (& git -C $driver rev-parse HEAD).Trim()
if ($LASTEXITCODE -or $driverSha -cne $SourceSha -or $env:GITHUB_SHA -cne $SourceSha) { throw 'CI-driver SHA mismatch' }
$contract = Get-Content -LiteralPath "$PSScriptRoot/contract.json" -Raw | ConvertFrom-Json
if ($contract.schema_version -ne 1 -or $contract.status -cne 'ready' -or
    $contract.approval_date -cne $ApprovalDate -or $contract.repository -cne $env:GITHUB_REPOSITORY -or
    $contract.base_sha -cne 'c65fc75f41f295a6a079098ac7c84172983a6dfd') { throw 'Frozen reviewed contract required' }
$pin = $contract.sources.PSObject.Properties[$PullRequest].Value
if ($null -eq $pin -or $pin.sha -cnotmatch '^[0-9a-f]{40}$' -or $pin.tree -cnotmatch '^[0-9a-f]{40}$') { throw 'Missing exact PR source pin' }
$source = (Resolve-Path "$env:GITHUB_WORKSPACE/target-source").Path
Set-Location $source
$actual = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -or $actual -cne $pin.sha) { throw 'PR source SHA mismatch' }
$tree = (& git rev-parse 'HEAD^{tree}').Trim()
if ($LASTEXITCODE -or $tree -cne $pin.tree) { throw 'PR source tree mismatch' }
$serverMode = if ($PullRequest -ceq '223') { 'ON' } else { 'OFF' }
if ($pin.server_mode -cne $serverMode) { throw 'Wrong requested server-mode configuration' }
Checked git @('diff','--exit-code','--ignore-submodules=all','HEAD','--','.')
Checked git @('diff','--cached','--exit-code','HEAD','--','.')
foreach ($row in $pin.files) {
    $blob = (& git rev-parse "HEAD:$($row[0])").Trim()
    if ($LASTEXITCODE -or $blob -cne $row[1]) { throw "Committed identity mismatch: $($row[0])" }
    SourceHashIs "$source/$($row[0])" $row[2]
}
foreach ($row in $pin.dependencies) {
    $identity = (& git rev-parse "HEAD:$($row[0])").Trim()
    if ($LASTEXITCODE -or $identity -cne $row[1]) { throw "Dependency identity mismatch: $($row[0])" }
}
SourceHashIs "$PSScriptRoot/old-CTextureScroller.cpp" $contract.old_scroller.sha256
$root = Join-Path $env:RUNNER_TEMP "pr$PullRequest-review-x64"
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
Checked cmake (@('-S',$source,'-B',$build,'-DFAF_ENABLE_TRACY=OFF','-DFAF_DXSDK_FORCE_DOWNLOAD=ON',"-DFAF_SERVER_MODE=$serverMode","-DFAF_OUTPUT_NAME=faf_review_pr${PullRequest}_x64") + $common)
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
# The pinned DXC package is extracted by upstream, never installed or uploaded.
HashIs "$source/dependencies/.downloads/dxc_2026_09_29.zip" 'ad31b1fc8443175d204f77a611fdb3ef2ec42759bdc2f1167368de24a4a7e7f1'
$env:PATH = "$source/dependencies/dxc/bin/x64;$env:PATH"
$specificTarget = if ($PullRequest -ceq '223') { 'faf_recon_scroll_packet_tests' } else { 'faf_tread_rotation_tests' }
$specificTest = if ($PullRequest -ceq '223') { 'recon_scroll_packet' } else { 'tread_rotation_guard' }
$targets = @('faf_main','faf_net_tests','faf_profiler_tests','faf_sim_math_tests',$specificTarget)
$cache = Get-Content -Raw -LiteralPath "$build/CMakeCache.txt"
if ($cache -notmatch ('(?m)^FAF_SERVER_MODE:BOOL=' + $serverMode + '\r?$')) { throw 'Wrong server mode in generated cache' }
# Fail fast on the actual affected translation units, including the server copy.
$targetListing = & ninja -C $build -t targets all
if ($LASTEXITCODE -ne 0) { throw 'Ninja target discovery failed' }
$suffixes = if ($PullRequest -ceq '223') {
    @('/moho/sim/ReconBlip.cpp.obj','/moho/sim/UnitUpdateFill.cpp.obj','/remote/ViewPackets.cpp.obj')
} else { @('/moho/entity/CTextureScroller.cpp.obj') }
$objects = @()
foreach ($suffix in $suffixes) {
    $found = @($targetListing | ForEach-Object {
        if ($_ -match '^(.+): [^:]+$') {
            $target = $Matches[1].Replace('\','/')
            if ($target.EndsWith($suffix, [StringComparison]::Ordinal)) { $target }
        }
    })
    if ($found.Count -ne 1) { throw "Expected one production object target for $suffix" }
    $objects += $found[0]
}
Checked ninja (@('-C',$build,'-j','2') + $objects)
Checked cmake (@('--build',$build,'--parallel','2','--target') + $targets)
function AssertClient() {
    $client = @(Get-ChildItem -LiteralPath $build -Filter "faf_review_pr${PullRequest}_x64.exe" -Recurse -File)
    if ($client.Count -ne 1) { throw 'Expected exactly one linked x64 client' }
    $bytes = [IO.File]::ReadAllBytes($client[0].FullName)
    if ($bytes.Length -lt 64 -or [BitConverter]::ToUInt16($bytes,0) -ne 0x5a4d) { throw 'Invalid DOS header' }
    $pe = [BitConverter]::ToInt32($bytes,0x3c)
    if ($pe -lt 0 -or $pe -gt ($bytes.Length-26) -or [BitConverter]::ToUInt32($bytes,$pe) -ne 0x4550 -or
        [BitConverter]::ToUInt16($bytes,$pe+4) -ne 0x8664 -or [BitConverter]::ToUInt16($bytes,$pe+24) -ne 0x20b) {
        throw 'Client must be AMD64 PE32+'
    }
    Write-Host "PASS linked AMD64 PE32+ client PR${PullRequest}: $((Get-FileHash -LiteralPath $client[0].FullName -Algorithm SHA256).Hash)"
}
function RunSuite([string]$Stage) {
    $pattern = "^(net_robustness|profiler_facade|sim_math|$specificTest)`$"
    $listing = & ctest --test-dir $build --show-only=json-v1 -R $pattern
    if ($LASTEXITCODE -ne 0) { throw 'CTest listing failed' }
    $tests = @( (($listing -join "`n") | ConvertFrom-Json).tests )
    $expected = @('net_robustness','profiler_facade','sim_math',$specificTest) | Sort-Object
    $registered = @($tests | ForEach-Object { $_.name } | Sort-Object)
    if ($registered.Count -ne 4 -or @((Compare-Object $expected $registered)).Count -ne 0) { throw 'Missing/extra selected tests' }
    $executables = @{net_robustness='faf_net_tests.exe';profiler_facade='faf_profiler_tests.exe';sim_math='faf_sim_math_tests.exe'}
    $executables[$specificTest] = "$specificTarget.exe"
    foreach ($test in $tests) {
        if (!(Test-Path -LiteralPath $test.command[0] -PathType Leaf) -or
            (Split-Path -Leaf $test.command[0]) -cne $executables[$test.name]) { throw 'Wrong/missing test executable' }
        if ($test.name -ceq $specificTest -and $test.command.Count -ne 1) { throw 'Specific test must have no obsolete selector' }
    }
    $junit = "$root/$Stage-junit.xml"
    Checked ctest @('--test-dir',$build,'--verbose','--output-on-failure','--no-tests=error','--timeout','120','--output-junit',$junit,'-R',$pattern) | ForEach-Object { Write-Host $_ }
    [xml]$results = Get-Content -LiteralPath $junit -Raw
    $cases = @($results.testsuite.testcase)
    $caseNames = @($cases | ForEach-Object { $_.name } | Sort-Object)
    if ($cases.Count -ne 4 -or @((Compare-Object $expected $caseNames)).Count -ne 0) { throw 'Missing JUnit cases' }
    foreach ($case in $cases) {
        if ($case.SelectNodes('skipped | failure | error').Count -ne 0 -or $case.status -cne 'run') { throw 'Skipped/failed native test' }
    }
    $specific = @($tests | Where-Object { $_.name -ceq $specificTest })
    return $specific[0].command[0]
}
AssertClient
# Host output only, returning one executable path, not native stdout.
$initialTestExe = RunSuite 'candidate'
if ($PullRequest -ceq '224') {
    $scroller = "$source/src/moho/entity/CTextureScroller.cpp"
    $candidateBytes = [IO.File]::ReadAllBytes($scroller)
    $candidateExeHash = (Get-FileHash -LiteralPath $initialTestExe -Algorithm SHA256).Hash
    try {
        Copy-Item -LiteralPath "$PSScriptRoot/old-CTextureScroller.cpp" -Destination $scroller -Force
        SourceHashIs $scroller $contract.old_scroller.sha256
        $changed = @(& git diff --name-only --ignore-submodules=all)
        if ($LASTEXITCODE -or $changed.Count -ne 1 -or $changed[0] -cne 'src/moho/entity/CTextureScroller.cpp') { throw 'Negative control changed more than old scroller' }
        # Same cleaned test, only the implementation differs. No A/B selector.
        Checked cmake @('--build',$build,'--parallel','2','--target',$specificTarget)
        if ((Get-FileHash -LiteralPath $initialTestExe -Algorithm SHA256).Hash -ceq $candidateExeHash) { throw 'Old-scroller test executable did not change' }
        $stdout = "$root/old-scroller.stdout.txt"
        $stderr = "$root/old-scroller.stderr.txt"
        $process = Start-Process -FilePath $initialTestExe -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if (!$process.WaitForExit(120000)) { $process.Kill(); throw 'Old-scroller control timed out' }
        $process.WaitForExit()
        $out = [IO.File]::ReadAllText($stdout)
        $err = [IO.File]::ReadAllText($stderr)
        Write-Host $out
        Write-Host $err
        if ($process.ExitCode -ne 1 -or $err.Trim() -cne 'FAIL yaw left tread' -or $out -match 'PASS') {
            throw "Wrong negative-control outcome, exit=$($process.ExitCode)"
        }
        Write-Host 'PASS negative control: old scroller fails exactly at yaw left tread, exit 1'
    } finally {
        [IO.File]::WriteAllBytes($scroller, $candidateBytes)
    }
    # Finish on the exact candidate and rerun after restoration, not on the control.
    Checked cmake (@('--build',$build,'--parallel','2','--target') + $targets)
    AssertClient
    $null = RunSuite 'candidate-restored'
}
Checked git @('diff','--exit-code','--ignore-submodules=all','HEAD','--','.')
Checked git @('diff','--cached','--exit-code','HEAD','--','.')
if ((& git rev-parse HEAD).Trim() -cne $pin.sha) { throw 'PR source HEAD moved' }
foreach ($row in $pin.files) { SourceHashIs "$source/$($row[0])" $row[2] }
$specificResult = if ($PullRequest -ceq '223') {
    'PASS: the production server ViewPackets.cpp object is compiled in this build.'
} else {
    'PASS: the same cleaned test fails on the pinned old scroller with exit 1 / FAIL yaw left tread, then passes after candidate restoration.'
}
@"
## PR$PullRequest exact-source native check
- Source: $actual; full Windows x64 Release client linked; server mode $serverMode.
- PASS: net_robustness, profiler_facade, sim_math, $specificTest.
- $specificResult
- Replay and rendered visibility/turning checks are not performed by this source-only job.
- No binaries, SDK files, game assets or raw logs uploaded as artifacts.
"@ | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
