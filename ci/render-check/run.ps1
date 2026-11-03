param([Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$DriverSha,
      [Parameter(Mandatory)][ValidateSet('particle','shadow','d3d12')][string]$Case,
      [Parameter(Mandatory)][ValidateSet('x64','x86')][string]$Arch,
      [Parameter(Mandatory)][string]$AuthorizationReference)
# One independent, frozen source per job. Native builds/tests, not a GPU or replay test.
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
if (!$IsWindows -or $env:RUNNER_OS -cne 'Windows' -or $env:RUNNER_ARCH -cne 'X64' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'zhanghm18GIT/faf-re' -or
    $env:GITHUB_REF -cne 'refs/heads/ci/render-source-check-20261103-fix1' -or $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
    $env:GITHUB_RUN_ATTEMPT -cne '1' -or $env:ImageOS -cne 'win22') {
    throw 'Only the single scoped dispatch on standard GitHub-hosted windows-2022 is permitted; reruns are not authorized'
}
$event = Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json
if ($event.repository.private -ne $false) { throw 'Repository must be public' }
$driver = (Resolve-Path "$PSScriptRoot/../..").Path
$driverHead = (& git -C $driver rev-parse HEAD).Trim()
if ($LASTEXITCODE -or $driverHead -cne $DriverSha -or $env:GITHUB_SHA -cne $DriverSha) { throw 'CI-driver SHA mismatch' }
Checked git @('-C',$driver,'diff','--exit-code','HEAD','--','.')
Checked git @('-C',$driver,'diff','--cached','--exit-code','HEAD','--','.')
$contract = Get-Content -LiteralPath "$PSScriptRoot/contract.json" -Raw | ConvertFrom-Json
if ($contract.schema_version -ne 1 -or $contract.status -cne 'frozen-authorized' -or
    [string]::IsNullOrWhiteSpace($AuthorizationReference) -or $contract.authorization_reference -cne $AuthorizationReference -or
    $contract.repository -cne $env:GITHUB_REPOSITORY -or $contract.driver_branch -cne 'ci/render-source-check-20261103-fix1' -or
    $contract.base_sha -cne '1fff92773cd918b274b91ace8e6e6d5a790c8ae3') { throw 'Frozen reviewed and newly authorized contract required' }
$names = @($contract.sources.PSObject.Properties.Name)
if ($names.Count -ne 3 -or @($names | Where-Object { $_ -cnotin @('particle','shadow','d3d12') }).Count -ne 0 -or
    $contract.limits.source_count -ne $names.Count -or $contract.limits.job_count -ne (2 * $names.Count) -or
    $contract.limits.max_parallel -ne 2 -or $contract.limits.timeout_minutes -ne 60 -or $contract.limits.runner -cne 'windows-2022' -or
    $contract.limits.dispatches -ne 1 -or $contract.limits.reruns -ne 0 -or ($contract.limits.architectures -join ',') -cne 'x64,x86') {
    throw 'Reviewed job bounds changed'
}
$expectedJob = if ($Case -ceq 'd3d12' -and $Arch -ceq 'x64') { 'pilot' } else { 'remaining' }
if ($env:GITHUB_JOB -cne $expectedJob -or $contract.limits.pilot.case -cne 'd3d12' -or
    $contract.limits.pilot.arch -cne 'x64' -or $contract.limits.remaining_requires_pilot_success -ne $true) {
    throw 'Only the fixed pilot or its success-gated remaining jobs are permitted'
}
$remainingRows = @($contract.limits.remaining | ForEach-Object { "$($_.case)/$($_.arch)" })
if (($remainingRows -join ',') -cne 'particle/x64,particle/x86,shadow/x64,shadow/x86,d3d12/x86') {
    throw 'The fixed five-job follow-on matrix changed'
}
$pinProperty = $contract.sources.PSObject.Properties[$Case]
if ($null -eq $pinProperty) { throw 'Source not in frozen contract' }
$pin = $pinProperty.Value
if ($pin.sha -cnotmatch '^[0-9a-f]{40}$' -or $pin.tree -cnotmatch '^[0-9a-f]{40}$' -or $pin.server_mode -cne 'OFF') { throw 'Invalid source pin' }
$source = (Resolve-Path "$env:GITHUB_WORKSPACE/target-source").Path
Set-Location $source
$actual = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -or $actual -cne $pin.sha) { throw 'Source SHA mismatch' }
$tree = (& git rev-parse 'HEAD^{tree}').Trim()
if ($LASTEXITCODE -or $tree -cne $pin.tree) { throw 'Complete source tree mismatch' }
Checked git @('diff','--exit-code','--ignore-submodules=all','HEAD','--','.')
Checked git @('diff','--cached','--exit-code','HEAD','--','.')
$untracked = @(& git ls-files --others --exclude-standard)
if ($LASTEXITCODE -or $untracked.Count -ne 0) { throw 'Source checkout must start clean without untracked files' }
foreach ($row in $pin.files) {
    $blob = (& git rev-parse "HEAD:$($row[0])").Trim()
    if ($LASTEXITCODE -or $blob -cne $row[1]) { throw "Committed identity mismatch: $($row[0])" }
    SourceHashIs "$source/$($row[0])" $row[2]
}
foreach ($row in @($pin.dependencies) + @($pin.protected_trees)) {
    $identity = (& git rev-parse "HEAD:$($row[0])").Trim()
    if ($LASTEXITCODE -or $identity -cne $row[1]) { throw "Dependency/build tree identity mismatch: $($row[0])" }
}
$root = Join-Path $env:RUNNER_TEMP "render-check-$Case-$Arch"
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
foreach ($leaf in @('include/vcruntime.h','include/vector',"lib/$Arch/libcmt.lib","lib/$Arch/libvcruntime.lib")) {
    if (!(Test-Path "$vc/$leaf")) { throw "MSVC component missing $leaf" }
}
$sdk = "${env:ProgramFiles(x86)}/Windows Kits/10"
$versions = @(Get-ChildItem "$sdk/Include" -Directory | Where-Object {
    $_.Name -match '^10\.0\.\d+\.\d+$' -and (Test-Path "$($_.FullName)/um/windows.h")
} | Sort-Object { [version]$_.Name } -Descending)
if (!$versions.Count) { throw 'Preinstalled Windows SDK missing' }
$headers = $versions[0].Name
foreach ($leaf in @("Include/$headers/ucrt/stdio.h", "Lib/$headers/um/$Arch/kernel32.lib")) {
    if (!(Test-Path "$sdk/$leaf")) { throw "SDK component missing $leaf" }
}
# Only official data package; never invoke NuGet/MSBuild/installers.
$package = "$root/ucrt.nupkg"
$ucrtPins = @{
    x64 = @('6d83c2c9e2ac3d43e74dd200fd90744cb8b7f9ee780dbcb735a21f4a2542b556','56378d8598e3134d5c7e844079e07c1a56ad7c138f74d5f398f7452e5abc6550')
    x86 = @('54b2d290b4e315b0111fa4fada52b436672733687455060dc5b6f75e74ab4c5b','b37c09557bb7c2dc29da57f85c3dce85243d03b9e0312082a2468dcafd677956')
}
Fetch "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp.$Arch/10.0.22000.196/microsoft.windows.sdk.cpp.$Arch.10.0.22000.196.nupkg" $package $ucrtPins[$Arch][0]
$overlay = "$root/sdk"
New-Item -ItemType Directory -Path "$overlay/Lib/10.0.22000.0/ucrt/$Arch" -Force | Out-Null
New-Item -ItemType Junction -Path "$overlay/Include" -Target "$sdk/Include" | Out-Null
if ($headers -eq '10.0.22000.0') { throw 'Overlay layout requires separate current SDK header/UM version; review runner' }
New-Item -ItemType Junction -Path "$overlay/Lib/$headers" -Target "$sdk/Lib/$headers" | Out-Null
$ucrt = "$overlay/Lib/10.0.22000.0/ucrt/$Arch/libucrt.lib"
$zip = [IO.Compression.ZipFile]::OpenRead($package)
try {
    $entries = @($zip.Entries | Where-Object { $_.FullName -ceq "c/ucrt/$Arch/libucrt.lib" })
    if ($entries.Count -ne 1) { throw 'Unexpected UCRT archive layout' }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $ucrt, $false)
} finally { $zip.Dispose() }
HashIs $ucrt $ucrtPins[$Arch][1]
# LLVM20 selects x64 MASM mode by basename. TEMP alias is byte-identical.
$masm = "$llvm/bin/llvm-ml.exe"
if ($Arch -ceq 'x64') {
    $masm = "$llvm/bin/llvm-ml64.exe"
    if (!(Test-Path $masm)) {
        $masm = "$root/llvm-ml64.exe"
        Copy-Item "$llvm/bin/llvm-ml.exe" $masm
        HashIs $masm (Get-FileHash "$llvm/bin/llvm-ml.exe" -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$env:FAF_CI_ARCH = $Arch
$env:FAF_CI_SOURCE = Posix $source
$env:FAF_CI_MASM = Posix $masm
$adapter = Posix "$PSScriptRoot/toolchain.cmake"
$common = @('-G','Ninja','-DCMAKE_BUILD_TYPE=Release',"-DCMAKE_TOOLCHAIN_FILE=$adapter",
    "-DFAF_LLVM_ROOT=$llvm", "-DFAF_MSVC_TOOLS_DIR=$vc", "-DFAF_WINSDK_DIR=$(Posix $overlay)",
    "-DFAF_WINSDK_VERSION=$headers", '-DFAF_UCRT_LIB_VERSION=10.0.22000.0')
Write-Host "Source $actual; architecture $Arch; runner $env:ImageVersion; MSVC $vcVersion; SDK headers $headers; static UCRT 10.0.22000.0"
# Full normal client, no production seam, instrumentation or game assets.
# Only D3D12/x64 later performs a pinned temporary one-file baseline test and restores it.
$build = "$root/build"
$outputName = "faf_render_${Case}_$Arch"
$configureExtra = @()
if ($Case -ceq 'd3d12' -and $Arch -ceq 'x64') {
    if ($null -eq $contract.PSObject.Properties['warp']) { throw 'Reviewed WARP fixture contract missing' }
    foreach ($row in $contract.warp.fixture_files) { SourceHashIs "$PSScriptRoot/$($row[0])" $row[1] }
    $configureExtra += "-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=$(Posix "$PSScriptRoot/warp/attach.cmake")"
}
Checked cmake (@('-S',$source,'-B',$build,'-DFAF_ENABLE_TRACY=OFF','-DFAF_DXSDK_FORCE_DOWNLOAD=ON',
    '-DFAF_SERVER_MODE=OFF','-DFAF_CALL_HASH_BUILD=OFF','-DFAF_RETAIL_LAYOUT=OFF',
    "-DFAF_OUTPUT_NAME=$outputName") + $common + $configureExtra)
$dxArchive = "$source/dependencies/.downloads/DXSDK_Jun10.exe"
HashIs $dxArchive '705271dc83bfee54d9b94e028426e288d5f070784b7446d164f48ecfbb2a02cb'
$runtime = "$root/runtime"
New-Item -ItemType Directory -Path $runtime | Out-Null
Checked cmake @("-DSDK_ARCHIVE=$(Posix $dxArchive)", "-DDEST=$(Posix $runtime)", "-DARCH=$Arch", '-P', "$PSScriptRoot/runtime.cmake")
$dlls = if ($Arch -ceq 'x64') { @(
  @('Jun2010_d3dx9_43_x64.cab','9b98a1269af7f3a0007bfdc73206a47a6ee158d34ba8a87009396c18186bb06a','d3dx9_43.dll','84b900dbd7fa978d6e0caee26fc54f2f61d92c9c75d10b35f00e3e82cd1d67b4'),
  @('Feb2010_X3DAudio_x64.cab','832b6d48e169b4725ae482ea4d1c3360a09631a89b2fac3aba81a50805a50adc','X3DAudio1_7.dll','9460709339701ad471a5cabe6365355f4d586dc4fcb86507c1331839dc555446'),
  @('Jun2010_D3DCompiler_43_x64.cab','213ad66ab9e469db1e6a49a646d082bfc3700db94172984e7e36801612af50c6','D3DCompiler_43.dll','44c3a7e330b54a35a9efa015831392593aa02e7da1460be429d17c3644850e8a')
) } else { @(
  @('Jun2010_D3DCompiler_43_x86.cab','417eebd5b19f45c67c94c2d2ba8b774c0fc6d958b896d7b1ac12cf5a0ea06e0e','D3DCompiler_43.dll','2f23182ec6f4889397ac4bf03d62536136c5bdba825c7d2c4ef08c827f3a8a1c'),
  @('Jun2010_d3dx9_43_x86.cab','fcc6cf0966b4853d6fa3d32ab299cde5a9824feaecb0d4f34ea452fb9fd1c867','d3dx9_43.dll','0b28546be22c71834501f7d7185ede5d79742457331c7ee09efc14490dd64f5f'),
  @('Feb2010_X3DAudio_x86.cab','acba5c4d4ac90e1df1c8404be5ff780e24238153cb410af909cd4364d213f2a9','X3DAudio1_7.dll','288c701bdedf1d45c63dd0b7d424a752f8819f90feb5088c582f76bc98970ba3')
) }
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
$env:PATH = "$source/dependencies/dxc/bin/$Arch;$env:PATH"
if ($Arch -ceq 'x86') {
    HashIs "$source/dependencies/dxc/bin/x86/dxcompiler.dll" '691b2578c2ef13aaaa41b543d1b6019b1f0ebfcef3b9568d78ce2dbaa359faf7'
    HashIs "$source/dependencies/dxc/bin/x86/dxil.dll" 'ebf7f9dabeb6d80a167a5b7cab9275573f061afd7b86a90bf5c579d58f9d08dd'
}
foreach ($dll in @('dxcompiler.dll','dxil.dll')) {
    if (!(Test-Path "$source/dependencies/dxc/bin/$Arch/$dll")) { throw "Missing pinned DXC runtime $dll for $Arch" }
}
$cache = Get-Content -Raw -LiteralPath "$build/CMakeCache.txt"
foreach ($setting in @('FAF_SERVER_MODE','FAF_ENABLE_TRACY','FAF_CALL_HASH_BUILD','FAF_RETAIL_LAYOUT')) {
    if ($cache -notmatch ('(?m)^' + $setting + ':BOOL=OFF\r?$')) { throw "Unexpected build setting $setting" }
}
if ($cache -notmatch '(?m)^CMAKE_BUILD_TYPE:STRING=Release\r?$') { throw 'Release build required' }
# Fail fast on the changed production translation unit before the full build.
$targetListing = & ninja -C $build -t targets all
if ($LASTEXITCODE -ne 0) { throw 'Ninja target discovery failed' }
$suffixes = @{
    particle='/moho/particles/BeamRenderHelpers.cpp.obj'
    shadow='/moho/render/Shadow.cpp.obj'
    d3d12='/gpg/gal/backends/d3d12/DeviceD3D12.cpp.obj'
}
$suffix = $suffixes[$Case]
$objects = @($targetListing | ForEach-Object {
    if ($_ -match '^(.+): [^:]+$') {
        $target = $Matches[1].Replace('\','/')
        if ($target.EndsWith($suffix, [StringComparison]::Ordinal)) { $target }
    }
})
if ($objects.Count -ne 1) { throw "Expected exactly one changed production object for $Case" }
Checked ninja (@('-C',$build,'-j','2') + $objects)
$targets = @('faf_main','faf_net_tests','faf_profiler_tests','faf_sim_math_tests')
Checked cmake (@('--build',$build,'--parallel','2','--target') + $targets)
function AssertPE([string]$Executable, [bool]$RequireLaa) {
    $bytes = [IO.File]::ReadAllBytes($Executable)
    if ($bytes.Length -lt 64 -or [BitConverter]::ToUInt16($bytes,0) -ne 0x5a4d) { throw 'Invalid DOS header' }
    $pe = [BitConverter]::ToInt32($bytes,0x3c)
    if ($pe -lt 0 -or $pe -gt ($bytes.Length-26) -or [BitConverter]::ToUInt32($bytes,$pe) -ne 0x4550) { throw 'Invalid PE header' }
    $machine = if ($Arch -ceq 'x64') { 0x8664 } else { 0x14c }
    $magic = if ($Arch -ceq 'x64') { 0x20b } else { 0x10b }
    if ([BitConverter]::ToUInt16($bytes,$pe+4) -ne $machine -or [BitConverter]::ToUInt16($bytes,$pe+24) -ne $magic) { throw 'Wrong executable architecture' }
    if ($RequireLaa -and $Arch -ceq 'x86' -and ([BitConverter]::ToUInt16($bytes,$pe+22) -band 0x20) -eq 0) { throw 'x86 client must be LARGEADDRESSAWARE' }
    Write-Host "PASS $Arch PE: $(Split-Path -Leaf $Executable); SHA256=$((Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash)"
}
$client = @(Get-ChildItem -LiteralPath $build -Filter "$outputName.exe" -Recurse -File)
if ($client.Count -ne 1) { throw 'Expected exactly one linked full client' }
AssertPE $client[0].FullName $true
function RunCoreSuite([string]$Stage) {
    $pattern = '^(net_robustness|profiler_facade|sim_math)$'
    $listing = & ctest --test-dir $build --show-only=json-v1 -R $pattern
    if ($LASTEXITCODE -ne 0) { throw 'CTest listing failed' }
    $tests = @( (($listing -join "`n") | ConvertFrom-Json).tests )
    $expected = @('net_robustness','profiler_facade','sim_math')
    $registered = @($tests | ForEach-Object { $_.name } | Sort-Object)
    if ($registered.Count -ne 3 -or @((Compare-Object $expected $registered)).Count -ne 0) { throw 'Missing/extra selected tests' }
    $executables = @{net_robustness='faf_net_tests.exe';profiler_facade='faf_profiler_tests.exe';sim_math='faf_sim_math_tests.exe'}
    foreach ($test in $tests) {
        if (!(Test-Path -LiteralPath $test.command[0] -PathType Leaf) -or
            (Split-Path -Leaf $test.command[0]) -cne $executables[$test.name]) { throw 'Wrong/missing test executable' }
        AssertPE $test.command[0] $false
        if ($test.name -ceq 'sim_math') {
            $wantedArgs = @((Posix "$source/tests/sim_math/golden.txt"))
            if ($Arch -ceq 'x86') { $wantedArgs += @('--known',(Posix "$source/tests/sim_math/known_windows-x86.txt")) }
            $actualArgs = @($test.command | Select-Object -Skip 1 | ForEach-Object { Posix $_ })
            if (($wantedArgs -join '|') -cne ($actualArgs -join '|')) { throw 'Wrong sim-math baseline/architecture-specific known expectations' }
        } elseif ($test.command.Count -ne 1) { throw 'Unexpected core-test argument' }
    }
    $junit = "$root/core-$Stage-junit.xml"
    Checked ctest @('--test-dir',$build,'--verbose','--output-on-failure','--no-tests=error','--timeout','120','--output-junit',$junit,'-R',$pattern)
    [xml]$results = Get-Content -LiteralPath $junit -Raw
    $cases = @($results.testsuite.testcase)
    $caseNames = @($cases | ForEach-Object { $_.name } | Sort-Object)
    if ($cases.Count -ne 3 -or @((Compare-Object $expected $caseNames)).Count -ne 0) { throw 'Missing JUnit cases' }
    foreach ($result in $cases) {
        if ($result.SelectNodes('skipped | failure | error').Count -ne 0 -or $result.status -cne 'run') { throw 'Skipped/failed native test' }
    }
}
RunCoreSuite 'candidate'
# Optional narrow probes live only in this driver, never alter production or the normal client.
$probeResult = 'Source-body mock probe not applicable to this D3D12 job.'
$script:WarpResult = 'Not run: WARP is limited to the existing D3D12 x64 job.'
if ($Case -cin @('particle','shadow')) {
    $probeSource = "$root/probe-source"
    New-Item -ItemType Directory -Path $probeSource | Out-Null
    Checked python @("$PSScriptRoot/generate_probe.py",'--source',$source,'--case',$Case,'--output',"$probeSource/probe.cpp")
    Copy-Item -LiteralPath "$PSScriptRoot/probe.cmake" -Destination "$probeSource/CMakeLists.txt"
    $probeBuild = "$root/probe-build"
    Checked cmake (@('-S',$probeSource,'-B',$probeBuild) + $common)
    Checked cmake @('--build',$probeBuild,'--parallel','2','--target','render_source_probe')
    $probeExe = "$probeBuild/render_source_probe.exe"
    AssertPE $probeExe $false
    Checked ctest @('--test-dir',$probeBuild,'--verbose','--output-on-failure','--no-tests=error','--timeout','30','-R','^render_source_probe$')
    $probeResult = 'PASS: exact-source function body against a recording mock; no graphics device or rendered validation.'
}
if ($Case -ceq 'd3d12' -and $Arch -ceq 'x64') {
    . "$PSScriptRoot/warp.ps1"
    Invoke-WarpRegression
}
# Upstream patches only dependency contents. All tracked parent source must remain exact.
Checked git @('diff','--exit-code','--ignore-submodules=all','HEAD','--','.')
Checked git @('diff','--cached','--exit-code','HEAD','--','.')
if ((& git rev-parse HEAD).Trim() -cne $pin.sha -or (& git rev-parse 'HEAD^{tree}').Trim() -cne $pin.tree) { throw 'Source HEAD/tree moved' }
foreach ($row in $pin.files) { SourceHashIs "$source/$($row[0])" $row[2] }
@"
## $Case exact-source Windows $Arch check
- Source: $actual; tree: $tree.
- PASS: complete Release client linked, server mode OFF, PE architecture verified.
- PASS: net_robustness, profiler_facade, sim_math; upstream x86 known differences retained.
- $probeResult
- $script:WarpResult
- No replay, game-data, user-scene reproduction, hardware-GPU or broad smoke/shadow visual-parity claims.
- No binaries, SDK data, commercial shaders or raw logs uploaded as artifacts; ordinary Actions logs remain public.
"@ | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
