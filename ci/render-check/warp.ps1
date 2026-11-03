# Driver-only real WARP checks; functions use the verified main driver's paths/helpers.
# No selectors, extra tests, altered descriptors or hooks are added to engine sources.
function Invoke-WarpRegression {
    if ($Case -cne 'd3d12' -or $Arch -cne 'x64') { throw 'WARP is limited to the existing D3D12 x64 job' }
    $warp = $contract.warp
    if ($null -eq $warp -or $warp.source_sha -cne $pin.sha -or $warp.base_sha -cne $contract.base_sha -or
        $warp.baseline.path -cne 'src/gpg/gal/backends/d3d12/DeviceD3D12.cpp' -or
        $warp.baseline.driver_file -cne 'warp/baseline-DeviceD3D12.cpp') { throw 'Reviewed WARP contract required' }
    foreach ($row in $warp.fixture_files) { SourceHashIs "$PSScriptRoot/$($row[0])" $row[1] }
    $baseline = "$PSScriptRoot/$($warp.baseline.driver_file)"
    SourceHashIs $baseline $warp.baseline.sha256
    $baselineCases = @('rollover-invalid','rollover-boundary','no-rollover','no-poison','same-page-carry')
    $candidateCases = @($baselineCases) + @('threshold-only','rollover-threshold')
    if (($warp.baseline_cases -join ',') -cne ($baselineCases -join ',') -or
        ($warp.candidate_cases -join ',') -cne ($candidateCases -join ',')) { throw 'WARP case budget changed' }

    # Provenance is transitive from the fixed whole archive; do not invent member pins.
    HashIs $dxArchive '705271dc83bfee54d9b94e028426e288d5f070784b7446d164f48ecfbb2a02cb'
    $cabMember = 'DXSDK/Redist/Jun2010_d3dx11_43_x64.cab'
    $members = @(& cmake -E tar tf $dxArchive)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate verified SDK archive' }
    foreach ($member in $members) {
        if ($member -match '(^|[/\\])\.\.([/\\]|$)|^[/\\]|^[A-Za-z]:') { throw 'Unsafe archive member path' }
    }
    $matching = @($members | Where-Object { $_.Replace('\','/').TrimStart([char[]]'./') -ieq $cabMember })
    if ($matching.Count -ne 1 -or $matching[0] -cne $cabMember) { throw 'SDK cabinet member must occur once at its exact path' }
    $cabRoot = "$root/warp-cab"
    New-Item -ItemType Directory -Path $cabRoot | Out-Null
    Checked cmake @("-DSDK_ARCHIVE=$(Posix $dxArchive)","-DDEST=$(Posix $cabRoot)",'-P',"$PSScriptRoot/warp-runtime.cmake")
    $extracted = @(Get-ChildItem -LiteralPath $cabRoot -File -Recurse -Force)
    $cab = "$cabRoot/$cabMember"
    if ($extracted.Count -ne 1 -or [IO.Path]::GetFullPath($extracted[0].FullName) -cne [IO.Path]::GetFullPath($cab)) { throw 'Unexpected SDK extraction result' }
    $cabHash = (Get-FileHash -LiteralPath $cab -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "Verified whole SDK -> exact cabinet $cabMember SHA256=$cabHash"

    # Read only the CAB CFFILE name table before expand.exe, so traversal or duplicate
    # target names are rejected before extraction, even though the enclosing bytes are pinned.
    $cabBytes = [IO.File]::ReadAllBytes($cab)
    if ($cabBytes.Length -lt 36 -or [Text.Encoding]::ASCII.GetString($cabBytes,0,4) -cne 'MSCF') { throw 'Unexpected cabinet header' }
    $cabEnd = [uint64][BitConverter]::ToUInt32($cabBytes,8)
    if ($cabEnd -lt 36 -or $cabEnd -gt $cabBytes.Length) { throw 'Invalid advertised cabinet size' }
    $offset = [uint64][BitConverter]::ToUInt32($cabBytes,16)
    if ($offset -lt 36) { throw 'Invalid cabinet file-table offset' }
    $count = [BitConverter]::ToUInt16($cabBytes,28)
    if ($count -lt 1 -or $count -gt 256) { throw 'Unexpected cabinet file count' }
    $names = @()
    $utf8 = [Text.UTF8Encoding]::new($false,$true)
    for ($i=0; $i -lt $count; ++$i) {
        if ($offset -gt ($cabEnd-17)) { throw 'Truncated cabinet file table' }
        $offset += 16
        $begin = $offset
        while ($offset -lt $cabEnd -and $cabBytes[$offset] -ne 0) { ++$offset }
        if ($offset -ge $cabEnd -or ($offset-$begin) -gt 512) { throw 'Invalid cabinet filename' }
        $name = $utf8.GetString($cabBytes,[int]$begin,[int]($offset-$begin))
        if ([string]::IsNullOrWhiteSpace($name) -or $name -match '(^|[/\\])\.\.([/\\]|$)|^[/\\]|^[A-Za-z]:') { throw 'Unsafe cabinet member path' }
        $names += $name
        ++$offset
    }
    $dllName = 'd3dx11_43.dll'
    $dllMatches = @($names | Where-Object { $_.Replace('\','/').TrimStart([char[]]'./') -ieq $dllName })
    if ($dllMatches.Count -ne 1 -or $dllMatches[0] -cne $dllName) { throw 'DLL member must occur once with exact name' }
    $warpRuntime = "$root/warp-runtime"
    New-Item -ItemType Directory -Path $warpRuntime | Out-Null
    Checked "$env:SystemRoot/System32/expand.exe" @($cab,"-F:$dllName",$warpRuntime)
    $dllFiles = @(Get-ChildItem -LiteralPath $warpRuntime -File -Recurse -Force)
    if ($dllFiles.Count -ne 1 -or $dllFiles[0].Name -cne $dllName -or $dllFiles[0].DirectoryName -cne [IO.Path]::GetFullPath($warpRuntime)) { throw 'Unexpected DLL extraction result' }
    AssertPE $dllFiles[0].FullName $false
    $dllHash = (Get-FileHash -LiteralPath $dllFiles[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "Verified exact cabinet -> exact DLL $dllName SHA256=$dllHash"
    $env:PATH = "$warpRuntime;$env:PATH"
    $env:FAF_DXC_DIR = "$source/dependencies/dxc/bin/x64"
    if ($env:FAF_GAL_SOLID_PS -or $env:FAF_GAL_CLEAR_TEST) { throw 'Unexpected render diagnostic override' }

    $warpTarget = 'faf_d3d12_warp_regression'
    $warpExe = "$build/warp-regression/$warpTarget.exe"
    Checked cmake @('--build',$build,'--parallel','2','--target',$warpTarget)
    AssertPE $warpExe $false
    if ($objects.Count -ne 1) { throw 'Exactly one changed D3D12 object required' }
    $buildRoot = [IO.Path]::GetFullPath($build).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $object = [IO.Path]::GetFullPath((Join-Path $build $objects[0]))
    $clientPath = [IO.Path]::GetFullPath($client[0].FullName)
    $warpExe = [IO.Path]::GetFullPath($warpExe)
    $outputs = @($object,$clientPath,$warpExe)
    foreach ($file in $outputs) {
        if (!$file.StartsWith($buildRoot,[StringComparison]::OrdinalIgnoreCase) -or !(Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Expected generated output beneath this build only' }
    }
    if (!$object.EndsWith('DeviceD3D12.cpp.obj',[StringComparison]::Ordinal) -or
        (Split-Path -Leaf $clientPath) -cne "$outputName.exe" -or
        (Split-Path -Leaf $warpExe) -cne "$warpTarget.exe") { throw 'Unexpected generated output identities' }
    $candidateObjectHash = (Get-FileHash -LiteralPath $object -Algorithm SHA256).Hash
    $candidateExeHash = (Get-FileHash -LiteralPath $warpExe -Algorithm SHA256).Hash
    function Invalidate-WarpOutputs([string]$Stage) {
        foreach ($file in $outputs) {
            if (Test-Path -LiteralPath $file) {
                $item = Get-Item -LiteralPath $file -Force
                if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe generated-output type' }
                Remove-Item -LiteralPath $file -Force
            }
            if (Test-Path -LiteralPath $file) { throw 'Generated output invalidation failed' }
            Write-Host "Invalidated $Stage generated output: $(Split-Path -Leaf $file)"
        }
    }
    function Run-WarpCase([string]$Stage,[string]$Name,[int]$ExpectedExit) {
        $env:FAF_SHADER_CACHE_DIR = "$root/shader-cache-$Stage-$Name"
        if (Test-Path -LiteralPath $env:FAF_SHADER_CACHE_DIR) { throw 'Shader cache must be fresh for each process' }
        New-Item -ItemType Directory -Path $env:FAF_SHADER_CACHE_DIR | Out-Null
        $stdout = "$root/warp-$Stage-$Name.stdout.txt"
        $stderr = "$root/warp-$Stage-$Name.stderr.txt"
        $process = Start-Process -FilePath $warpExe -ArgumentList @($Name) -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if (!$process.WaitForExit(120000)) {
            $process.Kill($true); $process.WaitForExit()
            throw "WARP $Stage $Name timed out"
        }
        $process.WaitForExit()
        $out = [IO.File]::ReadAllText($stdout)
        $err = [IO.File]::ReadAllText($stderr)
        Write-Host $out
        Write-Host $err
        if ($process.ExitCode -eq 77 -or $out -match '(?m)^SKIP WARP_REGRESSION ') {
            throw "SKIP/BLOCKED: WARP $Stage $Name; this is not a pass"
        }
        $marker = if ($ExpectedExit -eq 42) {
            "FAIL_EXPECTED_POISON WARP_REGRESSION case=$Name retired_upload_page_reused_red_constant"
        } else { "PASS WARP_REGRESSION case=$Name sampled_texture_and_constants_intact" }
        $resultLines = @($out -split '\r?\n' | Where-Object { $_ -match '^(PASS|FAIL_EXPECTED_POISON|SKIP|FAIL) WARP_REGRESSION ' })
        if ($process.ExitCode -ne $ExpectedExit -or $resultLines.Count -ne 1 -or $resultLines[0] -cne $marker -or ![string]::IsNullOrWhiteSpace($err)) {
            throw "Unexpected WARP $Stage $Name outcome, exit=$($process.ExitCode), expected=$ExpectedExit"
        }
        Write-Host "ACCEPTED WARP $Stage $Name exit=$ExpectedExit"
    }

    $productionFile = "$source/$($warp.baseline.path)"
    $candidateBytes = [IO.File]::ReadAllBytes($productionFile)
    $candidateSourceHash = $null
    $candidateMatches = 0
    foreach ($row in $pin.files) {
        if ($row[0] -ceq $warp.baseline.path) { $candidateSourceHash = $row[2]; ++$candidateMatches }
    }
    if ($candidateMatches -ne 1) { throw 'Missing exact candidate source hash' }
    SourceHashIs $productionFile $candidateSourceHash
    $baselineFailure = $null
    try {
        Copy-Item -LiteralPath $baseline -Destination $productionFile -Force
        SourceHashIs $productionFile $warp.baseline.sha256
        $changed = @(& git -C $source diff --name-only --ignore-submodules=all)
        if ($LASTEXITCODE -or $changed.Count -ne 1 -or $changed[0] -cne $warp.baseline.path) { throw 'Baseline changed more than the one permitted production file' }
        Invalidate-WarpOutputs 'baseline'
        Checked cmake @('--build',$build,'--parallel','2','--target',$warpTarget)
        $baselineObjectHash = (Get-FileHash -LiteralPath $object -Algorithm SHA256).Hash
        if ($baselineObjectHash -ceq $candidateObjectHash -or (Get-FileHash -LiteralPath $warpExe -Algorithm SHA256).Hash -ceq $candidateExeHash) { throw 'Baseline object/fixture did not change' }
        Write-Host "Baseline changed-object SHA256=$baselineObjectHash; initial candidate SHA256=$candidateObjectHash"
        AssertPE $warpExe $false
        foreach ($name in $baselineCases) {
            $expected = if ($name -cin @('rollover-invalid','rollover-boundary')) { 42 } else { 0 }
            Run-WarpCase 'baseline' $name $expected
        }
    } catch { $baselineFailure = $_ } finally {
        [IO.File]::WriteAllBytes($productionFile,$candidateBytes)
        SourceHashIs $productionFile $candidateSourceHash
        Invalidate-WarpOutputs 'restored-candidate'
    }

    # Never finish on a baseline client or cached object. Repeat normal client/core tests.
    Checked cmake (@('--build',$build,'--parallel','2','--target') + $targets + @($warpTarget))
    $restoredHash = (Get-FileHash -LiteralPath $object -Algorithm SHA256).Hash
    if ($restoredHash -cne $candidateObjectHash) { throw 'Restored candidate object differs from initial exact candidate object' }
    AssertPE $clientPath $true
    AssertPE $warpExe $false
    RunCoreSuite 'restored-candidate'
    $candidateFailure = $null
    try {
        foreach ($name in $candidateCases) { Run-WarpCase 'candidate' $name 0 }
    } catch { $candidateFailure = $_ }
    Checked git @('-C',$source,'diff','--exit-code','--ignore-submodules=all','HEAD','--','.')
    Checked git @('-C',$source,'diff','--cached','--exit-code','HEAD','--','.')
    SourceHashIs $productionFile $candidateSourceHash
    if ($baselineFailure -or $candidateFailure) {
        @"
## D3D12 WARP blocked or failed
- Exact candidate source restored; full client/core tests rebuilt and repeated before this result.
- Baseline: $baselineFailure
- Candidate: $candidateFailure
- A skip, timeout, unexpected pixel/result or missing precise baseline failure is not a WARP pass.
"@ | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
        throw 'WARP acceptance incomplete; see explicit baseline/candidate outcomes above'
    }
    $script:WarpResult = 'PASS: actual production D3D12/WARP offscreen draw/readback; 2 exact baseline poison failures, 3 baseline controls, 7 restored-candidate cases. Debug layer availability is reported separately by each process.'
    @"
## Real D3D12/WARP source regression
- $script:WarpResult
- Verified whole Microsoft SDK archive -> exact cabinet SHA256 $cabHash -> exact DLL SHA256 $dllHash.
- Final candidate object SHA256 $restoredHash; final full client/core tests rebuilt after restoration.
- Not a reproduction of the user game scene, hardware-GPU validation or broad rendered parity.
"@ | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
}
