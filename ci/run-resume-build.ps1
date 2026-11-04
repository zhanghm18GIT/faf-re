param([Parameter(Mandatory=$true)][ValidateSet('A','B')][string]$Stage)
# Ordinary repository install phase. No embedded payload or source ref writes.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:APPVEYOR_SKIP_FINALIZE_ON_EXIT = 'true'
$env:APPVEYOR_ARTIFACT_UPLOAD_TIMEOUT = '300'
$env:CMAKE_BUILD_PARALLEL_LEVEL = '2'
$env:GIT_TERMINAL_PROMPT = '0'
$env:GIT_LFS_SKIP_SMUDGE = '1'
if ($env:APPVEYOR -ne 'True') { throw 'Not an AppVeyor job' }
$driverDir = $PSScriptRoot
# Official image inventory lists Python312 as x86 and Python312-x64 as x64.
$python = 'C:\Python312-x64\python.exe'
$entry = Join-Path $driverDir 'resume_driver.py'
$contract = Join-Path $driverDir ('execution-resume-' + $Stage.ToLowerInvariant() + '.json')
if ((Get-FileHash -LiteralPath $entry -Algorithm SHA256).Hash.ToLowerInvariant() -ne '1a876430788cb7dd8dc798aa037538e45cbe5c02d25cf57ac7c71cd2df77b658') {
    throw 'Driver entry SHA-256 mismatch'
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Documented installed x64 Python missing; no fallback or installation' }
# Read the selected executable header before launching it. Do not infer bitness from its name/version.
$stream = [IO.File]::OpenRead($python)
$reader = New-Object IO.BinaryReader($stream)
try {
    if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) { throw 'Python executable lacks DOS/PE header' }
    $stream.Position = 0x3C
    $offset = $reader.ReadUInt32()
    if ([uint64]$offset + 26 -gt [uint64]$stream.Length) { throw 'Python PE header offset is invalid' }
    $stream.Position = $offset
    if ($reader.ReadUInt32() -ne 0x00004550) { throw 'Python PE signature is invalid' }
    $machine = $reader.ReadUInt16()
    $stream.Position = [uint64]$offset + 24
    $magic = $reader.ReadUInt16()
    Write-Host ('INTERPRETER_PE path={0} machine=0x{1:X4} optional_header=0x{2:X4}' -f $python, $machine, $magic)
    if ($machine -ne 0x8664 -or $magic -ne 0x020B) { throw 'Selected Python must be an AMD64 PE32+ executable' }
} finally {
    $reader.Dispose()
}
# Run the same driver's identity-only mode with a bounded child; never kill the host.
$start = New-Object Diagnostics.ProcessStartInfo
$start.FileName = $python
$start.Arguments = '-I -B "' + $entry + '" --check-interpreter'
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$probe = New-Object Diagnostics.Process
$probe.StartInfo = $start
$probeStarted = $false
try {
    $probeStarted = $probe.Start()
    if (-not $probeStarted) { throw 'Could not start interpreter validation child' }
    $stdout = $probe.StandardOutput.ReadToEndAsync()
    $stderr = $probe.StandardError.ReadToEndAsync()
    if (-not $probe.WaitForExit(15000)) {
        $probe.Kill()
        if (-not $probe.WaitForExit(5000)) { throw 'Interpreter validation timed out; child cleanup uncertain' }
        throw 'Interpreter validation exceeded 15 seconds; build not started'
    }
    Write-Host ($stdout.GetAwaiter().GetResult())
    $errorText = $stderr.GetAwaiter().GetResult()
    if ($errorText) { Write-Host $errorText }
    if ($probe.ExitCode -ne 0) { throw 'Interpreter validation failed; build not started' }
} finally {
    if ($probeStarted -and -not $probe.HasExited) {
        $probe.Kill()
        if (-not $probe.WaitForExit(5000)) { throw 'Interpreter child cleanup uncertain; no build continuation' }
    }
    $probe.Dispose()
}
& $python '-I' '-B' $entry '--contract' $contract '--execute'
if ($LASTEXITCODE -ne 0) { throw "Bounded RE driver failed with exit code $LASTEXITCODE. No retry or artifact fallback." }
# Producer alone enables the one pinned native cache after cleanup and readiness.
if ($Stage -eq 'A') {
    $c = Get-Content -Raw -LiteralPath $contract | ConvertFrom-Json
    $recipe = [string]$c.resume_recipe_sha256
    if ($recipe -notmatch '^[a-f0-9]{64}$') { throw 'Invalid resume recipe' }
    $cacheDir = 'C:\faf-re-resume\' + $recipe.Substring(0, 24)
    & $python '-I' '-B' (Join-Path $driverDir 'resume_ready.py') '--directory' $cacheDir '--recipe' $recipe
    if ($LASTEXITCODE -ne 0) { throw 'Cache readiness failed' }
    $env:APPVEYOR_CACHE_SKIP_SAVE = 'false'
    $env:APPVEYOR_SKIP_FINALIZE_ON_EXIT = 'false'
}
Exit-AppveyorBuild
