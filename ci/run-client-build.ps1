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
$python = 'C:\Python312\python.exe'
$entry = Join-Path $driverDir 'driver.py'
$contract = Join-Path $driverDir 'execution-contract.json'
if ((Get-FileHash -LiteralPath $entry -Algorithm SHA256).Hash.ToLowerInvariant() -ne '669b820ef5faa3b104ee58756c61730108b6946c1878dcbce3505527b4157d4f') {
    throw 'Driver entry SHA-256 mismatch'
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Installed Python executable missing' }
& $python $entry '--contract' $contract '--execute'
if ($LASTEXITCODE -ne 0) { throw "Bounded RE driver failed with exit code $LASTEXITCODE. No retry or artifact fallback." }
# Driver already performed all build/test/package gates and the single explicit upload.
# Skip later default phases; finalize skip is required even though project handlers are empty.
Exit-AppveyorBuild
throw 'Exit-AppveyorBuild returned unexpectedly; do not continue pipeline'
