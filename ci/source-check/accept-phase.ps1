# Source-only acceptance driver. Does NOT build, download, install or dispatch anything.
param(
  [Parameter(Mandatory)][ValidateSet('baseline','candidate')][string]$Variant,
  [Parameter(Mandatory)][string]$Exe,
  [Parameter(Mandatory)][string]$BuildDirectory,
  [Parameter(Mandatory)][string]$LogDirectory
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
function Assert-X86Laa([string]$Path) {
  $data = [System.IO.File]::ReadAllBytes($Path)
  if ($data.Length -lt 64 -or [BitConverter]::ToUInt16($data,0) -ne 0x5A4D) { throw 'Invalid DOS header' }
  $pe = [BitConverter]::ToInt32($data,0x3c)
  if ($pe -lt 0 -or $pe -gt ($data.Length-26)) { throw 'Invalid PE offset' }
  if ([BitConverter]::ToUInt32($data,$pe) -ne 0x4550 -or
      [BitConverter]::ToUInt16($data,$pe+4) -ne 0x14c -or
      [BitConverter]::ToUInt16($data,$pe+24) -ne 0x10b -or
      (([BitConverter]::ToUInt16($data,$pe+22) -band 0x20) -eq 0)) { throw 'Requires I386 PE32 LARGEADDRESSAWARE' }
  Write-Output "PE verified $Path SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash)"
}
function Assert-Registrations([string]$BuildDirectory, [string]$Exe) {
  $json = & ctest --test-dir $BuildDirectory --show-only=json-v1 -R '^allocator_bounds_'
  if ($LASTEXITCODE -ne 0) { throw 'CTest enumeration failed' }
  $listing = ($json -join "`n") | ConvertFrom-Json
  $expected = @('normal','low','high','map','separate')
  if (@($listing.tests).Count -ne 5) { throw 'Exactly five native test registrations required' }
  foreach ($case in $expected) {
    $entry = @($listing.tests | Where-Object { $_.name -eq "allocator_bounds_$case" })
    if ($entry.Count -ne 1 -or $entry[0].command.Count -ne 2 -or
        $entry[0].command[1] -ne $case -or
        (Resolve-Path -LiteralPath $entry[0].command[0]).Path -ne $Exe) {
      throw "CTest registration/executable mismatch for $case"
    }
  }
}
$Exe = (Resolve-Path -LiteralPath $Exe).Path
Assert-X86Laa $Exe
Assert-Registrations $BuildDirectory $Exe
& {
  $variant = $Variant
  $exe = $Exe
  foreach ($case in @('normal','low','high','map','separate')) {
    $stdout = Join-Path $LogDirectory "$variant-$case.stdout.txt"
    $stderr = Join-Path $LogDirectory "$variant-$case.stderr.txt"
    $p = Start-Process -FilePath $exe -ArgumentList $case -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $p.WaitForExit(120000)) { $p.Kill(); throw "TIMEOUT $variant $case" }
    $p.WaitForExit()
    $code = $p.ExitCode
    $err = Get-Content -Raw -LiteralPath $stderr
    $out = Get-Content -Raw -LiteralPath $stdout
    if ($code -eq 77) { throw "BLOCKED required native evidence: $variant $case : $err" }
    $expectedFailure = $variant -eq 'baseline' -and $case -in @('high','map')
    if ($expectedFailure) {
      $message = if ($case -eq 'high') { 'FAIL: adjacent same-reservation merge' } else { 'FAIL: full x86 map capacity' }
      if ($code -ne 1 -or $err -notmatch [regex]::Escape($message)) { throw "Wrong baseline discrimination: $case code=$code $err" }
    } elseif ($code -ne 0 -or $out -notmatch [regex]::Escape("PASS native production-backed allocator case=$case")) {
      throw "FAIL $variant $case code=$code $err"
    }
    if ($out) { Write-Output $out.Trim() }
    if ($expectedFailure) { Write-Output $err.Trim() }
    Write-Output "Accepted $variant $case code=$code"
  }
}
Write-Output 'PASS bounded native boundary suite; not public-path high-address or replay acceptance'
