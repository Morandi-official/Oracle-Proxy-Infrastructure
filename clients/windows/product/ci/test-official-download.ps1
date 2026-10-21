$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'official-download.ps1')
$root=Join-Path $env:RUNNER_TEMP ('oracle-download-fixture-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root | Out-Null
$script:attempt=0;$script:alwaysBad=$false
function Invoke-WebRequest {
  param($Uri,$OutFile,$MaximumRedirection,$TimeoutSec)
  $script:attempt++
  if($script:attempt -eq 1){[IO.File]::WriteAllText($OutFile,'partial');throw 'Synthetic interrupted response'}
  [IO.File]::WriteAllText($OutFile, $(if($script:alwaysBad){'tampered'}else{'expected-static-fixture'}))
}
function Start-Sleep {param($Seconds)}
try{
  $expected=Join-Path $root 'expected';[IO.File]::WriteAllText($expected,'expected-static-fixture')
  $digest=(Get-FileHash $expected -Algorithm SHA256).Hash;$destination=Join-Path $root 'download'
  Get-OfficialFile -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $destination -SHA256 $digest
  if($script:attempt -ne 2 -or (Get-FileHash $destination -Algorithm SHA256).Hash -ne $digest -or (Test-Path ($destination+'.partial'))){throw 'Interrupted transfer was not safely retried'}
  $script:attempt=0;$script:alwaysBad=$true;$failed=$false
  try{Get-OfficialFile -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $destination -SHA256 $digest}catch{$failed=$true}
  if(!$failed -or $script:attempt -ne 3 -or (Get-FileHash $destination -Algorithm SHA256).Hash -ne $digest -or (Test-Path ($destination+'.partial'))){throw 'Digest failure overwrote a valid source or escaped its retry bound'}
  $failed=$false;try{Get-OfficialFile -Uri 'https://example.invalid/untrusted' -OutFile $destination}catch{$failed=$true}
  if(!$failed -or $script:attempt -ne 3){throw 'Untrusted source was fetched'}
  Write-Host 'BOUNDED_INTERRUPTED_DOWNLOAD_RETRY_AND_DIGEST_FAILURE_ATOMICITY=PASS'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
