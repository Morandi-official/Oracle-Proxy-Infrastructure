# Verify the exact upstream embedded x64 DLL against the official signed release.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'official-download.ps1')
$module=Join-Path ((go env GOMODCACHE).Trim()) 'github.com/sagernet/sing-tun@v0.9.7-0.20261009020158-bca4bf029237/internal/wintun/amd64/wintun.dll'
if(!(Test-Path $module)){throw 'Pinned upstream Wintun payload missing'}
$archive=Join-Path $env:RUNNER_TEMP 'oracle-wintun-0.14.1.zip'
Get-OfficialFile -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archive
$directory=Join-Path $env:RUNNER_TEMP 'oracle-official-wintun'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[IO.Compression.ZipFile]::OpenRead($archive)
try{
  $entry=$zip.GetEntry('wintun/bin/amd64/wintun.dll')
  if(!$entry -or $entry.Length -gt 10000000){throw 'Unexpected official driver archive'}
  New-Item -ItemType Directory -Force $directory | Out-Null
  $official=Join-Path $directory 'wintun.dll'
  [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$official,$true)
  foreach($name in @('wintun/COPYING','wintun/LICENSE','wintun/README.md','wintun/README.txt')){
    $license=$zip.GetEntry($name)
    if($license -and $license.Length -lt 200000){[IO.Compression.ZipFileExtensions]::ExtractToFile($license,(Join-Path $directory ([IO.Path]::GetFileName($name))),$true)}
  }
}finally{$zip.Dispose()}
if((Get-FileHash $module -Algorithm SHA256).Hash -ne (Get-FileHash $official -Algorithm SHA256).Hash){throw 'Embedded Wintun differs from official signed release'}
$signature=Get-AuthenticodeSignature $official
if($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -ne 'WireGuard LLC'){throw 'Official Wintun signature or publisher mismatch'}
$out=Join-Path $PWD 'dist/review';New-Item -ItemType Directory -Force $out | Out-Null
@{version='0.14.1';architecture='amd64';sha256=(Get-FileHash $official -Algorithm SHA256).Hash.ToLowerInvariant();signature=$signature.Status.ToString();publisher='WireGuard LLC';source='https://www.wintun.net/builds/wintun-0.14.1.zip'} | ConvertTo-Json | Set-Content "$out/wintun-provenance.json"
Get-ChildItem $directory -File | Where-Object Extension -ne '.dll' | Copy-Item -Destination $out
Write-Host 'WINTUN_EMBEDDED_BYTES_MATCH_OFFICIAL_VALID_SIGNATURE=PASS'
