# Static inspection only: installers and extracted programs are never run.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'official-download.ps1')
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted Windows required'}
$versions=@(
  @{Version='4.39.2.1561';Url='https://a56.gdl.netease.com/UURemote_Setup_4.39.2.1561_0904121034_gwqd.exe';SHA='CF06187BE7B1382EAB9D53AFA129E4DC0DC07B0C7526D1E7A849475E0CA046F5'},
  @{Version='4.41.1.2335';Url='https://a56.gdl.netease.com/UURemote_Setup_4.41.1.2335_0917134939_gwqd.exe';SHA='4DE4AF35656D8395E01BE64D094C5F750B2FD7C8B47DB4289BCE7B05CF85412E'}
)
$out=Join-Path $PWD 'dist/gameviewer-review';New-Item -ItemType Directory -Force $out | Out-Null
$rows=@()
foreach($item in $versions){
  $installer=Join-Path $env:RUNNER_TEMP "GameViewer-$($item.Version).exe"
  Get-OfficialFile -Uri $item.Url -OutFile $installer -SHA256 $item.SHA
  if((Get-FileHash $installer -Algorithm SHA256).Hash -ne $item.SHA){throw 'GameViewer installer checksum mismatch'}
  $sig=Get-AuthenticodeSignature $installer
  if($sig.Status -ne 'Valid'){throw 'GameViewer installer signature is not trusted'}
  Write-Host "GAMEVIEWER_INSTALLER=$($item.Version);SIGNER=$($sig.SignerCertificate.Subject);STATUS=$($sig.Status)"
  $extract=Join-Path $env:RUNNER_TEMP "GameViewer-static-$($item.Version)"
  python ./clients/windows/product/ci/extract_nsis_lzma2.py $installer $extract
  if($LASTEXITCODE -ne 0){throw 'Bounded static NSIS extraction failed'}
  foreach($file in Get-ChildItem $extract -Filter '*.exe' -Recurse -File){
    $signature=Get-AuthenticodeSignature $file.FullName
    $rows+=@{version=$item.Version;file=$file.VersionInfo.OriginalFilename;product=$file.VersionInfo.ProductName;signature=$signature.Status.ToString();publisher=if($signature.SignerCertificate){$signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)}else{''};sha256=(Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
  }
}
ConvertTo-Json -InputObject @($rows) -Depth 4 | Set-Content "$out/gameviewer-signatures.json"
$rows | Where-Object { $_.file -match '(GameViewer|UU)' } | ForEach-Object {Write-Host "GAMEVIEWER_BINARY=$($_.version);FILE=$($_.file);SIGNER=$($_.publisher);STATUS=$($_.signature)"}
if($rows.Count -eq 0){throw 'No executable payload extracted; inspect static archive layout'}
Write-Host 'GAMEVIEWER_OFFICIAL_HASH_AND_SIGNATURE_STATIC_REVIEW=PASS'
