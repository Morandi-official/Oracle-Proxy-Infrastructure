# CI-only bounded static-source retrieval. Never executes downloaded programs.
function Get-OfficialFile {
  param([Parameter(Mandatory)][string]$Uri,[Parameter(Mandatory)][string]$OutFile,[string]$SHA256='')
  $source=[Uri]$Uri
  if($source.Scheme -ne 'https' -or $source.Host -notin @('a56.gdl.netease.com','www.wintun.net') -or $source.UserInfo){throw 'Unsupported official source'}
  if($SHA256 -and $SHA256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Invalid source digest'}
  $partial=$OutFile+'.partial'
  for($attempt=1;$attempt -le 3;$attempt++){
    try{
      Invoke-WebRequest -Uri $Uri -OutFile $partial -MaximumRedirection 2 -TimeoutSec 30
      if($SHA256 -and (Get-FileHash $partial -Algorithm SHA256).Hash -ne $SHA256){throw 'Source checksum mismatch'}
      [IO.File]::Move($partial,$OutFile,$true)
      return
    }catch{
      Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
      if($attempt -eq 3){throw 'Official source download failed after three bounded attempts'}
      Write-Host 'OFFICIAL_SOURCE_DOWNLOAD_RETRY'
      Start-Sleep -Seconds 2
    }
  }
}
