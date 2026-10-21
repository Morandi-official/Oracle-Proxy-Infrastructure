# Non-shipped hosted fixture: verified signed bytes are never executed.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'official-download.ps1')
function New-CIUuNetworkFixture {
  if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Hosted runner required'}
  $folder=Join-Path $env:ProgramFiles 'OracleProxy/GameViewer-Network-Fixture'
  $key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OracleProxy.GameViewerNetworkFixture'
  if((Test-Path $folder) -or (Test-Path $key)){throw 'Preexisting network fixture refused'}
  New-Item -ItemType Directory $folder | Out-Null
  Set-Content (Join-Path $folder 'fixture.authorized') 'DISPOSABLE_GITHUB_ONLY'
  $image=Join-Path $folder 'GameViewer.exe'
  Get-OfficialFile -Uri 'https://a56.gdl.netease.com/UURemote_Setup_4.40.1.2090_0914120217_gwqd.exe' -OutFile $image -SHA256 '64F918B80A99A570DD43A0CA0C8C4FAC5B9B734AD6308E0F5C69BC0BE6CE5167'
  if((Get-AuthenticodeSignature $image).Status -ne 'Valid'){throw 'Official fixture signature refused'}
  # Hardlinks avoid copying the installer 19 times. All names and the single
  # underlying file are under the same protected, CI-owned program directory.
  for($index=1;$index -lt 19;$index++){New-Item -ItemType HardLink -Path (Join-Path $folder "GameViewer-$index.exe") -Target $image | Out-Null}
  New-Item $key | Out-Null
  New-ItemProperty $key -Name DisplayName -Value 'GameViewer CI network fixture' -PropertyType String | Out-Null
  New-ItemProperty $key -Name InstallLocation -Value $folder -PropertyType String | Out-Null
}
function Remove-CIUuNetworkFixture {
  if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Hosted runner required'}
  $folder=Join-Path $env:ProgramFiles 'OracleProxy/GameViewer-Network-Fixture'
  $key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OracleProxy.GameViewerNetworkFixture'
  if(!(Test-Path (Join-Path $folder 'fixture.authorized'))){return}
  if((Get-Item $folder -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Fixture link refused'}
  if(Test-Path $key){if((Get-ItemProperty $key).InstallLocation -ne $folder){throw 'Foreign fixture key refused'};Remove-Item $key}
  Remove-Item $folder -Recurse -Force
}
