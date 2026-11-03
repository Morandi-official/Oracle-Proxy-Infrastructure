param([Parameter(Mandatory=$true)][string]$FixtureExe)
$ErrorActionPreference='Stop'
function Get-RawFixtureBusType {
  param([Parameter(Mandatory=$true)]$Disk)
  # MSFT_Disk.BusType is a CIM UInt16. The adapted PowerShell property can
  # expose a localized friendly name; only the underlying numeric value is
  # suitable for an identity decision. Virtual(14) is deliberately refused.
  $properties=$Disk.CimInstanceProperties
  if($null -eq $properties){throw 'RAW_CIM_BUS_TYPE_REQUIRED'}
  $property=$properties['BusType']
  if($null -eq $property){throw 'RAW_CIM_BUS_TYPE_REQUIRED'}
  $raw=$property.Value
  if($null -eq $raw -or $raw -isnot [UInt16]){throw 'RAW_CIM_BUS_TYPE_REQUIRED'}
  return [UInt32]$raw
}
function Get-FixedFixtureError {
  param([Parameter(Mandatory=$true)]$Record)
  $known=@('OFFICIAL_NETEASE_SIGNATURE_REQUIRED','NO_UNUSED_FIXTURE_DRIVE_LETTER','VHD_CREATE_TIMEOUT','VHD_CREATE_FAILED',
    'OWNED_VHD_ATTACHMENT_REQUIRED','RAW_CIM_BUS_TYPE_REQUIRED','OWNED_VIRTUAL_DISK_REQUIRED','OWNED_VHD_PARTITION_REQUIRED',
    'OWNED_NTFS_LABEL_REQUIRED','OWNED_VOLUME_GUID_REQUIRED','SYSTEM_VOLUME_REFUSED','EXISTING_TEST_USER_REFUSED',
    'PREEXISTING_FIXTURE_ENV_REFUSED','UU_PATH_FIXTURE_SETUP_BUDGET_EXCEEDED','UU_PATH_FIXTURE_TOTAL_BUDGET_EXCEEDED',
    'UU_PATH_PROTECTION_NATIVE_GATE_FAILED','TEST_USER_IDENTITY_CHANGED_REFUSE_DELETE','VHD_FILE_CHANGED_REFUSE_DETACH',
    'VHD_IDENTITY_CHANGED_REFUSE_DETACH','VOLUME_IDENTITY_CHANGED_REFUSE_DETACH','VOLUME_MARKER_CHANGED_REFUSE_DETACH',
    'OWNED_VHD_DID_NOT_DETACH')
  if($known -ccontains $Record.Exception.Message){return $Record.Exception.Message}
  if($Record.Exception.Message -ceq 'Official source download failed after three bounded attempts'){return 'OFFICIAL_SOURCE_DOWNLOAD_FAILED'}
  return 'UU_PATH_PLATFORM_ERROR'
}
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ADMIN_REQUIRED'}
$fixture=Get-Item -LiteralPath $FixtureExe
if($fixture.Name -ne 'OracleProxy.Product.Tests.exe' -or ($fixture.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'FIXTURE_BINARY_REQUIRED'}
. "$PSScriptRoot/official-download.ps1"
$token=[Guid]::NewGuid().ToString('N')
$label='OPUPTEST_'+$token.Substring(0,12)
$work=Join-Path $env:RUNNER_TEMP ('OracleProxy-UuPath-'+$token)
$vhd=Join-Path $work 'owned.vhdx'
$userName='opuu'+$token.Substring(0,10)
$userTag='OPUP '+$token
$diskNumber=$null;$volumeGuid=$null;$driveRoot=$null;$userSid=$null;$attached=$false;$setCredentialEnvironment=$false
$clock=[Diagnostics.Stopwatch]::StartNew()
$stage='SETUP';$primaryFailure=$null;$cleanupFailure=$null
New-Item -ItemType Directory -Path $work | Out-Null
try {
  $stage='OFFICIAL_SOURCE'
  $installer=Join-Path $work 'official.exe'
  $digest='64F918B80A99A570DD43A0CA0C8C4FAC5B9B734AD6308E0F5C69BC0BE6CE5167'
  Get-OfficialFile -Uri 'https://a56.gdl.netease.com/UURemote_Setup_4.40.1.2090_0914120217_gwqd.exe' -OutFile $installer -SHA256 $digest
  if((Get-AuthenticodeSignature -LiteralPath $installer).Status -ne 'Valid'){throw 'OFFICIAL_NETEASE_SIGNATURE_REQUIRED'}
  $used=@(Get-PSDrive -PSProvider FileSystem | ForEach-Object Name)+@(Get-Volume | Where-Object DriveLetter | ForEach-Object {[string]$_.DriveLetter})
  $letter=@(90..71 | ForEach-Object {[string][char]$_} | Where-Object {$_ -notin $used -and -not (Test-Path ($_+':\'))}) | Select-Object -First 1
  if(-not $letter){throw 'NO_UNUSED_FIXTURE_DRIVE_LETTER'}
  $stage='VHD_CREATE'
  $diskpart=Join-Path $work 'create.txt'
  @("create vdisk file=`"$vhd`" maximum=512 type=expandable", "select vdisk file=`"$vhd`"",'attach vdisk','create partition primary',"format fs=ntfs quick label=$label","assign letter=$letter") | Set-Content -LiteralPath $diskpart -Encoding ASCII
  $diskpartLog=Join-Path $work 'diskpart-create.log'
  $create=Start-Process -FilePath "$env:WINDIR\System32\diskpart.exe" -ArgumentList @('/s',"`"$diskpart`"") -PassThru -NoNewWindow -RedirectStandardOutput $diskpartLog
  if(-not $create.WaitForExit(30000)){$create.Kill();[void]$create.WaitForExit(5000);throw 'VHD_CREATE_TIMEOUT'}
  if($create.ExitCode -ne 0){throw 'VHD_CREATE_FAILED'}
  $stage='VHD_VERIFY'
  $image=Get-DiskImage -ImagePath $vhd
  if(-not $image.Attached -or $image.ImagePath -ne $vhd){throw 'OWNED_VHD_ATTACHMENT_REQUIRED'}
  $attached=$true
  $disk=$image | Get-Disk
  $bus=Get-RawFixtureBusType -Disk $disk
  Write-Host ("UU_PATH_STORAGE_NUMERIC stage=VHD_VERIFY disk={0} bus={1}" -f [UInt32]$disk.Number,$bus)
  if($bus -ne 15){throw 'OWNED_VIRTUAL_DISK_REQUIRED'}
  $diskNumber=$disk.Number
  $partition=@(Get-Partition -DiskNumber $diskNumber | Where-Object {$_.DriveLetter -eq $letter})
  if($partition.Count -ne 1){throw 'OWNED_VHD_PARTITION_REQUIRED'}
  $volume=Get-Volume -DriveLetter $letter
  if($volume.FileSystem -ne 'NTFS' -or $volume.FileSystemLabel -ne $label){throw 'OWNED_NTFS_LABEL_REQUIRED'}
  $volumeGuid=$volume.UniqueId
  if($volumeGuid -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$'){throw 'OWNED_VOLUME_GUID_REQUIRED'}
  $driveRoot=$letter+':\'
  if($driveRoot -eq [IO.Path]::GetPathRoot($env:WINDIR)){throw 'SYSTEM_VOLUME_REFUSED'}
  @{schema=1;token=$token;label=$label;volume=$volumeGuid;disk=$diskNumber} | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $driveRoot '.oracle-uu-vhd-fixture.json') -Encoding UTF8
  Move-Item -LiteralPath $installer -Destination (Join-Path $driveRoot 'official.exe')
  $stage='ORDINARY_ACCOUNT'
  if(Get-LocalUser -Name $userName -ErrorAction SilentlyContinue){throw 'EXISTING_TEST_USER_REFUSED'}
  $password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(36))+'aA1!'
  $user=New-LocalUser -Name $userName -Password (ConvertTo-SecureString $password -AsPlainText -Force) -Description $userTag -AccountNeverExpires -PasswordNeverExpires
  $userSid=$user.SID.Value
  Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545').Name -Member $user
  foreach($name in @('ORACLE_UU_PATH_FIXTURE_USERNAME','ORACLE_UU_PATH_FIXTURE_PASSWORD')){if([Environment]::GetEnvironmentVariable($name)){throw 'PREEXISTING_FIXTURE_ENV_REFUSED'}}
  $env:ORACLE_UU_PATH_FIXTURE_USERNAME=$userName;$env:ORACLE_UU_PATH_FIXTURE_PASSWORD=$password
  $setCredentialEnvironment=$true
  $remaining=165000-[int]$clock.ElapsedMilliseconds
  if($remaining -le 0){throw 'UU_PATH_FIXTURE_SETUP_BUDGET_EXCEEDED'}
  $output=Join-Path $work 'fixture.log';$errors=Join-Path $work 'fixture-error.log'
  $stage='NATIVE_FIXTURE'
  $test=Start-Process -FilePath $fixture.FullName -ArgumentList @('--uu-path-protection-self-test',($driveRoot+'.'),$volumeGuid.TrimEnd('\')) -PassThru -NoNewWindow -RedirectStandardOutput $output -RedirectStandardError $errors
  if(-not $test.WaitForExit($remaining)){$test.Kill();[void]$test.WaitForExit(5000);throw 'UU_PATH_FIXTURE_TOTAL_BUDGET_EXCEEDED'}
  Get-Content -LiteralPath $output
  if($test.ExitCode -ne 0){Get-Content -LiteralPath $errors;throw 'UU_PATH_PROTECTION_NATIVE_GATE_FAILED'}
  Write-Host 'REAL_OWNED_NTFS_UU_PATH_PROTECTION_GATE=PASS'
} catch {
  $primaryFailure=@{Stage=$stage;Code=(Get-FixedFixtureError -Record $_)}
  Write-Host ("UU_PATH_PRIMARY_FAILURE stage={0} code={1} hresult=0x{2:X8}" -f $stage,$primaryFailure.Code,[UInt32]($_.Exception.HResult -band 0xffffffffL))
} finally {
  $cleanupStage='ACCOUNT_CLEANUP'
  try {
  if($setCredentialEnvironment){Remove-Item Env:ORACLE_UU_PATH_FIXTURE_USERNAME,Env:ORACLE_UU_PATH_FIXTURE_PASSWORD -ErrorAction SilentlyContinue}
  $password=$null
  if($userSid){$actual=Get-LocalUser -Name $userName -ErrorAction SilentlyContinue;if($actual -and $actual.SID.Value -eq $userSid -and $actual.Description -eq $userTag){Remove-LocalUser -SID $actual.SID}else{throw 'TEST_USER_IDENTITY_CHANGED_REFUSE_DELETE'}}
  $cleanupStage='VHD_CLEANUP'
  # Never detach a disk by a reused drive letter or unverified disk number.
  if(Test-Path -LiteralPath $vhd){
    $vhdFile=Get-Item -LiteralPath $vhd
    if($vhdFile.PSIsContainer -or ($vhdFile.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'VHD_FILE_CHANGED_REFUSE_DETACH'}
    $image=Get-DiskImage -ImagePath $vhd -ErrorAction SilentlyContinue
    if($image -and $image.Attached){
      $disk=$image | Get-Disk
      $bus=Get-RawFixtureBusType -Disk $disk
      Write-Host ("UU_PATH_STORAGE_NUMERIC stage=VHD_CLEANUP disk={0} bus={1}" -f [UInt32]$disk.Number,$bus)
      if($image.ImagePath -ne $vhd -or ($diskNumber -ne $null -and $disk.Number -ne $diskNumber) -or $bus -ne 15){throw 'VHD_IDENTITY_CHANGED_REFUSE_DETACH'}
      if($volumeGuid){
        $actual=Get-Volume -DriveLetter $driveRoot.Substring(0,1)
        if($actual.UniqueId -ne $volumeGuid -or $actual.FileSystemLabel -ne $label){throw 'VOLUME_IDENTITY_CHANGED_REFUSE_DETACH'}
        $markerPath=Join-Path $driveRoot '.oracle-uu-vhd-fixture.json'
        if((Get-Item -LiteralPath $markerPath).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'VOLUME_MARKER_CHANGED_REFUSE_DETACH'}
        $marker=Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
        if($marker.schema -ne 1 -or $marker.token -ne $token -or $marker.label -ne $label -or $marker.volume -ne $volumeGuid -or $marker.disk -ne $diskNumber){throw 'VOLUME_MARKER_CHANGED_REFUSE_DETACH'}
      }
      Dismount-DiskImage -ImagePath $vhd
    }
    if((Get-DiskImage -ImagePath $vhd).Attached){throw 'OWNED_VHD_DID_NOT_DETACH'}
    Remove-Item -LiteralPath $vhd -Force
  }
  $cleanupStage='WORK_CLEANUP'
  if(Test-Path -LiteralPath $work){Remove-Item -LiteralPath $work -Recurse -Force}
  } catch {
    $cleanupFailure=@{Stage=$cleanupStage;Code=(Get-FixedFixtureError -Record $_)}
    Write-Host ("UU_PATH_CLEANUP_FAILURE stage={0} code={1} hresult=0x{2:X8}" -f $cleanupStage,$cleanupFailure.Code,[UInt32]($_.Exception.HResult -band 0xffffffffL))
  }
}
if($primaryFailure){throw ('UU_PATH_FAILURE stage='+$primaryFailure.Stage+' code='+$primaryFailure.Code)}
if($cleanupFailure){throw ('UU_PATH_CLEANUP_FAILURE stage='+$cleanupFailure.Stage+' code='+$cleanupFailure.Code)}
