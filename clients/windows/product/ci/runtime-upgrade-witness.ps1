param(
 [Parameter(Mandatory=$true)][ValidateSet('Seed','VerifyUdp','VerifyAuto','Runtime8','Runtime10')][string]$Phase,
 [Parameter(Mandatory=$true)][string]$FixtureRoot,
 [Parameter(Mandatory=$true)][string]$ResultPath,
 [uint32]$ExpectedPid=0
)
# Non-shipped, disposable-host fixture. Only fixed public RFC 7748 test keys
# are ever seeded; no account login, bearer, tunnel, or production peer exists.
$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsIdentity]::GetCurrent().User.IsWellKnown([Security.Principal.WellKnownSidType]::LocalSystemSid)) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0){exit 3}
$expected=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'OracleProxyRuntimeUpgradeFixture'
if($FixtureRoot -cne $expected -or -not (Test-Path (Join-Path $FixtureRoot 'authorized')) -or (Get-Content -Raw (Join-Path $FixtureRoot 'authorized')).Trim() -cne 'HOSTED_DISPOSABLE_RUNTIME_UPGRADE_ONLY'){exit 3}
if((Split-Path $ResultPath) -cne $FixtureRoot -or (Split-Path $ResultPath -Leaf) -notmatch '^result-[a-f0-9]{32}\.json$'){exit 3}
$stateRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'OracleProxy'
$statePath=Join-Path $stateRoot 'state.dpapi'
if($Phase -in @('Runtime8','Runtime10')){
 $major=if($Phase -eq 'Runtime8'){8}else{10}
 $observation=@{ok=$false;module_count=0;major=-1;pid_bound=$false;cache_bound=$false}
 $cachePrefix=[IO.Path]::GetFullPath((Join-Path $stateRoot 'bundle'))+[IO.Path]::DirectorySeparatorChar
 $image='"'+(Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'OracleProxy\OracleProxy.Service.exe')+'" --service'
 for($attempt=0;$attempt -lt 20;$attempt++){
  $process=$null
  try{
   $service=Get-CimInstance Win32_Service -Filter "Name='OracleProxyService'"
   $observation.pid_bound=$ExpectedPid -gt 0 -and $service -and $service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem' -and $service.PathName -ceq $image -and $service.ProcessId -eq $ExpectedPid
   if($observation.pid_bound){
    $process=[Diagnostics.Process]::GetProcessById([int]$ExpectedPid)
    $modules=@($process.Modules | Where-Object ModuleName -eq 'coreclr.dll')
    $observation.module_count=[Math]::Min($modules.Count,1024)
    if($modules.Count -eq 1){
     $path=[IO.Path]::GetFullPath($modules[0].FileName)
     $observation.cache_bound=$path.StartsWith($cachePrefix,[StringComparison]::OrdinalIgnoreCase)
     if($observation.cache_bound){$observation.major=[Diagnostics.FileVersionInfo]::GetVersionInfo($path).ProductMajorPart}
    }
   }
   $observation.ok=$observation.pid_bound -and $observation.cache_bound -and $observation.module_count -eq 1 -and $observation.major -eq $major
   if($observation.ok){break}
  }catch{ # Retain only count/major/bool evidence; no raw paths or messages.
  }finally{if($null -ne $process){$process.Dispose()}}
  Start-Sleep -Milliseconds 100
 }
 [IO.File]::WriteAllText($ResultPath,($observation | ConvertTo-Json -Compress))
 if($observation.ok){exit 0}else{exit 1}
}
$private=[Convert]::ToBase64String([byte[]](0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a))
$public=[Convert]::ToBase64String([byte[]](0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a))
$plain=$null
try {
 Add-Type -AssemblyName System.Security
 if($Phase -eq 'Seed'){
  $service=Get-CimInstance Win32_Service -Filter "Name='OracleProxyService'"
  $image='"'+(Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'OracleProxy\OracleProxy.Service.exe')+'" --service'
  if(-not $service -or $service.State -ne 'Stopped' -or $service.PathName -cne $image -or -not (Test-Path $stateRoot) -or (Test-Path $statePath)){throw 'SEED_ONLY_FRESH_OWNED_STOPPED_SERVICE'}
  $value=@{PrivateKey=$private;PublicKey=$public;Token='';TransportPreference='auto';NativeUdpPortPreference=0;ConnectIntent=$false;RecoveryRequired=$false;UuPaths=@()}
  $plain=[Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Compress))
  $cipher=[Security.Cryptography.ProtectedData]::Protect($plain,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
  [IO.File]::WriteAllBytes($statePath,$cipher)
 }else{
  $plain=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($statePath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
  $value=[Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
  $preference=if($Phase -eq 'VerifyUdp'){'udp'}else{'auto'}
  if($value.PrivateKey -cne $private -or $value.PublicKey -cne $public -or $value.Token -cne '' -or $value.ConnectIntent -ne $false -or $value.RecoveryRequired -ne $false -or @($value.UuPaths).Count -ne 0 -or $value.TransportPreference -cne $preference){throw 'SYNTHETIC_SYSTEM_IDENTITY_OR_PREFERENCE_CHANGED'}
 }
 [IO.File]::WriteAllText($ResultPath,'{"ok":true,"synthetic_key_pair_preserved":true,"system_dpapi":true}')
 exit 0
}catch{
 [IO.File]::WriteAllText($ResultPath,'{"ok":false}')
 exit 1
}finally{
 if($null -ne $plain){[Array]::Clear($plain,0,$plain.Length)}
}
