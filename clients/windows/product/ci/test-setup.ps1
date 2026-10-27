param([Parameter(Mandatory=$true)][string]$SetupPath)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not [Environment]::Is64BitProcess){throw 'HOSTED_WINDOWS_X64_SETUP_TEST_REQUIRED'}
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ADMIN_REQUIRED'}
$desktopRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'OracleProxyDesktop'
$serviceRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'OracleProxy'
$stateRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'OracleProxy'
$arp='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{26C03D94-CA79-4A48-BC2C-F45BD14C69F5}_is1'
$shortcut=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)) 'Oracle Proxy\Oracle Proxy.lnk'
if((Get-Service OracleProxyService -ErrorAction SilentlyContinue) -or (Test-Path $desktopRoot) -or (Test-Path $serviceRoot) -or (Test-Path $arp)){throw 'PREEXISTING_INSTALLATION_REFUSED'}
$setup=(Resolve-Path $SetupPath).Path
$metadata=Get-Content -Raw (Join-Path (Split-Path $setup) 'BUILD.json') | ConvertFrom-Json
if((Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.installer.sha256){throw 'SETUP_DIGEST_MISMATCH'}
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function Invoke-SetupProcess([string]$File,[string[]]$Arguments) {
 $process=Start-Process -FilePath $File -ArgumentList $Arguments -PassThru
 if(-not $process.WaitForExit(120000)){Stop-Process -Id $process.Id -Force;throw 'SETUP_PROCESS_DEADLINE'}
 if($process.ExitCode -ne 0){throw ('SETUP_PROCESS_FAILED_'+$process.ExitCode)}
}
function Check-Installed {
 $service=Get-CimInstance Win32_Service -Filter "Name='OracleProxyService'"
 $expected='"'+(Join-Path $serviceRoot 'OracleProxy.Service.exe')+'" --service'
 if(-not $service -or $service.State -ne 'Running' -or $service.ProcessId -le 0 -or $service.PathName -ne $expected -or $service.StartMode -ne 'Auto'){throw 'FIXED_SERVICE_IMAGE_PID_AUTOSTART_FAILED'}
 foreach($root in @($serviceRoot,$desktopRoot)){
  $acl=Get-Acl $root
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544') -or -not $acl.AreAccessRulesProtected){throw 'INSTALLED_DIRECTORY_PROTECTED_ADMIN_OWNER_REQUIRED'}
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
   if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and ($rule.FileSystemRights -band ([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)) -ne 0){throw 'INSTALLED_DIRECTORY_UNTRUSTED_WRITER'}
  }
 }
 if((Get-Content -Raw (Join-Path $desktopRoot 'desktop.marker')) -ne 'OracleProxy.Desktop.v1'){throw 'DESKTOP_PRODUCT_MARKER_REQUIRED'}
 foreach($name in @('OracleProxy.exe','OracleProxy.Core.exe','OracleProxy.Guard.dll')){
  if((Get-FileHash (Join-Path $desktopRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.payload_sha256.$name){throw 'DESKTOP_PAYLOAD_DIGEST_MISMATCH'}
 }
 foreach($name in @('OracleProxy.Core.exe','OracleProxy.Guard.dll')){
  if((Get-FileHash (Join-Path $serviceRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.payload_sha256.$name){throw 'SERVICE_PAYLOAD_DIGEST_MISMATCH'}
 }
 if((Get-FileHash (Join-Path $serviceRoot 'OracleProxy.Service.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.payload_sha256.'OracleProxy.exe'){throw 'SERVICE_HOST_DIGEST_MISMATCH'}
 if((Get-Content -Raw (Join-Path $serviceRoot 'owner.sid')).Trim() -ne $owner){throw 'OWNER_BINDING_MISMATCH'}
 if(-not (Test-Path $shortcut) -or -not (Test-Path $arp)){throw 'STANDARD_SHORTCUT_AND_UNINSTALL_ENTRY_REQUIRED'}
 $registration=Get-ItemProperty $arp
 if($registration.DisplayName -notlike 'Oracle Proxy*' -or $registration.DisplayVersion -ne $metadata.version){throw 'STANDARD_UNINSTALL_METADATA_REQUIRED'}
 $shell=New-Object -ComObject WScript.Shell
 if($shell.CreateShortcut($shortcut).TargetPath -ne (Join-Path $desktopRoot 'OracleProxy.exe')){throw 'SHORTCUT_TARGET_MISMATCH'}
 return [int]$service.ProcessId
}

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class SetupAcceptancePipe {
 [DllImport("kernel32.dll")] static extern bool GetNamedPipeServerProcessId(SafePipeHandle handle,out uint pid);
 public static string PreferUdp(uint expectedPid) {
  using(var pipe=new NamedPipeClientStream(".","OracleProxy.Control.v1",PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation)){
   pipe.Connect(3000);uint pid;if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid)||pid!=expectedPid)throw new IOException("SERVICE_PID_BINDING_FAILED");
   byte[] request=Encoding.UTF8.GetBytes("{\"version\":1,\"command\":\"PreferUdp\"}\n");pipe.Write(request,0,request.Length);pipe.Flush();
   byte[] bytes=new byte[65537];int n=0;var watch=System.Diagnostics.Stopwatch.StartNew();
   while(n<bytes.Length){int remaining=8000-(int)watch.ElapsedMilliseconds;if(remaining<=0)throw new IOException("SERVICE_RESPONSE_TIMEOUT");var read=pipe.ReadAsync(bytes,n,1);if(!read.Wait(remaining))throw new IOException("SERVICE_RESPONSE_TIMEOUT");if(read.Result!=1)throw new IOException("SERVICE_EOF");if(bytes[n++]==10)return Encoding.UTF8.GetString(bytes,0,n-1);}
   throw new IOException("SERVICE_RESPONSE_TOO_LARGE");
  }
 }
}
'@

$started=$false
try {
 $arguments=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/OwnerSid='+$owner))
 # A different installer's Users-Modify desktop tree must not become the
 # source of an elevated uninstaller. This directory is created by this test.
 New-Item -ItemType Directory $desktopRoot | Out-Null
 $unsafe=New-Object Security.AccessControl.DirectorySecurity
 $unsafe.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
 $unsafe.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $unsafe.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
 }
 $unsafe.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')),'Modify','ContainerInherit,ObjectInherit','None','Allow')))
 Set-Acl -LiteralPath $desktopRoot -AclObject $unsafe
 Set-Content -LiteralPath (Join-Path $desktopRoot 'foreign-sentinel.txt') -Value 'DISPOSABLE_FOREIGN_DESKTOP_FIXTURE'
 $rejected=Start-Process -FilePath $setup -ArgumentList $arguments -PassThru
 if(-not $rejected.WaitForExit(120000)){Stop-Process -Id $rejected.Id -Force;throw 'UNSAFE_DESKTOP_REJECTION_DEADLINE'}
 if($rejected.ExitCode -eq 0 -or (Get-Service OracleProxyService -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $desktopRoot 'OracleProxy.exe')) -or (Test-Path (Join-Path $desktopRoot 'desktop.marker')) -or (Test-Path $arp) -or (Get-Content -Raw (Join-Path $desktopRoot 'foreign-sentinel.txt')).Trim() -ne 'DISPOSABLE_FOREIGN_DESKTOP_FIXTURE'){throw 'WRITABLE_FOREIGN_DESKTOP_WAS_ADOPTED'}
 Remove-Item -LiteralPath (Join-Path $desktopRoot 'foreign-sentinel.txt')
 [IO.Directory]::Delete($desktopRoot,$false)
 Write-Host 'REAL_EXE_SETUP_REFUSES_PREEXISTING_USERS_MODIFY_DESKTOP_WITHOUT_SERVICE_OR_FILE_CHANGES=PASS'
 $started=$true
 Invoke-SetupProcess $setup $arguments
 $firstPid=Check-Installed
 $response=[SetupAcceptancePipe]::PreferUdp([uint32]$firstPid) | ConvertFrom-Json
 if(-not $response.ok -or $response.mode -ne 'disconnected' -or $response.transport_preference -ne 'udp'){throw 'SYNTHETIC_NON_ACCOUNT_STATE_NOT_SAVED'}
 $savedState=(Get-FileHash (Join-Path $stateRoot 'state.dpapi') -Algorithm SHA256).Hash
 Invoke-SetupProcess $setup $arguments
 $secondPid=Check-Installed
 if($secondPid -eq $firstPid){throw 'UPGRADE_DID_NOT_REPLACE_SERVICE_PROCESS'}
 if((Get-FileHash (Join-Path $stateRoot 'state.dpapi') -Algorithm SHA256).Hash -ne $savedState){throw 'UPGRADE_DID_NOT_PRESERVE_DPAPI_STATE'}
 Write-Host 'REAL_EXE_SETUP_UPGRADE_SHORTCUT_ARP_PID_HASH_OWNER_AND_DPAPI_PRESERVATION=PASS'
 Invoke-SetupProcess (Join-Path $desktopRoot 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
 if((Get-Service OracleProxyService -ErrorAction SilentlyContinue) -or (Test-Path $arp) -or (Test-Path $shortcut) -or (Test-Path (Join-Path $desktopRoot 'OracleProxy.exe')) -or (Test-Path (Join-Path $stateRoot 'state.dpapi'))){throw 'STANDARD_UNINSTALL_NOT_COMPLETE'}
 Write-Host 'REAL_EXE_STANDARD_UNINSTALL_REMOVES_OWN_SERVICE_SHORTCUT_ARP_AND_LOCAL_STATE=PASS'
 if([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){Write-Host 'WTS_ORIGINAL_DESKTOP_OWNER_BRANCH=NOT_COVERED_HEADLESS_SESSION'}else{Write-Host 'WTS_ORIGINAL_DESKTOP_OWNER_BRANCH=EXPLICIT_OWNER_CI_OVERRIDE_ONLY'}
} finally {
 # Fixed candidate-owned cleanup only; there are no credentials, peers or
 # Connect requests in this fixture. A failed install must not affect others.
 if($started -and (Get-Service OracleProxyService -ErrorAction SilentlyContinue)){
  $client=Join-Path $desktopRoot 'OracleProxy.exe'
  if(-not (Test-Path $client)){$client=Join-Path $PWD 'dist/product/OracleProxy.exe'}
  if((Test-Path $client) -and (Get-FileHash $client -Algorithm SHA256).Hash.ToLowerInvariant() -eq $metadata.payload_sha256.'OracleProxy.exe'){
   $process=Start-Process -FilePath $client -ArgumentList '--uninstall' -PassThru
   if(-not $process.WaitForExit(60000)){Stop-Process -Id $process.Id -Force;Write-Warning 'Candidate cleanup did not complete'}
  }
 }
}
