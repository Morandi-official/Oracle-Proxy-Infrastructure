$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not [Environment]::Is64BitProcess){throw 'HOSTED_WINDOWS_X64_RUNTIME_UPGRADE_REQUIRED'}
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ADMIN_REQUIRED'}
$serviceRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'OracleProxy'
$stateRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'OracleProxy'
$fixture=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'OracleProxyRuntimeUpgradeFixture'
if((Get-Service OracleProxyService,OracleProxyRecovery -ErrorAction SilentlyContinue) -or (Test-Path $serviceRoot) -or (Test-Path $stateRoot) -or (Test-Path $fixture) -or (Get-NetAdapter -Name OracleProxy -ErrorAction SilentlyContinue)){throw 'PREEXISTING_PRODUCT_OR_FIXTURE_REFUSED'}
$new=(Resolve-Path './dist/product/OracleProxy.exe').Path
$newHash=(Get-FileHash $new -Algorithm SHA256).Hash
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$oldRevision='fc988d72983906b74aeb629163a8110bc36ee8ab'
$oldArchiveHash='6f8a133fd2f297b9479affe954d95f5988f4ae44fc747c7df30ba958f6c6f78f'
$oldUrl='https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/releases/download/v0.3.0-rc21/OracleProxy-0.3.0-rc21-win-x64-fc988d729839.zip'
$task='OracleProxyRuntimeUpgrade-'+[Guid]::NewGuid().ToString('N')
$owned=$false
$taskOwned=$false

function Invoke-RuntimeProduct([string]$File,[string[]]$Arguments){
 $process=Start-Process -FilePath $File -ArgumentList $Arguments -PassThru
 if(-not $process.WaitForExit(120000)){Stop-Process -Id $process.Id -Force;throw 'RUNTIME_UPGRADE_PROCESS_DEADLINE'}
 if($process.ExitCode -ne 0){throw ('RUNTIME_UPGRADE_PRODUCT_FAILED_'+$process.ExitCode)}
}
function Get-VerifiedProductService([string]$Hash){
 $service=Get-CimInstance Win32_Service -Filter "Name='OracleProxyService'"
 $image='"'+(Join-Path $serviceRoot 'OracleProxy.Service.exe')+'" --service'
 if(-not $service -or $service.State -ne 'Running' -or $service.ProcessId -le 0 -or $service.PathName -cne $image -or $service.StartName -ne 'LocalSystem' -or $service.StartMode -ne 'Auto'){throw 'RUNTIME_UPGRADE_FIXED_SYSTEM_SERVICE_REQUIRED'}
 if((Get-FileHash (Join-Path $serviceRoot 'OracleProxy.Service.exe') -Algorithm SHA256).Hash -ne $Hash -or (Get-Content -Raw (Join-Path $serviceRoot 'owner.sid')).Trim() -cne $owner){throw 'RUNTIME_UPGRADE_SERVICE_PAYLOAD_OR_OWNER_CHANGED'}
 return [uint32]$service.ProcessId
}
function Invoke-RuntimeWitness([string]$Phase){
 $result=Join-Path $fixture ('result-'+[Guid]::NewGuid().ToString('N')+'.json')
 $script=Join-Path $fixture 'runtime-upgrade-witness.ps1'
 $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$script+'" -Phase '+$Phase+' -FixtureRoot "'+$fixture+'" -ResultPath "'+$result+'"'
 # Process-scoped policy is only for this checked-in, non-shipped witness.
 # No execution policy, firewall, network binding or OS setting is changed.
 $action=New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $arguments
 Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest -Force | Out-Null
 $script:taskOwned=$true
 Start-ScheduledTask -TaskName $task
 for($i=0;$i -lt 80 -and -not (Test-Path $result);$i++){Start-Sleep -Milliseconds 250}
 if(-not (Test-Path $result)){throw 'SYSTEM_RUNTIME_WITNESS_DEADLINE'}
 $value=Get-Content -Raw $result | ConvertFrom-Json
 if(-not $value.ok -or -not $value.system_dpapi -or -not $value.synthetic_key_pair_preserved){throw 'SYSTEM_RUNTIME_WITNESS_FAILED'}
 for($i=0;$i -lt 40 -and (Get-ScheduledTask -TaskName $task).State -eq 'Running';$i++){Start-Sleep -Milliseconds 100}
 if((Get-ScheduledTask -TaskName $task).State -eq 'Running' -or (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult -ne 0){throw 'SYSTEM_RUNTIME_WITNESS_NOT_COMPLETED'}
}

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class RuntimeUpgradePipe {
 [DllImport("kernel32.dll")] static extern bool GetNamedPipeServerProcessId(SafePipeHandle handle,out uint pid);
 public static string Send(uint expectedPid,string command) {
  if(command!="Status" && command!="PreferUdp" && command!="PreferAuto")throw new IOException("FIXED_RUNTIME_FIXTURE_COMMANDS_ONLY");
  using(var pipe=new NamedPipeClientStream(".","OracleProxy.Control.v1",PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation)){
   pipe.Connect(3000);uint pid;if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid)||pid!=expectedPid)throw new IOException("SERVICE_PID_BINDING_FAILED");
   byte[] request=Encoding.UTF8.GetBytes("{\"version\":1,\"command\":\""+command+"\"}\n");pipe.Write(request,0,request.Length);pipe.Flush();
   byte[] bytes=new byte[65537];int n=0;var watch=System.Diagnostics.Stopwatch.StartNew();
   while(n<bytes.Length){int remaining=8000-(int)watch.ElapsedMilliseconds;if(remaining<=0)throw new IOException("SERVICE_RESPONSE_TIMEOUT");var read=pipe.ReadAsync(bytes,n,1);if(!read.Wait(remaining))throw new IOException("SERVICE_RESPONSE_TIMEOUT");if(read.Result!=1)throw new IOException("SERVICE_EOF");if(bytes[n++]==10)return Encoding.UTF8.GetString(bytes,0,n-1);}
   throw new IOException("SERVICE_RESPONSE_TOO_LARGE");
  }
 }
}
'@
function Assert-RuntimeStatus([uint32]$ExpectedPid,[string]$Command,[string]$Version,[string]$Preference){
 $value=[RuntimeUpgradePipe]::Send($ExpectedPid,$Command) | ConvertFrom-Json
 if($value.schema -ne 1 -or -not $value.ok -or $value.mode -ne 'disconnected' -or $value.intent -ne $false -or $value.guard -ne $false -or $value.product_version -notlike ($Version+'*') -or $value.transport_preference -cne $Preference){throw 'RUNTIME_UPGRADE_AUTHENTICATED_STATUS_OR_STATE_FAILED'}
}

try {
 New-Item -ItemType Directory $fixture | Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
 $acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
 }
 Set-Acl -LiteralPath $fixture -AclObject $acl
 Set-Content -LiteralPath (Join-Path $fixture 'authorized') -Value 'HOSTED_DISPOSABLE_RUNTIME_UPGRADE_ONLY'
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'runtime-upgrade-witness.ps1') -Destination $fixture
 $archive=Join-Path $fixture 'accepted-rc21.zip'
 for($attempt=1;$attempt -le 3;$attempt++){
  try{Invoke-WebRequest -Uri $oldUrl -OutFile $archive -MaximumRedirection 3 -TimeoutSec 60;break}catch{if($attempt -eq 3){throw};Start-Sleep -Seconds 2}
 }
 if((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $oldArchiveHash){throw 'OLD_ACCEPTED_ARCHIVE_CHECKSUM_MISMATCH'}
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $oldRoot=Join-Path $fixture 'accepted-rc21'
 New-Item -ItemType Directory $oldRoot | Out-Null
 $zip=[IO.Compression.ZipFile]::OpenRead($archive)
 try{
  $payloads=@('OracleProxy.exe','OracleProxy.Core.exe','OracleProxy.Guard.dll')
  $runnable=@($zip.Entries | Where-Object FullName -match '(?i)\.(exe|dll)$' | ForEach-Object FullName)
  if($runnable.Count -ne 3 -or @($runnable | Where-Object {$_ -cnotin $payloads}).Count -ne 0){throw 'OLD_ARCHIVE_RUNNABLE_ALLOWLIST_MISMATCH'}
  $entries=@($zip.Entries | Where-Object FullName -ceq 'BUILD.json')
  if($entries.Count -ne 1){throw 'OLD_ARCHIVE_BUILD_METADATA_REQUIRED'}
  $reader=[IO.StreamReader]::new($entries[0].Open())
  try{$oldMetadata=$reader.ReadToEnd() | ConvertFrom-Json}finally{$reader.Dispose()}
  if($oldMetadata.version -cne '0.3.0-rc21' -or $oldMetadata.source_revision -cne $oldRevision -or $oldMetadata.architecture -cne 'win-x64' -or $oldMetadata.real_oracle_acceptance_passed -ne $true){throw 'OLD_ACCEPTED_BUILD_IDENTITY_MISMATCH'}
  # The SDK used for this accepted release was 10.x; that does not make
  # its self-contained runtime 10.x. Verify the actual recorded runtime packs.
  if($oldMetadata.dotnet_sdk -cnotmatch '^\d+\.\d+\.\d+$'){throw 'OLD_ACCEPTED_RELEASE_SDK_IDENTITY_INVALID'}
  $netcore=@($oldMetadata.nuget_packages | Where-Object package -cmatch '^microsoft\.netcore\.app\.runtime\.win-x64/')
  $desktop=@($oldMetadata.nuget_packages | Where-Object package -cmatch '^microsoft\.windowsdesktop\.app\.runtime\.win-x64/')
  if($netcore.Count -ne 1 -or $desktop.Count -ne 1){throw 'OLD_RELEASE_REQUIRES_UNIQUE_CORE_AND_DESKTOP_RUNTIME_PACKS'}
  $coreVersion=$netcore[0].package.Split('/')[-1]
  $desktopVersion=$desktop[0].package.Split('/')[-1]
  if($coreVersion -cnotmatch '^8\.0\.\d+$' -or $desktopVersion -cne $coreVersion){throw 'OLD_RELEASE_SELF_CONTAINED_NET8_RUNTIME_PACKS_MISMATCH'}
  Write-Host ('PINNED_OLD_RELEASE_SDK='+$oldMetadata.dotnet_sdk+' SELF_CONTAINED_RUNTIME_PACKS='+$coreVersion)
  foreach($name in $payloads){
   $entry=@($zip.Entries | Where-Object FullName -ceq $name)
   if($entry.Count -ne 1 -or $entry[0].Length -le 0 -or $entry[0].Length -gt 300MB){throw 'OLD_ARCHIVE_EXACT_PAYLOAD_REQUIRED'}
   $path=Join-Path $oldRoot $name
   [IO.Compression.ZipFileExtensions]::ExtractToFile($entry[0],$path,$false)
   if((Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $oldMetadata.payload_sha256.$name){throw 'OLD_ACCEPTED_PAYLOAD_CHECKSUM_MISMATCH'}
  }
 }finally{$zip.Dispose()}
 $old=Join-Path $oldRoot 'OracleProxy.exe'
 $oldHash=(Get-FileHash $old -Algorithm SHA256).Hash
 Invoke-RuntimeProduct $old @('--self-test')
 Invoke-RuntimeProduct $new @('--self-test')
 if((Get-FileHash $new -Algorithm SHA256).Hash -ne $newHash){throw 'SELFTESTED_NET10_PAYLOAD_CHANGED_BEFORE_INSTALL'}
 Write-Host 'PINNED_NET8_RELEASE_AND_ACTUAL_NET10_SELFTEST_PAYLOADS=PASS'
 $owned=$true
 Invoke-RuntimeProduct $old @('--install',$owner)
 $oldPid=Get-VerifiedProductService $oldHash
 Stop-Service OracleProxyService
 Invoke-RuntimeWitness 'Seed'
 Start-Service OracleProxyService
 $oldPid=Get-VerifiedProductService $oldHash
 Assert-RuntimeStatus $oldPid 'PreferUdp' '0.3.0-rc21+' 'udp'
 Invoke-RuntimeWitness 'VerifyUdp'
 $cipherBefore=(Get-FileHash (Join-Path $stateRoot 'state.dpapi') -Algorithm SHA256).Hash
 Write-Host 'PINNED_NET8_RELEASE_SYSTEM_DPAPI_SYNTHETIC_KEY_AND_SCM_BOUND_PIPE=PASS'

 Invoke-RuntimeProduct $new @('--install',$owner)
 $newPid=Get-VerifiedProductService $newHash
 if($newPid -eq $oldPid){throw 'CROSS_RUNTIME_UPGRADE_DID_NOT_REPLACE_PROCESS'}
 Assert-RuntimeStatus $newPid 'Status' '0.3.0-rc22+' 'udp'
 if((Get-FileHash (Join-Path $stateRoot 'state.dpapi') -Algorithm SHA256).Hash -ne $cipherBefore){throw 'CROSS_RUNTIME_UPGRADE_REWROTE_EXISTING_DPAPI_STATE'}
 Invoke-RuntimeWitness 'VerifyUdp'
 Assert-RuntimeStatus $newPid 'PreferAuto' '0.3.0-rc22+' 'auto'
 if((Get-FileHash (Join-Path $stateRoot 'state.dpapi') -Algorithm SHA256).Hash -eq $cipherBefore){throw 'NET10_SERVICE_DID_NOT_SAVE_SYNTHETIC_PREFERENCE'}
 Invoke-RuntimeWitness 'VerifyAuto'
 Restart-Service OracleProxyService
 $newPid=Get-VerifiedProductService $newHash
 Assert-RuntimeStatus $newPid 'Status' '0.3.0-rc22+' 'auto'
 Invoke-RuntimeWitness 'VerifyAuto'
 Write-Host 'REAL_NET8_TO_NET10_SYSTEM_DPAPI_OWNER_PUBLIC_PRIVATE_KEY_AND_SCM_PIPE_UPGRADE=PASS'
 Invoke-RuntimeProduct $new @('--uninstall')
 if((Get-Service OracleProxyService -ErrorAction SilentlyContinue) -or (Test-Path $serviceRoot) -or (Test-Path $stateRoot)){throw 'CROSS_RUNTIME_UNINSTALL_NOT_COMPLETE'}
 $owned=$false
 Write-Host 'CROSS_RUNTIME_FIXTURE_SAFE_UNINSTALL_LEAVES_NO_SHARED_PRODUCT_STATE=PASS'
}finally{
 if($taskOwned){Stop-ScheduledTask $task -ErrorAction SilentlyContinue;Unregister-ScheduledTask $task -Confirm:$false -ErrorAction SilentlyContinue}
 if($owned){
  # No Login or Connect was sent. Only uninstall a service whose installed
  # image, owner and exact payload are from this fixture's checked inputs.
  $service=Get-CimInstance Win32_Service -Filter "Name='OracleProxyService'"
  $image='"'+(Join-Path $serviceRoot 'OracleProxy.Service.exe')+'" --service'
  $path=Join-Path $serviceRoot 'OracleProxy.Service.exe'
  if($service -and $service.PathName -ceq $image -and (Test-Path $path) -and (Test-Path (Join-Path $serviceRoot 'owner.sid')) -and (Get-Content -Raw (Join-Path $serviceRoot 'owner.sid')).Trim() -ceq $owner){
   $currentHash=(Get-FileHash $path -Algorithm SHA256).Hash
   if($currentHash -eq $newHash){Invoke-RuntimeProduct $new @('--uninstall')}
   elseif($currentHash -eq $oldHash){Invoke-RuntimeProduct $old @('--uninstall')}
   else{throw 'UNKNOWN_SERVICE_IMAGE_REFUSE_RUNTIME_FIXTURE_CLEANUP'}
  }
  if((Get-Service OracleProxyService -ErrorAction SilentlyContinue) -or (Test-Path $serviceRoot) -or (Test-Path $stateRoot)){throw 'RUNTIME_FIXTURE_CLEANUP_NOT_VERIFIED'}
 }
 if(Test-Path $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force}
}
