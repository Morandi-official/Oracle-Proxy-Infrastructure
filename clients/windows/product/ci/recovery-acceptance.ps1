param([switch]$ParkOnly)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted Windows required'}
if($ParkOnly){
 if($env:GITHUB_EVENT_NAME -ne 'pull_request' -or $env:GITHUB_REF -notmatch '^refs/pull/[0-9]+/merge$'){throw 'Offline holder test requires a pull request'}
}else{
 if($env:GITHUB_REF -ne 'refs/heads/main'){throw 'Main-only recovery fixture required'}
}
if(Get-Service OracleProxyService,OracleProxyCandidateFixture -ErrorAction SilentlyContinue){throw 'Preexisting service refused'}
if(Test-Path "$env:ProgramFiles/OracleProxy"){throw 'Preexisting product directory refused'}
$root=Join-Path $env:ProgramData 'OracleProxyCandidateFixture'
if(Test-Path $root){throw 'Preexisting fixture state refused'}
$exe=(Resolve-Path './dist/product/Proxy.exe').Path
$test=(Resolve-Path './dist/product-tests/OracleProxy.Product.Tests.exe').Path
New-Item -ItemType Directory $root | Out-Null
Set-Content "$root/authorized" 'DISPOSABLE_GITHUB_ONLY'
if($ParkOnly){
 . (Join-Path $PSScriptRoot 'adapter-binding-witness.ps1')
 $otherBindings=@(Get-OtherAdapterBindingState)
 $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}else{
 if(Get-LocalUser OracleProxyOwner -ErrorAction SilentlyContinue){throw 'Preexisting fixture owner refused'}
 $ownerPassword=ConvertTo-SecureString ('Proxy!'+[Guid]::NewGuid().ToString('N')) -AsPlainText -Force
 $ownerUser=New-LocalUser -Name OracleProxyOwner -Password $ownerPassword -AccountNeverExpires -PasswordNeverExpires
 $owner=$ownerUser.SID.Value
 $ownerCredential=[Management.Automation.PSCredential]::new("$env:COMPUTERNAME\OracleProxyOwner",$ownerPassword)
 Set-Content "$root/owner-created" 'OracleProxyOwner'
}
$watch=New-ScheduledTaskAction -Execute $test -Argument '--watchdog'
Register-ScheduledTask -TaskName 'OracleProxyCandidateWatchdog' -Action $watch -User SYSTEM -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'OracleProxyCandidateWatchdog'
$install=Start-Process $exe -ArgumentList @('--install',$owner) -Wait -PassThru
if($install.ExitCode -ne 0){throw 'Recovery fixture installation failed'}
Stop-Service OracleProxyService
if(!$ParkOnly){
 $normalOwner=Start-Process $test -ArgumentList '--owner-status' -Credential $ownerCredential -WorkingDirectory $env:WINDIR -LoadUserProfile -Wait -PassThru
 if($normalOwner.ExitCode -ne 0 -or (Get-Service OracleProxyService).Status -ne 'Running'){throw 'Ordinary owner failed fixed service start without UAC'}
 Write-Host 'REAL_NONADMIN_OWNER_STARTS_STOPPED_CONTROL_SERVICE_WITHOUT_UAC=PASS'
 Stop-Service OracleProxyService
}
$fixtureMode=if($ParkOnly){'--park-service'}else{'--recovery-service'}
$sc=[Diagnostics.ProcessStartInfo]::new('sc.exe');$sc.UseShellExecute=$false
foreach($arg in @('create','OracleProxyCandidateFixture','binPath=',('"'+$test+'" '+$fixtureMode),'obj=','LocalSystem','start=','demand')){$sc.ArgumentList.Add($arg)}
$created=[Diagnostics.Process]::Start($sc);$created.WaitForExit()
if($created.ExitCode -ne 0){throw 'Recovery fixture service create failed'}
New-ItemProperty 'HKLM:/SYSTEM/CurrentControlSet/Services/OracleProxyCandidateFixture' -Name Environment -PropertyType MultiString -Value @("DOTNET_BUNDLE_EXTRACT_BASE_DIR=$env:ProgramData\OracleProxy\bundle") -Force | Out-Null
Start-Service OracleProxyCandidateFixture
$fixturePid=(Get-CimInstance Win32_Service -Filter "Name='OracleProxyCandidateFixture'").ProcessId
$result=Join-Path $root 'result.txt'
$observed=$false
for($i=0;$i -lt 150 -and !(Test-Path $result);$i++){
 if($ParkOnly -and !$observed -and (Test-Path -LiteralPath "$root/park-ready")){
  try{
   $luid=[uint64](Get-Content -LiteralPath "$root/park-ready" -Raw)
   Assert-OwnedIpBindings $luid $false
   $registryKey=Get-Item -LiteralPath 'HKLM:/SYSTEM/CurrentControlSet/Services/OracleProxyService' -ErrorAction Stop
   $saved=@($registryKey.GetValue('OracleProxyOriginalWintunBindings'))
   if($saved.Count -lt 7 -or $saved[0] -ne 'OracleProxy-Bindings-1' -or $saved[1] -ne $luid.ToString()){
    throw 'PARKED_BINDING_RECEIPT_NOT_DURABLE'
   }
   Write-Host 'ACTUAL_PARKED_BINDINGS_HAVE_MATCHING_DURABLE_RECEIPT=PASS' 
   Assert-OtherAdapterBindingState $otherBindings
   $observed=$true
  }finally{Set-Content "$root/park-observed" 'DONE'}
 }
 Start-Sleep -Seconds 1
}
if(!(Test-Path $result)){throw 'Focused recovery fixture timed out; SYSTEM watchdog retained'}
$body=Get-Content -Raw $result
Write-Host $body
$expected=if($ParkOnly){'REAL_SYSTEM_PARKED_HOLDER_EXITED_AND_ADAPTER_REMOVED=PASS'}else{'REAL_UAC_RECOVERY_TRANSACTION_REMOVES_DORMANT_ORPHAN_AND_RESTARTS_AUTHENTICATED_CONTROL_SERVICE=PASS'}
if($body -notmatch 'RESULT=PASS' -or !$body.Contains($expected)){throw 'Real SYSTEM fixture failed'}
if($fixturePid){Wait-Process -Id $fixturePid -Timeout 10 -ErrorAction SilentlyContinue}
if($ParkOnly){
 $registryKey=Get-Item -LiteralPath 'HKLM:/SYSTEM/CurrentControlSet/Services/OracleProxyService' -ErrorAction Stop
 if($null -ne $registryKey.GetValue('OracleProxyOriginalWintunBindings')){throw 'ORIGINAL_BINDING_RECEIPT_STILL_PRESENT'}
 Write-Host 'ACTUAL_RESTORED_BINDING_RECEIPT_RETIRED=PASS'
}
$remove=Start-Process $exe -ArgumentList '--uninstall' -Wait -PassThru
if($remove.ExitCode -ne 0){throw 'Focused recovery fixture uninstall failed'}
if($ParkOnly){
 if(!$observed -or !$body.Contains('REAL_SYSTEM_CRASHED_PARKED_HOLDER_REMOVED_BY_ORDINARY_RECOVERY=PASS')){throw 'Parked crash recovery was not observed'}
 Assert-OtherAdapterBindingState $otherBindings
 # This test created the fixture service, watchdog and empty state root.
 # Retire them after the verified uninstall so the next isolated test starts clean.
 & sc.exe delete OracleProxyCandidateFixture | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Parked fixture service removal failed'}
 Stop-ScheduledTask -TaskName OracleProxyCandidateWatchdog -ErrorAction SilentlyContinue
 Unregister-ScheduledTask -TaskName OracleProxyCandidateWatchdog -Confirm:$false
 Remove-Item -LiteralPath $root -Recurse -Force
 Write-Host 'REAL_OFFLINE_EMPTY_ADAPTER_HOLDER=PASS'
}
else{Write-Host 'FOCUSED_REAL_SYSTEM_DORMANT_STARTUP_AND_UAC_RECOVERY=PASS'}
