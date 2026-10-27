$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'official-download.ps1')
. (Join-Path $PSScriptRoot 'uu-network-fixture.ps1')
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted Windows required'}
if(Get-Service OracleProxyService,OracleProxyCandidateFixture -ErrorAction SilentlyContinue){throw 'Preexisting service refused'}
if(Test-Path "$env:ProgramFiles/OracleProxy"){throw 'Preexisting install refused'}
$exe=(Resolve-Path './dist/product/OracleProxy.exe').Path
$test=(Resolve-Path './dist/product-tests/OracleProxy.Product.Tests.exe').Path
& $test --udp-loss-self-test
if($LASTEXITCODE -ne 0){throw 'Disposable packet-layer UDP fault session failed'}
& $test --probe-self-test
if($LASTEXITCODE -ne 0){throw 'Progress-aware exit deadline or exact exit verification failed'}
if(Get-LocalUser OracleProxyOwner,OracleProxyOther -ErrorAction SilentlyContinue){throw 'Preexisting fixture user refused'}
$root=Join-Path $env:ProgramData 'OracleProxyCandidateFixture'
if(Test-Path $root){throw 'Preexisting fixture state refused'}
New-Item -ItemType Directory -Path $root | Out-Null
Set-Content "$root/authorized" 'DISPOSABLE_GITHUB_ONLY'
$ownerPassword=ConvertTo-SecureString ('OracleProxy!'+[Guid]::NewGuid().ToString('N')) -AsPlainText -Force
$ownerUser=New-LocalUser -Name OracleProxyOwner -Password $ownerPassword -AccountNeverExpires -PasswordNeverExpires
Set-Content "$root/owner-created" 'OracleProxyOwner'
$owner=$ownerUser.SID.Value
$ownerCredential=[Management.Automation.PSCredential]::new("$env:COMPUTERNAME\OracleProxyOwner",$ownerPassword)
$install=Start-Process $exe -ArgumentList @('--install',$owner) -Wait -PassThru
if($install.ExitCode -ne 0){if(Test-Path "$env:ProgramFiles/OracleProxy/diagnostics.json"){Get-Content "$env:ProgramFiles/OracleProxy/diagnostics.json"};Get-Service OracleProxyService -ErrorAction SilentlyContinue | Select-Object Status,Name;throw 'Actual product setup failed'}
& $test --owner-status
if($LASTEXITCODE -ne 0){throw 'SCM-authenticated owner pipe failed'}
& $test --native-denial
if($LASTEXITCODE -ne 0){throw 'Native policy mutation admitted non-SYSTEM caller'}
& $test --ui-self-test
if($LASTEXITCODE -ne 0){throw 'Client usage progress/staleness render failed'}
& $test --malformed-pipe
if($LASTEXITCODE -ne 0){throw 'Malformed/arbitrary pipe requests were not rejected'}
Stop-Service OracleProxyService
& $test --rogue-pipe
if($LASTEXITCODE -ne 0){throw 'Client sent credentials to a rogue pipe'}
Start-Service OracleProxyService
Write-Host 'REAL_SCM_BOUND_PIPE_REJECTS_ROGUE_SERVER_DUPLICATE_FIELDS_AND_ARBITRARY_PATHS=PASS'
$normalOwner=Start-Process $test -ArgumentList '--owner-control' -Credential $ownerCredential -WorkingDirectory $env:WINDIR -LoadUserProfile -Wait -PassThru
if($normalOwner.ExitCode -ne 0){throw 'Actual ordinary owner could not use fixed SYSTEM control commands'}
Write-Host 'REAL_NONADMIN_OWNER_USES_FIXED_SYSTEM_COMMANDS_WITHOUT_UAC=PASS'
Write-Host 'REAL_NONADMIN_OWNER_CANNOT_READ_SYSTEM_BUNDLE_CACHE=PASS' 
$other='OracleProxyOther'
$fixturePassword=ConvertTo-SecureString ('OracleProxy!'+[Guid]::NewGuid().ToString('N')) -AsPlainText -Force
try{
  New-LocalUser -Name $other -Password $fixturePassword -AccountNeverExpires -PasswordNeverExpires | Out-Null
  $credential=[Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$other",$fixturePassword)
  $denial=Start-Process $test -ArgumentList '--nonowner-pipe' -Credential $credential -WorkingDirectory $env:WINDIR -LoadUserProfile -Wait -PassThru
  if($denial.ExitCode -ne 0){throw 'Actual non-owner pipe denial not established'}
  Write-Host 'REAL_NONADMIN_NONOWNER_WINDOWS_IDENTITY_PIPE_ACCESS_DENIED=PASS'
}finally{Remove-LocalUser $other -ErrorAction SilentlyContinue}
$uuFixture=Join-Path $env:ProgramFiles 'OracleProxy/GameViewer-Trust-Fixture'
New-Item -ItemType Directory $uuFixture | Out-Null
$officialInstaller=Join-Path $uuFixture 'GameViewer.exe'
try{
  Get-OfficialFile -Uri 'https://a56.gdl.netease.com/UURemote_Setup_4.39.2.1561_0904121034_gwqd.exe' -OutFile $officialInstaller -SHA256 'CF06187BE7B1382EAB9D53AFA129E4DC0DC07B0C7526D1E7A849475E0CA046F5'
  if((Get-FileHash $officialInstaller -Algorithm SHA256).Hash -ne 'CF06187BE7B1382EAB9D53AFA129E4DC0DC07B0C7526D1E7A849475E0CA046F5'){throw 'Official UU fixture checksum mismatch'}
  if((Get-AuthenticodeSignature $officialInstaller).Status -ne 'Valid'){throw 'Official UU fixture signature invalid'}
  & $test --uu-trust-signed
  if($LASTEXITCODE -ne 0){throw 'Actual signed NetEase file/ACL trust boundary failed'}
}finally{if(Test-Path $uuFixture){Remove-Item -Recurse -Force $uuFixture}}
New-CIUuNetworkFixture
$action=New-ScheduledTaskAction -Execute $test -Argument '--watchdog'
Register-ScheduledTask -TaskName 'OracleProxyCandidateWatchdog' -Action $action -User SYSTEM -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'OracleProxyCandidateWatchdog'
$image='"'+$test+'" --service'
$sc=[Diagnostics.ProcessStartInfo]::new('sc.exe');$sc.UseShellExecute=$false
foreach($arg in @('create','OracleProxyCandidateFixture','binPath=',$image,'obj=','LocalSystem','start=','demand')){$sc.ArgumentList.Add($arg)}
$created=[Diagnostics.Process]::Start($sc);$created.WaitForExit()
$LASTEXITCODE=$created.ExitCode
if($LASTEXITCODE -ne 0){throw 'Fixture service create failed'}
& sc.exe start OracleProxyCandidateFixture | Out-Null
if($LASTEXITCODE -ne 0){throw 'Fixture service start failed'}
$result=Join-Path $root 'result.txt'
for($i=0;$i -lt 100 -and !(Test-Path $result);$i++){Start-Sleep -Seconds 1}
if(!(Test-Path $result)){throw 'Fixture timed out; SYSTEM watchdog retains recovery'}
$body=Get-Content -Raw $result
Write-Host $body
if($body -notmatch 'RESULT=PASS'){throw 'Actual WFP/WireGuard fixture failed'}
Remove-CIUuNetworkFixture
# The runner account is an Administrator, but is not LocalSystem; CurrentUser
# DPAPI ciphertext created inside the real SCM process must remain unreadable.
Add-Type -AssemblyName System.Security
$denied=$false
try{[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes("$env:ProgramData/OracleProxy/state.dpapi"),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser) | Out-Null}catch{$denied=$true}
if(!$denied){throw 'Runner identity decrypted SYSTEM key storage'}
Write-Host 'REAL_OTHER_WINDOWS_IDENTITY_CANNOT_UNSEAL_SYSTEM_DPAPI=PASS'
$serviceEnvironment=(Get-ItemProperty 'HKLM:/SYSTEM/CurrentControlSet/Services/OracleProxyService').Environment
if($serviceEnvironment -notcontains "DOTNET_BUNDLE_EXTRACT_BASE_DIR=$env:ProgramData\OracleProxy\bundle"){throw 'SYSTEM runtime extraction is not pinned to protected product state'}
Stop-Service OracleProxyService
$stateBackup="$env:ProgramData/OracleProxy/state.recovery-$([Guid]::NewGuid().ToString('N')).dpapi"
Move-Item "$env:ProgramData/OracleProxy/state.dpapi" $stateBackup
Start-Service OracleProxyService
& $test --owner-protected
if($LASTEXITCODE -ne 0){throw 'Missing encrypted state silently disabled persistent protection'}
Write-Host 'REAL_MISSING_ENCRYPTED_STATE_STARTUP_RETAINS_PERSISTENT_GUARD=PASS'
Stop-Service OracleProxyService
Move-Item $stateBackup "$env:ProgramData/OracleProxy/state.dpapi" -Force
function Show-RecoveryFixture([string]$Stage){
 try{
  $adapters=@(Get-NetAdapter -Name OracleProxy -IncludeHidden -ErrorAction SilentlyContinue | Select-Object Name,Status,ifIndex)
  $cores=@(Get-CimInstance Win32_Process -Filter "Name='OracleProxy.Core.exe'" -Property ProcessId,ExecutablePath)
  $corePath=Join-Path $env:ProgramFiles 'OracleProxy\OracleProxy.Core.exe'
  $owned=@($cores | Where-Object ExecutablePath -eq $corePath).Count
  $unknown=@($cores | Where-Object {-not $_.ExecutablePath}).Count
  $services=@(Get-CimInstance Win32_Service -Filter "Name='OracleProxyService' OR Name='OracleProxyRecovery'" -Property Name,State | Select-Object Name,State)
  Write-Host ('RECOVERY_FIXTURE_'+$Stage+'='+(@{adapters=$adapters;product_core_count=$owned;unknown_path_core_count=$unknown;scm=$services} | ConvertTo-Json -Depth 4 -Compress))
  & $test --tun-presence-diagnostic
  if($LASTEXITCODE -ne 0){Write-Host ('RECOVERY_DOTNET_TUN_'+$Stage+'=DIAGNOSTIC_UNAVAILABLE')}
 }catch{Write-Host ('RECOVERY_FIXTURE_'+$Stage+'=DIAGNOSTIC_UNAVAILABLE')}
}
Show-RecoveryFixture 'BEFORE'
$recovery=Start-Process $exe -ArgumentList '--recover' -Wait -PassThru
if($recovery.ExitCode -ne 0){Show-RecoveryFixture 'FAILED';if(Test-Path "$env:ProgramFiles/OracleProxy/diagnostics.json"){Get-Content "$env:ProgramFiles/OracleProxy/diagnostics.json"};throw 'Public fixed-action SYSTEM recovery failed'}
$verification=New-ScheduledTaskAction -Execute $test -Argument '--verify-recovered'
Register-ScheduledTask -TaskName 'OracleProxyCandidateVerifyRecovery' -Action $verification -User SYSTEM -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'OracleProxyCandidateVerifyRecovery'
for($i=0;$i -lt 30 -and !(Test-Path "$root/recovery-verified");$i++){Start-Sleep -Milliseconds 250}
if(!(Test-Path "$root/recovery-verified") -or (Get-Content -Raw "$root/recovery-verified") -ne 'KEY_AND_SAFE_OFF_PRESERVED'){throw 'Recovery lost encrypted key or failed to commit safe Off'}
Write-Host 'REAL_PRODUCT_UAC_SYSTEM_RECOVERY_PRESERVES_KEY_AND_COMMITS_SAFE_OFF=PASS' 
Write-Host 'REAL_FIXED_UAC_RECOVERY_REMOVES_RECEIPT_OWNED_KERNEL_ORPHAN_BEFORE_SAFE_OFF=PASS'
Copy-Item "$env:ProgramData/OracleProxy/state.dpapi" "$env:ProgramData/OracleProxy/state.recovery-$([Guid]::NewGuid().ToString('N')).dpapi"
Remove-Item "$env:ProgramData/OracleProxy/state.dpapi"
$oldHash=(Get-FileHash "$env:ProgramFiles/OracleProxy/OracleProxy.Service.exe").Hash
$bad=(Resolve-Path './dist/bad-upgrade/OracleProxy.exe').Path
$upgrade=Start-Process $bad -ArgumentList @('--install',$owner) -Wait -PassThru
if($upgrade.ExitCode -eq 0){throw 'Deliberate bad startup unexpectedly installed'}
if((Get-FileHash "$env:ProgramFiles/OracleProxy/OracleProxy.Service.exe").Hash -ne $oldHash){throw 'Automatic rollback did not restore the previous executable'}
& $test --owner-status
if($LASTEXITCODE -ne 0){throw 'Previous service did not recover after rollback'}
Write-Host 'REAL_BAD_UPGRADE_AUTOMATIC_BINARY_AND_SERVICE_ROLLBACK=PASS' 
$remove=Start-Process $exe -ArgumentList '--uninstall' -Wait -PassThru
if($remove.ExitCode -ne 0){throw 'Actual product uninstall failed'}
if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){throw 'Service survived uninstall'}
if(Test-Path "$env:ProgramData/OracleProxy"){throw 'Product key/runtime state survived uninstall'}
Write-Host 'REAL_PRODUCT_SETUP_AUTHENTICATED_IPC_AND_UNINSTALL=PASS'
