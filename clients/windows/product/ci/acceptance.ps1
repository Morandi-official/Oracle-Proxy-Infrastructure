$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted Windows required'}
if(Get-Service OracleProxyService,OracleProxyCandidateFixture -ErrorAction SilentlyContinue){throw 'Preexisting service refused'}
if(Test-Path "$env:ProgramFiles/OracleProxy"){throw 'Preexisting install refused'}
$exe=(Resolve-Path './dist/product/OracleProxy.exe').Path
$test=(Resolve-Path './dist/product-tests/OracleProxy.Product.Tests.exe').Path
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
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
$other='OracleProxyOther'
$fixturePassword=ConvertTo-SecureString ('OracleProxy!'+[Guid]::NewGuid().ToString('N')) -AsPlainText -Force
try{
  New-LocalUser -Name $other -Password $fixturePassword -AccountNeverExpires -PasswordNeverExpires | Out-Null
  $credential=[Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$other",$fixturePassword)
  $denial=Start-Process $test -ArgumentList '--nonowner-pipe' -Credential $credential -WorkingDirectory $env:WINDIR -LoadUserProfile -Wait -PassThru
  if($denial.ExitCode -ne 0){throw 'Actual non-owner pipe denial not established'}
  Write-Host 'REAL_NONADMIN_NONOWNER_WINDOWS_IDENTITY_PIPE_ACCESS_DENIED=PASS'
}finally{Remove-LocalUser $other -ErrorAction SilentlyContinue}
$root=Join-Path $env:ProgramData 'OracleProxyCandidateFixture'
New-Item -ItemType Directory -Path $root | Out-Null
Set-Content (Join-Path $root 'authorized') 'DISPOSABLE_GITHUB_ONLY'
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
# The runner account is an Administrator, but is not LocalSystem; CurrentUser
# DPAPI ciphertext created inside the real SCM process must remain unreadable.
Add-Type -AssemblyName System.Security
$denied=$false
try{[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes("$env:ProgramData/OracleProxy/state.dpapi"),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser) | Out-Null}catch{$denied=$true}
if(!$denied){throw 'Runner identity decrypted SYSTEM key storage'}
Write-Host 'REAL_OTHER_WINDOWS_IDENTITY_CANNOT_UNSEAL_SYSTEM_DPAPI=PASS'
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
if(Test-Path "$env:ProgramData/OracleProxy/state.dpapi"){throw 'Secret state survived uninstall'}
Write-Host 'REAL_PRODUCT_SETUP_AUTHENTICATED_IPC_AND_UNINSTALL=PASS'
