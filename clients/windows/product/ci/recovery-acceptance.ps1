$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_REF -ne 'refs/heads/main'){throw 'Main-only disposable Windows required'}
if(Get-Service OracleProxyService,OracleProxyCandidateFixture -ErrorAction SilentlyContinue){throw 'Preexisting service refused'}
if(Test-Path "$env:ProgramFiles/OracleProxy"){throw 'Preexisting product directory refused'}
$root=Join-Path $env:ProgramData 'OracleProxyCandidateFixture'
if(Test-Path $root){throw 'Preexisting fixture state refused'}
$exe=(Resolve-Path './dist/product/Proxy.exe').Path
$test=(Resolve-Path './dist/product-tests/OracleProxy.Product.Tests.exe').Path
if(Get-LocalUser OracleProxyOwner -ErrorAction SilentlyContinue){throw 'Preexisting fixture owner refused'}
$ownerPassword=ConvertTo-SecureString ('Proxy!'+[Guid]::NewGuid().ToString('N')) -AsPlainText -Force
$ownerUser=New-LocalUser -Name OracleProxyOwner -Password $ownerPassword -AccountNeverExpires -PasswordNeverExpires
$owner=$ownerUser.SID.Value
$ownerCredential=[Management.Automation.PSCredential]::new("$env:COMPUTERNAME\OracleProxyOwner",$ownerPassword)
New-Item -ItemType Directory $root | Out-Null
Set-Content "$root/authorized" 'DISPOSABLE_GITHUB_ONLY'
Set-Content "$root/owner-created" 'OracleProxyOwner'
$watch=New-ScheduledTaskAction -Execute $test -Argument '--watchdog'
Register-ScheduledTask -TaskName 'OracleProxyCandidateWatchdog' -Action $watch -User SYSTEM -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'OracleProxyCandidateWatchdog'
$install=Start-Process $exe -ArgumentList @('--install',$owner) -Wait -PassThru
if($install.ExitCode -ne 0){throw 'Recovery fixture installation failed'}
Stop-Service OracleProxyService
$normalOwner=Start-Process $test -ArgumentList '--owner-status' -Credential $ownerCredential -WorkingDirectory $env:WINDIR -LoadUserProfile -Wait -PassThru
if($normalOwner.ExitCode -ne 0 -or (Get-Service OracleProxyService).Status -ne 'Running'){throw 'Ordinary owner failed fixed service start without UAC'}
Write-Host 'REAL_NONADMIN_OWNER_STARTS_STOPPED_CONTROL_SERVICE_WITHOUT_UAC=PASS'
Stop-Service OracleProxyService
$sc=[Diagnostics.ProcessStartInfo]::new('sc.exe');$sc.UseShellExecute=$false
foreach($arg in @('create','OracleProxyCandidateFixture','binPath=',('"'+$test+'" --recovery-service'),'obj=','LocalSystem','start=','demand')){$sc.ArgumentList.Add($arg)}
$created=[Diagnostics.Process]::Start($sc);$created.WaitForExit()
if($created.ExitCode -ne 0){throw 'Recovery fixture service create failed'}
New-ItemProperty 'HKLM:/SYSTEM/CurrentControlSet/Services/OracleProxyCandidateFixture' -Name Environment -PropertyType MultiString -Value @("DOTNET_BUNDLE_EXTRACT_BASE_DIR=$env:ProgramData\OracleProxy\bundle") -Force | Out-Null
Start-Service OracleProxyCandidateFixture
$fixturePid=(Get-CimInstance Win32_Service -Filter "Name='OracleProxyCandidateFixture'").ProcessId
$result=Join-Path $root 'result.txt'
for($i=0;$i -lt 150 -and !(Test-Path $result);$i++){Start-Sleep -Seconds 1}
if(!(Test-Path $result)){throw 'Focused recovery fixture timed out; SYSTEM watchdog retained'}
$body=Get-Content -Raw $result
Write-Host $body
if($body -notmatch 'RESULT=PASS' -or $body -notmatch 'REAL_UAC_RECOVERY_TRANSACTION_REMOVES_DORMANT_ORPHAN_AND_RESTARTS_AUTHENTICATED_CONTROL_SERVICE=PASS'){throw 'Real SYSTEM recovery regression failed'}
if($fixturePid){Wait-Process -Id $fixturePid -Timeout 10 -ErrorAction SilentlyContinue}
$remove=Start-Process $exe -ArgumentList '--uninstall' -Wait -PassThru
if($remove.ExitCode -ne 0){throw 'Focused recovery fixture uninstall failed'}
Write-Host 'FOCUSED_REAL_SYSTEM_DORMANT_STARTUP_AND_UAC_RECOVERY=PASS'
