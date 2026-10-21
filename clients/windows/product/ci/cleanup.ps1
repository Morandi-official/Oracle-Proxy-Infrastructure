$ErrorActionPreference='Continue'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted Windows required'}
$test=Join-Path $PWD 'dist/product-tests/OracleProxy.Product.Tests.exe'
$root=Join-Path $env:ProgramData 'OracleProxyCandidateFixture'
if((Test-Path $test) -and (Test-Path "$root/authorized") -and (Test-Path "$env:ProgramFiles/OracleProxy/OracleProxy.Guard.dll")){
  $action=New-ScheduledTaskAction -Execute $test -Argument '--rescue'
  Register-ScheduledTask -TaskName 'OracleProxyCandidateRescue' -Action $action -User SYSTEM -RunLevel Highest -Force | Out-Null
  Remove-Item "$root/rescued" -ErrorAction SilentlyContinue
  Start-ScheduledTask -TaskName 'OracleProxyCandidateRescue'
  for($i=0;$i -lt 30 -and !(Test-Path "$root/rescued");$i++){Start-Sleep -Seconds 1}
  if(!(Test-Path "$root/rescued")){throw 'Immediate rescue not verified; keep SYSTEM watchdog active'}
}
foreach($name in @('OracleProxyCandidateFixture','OracleProxyService','OracleProxyRecovery')){
  $service=Get-Service $name -ErrorAction SilentlyContinue
  if($service){Stop-Service $name -Force -ErrorAction SilentlyContinue; & sc.exe delete $name | Out-Null}
}
foreach($task in @('OracleProxyCandidateWatchdog','OracleProxyCandidateRescue','OracleProxyCandidateVerifyRecovery')){Stop-ScheduledTask $task -ErrorAction SilentlyContinue;Unregister-ScheduledTask $task -Confirm:$false -ErrorAction SilentlyContinue}
if(Test-Path "$root/owner-created"){Remove-LocalUser OracleProxyOwner -ErrorAction SilentlyContinue;Remove-Item "$root/owner-created" -ErrorAction SilentlyContinue}
exit 0
