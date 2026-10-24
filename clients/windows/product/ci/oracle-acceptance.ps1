$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'uu-network-fixture.ps1')
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_REF -ne 'refs/heads/main'){throw 'Main-only disposable Oracle client acceptance required'}
if(!$env:ORACLE_CLIENT_ACCEPTANCE_USERNAME -or !$env:ORACLE_CLIENT_ACCEPTANCE_PASSWORD){throw 'Dedicated client Environment credentials are missing'}
if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){throw 'Preexisting product service refused'}
if(Test-Path "$env:ProgramFiles/OracleProxy"){throw 'Preexisting product directory refused'}
$exe=(Resolve-Path './dist/product/OracleProxy.exe').Path
$test=(Resolve-Path './dist/product-tests/OracleProxy.Product.Tests.exe').Path
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Join-Path $env:ProgramData 'OracleProxyCandidateFixture'
New-Item -ItemType Directory -Force $root | Out-Null
Set-Content "$root/authorized" 'DISPOSABLE_GITHUB_ONLY'
$action=New-ScheduledTaskAction -Execute $test -Argument '--oracle-watchdog'
Register-ScheduledTask -TaskName 'OracleProxyCandidateWatchdog' -Action $action -User SYSTEM -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'OracleProxyCandidateWatchdog'
try{
  $setup=Start-Process $exe -ArgumentList @('--install',$owner) -Wait -PassThru
  if($setup.ExitCode -ne 0){throw 'Oracle acceptance setup failed'}
  New-CIUuNetworkFixture
  & $test --oracle-client
  if($LASTEXITCODE -ne 0){throw 'Real Oracle acceptance failed; no credential or private-key logs are exported'}
  Remove-CIUuNetworkFixture
  $remove=Start-Process $exe -ArgumentList '--uninstall' -Wait -PassThru
  if($remove.ExitCode -ne 0){throw 'Post-acceptance uninstall failed'}
}finally{
  Remove-Item Env:ORACLE_CLIENT_ACCEPTANCE_USERNAME,Env:ORACLE_CLIENT_ACCEPTANCE_PASSWORD -ErrorAction SilentlyContinue
  if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){
    $recover=Start-Process $exe -ArgumentList '--recover' -Wait -PassThru
    if($recover.ExitCode -eq 0){Start-Process $exe -ArgumentList '--uninstall' -Wait | Out-Null}
  }
  ./clients/windows/product/ci/cleanup.ps1
}
