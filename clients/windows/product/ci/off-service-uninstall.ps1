$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted Windows required'}
if(Get-Service OracleProxyService,OracleProxyRecovery -ErrorAction SilentlyContinue){throw 'Preexisting services refused'}
$installed=Join-Path $env:ProgramFiles 'OracleProxy'
$state=Join-Path $env:ProgramData 'OracleProxy'
if((Test-Path $installed) -or (Test-Path $state)){throw 'Preexisting owned directories refused'}
$exe=(Resolve-Path './dist/off-service-fixture/Proxy.exe').Path
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function Invoke-OffStep([string[]]$Arguments){
  $process=Start-Process $exe -ArgumentList $Arguments -Wait -PassThru
  if($process.ExitCode -ne 0){
    $diag=Join-Path $installed 'diagnostics.json'
    if(Test-Path $diag){Get-Content -LiteralPath $diag -Raw}
    throw "OFF_FIXTURE_STEP_FAILED=$($Arguments[0]);EXIT=$($process.ExitCode)"
  }
}
try {
  foreach($cycle in 1..3){
    Invoke-OffStep -Arguments @('--install',$owner)
    # Actual no-account GUI owner: kill it immediately before uninstall so its
    # independent lifetime cleanup can race both pipe admission and SCM Stop.
    $gui=Start-Process $exe -PassThru
    try {
      if(!$gui.WaitForInputIdle(10000)){throw 'OWNED_GUI_DID_NOT_START'}
      Start-Sleep -Seconds 1
      $gui.Kill();$gui.WaitForExit()
      Invoke-OffStep -Arguments @('--uninstall')
    } finally {if(!$gui.HasExited){$gui.Kill();$gui.WaitForExit()};$gui.Dispose()}
    for($i=0;$i -lt 20;$i++){
      $service=Get-Service OracleProxyService -ErrorAction SilentlyContinue
      if(!$service){break};$service.Dispose();Start-Sleep -Milliseconds 100
    }
    if($service -or (Test-Path $installed) -or (Test-Path $state)){throw 'OWNED_OFF_FIXTURE_CLEANUP_NOT_COMPLETE'}
    Write-Host "REAL_OFF_SELF_STOP_UNINSTALL_CYCLE_${cycle}=PASS"
  }
} finally {
  # Same fixed recovery/uninstall entry points; no global firewall or route reset.
  if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){
    Start-Process $exe -ArgumentList '--recover' -Wait | Out-Null
    Start-Process $exe -ArgumentList '--uninstall' -Wait | Out-Null
  }
}
