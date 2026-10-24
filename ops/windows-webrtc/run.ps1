$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_REF -ne 'refs/heads/main' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable main only'}
if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){throw 'Preexisting service refused'}
if(Test-Path "$env:ProgramFiles/OracleProxy"){throw 'Preexisting install refused'}
$exe=(Resolve-Path './dist/product/OracleProxy.exe').Path
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
try{
 $setup=Start-Process $exe -ArgumentList @('--install',$owner) -Wait -PassThru
 if($setup.ExitCode -ne 0){throw 'Setup failed'}
 & ./dist/webrtc-tests/OracleProxy.WebRtc.Acceptance.exe
 if($LASTEXITCODE -ne 0){throw 'Browser WebRTC acceptance failed'}
}finally{
 Remove-Item Env:ORACLE_CLIENT_ACCEPTANCE_USERNAME,Env:ORACLE_CLIENT_ACCEPTANCE_PASSWORD -ErrorAction SilentlyContinue
 if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){
  $recovery=Start-Process $exe -ArgumentList '--recover' -Wait -PassThru
  if($recovery.ExitCode -ne 0){throw 'Safe recovery failed'}
  $remove=Start-Process $exe -ArgumentList '--uninstall' -Wait -PassThru
  if($remove.ExitCode -ne 0){throw 'Safe uninstall failed'}
 }
}
