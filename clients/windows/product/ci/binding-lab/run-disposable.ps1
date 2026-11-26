$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_EVENT_NAME -ne 'pull_request' -or $env:GITHUB_REF -notmatch '^refs/pull/[0-9]+/merge$'){throw 'Disposable hosted PR runner required'}
$fixture=Join-Path $env:ProgramData OracleProxyCandidateFixture
$task='OracleProxyDisposableBindingLab'
if((Test-Path $fixture) -or (Test-Path "$env:ProgramFiles/OracleProxy") -or (Get-Service OracleProxyService -ErrorAction Ignore) -or
   (Get-ScheduledTask $task -ErrorAction Ignore) -or (Get-NetAdapter -Name 'OracleProxy' -IncludeHidden -ErrorAction Ignore)){throw 'Preexisting host state refused'}
$null=New-Item -ItemType Directory -Path $fixture
try{
    & icacls.exe $fixture '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
    if($LASTEXITCODE){throw 'SYSTEM fixture ACL not secured'}
    Set-Content "$fixture/authorized" 'DISPOSABLE_GITHUB_ONLY' -Encoding ascii
    Copy-Item "$env:RUNNER_TEMP/binding-lab.test.exe" "$fixture/binding-lab.test.exe"
    $body=@'
$env:ORACLE_BINDING_LAB='DISPOSABLE_WINDOWS_RUNNER'
$fixture=Join-Path $env:ProgramData OracleProxyCandidateFixture
& "$fixture/binding-lab.test.exe" -test.run '^TestDisposableOracleBindings$' -test.count=2 -test.timeout=180s -test.v *> "$fixture/binding.log"
Set-Content "$fixture/result" $LASTEXITCODE
'@
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $action=New-ScheduledTaskAction -Execute "$env:SystemRoot/System32/WindowsPowerShell/v1.0/powershell.exe" -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
    Register-ScheduledTask -TaskName $task -User SYSTEM -RunLevel Highest -Action $action | Out-Null
    Start-ScheduledTask $task
    for($i=0;$i -lt 210 -and !(Test-Path "$fixture/result");$i++){Start-Sleep -Seconds 1}
    if(!(Test-Path "$fixture/result")){throw 'Disposable child deadline expired'}
    Get-Content "$fixture/binding.log"
    if((Get-Content "$fixture/result") -ne '0'){throw 'Protocol binding measurement failed'}
}finally{
    if(Get-ScheduledTask $task -ErrorAction Ignore){Stop-ScheduledTask $task -ErrorAction Ignore;Unregister-ScheduledTask $task -Confirm:$false}
    if(Get-NetAdapter -Name OracleProxy -IncludeHidden -ErrorAction Ignore){throw 'Temporary adapter persisted'}
    Remove-Item $fixture -Recurse -Force
}
