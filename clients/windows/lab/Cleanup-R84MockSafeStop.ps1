# Always-run cleanup ONLY for CI-created no-network mock and exact task.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R84 -ne 'CI_ONLY') {
    throw 'R84_REFUSED: outside disposable CI'
}
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$marker=Join-Path $root '.r81-owned'
$exe=Join-Path $root 'r84-mock.exe'
$service='WireGuardTunnel$lab-field'
$taskName='OracleProxy-R84-CI-MockSafeStop'
$t=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
$s=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
if (!$t -and !$s -and !(Test-Path -LiteralPath $exe)) {
    Write-Host 'R84_MOCK_SERVICE_AND_TIMER_ABSENT_PASS'
    exit 0
}
if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne
        'CI_R81_ONLY_DISPOSABLE_GITHUB_VM') {
    throw 'R84_REFUSED: cannot prove exact runner-owned staging'
}
$expected=('"{0}" --ci-r84-no-network-service' -f $exe)
if ($s -and ($s.StartName -ne 'LocalSystem' -or $s.StartMode -ne 'Manual' -or
    ![string]::Equals([string]$s.PathName,$expected,
        [StringComparison]::OrdinalIgnoreCase))) {
    throw 'R84_REFUSED: cannot delete foreign service'
}
if ($t) {
    $worker=(Resolve-Path ./clients/windows/lab/Invoke-R84SystemMockSafeStop.ps1).Path
    $pwsh=(Get-Command pwsh).Source
    if (@($t.Actions).Count -ne 1 -or
        $t.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
        $t.Principal.LogonType -ne 'ServiceAccount' -or
        ![string]::Equals($t.Actions[0].Execute,$pwsh,
            [StringComparison]::OrdinalIgnoreCase) -or
        !$t.Actions[0].Arguments.Contains(('"{0}"' -f $worker))) {
        throw 'R84_REFUSED: cannot remove foreign scheduled task'
    }
    Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false -ErrorAction Stop
}
if ($s) {
    if ((Get-Service -Name $service).Status -ne 'Stopped') {
        Stop-Service -Name $service -ErrorAction Stop
        (Get-Service -Name $service).WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(25))
    }
    & sc.exe delete $service | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'R84 exact mock service delete refused' }
    $until=[DateTime]::UtcNow.AddSeconds(20)
    do {
        if (!(Get-Service -Name $service -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $until)
}
if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
    throw 'R84 mock service still registered'
}
if (Test-Path -LiteralPath $exe -PathType Leaf) {
    if ((Get-Item -LiteralPath $exe).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw 'R84_REFUSED: mock path linked'
    }
    Remove-Item -LiteralPath $exe -Force -ErrorAction Stop
}
if ((Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue) -or
    (Test-Path -LiteralPath $exe)) {
    throw 'R84 owned scheduler or mock executable residual'
}
Write-Host 'R84_EXACT_NO_NETWORK_MOCK_SCM_AND_SYSTEM_TASK_REMOVED_PASS'
