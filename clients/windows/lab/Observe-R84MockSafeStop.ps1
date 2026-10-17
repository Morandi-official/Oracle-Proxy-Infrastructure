# R84 separate observer step, no start/stop actions.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R84 -ne 'CI_ONLY') {
    throw 'R84_REFUSED: disposable CI only'
}
$service='WireGuardTunnel$lab-field'
$taskName='OracleProxy-R84-CI-MockSafeStop'
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$conf=Join-Path $root 'config\lab-field.conf'
$lease=Join-Path $root 'config\lab-field-lease.json'
$until=[DateTime]::UtcNow.AddSeconds(115)
$seen=$false
do {
    $task=Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\' -ErrorAction Stop
    $status=(Get-Service -Name $service -ErrorAction Stop).Status
    if ($task.LastTaskResult -eq 0 -and
        $task.LastRunTime -gt [DateTime]::Now.AddMinutes(-3) -and
        $status -eq 'Stopped' -and
        !(Test-Path -LiteralPath $conf) -and
        !(Test-Path -LiteralPath $lease)) {
        $seen=$true
        break
    }
    Start-Sleep -Milliseconds 500
} while ([DateTime]::UtcNow -lt $until)
if (!$seen) {
    throw 'R84 OS scheduler did not safely stop exact running mock and remove lease'
}
if (@(Get-NetRoute -ErrorAction Stop |
    Where-Object DestinationPrefix -in @('10.77.72.1/32','10.77.72.2/32')).Count -ne 0) {
    throw 'R84 mock unexpectedly created a native tunnel route'
}
Write-Host 'R84_SYSTEM_SCHEDULED_RUNNING_MOCK_STOP_AND_LEASE_CLEAN_PASS'
