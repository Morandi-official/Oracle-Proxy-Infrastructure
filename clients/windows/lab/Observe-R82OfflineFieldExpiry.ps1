# R82 monitoring runs in the next CI step AFTER registration has returned.
# No explicit start/stop service/task invocation is allowed here.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R82 -ne 'CI_ONLY') {
    throw 'R82_REFUSED: no physical/production monitoring'
}
$taskName='OracleProxy-R82-CI-Field-Offline-Expiry'
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$conf=Join-Path $root 'config\lab-field.conf'
$lease=Join-Path $root 'config\lab-field-lease.json'
$task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
$start=[DateTime]::Now
$timeout=[DateTime]::Now.AddSeconds(110)
$observed=$false
while ([DateTime]::Now -lt $timeout) {
    $state=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName -ErrorAction Stop
    if ($state.LastRunTime -ge $start.AddMinutes(-1) -and
        $state.LastTaskResult -eq 0 -and
        !(Test-Path -LiteralPath $conf) -and
        !(Test-Path -LiteralPath $lease)) {
        $observed=$true
        break
    }
    Start-Sleep -Milliseconds 500
}
if (!$observed) { throw 'R82 OS did not independently expire exact-owned config files' }
if (Get-Service -Name 'WireGuardTunnel$lab-field' -ErrorAction SilentlyContinue) {
    throw 'R82 unexpectedly installed native service'
}
if (@(Get-NetRoute -ErrorAction Stop |
    Where-Object DestinationPrefix -in @('10.77.72.1/32','10.77.72.2/32')).Count -ne 0) {
    throw 'R82 unexpectedly created native route'
}
Write-Host 'R82_OS_SYSTEM_TASK_AUTO_EXPIRED_OFFLINE_FIELD_FILES_PASS'
