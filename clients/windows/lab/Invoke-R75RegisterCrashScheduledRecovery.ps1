# R75 CI-only: Windows Task Scheduler SYSTEM trigger with real native test peers.
# Do NOT register this task on a user's Windows PC.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ExpectedManagerExe)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R75_TASK -ne 'CI_ONLY' -or
    $env:ORACLE_R73_RECOVERY -ne 'CI_ONLY') {
    throw 'R75_REFUSED: isolated GitHub Windows runner only'
}
$root = Join-Path $env:ProgramData 'OracleProxyLab'
$jobMarker = Join-Path $env:RUNNER_TEMP 'oracle-lab-owned.flag'
$marker = Join-Path $root '.ci-control-approved'
$taskName = 'OracleProxy-R75-CI-Native-Expiry'
$receipt = Join-Path $root '.r75-expiry-receipt'
if (!(Test-Path $jobMarker -PathType Leaf) -or
    !(Test-Path $marker -PathType Leaf) -or
    (Get-Content -LiteralPath $jobMarker -Raw).Trim() -ne 'created-by-disposable-github-runner' -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'DISPOSABLE_GITHUB_RUNNER_ONLY' -or
    (Test-Path $receipt -PathType Leaf) -or
    (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue)) {
    throw 'R75_REFUSED: owned lab absent or task/receipt already exists'
}
$managerName = 'OracleProxyLabManager'
$m = Get-CimInstance Win32_Service -Filter "Name='$managerName'" -ErrorAction Stop
$p = if ($m -and $m.ProcessId -gt 4) {
    Get-CimInstance Win32_Process -Filter "ProcessId=$($m.ProcessId)" -ErrorAction Stop
}
if (!$m -or $m.State -ne 'Running' -or !$p -or !$p.ExecutablePath -or
    ![string]::Equals([IO.Path]::GetFullPath($p.ExecutablePath),
        [IO.Path]::GetFullPath($ExpectedManagerExe),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'R75_REFUSED: manager service process not exactly job-owned'
}
$peers = @('WireGuardTunnel$lab-peer-a','WireGuardTunnel$lab-peer-b')
foreach ($name in $peers) {
    if ((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running') {
        throw 'R75_REFUSED: native lab peer not running'
    }
}
$worker = (Resolve-Path ./clients/windows/lab/Invoke-R75SystemExpiryWorker.ps1).Path
$pwsh = (Get-Command pwsh -ErrorAction Stop).Source
$registered = $false
$triggerAt = (Get-Date).AddSeconds(40)
$expires = [DateTime]::UtcNow.AddSeconds(40).ToString('yyyy-MM-ddTHH:mm:ssZ')
$arguments = ('-NoProfile -NonInteractive -File "{0}" -ExpiryUtc {1} -JobMarker "{2}"' -f
    $worker,$expires,$jobMarker)
try {
    # Direct user/admin caller must NOT be able to invoke the system worker.
    $prematureRejected = $false
    try { & $worker -ExpiryUtc $expires -JobMarker $jobMarker }
    catch { $prematureRejected = $true }
    if (!$prematureRejected) { throw 'R75 early / non-SYSTEM request accepted' }

    $action = New-ScheduledTaskAction -Execute $pwsh -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Once -At $triggerAt
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable
    $registration = @{
        TaskPath = '\'
        TaskName = $taskName
        Action = $action
        Trigger = $trigger
        Principal = $principal
        Settings = $settings
        ErrorAction = 'Stop'
    }
    Register-ScheduledTask @registration | Out-Null
    $registered = $true
    $scheduled = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
    if (@($scheduled.Actions).Count -ne 1 -or
        $scheduled.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
        $scheduled.Principal.RunLevel -ne 'Highest' -or
        $scheduled.Principal.LogonType -ne 'ServiceAccount' -or
        ![string]::Equals($scheduled.Actions[0].Execute,$pwsh,
            [StringComparison]::OrdinalIgnoreCase) -or
        $scheduled.Actions[0].Arguments -cne $arguments) {
        throw 'R75 task action or SYSTEM identity differs after registration'
    }
    Write-Host 'R75_OWNED_SYSTEM_SCHEDULED_EXPIRY_REGISTERED_PASS'
    Stop-Process -Id ([int]$m.ProcessId) -Force -ErrorAction Stop
    (Get-Service -Name $managerName).WaitForStatus(
        'Stopped',[TimeSpan]::FromSeconds(20))
    foreach ($name in $peers) {
        if ((Get-Service -Name $name).Status -ne 'Running') {
            throw 'R75 native tunnel stopped before expiry'
        }
    }
    $timeLimit = [DateTime]::UtcNow.AddSeconds(105)
    while (!(Test-Path -LiteralPath $receipt -PathType Leaf) -and
            [DateTime]::UtcNow -lt $timeLimit) {
        Start-Sleep -Milliseconds 500
    }
    if (!(Test-Path -LiteralPath $receipt -PathType Leaf) -or
        (Get-Content -LiteralPath $receipt -Raw).Trim() -ne
            'R75_SYSTEM_SCHEDULED_TASK_EXPIRED_AND_STOPPED_OWNED_NATIVE_PEERS_PASS') {
        throw 'R75 OS Task Scheduler did not deliver verified expired recovery'
    }
    foreach ($name in $peers) {
        if ((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Stopped') {
            throw 'R75 owned native peer remains live after scheduled trigger'
        }
    }
    $taskInfo = Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName -ErrorAction Stop
    if ($taskInfo.LastTaskResult -ne 0) {
        throw 'R75 Task Scheduler recorded nonzero worker exit'
    }
    Write-Host 'R75_SYSTEM_SCHEDULER_RECOVERED_NATIVE_AFTER_MANAGER_CRASH_PASS'
}
finally {
    if ($registered) {
        $t = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
        if ($t) {
            if (@($t.Actions).Count -ne 1 -or
                ![string]::Equals([string]$t.Actions[0].Execute,$pwsh,
                    [StringComparison]::OrdinalIgnoreCase) -or
                $t.Actions[0].Arguments -cne $arguments) {
                throw 'R75 exact-owned task changed; refuse foreign task deletion'
            }
            Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false -ErrorAction Stop
        }
    }
}
