# R82: register exactly ONE future OS-owned LocalSystem offline expiry task
# on a disposable GitHub Windows VM and then EXIT before the deadline.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R81 -ne 'CI_ONLY' -or
    $env:ORACLE_R82 -ne 'CI_ONLY') {
    throw 'R82_REFUSED: hosted Windows CI only'
}
$taskName='OracleProxy-R82-CI-Field-Offline-Expiry'
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$marker=Join-Path $root '.r81-owned'
if ((Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue) -or
    !(Test-Path -LiteralPath $marker -PathType Leaf) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'CI_R81_ONLY_DISPOSABLE_GITHUB_VM' -or
    (Get-Service -Name 'WireGuardTunnel$lab-field' -ErrorAction SilentlyContinue)) {
    throw 'R82_REFUSED: cannot prove unused task and exact offline fixture'
}
$worker=(Resolve-Path ./clients/windows/lab/Invoke-R82SystemOfflineExpiry.ps1).Path
$pwsh=(Get-Command pwsh -ErrorAction Stop).Source
$expires=[DateTime]::UtcNow.AddSeconds(43).ToString('yyyy-MM-ddTHH:mm:ssZ')
$at=(Get-Date).AddSeconds(47)
$argsLine=('-NoProfile -NonInteractive -File "{0}" -DeadlineUtc {1}' -f $worker,$expires)
$action=New-ScheduledTaskAction -Execute $pwsh -Argument $argsLine
$trigger=New-ScheduledTaskTrigger -Once -At $at
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable
$registered=$false
try {
    $params=@{
        TaskName=$taskName
        TaskPath='\'
        Action=$action
        Trigger=$trigger
        Principal=$principal
        Settings=$settings
        ErrorAction='Stop'
    }
    Register-ScheduledTask @params | Out-Null
    $registered=$true
    $task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
    if (@($task.Actions).Count -ne 1 -or
        $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
        $task.Principal.RunLevel -ne 'Highest' -or
        $task.Principal.LogonType -ne 'ServiceAccount' -or
        ![string]::Equals($task.Actions[0].Execute,$pwsh,
            [StringComparison]::OrdinalIgnoreCase) -or
        $task.Actions[0].Arguments -cne $argsLine) {
        throw 'R82 registered task not the exact CI-owned action'
    }
    # Test explicit premature attempt in current runner user context.
    $blocked=$false
    try { & $worker -DeadlineUtc $expires }
    catch { $blocked=$true }
    if (!$blocked) { throw 'R82 early or non-SYSTEM caller was admitted' }
    if (!(Test-Path -LiteralPath (Join-Path $root 'config\lab-field.conf')) -or
        !(Test-Path -LiteralPath (Join-Path $root 'config\lab-field-lease.json'))) {
        throw 'R82 premature refusal mutated owned config'
    }
    Write-Host 'R82_OS_OWNED_SYSTEM_EXPIRY_REGISTERED_BEFORE_FIELD_USE_PASS'
}
catch {
    # Never leave this CI-created timer armed on failed preflight.
    if ($registered) {
        $t=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
        if ($t -and @($t.Actions).Count -eq 1 -and
            $t.Actions[0].Arguments -cne $argsLine) {
            throw 'R82_REFUSED: task identity changed, cannot safely unregister'
        }
        if ($t) { Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop }
    }
    throw
}
# NO native service activation, no resident watchdog process.
