# R82 always-run removal of exactly one CI-owned scheduled SYSTEM entry.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R82 -ne 'CI_ONLY') {
    throw 'R82_REFUSED: disposable runner only'
}
$taskName='OracleProxy-R82-CI-Field-Offline-Expiry'
$task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    $root=Join-Path $env:ProgramData 'OracleProxyLab'
    $marker=Join-Path $root '.r81-owned'
    $worker=(Resolve-Path ./clients/windows/lab/Invoke-R82SystemOfflineExpiry.ps1).Path
    $binary=(Get-Command pwsh -ErrorAction Stop).Source
    if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or
        (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'CI_R81_ONLY_DISPOSABLE_GITHUB_VM' -or
        $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
        $task.Principal.LogonType -ne 'ServiceAccount' -or
        @($task.Actions).Count -ne 1 -or
        ![string]::Equals($task.Actions[0].Execute,$binary,
            [StringComparison]::OrdinalIgnoreCase) -or
        !$task.Actions[0].Arguments.Contains(('"{0}"' -f $worker))) {
        throw 'R82_REFUSED: cannot prove exact scheduled task ownership'
    }
    Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false -ErrorAction Stop
}
if (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'R82_FAIL: owned expiry task survived cleanup'
}
Write-Host 'R82_EXACT_OWNED_SYSTEM_EXPIRY_TASK_CLEANUP_PASS'
