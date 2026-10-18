# Always-run CI cleanup; owned R89 task ONLY, never system/user tasks.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R89_TASK -ne 'CI_ONLY') {
    throw 'R89_REFUSED: outside disposable Windows CI'
}
$taskName='OracleProxy-R89-CI-Native-Startup'
$task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    $marker=Join-Path $env:ProgramData 'OracleProxyLab\.ci-control-approved'
    $runMarker=Join-Path $env:RUNNER_TEMP 'oracle-lab-owned.flag'
    $worker=(Resolve-Path ./clients/windows/lab/Invoke-R89SystemExpiryWorker.ps1).Path
    if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or
        !(Test-Path -LiteralPath $runMarker -PathType Leaf) -or
        (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'DISPOSABLE_GITHUB_RUNNER_ONLY' -or
        (Get-Content -LiteralPath $runMarker -Raw).Trim() -ne 'created-by-disposable-github-runner' -or
        @($task.Actions).Count -ne 1 -or
        @($task.Triggers).Count -ne 1 -or
        $task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger' -or
        $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
        $task.Principal.LogonType -ne 'ServiceAccount' -or
        ![string]::Equals([string]$task.Actions[0].Execute,
            (Get-Command pwsh).Source,[StringComparison]::OrdinalIgnoreCase) -or
        !$task.Actions[0].Arguments.Contains(('"{0}"' -f $worker))) {
        throw 'R89_REFUSED: cannot prove exact task ownership, no deletion'
    }
    Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false -ErrorAction Stop
}
if (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'R89_FAIL: task survived exact owned cleanup'
}
Write-Host 'R89_OS_SCHEDULED_TASK_REMOVED_OR_ABSENT_PASS'
