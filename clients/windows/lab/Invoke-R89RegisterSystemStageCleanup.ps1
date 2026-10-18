# R89 disposable CI ONLY. Exact owned SYSTEM cleanup, never on a physical PC.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:ORACLE_R89_STRICT_CLEANUP -ne 'CI_ONLY') {
    throw 'R89_REFUSED: disposable GitHub-hosted Windows only'
}
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$marker=Join-Path $root '.ci-control-approved'
$jobMarker=Join-Path $env:RUNNER_TEMP 'oracle-lab-owned.flag'
$taskName='OracleProxy-R89-CI-StageCleanup'
$worker=(Resolve-Path ./clients/windows/lab/Invoke-R89SystemStageCleanup.ps1).Path
$pwsh=(Get-Command pwsh -ErrorAction Stop).Source
$arguments=('-NoProfile -NonInteractive -File "{0}" -JobMarker "{1}"' -f $worker,$jobMarker)
if (!(Test-Path -LiteralPath $root -PathType Container) -or
    !(Test-Path -LiteralPath $marker -PathType Leaf) -or
    !(Test-Path -LiteralPath $jobMarker -PathType Leaf) -or
    (Get-Item -LiteralPath $root).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    (Get-Item -LiteralPath $marker).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    (Get-Item -LiteralPath $jobMarker).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -cne 'DISPOSABLE_GITHUB_RUNNER_ONLY' -or
    (Get-Content -LiteralPath $jobMarker -Raw).Trim() -cne 'created-by-disposable-github-runner' -or
    (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue)) {
    throw 'R89_REFUSED: ownership or absent task not proven'
}
$registered=$false
try {
    $action=New-ScheduledTaskAction -Execute $pwsh -Argument $arguments
    $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(2)
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable
    $params=@{TaskPath='\';TaskName=$taskName;Action=$action;Trigger=$trigger;
        Principal=$principal;Settings=$settings;ErrorAction='Stop'}
    Register-ScheduledTask @params | Out-Null
    $registered=$true
    $task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
    if (@($task.Actions).Count -ne 1 -or @($task.Triggers).Count -ne 1 -or
        $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
        $task.Principal.LogonType -ne 'ServiceAccount' -or
        $task.Principal.RunLevel -ne 'Highest' -or
        ![string]::Equals([string]$task.Actions[0].Execute,$pwsh,
            [StringComparison]::OrdinalIgnoreCase) -or
        $task.Actions[0].Arguments -cne $arguments) {
        throw 'R89_REFUSED: wrong registered SYSTEM cleanup task'
    }
    $started=Get-Date
    Start-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
    $limit=[DateTime]::UtcNow.AddSeconds(28)
    $success=$false
    do {
        $info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName -ErrorAction Stop
        if ($info.LastRunTime -ge $started.AddSeconds(-2) -and
            $info.LastTaskResult -eq 0 -and
            !(Test-Path -LiteralPath $root)) {
            $success=$true; break
        }
        Start-Sleep -Milliseconds 400
    } while ([DateTime]::UtcNow -lt $limit)
    if (!$success) {
        # Only bounded nonsecret OS facts and fixed lab-relative entry names.
        $last=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName -ErrorAction Stop
        $stagePresent=Test-Path -LiteralPath $root
        $entries=@()
        if ($stagePresent) {
            try {
                $entries=@(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop |
                    ForEach-Object { $_.FullName.Substring($root.Length + 1) } |
                    Sort-Object)
            } catch {
                $entries=@('INVENTORY_UNAVAILABLE')
            }
        }
        Write-Host ("R89_STAGE_CLEANUP_DIAGNOSTIC lastResult={0} taskState={1} rootPresent={2} entryNames={3}" -f
            $last.LastTaskResult,
            (Get-ScheduledTask -TaskPath '\' -TaskName $taskName).State,
            [bool]$stagePresent,($entries -join ','))
        throw 'R89_FAIL: SYSTEM cleanup not proven'
    }
    Write-Host 'R89_SYSTEM_EXACT_ALLOWLISTED_STAGE_CLEANUP_PASS'
}
finally {
    if ($registered) {
        $task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            if (@($task.Actions).Count -ne 1 -or
                $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
                $task.Principal.LogonType -ne 'ServiceAccount' -or
                ![string]::Equals([string]$task.Actions[0].Execute,$pwsh,
                    [StringComparison]::OrdinalIgnoreCase) -or
                $task.Actions[0].Arguments -cne $arguments) {
                throw 'R89_REFUSED: foreign cleanup task identity; no unregister'
            }
            Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false -ErrorAction Stop
        }
    }
}
if ((Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue) -or
    (Test-Path -LiteralPath $root)) {
    throw 'R89_FAIL: stage or cleanup task residual'
}
Write-Host 'R89_SYSTEM_STAGE_CLEANUP_TASK_AND_FILES_ZERO_PASS'
