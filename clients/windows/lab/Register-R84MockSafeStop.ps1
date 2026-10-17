# R84: stage no-network SCM mock, register exact SYSTEM timeout, and exit.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R81 -ne 'CI_ONLY' -or
    $env:ORACLE_R84 -ne 'CI_ONLY') {
    throw 'R84_REFUSED: hosted disposable Windows CI only'
}
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$exe=Join-Path $root 'r84-mock.exe'
$marker=Join-Path $root '.r81-owned'
$service='WireGuardTunnel$lab-field'
$taskName='OracleProxy-R84-CI-MockSafeStop'
if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'CI_R81_ONLY_DISPOSABLE_GITHUB_VM' -or
    (Test-Path -LiteralPath $exe) -or
    (Get-Service -Name $service -ErrorAction SilentlyContinue) -or
    (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue)) {
    throw 'R84_REFUSED: preexisting fixture service or task'
}
$source=(Resolve-Path ./dist/r84-mock/OracleProxy.R84.NoNetworkMock.exe).Path
Copy-Item -LiteralPath $source -Destination $exe -ErrorAction Stop
$admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$acl=[Security.AccessControl.FileSecurity]::new()
$acl.SetOwner($admin)
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @($admin,$system)) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid,[Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow))
}
Set-Acl -LiteralPath $exe -AclObject $acl -ErrorAction Stop
$pathString=('"{0}" --ci-r84-no-network-service' -f $exe)
$createdService=$false
$createdTask=$false
try {
    New-Service -Name $service -BinaryPathName $pathString -StartupType Manual -ErrorAction Stop | Out-Null
    $createdService=$true
    $svc=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
    if (!$svc -or $svc.StartName -ne 'LocalSystem' -or
        $svc.StartMode -ne 'Manual' -or
        ![string]::Equals([string]$svc.PathName,$pathString,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'R84 exact owner binary not registered'
    }
    $worker=(Resolve-Path ./clients/windows/lab/Invoke-R84SystemMockSafeStop.ps1).Path
    $pwsh=(Get-Command pwsh).Source
    $expires=[DateTime]::UtcNow.AddSeconds(42).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $at=(Get-Date).AddSeconds(46)
    $argsLine=('-NoProfile -NonInteractive -File "{0}" -DeadlineUtc {1}' -f $worker,$expires)
    $action=New-ScheduledTaskAction -Execute $pwsh -Argument $argsLine
    $trigger=New-ScheduledTaskTrigger -Once -At $at
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable
    $params=@{TaskPath='\';TaskName=$taskName;Action=$action;Trigger=$trigger;
        Principal=$principal;Settings=$settings;ErrorAction='Stop'}
    Register-ScheduledTask @params | Out-Null
    $createdTask=$true
    $task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
    if (@($task.Actions).Count -ne 1 -or
        $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
        $task.Principal.LogonType -ne 'ServiceAccount' -or
        $task.Actions[0].Arguments -cne $argsLine) {
        throw 'R84 registered SYSTEM task not exact'
    }
    $rejected=$false
    try { & $worker -DeadlineUtc $expires } catch { $rejected=$true }
    if (!$rejected) { throw 'R84 premature/admin worker accepted' }
    Start-Service -Name $service -ErrorAction Stop
    (Get-Service -Name $service).WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(20))
    Write-Host 'R84_TIMER_REGISTERED_BEFORE_NONNETWORK_SCM_SERVICE_START_PASS'
}
catch {
    # Only the task we just created may be cancelled here. A separate
    # always-run cleanup also handles interrupted registration or service.
    if ($createdTask) {
        $t=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
        if ($t -and @($t.Actions).Count -eq 1 -and
            $t.Actions[0].Arguments -cne $argsLine) {
            throw 'R84_REFUSED: foreign task cannot be deleted'
        }
        if ($t) { Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false }
    }
    throw
}
