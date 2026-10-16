# R51: ONLY one IP (1.1.1.1), TCP port 443, on a noncritical test PC.
# No WireGuard, Oracle, WireSock, UU, DNS, route, or network-profile changes.
# Default invocation is READ ONLY. Requires actual local admin console
# and a verified, independent SYSTEM timed+boot recovery task to mutate.
[CmdletBinding()]
param([ValidateSet('ReadOnly','CiExercise','AttendedExercise')]
      [string]$Mode='ReadOnly', [string]$HumanConfirmation='')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ruleName = 'OracleProxy-R51-Attended-TCP443-1.1.1.1'
$taskName = 'OracleProxy-R51-SafetyAutoUndo'

function Get-OwnedRule {
    @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
}
function Test-FixedTcp {
    $client = New-Object Net.Sockets.TcpClient -ArgumentList (
        [Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $connect = $client.ConnectAsync([Net.IPAddress]::Parse('1.1.1.1'),443)
        return [bool]($connect.Wait(2500) -and $client.Connected)
    } catch { return $false }
    finally { $client.Dispose() }
}
function Assert-ExactRule([bool]$enabled) {
    $rules = @(Get-NetFirewallRule -Name $ruleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    if ($rules.Count -ne 1) { throw 'R51_REFUSED: missing or duplicated rule' }
    $r = $rules[0]
    $p = $r | Get-NetFirewallPortFilter -ErrorAction Stop
    $a = $r | Get-NetFirewallAddressFilter -ErrorAction Stop
    $app = $r | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $addresses = @($a.RemoteAddress)
    if ($r.Direction -ne 'Outbound' -or $r.Action -ne 'Block' -or
        [string]$r.Enabled -ne [string]$enabled -or
        [string]$p.Protocol -notin @('TCP','6') -or
        [string]$p.RemotePort -ne '443' -or
        [string]$app.Program -ne 'Any' -or
        $addresses.Count -ne 1 -or
        [string]$addresses[0] -notin @(
          '1.1.1.1','1.1.1.1/255.255.255.255','1.1.1.1/32')) {
        throw 'R51_REFUSED: single-IP TCP443 rule scope altered'
    }
}
function Get-NetworkFingerprint {
    $routes = @(Get-NetRoute -ErrorAction Stop |
        Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') |
        ForEach-Object {
            '{0}|{1}|{2}|{3}' -f $_.DestinationPrefix,
                $_.InterfaceIndex,$_.NextHop,$_.RouteMetric
        } | Sort-Object)
    $dns = @(Get-DnsClientServerAddress -ErrorAction Stop |
        ForEach-Object {
            '{0}|{1}|{2}' -f $_.InterfaceIndex,$_.AddressFamily,
                ($_.ServerAddresses -join ',')
        } | Sort-Object)
    return [pscustomobject]@{
        Routes = [string]::Join([Environment]::NewLine,$routes)
        Dns = [string]::Join([Environment]::NewLine,$dns)
    }
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'R51_REFUSED: Windows required'
}
if ($Mode -eq 'ReadOnly') {
    if (@(Get-OwnedRule).Count -ne 0 -or
        @(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'R51_REFUSED: existing R51 rule/task needs manual review'
    }
    Write-Host 'R51_READ_ONLY_NO_COLLISION_PASS'
    return
}
$id = New-Object Security.Principal.WindowsPrincipal (
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R51_REFUSED: elevated local Administrator required'
}
$ci = $Mode -eq 'CiExercise' -and $env:GITHUB_ACTIONS -eq 'true' -and
    $env:RUNNER_ENVIRONMENT -eq 'github-hosted' -and
    $env:RUNNER_OS -eq 'Windows' -and $env:ORACLE_R51_FIELD_CI -eq 'CI_ONLY'
$field = $Mode -eq 'AttendedExercise' -and
    $HumanConfirmation -ceq 'SECOND_PC_LOCAL_CONSOLE_RECOVERY_READY' -and
    $env:SESSIONNAME -eq 'Console'
if (-not ($ci -or $field)) {
    throw 'R51_REFUSED: disposable CI or explicit supervised local-console only'
}
foreach ($svc in @('BFE','MpsSvc','Schedule')) {
    if ((Get-Service $svc -ErrorAction Stop).Status -ne 'Running') {
        throw 'R51_REFUSED: firewall or scheduler service unavailable'
    }
}
if (@(Get-NetFirewallProfile -ErrorAction Stop |
    Where-Object { [string]$_.Enabled -ne 'True' }).Count -gt 0) {
    throw 'R51_REFUSED: firewall profile disabled'
}
if (@(Get-DnsClientServerAddress -ErrorAction Stop |
    ForEach-Object { $_.ServerAddresses } |
    Where-Object { $_ -eq '1.1.1.1' }).Count -gt 0) {
    throw 'R51_REFUSED: target is current system DNS'
}
if (@(Get-OwnedRule).Count -ne 0 -or
    @(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'R51_REFUSED: existing R51 rule/task; never overwrite'
}
if (-not (Test-FixedTcp) -or -not (Test-FixedTcp)) {
    throw 'R51_REFUSED: two real TCP baseline connections required'
}
$baseline = Get-NetworkFingerprint
$taskCreated = $false
$ownedCreated = $false
$err = $null
try {
    # Exact fixed rule only: no script execution-policy changes, no wildcard.
    $command = '$r = Get-NetFirewallRule -Name ''OracleProxy-R51-Attended-TCP443-1.1.1.1'' -ErrorAction SilentlyContinue; if ($r) { $r | Remove-NetFirewallRule -ErrorAction Stop }'
    $argsLine = '-NoProfile -NonInteractive -Command "' + $command + '"'
    $action = New-ScheduledTaskAction -Execute (
        Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $argsLine
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $triggers = @(
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(4)),
        (New-ScheduledTaskTrigger -AtStartup)
    )
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (
        New-TimeSpan -Minutes 2)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Trigger $triggers -Settings $settings -ErrorAction Stop | Out-Null
    $taskCreated = $true
    $registered = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($registered.Principal.UserId -notin @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -or
        @($registered.Triggers).Count -ne 2 -or
        $registered.Actions[0].Arguments -ne $argsLine) {
        throw 'R51_REFUSED: independent watchdog identity/triggers mismatch'
    }
    # CANARY: disabled rule never blocks traffic. SYSTEM task must delete it.
    New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Enabled False -Direction Outbound -Action Block -Profile Any -Protocol TCP -RemotePort 443 -RemoteAddress '1.1.1.1' -ErrorAction Stop | Out-Null
    $ownedCreated = $true
    Assert-ExactRule $false
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while (@(Get-OwnedRule).Count -ne 0 -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 300
    }
    if (@(Get-OwnedRule).Count -ne 0) {
        throw 'R51_REFUSED: independent SYSTEM auto-undo canary failed'
    }
    $ownedCreated = $false
    Write-Host 'R51_SYSTEM_AUTOUNDO_CANARY_PASS'
    if (-not (Test-FixedTcp)) {
        throw 'R51_REFUSED: TCP baseline lost before live test'
    }
    New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Enabled True -Direction Outbound -Action Block -Profile Any -Protocol TCP -RemotePort 443 -RemoteAddress '1.1.1.1' -ErrorAction Stop | Out-Null
    $ownedCreated = $true
    Assert-ExactRule $true
    Start-Sleep -Milliseconds 600
    if (Test-FixedTcp) { throw 'R51_FAIL: TCP escaped scoped OS WFP' }
    if (Test-FixedTcp) { throw 'R51_FAIL: second TCP socket escaped' }
    Write-Host 'R51_REAL_FIXED_TCP443_BLOCK_PASS'
} catch { $err = $_ }
finally {
    if ($taskCreated) {
        try { Start-ScheduledTask -TaskName $taskName -ErrorAction Stop }
        catch { Write-Host 'R51_WARNING: manual auto-undo trigger failed; timed/boot watchdog stays' }
    }
    if ($ownedCreated) {
        $limit = [DateTime]::UtcNow.AddSeconds(20)
        while (@(Get-OwnedRule).Count -ne 0 -and [DateTime]::UtcNow -lt $limit) {
            Start-Sleep -Milliseconds 300
        }
    }
    if (@(Get-OwnedRule).Count -eq 0 -and $taskCreated) {
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            $taskCreated = $false
        } catch {
            Write-Host 'R51_WARNING: task remains; inspect before manual deletion'
        }
    }
    if (@(Get-OwnedRule).Count -gt 0) {
        Write-Host 'R51_RESTORE_PENDING: timed/boot SYSTEM task retained; use local console recovery'
    }
}
if ($err) { throw ('R51_FAILED: ' + $err.Exception.Message) }
if (@(Get-OwnedRule).Count -ne 0 -or
    @(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'R51_FAILED: own rule/task residue'
}
$after = Get-NetworkFingerprint
if ($baseline.Routes -ne $after.Routes -or $baseline.Dns -ne $after.Dns) {
    throw 'R51_FAILED: unrelated route/DNS drift; do not reset third-party state'
}
if (-not (Test-FixedTcp)) {
    throw 'R51_FAILED: direct TCP443 did not recover'
}
Write-Host 'R51_DIRECT_TCP443_RESTORED_ROUTES_DNS_UNCHANGED_PASS'
