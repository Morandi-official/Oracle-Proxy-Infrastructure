# R74 disposable Windows CI fault injection only. Start independent watchdog,
# terminate owned manager, wait for watchdog to stop two real native peers.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ExpectedManagerExe)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R73_RECOVERY -ne 'CI_ONLY' -or
    $env:ORACLE_R74_TIMER -ne 'CI_ONLY') {
    throw 'R74_REFUSED: not a disposable Windows trial'
}
$m=Get-CimInstance Win32_Service -Filter "Name='OracleProxyLabManager'" -ErrorAction Stop
if (!$m -or $m.State -ne 'Running' -or $m.ProcessId -le 4) {
    throw 'R74_REFUSED: owned manager missing'
}
$p=Get-CimInstance Win32_Process -Filter "ProcessId=$($m.ProcessId)" -ErrorAction Stop
if (!$p -or !$p.ExecutablePath -or
    ![string]::Equals([IO.Path]::GetFullPath($p.ExecutablePath),
        [IO.Path]::GetFullPath($ExpectedManagerExe),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'R74_REFUSED: manager executable identity not exact'
}
$names=@('WireGuardTunnel$lab-peer-a','WireGuardTunnel$lab-peer-b')
foreach ($name in $names) {
    if ((Get-Service $name -ErrorAction Stop).Status -ne 'Running') {
        throw 'R74_REFUSED: both native peers must be active'
    }
}
$watch=(Resolve-Path ./clients/windows/lab/Invoke-R74CiTimedExpiryWatch.ps1).Path
$expires=[DateTime]::UtcNow.AddSeconds(16).ToString('yyyy-MM-ddTHH:mm:ssZ')
$argsList=@('-NoProfile','-NonInteractive','-File',('"{0}"' -f $watch),
    '-ExpiryUtc',$expires)
$child=Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList $argsList -PassThru
try {
    if ($child.HasExited) { throw 'R74 watcher exited before expiration' }
    Stop-Process -Id ([int]$m.ProcessId) -Force -ErrorAction Stop
    (Get-Service -Name 'OracleProxyLabManager').WaitForStatus(
        'Stopped',[TimeSpan]::FromSeconds(20))
    foreach ($name in $names) {
        if ((Get-Service $name).Status -ne 'Running') {
            throw 'R74 peers stopped before timed expiry'
        }
    }
    if (!$child.WaitForExit(45000) -or $child.ExitCode -ne 0) {
        throw 'R74 timed separate process failed to stop owned peers'
    }
    foreach ($name in $names) {
        if ((Get-Service $name).Status -ne 'Stopped') {
            throw 'R74 native tunnel remained running after timeout'
        }
    }
    Write-Host 'R74_NATIVE_MANAGER_CRASH_AUTOMATIC_CI_PROCESS_EXPIRY_PASS'
}
finally {
    if (!$child.HasExited) {
        # Only the known CI-owned child we JUST started, never third-party.
        try { Stop-Process -Id $child.Id -Force -ErrorAction Stop } catch {}
    }
    $child.Dispose()
}
