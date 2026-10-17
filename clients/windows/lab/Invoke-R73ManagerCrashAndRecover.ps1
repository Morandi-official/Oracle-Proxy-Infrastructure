# R73 CI-only dedicated orchestrator. It runs AFTER G14 native datapath passed.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ExpectedManagerExe)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R73_RECOVERY -ne 'CI_ONLY') {
    throw 'R73_REFUSED: hosted CI-only'
}
$m = Get-CimInstance Win32_Service -Filter "Name='OracleProxyLabManager'" -ErrorAction Stop
if (!$m -or $m.State -ne 'Running' -or $m.ProcessId -le 4) {
    throw 'R73_REFUSED: no exact live manager'
}
$p = Get-CimInstance Win32_Process -Filter "ProcessId=$($m.ProcessId)" -ErrorAction Stop
if (!$p -or !$p.ExecutablePath -or
    ![string]::Equals([IO.Path]::GetFullPath($p.ExecutablePath),
        [IO.Path]::GetFullPath($ExpectedManagerExe),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'R73_REFUSED: manager executable identity differs'
}
Stop-Process -Id ([int]$m.ProcessId) -Force -ErrorAction Stop
(Get-Service -Name 'OracleProxyLabManager').WaitForStatus(
    'Stopped',[TimeSpan]::FromSeconds(20))
foreach ($name in @('WireGuardTunnel$lab-peer-a','WireGuardTunnel$lab-peer-b')) {
    if ((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running') {
        throw 'R73_FAIL: native peer did not survive manager crash'
    }
}
$recovery=(Resolve-Path ./clients/windows/lab/Invoke-R73CiOwnedExpiryRecovery.ps1).Path
$future=[DateTime]::UtcNow.AddMinutes(2).ToString('yyyy-MM-ddTHH:mm:ssZ')
$rejected=$false
try { & $recovery -Mode Expire -DeadlineUtc $future } catch { $rejected=$true }
if (!$rejected) { throw 'R73_FAIL: early expiry was admitted' }
foreach ($name in @('WireGuardTunnel$lab-peer-a','WireGuardTunnel$lab-peer-b')) {
    if ((Get-Service -Name $name).Status -ne 'Running') {
        throw 'R73_FAIL: refusal changed native service state'
    }
}
$past=[DateTime]::UtcNow.AddSeconds(-12).ToString('yyyy-MM-ddTHH:mm:ssZ')
$argsList=@('-NoProfile','-NonInteractive','-File',('"{0}"' -f $recovery),
    '-Mode','Expire','-DeadlineUtc',$past)
$child=Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList $argsList -Wait -PassThru
if ($child.ExitCode -ne 0) { throw 'R73_FAIL: separate recovery process refused expiry' }
Write-Host 'R73_NATIVE_MANAGER_CRASH_INDEPENDENT_RECOVERY_PASS'
