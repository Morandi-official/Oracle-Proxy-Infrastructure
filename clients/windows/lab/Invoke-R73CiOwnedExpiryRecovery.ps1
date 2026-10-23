# R73: independent child-process stop of ONLY two exact owned WireGuardNT
# disposable Windows CI services after an expired, explicit CI-only deadline.
# This is NOT a production watchdog, safe-Off, installation or WFP release.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Expire')][string]$Mode,
  [Parameter(Mandatory=$true)][string]$DeadlineUtc
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R73_RECOVERY -ne 'CI_ONLY') {
    throw 'R73_REFUSED: CI-only guard'
}
$root = Join-Path $env:ProgramData 'OracleProxyLab'
$marker = Join-Path $root '.ci-control-approved'
$runMarker = Join-Path $env:RUNNER_TEMP 'oracle-lab-owned.flag'
if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or
    !(Test-Path -LiteralPath $runMarker -PathType Leaf) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'DISPOSABLE_GITHUB_RUNNER_ONLY' -or
    (Get-Content -LiteralPath $runMarker -Raw).Trim() -ne 'created-by-disposable-github-runner') {
    throw 'R73_REFUSED: job-scoped owned lab markers not verified'
}
$deadline = [DateTimeOffset]::MinValue
if ($DeadlineUtc -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' -or
    -not [DateTimeOffset]::TryParseExact($DeadlineUtc, 'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$deadline)) {
    throw 'R73_REFUSED: invalid UTC expiry'
}
$now = [DateTimeOffset]::UtcNow
if ($deadline -gt $now -or ($now - $deadline).TotalMinutes -gt 5) {
    throw 'R73_REFUSED: expiry not due or stale'
}
$owned = @()
foreach ($profile in @('lab-peer-a','lab-peer-b')) {
    $name = 'WireGuardTunnel$' + $profile
    $expectedExe = Join-Path (Join-Path $root $profile) 'OracleProxy.WireGuardHost.exe'
    if (!(Test-Path -LiteralPath $expectedExe -PathType Leaf)) {
        throw 'R73_REFUSED: owned service executable missing'
    }
    $record = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
    if (!$record -or $record.StartName -ne 'LocalSystem' -or
        $record.StartMode -ne 'Manual' -or !$record.PathName) {
        throw 'R73_REFUSED: native service identity or mode not exact'
    }
    $expectedBinPath = ('"{0}" --wireguard-service {1}' -f $expectedExe,$profile)
    if (-not [string]::Equals([string]$record.PathName, $expectedBinPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'R73_REFUSED: native service path not exactly owned'
    }
    $owned += $name
}
# Preflight both services BEFORE stopping either. Refuse any foreign identity,
# and NEVER touch an existing WireSock, UU or production WireGuard service.
foreach ($name in $owned) {
    $service = Get-Service -Name $name -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        throw 'R73_REFUSED: expected both live native services before recovery'
    }
}
foreach ($name in @('WireGuardTunnel$lab-peer-b','WireGuardTunnel$lab-peer-a')) {
    Stop-Service -Name $name -ErrorAction Stop
    (Get-Service -Name $name -ErrorAction Stop).WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(20))
}
$deadlineWait = [DateTime]::UtcNow.AddSeconds(18)
$scoped = @('10.249.129.1/32','10.249.129.2/32','fd42:14::1/128','fd42:14::2/128')
do {
    $remaining = @(Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -in $scoped })
    $active = @(Get-Service -Name $owned -ErrorAction Stop |
        Where-Object Status -ne 'Stopped')
    if ($remaining.Count -eq 0 -and $active.Count -eq 0) { break }
    Start-Sleep -Milliseconds 450
} while ([DateTime]::UtcNow -lt $deadlineWait)
if ($remaining.Count -ne 0 -or $active.Count -ne 0) {
    throw 'R73_FAIL: owned route/service residual after independent expiry'
}
Write-Host 'R73_EXPIRED_OWNED_NATIVE_PEERS_STOPPED_WITHOUT_GUI_MANAGER_PASS'
