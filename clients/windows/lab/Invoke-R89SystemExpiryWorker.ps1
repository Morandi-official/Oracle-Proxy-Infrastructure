# CI AtStartup task is MANUALLY fired, no actual Windows reboot occurs.
# R89: Task Scheduler STARTS this independently as LocalSystem at deadline.
# Fixed CI-only native lab; never execute on physical Windows hosts.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExpiryUtc,
    [Parameter(Mandatory=$true)][string]$JobMarker
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'OracleProxyLab'
$marker = Join-Path $root '.ci-control-approved'
$taskName = 'OracleProxy-R89-CI-Native-Startup'
$receipt = Join-Path $root '.r89-expiry-receipt'
$expire = [DateTimeOffset]::MinValue
if ($ExpiryUtc -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' -or
    -not [DateTimeOffset]::TryParseExact($ExpiryUtc,'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,[ref]$expire)) {
    throw 'R89_REFUSED: invalid UTC deadline'
}
$now = [DateTimeOffset]::UtcNow
if ($expire -gt $now -or ($now - $expire).TotalMinutes -gt 2) {
    throw 'R89_REFUSED: not expired or stale'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (!$identity.IsSystem -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'R89_REFUSED: LocalSystem Session 0 required'
    }
} finally { $identity.Dispose() }
if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or
    !(Test-Path -LiteralPath $JobMarker -PathType Leaf) -or
    (Get-Item -LiteralPath $marker).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    (Get-Item -LiteralPath $JobMarker).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'DISPOSABLE_GITHUB_RUNNER_ONLY' -or
    (Get-Content -LiteralPath $JobMarker -Raw).Trim() -ne 'created-by-disposable-github-runner') {
    throw 'R89_REFUSED: protected independent job ownership absent'
}
if (Test-Path -LiteralPath $receipt) {
    throw 'R89_REFUSED: preexisting receipt'
}
# Task registration must still be exact SYSTEM Highest (not a user task).
$task = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
if (@($task).Count -ne 1 -or
    $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
    $task.Principal.RunLevel -ne 'Highest' -or
    $task.Principal.LogonType -ne 'ServiceAccount' -or
    @($task.Actions).Count -ne 1 -or
    @($task.Triggers).Count -ne 1 -or
    $task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger') {
    throw 'R89_REFUSED: task principal/action not exact'
}
$expectedExecutable = (Get-Command pwsh -ErrorAction Stop).Source
if (-not [string]::Equals([string]$task.Actions[0].Execute,
        [string]$expectedExecutable,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'R89_REFUSED: unexpected task binary'
}
# Environment values below are injected ONLY after independently checking
# the exact SYSTEM task, owner markers and expiry. They are a compatibility
# bridge for R73's CI-only disposable recovery, NOT host attestation.
$env:GITHUB_ACTIONS = 'true'
$env:RUNNER_ENVIRONMENT = 'github-hosted'
$env:RUNNER_OS = 'Windows'
$env:ORACLE_R73_RECOVERY = 'CI_ONLY'
$env:RUNNER_TEMP = (Split-Path -Parent $JobMarker)
$recovery = Join-Path $PSScriptRoot 'Invoke-R73CiOwnedExpiryRecovery.ps1'
& $recovery -Mode Expire -DeadlineUtc $ExpiryUtc
if (-not $?) { throw 'R89_FAIL: exact owned peer stop failed' }
'R89_SYSTEM_STARTUP_PHASE_OWNED_NATIVE_PEERS_STOPPED_NO_REBOOT' |
    Set-Content -LiteralPath $receipt -Encoding ascii -NoNewline -ErrorAction Stop
