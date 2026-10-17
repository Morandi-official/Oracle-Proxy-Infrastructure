# R74 CI ONLY: separate process waits for an expiration time, then invokes
# R73's exact-owned native peer service recovery WITHOUT GUI or manager.
# Not persistent across reboot, and NOT a production or physical-PC watchdog.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ExpiryUtc)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R73_RECOVERY -ne 'CI_ONLY' -or
    $env:ORACLE_R74_TIMER -ne 'CI_ONLY') {
    throw 'R74_REFUSED: disposable Windows runner only'
}
$deadline=[DateTimeOffset]::MinValue
if ($ExpiryUtc -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' -or
    -not [DateTimeOffset]::TryParseExact($ExpiryUtc,'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$deadline)) {
    throw 'R74_REFUSED: malformed expiration'
}
$now=[DateTimeOffset]::UtcNow
if ($deadline -le $now -or ($deadline - $now).TotalSeconds -gt 25) {
    throw 'R74_REFUSED: not a newly scheduled expiry'
}
$rollback=(Resolve-Path ./clients/windows/lab/Invoke-R73CiOwnedExpiryRecovery.ps1).Path
# A manager/GUI process is NOT needed; only this independent process waits.
do {
    $wait=($deadline-[DateTimeOffset]::UtcNow).TotalMilliseconds
    if ($wait -le 0) { break }
    Start-Sleep -Milliseconds ([Math]::Min(200,[Math]::Max(1,[int]$wait)))
} while ($true)
& $rollback -Mode Expire -DeadlineUtc $ExpiryUtc
if (-not $?) { throw 'R74_FAIL: expired owned recovery refused' }
Write-Host 'R74_CI_INDEPENDENT_WATCHER_FIRED_AFTER_DEADLINE_PASS'
