[CmdletBinding()]
param([switch]$CiHarness)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'R86-Common.ps1')
Assert-R86-Environment ([bool]$CiHarness)
Assert-R86-Ownership
Assert-R86-ServiceRecord | Out-Null
Assert-R86-TaskRecord | Out-Null
$values=@(Get-Content -LiteralPath $script:R86State)
$utc=[DateTimeOffset]::MinValue
if (![DateTimeOffset]::TryParseExact($values[0],'yyyy-MM-ddTHH:mm:ssZ',
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal,[ref]$utc)) {
    throw 'R86_REFUSED: invalid due timestamp'
}
$service=Get-Service -Name $script:R86Service -ErrorAction Stop
$info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $script:R86Task -ErrorAction Stop
$receipt=Join-Path $script:R86Root 'expired.ok'
$now=[DateTimeOffset]::UtcNow
if ($now -lt $utc.AddSeconds(-2)) {
    if ($service.Status -ne 'Running') { throw 'R86_FAIL: mock service not running before expiry' }
    Write-Host 'R86_BEFORE_EXPIRY: mock Running; exact SYSTEM task registered; no VPN'
} else {
    if ($service.Status -ne 'Stopped' -or
        !(Test-Path -LiteralPath $receipt -PathType Leaf) -or
        (Get-Content -LiteralPath $receipt -Raw).Trim() -cne
            'R86_SYSTEM_STOPPED_EXACT_NONNETWORK_MOCK' -or
        $info.LastTaskResult -ne 0 -or
        $info.LastRunTime -lt $utc.LocalDateTime.AddSeconds(-25)) {
        throw 'R86_FAIL: SYSTEM scheduled auto-stop not proven; use emergency cleanup'
    }
    Write-Host 'R86_SYSTEM_SCHEDULER_STOPPED_RUNNING_MOCK_PASS'
}
$old=(Get-Content -LiteralPath (Join-Path $script:R86Root 'baseline.sha256') -Raw).Trim()
$new=Get-R86-NetworkDigest
if ($old -cne $new) {
    throw 'R86_NETWORK_FINGERPRINT_CHANGED: inspect ordinary network before cleanup'
}
Write-Host 'R86_DEFAULT_ROUTES_DNS_FIREWALL_BASELINE_UNCHANGED_PASS'
Write-Host 'R86_UU_CONTINUITY_REQUIRES_MANUAL_CONFIRMATION'
