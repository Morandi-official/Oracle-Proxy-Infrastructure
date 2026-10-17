# R82 disposable Windows CI ONLY: OS Task Scheduler invokes this worker
# as SYSTEM after the independently registered deadline. This is OFFLINE
# field-config expiry only: it NEVER installs/stops native VPN services,
# touches firewall/WFP, Oracle, routes, DNS, or any user computer.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$DeadlineUtc)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$taskName='OracleProxy-R82-CI-Field-Offline-Expiry'
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$cfgdir=Join-Path $root 'config'
$marker=Join-Path $root '.r81-owned'
$config=Join-Path $cfgdir 'lab-field.conf'
$lease=Join-Path $cfgdir 'lab-field-lease.json'
$deadline=[DateTimeOffset]::MinValue
if ($DeadlineUtc -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' -or
    -not [DateTimeOffset]::TryParseExact($DeadlineUtc,'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,[ref]$deadline)) {
    throw 'R82_REFUSED: malformed UTC expiry'
}
$now=[DateTimeOffset]::UtcNow
if ($deadline -gt $now -or ($now-$deadline).TotalMinutes -gt 3) {
    throw 'R82_REFUSED: not due or stale'
}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (!$id.IsSystem -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'R82_REFUSED: only SYSTEM session 0 may expire owned files'
    }
} finally { $id.Dispose() }
$task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
$expectedExecutable=(Get-Command pwsh -ErrorAction Stop).Source
$expectedArgs=('-NoProfile -NonInteractive -File "{0}" -DeadlineUtc {1}' -f
    $PSCommandPath,$DeadlineUtc)
if (@($task.Actions).Count -ne 1 -or
    $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
    $task.Principal.RunLevel -ne 'Highest' -or
    $task.Principal.LogonType -ne 'ServiceAccount' -or
    ![string]::Equals($task.Actions[0].Execute,$expectedExecutable,
        [StringComparison]::OrdinalIgnoreCase) -or
    $task.Actions[0].Arguments -cne $expectedArgs) {
    throw 'R82_REFUSED: exact task identity/action not verified'
}
foreach ($path in @($root,$cfgdir,$marker,$config,$lease)) {
    $item=Get-Item -LiteralPath $path -ErrorAction Stop
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw 'R82_REFUSED: linked profile stage'
    }
    $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (!$acl.AreAccessRulesProtected -or
        $owner -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'R82_REFUSED: unprotected stage owner'
    }
    $aces=@($acl.GetAccessRules($true,$true,
        [Security.Principal.SecurityIdentifier]))
    if ($aces.Count -lt 2 -or
        @($aces | Where-Object {
            $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            $_.AccessControlType -ne 'Allow'
        }).Count -ne 0) {
        throw 'R82_REFUSED: stage ACL changed'
    }
}
if ((Get-Content -LiteralPath $marker -Raw).Trim() -ne
    'CI_R81_ONLY_DISPOSABLE_GITHUB_VM') {
    throw 'R82_REFUSED: exact disposable ownership missing'
}
if (@(Get-ChildItem -LiteralPath $cfgdir -Force |
    Where-Object { $_.Name -notin @('lab-field.conf','lab-field-lease.json') }).Count -ne 0 -or
    (Get-Service -Name 'WireGuardTunnel$lab-field' -ErrorAction SilentlyContinue)) {
    throw 'R82_REFUSED: foreign files or native VPN service; offline cleanup only'
}
foreach ($path in @($config,$lease)) {
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
}
if ((Test-Path -LiteralPath $config) -or (Test-Path -LiteralPath $lease)) {
    throw 'R82_FAIL: owned candidate not removed'
}
Write-Host 'R82_SYSTEM_TASK_EXPIRED_EXACT_OWNED_OFFLINE_CONFIG_PASS'
