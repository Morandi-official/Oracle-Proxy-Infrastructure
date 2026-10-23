# R84 CI-only: scheduled SYSTEM safe-stop of a NON-NETWORK mock service,
# NOT a native WireGuardNT tunnel. Never deploy on the physical test PC.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$DeadlineUtc)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$taskName='OracleProxy-R84-CI-MockSafeStop'
$service='WireGuardTunnel$lab-field'
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$marker=Join-Path $root '.r81-owned'
$exe=Join-Path $root 'r84-mock.exe'
$conf=Join-Path $root 'config\lab-field.conf'
$lease=Join-Path $root 'config\lab-field-lease.json'
$due=[DateTimeOffset]::MinValue
if ($DeadlineUtc -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' -or
    -not [DateTimeOffset]::TryParseExact($DeadlineUtc,'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,[ref]$due)) {
    throw 'R84_REFUSED: incorrect deadline'
}
$now=[DateTimeOffset]::UtcNow
if ($due -gt $now -or ($now-$due).TotalMinutes -gt 3) {
    throw 'R84_REFUSED: expiry not due'
}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (!$id.IsSystem -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'R84_REFUSED: SYSTEM Session0 required'
    }
} finally { $id.Dispose() }
$task=Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
$pwsh=(Get-Command pwsh -ErrorAction Stop).Source
$argLine=('-NoProfile -NonInteractive -File "{0}" -DeadlineUtc {1}' -f
    $PSCommandPath,$DeadlineUtc)
if (@($task.Actions).Count -ne 1 -or
    $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
    $task.Principal.RunLevel -ne 'Highest' -or
    $task.Principal.LogonType -ne 'ServiceAccount' -or
    ![string]::Equals($task.Actions[0].Execute,$pwsh,
        [StringComparison]::OrdinalIgnoreCase) -or
    $task.Actions[0].Arguments -cne $argLine) {
    throw 'R84_REFUSED: unauthorized task identity/action'
}
foreach ($path in @($root,$marker,$exe,$conf,$lease)) {
    $item=Get-Item -LiteralPath $path -ErrorAction Stop
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw 'R84_REFUSED: linked owned resource'
    }
    $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (!$acl.AreAccessRulesProtected -or
        $owner -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'R84_REFUSED: owner or inherited DACL'
    }
    $aces=@($acl.GetAccessRules($true,$true,
        [Security.Principal.SecurityIdentifier]))
    if ($aces.Count -lt 2 -or
        @($aces|Where-Object {
            $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            $_.AccessControlType -ne 'Allow'
        }).Count -ne 0) {
        throw 'R84_REFUSED: untrusted file access'
    }
}
if ((Get-Content -LiteralPath $marker -Raw).Trim() -ne
    'CI_R81_ONLY_DISPOSABLE_GITHUB_VM') {
    throw 'R84_REFUSED: stage not owned'
}
$svc=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
$expectedPath=('"{0}" --ci-r84-no-network-service' -f $exe)
if (!$svc -or $svc.StartName -ne 'LocalSystem' -or
    $svc.StartMode -ne 'Manual' -or $svc.State -ne 'Running' -or
    ![string]::Equals([string]$svc.PathName,$expectedPath,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'R84_REFUSED: not exact running CI-owned no-network mock service'
}
Stop-Service -Name $service -ErrorAction Stop
(Get-Service -Name $service -ErrorAction Stop).WaitForStatus(
    [ServiceProcess.ServiceControllerStatus]::Stopped,
    [TimeSpan]::FromSeconds(25))
foreach ($path in @($conf,$lease)) {
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
}
if ((Get-Service -Name $service).Status -ne 'Stopped' -or
    (Test-Path -LiteralPath $conf) -or (Test-Path -LiteralPath $lease)) {
    throw 'R84_FAIL: exactly owned service/config not cleared'
}
Write-Host 'R84_SYSTEM_TASK_SAFESTOP_NONNETWORK_MOCK_AND_LEASE_PASS'
