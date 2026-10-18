# R89 disposable GitHub Windows CI ONLY: exact-owned SYSTEM cleanup.
# No physical machine, no arbitrary path, no network-policy mutation.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$JobMarker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'OracleProxyLab'
$taskName = 'OracleProxy-R89-CI-StageCleanup'
$marker = Join-Path $root '.ci-control-approved'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (!$identity.IsSystem -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'R89_REFUSED: exact stage cleanup requires SYSTEM Session0'
    }
} finally { $identity.Dispose() }
if (!(Test-Path -LiteralPath $root -PathType Container) -or
    !(Test-Path -LiteralPath $marker -PathType Leaf) -or
    !(Test-Path -LiteralPath $JobMarker -PathType Leaf) -or
    (Get-Item -LiteralPath $root).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    (Get-Item -LiteralPath $marker).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    (Get-Item -LiteralPath $JobMarker).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -cne 'DISPOSABLE_GITHUB_RUNNER_ONLY' -or
    (Get-Content -LiteralPath $JobMarker -Raw).Trim() -cne 'created-by-disposable-github-runner') {
    throw 'R89_REFUSED: fixed runner-owned markers not validated'
}
$task = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
$exe = (Get-Command pwsh -ErrorAction Stop).Source
$argsExpected = ('-NoProfile -NonInteractive -File "{0}" -JobMarker "{1}"' -f
    $PSCommandPath,$JobMarker)
if (@($task.Actions).Count -ne 1 -or
    $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
    $task.Principal.LogonType -ne 'ServiceAccount' -or
    $task.Principal.RunLevel -ne 'Highest' -or
    ![string]::Equals([string]$task.Actions[0].Execute,$exe,
        [StringComparison]::OrdinalIgnoreCase) -or
    $task.Actions[0].Arguments -cne $argsExpected) {
    throw 'R89_REFUSED: SYSTEM stage-cleanup task identity/action mismatch'
}
# Refuse to delete even CI-owned files while test services are running.
foreach ($svc in @('OracleProxyLabManager','WireGuardTunnel$lab-peer-a',
                    'WireGuardTunnel$lab-peer-b')) {
    $actual = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($actual -and $actual.Status -ne 'Stopped') {
        throw 'R89_REFUSED: native service still active during stage cleanup'
    }
}
# Allowlist only the exact synthetic R89/G14 profile tree. This is checked
# BEFORE any destructive action. No foreign files, folders or reparse links.
$allowedFiles = @(
    '.ci-control-approved', '.r89-expiry-receipt',
    'config\lab-peer-a.conf', 'config\lab-peer-b.conf',
    'lab-peer-a\OracleProxy.WireGuardHost.exe',
    'lab-peer-a\tunnel.dll','lab-peer-a\wireguard.dll',
    'lab-peer-a\engine-pins.json',
    'lab-peer-b\OracleProxy.WireGuardHost.exe',
    'lab-peer-b\tunnel.dll','lab-peer-b\wireguard.dll',
    'lab-peer-b\engine-pins.json'
)
$allowedDirs = @('config','lab-peer-a','lab-peer-b')
$entries = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop)
foreach ($item in $entries) {
    $relative = $item.FullName.Substring($root.Length + 1)
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
        ($item.PSIsContainer -and $relative -notin $allowedDirs) -or
        (!$item.PSIsContainer -and $relative -notin $allowedFiles)) {
        throw 'R89_REFUSED: unexpected or reparse stage entry, no deletion'
    }
}
# SYSTEM has the original protected-file identity; do NOT relax any ACL.
# The marker is removed last; the fixed stage is never recursively removed
# until the complete inventory was independently allowed above.
foreach ($item in @($entries | Where-Object { !$_.PSIsContainer } |
        Sort-Object FullName -Descending)) {
    Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
}
foreach ($name in @('lab-peer-b','lab-peer-a','config')) {
    $dir = Join-Path $root $name
    if (Test-Path -LiteralPath $dir) {
        Remove-Item -LiteralPath $dir -ErrorAction Stop
    }
}
Remove-Item -LiteralPath $root -ErrorAction Stop
if (Test-Path -LiteralPath $root) {
    throw 'R89_FAIL: stage not deleted by exact SYSTEM cleanup'
}
