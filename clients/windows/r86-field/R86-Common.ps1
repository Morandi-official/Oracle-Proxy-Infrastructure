# R86 helper library. This ONLY operates on OracleProxyR86Attended and a
# dedicated no-network SCM service and OS Task Scheduler entry.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:R86Root=Join-Path $env:ProgramData 'OracleProxyR86Attended'
$script:R86Service='OracleProxyR86NoNetworkMock'
$script:R86Task='OracleProxyR86AutoStop'
$script:R86Marker='R86-ATTENDED-OWNED-NO-NETWORK-ONLY'
$script:R86Binary=Join-Path $script:R86Root 'R86NoNetworkMock.exe'
$script:R86State=Join-Path $script:R86Root 'state.txt'
$script:R86MockArg='--r86-no-network-mock'

function Assert-R86-Environment([bool]$CiHarness) {
    if (![Environment]::Is64BitOperatingSystem -or
        [Environment]::OSVersion.Platform -ne 'Win32NT') {
        throw 'R86_REFUSED: Windows 64-bit only'
    }
    $user=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if (!$user.IsAuthenticated -or
            !([Security.Principal.WindowsPrincipal]::new($user)).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator) -or $user.IsSystem) {
            throw 'R86_REFUSED: attended elevated ADMINISTRATOR session required'
        }
    } finally { $user.Dispose() }
    if ($CiHarness) {
        if ($env:GITHUB_ACTIONS -ne 'true' -or
            $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
            $env:ORACLE_R86_CI -ne 'CI_ONLY') {
            throw 'R86_REFUSED: CI mode requires disposable GitHub runner'
        }
    } else {
        if ($env:GITHUB_ACTIONS -eq 'true' -or $env:ORACLE_R86_CI) {
            throw 'R86_REFUSED: CI environment cannot use physical mode'
        }
        if ($env:SESSIONNAME -like 'RDP-*') {
            throw 'R86_REFUSED: RDP session; attend the physical console'
        }
        if (!('R86Console' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class R86Console {
    [DllImport("kernel32.dll")] public static extern UInt32 WTSGetActiveConsoleSessionId();
}
'@ -ErrorAction Stop
        }
        if ([uint32]([Diagnostics.Process]::GetCurrentProcess().SessionId) -ne
            [R86Console]::WTSGetActiveConsoleSessionId()) {
            throw 'R86_REFUSED: this admin shell is not in active physical console session'
        }
    }
    foreach($name in @('BFE','MpsSvc')) {
        if ((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running') {
            throw 'R86_REFUSED: Windows security service not running'
        }
    }
}

function Get-R86-NetworkDigest {
    # Compare only; never print/upload addresses or DNS servers.
    $routes=@(Get-NetRoute -ErrorAction Stop |
        Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') |
        Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric)
    $dns=@(Get-DnsClientServerAddress -ErrorAction Stop |
        Select-Object InterfaceIndex,AddressFamily,ServerAddresses |
        Sort-Object InterfaceIndex,AddressFamily)
    $n=@(Get-NetFirewallRule -ErrorAction Stop).Count
    $json=([ordered]@{
        routes=$routes
        dns=$dns
        firewall_count=$n
        bfe=(Get-Service BFE).Status.ToString()
        firewall=(Get-Service MpsSvc).Status.ToString()
    }|ConvertTo-Json -Depth 7 -Compress)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes($json)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')
    } finally { $sha.Dispose() }
}

function Assert-R86-Ownership {
    if (!(Test-Path -LiteralPath $script:R86Root -PathType Container) -or
        (Get-Item -LiteralPath $script:R86Root).Attributes.HasFlag(
            [IO.FileAttributes]::ReparsePoint)) {
        throw 'R86_REFUSED: expected owned directory not found or linked'
    }
    $marker=Join-Path $script:R86Root 'owner.txt'
    if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or
        (Get-Item -LiteralPath $marker).Attributes.HasFlag(
            [IO.FileAttributes]::ReparsePoint) -or
        (Get-Content -LiteralPath $marker -Raw).Trim() -cne $script:R86Marker) {
        throw 'R86_REFUSED: dedicated ownership marker not verified'
    }
    $acl=Get-Acl -LiteralPath $script:R86Root
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (!$acl.AreAccessRulesProtected -or
        $owner -notin @('S-1-5-32-544','S-1-5-18')) {
        throw 'R86_REFUSED: protected ownership not verified'
    }
    $rules=@($acl.GetAccessRules($true,$true,
        [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -lt 2 -or
        @($rules|Where-Object {
            $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            $_.AccessControlType -ne 'Allow'
        }).Count -ne 0) {
        throw 'R86_REFUSED: unexpected ACL principal'
    }
}

function Assert-R86-ServiceRecord {
    $svc=Get-CimInstance Win32_Service -Filter "Name='$script:R86Service'" -ErrorAction Stop
    $expected=('"{0}" {1}' -f $script:R86Binary,$script:R86MockArg)
    if (!$svc -or $svc.StartName -ne 'LocalSystem' -or $svc.StartMode -ne 'Manual' -or
        ![string]::Equals([string]$svc.PathName,$expected,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'R86_REFUSED: service path or identity differs'
    }
    return $svc
}

function Assert-R86-TaskRecord {
    $task=Get-ScheduledTask -TaskPath '\' -TaskName $script:R86Task -ErrorAction Stop
    $values=@(Get-Content -LiteralPath $script:R86State)
    if ($values.Count -ne 3) { throw 'R86_REFUSED: invalid lease state' }
    $expected=('--r86-expire {0} {1}' -f $values[0],$values[1])
    if (@($task.Actions).Count -ne 1 -or
        $task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
        $task.Principal.LogonType -ne 'ServiceAccount' -or
        $task.Principal.RunLevel -ne 'Highest' -or
        ![string]::Equals([string]$task.Actions[0].Execute,$script:R86Binary,
            [StringComparison]::OrdinalIgnoreCase) -or
        $task.Actions[0].Arguments -cne $expected) {
        throw 'R86_REFUSED: scheduled task is not exact'
    }
    return $task
}
