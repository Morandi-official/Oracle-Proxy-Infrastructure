# R51 supervised noncritical Windows test PC. READ ONLY.
# Compatible with built-in Windows PowerShell 5.1; no policy changes.
# This does not identify, start, stop or query config of UU or WireSock.
[CmdletBinding()]
param([switch]$ReviewOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $ReviewOnly) { throw 'R51_REFUSED: explicit -ReviewOnly required' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'R51_REFUSED: Windows only'
}

$ruleName = 'OracleProxy-R51-Attended-TCP443-1.1.1.1'
$taskName = 'OracleProxy-R51-SafetyAutoUndo'
$principal = New-Object Security.Principal.WindowsPrincipal (
    [Security.Principal.WindowsIdentity]::GetCurrent())
$admin = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$services = @('BFE','MpsSvc','Schedule') | ForEach-Object {
    (Get-Service -Name $_ -ErrorAction Stop).Status -eq 'Running'
}
$routes4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
$routes6 = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue)
$adapterIds = @((Get-NetAdapter -Physical -ErrorAction Stop).ifIndex)
$up = @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up')
$matches = @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
$task = @(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
$targetAsSystemDns = @(Get-DnsClientServerAddress -ErrorAction Stop |
    ForEach-Object { $_.ServerAddresses } |
    Where-Object { $_ -eq '1.1.1.1' })
$firewallProfilesEnabled = @(
    Get-NetFirewallProfile -ErrorAction Stop |
    Where-Object { [string]$_.Enabled -ne 'True' }
).Count -eq 0
$session = [Environment]::GetEnvironmentVariable('SESSIONNAME','Process')
# A remote PowerShell shell is not an acceptable substitute for the
# physical keyboard. Operators must independently confirm console access.
$consoleIndicated = [string]::Equals($session,'Console',
    [StringComparison]::OrdinalIgnoreCase)
# Do NOT probe third party process names, gateways, DNS server values,
# local IP addresses or remote identities, and do not modify anything.
$report = [ordered]@{
    schema_version = 1
    action = 'READ_ONLY'
    os_windows = $true
    elevated_admin = [bool]$admin
    physical_console_indicated = [bool]$consoleIndicated
    bfe_running = [bool]$services[0]
    firewall_service_running = [bool]$services[1]
    task_scheduler_running = [bool]$services[2]
    firewall_profiles_enabled = [bool]$firewallProfilesEnabled
    active_physical_adapters = @($up | Where-Object {
        $_.ifIndex -in $adapterIds }).Count
    active_other_adapters = @($up | Where-Object {
        $_.ifIndex -notin $adapterIds }).Count
    ipv4_default_routes = $routes4.Count
    ipv6_default_routes = $routes6.Count
    target_used_as_system_dns = ($targetAsSystemDns.Count -gt 0)
    test_rule_preexists = ($matches.Count -gt 0)
    rollback_task_preexists = ($task.Count -gt 0)
    production_tunnel_enabled = $false
    network_mutation_performed = $false
    ready_for_mutation = $false
}
$report | ConvertTo-Json -Compress -Depth 3
