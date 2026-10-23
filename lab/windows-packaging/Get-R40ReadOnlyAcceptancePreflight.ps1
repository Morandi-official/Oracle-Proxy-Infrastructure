# R40: READ-ONLY inventory for an explicitly authorized separate Windows TEST PC.
# This script does not start, stop, inspect secrets of, or modify existing VPN/UU.
# No capture or remote connection test is attempted.
[CmdletBinding()]
param([switch]$ReviewOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $ReviewOnly) { throw 'R40_REFUSED: explicit ReviewOnly required' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'R40_REFUSED: Windows only'
}
$serviceStatus = @('BFE','MpsSvc') | ForEach-Object {
    $svc = Get-Service -Name $_ -ErrorAction Stop
    $svc.Status -eq 'Running'
}
$routes4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).Count -gt 0
$routes6 = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue).Count -gt 0
# Avoid printing the device's addresses, interface IDs, active DNS servers,
# remote session identity, process names or third-party configuration.
$report = [ordered]@{
    schema_version = 1
    mode = 'read_only_local_preflight'
    bfe_running = [bool]$serviceStatus[0]
    firewall_service_running = [bool]$serviceStatus[1]
    ipv4_default_route_present = $routes4
    ipv6_default_route_present = $routes6
    wfp_all_device_verified = $false
    real_cross_host_capture_verified = $false
    uu_continuity_verified = $false
    signed_installer_verified = $false
    production_replacement_approved = $false
    network_mutation_performed = $false
}
$report | ConvertTo-Json -Compress -Depth 2
