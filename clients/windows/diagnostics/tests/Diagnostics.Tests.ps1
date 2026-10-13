$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Diagnostics.psm1'
$collectorPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Collect-ReadOnly.ps1'
Import-Module $modulePath -Force -ErrorAction Stop

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAILED: $Message" }
}

$wlanRoute = [pscustomobject]@{ InterfaceIndex = 8; NextHop = 'fe80::sample' }
$vpnRoute = [pscustomobject]@{ InterfaceIndex = 50; NextHop = 'example' }

Assert-True (Test-PhysicalDefaultRoute -Routes @($wlanRoute) -PhysicalInterfaceIndices @(8)) 'physical default route detected'
Assert-True (-not (Test-PhysicalDefaultRoute -Routes @($vpnRoute) -PhysicalInterfaceIndices @(8))) 'VPN-only route must not count'
Assert-True (-not (Test-PhysicalDefaultRoute -Routes @($wlanRoute) -PhysicalInterfaceIndices @())) 'no active physical adapters'
Assert-True (-not (Test-PhysicalDefaultRoute -Routes @() -PhysicalInterfaceIndices @(8))) 'no default routes'

# Integration smoke test on a GitHub-hosted Windows runner, using only local OS queries.
$json = & $collectorPath
$report = $json | ConvertFrom-Json
Assert-True ($report.schema_version -eq 1) 'schema version'
Assert-True ($report.mode -eq 'read_only_local') 'collector mode'
Assert-True ($report.vpn_connected -eq 'unknown') 'no false claim of VPN connection'
Assert-True ($report.network_lock -eq 'unknown') 'no false claim of leak protection'
Assert-True ($null -ne $report.physical_network.ipv4_default_route_present) 'IPv4 default route flag'
Assert-True ($null -ne $report.physical_network.ipv6_default_route_present) 'IPv6 default route flag'
Assert-True ($report.uu_processes_present.PSObject.Properties.Count -eq 4) 'UU allowlisted process keys'

# No private keys, peer endpoints, interface addresses, PIDs or raw command lines in output.
Assert-True (-not ($json -match '(?i)private.?key|public.?key|endpoint|next.?hop|remote.?address|process.?id|command.?line|executable.?path')) 'redaction contract'
Write-Host 'Windows read-only diagnostics tests passed.'
