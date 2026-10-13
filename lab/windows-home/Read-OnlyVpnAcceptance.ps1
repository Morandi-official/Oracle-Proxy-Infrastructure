# G16: read-only, sanitized Windows 11 inspection; no elevation needed.
# No VPN, service, route, firewall, DNS or registry modifications.
param([switch]$SelfTest)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function New-Baseline {
    param(
        [string]$Edition,[int]$Build,[bool]$Os64,
        [string]$Bfe,[string]$FirewallService,
        [int]$ActiveAdapters,[int]$V4Routes,[int]$V6Routes,
        [int]$DnsEntries,[int]$EnabledProfiles
    )
    foreach ($count in @($Build,$ActiveAdapters,$V4Routes,$V6Routes,$DnsEntries,$EnabledProfiles)) {
        if ($count -lt 0) { throw 'Negative baseline count refused' }
    }
    return [pscustomobject][ordered]@{
        schema_version = 1
        mode = 'read_only_sanitized_baseline'
        windows_edition = $Edition
        windows_build = $Build
        os_64_bit = $Os64
        bfe_service_status = $Bfe
        firewall_service_status = $FirewallService
        active_adapter_count = $ActiveAdapters
        ipv4_default_route_count = $V4Routes
        ipv6_default_route_count = $V6Routes
        dns_server_entry_count = $DnsEntries
        firewall_profile_enabled_count = $EnabledProfiles
        vpn_connection_verified = $false
        os_enforced_ipv4_ipv6_dns_fail_closed_verified = $false
        uu_p2p_identity_or_continuity_verified = $false
        out_of_band_restore_verified = $false
        network_changes_performed = $false
        production_install_authorized = $false
    }
}
if ($SelfTest) {
    $report = New-Baseline -Edition 'Windows 11 Home' -Build 26100 -Os64 $true -Bfe 'running' -FirewallService 'running' -ActiveAdapters 1 -V4Routes 1 -V6Routes 0 -DnsEntries 2 -EnabledProfiles 3
    if ($report.schema_version -ne 1 -or $report.mode -ne 'read_only_sanitized_baseline' -or $report.windows_build -ne 26100 -or $report.active_adapter_count -ne 1 -or $report.os_enforced_ipv4_ipv6_dns_fail_closed_verified -or $report.uu_p2p_identity_or_continuity_verified -or $report.out_of_band_restore_verified -or $report.production_install_authorized -or $report.network_changes_performed -or $report.vpn_connection_verified) {
        throw 'G16 false security claim regression'
    }
    $publicFields = @($report.PSObject.Properties.Name)
    foreach ($sensitiveField in @('username','hostname','ip_address','dns_server_addresses','private_key','peer_endpoint')) {
        if ($publicFields -contains $sensitiveField) { throw 'G16 sensitive field in report' }
    }
    Write-Host 'G16_SELF_TEST_PASS: sanitized read-only model; no production safety claims'
    exit 0
}
function Read-ServiceStatus([string]$name) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return 'not_detected' }
    return ([string]$svc.Status).ToLowerInvariant()
}
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up')
$v4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
$v6 = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue)
$dnsCount = 0
foreach ($row in @(Get-DnsClientServerAddress -ErrorAction Stop)) {
    $dnsCount += @($row.ServerAddresses | Where-Object { $_ }).Count
}
$fwEnabled = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object Enabled -eq $true).Count
$argsReport = @{
    Edition = [string]$os.Caption
    Build = [int]$os.BuildNumber
    Os64 = [bool]([string]$os.OSArchitecture -match '64')
    Bfe = Read-ServiceStatus 'BFE'
    FirewallService = Read-ServiceStatus 'MpsSvc'
    ActiveAdapters = $adapters.Count
    V4Routes = $v4.Count
    V6Routes = $v6.Count
    DnsEntries = $dnsCount
    EnabledProfiles = $fwEnabled
}
New-Baseline @argsReport | ConvertTo-Json -Compress -Depth 3
