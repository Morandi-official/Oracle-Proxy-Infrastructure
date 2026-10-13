Set-StrictMode -Version Latest

function Test-PhysicalDefaultRoute {
    [CmdletBinding()]
    param(
        [object[]]$Routes = @(),
        [int[]]$PhysicalInterfaceIndices = @()
    )

    $indices = @{}
    foreach ($index in $PhysicalInterfaceIndices) {
        $indices[[string]$index] = $true
    }
    foreach ($route in $Routes) {
        if ($null -ne $route -and $indices.ContainsKey([string]$route.InterfaceIndex)) {
            return $true
        }
    }
    return $false
}

function Get-ReadOnlyWindowsDiagnostics {
    [CmdletBinding()]
    param()

    if ($env:OS -ne 'Windows_NT') {
        throw 'This diagnostic collector supports Windows only.'
    }

    # Query Windows state only. No external requests, writes, firewall changes, or VPN commands.
    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop)
    $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })
    $ipv4Routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' })
    $ipv6Routes = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq '::/0' })
    $physicalIndices = @($adapters | ForEach-Object { [int]$_.ifIndex })

    $serviceStates = [ordered]@{}
    foreach ($name in @('WireSockAppService', 'WireSockConnectService', 'WireGuardManager')) {
        $match = @($services | Where-Object { $_.Name -eq $name } | Select-Object -First 1)
        $serviceStates[$name] = if ($match.Count -gt 0) { [string]$match[0].State } else { 'Absent' }
    }

    $driverStates = [ordered]@{}
    foreach ($name in @('WireSock', 'WireGuard')) {
        $match = @($drivers | Where-Object { $_.Name -eq $name } | Select-Object -First 1)
        $driverStates[$name] = if ($match.Count -gt 0) { [string]$match[0].State } else { 'Absent' }
    }

    $processNames = @($processes | ForEach-Object { [string]$_.Name })
    $uuProcessPresence = [ordered]@{}
    foreach ($name in @(
        'GameViewer.exe',
        'GameViewerServer.exe',
        'GameViewerService.exe',
        'GameViewerHealthd.exe'
    )) {
        $uuProcessPresence[$name] = ($processNames -contains $name)
    }

    $wireSockProcessPresence = [ordered]@{}
    foreach ($name in @(
        'WireSockConnect.exe',
        'wiresock-connect-app-service.exe',
        'wiresock-connect-service.exe'
    )) {
        $wireSockProcessPresence[$name] = ($processNames -contains $name)
    }

    # Report only booleans and allowlisted component names. Never serialize raw CIM/routes.
    return [pscustomobject][ordered]@{
        schema_version = 1
        collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        mode = 'read_only_local'
        vpn_handshake = 'not_checked'
        vpn_connected = 'unknown'
        network_lock = 'unknown'
        physical_network = [ordered]@{
            active_physical_adapter_count = $adapters.Count
            ipv4_default_route_present = Test-PhysicalDefaultRoute -Routes $ipv4Routes -PhysicalInterfaceIndices $physicalIndices
            ipv6_default_route_present = Test-PhysicalDefaultRoute -Routes $ipv6Routes -PhysicalInterfaceIndices $physicalIndices
        }
        services = $serviceStates
        drivers = $driverStates
        uu_processes_present = $uuProcessPresence
        wiresock_processes_present = $wireSockProcessPresence
        caveats = @(
            'Service or process presence does not prove VPN connectivity.',
            'A physical default route does not by itself prove an IP leak.',
            'No leak test, network lock test, or handshake verification is performed.'
        )
    }
}

Export-ModuleMember -Function Test-PhysicalDefaultRoute, Get-ReadOnlyWindowsDiagnostics
