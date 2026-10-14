$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ProtectionPolicy.psm1') -Force -ErrorAction Stop

$script:checks = 0

function Check-Policy {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [hashtable]$Changes = @{},
        [Parameter(Mandatory = $true)][bool]$ExpectedAllowed,
        [Parameter(Mandatory = $true)][string]$ExpectedReason
    )

    $inputParams = @{
        VpnIntent = 'Enabled'
        TunnelState = 'Connected'
        HandshakeFresh = $true
        TunnelRouteVerified = $true
        ApplicationClass = 'Other'
        Egress = 'Tunnel'
        IdentityVerified = $false
        EndpointVerified = $false
        AddressFamily = 'IPv4'
        TrafficKind = 'TCP'
    }
    foreach ($key in $Changes.Keys) {
        $inputParams[$key] = $Changes[$key]
    }
    $result = Get-SimulatedProtectionDecision @inputParams
    if ($result.allowed -ne $ExpectedAllowed) {
        throw ("{0}: expected allowed={1}, got {2} [{3}]" -f $Name, $ExpectedAllowed, $result.allowed, $result.reason)
    }
    if ($result.reason -ne $ExpectedReason) {
        throw ("{0}: expected reason={1}, got {2}" -f $Name, $ExpectedReason, $result.reason)
    }
    if ($result.policy_simulation_only -ne $true) {
        throw ("{0}: simulation-only indicator missing" -f $Name)
    }
    $script:checks++
}

# Every combination of IP family and TCP / UDP / DNS flow must be fail-closed
# for ordinary applications on the physical interface while VPN is requested.
foreach ($family in @('IPv4', 'IPv6')) {
    foreach ($kind in @('TCP', 'UDP', 'DNS')) {
        $flow = @{ AddressFamily = $family; TrafficKind = $kind }
        Check-Policy -Name "Connected verified tunnel $family/$kind" -Changes $flow -ExpectedAllowed $true -ExpectedReason 'VERIFIED_TUNNEL_ONLY'

        $physical = $flow.Clone(); $physical['Egress'] = 'Physical'
        Check-Policy -Name "Connected direct denied $family/$kind" -Changes $physical -ExpectedAllowed $false -ExpectedReason 'PHYSICAL_EGRESS_DENIED'

        foreach ($state in @('Connecting', 'Failed', 'Disconnected')) {
            $pending = $flow.Clone(); $pending['TunnelState'] = $state
            Check-Policy -Name "$state tunnel denied $family/$kind" -Changes $pending -ExpectedAllowed $false -ExpectedReason 'TUNNEL_NOT_VERIFIED_READY'

            $pendingPhysical = $pending.Clone(); $pendingPhysical['Egress'] = 'Physical'
            Check-Policy -Name "$state direct denied $family/$kind" -Changes $pendingPhysical -ExpectedAllowed $false -ExpectedReason 'PHYSICAL_EGRESS_DENIED'
        }

        $stale = $flow.Clone(); $stale['HandshakeFresh'] = $false
        Check-Policy -Name "Stale handshake denied $family/$kind" -Changes $stale -ExpectedAllowed $false -ExpectedReason 'TUNNEL_NOT_VERIFIED_READY'

        $unverifiedRoute = $flow.Clone(); $unverifiedRoute['TunnelRouteVerified'] = $false
        Check-Policy -Name "Unverified route denied $family/$kind" -Changes $unverifiedRoute -ExpectedAllowed $false -ExpectedReason 'TUNNEL_NOT_VERIFIED_READY'

        $uu = $physical.Clone(); $uu['ApplicationClass'] = 'UU'; $uu['IdentityVerified'] = $true
        foreach ($state in @('Connected', 'Connecting', 'Failed', 'Disconnected')) {
            $uuState = $uu.Clone(); $uuState['TunnelState'] = $state
            Check-Policy -Name "UU exception survives $state $family/$kind" -Changes $uuState -ExpectedAllowed $true -ExpectedReason 'UU_VERIFIED_DIRECT_EXCEPTION'
        }

        $unverifiedUU = $uu.Clone(); $unverifiedUU['IdentityVerified'] = $false
        Check-Policy -Name "Unverified UU denied $family/$kind" -Changes $unverifiedUU -ExpectedAllowed $false -ExpectedReason 'UU_IDENTITY_UNVERIFIED'

        $uuTunnel = $uu.Clone(); $uuTunnel['Egress'] = 'Tunnel'
        Check-Policy -Name "UU does not enter tunnel $family/$kind" -Changes $uuTunnel -ExpectedAllowed $false -ExpectedReason 'UU_TUNNEL_NOT_ALLOWED'

        $unknown = $physical.Clone(); $unknown['ApplicationClass'] = 'Unknown'; $unknown['IdentityVerified'] = $false
        Check-Policy -Name "Unknown program cannot bypass $family/$kind" -Changes $unknown -ExpectedAllowed $false -ExpectedReason 'PHYSICAL_EGRESS_DENIED'

        $userOff = $physical.Clone(); $userOff['VpnIntent'] = 'Disabled'; $userOff['TunnelState'] = 'Disconnected'
        Check-Policy -Name "Explicit user off allows direct $family/$kind" -Changes $userOff -ExpectedAllowed $true -ExpectedReason 'USER_EXPLICITLY_DISABLED_VPN'

        $offTunnel = $userOff.Clone(); $offTunnel['Egress'] = 'Tunnel'
        Check-Policy -Name "Off means no VPN tunnel $family/$kind" -Changes $offTunnel -ExpectedAllowed $false -ExpectedReason 'VPN_NOT_REQUESTED'
    }
}

# Oracle transport is allowed ONLY with a verified engine identity and endpoint,
# for the known UDP/IPv4 physical route. No generic app obtains this exemption.
foreach ($state in @('Connecting', 'Connected', 'Failed', 'Disconnected')) {
    Check-Policy -Name "Verified engine can reconnect from $state" -Changes @{
        TunnelState = $state; ApplicationClass = 'VpnEngine'; Egress = 'Physical'
        IdentityVerified = $true; EndpointVerified = $true; AddressFamily = 'IPv4'; TrafficKind = 'UDP'
    } -ExpectedAllowed $true -ExpectedReason 'VERIFIED_VPN_TRANSPORT_ONLY'
}
foreach ($variation in @(
    @{ IdentityVerified = $false; EndpointVerified = $true; AddressFamily = 'IPv4'; TrafficKind = 'UDP' },
    @{ IdentityVerified = $true; EndpointVerified = $false; AddressFamily = 'IPv4'; TrafficKind = 'UDP' },
    @{ IdentityVerified = $true; EndpointVerified = $true; AddressFamily = 'IPv6'; TrafficKind = 'UDP' },
    @{ IdentityVerified = $true; EndpointVerified = $true; AddressFamily = 'IPv4'; TrafficKind = 'TCP' },
    @{ IdentityVerified = $true; EndpointVerified = $true; AddressFamily = 'IPv4'; TrafficKind = 'DNS' }
)) {
    $variation['ApplicationClass'] = 'VpnEngine'; $variation['Egress'] = 'Physical'
    Check-Policy -Name 'Unverified or mismatched engine flow denied' -Changes $variation -ExpectedAllowed $false -ExpectedReason 'VPN_TRANSPORT_NOT_VERIFIED'
}

# Even an OS report of Connected never authorizes a tunnel without separate
# verified handshake freshness AND verified tunnel path.
Check-Policy -Name 'Connected with no fresh handshake' -Changes @{ HandshakeFresh = $false } -ExpectedAllowed $false -ExpectedReason 'TUNNEL_NOT_VERIFIED_READY'
Check-Policy -Name 'Connected with no verified tunnel path' -Changes @{ TunnelRouteVerified = $false } -ExpectedAllowed $false -ExpectedReason 'TUNNEL_NOT_VERIFIED_READY'

# A crash may change TunnelState but must not change the user's Enabled intent.
Check-Policy -Name 'Crash does not automatically disable VPN intent' -Changes @{
    VpnIntent = 'Enabled'; TunnelState = 'Disconnected'; Egress = 'Physical'
} -ExpectedAllowed $false -ExpectedReason 'PHYSICAL_EGRESS_DENIED'

# The ONLY fail-open transition is explicit Disabled intent, not Disconnect.
Check-Policy -Name 'Explicit Off restores normal direct routing' -Changes @{
    VpnIntent = 'Disabled'; TunnelState = 'Disconnected'; Egress = 'Physical'
} -ExpectedAllowed $true -ExpectedReason 'USER_EXPLICITLY_DISABLED_VPN'

Write-Host ("PASS: {0} pure/offline policy simulation cases; no network or firewall actions." -f $script:checks)
