Set-StrictMode -Version Latest

# Pure state-machine POLICY SIMULATION only.
# All input fields are mock facts from a test harness, NOT trusted OS attestations.
# This module never configures WFP, the firewall, DNS, routing, WireSock, or a VPN.
function Get-SimulatedProtectionDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enabled', 'Disabled')]
        [string]$VpnIntent,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Connected', 'Connecting', 'Failed', 'Disconnected')]
        [string]$TunnelState,

        [bool]$HandshakeFresh = $false,
        [bool]$TunnelRouteVerified = $false,

        [Parameter(Mandatory = $true)]
        [ValidateSet('UU', 'VpnEngine', 'Other', 'Unknown')]
        [string]$ApplicationClass,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Physical', 'Tunnel')]
        [string]$Egress,

        [bool]$IdentityVerified = $false,
        [bool]$EndpointVerified = $false,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$AddressFamily = 'IPv4',

        [ValidateSet('TCP', 'UDP', 'DNS')]
        [string]$TrafficKind = 'TCP'
    )

    # Deliberate Off and an accidental disconnect are intentionally distinct.
    # A crash/disconnect must NEVER flip the requested mode to Disabled.
    if ($VpnIntent -eq 'Disabled') {
        $state = 'DeliberateDirectMode'
        $allowed = ($Egress -eq 'Physical')
        $reason = if ($allowed) { 'USER_EXPLICITLY_DISABLED_VPN' } else { 'VPN_NOT_REQUESTED' }
    }
    else {
        $healthy = (
            $TunnelState -eq 'Connected' -and
            $HandshakeFresh -and
            $TunnelRouteVerified
        )
        $state = if ($healthy) { 'SimulatedTunnelReady' } else { 'SimulatedFailClosed' }

        if ($ApplicationClass -eq 'UU') {
            # Only a separately VERIFIED UU identity is eligible; names alone are unsafe.
            $allowed = ($IdentityVerified -and $Egress -eq 'Physical')
            if (-not $IdentityVerified) {
                $reason = 'UU_IDENTITY_UNVERIFIED'
            }
            elseif ($Egress -ne 'Physical') {
                $reason = 'UU_TUNNEL_NOT_ALLOWED'
            }
            else {
                $reason = 'UU_VERIFIED_DIRECT_EXCEPTION'
            }
        }
        elseif ($ApplicationClass -eq 'VpnEngine') {
            # The *real* implementation must verify the exact Oracle endpoint,
            # executable identity and UDP/IPv4 tuple before permitting this path.
            $allowed = (
                $IdentityVerified -and $EndpointVerified -and
                $Egress -eq 'Physical' -and
                $AddressFamily -eq 'IPv4' -and $TrafficKind -eq 'UDP'
            )
            $reason = if ($allowed) { 'VERIFIED_VPN_TRANSPORT_ONLY' } else { 'VPN_TRANSPORT_NOT_VERIFIED' }
        }
        else {
            # Other/Unknown programs can never use the physical ISP link while
            # the user's VPN intent remains Enabled, even during failure.
            $allowed = ($Egress -eq 'Tunnel' -and $healthy)
            if ($Egress -eq 'Physical') {
                $reason = 'PHYSICAL_EGRESS_DENIED'
            }
            elseif (-not $healthy) {
                $reason = 'TUNNEL_NOT_VERIFIED_READY'
            }
            else {
                $reason = 'VERIFIED_TUNNEL_ONLY'
            }
        }
    }

    # Only generic decisions are emitted: no keys, addresses, executable paths,
    # routes, endpoint identifiers, or live process metadata.
    return [pscustomobject][ordered]@{
        policy_simulation_only = $true
        simulated_state = $state
        allowed = [bool]$allowed
        reason = $reason
    }
}

Export-ModuleMember -Function Get-SimulatedProtectionDecision
