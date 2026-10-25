# RFC 9000 version negotiation only. No VPN secrets, service IPC or system changes.
[CmdletBinding()]
param([switch]$DefinitionsOnly, [switch]$RequireReply)
$ErrorActionPreference = 'Stop'

function New-OPVersionProbe {
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $dcid = New-Object byte[] 8; $scid = New-Object byte[] 8
        $random.GetBytes($dcid); $random.GetBytes($scid)
        $packet = New-Object byte[] 1200
        $packet[0] = 0xc0
        # Reserved version 0x?a?a?a?a, RFC 9000 section 15.
        $packet[1]=0x0a; $packet[2]=0x0a; $packet[3]=0x0a; $packet[4]=0x0a
        $packet[5]=8; [Array]::Copy($dcid,0,$packet,6,8)
        $packet[14]=8; [Array]::Copy($scid,0,$packet,15,8)
        $packet[23]=0 # Empty token; payload length 1174, two-byte QUIC varint.
        $packet[24]=0x44; $packet[25]=0x96
        return @{ Packet=$packet; Destination=$dcid; Source=$scid }
    } finally { $random.Dispose() }
}

function Test-OPVersionReply([byte[]]$Packet, $Probe) {
    # VN must echo both unpredictable IDs, version=0 and contain supported versions.
    if ($Packet.Length -lt 27 -or $Packet.Length -gt 4096 -or
        ($Packet[0] -band 0x80) -eq 0) { return $false }
    if ($Packet[1] -ne 0 -or $Packet[2] -ne 0 -or $Packet[3] -ne 0 -or $Packet[4] -ne 0) { return $false }
    if ($Packet[5] -ne 8 -or $Packet[14] -ne 8 -or (($Packet.Length-23) % 4) -ne 0) { return $false }
    for ($i=0; $i -lt 8; $i++) {
        if ($Packet[6+$i] -ne $Probe.Source[$i] -or $Packet[15+$i] -ne $Probe.Destination[$i]) { return $false }
    }
    $supported = $false
    for ($i=23; $i -lt $Packet.Length; $i+=4) {
        if ($Packet[$i] -eq 0x0a -and $Packet[$i+1] -eq 0x0a -and $Packet[$i+2] -eq 0x0a -and $Packet[$i+3] -eq 0x0a) { return $false }
        if ($Packet[$i] -eq 0 -and $Packet[$i+1] -eq 0 -and $Packet[$i+2] -eq 0 -and $Packet[$i+3] -eq 1) { $supported=$true }
    }
    return $supported
}

function Get-OPSocketError($Record) {
    # PS5 can wrap .NET method errors; inspect the root exception explicitly.
    $cause=$Record.Exception.GetBaseException()
    if ($cause -isnot [Net.Sockets.SocketException]) { throw $Record }
    return [string]$cause.SocketErrorCode
}

function Invoke-OPVersionProbe([ValidateSet(443,8443)][int]$Port) {
    $probe=New-OPVersionProbe
    $socket=New-Object Net.Sockets.UdpClient ([Net.Sockets.AddressFamily]::InterNetwork)
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $matched=$false; $received=0; $socketError=''
    try {
        $socket.Connect('152.67.156.100',$Port)
        $socket.Client.ReceiveTimeout=5000
        [void]$socket.Send($probe.Packet,$probe.Packet.Length)
        while ($watch.ElapsedMilliseconds -lt 5000) {
            $socket.Client.ReceiveTimeout=[Math]::Max(1,5000-[int]$watch.ElapsedMilliseconds)
            $remote=New-Object Net.IPEndPoint ([Net.IPAddress]::Any),0
            $reply=$socket.Receive([ref]$remote); $received++
            if (Test-OPVersionReply $reply $probe) { $matched=$true; break }
            if ($received -ge 8) { break }
        }
    } catch {
        $socketError=Get-OPSocketError $_
    } finally { $watch.Stop(); $socket.Dispose() }
    return [pscustomobject]@{
        port=$Port; matching_version_reply=$matched; received_datagrams=$received
        elapsed_ms=$watch.ElapsedMilliseconds; socket_error=$socketError
        tls_verified=$false; vpn_peer_tested=$false
    }
}

if ($DefinitionsOnly) { return }
# Refuse an active tunnel: we need the direct physical path for this comparison.
if (@(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Name -eq 'OracleProxy' -and $_.Status -eq 'Up' }).Count) {
    throw 'VPN_ADAPTER_ACTIVE_DISCONNECT_FIRST'
}
Write-Host 'UDP return-path control only; no TLS/VPN authentication. No settings are changed.'
$results=@()
foreach ($port in @(443,8443)) {
    foreach ($attempt in @(1,2)) {
        $result=Invoke-OPVersionProbe $port
        $results+=$result
        Write-Host ('UDP_CONTROL_RESULT='+($result | ConvertTo-Json -Compress))
    }
}
if ($RequireReply -and (@($results | Where-Object { -not $_.matching_version_reply }).Count -ne 0)) {
    throw 'PUBLIC_UDP_VERSION_NEGOTIATION_CONTROL_FAILED'
}
Write-Host 'UDP_CONTROL_FINISHED'
