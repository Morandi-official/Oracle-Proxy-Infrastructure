$ErrorActionPreference='Stop'
$script=Join-Path $PSScriptRoot '../Test-QuicUdpReturn.ps1'
. $script -DefinitionsOnly
$probe=New-OPVersionProbe
if ($probe.Packet.Length -ne 1200) { throw 'SIZE' }
$reply=New-Object byte[] 27
$reply[0]=0x80; $reply[5]=8; $reply[14]=8; $reply[26]=1
[Array]::Copy($probe.Source,0,$reply,6,8)
[Array]::Copy($probe.Destination,0,$reply,15,8)
if (-not (Test-OPVersionReply $reply $probe)) { throw 'VALID_VN_REFUSED' }
$reply[6]=$reply[6] -bxor 1
if (Test-OPVersionReply $reply $probe) { throw 'WRONG_NONCE_ACCEPTED' }
$reply[6]=$reply[6] -bxor 1
$reply[1]=1
if (Test-OPVersionReply $reply $probe) { throw 'NON_VN_ACCEPTED' }
foreach ($size in @(0,1,6,14,23,26,28,4097)) {
    if (Test-OPVersionReply (New-Object byte[] $size) $probe) { throw 'MALFORMED_ACCEPTED' }
}
Write-Host 'QUIC_VERSION_NEGOTIATION_NONCE_AND_MALFORMED_REPLY=PASS'
& $script -RequireReply
Write-Host 'REAL_WINDOWS_PUBLIC_UDP443_AND_8443_RETURN=PASS'
