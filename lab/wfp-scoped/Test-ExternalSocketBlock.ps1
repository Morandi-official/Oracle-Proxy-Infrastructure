# R8: actual Windows Firewall TCP packet-denial test from a disposable CI VM.
# Scoped to only this pwsh.exe, one public target address and TCP/443.
# NOT a full VPN kill switch, DNS leak test or UU continuity proof.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$who = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    -not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R8_REFUSED: only elevated disposable Windows GitHub runner may test WFP'
}
if ((Get-Service BFE -ErrorAction Stop).Status -ne 'Running' -or
    (Get-Service MpsSvc -ErrorAction Stop).Status -ne 'Running') {
    throw 'R8_REFUSED: WFP/BFE and Windows Firewall not running'
}
$program = (Get-Process -Id $PID -ErrorAction Stop).Path
if (-not $program.EndsWith('pwsh.exe',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'R8_REFUSED: CI test process path invalid'
}
$before = @(Get-NetFirewallRule -ErrorAction Stop).Count
$id = [Guid]::NewGuid().ToString('N')
$created = New-Object 'System.Collections.Generic.List[string]'

function Connect-Tcp([string]$target,[int]$milliseconds=2500) {
    $address = [System.Net.IPAddress]::Parse($target)
    $socket = [System.Net.Sockets.TcpClient]::new($address.AddressFamily)
    try {
        $request = $socket.ConnectAsync($address, 443)
        if (-not $request.Wait($milliseconds)) { return $false }
        return [bool]$socket.Connected
    }
    catch { return $false }
    finally { $socket.Dispose() }
}
function Assert-ExternalBlock([string]$address,[string]$type) {
    if (-not (Connect-Tcp $address 4500)) {
        if ($type -eq 'v6') {
            Write-Host 'R8_IPV6_BASELINE_UNAVAILABLE: cloud runner lacks verified IPv6 external TCP; no IPv6 WFP packet-block claim'
            return
        }
        throw 'R8_FAIL: no external IPv4 TCP baseline; cannot test WFP packet enforcement'
    }
    $name = "OracleProxy-R8-CI-$id-$type"
    $options = @{
        Name=$name; DisplayName=$name; PolicyStore='PersistentStore'
        Direction='Outbound'; Action='Block'; Protocol='TCP'
        RemoteAddress=$address; RemotePort='443'; Program=$program
        Profile='Any'; Enabled='True'; ErrorAction='Stop'
    }
    New-NetFirewallRule @options | Out-Null
    $created.Add($name)
    $effective = Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop
    if ($effective.Action -ne 'Block' -or $effective.Direction -ne 'Outbound') {
        throw 'R8_FAIL: exact active firewall rule has incorrect action/direction'
    }
    Start-Sleep -Milliseconds 600
    if (Connect-Tcp $address 2500) {
        throw "R8_FAIL: outbound $type TCP connection succeeded despite WFP-backed program/address/port block"
    }
    Write-Host "R8_$($type)_WFP_PACKET_DENY_PASS: real Windows filtering denied a new externally addressed TCP socket"
    Remove-NetFirewallRule -Name $name -ErrorAction Stop
    $created.Remove($name) | Out-Null
    Start-Sleep -Milliseconds 600
    if (-not (Connect-Tcp $address 4500)) {
        throw "R8_FAIL: $type external TCP did not recover when synthetic rule was removed"
    }
    Write-Host "R8_$($type)_CONNECT_RESTORE_PASS: external TCP restored after removing precise block filter"
}
try {
    # Public resolver addresses are used solely as stable TCP/443 endpoints.
    # No DNS, HTTP or personal data payload is transmitted.
    Assert-ExternalBlock '1.1.1.1' 'v4'
    Assert-ExternalBlock '2606:4700:4700::1111' 'v6'
}
finally {
    foreach ($name in $created) {
        Remove-NetFirewallRule -Name $name -ErrorAction Stop
    }
    if (@(Get-NetFirewallRule -ErrorAction Stop |
        Where-Object { $_.Name -like 'OracleProxy-R8-CI-*' }).Count -gt 0) {
        throw 'R8_FAIL: temporary rules remain after test'
    }
    if (@(Get-NetFirewallRule -ErrorAction Stop).Count -ne $before) {
        throw 'R8_FAIL: rule count mismatch after cleanup'
    }
    Write-Host 'R8_FIREWALL_CLEANUP_PASS: no synthetic policies remain'
}
