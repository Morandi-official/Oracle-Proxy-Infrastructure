# R48 disposable hosted Windows probe: no firewall rule mutation here.
# SYSTEM service owns an OS-backed all-application rule with four fixed targets.
param([ValidateSet('Before','During','After')][string]$Phase)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R48_PACKET_CI -ne 'CI_ONLY' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R48_REFUSED: disposable Windows CI only'
}
$name = 'OracleProxy-R48-CI-SYSTEM-AllApps-FixedDestinations'
$path = Join-Path $env:RUNNER_TEMP 'r48-fixed-public-baseline.json'
$destinations = @('1.1.1.1','8.8.8.8',
                  '2606:4700:4700::1111','2001:4860:4860::8888')
function Tcp([string]$address) {
    $ip = [Net.IPAddress]::Parse($address)
    $socket = [Net.Sockets.TcpClient]::new($ip.AddressFamily)
    try {
        $pending = $socket.ConnectAsync($ip,443)
        return $pending.Wait(2500) -and $socket.Connected
    } catch { return $false }
    finally { $socket.Dispose() }
}
function Dns([string]$address) {
    $ip = [Net.IPAddress]::Parse($address)
    $client = [Net.Sockets.UdpClient]::new($ip.AddressFamily)
    try {
        $client.Connect($ip,53)
        $id = [Security.Cryptography.RandomNumberGenerator]::GetInt32(1,65536)
        [byte[]]$query = @([byte]($id -shr 8),[byte]($id -band 255),
            1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,
            3,99,111,109,0,0,1,0,1)
        [void]$client.Send($query,$query.Length)
        $pending = $client.ReceiveAsync()
        if (!$pending.Wait(2500)) { return $false }
        [byte[]]$buffer = $pending.Result.Buffer
        return $buffer.Length -ge 12 -and
            (([int]$buffer[0] -shl 8) -bor [int]$buffer[1]) -eq $id -and
            ($buffer[2] -band 128) -ne 0 -and ($buffer[3] -band 15) -eq 0
    } catch { return $false }
    finally { $client.Dispose() }
}
function Assert-Rule([bool]$mustExist) {
    $found = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object DisplayName -eq $name)
    if (!$mustExist) {
        if ($found.Count -ne 0) { throw 'R48 unowned/residual guard exists' }
        return
    }
    if ($found.Count -ne 1 -or $found[0].Action -ne 'Block' -or
        $found[0].Direction -ne 'Outbound' -or
        [string]$found[0].Enabled -ne 'True') {
        throw 'R48 SYSTEM WFP guard missing or duplicated'
    }
    $app = $found[0] | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $port = $found[0] | Get-NetFirewallPortFilter -ErrorAction Stop
    $addr = $found[0] | Get-NetFirewallAddressFilter -ErrorAction Stop
    $type = $found[0] | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
    if ([string]$app.Program -ne 'Any' -or
        [string]$port.Protocol -notin @('Any','256') -or
        [string]$port.RemotePort -ne 'Any' -or
        [string]$type.InterfaceType -notin @('Any','All')) {
        throw 'R48 all-application, all-interface, all-protocol scope narrowed'
    }
    $actual = @($addr.RemoteAddress | ForEach-Object {
        @([string]$_ -split '[,; ]+') | Where-Object { $_ } | ForEach-Object {
            [Net.IPAddress]::Parse($_).ToString()
        }
    } | Sort-Object -Unique)
    $expected = @($destinations | ForEach-Object {
        [Net.IPAddress]::Parse($_).ToString()
    } | Sort-Object -Unique)
    if (($actual -join '|') -ne ($expected -join '|')) {
        throw 'R48 destination addresses altered'
    }
}
if ($Phase -eq 'Before') {
    if (Test-Path -LiteralPath $path) { throw 'R48 preexisting test evidence' }
    Assert-Rule $false
    $tcp = @('1.1.1.1','8.8.8.8') |
        Where-Object { (Tcp $_) -and (Tcp $_) } | Select-Object -First 1
    $dns = @('1.1.1.1','8.8.8.8') |
        Where-Object { (Dns $_) -and (Dns $_) } | Select-Object -First 1
    if (!$tcp -or !$dns) {
        throw 'R48_BASELINE_UNAVAILABLE: no repeatable TCP and raw UDP DNS'
    }
    $ipv6 = @('2606:4700:4700::1111','2001:4860:4860::8888') |
        Where-Object { Tcp $_ } | Select-Object -First 1
    [ordered]@{ Tcp=$tcp; Dns=$dns; Ipv6=[string]$ipv6 } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $path -Encoding ascii
    Write-Host 'R48_PRE_FILTER_REAL_TCP_DNS_BASELINE_PASS'
}
else {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'R48 missing genuine pre-filter packet baseline'
    }
    $baseline = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($baseline.Tcp -notin @('1.1.1.1','8.8.8.8') -or
        $baseline.Dns -notin @('1.1.1.1','8.8.8.8')) {
        throw 'R48 unexpected baseline destination'
    }
    Start-Sleep -Milliseconds 700
    if ($Phase -eq 'During') {
        Assert-Rule $true
        if ((Tcp $baseline.Tcp) -or (Dns $baseline.Dns) -or (Dns $baseline.Dns)) {
            throw 'R48_FAIL: SYSTEM all-app WFP physical TCP or UDP DNS escaped'
        }
        Write-Host 'R48_SYSTEM_ALL_PROCESS_IPV4_TCP_UDP_DNS_PACKET_DENIAL_PASS'
        if ($baseline.Ipv6) {
            if (Tcp $baseline.Ipv6) { throw 'R48_FAIL: IPv6 packet escaped' }
            Write-Host 'R48_SYSTEM_ALL_PROCESS_IPV6_TCP_PACKET_DENIAL_PASS'
        }
        else { Write-Host 'R48_IPV6_EXTERNAL_BASELINE_UNAVAILABLE_NOT_PROVEN' }
    }
    else {
        Assert-Rule $false
        if (!(Tcp $baseline.Tcp) -or !(Dns $baseline.Dns)) {
            throw 'R48_FAIL: direct IPv4 TCP/UDP DNS not restored after owned WFP release'
        }
        if ($baseline.Ipv6 -and !(Tcp $baseline.Ipv6)) {
            throw 'R48_FAIL: IPv6 TCP not restored'
        }
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        Write-Host 'R48_OWNED_WFP_REMOVED_AND_TCP_DNS_RESTORED_PASS'
    }
}
