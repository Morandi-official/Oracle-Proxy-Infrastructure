# R31 disposable Windows OS WFP proof: all-application outbound blocking,
# fixed external test destinations ONLY. NEVER a production kill switch.
# Intentionally does not change default routes, DNS, profiles or global policy.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R31_NARROW_OS_WFP -ne 'CI_ONLY' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R31_REFUSED: disposable elevated Windows CI only'
}
if ((Get-Service BFE).Status -ne 'Running' -or
    (Get-Service MpsSvc).Status -ne 'Running') {
    throw 'R31_REFUSED: Windows filtering services unavailable'
}
$name = 'OracleProxy-R31-CI-AllApps-FixedDestination'
# Use fixed public resolvers as targets; MUST NEVER block entire physical
# interface or all Internet connectivity of a CI-hosted runner.
$destinations = @('1.1.1.1', '8.8.8.8',
                  '2606:4700:4700::1111', '2001:4860:4860::8888')
$existing = @(Get-NetFirewallRule -ErrorAction Stop |
    Where-Object DisplayName -eq $name)
if ($existing.Count -ne 0) { throw 'R31_REFUSED: owned rule already exists' }
# R46: actual new application sockets on disposable CI, fixed allowlisted
# resolver destinations. Successful baseline required before test-only block.
function Test-R46Tcp([string]$address) {
    $ip = [Net.IPAddress]::Parse($address)
    $client = [Net.Sockets.TcpClient]::new($ip.AddressFamily)
    try {
        $attempt = $client.ConnectAsync($ip, 443)
        return $attempt.Wait(2000) -and $client.Connected
    }
    catch { return $false }
    finally { $client.Dispose() }
}
function Test-R46Dns([string]$address) {
    $ip = [Net.IPAddress]::Parse($address)
    $udp = [Net.Sockets.UdpClient]::new($ip.AddressFamily)
    try {
        $udp.Connect($ip, 53)
        $nonce = [Security.Cryptography.RandomNumberGenerator]::GetInt32(1, 65536)
        [byte[]]$question = @(
          [byte]($nonce -shr 8),[byte]($nonce -band 255), 1,0,0,1,0,0,0,0,0,0,
          7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1)
        [void]$udp.Send($question,$question.Length)
        $reply = $udp.ReceiveAsync()
        if (-not $reply.Wait(2500)) { return $false }
        [byte[]]$data = $reply.Result.Buffer
        return $data.Length -ge 12 -and
            (([int]$data[0] -shl 8) -bor [int]$data[1]) -eq $nonce -and
            ($data[2] -band 0x80) -ne 0 -and
            ($data[3] -band 15) -eq 0
    }
    catch { return $false }
    finally { $udp.Dispose() }
}
$r46Tcp = $null
$r46Dns = $null
$r46V6 = $null
$r46BaselineReady = $false
if ($env:ORACLE_R46_PACKET_PROBE -eq 'CI_ONLY') {
    $r46Tcp = @('1.1.1.1','8.8.8.8') |
        Where-Object { (Test-R46Tcp $_) -and (Test-R46Tcp $_) } |
        Select-Object -First 1
    $r46Dns = @('1.1.1.1','8.8.8.8') |
        Where-Object { (Test-R46Dns $_) -and (Test-R46Dns $_) } |
        Select-Object -First 1
    if (!$r46Tcp -or !$r46Dns) {
        throw 'R46_BASELINE_UNAVAILABLE: real IPv4 TCP and UDP DNS cannot be independently observed'
    }
    $r46V6 = @('2606:4700:4700::1111','2001:4860:4860::8888') |
        Where-Object { Test-R46Tcp $_ } | Select-Object -First 1
    $r46BaselineReady = $true
    Write-Host 'R46_UNBLOCKED_IPV4_TCP_DNS_BASELINE_PASS'
}
$routesBefore = @(Get-NetRoute -ErrorAction Stop |
    Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') |
    Sort-Object ifIndex,DestinationPrefix,NextHop |
    ForEach-Object { "$($_.ifIndex):$($_.DestinationPrefix):$($_.NextHop):$($_.RouteMetric)" })
$profilesBefore = @(Get-NetFirewallProfile -ErrorAction Stop |
    Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })
$created = $false
try {
    New-NetFirewallRule -Name $name -DisplayName $name -Enabled True `
        -Direction Outbound -Action Block -Profile Any -Protocol Any `
        -RemoteAddress $destinations -InterfaceType Any `
        -ErrorAction Stop | Out-Null
    $created = $true
    $live = @(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop)
    if ($live.Count -ne 1 -or $live[0].Direction -ne 'Outbound' -or
        $live[0].Action -ne 'Block' -or
        [string]$live[0].Enabled -ne 'True') {
        throw 'R31_FAIL: OS outbound rule missing or mutated'
    }
    $app = $live[0] | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $port = $live[0] | Get-NetFirewallPortFilter -ErrorAction Stop
    $addr = $live[0] | Get-NetFirewallAddressFilter -ErrorAction Stop
    if ([string]$app.Program -ne 'Any' -or
        [string]$port.Protocol -notin @('Any','256') -or
        [string]$port.RemotePort -ne 'Any') {
        throw 'R31_FAIL: not a genuine all-process all-protocol rule'
    }
    # NetSecurity projects this property as a string array on some Windows
    # versions and a delimited scalar on others. Normalize both, and compare
    # numeric IP identities (IPv6 canonical text can differ).
    $actual = @($addr.RemoteAddress | ForEach-Object {
        @([string]$_ -split '[,; ]+') | Where-Object { $_ } | ForEach-Object {
            [System.Net.IPAddress]::Parse($_).ToString()
        }
    } | Sort-Object -Unique)
    $expected = @($destinations | ForEach-Object {
        [System.Net.IPAddress]::Parse($_).ToString()
    } | Sort-Object -Unique)
    if (($actual -join '|') -ne ($expected -join '|')) {
        throw 'R31_FAIL: target addresses altered'
    }
    # R37: fail-closed negative audit on a narrowly modified, CI-owned rule.
    # Keep the synthetic destination list only; do not affect default routes.
    if ($env:ORACLE_R37_SCOPE_TAMPER -eq 'CI_ONLY') {
        # Change one field that would enable physical-interface bypass.
        $ownedRule = Get-NetFirewallRule -Name $name -ErrorAction Stop
        $ifaceBefore = $ownedRule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
        if ([string]$ifaceBefore.InterfaceType -notin @('Any','All')) {
            throw 'R37_REFUSED: initial interface scope not all'
        }
        Set-NetFirewallRule -Name $name -InterfaceType Wireless -ErrorAction Stop
        $narrow = Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop |
            Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
        if ([string]$narrow.InterfaceType -notin @('Wireless','WLAN')) {
            throw 'R37_FAIL: scope tamper was not applied'
        }
        # A narrowed physical interface is NEVER acceptable WFP coverage.
        $verified = [string]$narrow.InterfaceType -in @('Any','All')
        if ($verified) { throw 'R37_FAIL: narrowed WFP interface accepted' }
        Write-Host 'R37_INTERFACE_NARROWING_REJECTED_PASS'
        # The exact owned rule is removed in finally, not "repaired" by
        # widening someone else's preexisting policy.
    }
    if ($env:ORACLE_R46_PACKET_PROBE -eq 'CI_ONLY') {
        if (!$r46BaselineReady) { throw 'R46 no valid baseline' }
        Start-Sleep -Milliseconds 750
        if ((Test-R46Tcp $r46Tcp) -or (Test-R46Dns $r46Dns) -or
            (Test-R46Dns $r46Dns)) {
            throw 'R46_PACKET_ESCAPE: physical fixed-destination IPv4 TCP or UDP DNS'
        }
        Write-Host 'R46_OS_WFP_IPV4_TCP_UDP_DNS_DENIED_PASS'
        if ($r46V6) {
            if (Test-R46Tcp $r46V6) {
                throw 'R46_PACKET_ESCAPE: physical IPv6 TCP'
            }
            Write-Host 'R46_OS_WFP_IPV6_TCP_DENIED_PASS'
        }
        else {
            Write-Host 'R46_IPV6_PACKET_PROOF_UNAVAILABLE: no IPv6 baseline, not a pass'
        }
    }
    Write-Host 'R31_OS_ALL_APPLICATION_IPV4_IPV6_WFP_RULE_ACTIVE_PASS'
    # OS metadata verifies cross-process applicability but not real remote
    # packet denial: no packet-level claim without independent witness.
}
finally {
    if ($created) {
        $matches = @(Get-NetFirewallRule -ErrorAction Stop |
            Where-Object DisplayName -eq $name)
        if ($matches.Count -ne 1 -or $matches[0].Name -ne $name) {
            throw 'R31_FAIL: refusing unsafe firewall cleanup'
        }
        Remove-NetFirewallRule -Name $name -ErrorAction Stop
    }
    if (@(Get-NetFirewallRule -ErrorAction Stop |
          Where-Object DisplayName -eq $name).Count -ne 0) {
        throw 'R31_FAIL: CI WFP filter survived cleanup'
    }
    $routesAfter = @(Get-NetRoute -ErrorAction Stop |
        Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') |
        Sort-Object ifIndex,DestinationPrefix,NextHop |
        ForEach-Object { "$($_.ifIndex):$($_.DestinationPrefix):$($_.NextHop):$($_.RouteMetric)" })
    $profilesAfter = @(Get-NetFirewallProfile -ErrorAction Stop |
        Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })
    if (($routesBefore -join '|') -ne ($routesAfter -join '|') -or
        ($profilesBefore -join '|') -ne ($profilesAfter -join '|')) {
        throw 'R31_FAIL: unrelated routes or firewall profiles changed'
    }
    if ($r46BaselineReady -and $created) {
        Start-Sleep -Milliseconds 650
        if (!(Test-R46Tcp $r46Tcp) -or !(Test-R46Dns $r46Dns)) {
            throw 'R46_FAIL: IPv4 TCP or UDP DNS did not recover after owned rule removal'
        }
        if ($r46V6 -and !(Test-R46Tcp $r46V6)) {
            throw 'R46_FAIL: IPv6 TCP did not recover after owned rule removal'
        }
        Write-Host 'R46_OS_WFP_REAL_TCP_DNS_RESTORE_PASS'
    }
    Write-Host 'R31_OWNED_WFP_RELEASE_AND_OS_BASELINE_PASS'
}
