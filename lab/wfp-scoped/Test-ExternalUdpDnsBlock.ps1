# R11: narrow outbound UDP/53 DNS deny/restore in a disposable GitHub Windows VM.
# Test-scoped WFP-backed firewall only. NO device kill switch or DNS leak claim.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R11_REFUSED: elevated, disposable GitHub-hosted Windows runner required'
}
if ((Get-Service BFE -ErrorAction Stop).Status -ne 'Running' -or (Get-Service MpsSvc -ErrorAction Stop).Status -ne 'Running') {
    throw 'R11_REFUSED: BFE and Windows Firewall must already be running'
}
$program = (Get-Process -Id $PID -ErrorAction Stop).Path
if (-not $program.EndsWith('pwsh.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'R11_REFUSED: caller executable is not the CI PowerShell host'
}
$tag = [guid]::NewGuid().ToString('N')
$rules = [System.Collections.Generic.List[string]]::new()
$originalCount = @(Get-NetFirewallRule -ErrorAction Stop).Count
$originalProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })

# Raw UDP DNS A query for example.com (never asks for private user domains).
# Fresh socket and query ID: cannot pass by reading the Windows DNS cache.
function Test-DirectDns([string]$address, [int]$waitMs = 2500) {
    $ip = [System.Net.IPAddress]::Parse($address)
    $sock = [System.Net.Sockets.UdpClient]::new($ip.AddressFamily)
    try {
        $sock.Connect($ip, 53)
        $transaction = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(1,65536)
        $query = [System.Collections.Generic.List[byte]]::new()
        $query.AddRange([byte[]]@([byte]($transaction -shr 8), [byte]($transaction -band 0xff), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        foreach ($label in @('example','com')) {
            [byte[]]$segment = [System.Text.Encoding]::ASCII.GetBytes($label)
            $query.Add([byte]$segment.Length)
            $query.AddRange($segment)
        }
        $query.AddRange([byte[]]@(0x00,0x00,0x01,0x00,0x01))
        [byte[]]$bytes = $query.ToArray()
        [void]$sock.Send($bytes, $bytes.Length)
        $pending = $sock.ReceiveAsync()
        if (-not $pending.Wait($waitMs)) { return $false }
        [byte[]]$reply = $pending.Result.Buffer
        if ($reply.Length -lt 12) { return $false }
        $returnedId = ([int]$reply[0] -shl 8) -bor [int]$reply[1]
        $rcode = [int]$reply[3] -band 0x0f
        $answers = ([int]$reply[6] -shl 8) -bor [int]$reply[7]
        return ($returnedId -eq $transaction -and (($reply[2] -band 0x80) -ne 0) -and $rcode -eq 0 -and $answers -gt 0)
    } catch {
        # A denied UDP socket or timeout is expected while filtered.
        return $false
    } finally {
        $sock.Dispose()
    }
}
function Select-VerifiedBaseline([string[]]$candidates) {
    foreach ($remote in $candidates) {
        if ((Test-DirectDns $remote) -and (Test-DirectDns $remote)) { return $remote }
    }
    return $null
}
function Assert-DenyRestore([string]$remote, [string]$family) {
    $ruleName = "OracleProxy-R11-CI-$tag-$family"
    $owned = $false
    try {
        # Exactly one CI pwsh.exe, remote IP and UDP destination port.
        New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -RemoteAddress $remote -Program $program -Profile Any -Enabled True -PolicyStore PersistentStore -ErrorAction Stop | Out-Null
        $owned = $true
        $rules.Add($ruleName)
        $live = Get-NetFirewallRule -PolicyStore ActiveStore -Name $ruleName -ErrorAction Stop
        $port = $live | Get-NetFirewallPortFilter -ErrorAction Stop
        $address = $live | Get-NetFirewallAddressFilter -ErrorAction Stop
        $app = $live | Get-NetFirewallApplicationFilter -ErrorAction Stop
        if ($live.Action -ne 'Block' -or $live.Direction -ne 'Outbound' -or [string]$port.Protocol -ne 'UDP' -or [string]$port.RemotePort -ne '53' -or [string]$address.RemoteAddress -ne $remote -or $app.Program -ne $program) {
            throw 'R11_FAIL: active rule not narrowly scoped to this DNS UDP client'
        }
        Start-Sleep -Milliseconds 800
        if ((Test-DirectDns $remote) -or (Test-DirectDns $remote)) {
            throw "R11_FAIL: $family UDP DNS response despite WFP-backed deny"
        }
        Write-Host "R11_$($family)_UDP_DNS_PACKET_DENY_PASS: direct DNS UDP response suppressed"
        Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
        $owned = $false
        [void]$rules.Remove($ruleName)
        Start-Sleep -Milliseconds 800
        if (-not (Test-DirectDns $remote) -or -not (Test-DirectDns $remote)) {
            throw "R11_FAIL: $family UDP DNS failed to recover after exact-rule removal"
        }
        Write-Host "R11_$($family)_UDP_DNS_RESTORE_PASS: direct DNS response returned"
    } finally {
        if ($owned) {
            Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
            [void]$rules.Remove($ruleName)
        }
    }
}
try {
    $v4 = Select-VerifiedBaseline @('1.1.1.1','8.8.8.8')
    if ($null -eq $v4) {
        throw 'R11_IPV4_BASELINE_UNAVAILABLE: no repeatable external UDP DNS; cannot claim deny proof'
    }
    Write-Host 'R11_IPV4_BASELINE_PASS: external UDP DNS answered twice'
    Assert-DenyRestore $v4 'IPV4'
    $v6 = Select-VerifiedBaseline @('2606:4700:4700::1111','2001:4860:4860::8888')
    if ($null -eq $v6) {
        Write-Host 'R11_IPV6_BASELINE_UNAVAILABLE: no IPv6 packet-denial evidence on this Windows runner'
    } else {
        Assert-DenyRestore $v6 'IPV6'
    }
} finally {
    foreach ($name in @($rules.ToArray())) {
        Remove-NetFirewallRule -Name $name -ErrorAction Stop
    }
    if (@(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Name -like "OracleProxy-R11-CI-$tag-*" }).Count -ne 0) {
        throw 'R11_FAIL: owned rules remained after cleanup'
    }
    if (@(Get-NetFirewallRule -ErrorAction Stop).Count -ne $originalCount) {
        throw 'R11_FAIL: firewall rule count differs from baseline'
    }
    $afterProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })
    if (($originalProfiles -join '|') -ne ($afterProfiles -join '|')) {
        throw 'R11_FAIL: Windows Firewall profile enabled states changed'
    }
    Write-Host 'R11_FIREWALL_CLEANUP_PASS: owned rules removed; profile states and firewall rule count restored'
}
